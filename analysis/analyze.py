#!/usr/bin/env python3
"""CODAX reproduction: threshold model + CODA vs CODAX replay + metrics.

Pipeline
--------
The tracer (bin/codax_tracer) writes connection-lifecycle events as JSONL:
    {"type":"accept"|"close","ts_ns":..,"start_ns":..,"elapsed_ns":..,
     "sport":8001,"dport":<client port>, ...}
The traffic generator writes ground-truth labels, one per connection, keyed by the
client ephemeral port it used:
    {"dport":45912,"label":"attack"|"benign"}

This module:
  1. builds a per-container detection threshold from a MEASUREMENT capture (benign only),
     tau = max(t_max, mu + k*sigma)              (paper eq. 46, Chebyshev, k=4)
  2. replays a TEST capture under two detectors:
       CODA  - flags a connection only when it CLOSES with elapsed > tau  (misses
               connections that never close: the gap CODAX targets)
       CODAX - Algorithm 6: on EVERY close in ANY container (the "clock"), scan all
               still-open connections and flag any whose age already exceeds tau; so a
               persistent attack is caught mid-flight, before it closes.
  3. scores both against ground truth -> ADR, FPR, detection latency, and compares
     CODA vs CODAX latency with a paired t-test + Wilcoxon (paper Sec. VIII).

Container is identified by server port (sport): 8001 redos, 8002 inloop, 8003 baseline.
Times are kernel CLOCK_MONOTONIC ns, so latency needs no cross-VM clock sync.
"""
import argparse
import json
import math
import sys
from collections import defaultdict

CONTAINER_BY_PORT = {8001: "redos", 8002: "inloop", 8003: "baseline"}


# ----------------------------------------------------------------------------- IO
def load_events(path):
    """Read tracer JSONL -> list of event dicts, sorted by ts_ns (replay order)."""
    evs = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                evs.append(json.loads(line))
    evs.sort(key=lambda e: e["ts_ns"])
    return evs


def load_labels(path):
    """Read generator JSONL -> {dport: label}. Warn on reused ports within a run."""
    labels = {}
    if not path:
        return labels
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            r = json.loads(line)
            dp = int(r["dport"])
            if dp in labels and labels[dp] != r["label"]:
                print(f"warn: dport {dp} reused with differing label", file=sys.stderr)
            labels[dp] = r["label"]
    return labels


def container_of(ev):
    return CONTAINER_BY_PORT.get(ev.get("sport"), f"port{ev.get('sport')}")


# ---------------------------------------------------------------- threshold model
def chebyshev_threshold(samples_ns, k=4.0):
    """tau = max(t_max, mu + k*sigma), computed directly (numpy-free) for validation."""
    n = len(samples_ns)
    if n == 0:
        return None
    mu = sum(samples_ns) / n
    var = sum((x - mu) ** 2 for x in samples_ns) / n  # population variance (paper eq. 2)
    sigma = math.sqrt(var)
    return max(max(samples_ns), mu + k * sigma)


def incremental_stats(samples_ns):
    """Reproduce the paper's in-kernel incremental mean/std (eq. 48/49) to show it
    matches the direct computation. eq. 49 is the paper's approximation, not Welford."""
    mean = 0.0
    std = 0.0
    n = 0
    for x in samples_ns:
        new_mean = (mean * n + x) / (n + 1)
        # paper eq. 49 (as written): std_new = sqrt((std_old^2 * n + (x-new_mean)^2)/(n+1))
        std = math.sqrt((std * std * n + (x - new_mean) ** 2) / (n + 1))
        mean = new_mean
        n += 1
    return mean, std


def build_thresholds(measure_events, k=4.0):
    """Per-container tau from the elapsed times of CLOSED connections in the measure capture."""
    by_container = defaultdict(list)
    for e in measure_events:
        if e["type"] == "close":
            by_container[container_of(e)].append(e["elapsed_ns"])
    return {c: chebyshev_threshold(v, k) for c, v in by_container.items()}, by_container


# ----------------------------------------------------------------- replay: CODA
def replay_coda(test_events, thresholds, tau_min_ns):
    """CODA: decide only at close(); elapsed > tau -> attack. Never-closing conns are
    never seen, so they can never be flagged. Returns {dport: (detect_ts, latency_ns)}."""
    detections = {}
    for e in test_events:
        if e["type"] != "close":
            continue
        tau = thresholds.get(container_of(e))
        if tau is None:
            continue
        if e["elapsed_ns"] > tau and e["elapsed_ns"] > tau_min_ns:
            dp = e["dport"]
            if dp not in detections:
                detections[dp] = (e["ts_ns"], e["elapsed_ns"])
    return detections


# ---------------------------------------------------------------- replay: CODAX
def replay_codax(test_events, thresholds, tau_min_ns):
    """CODAX / Algorithm 6: maintain open connections; on EVERY close event, scan all
    open connections and flag any whose current age exceeds its container threshold."""
    open_conns = {}  # sk -> {start_ns, container, dport}
    detections = {}  # dport -> (detect_ts, latency_ns)

    def scan(now):
        for sk, c in list(open_conns.items()):
            tau = thresholds.get(c["container"])
            if tau is None:
                continue
            age = now - c["start_ns"]
            if age > tau and age > tau_min_ns and c["dport"] not in detections:
                detections[c["dport"]] = (now, age)

    for e in test_events:
        if e["type"] == "accept":
            open_conns[e["sk"]] = {
                "start_ns": e["start_ns"],
                "container": container_of(e),
                "dport": e["dport"],
            }
        elif e["type"] == "close":
            # The close is the clock tick: first check all currently-open connections...
            scan(e["ts_ns"])
            # ...then also judge the connection that just closed (its final age).
            tau = thresholds.get(container_of(e))
            dp = e["dport"]
            if tau is not None and e["elapsed_ns"] > tau and e["elapsed_ns"] > tau_min_ns \
                    and dp not in detections:
                detections[dp] = (e["ts_ns"], e["elapsed_ns"])
            open_conns.pop(e["sk"], None)
    return detections


# --------------------------------------------------------------------- scoring
def connections_in(test_events):
    """All connections seen in test (by dport) with their container and start time."""
    conns = {}
    for e in test_events:
        dp = e.get("dport")
        if dp is None:
            continue
        if dp not in conns:
            conns[dp] = {"container": container_of(e), "start_ns": e.get("start_ns")}
    return conns


def score(conns, labels, detections):
    """TP/FP/TN/FN over connections with a known label. positive = flagged by detector."""
    tp = fp = tn = fn = 0
    for dp, meta in conns.items():
        label = labels.get(dp)
        if label is None:
            continue  # unlabeled (e.g. stray connection) -> excluded
        flagged = dp in detections
        if label == "attack":
            tp += flagged
            fn += not flagged
        else:
            fp += flagged
            tn += not flagged
    total = tp + tn + fp + fn
    adr = (tp + tn) / total if total else 0.0          # paper eq. 55 (accuracy)
    fpr = fp / (fp + tn) if (fp + tn) else 0.0          # paper eq. 54
    recall = tp / (tp + fn) if (tp + fn) else 0.0       # TPR
    return dict(tp=tp, fp=fp, tn=tn, fn=fn, ADR=adr, FPR=fpr, TPR=recall, n=total)


def paired_latency(conns, labels, det_coda, det_codax):
    """Latencies (ms) for attack connections detected by BOTH, paired for the t-test."""
    xs, ys = [], []  # CODA, CODAX
    for dp, meta in conns.items():
        if labels.get(dp) != "attack":
            continue
        if dp in det_coda and dp in det_codax:
            xs.append(det_coda[dp][1] / 1e6)
            ys.append(det_codax[dp][1] / 1e6)
    return xs, ys


def stats_tests(xs, ys):
    """Paired t-test + Wilcoxon on CODA vs CODAX latencies, if scipy is available."""
    if len(xs) < 2:
        return None
    try:
        from scipy import stats
    except Exception:
        return {"note": "scipy unavailable"}
    diffs = [a - b for a, b in zip(xs, ys)]
    out = {
        "n": len(xs),
        "mean_coda_ms": sum(xs) / len(xs),
        "mean_codax_ms": sum(ys) / len(ys),
        "mean_diff_ms": sum(diffs) / len(diffs),
    }
    t, p = stats.ttest_rel(xs, ys)
    out["ttest_t"], out["ttest_p"] = float(t), float(p)
    try:
        w, pw = stats.wilcoxon(xs, ys)
        out["wilcoxon_W"], out["wilcoxon_p"] = float(w), float(pw)
    except Exception as e:
        out["wilcoxon_note"] = str(e)
    return out


# ----------------------------------------------------------------------- driver
def evaluate(measure_events, test_events, labels, k, tau_min_ms):
    """Build thresholds from the measure capture, replay both detectors on test, score them.
    No printing, so it can be reused per trial. Returns thresholds, both scores, and the
    paired latencies."""
    tau_min_ns = int(tau_min_ms * 1e6)
    thresholds, measure_by_c = build_thresholds(measure_events, k)
    det_coda = replay_coda(test_events, thresholds, tau_min_ns)
    det_codax = replay_codax(test_events, thresholds, tau_min_ns)
    conns = connections_in(test_events)
    s_coda = score(conns, labels, det_coda)
    s_codax = score(conns, labels, det_codax)
    xs, ys = paired_latency(conns, labels, det_coda, det_codax)
    return dict(thresholds=thresholds, measure_by_c=measure_by_c,
                coda=s_coda, codax=s_codax, xs=xs, ys=ys)


def run(measure_events, test_events, labels, k, tau_min_ms):
    r = evaluate(measure_events, test_events, labels, k, tau_min_ms)

    print(f"== thresholds (k={k}, tau_min={tau_min_ms}ms) ==")
    for c, tau in sorted(r["thresholds"].items()):
        n = len(r["measure_by_c"][c])
        mu_i, std_i = incremental_stats(r["measure_by_c"][c])
        tau_ms = tau / 1e6 if tau is not None else float("nan")
        print(f"  {c:9s} n={n:5d}  tau={tau_ms:9.2f} ms   "
              f"(incremental mu={mu_i/1e6:.3f}ms sigma={std_i/1e6:.3f}ms)")

    print("\n== detection scores ==")
    for name, s in [("CODA", r["coda"]), ("CODAX", r["codax"])]:
        print(f"  {name:6s} ADR={s['ADR']:.3f} FPR={s['FPR']:.3f} TPR={s['TPR']:.3f}  "
              f"TP={s['tp']} FP={s['fp']} TN={s['tn']} FN={s['fn']} (n={s['n']})")

    st = stats_tests(r["xs"], r["ys"])
    print("\n== detection latency (attacks detected by both) ==")
    if st is None:
        print("  not enough paired detections for a test")
    else:
        print(f"  n={st['n']}  CODA={st.get('mean_coda_ms',0):.1f}ms  "
              f"CODAX={st.get('mean_codax_ms',0):.1f}ms  "
              f"improvement={st.get('mean_diff_ms',0):.1f}ms")
        if "ttest_p" in st:
            print(f"  paired t-test: t={st['ttest_t']:.2f} p={st['ttest_p']:.2e}")
        if "wilcoxon_p" in st:
            print(f"  wilcoxon:      W={st['wilcoxon_W']:.1f} p={st['wilcoxon_p']:.2e}")
    return dict(thresholds=r["thresholds"], coda=r["coda"], codax=r["codax"], latency=st)


def _mean_sd(vals):
    import statistics as st
    if not vals:
        return 0.0, 0.0
    return st.mean(vals), (st.pstdev(vals) if len(vals) > 1 else 0.0)


def run_trials(trials_dir, k, tau_min_ms):
    """Aggregate over N trial subdirs (t01/, t02/, ... each with measure/test/labels), reporting
    mean +/- SD of ADR/FPR/TPR per detector, pooled confusion totals, and the CODA-vs-CODAX
    latency improvement both across-trial (paired t-test on per-trial means) and pooled over
    every attack detected by both (t-test + Wilcoxon), matching the paper's Sec. VIII analysis."""
    import glob
    import os
    import statistics as st

    tdirs = sorted(d for d in glob.glob(os.path.join(trials_dir, "t*")) if os.path.isdir(d))
    if not tdirs:
        print(f"no trial subdirs in {trials_dir}", file=sys.stderr)
        return
    rows = []
    for td in tdirs:
        r = evaluate(load_events(os.path.join(td, "measure_events.jsonl")),
                     load_events(os.path.join(td, "test_events.jsonl")),
                     load_labels(os.path.join(td, "labels_test.jsonl")),
                     k, tau_min_ms)
        rows.append(r)

    print(f"== aggregate over {len(rows)} trials (k={k}, tau_min={tau_min_ms}ms) ==")
    print(f"  {'':6s}{'ADR':>16s}{'FPR':>16s}{'TPR':>16s}")
    for name, key in [("CODA", "coda"), ("CODAX", "codax")]:
        adr = _mean_sd([r[key]["ADR"] for r in rows])
        fpr = _mean_sd([r[key]["FPR"] for r in rows])
        tpr = _mean_sd([r[key]["TPR"] for r in rows])
        print(f"  {name:5s} {adr[0]:7.3f}±{adr[1]:.3f} {fpr[0]:7.3f}±{fpr[1]:.3f} "
              f"{tpr[0]:7.3f}±{tpr[1]:.3f}")

    print("\n== pooled confusion (summed over trials) ==")
    for name, key in [("CODA", "coda"), ("CODAX", "codax")]:
        tp = sum(r[key]["tp"] for r in rows); fp = sum(r[key]["fp"] for r in rows)
        tn = sum(r[key]["tn"] for r in rows); fn = sum(r[key]["fn"] for r in rows)
        print(f"  {name:5s} TP={tp} FP={fp} TN={tn} FN={fn}")

    # Latency: per-trial means (attacks detected by both), then paired across trials; and pooled.
    per_coda, per_codax, pool_x, pool_y = [], [], [], []
    for r in rows:
        if r["xs"]:
            per_coda.append(st.mean(r["xs"])); per_codax.append(st.mean(r["ys"]))
            pool_x += r["xs"]; pool_y += r["ys"]
    print("\n== detection latency (CODA vs CODAX, attacks detected by both) ==")
    if not per_coda:
        print("  no paired detections")
        return
    print(f"  per-trial means: CODA={st.mean(per_coda):.1f}ms CODAX={st.mean(per_codax):.1f}ms "
          f"improvement={st.mean(per_coda)-st.mean(per_codax):.1f}ms  (trials={len(per_coda)})")
    across = stats_tests(per_coda, per_codax)
    if across and "ttest_p" in across:
        print(f"  paired t-test ACROSS trials: t={across['ttest_t']:.2f} p={across['ttest_p']:.2e}")
    if across and "wilcoxon_p" in across:
        print(f"  wilcoxon ACROSS trials:      W={across['wilcoxon_W']:.1f} p={across['wilcoxon_p']:.2e}")
    pooled = stats_tests(pool_x, pool_y)
    if pooled:
        print(f"  POOLED over {len(pool_x)} attacks: improvement={pooled.get('mean_diff_ms',0):.1f}ms")
        if "ttest_p" in pooled:
            print(f"    t={pooled['ttest_t']:.2f} p={pooled['ttest_p']:.2e}")
        if "wilcoxon_p" in pooled:
            print(f"    wilcoxon W={pooled['wilcoxon_W']:.1f} p={pooled['wilcoxon_p']:.2e}")


# ------------------------------------------------------------------- self-test
def selftest():
    """Fabricate events proving the core claim: a persistent (never-closing during its
    attack) connection is MISSED by CODA but caught by CODAX via a heartbeat close."""
    NS = 1_000_000  # 1 ms
    # Measure phase: 50 benign redos closes ~2ms, 50 benign baseline closes ~1ms.
    measure = []
    for i in range(50):
        measure.append({"type": "accept", "ts_ns": i * 10 * NS, "start_ns": i * 10 * NS,
                        "elapsed_ns": 0, "sport": 8001, "dport": 1000 + i, "sk": i})
        measure.append({"type": "close", "ts_ns": i * 10 * NS + 2 * NS,
                        "start_ns": i * 10 * NS, "elapsed_ns": 2 * NS,
                        "sport": 8001, "dport": 1000 + i, "sk": i})
    # Test: one benign redos (2ms), one ATTACK redos that stays open 5s, and baseline
    # heartbeat closes every 1s providing the CODAX clock.
    T = 10_000 * NS
    test = [
        {"type": "accept", "ts_ns": T, "start_ns": T, "elapsed_ns": 0,
         "sport": 8001, "dport": 2001, "sk": 101},
        {"type": "close", "ts_ns": T + 2 * NS, "start_ns": T, "elapsed_ns": 2 * NS,
         "sport": 8001, "dport": 2001, "sk": 101},
        {"type": "accept", "ts_ns": T, "start_ns": T, "elapsed_ns": 0,
         "sport": 8001, "dport": 2002, "sk": 102},  # the attack: opens at T
    ]
    for j in range(1, 6):  # baseline heartbeats at T+1s..T+5s
        ht = T + j * 1000 * NS
        test.append({"type": "accept", "ts_ns": ht, "start_ns": ht, "elapsed_ns": 0,
                     "sport": 8003, "dport": 3000 + j, "sk": 200 + j})
        test.append({"type": "close", "ts_ns": ht + NS, "start_ns": ht,
                     "elapsed_ns": NS, "sport": 8003, "dport": 3000 + j, "sk": 200 + j})
    # attack finally closes at T+5s (so CODA sees it only here, very late)
    test.append({"type": "close", "ts_ns": T + 5000 * NS, "start_ns": T,
                 "elapsed_ns": 5000 * NS, "sport": 8001, "dport": 2002, "sk": 102})
    labels = {2001: "benign", 2002: "attack",
              **{3000 + j: "benign" for j in range(1, 6)}}

    print("### SELF-TEST ###")
    res = run(measure, test, labels, k=4.0, tau_min_ms=0.0)
    coda_lat = replay_coda(test, res["thresholds"], 0)[2002][1] / 1e6
    codax_lat = replay_codax(test, res["thresholds"], 0)[2002][1] / 1e6
    print(f"\nattack 2002: CODA latency={coda_lat:.0f}ms  CODAX latency={codax_lat:.0f}ms")
    assert res["codax"]["tp"] == 1, "CODAX must catch the attack"
    assert codax_lat < coda_lat, "CODAX must be earlier than CODA"
    print("OK: CODAX catches the persistent attack far earlier than CODA.")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--measure", help="measurement events JSONL (benign only)")
    ap.add_argument("--test", help="test events JSONL")
    ap.add_argument("--labels", help="ground-truth labels JSONL (dport,label)")
    ap.add_argument("--trials", help="directory of trial subdirs (t01/, t02/, ...) to aggregate")
    ap.add_argument("-k", type=float, default=4.0)
    ap.add_argument("--tau-min-ms", type=float, default=0.0,
                    help="minimum age before a connection can be flagged (paper tau_min)")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        selftest()
        return
    if a.trials:
        run_trials(a.trials, a.k, a.tau_min_ms)
        return
    if not (a.measure and a.test):
        ap.error("need --measure and --test, or --trials DIR (or --selftest)")
    run(load_events(a.measure), load_events(a.test), load_labels(a.labels),
        a.k, a.tau_min_ms)


if __name__ == "__main__":
    main()
