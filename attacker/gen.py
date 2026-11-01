#!/usr/bin/env python3
"""CODAX traffic generator: benign load + semantic attacks, with per-connection labels.

For every connection it opens it records the client ephemeral port (via getsockname)
and a label, so the analyzer can join kernel events to ground truth by port:
    {"dport":45912,"label":"benign"|"attack","container":"redos","kind":"..."}

Runs from the target VM (localhost, default) or from Kali (--host 192.168.56.102).
Either way the server inside the container does the accept()/close() the tracer sees.

Phases:
  measure - benign only, to all containers (establishes the per-container thresholds).
            This is pure statistics (mean/std of normal request times), NOT ML training.
  test    - benign + attacks, interleaved; some attacks are PERSISTENT (held open, never
            close during the phase) to exercise CODA's blind spot vs CODAX.
"""
import argparse
import json
import random
import socket
import threading
import time

PORTS = {"redos": 8001, "inloop": 8002, "baseline": 8003}
_lock = threading.Lock()
_labels = []


def _log(dport, label, container, kind):
    with _lock:
        _labels.append({"dport": dport, "label": label,
                        "container": container, "kind": kind})


def _request(host, container, path, label, kind, hold=False, read=True, timeout=30):
    """Open one connection, log its client port, send an HTTP GET.
    hold=True keeps the socket open (persistent attack: no close during the phase)."""
    port = PORTS[container]
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.settimeout(timeout)
        s.connect((host, port))
        dport = s.getsockname()[1]           # our source port == server's "dport"
        _log(dport, label, container, kind)
        req = f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
        s.sendall(req.encode())
        if read and not hold:
            try:
                while s.recv(4096):
                    pass
            except socket.timeout:
                pass
        if hold:
            return s  # caller keeps it open; returned so it isn't garbage-collected/closed
    except Exception as e:
        _log(-1, label, container, f"{kind}:ERR:{e}")
    if not hold:
        s.close()
    return None


# --------------------------------------------------------------------- phases
def phase_measure(host, per_container, concurrency=8):
    """Benign requests to every container -> baseline for threshold calculation.

    Runs the load across `concurrency` threads with no pacing, on purpose: a sequential,
    unloaded measurement run learns an artificially tight distribution (near-zero variance),
    so its tau = max(t_max, mu + k*sigma) sits just above idle latency and then false-positives
    on the normal scheduling jitter a busy host shows at test time. Concurrent benign load makes
    the measurement run see that jitter tail, so the learned threshold is representative, not
    brittle."""
    print(f"[measure] {per_container} benign/container x{concurrency} threads to {host}")

    def worker(c, n):
        for _ in range(n):
            _request(host, c, "/safe", "benign", "measure")

    threads = []
    for c in PORTS:
        per_t = max(1, per_container // concurrency)
        for _ in range(concurrency):
            threads.append(threading.Thread(target=worker, args=(c, per_t), daemon=True))
    for t in threads:
        t.start()
    for t in threads:
        t.join()


def phase_test(host, n_benign, n_attack_closing, n_attack_persistent,
               redos_persist_n, inloop_closing_ms, heartbeat_s, hold_s):
    """One role per container so detectors are not cross-contaminated:
      baseline - benign /safe + a periodic 'heartbeat' close (the CODAX clock); stays fast
                 under no load, so it is the clean true-negative source.
      inloop   - bounded closing attacks (?ms=): they DO close within the phase, so CODA and
                 CODAX both catch them -> paired detections for the latency test. Bounded, so
                 inloop self-recovers (no unbounded loop that would wedge single-threaded Node).
      redos    - persistent attacks: a high-n evil regex held open, running far longer than
                 the capture window, so they never close while we watch. CODA's blind spot;
                 CODAX catches them on a heartbeat scan. Flask threaded + cpus=2.0 cap keeps
                 them concurrent without starving the host; they self-recover after the run."""
    print(f"[test] benign={n_benign} closing_attacks={n_attack_closing} "
          f"persistent_attacks={n_attack_persistent}")
    held = []

    # Baseline heartbeat: a benign close every heartbeat_s (the CODAX clock tick).
    stop = threading.Event()

    def heartbeat():
        while not stop.is_set():
            _request(host, "baseline", "/safe", "benign", "heartbeat")
            stop.wait(heartbeat_s)

    hb = threading.Thread(target=heartbeat, daemon=True)
    hb.start()

    # Launch persistent attacks on redos (held open, never close during the phase).
    def launch_persistent():
        s = _request(host, "redos", f"/vulnerable?n={redos_persist_n}",
                     "attack", "persistent", hold=True)
        if s:
            held.append(s)

    for _ in range(n_attack_persistent):
        threading.Thread(target=launch_persistent, daemon=True).start()
        time.sleep(0.05)

    # Interleave benign (baseline, stays fast -> TN) and bounded closing attacks (inloop,
    # ?ms= deadline so they close within the phase -> both detectors catch them).
    work = (["benign"] * n_benign +
            ["attack_closing"] * n_attack_closing)
    random.shuffle(work)
    for w in work:
        if w == "benign":
            _request(host, "baseline", "/safe", "benign", "test")
        else:
            _request(host, "inloop", f"/vulnerable?ms={inloop_closing_ms}",
                     "attack", "closing")
        time.sleep(0.01)

    print(f"[test] holding {len(held)} persistent attacks open for {hold_s}s "
          f"(CODA should miss these)...")
    time.sleep(hold_s)
    stop.set()
    for s in held:
        try:
            s.close()
        except Exception:
            pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--phase", choices=["measure", "test"], required=True)
    ap.add_argument("--labels", required=True, help="output labels JSONL")
    ap.add_argument("--per-container", type=int, default=300,
                    help="benign requests per container in the measure phase")
    ap.add_argument("--measure-concurrency", type=int, default=8,
                    help="parallel threads during the measure phase (induces realistic jitter)")
    ap.add_argument("--benign", type=int, default=50, help="test benign count")
    ap.add_argument("--attack-closing", type=int, default=20,
                    help="test bounded attacks (eventually close)")
    ap.add_argument("--attack-persistent", type=int, default=10,
                    help="test persistent attacks on redos (held open, never close)")
    ap.add_argument("--redos-persist-n", type=int, default=30,
                    help="evil-regex exponent for persistent attacks (must outlast capture)")
    ap.add_argument("--inloop-closing-ms", type=int, default=2500,
                    help="busy-loop ms for bounded closing attacks on inloop (they do close)")
    ap.add_argument("--heartbeat-s", type=float, default=0.5)
    ap.add_argument("--hold-s", type=float, default=12.0)
    a = ap.parse_args()

    t0 = time.time()
    if a.phase == "measure":
        phase_measure(a.host, a.per_container, a.measure_concurrency)
    else:
        phase_test(a.host, a.benign, a.attack_closing, a.attack_persistent,
                   a.redos_persist_n, a.inloop_closing_ms, a.heartbeat_s, a.hold_s)

    with open(a.labels, "w") as f:
        for r in _labels:
            f.write(json.dumps(r) + "\n")
    print(f"[{a.phase}] wrote {len(_labels)} labels to {a.labels} in {time.time()-t0:.1f}s")


if __name__ == "__main__":
    main()
