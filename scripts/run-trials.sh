#!/usr/bin/env bash
# Multi-trial CODAX experiment: repeat capture N times, then aggregate (mean +/- SD, paired
# t-test, Wilcoxon) the way the paper reports its results (Sec. VIII, 10 trials).
# Run as root:
#   SUDO_ASKPASS=~/.config/codax/askpass.sh sudo -A bash scripts/run-trials.sh
#
# Each trial writes data/trials/tNN/{measure,test}_events.jsonl + labels_test.jsonl; the final
# step runs analysis/analyze.py --trials over all of them. The testbed is restarted BEFORE
# every trial: persistent ReDoS attacks wedge their gunicorn workers (--timeout 0), so a fresh
# set of workers is needed each time, and restart also yields fresh cgroup ids.
#
# Tunables via env (full-run defaults):
#   N_TRIALS (10) HOST (192.168.56.102) PER_CONTAINER (300) MEASURE_CONC (8)
#   BENIGN (100) ATK_CLOSING (10) ATK_PERSIST (6)
#   REDOS_PERSIST_N (30) INLOOP_CLOSING_MS (2500) HEARTBEAT_S (0.5) HOLD_S (10)
#   K (4) TAU_MIN_MS (5)
set -euo pipefail
cd "$(dirname "$0")/.."

N_TRIALS=${N_TRIALS:-10}
HOST=${HOST:-192.168.56.102}
PER_CONTAINER=${PER_CONTAINER:-300}; MEASURE_CONC=${MEASURE_CONC:-8}
BENIGN=${BENIGN:-100}; ATK_CLOSING=${ATK_CLOSING:-10}; ATK_PERSIST=${ATK_PERSIST:-6}
REDOS_PERSIST_N=${REDOS_PERSIST_N:-30}; INLOOP_CLOSING_MS=${INLOOP_CLOSING_MS:-2500}
HEARTBEAT_S=${HEARTBEAT_S:-0.5}; HOLD_S=${HOLD_S:-10}
K=${K:-4}; TAU_MIN_MS=${TAU_MIN_MS:-5}

mkdir -p data
start_tracer() {  # $1 = output events file
    mapfile -t CGIDS < <(scripts/cgids.sh | awk '{print $1}')
    [ "${#CGIDS[@]}" -gt 0 ] || { echo "no containers; start testbed first" >&2; exit 1; }
    ./bin/codax_tracer "${CGIDS[@]}" > "$1" 2>data/tracer.log &
    TRACER_PID=$!
    sleep 1
}
stop_tracer() { kill -INT "$TRACER_PID" 2>/dev/null || true; wait "$TRACER_PID" 2>/dev/null || true; }

rm -rf data/trials
mkdir -p data/trials

for i in $(seq 1 "$N_TRIALS"); do
    td=$(printf 'data/trials/t%02d' "$i")
    mkdir -p "$td"
    echo "===== TRIAL $i / $N_TRIALS ($td) ====="
    pkill -x codax_tracer 2>/dev/null || true
    pkill -f 'attacker/gen.py' 2>/dev/null || true
    ( cd testbed && docker compose restart ) >/dev/null 2>&1
    sleep 2

    start_tracer "$td/measure_events.jsonl"
    python3 attacker/gen.py --host "$HOST" --phase measure --labels "$td/labels_measure.jsonl" \
        --per-container "$PER_CONTAINER" --measure-concurrency "$MEASURE_CONC" >/dev/null
    stop_tracer

    start_tracer "$td/test_events.jsonl"
    python3 attacker/gen.py --host "$HOST" --phase test --labels "$td/labels_test.jsonl" \
        --benign "$BENIGN" --attack-closing "$ATK_CLOSING" --attack-persistent "$ATK_PERSIST" \
        --redos-persist-n "$REDOS_PERSIST_N" --inloop-closing-ms "$INLOOP_CLOSING_MS" \
        --heartbeat-s "$HEARTBEAT_S" --hold-s "$HOLD_S" >/dev/null
    stop_tracer

    echo "  measure=$(wc -l <"$td/measure_events.jsonl") test=$(wc -l <"$td/test_events.jsonl") events"
done

echo
echo "===== AGGREGATE ANALYSIS ====="
python3 analysis/analyze.py --trials data/trials -k "$K" --tau-min-ms "$TAU_MIN_MS"
