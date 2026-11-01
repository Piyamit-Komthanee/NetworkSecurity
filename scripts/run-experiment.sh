#!/usr/bin/env bash
# End-to-end CODAX experiment: capture the measure phase, capture test (with attacks), analyze.
# Run as root (tracer needs it):
#   SUDO_ASKPASS=~/.config/codax/askpass.sh sudo -A bash scripts/run-experiment.sh
#
# Tunables via env (quick-validation defaults; raise for a full run):
#   HOST (192.168.56.102) PER_CONTAINER (300) MEASURE_CONC (8) BENIGN (40) ATK_CLOSING (10) ATK_PERSIST (6)
#   REDOS_PERSIST_N (30) INLOOP_CLOSING_MS (2500) HEARTBEAT_S (0.5) HOLD_S (12)
#   K (4) TAU_MIN_MS (5)
set -euo pipefail
cd "$(dirname "$0")/.."

# Connect via the VM's LAN IP, NOT 127.0.0.1: loopback goes through docker-proxy, which
# opens a SEPARATE socket to the container, so the client port the generator records would
# not match the one the tracer sees inside the container (the dport join breaks). Traffic to
# the LAN IP goes through iptables DNAT, which preserves the client source port into the
# container -- the same path external (Kali) traffic takes.
HOST=${HOST:-192.168.56.102}
PER_CONTAINER=${PER_CONTAINER:-300}; MEASURE_CONC=${MEASURE_CONC:-8}
BENIGN=${BENIGN:-40}; ATK_CLOSING=${ATK_CLOSING:-10}; ATK_PERSIST=${ATK_PERSIST:-6}
REDOS_PERSIST_N=${REDOS_PERSIST_N:-30}; INLOOP_CLOSING_MS=${INLOOP_CLOSING_MS:-2500}
HEARTBEAT_S=${HEARTBEAT_S:-0.5}; HOLD_S=${HOLD_S:-12}
K=${K:-4}; TAU_MIN_MS=${TAU_MIN_MS:-5}
mkdir -p data

# Kill any orphaned tracer/generator from an interrupted run, and make sure every container
# is actually serving (a previous unbounded /vulnerable can wedge single-threaded Node) by
# restarting the testbed. Restart changes cgroup ids, but start_tracer resolves them fresh.
pkill -x codax_tracer 2>/dev/null || true
pkill -f 'attacker/gen.py' 2>/dev/null || true
echo "=== PHASE 0: (re)start testbed so all containers respond ==="
( cd testbed && docker compose restart )
sleep 2

start_tracer() {  # $1 = output events file
    mapfile -t CGIDS < <(scripts/cgids.sh | awk '{print $1}')
    [ "${#CGIDS[@]}" -gt 0 ] || { echo "no containers; start testbed first" >&2; exit 1; }
    ./bin/codax_tracer "${CGIDS[@]}" > "$1" 2>data/tracer.log &
    TRACER_PID=$!
    sleep 1   # let probes attach before traffic starts
}
stop_tracer() { kill -INT "$TRACER_PID" 2>/dev/null || true; wait "$TRACER_PID" 2>/dev/null || true; }

echo "=== PHASE 1: measure capture (benign only -> thresholds) ==="
start_tracer data/measure_events.jsonl
python3 attacker/gen.py --host "$HOST" --phase measure --labels data/labels_measure.jsonl \
    --per-container "$PER_CONTAINER" --measure-concurrency "$MEASURE_CONC"
stop_tracer
echo "  measure events: $(wc -l < data/measure_events.jsonl)"

echo "=== PHASE 2: test capture (benign + attacks) ==="
start_tracer data/test_events.jsonl
python3 attacker/gen.py --host "$HOST" --phase test --labels data/labels_test.jsonl \
    --benign "$BENIGN" --attack-closing "$ATK_CLOSING" --attack-persistent "$ATK_PERSIST" \
    --redos-persist-n "$REDOS_PERSIST_N" --inloop-closing-ms "$INLOOP_CLOSING_MS" \
    --heartbeat-s "$HEARTBEAT_S" --hold-s "$HOLD_S"
stop_tracer
echo "  test events: $(wc -l < data/test_events.jsonl)"

echo "=== PHASE 3: analysis ==="
python3 analysis/analyze.py --measure data/measure_events.jsonl --test data/test_events.jsonl \
    --labels data/labels_test.jsonl -k "$K" --tau-min-ms "$TAU_MIN_MS"
