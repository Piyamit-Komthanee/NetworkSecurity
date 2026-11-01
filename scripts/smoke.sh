#!/usr/bin/env bash
# Smoke test: start the tracer, generate a few connections, show captured events.
# Run as root:  sudo -A scripts/smoke.sh
set -euo pipefail
cd "$(dirname "$0")/.."

OUT=data/smoke.jsonl
echo "[1] container -> cgid mapping:"
scripts/cgids.sh | tee data/cgid_map.txt

echo "[2] starting tracer for ~15s..."
mapfile -t CGIDS < <(scripts/cgids.sh | awk '{print $1}')
./bin/codax_tracer "${CGIDS[@]}" > "$OUT" 2>data/tracer.log &
TR=$!
sleep 3

echo "[3] generating traffic:"
echo "  redos /safe:    $(curl -s -m 5 localhost:8001/safe || echo ERR)"
echo "  baseline /safe: $(curl -s -m 5 localhost:8003/safe || echo ERR)"
echo "  inloop 1.5s:    $(curl -s -m 5 'localhost:8002/vulnerable?ms=1500' || echo ERR)"
echo "  redos n=22:     $(curl -s -m 10 'localhost:8001/vulnerable?n=22' || echo ERR)"
sleep 2

kill -INT $TR 2>/dev/null || true
wait $TR 2>/dev/null || true

echo "[4] captured events ($(wc -l < "$OUT") lines):"
cat "$OUT"
echo "[5] tracer log:"; cat data/tracer.log
