#!/usr/bin/env bash
# Live eBPF monitor: stream accept/close events from the 3 containers to the screen,
# continuously, until you press Ctrl-C -- like a "tcpdump/wireshark for container
# connections". Unlike smoke.sh it does NOT generate traffic and does NOT stop after a
# fixed time: you drive it yourself from another terminal and watch events appear live.
#
# Run as root (the tracer needs CAP_BPF):   sudo bash scripts/watch.sh
#
# Then, in a SECOND terminal, poke the containers and watch lines show up here, e.g.:
#   curl -s '192.168.56.102:8003/safe'                 # baseline, fast  (~ms)
#   curl -s '192.168.56.102:8001/vulnerable?n=22'      # redos attack    (~1s)
#   curl -s '192.168.56.102:8002/vulnerable?ms=1500'   # inloop attack   (1.5s)
#
# Each line is one event (JSON). The number to watch is "elapsed_ns": benign requests are
# in the millions (a few ms), attacks are in the billions (~seconds).
set -euo pipefail
cd "$(dirname "$0")/.."

echo "=== container -> cgroup id mapping ==="
scripts/cgids.sh | tee data/cgid_map.txt
echo

mapfile -t CGIDS < <(scripts/cgids.sh | awk '{print $1}')
[ "${#CGIDS[@]}" -gt 0 ] || { echo "no containers running; start them with: (cd testbed && sudo docker compose up -d)" >&2; exit 1; }

echo "=== live events (Ctrl-C to stop) ==="
echo "watching cgids: ${CGIDS[*]}"
echo "open a second terminal and curl the containers to see events appear below:"
echo "  curl -s '192.168.56.102:8003/safe'               # benign  -> elapsed in millions (ms)"
echo "  curl -s '192.168.56.102:8001/vulnerable?n=22'    # attack  -> elapsed in billions (~1s)"
echo "-----------------------------------------------------------------------------------------"

# Run the tracer in the FOREGROUND so its JSONL streams straight to this terminal and
# Ctrl-C (SIGINT) stops it cleanly. Errors/log go to stderr (data/tracer.log kept too).
exec ./bin/codax_tracer "${CGIDS[@]}" 2> >(tee data/tracer.log >&2)
