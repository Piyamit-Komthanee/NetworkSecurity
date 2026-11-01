#!/usr/bin/env bash
# Launch the CODAX tracer for the 3 running containers, writing events as JSONL.
# Usage (as root):  sudo scripts/run-tracer.sh [output.jsonl]
set -euo pipefail

cd "$(dirname "$0")/.."
OUT="${1:-data/events.jsonl}"
mkdir -p "$(dirname "$OUT")"

# Resolve cgroup ids and also save the cgid -> name mapping for the analyzer.
mapfile -t ROWS < <(scripts/cgids.sh)
if [ "${#ROWS[@]}" -eq 0 ]; then
    echo "no containers found; start them with: docker compose -f testbed/docker-compose.yml up -d" >&2
    exit 1
fi

CGIDS=()
: > data/cgid_map.txt
for row in "${ROWS[@]}"; do
    cgid=${row%% *}; name=${row#* }
    CGIDS+=("$cgid")
    echo "$row" >> data/cgid_map.txt
    echo "mapping: $name -> cgid $cgid"
done

echo "writing events to $OUT (Ctrl-C to stop)"
exec ./bin/codax_tracer "${CGIDS[@]}" > "$OUT"
