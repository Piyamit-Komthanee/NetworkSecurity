#!/usr/bin/env bash
# Run the ReDoS timing probe inside the redos container. Run as root:
#   SUDO_ASKPASS=~/.config/codax/askpass.sh sudo -A bash scripts/probe-redos.sh
set -euo pipefail
cd "$(dirname "$0")/.."
docker exec -i codax_redos python < scripts/redos_probe.py
