#!/usr/bin/env bash
# Print "<cgid> <container_name>" for each running CODAX container.
# cgroup v2 id (what bpf_get_current_cgroup_id() returns) == inode of the container's cgroup dir.
# Run as root (needs docker + read of /sys/fs/cgroup).
set -euo pipefail

for name in codax_redos codax_inloop codax_baseline; do
    id=$(docker inspect -f '{{.Id}}' "$name" 2>/dev/null) || { echo "warn: $name not running" >&2; continue; }
    # systemd cgroup driver (Docker default here): .../system.slice/docker-<id>.scope
    dir="/sys/fs/cgroup/system.slice/docker-${id}.scope"
    # cgroupfs driver fallback: .../docker/<id>
    [ -d "$dir" ] || dir="/sys/fs/cgroup/docker/${id}"
    if [ -d "$dir" ]; then
        printf '%s %s\n' "$(stat -c %i "$dir")" "$name"
    else
        echo "warn: cgroup dir not found for $name" >&2
    fi
done
