#!/usr/bin/env bash
# Install the eBPF + Docker toolchain for the CODAX reproduction (Ubuntu 26.04, kernel 7.0).
# Run once:  sudo bash scripts/install-toolchain.sh
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "run with sudo" >&2
    exit 1
fi

TARGET_USER=${SUDO_USER:-vboxuser}

apt-get update

# eBPF build chain: clang compiles *.bpf.c to BPF bytecode, llvm-strip trims debug info,
# libbpf-dev provides the loader library + bpf_helpers.h, libelf/zlib are libbpf's deps.
# bpftool (already installed) generates vmlinux.h and skeleton headers.
apt-get install -y \
    clang llvm libbpf-dev libelf-dev zlib1g-dev \
    build-essential pkg-config make git \
    bpftool bpftrace linux-tools-common "linux-tools-$(uname -r)" "linux-headers-$(uname -r)"

# Containers
apt-get install -y docker.io docker-compose-v2

# Analysis (stats for ADR/FPR/latency, paired t-test, Wilcoxon) + measurement helpers
apt-get install -y python3-numpy python3-scipy python3-pandas python3-matplotlib \
    curl jq sysstat

systemctl enable --now docker
usermod -aG docker "$TARGET_USER"

echo
echo "== versions =="
clang --version | head -1
bpftool version | head -2
bpftrace --version
docker --version
docker compose version
pkg-config --modversion libbpf
echo
echo "Done. Log out and back in (or run 'newgrp docker') so '$TARGET_USER' can use docker without sudo."
