#!/usr/bin/env bash
# Build the bitcoin workload's container images and pack them into a single
# docker-archive tarball at workloads/bitcoin/images.tar. Hand that file
# (along with compose.yaml) to mkPodmanInitrd in flake.nix to bake them
# into a bootable bedrock initramfs.
#
# Usage:  ./build.sh
#
# Requires a working `docker` daemon (or `podman` with a `docker` shim).

set -euo pipefail
cd "$(dirname "$0")"

DOCKER="${DOCKER:-docker}"

# Vanilla upstream image (used by bitcoind1 + bitcoind2, and as the FROM for
# the miner image).
$DOCKER pull docker.io/bitcoin/bitcoin:latest

# Stage the shared guest hypercall library (header-only libvmcall.h) into each
# Docker build context. Docker's COPY can't reach files outside the build
# context, so the single source at guest/libvmcall.h is copied in here and
# removed on exit — keeping one source of truth instead of committed dupes.
trap 'rm -f miner/libvmcall.h shutdown/libvmcall.h' EXIT
cp ../../guest/libvmcall.h miner/libvmcall.h
cp ../../guest/libvmcall.h shutdown/libvmcall.h

# Workload-specific images with bedrock binaries baked in.
$DOCKER build -t bedrock/bitcoin-miner:latest miner/
$DOCKER build -t bedrock/shutdown:latest      shutdown/

# Pack all three into one docker-archive. `podman load` inside the initrd
# reads the embedded manifest to recover each image's name+tag, so the
# tarball's filename is opaque to consumers.
$DOCKER save \
    docker.io/bitcoin/bitcoin:latest \
    bedrock/bitcoin-miner:latest \
    bedrock/shutdown:latest \
    -o images.tar

echo
echo "Wrote $(pwd)/images.tar ($(du -h images.tar | cut -f1))"
