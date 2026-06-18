#!/usr/bin/env bash
# Build the integration-tests workload's container image and pack it into a
# docker-archive tarball at workloads/integration-tests/images.tar. That file
# and compose.yaml are served to the guest at runtime over the file-transmission
# hypercall (the guest's generic initrd downloads them at boot) — the
# integration-tests harness/app serves them via BEDROCK_COMPOSE / BEDROCK_IMAGES.
# See nix/podman-initrd.nix.
#
# Usage:  ./build.sh
#
# Requires a working `docker` daemon (or `podman` with a `docker` shim).

set -euo pipefail
cd "$(dirname "$0")"

DOCKER="${DOCKER:-docker}"

# Stage the shared guest hypercall library (header-only libvmcall.h) into the
# Docker build context. Docker's COPY can't reach files outside the context,
# so the single source at guest/libvmcall.h is copied in here and removed on
# exit — keeping one source of truth instead of a committed dup.
trap 'rm -f ready/libvmcall.h' EXIT
cp ../../guest/libvmcall.h ready/libvmcall.h

$DOCKER build -t bedrock/integration-tests-ready:latest ready/

# Pack into one docker-archive. `podman load` inside the initrd reads the
# embedded manifest to recover the image's name+tag, so the tarball's
# filename is opaque to consumers.
$DOCKER save \
    bedrock/integration-tests-ready:latest \
    -o images.tar

echo
echo "Wrote $(pwd)/images.tar ($(du -h images.tar | cut -f1))"
