# syntax=docker/dockerfile:1
#
# RaceBench workload image: real concurrent programs (PARSEC kernels) with
# pre-injected, self-observing concurrency bugs, plus the VMCALL ready/shutdown
# helper.
#
# Each target under targets/<name>/ is built FROM SOURCE here (we never ship or
# trust RaceBench's prebuilt binaries). When a bug's specific interleaving fires,
# the injected RaceBench harness calls abort() (SIGABRT) and records the bug id
# in a stat file - so the crash is self-observable with no external race
# detector. Under bedrock's single vCPU + emulated TSC the interleaving is a pure
# function of the getrandom stream, so a trigger reproduces from a fixed seed.
#
# The fuzzing scheduler is NOT in this image: sched_ext BPF + scx-init are guest
# infra loaded at boot, and thread-fuzz is bind-mounted into every container by
# the guest (see nix/podman-initrd.nix). run.sh opts a target in by wrapping it
# in thread-fuzz. Same contract as the concurrency-fuzz workload.
#
# Build context is this directory (fuzz/); build.sh stages guest/libvmcall.h in.

FROM debian:trixie AS build

RUN apt-get update && apt-get install -y --no-install-recommends \
      gcc g++ make libc6-dev \
 && rm -rf /var/lib/apt/lists/*

# Build every RaceBench target from source using its own (unmodified) Makefile,
# then stage the binary, its runtime inputs, and its command line into /out.
# The per-target Makefile compiles the instrumented program together with
# racebench.c / racebench_bugs.c and links them into racebench/<name>.
COPY targets/ /build/targets/
RUN set -eux; \
    for p in blackscholes streamcluster fluidanimate; do \
      ( cd "/build/targets/$p/code" && make && make install ); \
      install -Dm755 "/build/targets/$p/code/racebench/$p" "/out/bin/$p"; \
      install -Dm644 "/build/targets/$p/code/command.txt"  "/out/share/$p/command.txt"; \
      cp -r "/build/targets/$p/input"                      "/out/share/$p/input"; \
    done

# VMCALL ready/shutdown helper (same header-only libvmcall.h as other workloads).
WORKDIR /src
COPY vmcall.c libvmcall.h ./
RUN gcc -O2 -static -o /out/bin/bedrock-vmcall vmcall.c

FROM debian:trixie-slim
COPY --from=build /out/bin/   /usr/local/bin/
COPY --from=build /out/share/ /usr/local/share/rb/
COPY run.sh /usr/local/bin/run.sh
RUN chmod +x /usr/local/bin/run.sh
ENTRYPOINT ["/usr/local/bin/run.sh"]
