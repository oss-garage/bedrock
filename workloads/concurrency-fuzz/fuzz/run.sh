#!/bin/sh
# Entrypoint for the concurrency-fuzz workload.
#
#   1. Signal the VM ready (takes the boot checkpoint).
#   2. Run the producer/consumer sample under thread-fuzz until it crashes (the
#      expected outcome).
#   3. Shut the VM down so the run terminates deterministically.
#
# The in-kernel fuzzing scheduler is loaded by the guest at boot (scx-init). We
# opt `queue` into it explicitly by wrapping it in thread-fuzz, which switches
# itself to SCHED_EXT and then execs queue; queue and its threads inherit
# SCHED_EXT and are governed by the fuzzing scheduler, while everything else
# stays on the stock scheduler. thread-fuzz is bind-mounted into the container
# by the guest (see nix/podman-initrd.nix). Under bedrock's single vCPU +
# emulated TSC the schedule is a pure function of the getrandom stream bedrock
# serves; vary that stream to prove the crash time depends on it (determinism
# negative control).
set -eu

bedrock-vmcall --ready

# queue aborts (non-zero / SIGABRT) once the fuzzing scheduler starves its
# consumer long enough for an item to go stale: the success condition for a
# fuzz run. rc=0 default, then capture any non-zero via `||` so `set -e` doesn't
# abort us on the expected crash before we can log it and shut down.
rc=0
thread-fuzz /usr/local/bin/queue || rc=$?
echo "queue exited rc=$rc (rc=1 is the expected stale-item crash)"

# queue's crash line ("Item is invalid! age ...") travels an async pipeline
# (stderr -> conmon -> journald -> journalctl -> hvc0). The shutdown VMCALL
# below halts the VM the moment it is issued, so without a pause the last line
# can be dropped before it reaches the console. Yield the single vCPU briefly so
# the journal drains first. nanosleep is driven by the emulated TSC, so the
# drain window is deterministic.
sleep 0.5

bedrock-vmcall
