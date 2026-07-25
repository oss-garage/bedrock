#!/usr/bin/env bash
# Bedrock coverage for the RaceBench corpus, via FORK-BASED fuzzing: how many of
# the 60 injected bugs the concurrency-fuzz scheduler reaches UNDER bedrock
# (single vCPU, emulated TSC, thread-fuzz SCHED_EXT). Counterpart to baseline.sh:
# run the two and compare TOTALs.
#
# WHY FORK (not cold boot per seed). The strict late-inject abort (a late
# APIC-timer delivery aborts the run) fires during EARLY BOOT, so cold-booting a
# fresh guest per seed is no longer viable. Instead we boot ONE parent guest to
# the post-boot ready checkpoint and hold it there, then fork a re-seeded child
# per seed off it (copy-on-write):
#   - the expensive boot (kernel + podman + image load) is paid ONCE and shared;
#   - the early-boot late injects happen only in the throwaway parent, which
#     tolerates them (BEDROCK_IGNORE_LATE_INJECT=1, set by the parent app);
#   - each scored child runs STRICT, so a late inject inside a real schedule
#     aborts and is caught (logged here as a LATE-INJECT ABORT) rather than
#     silently diverging.
#
# A child's schedule is a pure function of its child seed (the getrandom stream
# the in-kernel fuzzing scheduler draws), exactly as a cold boot's was, so
# coverage still comes from sweeping the CHILD seed across forks, not from
# re-running one seed. Because it is deterministic, this sweep needs no reps:
# re-running the same (boot_seed, child-seed range) reproduces byte-identical
# coverage. The repro of a triggered bug is (target, input, boot_seed, child_seed).
#
# Each fork runs the full corpus (all three targets) once and prints one line per
# target to serial:
#   "<name>: BUG TRIGGERED (rc=134) bug_ids: 3 7"   or   "<name>: no trigger ..."
# We union bug_ids per target across forks and plateau per target, exactly like
# baseline.sh -- same PLATEAU/MAX semantics so the numbers are comparable.
#
# Prerequisites (run this ON THE HOST where bedrock is loaded, e.g. galactus):
#   - bedrock module loaded (lsmod | grep bedrock) and /dev/bedrock present
#   - workload image built: cd .. && ./build.sh
#   - the seed knobs drive bedrock-cli -s: BOOT_SEED for the parent boot,
#     RDRAND_SEED for each child fork (see the fork apps in flake.nix).
#
# Usage (capture to a dated, host-tagged file like the baseline does):
#   ./bedrock.sh 2>&1 | tee "bedrock-$(hostname -s)-$(date +%F).txt"
#
# WARNING: PLATEAU=500 is still many forks; a fork is far cheaper than a cold
# boot (no Linux boot) but not free. Start small to sanity check, e.g.
# PLATEAU=20 MAX=100 ./bedrock.sh, then raise for the real number.
#
# Env knobs:
#   SEED_BASE   first CHILD seed; fork i uses SEED_BASE + (i-1)      (default 1)
#   BOOT_SEED   parent boot seed; fixes the one-time throwaway boot  (default 0)
#   PLATEAU     stop a target after this many forks add no new bug   (default 500)
#   MAX         hard cap on forks                                    (default 20000)
#   PARENT_READY_TIMEOUT  seconds to wait for the parent to reach
#               the ready checkpoint before giving up               (default 300)
set -euo pipefail
cd "$(dirname "$0")"

REPO_ROOT=$(cd ../../.. && pwd)     # scripts -> racebench -> workloads -> repo root
SEED_BASE="${SEED_BASE:-1}"         # first CHILD seed; fork i uses SEED_BASE + (i-1)
BOOT_SEED="${BOOT_SEED:-0}"         # parent boot seed (one-time throwaway boot)
PLATEAU="${PLATEAU:-500}"           # stop a target after this many forks add no new bug
MAX="${MAX:-20000}"                 # hard cap on forks
PARENT_READY_TIMEOUT="${PARENT_READY_TIMEOUT:-300}"
PREEMPT_PERIOD="${BEDROCK_PREEMPT_PERIOD:-0}"   # forced-preempt period per child (retired instrs); 0=off
TARGETS=(blackscholes streamcluster fluidanimate)

# Capture lsmod and string-match it, rather than `lsmod | grep -q`: under
# `set -o pipefail`, grep -q exits at the first match and SIGPIPEs lsmod (whose
# freshly-insmod'd bedrock line is at the top), and pipefail then propagates that
# non-zero status - so the check spuriously fails even when the module IS loaded.
lsmod_out=$(lsmod 2>/dev/null || true)
case "$lsmod_out" in
  *bedrock*) : ;;
  *)
    echo "ERROR: bedrock module not loaded (lsmod | grep bedrock). Run this on the host where bedrock is loaded." >&2
    exit 1
    ;;
esac
if [ ! -f "$REPO_ROOT/workloads/racebench/images.tar" ]; then
  echo "ERROR: images.tar not found. Build it first: cd .. && ./build.sh" >&2
  exit 1
fi

# --- Build fingerprint ------------------------------------------------------
# A repro is (guest build, boot_seed, child_seed), not just the seeds. The guest
# kernel + initrd are byte-reproducible (nix), but a change under crates/
# legitimately produces a different guest, so record what this sweep ran against:
# the resolved store paths (content-exact even on a dirty tree), the workload
# image hash, and the bedrock commit. A later repro asserts these match; a
# mismatch means "different guest," not "flaky." `nix eval` resolves the paths
# without building (they were already built to run). Printed to stdout so it
# lands in the tee'd result file as a self-contained header.
commit=$(cd "$REPO_ROOT" && git rev-parse --short=12 HEAD 2>/dev/null || echo unknown)
[ -n "$(cd "$REPO_ROOT" && git status --porcelain 2>/dev/null)" ] && commit="$commit+dirty"
guest_kernel=$(cd "$REPO_ROOT" && nix eval --raw .#guestKernel.outPath 2>/dev/null || echo unknown)
guest_initrd=$(cd "$REPO_ROOT" && nix eval --raw .#podmanInitrd.outPath 2>/dev/null || echo unknown)
img_sha=$(sha256sum "$REPO_ROOT/workloads/racebench/images.tar" 2>/dev/null | cut -c1-16)
echo "--- guest-build: commit=$commit images.tar=sha256:$img_sha ---"
echo "--- guest-build: kernel=$guest_kernel ---"
echo "--- guest-build: initrd=$guest_initrd ---"

# --- Boot the fork parent once and capture its vm_id ------------------------
# The parent app boots to the ready checkpoint and HOLDS there (bedrock-cli
# --wait) tolerating early-boot late injects; children fork off its frozen,
# copy-on-write state. We run it in the background, tail its log for the
# "vm_id=N" line the CLI prints at the ready checkpoint, then fork children off N.
parent_log=$(mktemp)
parent_pid=""
cleanup() {
  # Release the held parent so its VM is freed (bedrock-cli's Ctrl-C handler on
  # SIGINT, or plain process exit -> fd close -> the kernel drops the VM).
  # SIGINT-ing the background subshell may not reach the bedrock-cli grandchild
  # under `nix run`, so also target the held parent directly: the `--wait` flag
  # uniquely marks it (child forks never use --wait). No child fork is running
  # during EXIT cleanup, so this cannot hit a scored fork.
  [ -n "$parent_pid" ] && kill -INT "$parent_pid" 2>/dev/null || true
  pkill -INT -f 'bedrock-cli.*--wait' 2>/dev/null || true
  [ -n "$parent_pid" ] && wait "$parent_pid" 2>/dev/null || true
  rm -f "$parent_log"
}
trap cleanup EXIT INT TERM

echo "--- booting fork parent (boot_seed=$BOOT_SEED); tolerating early-boot late injects ---" >&2
( cd "$REPO_ROOT" && BOOT_SEED="$BOOT_SEED" nix run .#test-racebench-fork-parent >"$parent_log" 2>&1 ) &
parent_pid=$!

PARENT_ID=""
deadline=$(( $(date +%s) + PARENT_READY_TIMEOUT ))
while [ "$(date +%s)" -lt "$deadline" ]; do
  if ! kill -0 "$parent_pid" 2>/dev/null; then
    echo "ERROR: fork parent exited before reaching the ready checkpoint. Parent log:" >&2
    cat "$parent_log" >&2
    exit 1
  fi
  # The CLI logs "... vm_id=N" at the ready checkpoint. Take the first match.
  PARENT_ID=$(sed -n 's/.*vm_id=\([0-9][0-9]*\).*/\1/p' "$parent_log" | head -1)
  [ -n "$PARENT_ID" ] && break
  sleep 1
done
if [ -z "$PARENT_ID" ]; then
  echo "ERROR: fork parent did not reach the ready checkpoint within ${PARENT_READY_TIMEOUT}s. Parent log:" >&2
  cat "$parent_log" >&2
  exit 1
fi
echo "--- fork parent ready: vm_id=$PARENT_ID (boot_seed=$BOOT_SEED) ---" >&2

declare -A reached                  # target -> space-separated union of bug ids
declare -A noNew                    # target -> consecutive forks with no new bug
for t in "${TARGETS[@]}"; do reached[$t]=""; noNew[$t]=0; done

echo "--- bedrock coverage (fork): boot_seed=$BOOT_SEED seed_base=$SEED_BASE plateau=$PLATEAU max=$MAX preempt_period=$PREEMPT_PERIOD ---"

forks=0
aborts=0
while [ "$forks" -lt "$MAX" ]; do
  # Stop once every target has plateaued.
  done_all=1
  for t in "${TARGETS[@]}"; do
    [ "${noNew[$t]}" -lt "$PLATEAU" ] && done_all=0
  done
  [ "$done_all" -eq 1 ] && break

  seed=$((SEED_BASE + forks))
  forks=$((forks + 1))

  # One deterministic fork of the whole corpus off the held parent. A triggered
  # bug aborts a target (rc=134) but the guest logs the line and runs to
  # shutdown, so the child exits 0. A late-inject abort makes the child exit
  # non-zero; capture rc without tripping `set -e`.
  child_rc=0
  out=$(cd "$REPO_ROOT" && BEDROCK_PARENT_ID="$PARENT_ID" RDRAND_SEED="$seed" \
        BEDROCK_PREEMPT_PERIOD="$PREEMPT_PERIOD" \
        nix run .#test-racebench-fork-child 2>&1) || child_rc=$?

  # Classify the fork. `case` (not `printf | grep -q`) avoids the pipefail/SIGPIPE
  # trap noted above.
  case "$out" in
    *"RaceBench workload: OK"*) : ;;
    *"Late-inject abort"*|*"injected late"*)
      # A late inject INSIDE a scored schedule: the child could not be delivered
      # deterministically. This is the signal the strict abort exists to surface
      # -- the schedule is not reproducible, so it contributes no coverage. If
      # these are frequent, the host PEBS margin is too small for the fork regime.
      aborts=$((aborts + 1))
      echo "fork $forks seed $seed: LATE-INJECT ABORT (non-reproducible schedule; rc=$child_rc)" >&2
      ;;
    *)
      echo "fork $forks seed $seed: WARNING fork did not complete cleanly (no OK marker, rc=$child_rc)" >&2
      ;;
  esac

  # Parse "<name>: BUG TRIGGERED (rc=...) bug_ids: 3 7" lines; update per-target
  # union and plateau counters. Targets with no trigger this fork just increment.
  # The guest lines reach us with a console prefix, e.g.
  #   "[vt   28.79] [fuzz] | streamcluster: BUG TRIGGERED (rc=134) bug_ids: 3 7"
  # so match the target name ANYWHERE on the line, not anchored at column 0. An
  # aborted fork simply has no trigger lines and counts as "no new".
  newmsg=""
  for t in "${TARGETS[@]}"; do
    ids=$(printf '%s\n' "$out" | sed -n "s/.*$t: BUG TRIGGERED[^:]*bug_ids:\(.*\)$/\1/p" | tr -s ' \n' ' ')
    newthis=""
    for id in $ids; do
      case " ${reached[$t]} " in
        *" $id "*) : ;;
        *) reached[$t]="${reached[$t]} $id"; newthis="$newthis $id" ;;
      esac
    done
    if [ -n "$newthis" ]; then
      noNew[$t]=0; newmsg="$newmsg ${t}+{${newthis# }}"
    else
      noNew[$t]=$((noNew[$t] + 1))
    fi
  done

  # Per-fork progress to stderr (kept off the stdout summary). `slowest-plateau`
  # is min(noNew) across targets: the sweep ends when it reaches PLATEAU, and it
  # resets to 0 whenever any target finds a new bug. `tail -f` the tee'd log.
  total_now=0; minplat="$PLATEAU"
  for t in "${TARGETS[@]}"; do
    c=$(echo "${reached[$t]}" | wc -w); total_now=$((total_now + c))
    [ "${noNew[$t]}" -lt "$minplat" ] && minplat="${noNew[$t]}"
  done
  [ -n "$newmsg" ] && newmsg=" NEW:$newmsg"
  echo "fork $forks seed $seed: coverage ${total_now}/60; slowest-plateau ${minplat}/${PLATEAU}${newmsg}" >&2
done

total=0
for t in "${TARGETS[@]}"; do
  ids=$(echo "${reached[$t]}" | tr -s ' ' ' ' | sed 's/^ //; s/ $//')
  cnt=$(echo "$ids" | wc -w)
  total=$((total + cnt))
  echo "$t: reached $cnt/20 in $forks forks -> bug_ids: $ids"
done
echo "TOTAL bedrock coverage: $total/60 (boot_seed=$BOOT_SEED, $forks forks, $aborts late-inject aborts)"
