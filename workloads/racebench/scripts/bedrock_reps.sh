#!/usr/bin/env bash
# Run bedrock.sh REPS times, saving each rep to its own file so the spread of the
# bedrock coverage number can be seen. Files are named:
#
#   bedrock-<host>-<date>-run<NN>.txt
#
# The counterpart to baseline_reps.sh, but the reason for reps is DIFFERENT.
# baseline_reps.sh reruns the *same* config to average out the host scheduler's
# nondeterminism. Under bedrock there is no nondeterminism: rerunning the same
# (boot_seed, child-seed range) reproduces byte-identical coverage, so plain reps
# would just write N identical files. What actually varies is WHICH schedules you
# sample. Since bedrock.sh is now fork-based, a schedule is the pair (boot_seed,
# child_seed), so each rep here varies BOTH:
#   - a distinct parent BOOT_SEED (rep i uses BOOT_SEED_BASE + (i-1)), so reps
#     sample different boot regimes (the parent's one-time boot the children
#     fork off), and
#   - a DISJOINT child-seed window (rep i sweeps [1 + (i-1)*MAX, ...)),
#     non-overlapping because a single bedrock.sh run forks at most MAX times.
# The reps then answer: is the coverage number stable across independent
# (boot_seed, child-seed-window) samples, or does it depend on which you picked?
#
# Usage:
#   ./bedrock_reps.sh                    # 10 reps, distinct regimes + windows
#   REPS=5 ./bedrock_reps.sh             # 5 reps
#   PLATEAU=100 ./bedrock_reps.sh        # shorter runs (passed through)
#   MAX=5000 ./bedrock_reps.sh           # smaller windows AND per-rep seed stride
#   BOOT_SEED_BASE=1000 ./bedrock_reps.sh  # shift the parent boot regimes
#
# This is a LONG, unattended job (each rep is a full bedrock.sh plateau sweep,
# which boots a fresh parent then forks it many times). Run it detached:
#   tmux new -s bedrock-reps   # paste this; detach with Ctrl-b d
#
# Each rep is independent: a failed rep is logged to its file (stderr captured)
# and the batch continues, so one transient boot error does not abort the run.
set -u
cd "$(dirname "$0")"

REPS="${REPS:-10}"
MAX="${MAX:-20000}"                  # hard cap on forks per rep AND per-rep seed stride
BOOT_SEED_BASE="${BOOT_SEED_BASE:-0}"  # rep i parent boot seed = BOOT_SEED_BASE + (i-1)
host=$(hostname -s)
date=$(date +%F)

export MAX                           # pass through to bedrock.sh (and reuse as the stride)

for i in $(seq -w 1 "$REPS"); do
  # 10#$i strips any leading zero so arithmetic is base-10, not octal.
  n=$((10#$i))
  base=$(( (n - 1) * MAX + 1 ))      # disjoint child-seed window per rep (rep forks <= MAX times)
  boot=$(( BOOT_SEED_BASE + n - 1 )) # distinct parent boot regime per rep
  echo "=== rep $i/$REPS: boot_seed=$boot child-seed window [$base, $((base + MAX - 1))] ==="
  BOOT_SEED="$boot" SEED_BASE="$base" ./bedrock.sh 2>&1 | tee "bedrock-$host-$date-run$i.txt"
done

echo "=== done: $REPS reps -> $(ls bedrock-$host-$date-run*.txt 2>/dev/null | wc -l) files ==="
