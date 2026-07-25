#!/usr/bin/env bash
# Run baseline.sh REPS times for each CPU config (single-core `cpuset0` and
# all-cores), saving each run to its own file in this directory so the run-to-run
# spread of the native baseline can be seen. Files are named:
#
#   baseline-<host>-<date>-cpuset0-run<NN>.txt
#   baseline-<host>-<date>-allcores-run<NN>.txt
#
# Usage:
#   ./baseline-reps.sh              # 10 reps of each config (default)
#   REPS=5 ./baseline-reps.sh       # 5 reps of each
#   PLATEAU=100 ./baseline-reps.sh  # shorter runs (passed through to baseline.sh)
#
# This is a LONG, unattended job: single-core streamcluster is ~12s/run x 500
# (PLATEAU) ~= 100 min per cpuset0 rep, so 10 reps is many hours. Run it detached:
#   tmux new -s baseline   # paste this; detach with Ctrl-b d
#
# Note: the single-core (cpuset0) config reaches ~0 bugs (one core -> no thread
# interleavings -> no races), so its reps mostly re-confirm zero; the run-to-run
# variance lives in the all-cores config. To spend less time, run cpuset0 once by
# hand (`CPUSET=0 ./baseline.sh`) and only loop the all-cores config here.
#
# Each rep is independent: a failed rep is logged to its file (stderr is captured)
# and the batch continues, so one transient docker error does not abort the run.
set -u
cd "$(dirname "$0")"

REPS="${REPS:-10}"
host=$(hostname -s)
date=$(date +%F)

for i in $(seq -w 1 "$REPS"); do
  echo "=== rep $i/$REPS: cpuset0 (single-core) ==="
  CPUSET=0 ./baseline.sh 2>&1 | tee "baseline-$host-$date-cpuset0-run$i.txt"
  echo "=== rep $i/$REPS: allcores ==="
           ./baseline.sh 2>&1 | tee "baseline-$host-$date-allcores-run$i.txt"
done

echo "=== done: $REPS reps per config -> $(ls baseline-$host-$date-*-run*.txt 2>/dev/null | wc -l) files ==="
