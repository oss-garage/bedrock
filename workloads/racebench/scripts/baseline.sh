#!/usr/bin/env bash
# Native baseline for the RaceBench corpus: how many of the 60 injected bugs the
# host's stock scheduler reaches WITHOUT bedrock (no thread-fuzz, no deterministic
# TSC/getrandom). Runs the identical from-source binaries from the workload image
# inside a container on the bare host, loops until coverage plateaus, and reports
# the union of triggered bug ids per target. This is the control for bedrock's
# concurrency-fuzz coverage: bugs bedrock reaches that this does not are the payoff.
#
# Prerequisite: the workload image must be loaded on this host (see README.md):
#   cd .. && ./build.sh && docker load -i images.tar
#
# Record both baselines:
#   CPUSET=0 ./baseline.sh   # single-core: apples-to-apples vs bedrock's 1 vCPU
#   ./baseline.sh            # all-cores: the realistic host baseline
#
# Container runtime defaults to docker; override with RUNTIME=podman if present.
set -euo pipefail
cd "$(dirname "$0")"

RUNTIME="${RUNTIME:-docker}"
IMAGE="${IMAGE:-bedrock/racebench:latest}"
CPUSET="${CPUSET:-}"               # CPUSET=0 for single-core (apples-to-apples w/ 1 vCPU); empty = all cores
export PLATEAU="${PLATEAU:-500}"   # stop a target after this many runs add no new bug
export MAX="${MAX:-20000}"         # hard cap on attempts per target

cpuset_arg=(); [ -n "$CPUSET" ] && cpuset_arg=(--cpuset-cpus "$CPUSET")

# Inner harness: mirrors run.sh's stat decode, minus thread-fuzz. Single-quoted
# so nothing expands host-side; PLATEAU/MAX come from the container env.
INNER='
set -u
RB=/usr/local/share/rb; BIN=/usr/local/bin; total=0
for name in blackscholes streamcluster fluidanimate; do
  input="$RB/$name/input/input-0"
  args=$(sed "s#{install_dir}#$BIN#g; s#{input_file}#$input#g" "$RB/$name/command.txt" | tr "\n" " ")
  reached=""; noNew=0; runs=0
  while [ "$noNew" -lt "$PLATEAU" ] && [ "$runs" -lt "$MAX" ]; do
    runs=$((runs+1)); stat=$(mktemp)
    RACEBENCH_STAT="$stat" $args >/dev/null 2>&1 || true
    new=0; i=0
    if [ -f "$stat" ]; then
      for v in $(od -An -v -tu8 -j 8 -N 160 "$stat" 2>/dev/null | tr -s " \n" " "); do
        if [ "$v" -gt 0 ] 2>/dev/null; then
          case " $reached " in *" $i "*) : ;; *) reached="$reached $i"; new=1 ;; esac
        fi
        i=$((i+1))
      done
    fi
    rm -f "$stat"
    if [ "$new" -eq 1 ]; then noNew=0; else noNew=$((noNew+1)); fi
  done
  cnt=$(echo $reached | wc -w); total=$((total+cnt))
  echo "$name: reached $cnt/20 in $runs runs -> bug_ids:$reached"
done
echo "TOTAL native baseline: $total/60"
'

echo "--- native baseline: image=$IMAGE cpuset=${CPUSET:-all} plateau=$PLATEAU ---"
exec "$RUNTIME" run --rm "${cpuset_arg[@]}" \
  -e PLATEAU -e MAX --entrypoint /bin/sh "$IMAGE" -c "$INNER"
