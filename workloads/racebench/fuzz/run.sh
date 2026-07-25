#!/bin/sh
# Entrypoint for the RaceBench workload.
#
#   1. Signal the VM ready (takes the boot checkpoint).
#   2. Run each RaceBench target under thread-fuzz. Each is a real concurrent
#      program with pre-injected concurrency bugs; when a bug's interleaving
#      fires, the injected harness prints "RaceBench crashes deliberately." and
#      abort()s (SIGABRT, rc=134), recording the bug id in its stat file. So a
#      triggered bug is self-observable - no TSan or external detector.
#   3. Shut the VM down so the run terminates deterministically.
#
# The in-kernel fuzzing scheduler is loaded by the guest at boot (scx-init). We
# opt each target into it by wrapping it in thread-fuzz (bind-mounted into the
# container by the guest), which switches itself to SCHED_EXT and execs the
# target; the target and its threads inherit SCHED_EXT and are governed by the
# fuzzing scheduler. Under bedrock's single vCPU + emulated TSC the schedule is a
# pure function of the getrandom stream bedrock serves, so a trigger reproduces
# from a fixed seed; vary the seed across boots to explore interleavings (the
# fuzzing loop, exactly as the concurrency-fuzz workload does for queue.c).
#
# A single boot runs the small corpus once under one schedule. Most seeds will
# NOT trigger (the bug needs its specific interleaving) - a clean rc=0 is the
# expected "no bug this seed" outcome. The stat file (RACEBENCH_STAT) records
# which of a target's 20 injected bugs fired, for offline scoring.
set -eu

RB=/usr/local/share/rb
BIN=/usr/local/bin

bedrock-vmcall --ready

for name in blackscholes streamcluster fluidanimate; do
	input="$RB/$name/input/input-0"

	# Build argv from the target's command.txt: substitute {install_dir} and
	# {input_file}. RaceBench reads the input file as argv[2] (see racebench.h).
	args=$(sed "s#{install_dir}#$BIN#g; s#{input_file}#$input#g" "$RB/$name/command.txt" | tr '\n' ' ')

	echo "=== racebench: $name ==="
	stat="/tmp/$name.rb_stat"
	# rc=0 default; capture any non-zero (rc=134 SIGABRT is a triggered bug) via
	# `||` so `set -e` does not abort us before we can log it.
	rc=0
	RACEBENCH_STAT="$stat" thread-fuzz $args >/dev/null || rc=$?

	# Decode which of the 20 injected bugs fired. The stat file is a packed
	# racebench_statis: u64 total_run, then u64 trigger_num[20] at byte offset 8.
	# trigger_num[i] != 0 means bug i triggered this run.
	bugs=""
	if [ -f "$stat" ]; then
		i=0
		for v in $(od -An -v -tu8 -j 8 -N 160 "$stat" 2>/dev/null | tr -s ' \n' ' '); do
			if [ "$v" -gt 0 ] 2>/dev/null; then bugs="$bugs $i"; fi
			i=$((i + 1))
		done
	fi

	if [ -n "$bugs" ]; then
		echo "$name: BUG TRIGGERED (rc=$rc) bug_ids:$bugs"
	else
		echo "$name: no trigger this seed (rc=$rc)"
	fi
done

# The trigger line travels an async pipeline (stderr -> conmon -> journald ->
# journalctl -> hvc0). The shutdown VMCALL halts the VM the moment it is issued,
# so yield the single vCPU briefly to let the journal drain first. nanosleep is
# driven by the emulated TSC, so the drain window is deterministic.
sleep 0.5

bedrock-vmcall
