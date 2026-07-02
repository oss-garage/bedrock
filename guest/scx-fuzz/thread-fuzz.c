// SPDX-License-Identifier: GPL-2.0
//
// Opt a command, and every process it spawns, into the in-kernel
// concurrency-fuzz scheduler by running it under SCHED_EXT.
//
// Usage: thread-fuzz <command> [args...]
//
// thread-fuzz sets its OWN scheduling policy to SCHED_EXT and then execs the
// given command. Scheduling policy is inherited across fork/exec, so every
// descendant of the command is governed by the fuzzing scheduler too, with no
// per-process opt-in. This is the manual-registration path used while we
// dogfood the scheduler: a workload opts in by wrapping the process it wants
// fuzzed, e.g. `thread-fuzz /usr/local/bin/queue`, and leaves everything else
// on the stock scheduler.
//
// It execs the target directly, so nothing in between resets the scheduling
// policy and plain inheritance suffices.
//
// The scheduler must already be attached (scx-init, at boot) with
// SCX_OPS_SWITCH_PARTIAL, so only the SCHED_EXT tasks thread-fuzz creates are
// governed while everything else stays on the stock scheduler. Setting
// SCHED_EXT needs CAP_SYS_NICE; the fuzzed workload's container runs privileged.
//
// Determinism is unchanged: the schedule is drawn from bedrock's getrandom
// stream (see scx-init.c), a pure function of the fuzzer input under the single
// vCPU + emulated TSC.

#define _GNU_SOURCE
#include <errno.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef SCHED_EXT
#define SCHED_EXT 7
#endif

int main(int argc, char **argv)
{
	struct sched_param p = { .sched_priority = 0 };

	if (argc < 2) {
		fprintf(stderr, "usage: %s <command> [args...]\n", argv[0]);
		return 2;
	}

	// Raw syscall, not the glibc wrapper: some libc versions reject an
	// unknown policy value (SCHED_EXT == 7) before the syscall.
	if (syscall(SYS_sched_setscheduler, 0, SCHED_EXT, &p) != 0) {
		fprintf(stderr, "thread-fuzz: sched_setscheduler(SCHED_EXT): %s\n",
			strerror(errno));
		return 1;
	}

	// Descendants inherit SCHED_EXT; only returns here if exec fails.
	execvp(argv[1], &argv[1]);

	fprintf(stderr, "thread-fuzz: exec %s: %s\n", argv[1], strerror(errno));
	return 127;
}
