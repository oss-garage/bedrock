/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Structures shared between the in-kernel BPF scheduler (main.bpf.c) and the
 * user-space init service (scx-init.c). scx-init.c includes this header
 * directly, so it has to be valid both as BPF C (where the fixed width types
 * come from vmlinux.h) and as plain C for the service (where we define them
 * ourselves below).
 */
#ifndef __INTF_H
#define __INTF_H

/*
 * vmlinux.h (included by the BPF program via scx/common.bpf.h) already defines
 * these. When this header is parsed on its own, e.g. by the user-space service,
 * vmlinux.h is absent, so define them here.
 */
#ifndef __VMLINUX_H__
typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;
#endif /* __VMLINUX_H__ */

/* Task comm is TASK_COMM_LEN (16) in the kernel. */
#define FUZZ_COMM_LEN 16

/*
 * Size of the scheduler's randomness pool. scx-init fills it from the getrandom
 * vmcall and the BPF scheduler consumes one value per random decision, in order.
 * This gives the fuzzer positional control: input position k feeds the k-th
 * scheduling decision, so mutating a late decision does not perturb earlier ones
 * (unlike a single seed fed through a PRNG). The pool is consumed in two halves;
 * scx-init refreshes each half from getrandom as soon as the scheduler moves on
 * to the other, so draws stay fresh and positional for the whole run (no reuse).
 * Must be a power of two (the BPF side masks the index).
 */
#define RND_POOL_N 4096

enum fuzz_event_type {
	FUZZ_EVENT_STARVE_BEGIN = 0,	/* a starvation interval began; duration_ns = length */
	FUZZ_EVENT_LOW_PRIO = 1,	/* a low-prio victim thread was frozen (parked); duration_ns = freeze length */
	/* Diagnostic (gated by the debug flag): a governed task seen on the
	 * enqueue path. duration_ns carries the pid. */
	FUZZ_EVENT_DEBUG = 2,
};

/*
 * One scheduler event, pushed to user space over a ring buffer so
 * scx-init can print the log lines. This is purely diagnostic: the scheduling
 * decision itself never leaves the kernel.
 */
struct fuzz_event {
	u64 time_ns;	  /* bpf_ktime_get_ns() at the transition */
	u64 duration_ns;  /* how long the new state lasts */
	u32 pid;
	u32 event_type;	  /* enum fuzz_event_type */
	char comm[FUZZ_COMM_LEN];
};

#endif /* __INTF_H */
