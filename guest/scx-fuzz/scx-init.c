// SPDX-License-Identifier: GPL-2.0
//
// Guest-side init service for the in-kernel concurrency-fuzz scheduler.
//
// Loaded once at guest boot (before podman), this service:
//   - opens the BPF skeleton, writes the read-only chaos-mode parameters into
//     rodata, loads it, and attaches the sched_ext struct_ops with
//     SCX_OPS_SWITCH_PARTIAL. From here on the scheduler governs every
//     SCHED_EXT task and leaves all stock tasks on CFS;
//   - drains the ring buffer of scheduler events for the log and runs until
//     terminated by a signal (the guest shuts down via the VMCALL path).
//
// Which tasks are SCHED_EXT is decided by the workload itself: it wraps the
// process it wants fuzzed in thread-fuzz, which switches that process (and its
// descendants) into SCHED_EXT. So this service needs no notion of "which
// cgroup": every task it sees was opted in explicitly.
//
// Determinism: all timestamps printed come from the kernel (bpf_ktime_get_ns),
// which derives from bedrock's deterministic emulated TSC. The schedule is
// driven by getrandom(), which the guest kernel sources from the
// HYPERCALL_GET_RANDOM vmcall — bedrock's controlled, fuzzer-driven stream. No
// wall-clock or host randomness is read here.
//
// Usage: scx-init   (no arguments)

#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "intf.h"
#include "fuzz_bpf.skel.h"

// Fixed chaos-mode parameters (after rr's chaos mode): the workload runs one
// fixed configuration; the schedule is varied only through the randomness pool.
// The base policy is weighted-vtime fair, so there is no timeslice to randomize
// — only the starvation schedule below is tuned.
//
// "Smooth" profile: many short starvation intervals rather than a few multi-
// second bursts. With a small STARVE_MAX the 35% budget is split into frequent
// small freezes, so the cap-recovery gaps shrink and the perturbation is roughly
// continuous; the occasional ~1.5s freeze still lets the concurrency-fuzz demo
// crash. Faster re-rolls keep the victim set drifting between the closer intervals.
#define STARVE_MIN_NS	(50ULL * 1000000)	// 50ms   starvation interval, low
#define STARVE_MAX_NS	(1500ULL * 1000000)	// 1.5s   starvation interval, high
#define GAP_MIN_NS	(100ULL * 1000000)	// 100ms  gap between intervals, low
#define GAP_MAX_NS	(800ULL * 1000000)	// 800ms  gap between intervals, high
#define PRIO_REROLL_NS	(500ULL * 1000000)	// 0.5s   priority re-randomization
#define LOW_PROB_INV	8ULL			// P(low) = 1/8 = 0.125
#define STARVE_CAP_PCT	35ULL			// <= 35% of run time spent starving

static volatile sig_atomic_t stop;

static void on_term(int sig)
{
	(void)sig;
	stop = 1;
}

static int handle_event(void *ctx, void *data, size_t size)
{
	const struct fuzz_event *e = data;
	(void)ctx;

	if (size < sizeof(*e))
		return 0;

	unsigned long long sec = e->time_ns / 1000000000ULL;
	unsigned long long ms = (e->time_ns % 1000000000ULL) / 1000000ULL;

	switch (e->event_type) {
	case FUZZ_EVENT_STARVE_BEGIN:
		printf("[%6llu.%03llu] starvation interval: %llums "
		       "(low-priority threads blocked)\n",
		       sec, ms, e->duration_ns / 1000000ULL);
		break;
	case FUZZ_EVENT_LOW_PRIO:
		printf("[%6llu.%03llu] froze %s (pid %u) for %llums "
		       "(starvation victim)\n",
		       sec, ms, e->comm, e->pid, e->duration_ns / 1000000ULL);
		break;
	case FUZZ_EVENT_DEBUG:
		printf("[%6llu.%03llu] debug: %s (pid %u) governed by scx-fuzz\n",
		       sec, ms, e->comm, e->pid);
		break;
	}
	fflush(stdout);
	return 0;
}

// Read len bytes from getrandom() (the guest kernel sources it from
// HYPERCALL_GET_RANDOM; see intf.h). Loops over short reads. Returns 0/-1.
static int get_random(void *buf, size_t len)
{
	uint8_t *p = buf;

	while (len > 0) {
		long n = syscall(SYS_getrandom, p, len, 0);

		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		p += n;
		len -= (size_t)n;
	}
	return 0;
}

// Scratch buffer holding one half of the pool during a refill (see the poll loop).
#define RND_HALF (RND_POOL_N / 2)
static uint64_t refill_buf[RND_HALF];

// Refill one half of the pool — slots [half*RND_HALF, half*RND_HALF + RND_HALF) —
// with fresh getrandom values. Only ever called for the half the scheduler is NOT
// currently consuming, so the slots being written are never read concurrently.
// Returns 0 on success, -1 on failure.
static int refill_half(int fd, int half)
{
	uint32_t base = (uint32_t)half * RND_HALF;

	if (get_random(refill_buf, sizeof(refill_buf)) != 0)
		return -1;
	for (uint32_t j = 0; j < RND_HALF; j++) {
		uint32_t key = base + j;

		if (bpf_map_update_elem(fd, &key, &refill_buf[j], BPF_ANY) != 0)
			return -1;
	}
	return 0;
}

int main(int argc, char **argv)
{
	(void)argc;
	(void)argv;

	struct fuzz_bpf *skel = fuzz_bpf__open();
	if (!skel) {
		fprintf(stderr, "failed to open BPF skeleton\n");
		return 2;
	}

	// Read-only config must be set before load.
	skel->rodata->starve_min_ns = STARVE_MIN_NS;
	skel->rodata->starve_max_ns = STARVE_MAX_NS;
	skel->rodata->gap_min_ns = GAP_MIN_NS;
	skel->rodata->gap_max_ns = GAP_MAX_NS;
	skel->rodata->prio_reroll_ns = PRIO_REROLL_NS;
	skel->rodata->low_prob_inv = LOW_PROB_INV;
	skel->rodata->starve_cap_pct = STARVE_CAP_PCT;
	skel->rodata->logging = true;
	// Per-task diagnostics: prints each governed task once. Flip to false to
	// quiet the log once the pipeline is confirmed working.
	skel->rodata->debug = true;

	int err = fuzz_bpf__load(skel);
	if (err) {
		fprintf(stderr, "failed to load BPF skeleton: %d\n", err);
		goto cleanup_skel;
	}

	// Fill both halves of the randomness pool from getrandom before attaching,
	// so it is fully populated before the scheduler can consume any of it (no
	// race). The poll loop below refreshes a half at a time from then on.
	int rnd_fd = bpf_map__fd(skel->maps.rnd_pool);
	if (refill_half(rnd_fd, 0) != 0 || refill_half(rnd_fd, 1) != 0) {
		fprintf(stderr, "failed to fill randomness pool\n");
		err = 2;
		goto cleanup_skel;
	}

	// Attaching the sched_ext struct_ops makes our policy the scheduler for
	// SCHED_EXT tasks. Hold the link; dropping it detaches.
	struct bpf_link *link =
		bpf_map__attach_struct_ops(skel->maps.chaos_ops);
	if (!link) {
		fprintf(stderr, "failed to attach sched_ext struct_ops: %d\n",
			-errno);
		err = 2;
		goto cleanup_skel;
	}

	struct ring_buffer *rb =
		ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event,
				 NULL, NULL);
	if (!rb) {
		fprintf(stderr, "failed to create ring buffer\n");
		err = 2;
		goto cleanup_link;
	}

	signal(SIGTERM, on_term);
	signal(SIGINT, on_term);

	// pool[0] is a stable fingerprint of the schedule (the first value drawn).
	uint64_t first = 0;
	uint32_t zero = 0;
	bpf_map_lookup_elem(rnd_fd, &zero, &first);
	printf("scx-fuzz attached (SWITCH_PARTIAL); rnd pool %d, pool[0] %#llx\n",
	       RND_POOL_N, (unsigned long long)first);
	fflush(stdout);

	// Drain with ring_buffer__consume(), not ring_buffer__poll() alone:
	// bpf_ringbuf_submit()'s adaptive wakeup does not reliably fire the epoll
	// notification under bedrock's single-vCPU execution, so poll() would leave
	// events unread. poll() here only paces the loop (~100ms); consume() then
	// force-drains everything pending.
	//
	// Between drains, refresh the pool a half at a time (see intf.h for why).
	// rnd_idx sweeps half 0, then half 1, then wraps; when it crosses into a half
	// we refill the one it just left, so the slots being written are never the
	// ones the scheduler is reading. At ~10 refills/s against a few draws/s the
	// next half is always fresh before the scheduler reaches it.
	int last_half = 0;
	while (!stop) {
		ring_buffer__poll(rb, 100 /* ms pacing */);
		ring_buffer__consume(rb);

		int half = (skel->bss->rnd_idx & (RND_POOL_N - 1)) >= RND_HALF ? 1 : 0;
		if (half != last_half) {
			refill_half(rnd_fd, last_half);
			last_half = half;
		}
	}

	err = 0;
	ring_buffer__free(rb);
cleanup_link:
	bpf_link__destroy(link);
cleanup_skel:
	fuzz_bpf__destroy(skel);
	return err;
}
