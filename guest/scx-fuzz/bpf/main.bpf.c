/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Concurrency fuzzing scheduler, in-kernel BPF version.
 *
 * A sched_ext scheduler that perturbs the scheduling of a workload's containers
 * to manufacture the rare interleavings that surface concurrency bugs. The
 * whole policy runs here in the kernel, so that under a deterministic
 * hypervisor (bedrock: single vCPU + emulated TSC) a run is fully reproducible
 * from the getrandom stream that drives it.
 *
 * Base policy: weighted virtual-time fair scheduling (à la scx_simple / CFS).
 * Non-frozen threads are scheduled fairly by accumulated, weight-scaled vtime,
 * so the only deliberate perturbation is the freezing below — not a custom
 * timeslice/ordering scheme. Each task's vtime is the kernel-provided
 * p->scx.dsq_vtime; the shared DSQ is ordered by it.
 *
 * Chaos (after rr's "chaos mode", R. O'Callahan 2016): designate a few "victim"
 * threads and starve them in bursts.
 *   - Two priorities, high and low. Each thread is low with probability
 *     1/low_prob_inv; the rest are high. The victim set re-randomizes every
 *     prio_reroll_ns: each period draws a fresh epoch_seed from the randomness pool
 *     and task_is_low() hashes (pid, epoch_seed), so membership re-rolls without
 *     any per-task storage (see task_is_low).
 *   - Periodically, for a short random interval (starve_min_ns..starve_max_ns),
 *     low-priority threads are not allowed to run at all — even if they are the
 *     only runnable threads. dispatch() simply skips them while an interval is
 *     open; everything else runs fair. High-priority threads are never frozen.
 *   - Because such intervals can stall forward progress, cumulative starvation
 *     is capped at starve_cap_pct% of elapsed run time.
 *   - Randomness (interval gaps/lengths and the per-epoch victim set) is drawn,
 *     one value per decision, from a pool that scx-init fills and continuously
 *     refreshes from the getrandom vmcall (NOT bpf_get_prandom_u32). bedrock
 *     serves that vmcall from its controlled, fuzzer-driven, replayable stream:
 *     deterministic on replay (same stream -> same schedule), and because each
 *     decision consumes a distinct pool entry the fuzzer steers decisions
 *     independently — mutating a late decision's input does not perturb the
 *     earlier schedule.
 *
 * Membership (who is governed):
 *   - Attached with SCX_OPS_SWITCH_PARTIAL, so it governs ONLY tasks whose
 *     policy is SCHED_EXT. Every ordinary host task stays on stock CFS/EEVDF.
 *   - A workload opts in by wrapping the process it wants fuzzed in thread-fuzz,
 *     which sets SCHED_EXT on itself and execs the target; the target's
 *     fork/exec descendants inherit it. So every task we see was opted in
 *     explicitly: there is nothing to exclude.
 *
 * Mechanism: two DSQs. A vtime-ordered "fair" queue holds everything allowed to
 * run; dispatch() always pulls the lowest-vtime task from it. A "frozen" queue
 * holds low-priority victims parked during a starvation interval; while an
 * interval is open enqueue() routes victims there and dispatch() does not pull
 * from it, so they sit unrun (in the kernel's custody) until the interval ends,
 * when dispatch() releases them back to the runqueue. A one-shot timer kicks the
 * CPU at interval end so the release happens even if the CPU went idle.
 */
#include <scx/common.bpf.h>
#include "intf.h"

char _license[] SEC("license") = "GPL";

/*
 * Two dispatch queues. The fair queue is vtime-ordered (p->scx.dsq_vtime) and
 * holds everything allowed to run; dispatch() always pulls from it. The frozen
 * queue holds low-priority victims parked during a starvation interval;
 * dispatch() does not pull from it while an interval is open, so those tasks sit
 * unrun until the interval ends and they are released back to the runqueue.
 */
#define FAIR_DSQ_ID   0
#define FROZEN_DSQ_ID 1

/* Bound for the kick loop in the timer callback. */
#define MAX_CPUS 1024

/* Base timeslice for the fair policy. Fixed (CFS-like), not randomized: the
 * only deliberate perturbation is the freezing, not the slice length. */
#define SLICE_NS (5ULL * 1000000)	/* 5ms */

/* Virtual-time comparison that is safe across u64 wraparound. */
#define vtime_before(a, b) ((s64)((a) - (b)) < 0)

/*
 * Read-only configuration, set by scx-init before the program is loaded.
 * "const volatile" is how sched_ext schedulers expose rodata to user space.
 */
const volatile u64 starve_min_ns;	/* starvation interval, low bound */
const volatile u64 starve_max_ns;	/* starvation interval, high bound */
const volatile u64 gap_min_ns;		/* gap between intervals, low bound */
const volatile u64 gap_max_ns;		/* gap between intervals, high bound */
const volatile u64 prio_reroll_ns;	/* how often priorities re-randomize */
const volatile u64 low_prob_inv;	/* P(low) = 1/low_prob_inv */
const volatile u64 starve_cap_pct;	/* max % of run time spent starving */
const volatile bool logging;
const volatile bool debug;		/* emit per-task membership diagnostics */

/*
 * Running consume counter for the randomness pool (slot = rnd_idx % RND_POOL_N;
 * see intf.h for the pool's positional-control semantics). Non-static so scx-init
 * can read it (skel->bss->rnd_idx) to drive its half-at-a-time refresh.
 */
u64 rnd_idx;

/*
 * Global virtual-time clock for the fair policy. Advances as tasks run (see
 * chaos_running); a task's vtime is clamped to within one slice of this so a
 * long-sleeping task can't accumulate unbounded scheduling credit.
 */
static u64 vtime_now;

/*
 * Global chaos schedule state, advanced lazily from enqueue (serialized on the
 * single-vCPU target). All times are bpf_ktime_get_ns(), i.e. the deterministic
 * emulated TSC.
 */
static u64 epoch_start;		/* time of first enqueue (run start); 0 = unset */
static u64 next_decision;	/* earliest time to open a new starvation interval */
static u64 starve_begin;	/* start of the current interval */
static u64 starve_until;	/* end of the current interval; 0 = not starving */
static u64 total_starve_ns;	/* cumulative completed starvation (for the cap) */
static u64 epoch_seed;		/* pool-drawn seed for the current victim epoch */
static u64 prio_reroll_at;	/* next time to re-roll the victim set (new epoch_seed) */

/*
 * No per-task storage. "Victim" status is derived deterministically from the
 * task's pid and the current priority epoch (see task_is_low), so there is
 * nothing to allocate on the enqueue hot path. Task-local storage is unusable
 * here anyway: bpf_task_storage_get() uses a trylock, and since enqueue runs
 * under the rq lock it returns NULL under load — on a busy workload (bitcoind's
 * ~50 threads) that fails >99% of the time, silently skipping the chaos policy.
 */

/*
 * Membership-log throttle (gated by the "debug" rodata flag). enqueue() runs on
 * every wakeup, so the "governed" membership line is sampled only for the first
 * few tasks to confirm the scheduler is live without flooding. The per-freeze
 * log is not throttled — it fires at most once per victim per starvation
 * interval, so it stays bounded yet keeps naming frozen threads for the whole run.
 */
static u64 dbg_logged;		/* membership lines emitted so far */

/* Wrapper so the timer can live in an array map (bpf_timer needs map storage). */
struct timer_wrap {
	struct bpf_timer timer;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct timer_wrap);
} timer_map SEC(".maps");

/* Ring buffer carrying fuzz_event records up to scx-init. 256 KiB. */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

/* Randomness pool, filled and refreshed by scx-init from the getrandom vmcall. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, RND_POOL_N);
	__type(key, u32);
	__type(value, u64);
} rnd_pool SEC(".maps");

/*
 * Next value from the randomness pool, consumed strictly in order (see intf.h).
 * The mask is safe because RND_POOL_N is a power of two, keeping the index in
 * range for the verifier.
 */
static __always_inline u64 rng_next(void)
{
	u32 i = rnd_idx & (RND_POOL_N - 1);
	u64 *v;

	rnd_idx++;
	v = bpf_map_lookup_elem(&rnd_pool, &i);
	return v ? *v : 0;
}

/* Random value in the half-open range [min, max). */
static __always_inline u64 rng_range(u64 min, u64 max)
{
	if (min >= max)
		return min;
	return min + rng_next() % (max - min);
}

static __always_inline void log_event(struct task_struct *p, u32 type, u64 now,
				       u64 duration_ns)
{
	struct fuzz_event *e;

	if (!logging)
		return;
	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return;
	e->time_ns = now;
	e->duration_ns = duration_ns;
	e->pid = BPF_CORE_READ(p, pid);
	e->event_type = type;
	bpf_probe_read_kernel_str(e->comm, sizeof(e->comm), BPF_CORE_READ(p, comm));
	bpf_ringbuf_submit(e, 0);
}

/*
 * Arm the one-shot release timer to fire in `delay` ns. The timer exists only
 * to wake parked victims when a starvation interval ends, so it is armed when an
 * interval opens and never otherwise. A workload that isn't being starved pays
 * no periodic timer overhead at all.
 */
static __always_inline void arm_release(u64 delay)
{
	struct timer_wrap *tw;
	u32 zero = 0;

	tw = bpf_map_lookup_elem(&timer_map, &zero);
	if (tw)
		bpf_timer_start(&tw->timer, delay, 0);
}

/*
 * Advance the global chaos schedule: re-randomize priorities on a period, close
 * a finished starvation interval, and maybe open a new one (subject to the
 * cap). Driven by enqueue, which is serialized on the single-vCPU target.
 */
static __always_inline void advance_schedule(struct task_struct *p, u64 now)
{
	if (epoch_start == 0) {
		epoch_start = now;
		next_decision = now + rng_range(gap_min_ns, gap_max_ns);
		prio_reroll_at = now + prio_reroll_ns;
	}

	/* Periodically re-randomize thread priorities. A fresh epoch_seed drawn
	 * from the randomness pool shifts the victim set: task_is_low() hashes
	 * (pid, epoch_seed), so every task's low/high status re-rolls when the seed
	 * changes — no per-task state, and each re-roll is its own fuzzer input. */
	if (now >= prio_reroll_at) {
		epoch_seed = rng_next();
		prio_reroll_at = now + prio_reroll_ns;
	}

	/* Close a finished starvation interval and schedule the next gap. */
	if (starve_until && now >= starve_until) {
		total_starve_ns += starve_until - starve_begin;
		starve_until = 0;
		next_decision = now + rng_range(gap_min_ns, gap_max_ns);
	}

	/* Maybe open a new starvation interval. Gate on cumulative starvation so
	 * far (not counting the new interval) so an interval can open from the
	 * very start of the run, while long-run starvation still converges to
	 * <= starve_cap_pct% of elapsed time. Bounds priority-inversion hangs. */
	if (!starve_until && now >= next_decision) {
		u64 elapsed = now - epoch_start;

		if (total_starve_ns * 100 <= elapsed * starve_cap_pct) {
			u64 len = rng_range(starve_min_ns, starve_max_ns);

			starve_begin = now;
			starve_until = now + len;
			arm_release(len);
			log_event(p, FUZZ_EVENT_STARVE_BEGIN, now, len);
		} else {
			next_decision = now + rng_range(gap_min_ns, gap_max_ns);
		}
	}
}

/*
 * Is this task a low-priority "victim" in the current priority epoch? Derived
 * deterministically from (pid, epoch_seed) with a finalizing hash, so it needs
 * no per-task storage and draws nothing from the randomness pool itself: it is stable
 * within an epoch, re-rolls when epoch_seed is redrawn (every prio_reroll_ns),
 * and is low with probability 1/low_prob_inv. epoch_seed is a randomness-pool value,
 * so which threads are victims is fuzzer-driven yet reproducible on replay.
 * NOTE: must NOT call rng_next() — the pool-consume order has to stay tied to the
 * (deterministic) enqueue sequence, independent of which tasks are sampled.
 */
static __always_inline bool task_is_low(struct task_struct *p)
{
	u64 h = (u64)BPF_CORE_READ(p, pid) * 0x9E3779B97F4A7C15ULL;

	h ^= epoch_seed * 0xD1B54A32D192ED03ULL;
	h ^= h >> 33;
	h *= 0xFF51AFD7ED558CCDULL;
	h ^= h >> 33;
	return low_prob_inv ? (h % low_prob_inv) == 0 : false;
}

s32 BPF_STRUCT_OPS(chaos_select_cpu, struct task_struct *p, s32 prev_cpu,
		   u64 wake_flags)
{
	/*
	 * Do not direct-dispatch here. Returning prev_cpu without inserting the
	 * task forces every wakeup through enqueue(), so the chaos policy sees
	 * it.
	 */
	return prev_cpu;
}

void BPF_STRUCT_OPS(chaos_enqueue, struct task_struct *p, u64 enq_flags)
{
	u64 now = bpf_ktime_get_ns();
	u64 vtime = p->scx.dsq_vtime;

	/*
	 * Every task we see was opted in explicitly: thread-fuzz sets SCHED_EXT
	 * on the wrapped process (its descendants inherit it), and
	 * SCX_OPS_SWITCH_PARTIAL means only SCHED_EXT tasks reach us. So there is
	 * nothing to exclude: fuzz them all. Advance the chaos schedule first.
	 */
	advance_schedule(p, now);

	/* Membership diagnostic: log the first few governed tasks (the comm shows
	 * the real payload — bitcoind, b-net, … — not crun's pre-exec name). */
	if (debug && dbg_logged < 64) {
		dbg_logged++;
		log_event(p, FUZZ_EVENT_DEBUG, now, BPF_CORE_READ(p, pid));
	}

	/*
	 * Freeze: while an interval is open, route low-priority victims to the
	 * frozen DSQ. dispatch() does not pull from it until the interval ends, so
	 * the victim is parked (in the kernel's custody) but unrun. Everything else
	 * — and victims outside an interval — goes to the fair DSQ.
	 */
	if (task_is_low(p) && starve_until && now < starve_until) {
		if (debug)
			log_event(p, FUZZ_EVENT_LOW_PRIO, now, starve_until - now);
		scx_bpf_dsq_insert(p, FROZEN_DSQ_ID, SLICE_NS, enq_flags);
		return;
	}

	/*
	 * Weighted-vtime fair ordering. Clamp the task's accumulated vtime so a
	 * long sleeper gains at most one slice of credit, then queue it. dispatch
	 * runs the lowest-vtime task in this DSQ.
	 */
	if (vtime_before(vtime, vtime_now - SLICE_NS))
		vtime = vtime_now - SLICE_NS;
	scx_bpf_dsq_insert_vtime(p, FAIR_DSQ_ID, SLICE_NS, vtime, enq_flags);
}

void BPF_STRUCT_OPS(chaos_dispatch, s32 cpu, struct task_struct *prev)
{
	u64 now = bpf_ktime_get_ns();
	bool starving = starve_until && now < starve_until;

	/*
	 * When no interval is open, first release any parked victims by moving the
	 * head of the frozen DSQ to the local CPU; over successive dispatch calls
	 * this drains the frozen queue back into normal scheduling. (No-op when the
	 * frozen DSQ is empty.) During an interval we skip this, so victims stay
	 * parked — even if they are the only runnable tasks, the CPU just idles
	 * until the one-shot release timer fires at interval end.
	 */
	if (!starving)
		scx_bpf_dsq_move_to_local(FROZEN_DSQ_ID);

	/* Run the lowest-vtime fair task. */
	scx_bpf_dsq_move_to_local(FAIR_DSQ_ID);
}

/* Keep the global virtual clock moving forward as tasks start running. */
void BPF_STRUCT_OPS(chaos_running, struct task_struct *p)
{
	if (vtime_before(vtime_now, p->scx.dsq_vtime))
		vtime_now = p->scx.dsq_vtime;
}

/* Charge the time the task ran, scaled by the inverse of its weight, so
 * higher-weight (lower-nice) tasks accumulate vtime more slowly and thus get a
 * larger share of the CPU — i.e. weighted fairness. */
void BPF_STRUCT_OPS(chaos_stopping, struct task_struct *p, bool runnable)
{
	u32 weight = p->scx.weight;

	if (!weight)
		weight = 100;	/* nice-0 weight; guards a div-by-zero */
	p->scx.dsq_vtime += (SLICE_NS - p->scx.slice) * 100 / weight;
}

/* A task entering the scheduler starts at the current global vtime, so it
 * neither dominates (huge negative credit) nor is penalized on entry. */
void BPF_STRUCT_OPS(chaos_enable, struct task_struct *p)
{
	p->scx.dsq_vtime = vtime_now;
}

static int timer_cb(void *map, int *key, struct timer_wrap *tw)
{
	u32 nr = scx_bpf_nr_cpu_ids();
	u32 i;

	/*
	 * One-shot: kick the CPUs so dispatch re-runs and releases victims whose
	 * starvation interval has just ended, even if the system would otherwise
	 * idle. NOT re-armed here — the timer is re-armed only when the next
	 * interval opens (advance_schedule), so a non-starving workload incurs no
	 * periodic timer overhead. On the single-vCPU target this is just CPU 0;
	 * the bounded loop keeps it correct on multi-CPU hosts and keeps the
	 * verifier happy.
	 */
	for (i = 0; i < MAX_CPUS; i++) {
		if (i >= nr)
			break;
		scx_bpf_kick_cpu(i, 0);
	}

	return 0;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(chaos_init)
{
	struct timer_wrap *tw;
	u32 zero = 0;
	s32 ret;

	ret = scx_bpf_create_dsq(FAIR_DSQ_ID, -1);
	if (ret)
		return ret;
	ret = scx_bpf_create_dsq(FROZEN_DSQ_ID, -1);
	if (ret)
		return ret;

	/* Draw the first victim set from the randomness pool. scx-init has already
	 * filled the pool, so this consumes pool[0]; subsequent epochs re-roll from
	 * later pool entries in advance_schedule. */
	epoch_seed = rng_next();

	tw = bpf_map_lookup_elem(&timer_map, &zero);
	if (!tw)
		return -1;
	bpf_timer_init(&tw->timer, &timer_map, CLOCK_MONOTONIC);
	bpf_timer_set_callback(&tw->timer, timer_cb);
	/* Not started here: armed on demand (arm_release) when a starvation
	 * interval opens, so there is no periodic timer when nothing is being
	 * starved. */

	return 0;
}

SEC(".struct_ops.link")
struct sched_ext_ops chaos_ops = {
	.select_cpu = (void *)chaos_select_cpu,
	.enqueue    = (void *)chaos_enqueue,
	.dispatch   = (void *)chaos_dispatch,
	.running    = (void *)chaos_running,
	.stopping   = (void *)chaos_stopping,
	.enable     = (void *)chaos_enable,
	.init       = (void *)chaos_init,
	/*
	 * SCX_OPS_SWITCH_PARTIAL: govern only tasks whose policy is SCHED_EXT
	 * (thread-fuzz opts the workload in); everything else stays on stock CFS.
	 * SCX_OPS_ENQ_LAST: keep getting enqueue() for the last runnable task so
	 * a lone victim still cycles through the policy.
	 */
	.flags      = SCX_OPS_SWITCH_PARTIAL | SCX_OPS_ENQ_LAST,
	.timeout_ms = 5000,
	.name       = "chaos_fuzz",
};
