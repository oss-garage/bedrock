// SPDX-License-Identifier: GPL-2.0

//! Precise VM exits via EPT-friendly PEBS.
//!
//! This module provides the per-VM state and EPT-trap setup used to get close
//! to exact retired-instruction counts with PEBS; the final few instructions
//! are handled by the MTF margin path in `exits/mod.rs`. The mechanism:
//! program PEBS on `IA32_FIXED_CTR0` to overflow before the desired event; mark
//! the PEBS Buffer page R+E (no W) in EPT; the PEBS record write traps as an
//! EPT violation with the EPT-friendly asynchronous-access bit set.
//!
//! See:
//! - Intel SDM Vol 3B Section 21.9.4 (Reduced Skid PEBS)
//! - Intel SDM Vol 3B Section 21.9 (PEBS Facility)
//! - Intel SDM Vol 3B Section 21.9.5 (EPT-Friendly PEBS)
//! - Intel SDM Vol 3C Section 29.2.1, Table 29-7 (EPT-violation exit
//!   qualification, bit 16 = "asynchronous to instruction execution")

use super::ept::translate_gva_to_gpa;
use super::helpers::ExitHandlerResult;
use super::qualifications::EptViolationQualification;
use core::sync::atomic::{AtomicU64, Ordering};

#[cfg(not(feature = "cargo"))]
use super::super::prelude::*;
#[cfg(feature = "cargo")]
use crate::prelude::*;

/// Offset within the registered scratch page where the PEBS Buffer begins.
/// The DS Management Area lives at offset 0 (~160 bytes used); the PEBS Buffer
/// starts at 0x100 to leave clearance.
pub const PEBS_BUFFER_OFFSET: u64 = 0x100;
/// Number of bytes reserved for the PEBS Buffer within the scratch page.
/// Sized to hold one Basic adaptive PEBS record. Since the trap fires on the
/// first record write, Bedrock never uses more than one record's worth in
/// practice.
pub const PEBS_BUFFER_SIZE: u64 = 0x800;

/// Linux x86_64 kernel direct-map base with KASLR disabled (which bedrock
/// requires for determinism — see `boot/constants.rs`). Every guest-physical
/// RAM page is mapped at `PAGE_OFFSET + paddr` in the kernel half of every
/// process's address space, so it's valid as `IA32_DS_AREA` regardless of
/// which process happens to be current when PEBS writes a record.
///
/// We can't use the userspace VA returned by `mmap` directly because
/// `IA32_DS_AREA` is interpreted via the *current* CR3 — when the guest
/// scheduler runs a different process while PEBS is armed, the userspace VA
/// isn't mapped in that process's CR3 and the PEBS write takes a guest #PF.
/// See `arch/x86/include/asm/page_64_types.h`.
pub const GUEST_LINUX_PAGE_OFFSET: u64 = 0xffff_8880_0000_0000;

/// Layout of the DS Management Area for adaptive (format ≥ 4) PEBS, used
/// when `IA32_PERF_CAPABILITIES.PEBS_BASELINE = 1`.
///
/// All offsets are 64-bit. The CPU reads/writes this area through linear
/// addressing — when used inside a guest, the linear address loaded into
/// `IA32_DS_AREA` is translated by guest paging then by EPT.
///
/// See Intel SDM Vol 3B Figure 21-69.
#[repr(C)]
#[derive(Default)]
pub struct DsManagementArea {
    pub bts_buffer_base: u64,
    pub bts_index: u64,
    pub bts_absolute_maximum: u64,
    pub bts_interrupt_threshold: u64,
    /// Linear address of the first byte of the PEBS Buffer.
    pub pebs_buffer_base: u64,
    /// Linear address of the next PEBS record to be written. Updated by
    /// hardware.
    pub pebs_index: u64,
    /// Linear address one past the end of the PEBS Buffer.
    pub pebs_absolute_maximum: u64,
    /// PEBS index threshold at which the PEBS PMI is signalled.
    pub pebs_interrupt_threshold: u64,
    /// PEBS record reload values for IA32_PMC0..IA32_PMC7 (offsets 0x40..0x78).
    pub pebs_gp_counter_reset: [u64; 8],
    /// PEBS record reload values for IA32_FIXED_CTR0..IA32_FIXED_CTR3
    /// (offsets 0x80..0x98).
    pub pebs_fixed_counter_reset: [u64; 4],
}

/// What the precise-exit handler should do when the PEBS-induced EPT violation
/// fires.
#[derive(Debug, Clone, Copy)]
pub enum PebsAction {
    /// Inject the given external interrupt vector and resume the guest.
    InjectInterrupt(u8),
}

/// Saved host PMU MSR values, captured before each VM-entry and restored on
/// VM-exit so the host kernel's perf state is preserved across guest
/// execution. See `pebs_pre_vm_entry` / `pebs_post_vm_exit`.
#[derive(Default, Clone, Copy)]
pub struct PebsHostMsrs {
    pub pebs_enable: u64,
    pub ds_area: u64,
    pub fixed_ctr_ctrl: u64,
    pub fixed_ctr0: u64,
    pub pebs_data_cfg: u64,
}

/// Per-VM PEBS state for precise exits.
///
/// Boxed in `VmState` so VMs that do not use precise exits do not pay the
/// stack cost. `Some(...)` once `HYPERCALL_REGISTER_PEBS_PAGE` has installed a
/// scratch page; `None` otherwise.
pub struct PebsState {
    /// Guest-physical address of the page holding the DS Management Area.
    /// Set at registration; constant for the VM's lifetime.
    pub ds_management_gpa: u64,
    /// Guest-physical address of the PEBS Buffer page. Same page as
    /// `ds_management_gpa`; mapped R+E (no W) in EPT once registered.
    pub pebs_buffer_gpa: u64,
    /// Guest linear address of `IA32_DS_AREA` — the value the CPU loads when
    /// PEBS is armed. Resolves through guest paging to `ds_management_gpa`.
    pub ds_area_va: u64,
    /// Action to apply when the next PEBS-induced EPT violation fires. None
    /// means PEBS is not currently armed for this VM.
    pub armed_action: Option<PebsAction>,
    /// PEBS firing-point TSC the most recent successful arming aimed at
    /// (`target_tsc - PEBS_MARGIN`, not the final interrupt deadline).
    /// Used to compute the PEBS skid (`current_tsc - armed_target_tsc`,
    /// where `current_tsc = last_instruction_count + tsc_offset`) recorded
    /// on the EPT_VIOLATION_PEBS entry in the non-deterministic exit records
    /// so userspace can see how far each PEBS exit landed from its programmed
    /// firing point. Only meaningful while `armed_action.is_some()`.
    pub armed_target_tsc: u64,
    /// `last_instruction_count` snapshot at the most recent successful
    /// arming. Combined with the value at fire time to derive the
    /// guest-INST_RETIRED delta — distinguishing hardware skid (PMC0 ticked
    /// past the encoded delta) from time-warp (HLT/MWAIT clamps).
    pub armed_inst_count: u64,
    /// `tsc_offset` snapshot at the most recent successful arming. Diff
    /// against fire-time tsc_offset reveals HLT/MWAIT clamps that occurred
    /// between arming and PEBS firing.
    pub armed_tsc_offset: u64,
    /// Iterations of the run loop that have begun with `armed_action`
    /// still set since the most recent successful arming. Reset to 0 in
    /// `arm_precise_exit`'s Armed path, incremented in
    /// `arm_for_next_iteration` when a prior arming is still live. A
    /// non-zero value at fire time indicates the firing iteration used a
    /// stale (multi-iter) arming rather than a freshly computed one.
    pub iters_since_arm: u32,
    /// Counter reload value (`IA32_FIXED_CTR0` initial value) for the next
    /// entry. Computed at arming time from the desired target TSC.
    pub counter_reload: u64,
    /// `IA32_FIXED_CTR_CTRL` value to load on entry when armed. Constant
    /// after init: `FIXED_CTR_CTRL_FC0_OS_USR`. Other fixed counters'
    /// control bits are zeroed.
    pub fixed_ctr_ctrl: u64,
    /// `IA32_PEBS_ENABLE` value to load on entry when armed. Constant
    /// `1 << 32` selecting `IA32_FIXED_CTR0` for PEBS.
    pub pebs_enable: u64,
    /// `MSR_PEBS_DATA_CFG` value — 0 selects the minimal PEBS record (Basic
    /// Info Group only). We never read the records, so anything beyond
    /// minimal is wasted bytes.
    pub pebs_data_cfg: u64,
    /// Saved host PMU MSR values from the most recent VM-entry. Restored on
    /// VM-exit. Only meaningful while `armed_action.is_some()`.
    pub host_msrs: PebsHostMsrs,
    /// Set to `true` after `arm_precise_exit` has logged the first successful
    /// arming. Used to print the PERFEVTSEL/reload/delta values that get
    /// loaded into the CPU exactly once per VM, so PDist enablement can be
    /// confirmed from dmesg without spamming the log on every arming.
    pub logged_first_arm: bool,
}

impl PebsState {
    /// Inherit PEBS registration from a parent VM into a forked child.
    ///
    /// The forked guest is at the parent's snapshot point and will never
    /// re-issue `HYPERCALL_REGISTER_PEBS_PAGE`; without this, the child runs
    /// with `pebs_state = None`, `pebs_pre_vm_entry` never fires, and every
    /// timer falls through to the late-inject path. We carry the registration
    /// constants — scratch-page GPAs, the `IA32_DS_AREA` linear address, and
    /// the static MSR values — from the parent and reset all runtime fields
    /// (no arming live, no skid measurements, no first-arm log gate) so the
    /// child arms fresh on its first iteration.
    ///
    /// The PEBS scratch page itself is shared with the parent through the
    /// child's EPT clone (`clone_for_fork` preserves the parent's R+E leaf for
    /// the registered GPA). The fork model assumes the parent does not run
    /// concurrently with the child, so sharing the host page is safe.
    pub fn clone_for_fork(&self) -> Self {
        Self {
            ds_management_gpa: self.ds_management_gpa,
            pebs_buffer_gpa: self.pebs_buffer_gpa,
            ds_area_va: self.ds_area_va,
            fixed_ctr_ctrl: self.fixed_ctr_ctrl,
            pebs_enable: self.pebs_enable,
            pebs_data_cfg: self.pebs_data_cfg,
            armed_action: None,
            armed_target_tsc: 0,
            armed_inst_count: 0,
            armed_tsc_offset: 0,
            iters_since_arm: 0,
            counter_reload: 0,
            host_msrs: PebsHostMsrs::default(),
            logged_first_arm: false,
        }
    }
}

/// `IA32_FIXED_CTR_CTRL` value enabling `IA32_FIXED_CTR0` in OS+USR with no
/// AnyThread, no PMI, no Adaptive_Record. Bits 0-1 (FC0_EN) = 0b11. The
/// other fixed counters' fields are zeroed because the IC doesn't use them
/// in this configuration (it's on `IA32_PMC0`).
///
/// We're switching the PEBS counter from `IA32_PMC0` to `IA32_FIXED_CTR0`
/// to test whether the fixed counter's PEBS path has different async-write
/// timing — Sapphire Rapids' Table 21-51 lists FIXED_CTR0 PDist as
/// "instruction-granularity" (vs the bare "PDist on IA32_PMC0" line),
/// which suggests a slightly different microcode path. See Intel SDM
/// Vol 3B Figure 21-2.
const FIXED_CTR_CTRL_FC0_OS_USR: u64 = 0b11;

/// Bit 32 of `IA32_PERF_GLOBAL_CTRL` enables `IA32_FIXED_CTR0`.
pub const PERF_GLOBAL_CTRL_FIXED_CTR0: u64 = 1 << 32;

/// Counter width (bits) used by Intel performance counters. PMC writes are
/// effectively masked to this width by the architecture; for full-width
/// writes (`IA32_PERF_CAPABILITIES.FULL_WRITE`), the high bits are ignored.
/// We intentionally write 48-bit values to stay within the architectural
/// range. See Intel SDM Vol 3B Section 21.2.8.
const PMC_COUNTER_WIDTH_BITS: u32 = 48;
const PMC_COUNTER_MASK: u64 = (1u64 << PMC_COUNTER_WIDTH_BITS) - 1;

/// Minimum encoded delta (counter_reload distance from overflow) Bedrock uses
/// for PDist.
///
/// PDist (Precise Distribution) requires the counter reload value to be at
/// least 256 events away from overflow (Intel SDM Vol 3B 21.9.6). Bedrock
/// uses 257 as a conservative cutoff, so the borderline 256-event period stays
/// on the MTF single-step path (`exits/mod.rs` `update_mtf_state`) instead of
/// depending on PDist.
pub const PEBS_MIN_DELTA: u64 = 257;

/// Margin (in retired guest instructions) by which the PEBS-armed precise
/// exit fires *before* the requested target. The PEBS exit lands at
/// `target_tsc - get_pebs_margin()`; MTF then single-steps the remaining
/// `get_pebs_margin()` instructions to land exactly on `target_tsc`.
///
/// PEBS+PDist on `IA32_FIXED_CTR0` lands with skid 0 in the common case —
/// but the asynchronous record-write path can occasionally drift by 1
/// instruction. The margin absorbs that drift so the timer interrupt
/// always arrives at the requested deadline rather than off-by-one. The
/// MTF single-step path (`update_mtf_state` in `exits/mod.rs`) takes over
/// once the count is within `get_pebs_margin()` of the target.
///
/// The required margin is CPU-model-specific (the async record-write skid
/// differs across microarchitectures), so it is resolved from CPUID on the
/// host once and cached for the process lifetime: the CPUID read happens
/// exactly once regardless of how many times this is called.
pub fn get_pebs_margin() -> u64 {
    // `u64::MAX` is the "not yet resolved" sentinel; a real margin is small.
    let cached = PEBS_MARGIN_CACHE.load(Ordering::Relaxed);
    if cached != u64::MAX {
        return cached;
    }
    // Racing callers all decode the same family/model and so store the same
    // value; an unsynchronized load/store race is therefore benign.
    let margin = margin_for_host_cpu();
    PEBS_MARGIN_CACHE.store(margin, Ordering::Relaxed);
    margin
}

/// Cache backing [`get_pebs_margin`]. Initialized to the `u64::MAX` sentinel.
static PEBS_MARGIN_CACHE: AtomicU64 = AtomicU64::new(u64::MAX);

/// Select the margin for the host CPU from its family/model.
fn margin_for_host_cpu() -> u64 {
    let (family, model) = host_family_model();
    // Margins were tested on the Bitcoin workload (0 timer late injects in the
    // child VM). See `intel-family.h` in Linux for the model numbers.
    match (family, model) {
        (0x6, 0x8F) => 3, // Sapphire Rapids-SP (ex: Xeon Gold 5412U)
        (0x6, 0x6A) => 8, // Ice Lake-SP (ex: Xeon Silver 4310)
        _ => 8,           // default for untested models
    }
}

/// CPU family and model decoded from CPUID leaf 1 (EAX). See Intel SDM,
/// Volume 1, Chapter 21.3 CPUID Leaves, CPUID.01H -- Version and Features.
fn host_family_model() -> (u32, u32) {
    let (eax, _, _, _) = super::cpuid::cpuid(1, 0);

    let base_model = (eax >> 4) & 0xF;
    let base_family = (eax >> 8) & 0xF;
    let ext_model = (eax >> 16) & 0xF;
    let ext_family = (eax >> 20) & 0xFF;

    // When the Family ID is 06H or 0FH, this field is prepended to the Model
    // ID to provide an 8-bit model identification.
    let model = if base_family == 0x6 || base_family == 0xF {
        (ext_model << 4) | base_model
    } else {
        base_model
    };

    // When the Family ID is 0FH, this field is added to the Family ID to
    // provide an 8-bit family identification.
    let family = if base_family == 0xF {
        base_family + ext_family
    } else {
        base_family
    };

    (family, model)
}

/// Outcome of arming a precise exit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArmResult {
    /// Successfully armed; the next VM-entry will program PEBS and the next
    /// PEBS-induced EPT violation will dispatch the requested action.
    Armed,
    /// `target_tsc` is strictly less than `current_tsc` — the exit point has
    /// already passed. Caller should take the requested action immediately
    /// without VM-entry.
    AlreadyPast,
    /// `target_tsc - current_tsc` is below `PEBS_MIN_DELTA + PEBS_MARGIN`
    /// — too short for PDist. Count is already inside the MTF single-step
    /// window; caller relies on `update_mtf_state` to land on the
    /// boundary.
    BelowMinDelta,
    /// No `PebsState` is installed (no scratch page registered).
    NotRegistered,
}

/// Arm a precise exit at `target_tsc - PEBS_MARGIN` with the given `action`.
///
/// PEBS lands the exit `PEBS_MARGIN` instructions before `target_tsc`;
/// `update_mtf_state` takes over from there to single-step onto the exact
/// target. Bedrock's emulated TSC ticks once per retired instruction, so
/// `delta_tsc == delta_instructions`.
///
/// The encoded distance to overflow is `delta - PEBS_MARGIN`, which must
/// be at least `PEBS_MIN_DELTA` for Bedrock to use PDist; below that, the
/// caller falls back to MTF stepping for the entire remaining distance.
pub fn arm_precise_exit(
    pebs: &mut PebsState,
    current_tsc: u64,
    target_tsc: u64,
    action: PebsAction,
    inst_count_now: u64,
    tsc_offset_now: u64,
) -> ArmResult {
    if target_tsc < current_tsc {
        return ArmResult::AlreadyPast;
    }
    let pebs_margin = get_pebs_margin();
    let delta = target_tsc - current_tsc;
    // Encoded distance to overflow must be ≥ PEBS_MIN_DELTA for Bedrock to
    // use PDist. The SDM minimum is 256 (Vol 3B 21.9.6); this code keeps a
    // one-event cushion and lets the MTF single-step window handle shorter
    // deltas directly.
    if delta < PEBS_MIN_DELTA + pebs_margin {
        return ArmResult::BelowMinDelta;
    }
    let encoded_delta = delta - pebs_margin;
    // Counter reload: FIXED_CTR0 = -encoded_delta, masked to the 48-bit
    // counter width. After `encoded_delta` increments the counter wraps to 0
    // (overflow); PDist records on that same overflowing instruction —
    // the (encoded_delta)-th instruction from now, i.e. PEBS_MARGIN before
    // the requested target — and MTF single-steps the remaining margin.
    pebs.counter_reload = encoded_delta.wrapping_neg() & PMC_COUNTER_MASK;
    // Track the actual PEBS firing point (target - margin) for skid
    // diagnostics: skid = emulated_tsc_at_pebs_exit - armed_target_tsc
    // should be 0 with PDist, regardless of margin.
    pebs.armed_target_tsc = target_tsc - pebs_margin;
    pebs.armed_inst_count = inst_count_now;
    pebs.armed_tsc_offset = tsc_offset_now;
    pebs.iters_since_arm = 0;
    pebs.armed_action = Some(action);
    if !pebs.logged_first_arm {
        pebs.logged_first_arm = true;
        log_info!(
            "pebs: first arm: fixed_ctr_ctrl=0x{:x} pebs_enable=0x{:x} pebs_data_cfg=0x{:x} reload=0x{:x} delta={}\n",
            pebs.fixed_ctr_ctrl,
            pebs.pebs_enable,
            pebs.pebs_data_cfg,
            pebs.counter_reload,
            encoded_delta,
        );
    }
    ArmResult::Armed
}

/// Disarm any pending precise exit. Idempotent; safe to call without an
/// armed action.
pub fn disarm_precise_exit(pebs: &mut PebsState) {
    pebs.armed_action = None;
}

/// Pre-VM-entry sweep: arm PEBS for the next APIC timer deadline so the
/// timer interrupt fires at the precise retired-instruction count instead of
/// at some later coarse exit boundary. Disarms if no timer deadline is set.
///
/// We also arm for `stop_at_tsc` when set. The coarse stop check in the
/// exit dispatcher (`exits/mod.rs`) only fires on the next deterministic
/// exit *after* `emulated_tsc >= stop_at_tsc`, so without PEBS arming the
/// guest can run far past the requested stop before any check triggers —
/// fine for the original "let the guest reach a natural boundary" use case,
/// but inadequate when callers want a tight stop (e.g. to queue additional
/// I/O actions at the same virtual time before resuming the VM). Arming
/// here makes `stop_at_tsc` exact to within the usual PEBS margin.
///
/// Called from `inject_pending_interrupt`. The `arm_precise_exit` call
/// disarms on `AlreadyPast` / `BelowMinDelta` so the stale counter_reload
/// from a prior arming doesn't fire PEBS far past the missed deadline;
/// the IRR-set path is the safety net for those cases.
pub fn arm_for_next_iteration<C: VmContext>(ctx: &mut C) {
    // Use last_instruction_count + tsc_offset as the current TSC rather
    // than ctx.state().emulated_tsc, because emulated_tsc is only updated
    // on deterministic exits — after a non-deterministic exit (external
    // interrupt, NMI, preemption timer) emulated_tsc lags by however many
    // instructions retired in the interrupted iter. The composed value is
    // always fresh: last_instruction_count is updated on every VM-exit
    // regardless of determinism, and tsc_offset is only advanced by HLT/
    // MWAIT clamps which are themselves deterministic exits.
    let inst_count = ctx.state().last_instruction_count;
    let tsc_offset = ctx.state().tsc_offset;
    let current = inst_count + tsc_offset;
    let apic_deadline = ctx.state().devices.apic.timer_deadline;
    let apic_vector = (ctx.state().devices.apic.lvt_timer & 0xFF) as u8;

    // The I/O channel piggy-backs on the same precise-arming machinery as
    // the APIC timer. When a request is queued with a non-zero target TSC
    // we compute its deadline and let PEBS arm for whichever event fires
    // earlier — same `target - PEBS_MARGIN` precision, same MTF margin
    // approach, same `check_io_channel` IRR set on the boundary step.
    // Shares the readiness predicate with the MTF/margin path via
    // `next_io_channel_target_tsc`.
    let io_channel_deadline = super::next_io_channel_target_tsc(ctx);

    // `stop_at_tsc` is the requested exit-to-userspace point. Arming PEBS
    // for it makes the stop precise; the exit dispatcher's coarse check
    // still catches any case where PEBS skids past or is disarmed.
    let stop_deadline = ctx.state().stop_at_tsc;

    // The start of a single-step TSC range is armed as a precise target so
    // the first single-step VM-exit lands on `count + tsc_offset == start`
    // deterministically. Without it, single-stepping begins on whichever
    // exit first crosses the boundary — possibly a non-deterministic
    // host-interrupt exit — and two forks start logging at different
    // instruction counts (their streams then compare as divergent despite
    // identical guest execution).
    let single_step_start = super::next_single_step_start_tsc(ctx);

    // Pick the earliest of the pending deadlines. Zero means "no APIC
    // timer arming" (Option-style absence encoded as 0 in the existing
    // code); `None` means "not pending" for the others. The chosen
    // target plus `apic_vector` are passed into `arm_precise_exit`; the
    // vector field of `PebsAction::InjectInterrupt` is informational (the
    // actual injection on PEBS fire is done by the normal pre-entry path's
    // `check_apic_timer` / `check_io_channel`), so it's fine to reuse the
    // APIC vector for all event types.
    let chosen_target = [
        Some(apic_deadline).filter(|&t| t != 0),
        io_channel_deadline,
        stop_deadline,
        single_step_start,
    ]
    .into_iter()
    .flatten()
    .min()
    .unwrap_or(0);

    let arm_result = {
        let pebs = match ctx.state_mut().pebs_state.as_deref_mut() {
            Some(p) => p,
            None => return,
        };

        // Account for the iteration we're about to enter. If a prior arming is
        // still live (we're starting a new iter on top of a previous arming),
        // bump the count. The Armed path of arm_precise_exit will reset to 0
        // if a fresh arming succeeds; the AlreadyPast / BelowMinDelta paths
        // disarm below, so a sticky non-zero only ever surfaces on a fresh
        // arming that re-armed across one or more non-PEBS exits.
        let prev_armed = pebs.armed_action.is_some();
        if prev_armed {
            pebs.iters_since_arm = pebs.iters_since_arm.saturating_add(1);
        }

        let result = if chosen_target != 0 {
            let r = arm_precise_exit(
                pebs,
                current,
                chosen_target,
                PebsAction::InjectInterrupt(apic_vector),
                inst_count,
                tsc_offset,
            );
            // AlreadyPast / BelowMinDelta leave the prior arming's
            // counter_reload in place. If we VM-enter with PEBS still
            // armed, the MSR-load list reloads FIXED_CTR0 with that
            // stale value and PEBS fires far past the missed deadline
            // (skid = instructions retired in the interrupting iter,
            // which is what we observed as the >1 skid outliers). Disarm
            // explicitly so only the IRR-set safety net delivers the
            // interrupt for those cases.
            if !matches!(r, ArmResult::Armed) {
                disarm_precise_exit(pebs);
            }
            Some(r)
        } else {
            disarm_precise_exit(pebs);
            None
        };
        (prev_armed, result)
    };

    let (prev_armed, arm_result) = arm_result;

    let stats = &mut ctx.state_mut().exit_stats;
    if prev_armed {
        stats.pebs_armed_iter_no_fire += 1;
    }
    match arm_result {
        Some(ArmResult::AlreadyPast) => stats.pebs_arm_already_past += 1,
        Some(ArmResult::BelowMinDelta) => stats.pebs_arm_below_min_delta += 1,
        _ => {}
    }
}

/// Snapshot host PMU MSRs and stage the per-arming guest values into the
/// VM-entry MSR-load list. The CPU writes those MSRs atomically with VM-entry,
/// after the page-table switch to guest CR3, so `IA32_DS_AREA` is never a
/// guest VA in host context — that was causing SMAP faults on bare metal,
/// because re-enabling `IA32_PEBS_ENABLE` in host with a guest DS_AREA
/// flushed the previous run's buffered PEBS record into user memory.
///
/// Repoints the VM-entry MSR-load list from the instruction counter's
/// single-entry page to the PEBS page (which carries `IA32_PMC0` as
/// entry 0 to preserve the IC's count, followed by the PEBS MSRs).
/// `pebs_post_vm_exit` switches it back so disarmed iterations only pay the
/// cost of reloading the instruction counter.
///
/// Called only when `pebs.armed_action.is_some()`.
pub fn pebs_pre_vm_entry<C: VmContext, M: MsrAccess>(ctx: &mut C, msr: &M) {
    // Snapshot host PMU state so `pebs_post_vm_exit` can restore it. PEBS
    // stays enabled in host between VM-exit and now (the VM-exit MSR-load
    // already wrote IA32_PEBS_ENABLE = 0), so these reads see clean values.
    let host_pebs_enable = msr.read_msr(msr::IA32_PEBS_ENABLE).unwrap_or(0);
    let host_ds_area = msr.read_msr(msr::IA32_DS_AREA).unwrap_or(0);
    let host_fixed_ctr_ctrl = msr.read_msr(msr::IA32_FIXED_CTR_CTRL).unwrap_or(0);
    let host_fixed_ctr0 = msr.read_msr(msr::IA32_FIXED_CTR0).unwrap_or(0);
    let host_pebs_data_cfg = msr.read_msr(msr::MSR_PEBS_DATA_CFG).unwrap_or(0);

    // Capture the instruction counter's current `IA32_PMC0` value so entry
    // 0 of the PEBS MSR-load list reloads it on VM-entry, preserving the
    // auto-save/load semantics the IC normally gets via its own page.
    let pmc0_value = ctx.state().instruction_counter.read();

    // Read the guest `IA32_PERF_GLOBAL_CTRL` value the VMCS will load at
    // VM-entry; we re-apply it as the final MSR-load entry so the counters
    // are running once the load list has finished reconfiguring them. The
    // first entry writes 0 to disable the counters during reconfig.
    let guest_perf_global_ctrl = ctx
        .state()
        .vmcs
        .read64(VmcsField64::GuestIa32PerfGlobalCtrl)
        .unwrap_or(0);

    let entry_load_va = ctx
        .state()
        .pebs_entry_msr_load_page
        .virtual_address()
        .as_u64();
    let entry_load_pa = ctx.state().pebs_entry_msr_load_page.physical_address();
    let pebs = ctx
        .state_mut()
        .pebs_state
        .as_deref_mut()
        .expect("pebs_pre_vm_entry called without registered pebs_state");
    pebs.host_msrs.pebs_enable = host_pebs_enable;
    pebs.host_msrs.ds_area = host_ds_area;
    pebs.host_msrs.fixed_ctr_ctrl = host_fixed_ctr_ctrl;
    pebs.host_msrs.fixed_ctr0 = host_fixed_ctr0;
    pebs.host_msrs.pebs_data_cfg = host_pebs_data_cfg;

    // Same order as `PEBS_ENTRY_MSR_INDEXES` in vm_state.rs:
    //   0 IA32_PMC0                  — preserve instruction counter
    //   1 IA32_PERF_GLOBAL_CTRL = 0  — disable counters before reconfig
    //   2 IA32_FIXED_CTR0            — counter reload value
    //   3 IA32_FIXED_CTR_CTRL        — enable FC0 in OS+USR
    //   4 MSR_PEBS_DATA_CFG          — 0 (basic record)
    //   5 IA32_DS_AREA
    //   6 IA32_PERF_GLOBAL_STATUS_RESET — clear overflow bits
    //   7 IA32_PEBS_ENABLE           — bit 32 (PEBS on FIXED_CTR0)
    //   8 IA32_PERF_GLOBAL_CTRL = guest — re-enable counters after reconfig
    //
    // `IA32_PERF_GLOBAL_STATUS_RESET` uses the same bitmask as
    // `IA32_PEBS_ENABLE` — it clears overflow status for the counters we're
    // about to use, which prevents the architecture from flushing a stale
    // buffered PEBS record on the re-enable. `IA32_PEBS_ENABLE` precedes
    // the final `IA32_PERF_GLOBAL_CTRL` write so PEBS arming is in place
    // before counters resume running.
    let values = [
        pmc0_value,
        0,
        pebs.counter_reload,
        pebs.fixed_ctr_ctrl,
        pebs.pebs_data_cfg,
        pebs.ds_area_va,
        pebs.pebs_enable,
        pebs.pebs_enable,
        guest_perf_global_ctrl,
    ];

    // Each MSR-load entry is 16 bytes: u32 index, u32 reserved, u64 value
    // (SDM Vol 3C Table 26-16). We only update the value field at offset +8;
    // the index field was set once at VmState construction.
    // SAFETY: page is 4KB, page-aligned; we touch bytes within the 9-entry
    // MSR-load area (9 * 16 = 144), well within bounds.
    unsafe {
        for (i, value) in values.iter().enumerate() {
            let value_ptr = (entry_load_va as *mut u8).add(i * 16 + 8).cast::<u64>();
            core::ptr::write(value_ptr, *value);
        }
    }

    // Repoint the VM-entry MSR-load list at the PEBS page for this iteration.
    // `pebs_post_vm_exit` switches it back to the instruction counter's page.
    let _ = ctx
        .state()
        .vmcs
        .write64(VmcsField64::VmEntryMsrLoadAddr, entry_load_pa.as_u64());
    let _ = ctx
        .state()
        .vmcs
        .write32(VmcsField32::VmEntryMsrLoadCount, values.len() as u32);
}

/// Restore the VM-entry MSR-load list to the instruction counter's page and
/// restore host PMU MSRs from the saved snapshot. Called only when
/// `pebs_pre_vm_entry` ran for this entry. `IA32_PEBS_ENABLE` was already set
/// to 0 atomically by the VM-exit MSR-load list, so it's safe to touch the
/// other PEBS MSRs here.
pub fn pebs_post_vm_exit<C: VmContext, M: MsrAccess>(ctx: &mut C, msr: &M) {
    // Hand the VM-entry MSR-load list back to the instruction counter so
    // disarmed iterations only reload `IA32_FIXED_CTR0`. If the IC has no
    // backing page (null counter), drop the count to 0 instead.
    if let Some(ic_phys) = ctx.state().instruction_counter.msr_save_load_entry_phys() {
        let _ = ctx
            .state()
            .vmcs
            .write64(VmcsField64::VmEntryMsrLoadAddr, ic_phys);
        let _ = ctx
            .state()
            .vmcs
            .write32(VmcsField32::VmEntryMsrLoadCount, 1);
    } else {
        let _ = ctx
            .state()
            .vmcs
            .write32(VmcsField32::VmEntryMsrLoadCount, 0);
    }

    let pebs = ctx
        .state()
        .pebs_state
        .as_deref()
        .expect("pebs_post_vm_exit called without registered pebs_state");
    let _ = msr.write_msr(msr::IA32_FIXED_CTR_CTRL, pebs.host_msrs.fixed_ctr_ctrl);
    let _ = msr.write_msr(msr::IA32_FIXED_CTR0, pebs.host_msrs.fixed_ctr0);
    let _ = msr.write_msr(msr::IA32_DS_AREA, pebs.host_msrs.ds_area);
    let _ = msr.write_msr(msr::MSR_PEBS_DATA_CFG, pebs.host_msrs.pebs_data_cfg);
    let _ = msr.write_msr(msr::IA32_PEBS_ENABLE, pebs.host_msrs.pebs_enable);
}

/// True if the EPT violation was caused by PEBS writing its record to a
/// write-trapped buffer page on a processor with the EPT-friendly enhancement.
///
/// Bit 16 of the EPT-violation exit qualification is set for accesses that
/// are asynchronous to instruction execution and not part of event delivery —
/// this includes PEBS record writes, Intel PT trace output, and user-interrupt
/// delivery (Intel SDM Vol 3C Table 29-7). For the precise-exit feature only
/// PEBS is in use, so bit 16 acts as the indicator.
pub fn is_pebs_induced(qual: &EptViolationQualification) -> bool {
    qual.asynchronous && qual.write
}

/// Result codes returned from the `HYPERCALL_REGISTER_PEBS_PAGE` hypercall.
/// Encoded into RAX so guest userspace can distinguish the failure modes.
#[repr(u64)]
pub enum RegisterPebsPageResult {
    Success = 0,
    /// Host CPU does not advertise EPT-friendly PEBS prerequisites
    /// (`IA32_PERF_CAPABILITIES.PEBS_BASELINE` clear, or `PEBS_FMT < 4`).
    /// On a CPU without the MSR at all the read `#GP`s and we treat that
    /// as unsupported too.
    Unsupported = u64::MAX,
    /// Guest virtual address is not 4KB-aligned.
    Misaligned = u64::MAX - 1,
    /// Guest page-table walk failed — page not currently mapped.
    Untranslatable = u64::MAX - 2,
    /// EPT lookup for the resolved GPA failed — page not faulted in yet.
    /// The guest should `mlock`/touch the page before calling.
    NotEptMapped = u64::MAX - 3,
    /// `PebsState` was already registered for this VM.
    AlreadyRegistered = u64::MAX - 4,
}

/// Build the contents of a DS Management Area for a single-page PEBS scratch
/// region. All fields are guest linear addresses derived from `page_va`. The
/// PEBS Buffer is co-located with the DS Management Area on the same trapped
/// page; see `PEBS_BUFFER_OFFSET` / `PEBS_BUFFER_SIZE`.
///
/// PEBS Interrupt Threshold is set equal to PEBS Buffer Base so the PMI
/// signaling threshold is crossed immediately upon the first record write.
/// We don't actually take the PMI — the EPT violation traps the write
/// before the buffer is updated, and the record is then dropped on the
/// floor when we disarm. The hypothesis is that hardware may shorten the
/// asynchronous record-write latency when a PMI is pending, since once
/// the threshold is reached the PMI must precede further guest progress.
fn build_ds_management_area(page_va: u64) -> DsManagementArea {
    let buffer_base = page_va + PEBS_BUFFER_OFFSET;
    let buffer_max = buffer_base + PEBS_BUFFER_SIZE;
    DsManagementArea {
        bts_buffer_base: 0,
        bts_index: 0,
        bts_absolute_maximum: 0,
        bts_interrupt_threshold: 0,
        pebs_buffer_base: buffer_base,
        pebs_index: buffer_base,
        pebs_absolute_maximum: buffer_max,
        pebs_interrupt_threshold: buffer_base,
        pebs_gp_counter_reset: [0; 8],
        pebs_fixed_counter_reset: [0; 4],
    }
}

/// Serialize a `DsManagementArea` to its on-page byte layout.
fn ds_management_area_bytes(
    area: &DsManagementArea,
) -> [u8; core::mem::size_of::<DsManagementArea>()] {
    // SAFETY: `DsManagementArea` is `#[repr(C)]` with only u64 fields and no
    // padding; reinterpreting it as a byte array is well-defined.
    unsafe {
        core::mem::transmute::<DsManagementArea, [u8; core::mem::size_of::<DsManagementArea>()]>(
            DsManagementArea {
                bts_buffer_base: area.bts_buffer_base,
                bts_index: area.bts_index,
                bts_absolute_maximum: area.bts_absolute_maximum,
                bts_interrupt_threshold: area.bts_interrupt_threshold,
                pebs_buffer_base: area.pebs_buffer_base,
                pebs_index: area.pebs_index,
                pebs_absolute_maximum: area.pebs_absolute_maximum,
                pebs_interrupt_threshold: area.pebs_interrupt_threshold,
                pebs_gp_counter_reset: area.pebs_gp_counter_reset,
                pebs_fixed_counter_reset: area.pebs_fixed_counter_reset,
            },
        )
    }
}

/// Process `HYPERCALL_REGISTER_PEBS_PAGE`.
///
/// `page_va` is the guest linear address of a 4KB page the guest has reserved
/// for PEBS scratch use. The hypervisor:
/// 1. Translates `page_va` to its guest physical address (the page must be
///    currently mapped in guest paging — guest userspace is expected to have
///    `mlock`'d it).
/// 2. Populates the DS Management Area at the start of the page.
/// 3. Remaps the page in EPT as R+E (no W). PEBS Buffer Base is set to a
///    later offset within the same page; the next PEBS record write will trap.
/// 4. Stores `PebsState` in `VmState`. Subsequent precise-exit arming reads
///    from this state to find the GPA / DS_AREA linear address.
///
/// Returns the `RegisterPebsPageResult` value to encode into guest RAX.
pub fn register_pebs_page<C: VmContext, A: CowAllocator<C::CowPage>>(
    ctx: &mut C,
    allocator: &mut A,
    page_va: u64,
) -> RegisterPebsPageResult {
    if !ctx.state().pebs_supported {
        // Host CPU lacks the architectural PEBS support bedrock relies on
        // (most commonly: running inside a basic-CPU QEMU/KVM L1 that
        // doesn't expose PEBS to nested guests). Refuse here — once
        // registered, every VM-entry would touch PEBS MSRs and `#GP`.
        return RegisterPebsPageResult::Unsupported;
    }
    if page_va & 0xFFF != 0 {
        return RegisterPebsPageResult::Misaligned;
    }
    if ctx.state().pebs_state.is_some() {
        return RegisterPebsPageResult::AlreadyRegistered;
    }

    let gpa = match translate_gva_to_gpa(ctx, page_va) {
        Ok(g) => g,
        Err(()) => return RegisterPebsPageResult::Untranslatable,
    };
    // Page-align the GPA: translate_gva_to_gpa preserves the byte offset
    // within the page; we want the page-aligned GPA.
    let gpa_page = gpa.as_u64() & !0xFFF;

    // Confirm the page is already mapped in EPT (we don't allocate it here —
    // the guest is responsible for touching the page before registering).
    if ctx
        .state()
        .ept
        .lookup(allocator, GuestPhysAddr::new(gpa_page))
        .is_none()
    {
        return RegisterPebsPageResult::NotEptMapped;
    }

    // Use the kernel direct-map alias for IA32_DS_AREA, not the userspace VA.
    // The userspace VA is only valid in bedrock-pebs-register's CR3; when
    // the guest scheduler swaps in a different process while PEBS is armed,
    // the PEBS engine resolves IA32_DS_AREA through the current CR3 and
    // takes a guest #PF if the VA isn't mapped there. The kernel direct map
    // is mapped in every process's CR3 (the kernel half), so it works
    // regardless of which process is current.
    let kernel_va = GUEST_LINUX_PAGE_OFFSET + gpa_page;

    // Populate the DS Management Area at the start of the page. The host
    // writes through its own kernel mapping of the host-physical page, which
    // is unaffected by EPT permissions on the guest side.
    let area = build_ds_management_area(kernel_va);
    let bytes = ds_management_area_bytes(&area);
    if ctx
        .write_guest_memory(GuestPhysAddr::new(gpa_page), &bytes)
        .is_err()
    {
        return RegisterPebsPageResult::NotEptMapped;
    }

    // Re-map the EPT entry as R+E (no W) so subsequent PEBS record writes
    // trap. Writes from the host (via `write_guest_memory`) bypass EPT, so we
    // can still update the DS_AREA contents from the host side later if
    // needed (e.g., to reset `pebs_index` between arming cycles).
    let host_phys = match ctx
        .state()
        .ept
        .lookup(allocator, GuestPhysAddr::new(gpa_page))
    {
        Some((hp, _)) => hp,
        None => return RegisterPebsPageResult::NotEptMapped,
    };
    if ctx
        .state_mut()
        .ept
        .remap_4k(
            allocator,
            GuestPhysAddr::new(gpa_page),
            host_phys,
            EptPermissions::READ_EXECUTE,
            EptMemoryType::WriteBack,
        )
        .is_err()
    {
        return RegisterPebsPageResult::NotEptMapped;
    }

    // Enable IA32_FIXED_CTR0 in the guest PERF_GLOBAL_CTRL VMCS field so
    // the PEBS counter ticks during guest execution. Bit 32 selects
    // IA32_FIXED_CTR0; we OR it into whatever the kernel's instruction
    // counter already sets (bit 0 for IA32_PMC0) so both counters run. The
    // host PERF_GLOBAL_CTRL stays unchanged — FIXED_CTR0 is gated off
    // during host execution. See SDM Vol 3B Section 21.4.2.
    if let Ok(prev) = ctx
        .state()
        .vmcs
        .read64(VmcsField64::GuestIa32PerfGlobalCtrl)
    {
        let _ = ctx.state().vmcs.write64(
            VmcsField64::GuestIa32PerfGlobalCtrl,
            prev | PERF_GLOBAL_CTRL_FIXED_CTR0,
        );
    }

    // Wire the VM-exit MSR-load list to disable IA32_PEBS_ENABLE atomically
    // on every VM-exit. PEBS records can be pending after the eventing
    // instruction (Reduced Skid PEBS, SDM Vol 3B 21.9.4) and EPT-friendly
    // PEBS may defer a record until after the subsequent VM entry (Vol 3B
    // 21.9.5). If a pending record reaches host context with the guest's
    // IA32_DS_AREA still loaded, the write attempts a supervisor access to the
    // guest VA and faults under SMAP. Setting PEBS_ENABLE = 0 atomically with
    // VM-exit tells the PEBS engine to drop any pending record before the host
    // runs a single instruction. See SDM Vol 3C Section 26.7.2 and Section
    // 29.6 (VM-exit MSR-load area).
    let exit_load_pa = ctx.state().pebs_exit_msr_load_page.physical_address();
    let _ = ctx
        .state()
        .vmcs
        .write64(VmcsField64::VmExitMsrLoadAddr, exit_load_pa.as_u64());
    let _ = ctx.state().vmcs.write32(VmcsField32::VmExitMsrLoadCount, 1);
    // The VM-entry MSR-load list pointer is owned by the instruction counter
    // when disarmed (single entry: `IA32_FIXED_CTR0`). `pebs_pre_vm_entry`
    // repoints it at `pebs_entry_msr_load_page` per-iteration when armed,
    // and `pebs_post_vm_exit` switches it back. Nothing to wire here.

    ctx.state_mut().pebs_state = Some(heap_box(PebsState {
        ds_management_gpa: gpa_page,
        pebs_buffer_gpa: gpa_page,
        // The guest linear address loaded into IA32_DS_AREA — kernel
        // direct-map alias of the registered page so it's valid in every
        // process's CR3, not just the registering process's.
        ds_area_va: kernel_va,
        armed_action: None,
        armed_target_tsc: 0,
        armed_inst_count: 0,
        armed_tsc_offset: 0,
        iters_since_arm: 0,
        counter_reload: 0,
        fixed_ctr_ctrl: FIXED_CTR_CTRL_FC0_OS_USR,
        // PEBS for IA32_FIXED_CTR0 (bit 32). See SDM Vol 3B Figure 21-68.
        pebs_enable: 1u64 << 32,
        // Basic PEBS record — adaptive path didn't change skid.
        pebs_data_cfg: 0,
        host_msrs: PebsHostMsrs::default(),
        logged_first_arm: false,
    }));

    log_info!(
        "HYPERCALL_REGISTER_PEBS_PAGE: user_va={:#x} kernel_va={:#x} gpa={:#x}\n",
        page_va,
        kernel_va,
        gpa_page
    );

    RegisterPebsPageResult::Success
}

#[cfg(all(test, feature = "cargo"))]
mod tests {
    use super::*;

    fn make_pebs_state() -> PebsState {
        PebsState {
            ds_management_gpa: 0x1000,
            pebs_buffer_gpa: 0x1000,
            ds_area_va: 0xffff_8000_0000_1000,
            armed_action: None,
            armed_target_tsc: 0,
            armed_inst_count: 0,
            armed_tsc_offset: 0,
            iters_since_arm: 0,
            counter_reload: 0,
            fixed_ctr_ctrl: FIXED_CTR_CTRL_FC0_OS_USR,
            pebs_enable: 1u64 << 32,
            pebs_data_cfg: 0,
            host_msrs: PebsHostMsrs::default(),
            logged_first_arm: false,
        }
    }

    #[test]
    fn arm_already_past_returns_already_past_and_does_not_arm() {
        let mut p = make_pebs_state();
        let r = arm_precise_exit(&mut p, 100, 50, PebsAction::InjectInterrupt(0x20), 0, 0);
        assert_eq!(r, ArmResult::AlreadyPast);
        assert!(p.armed_action.is_none());
    }

    #[test]
    fn arm_below_min_delta_returns_below_min_delta() {
        let mut p = make_pebs_state();
        // delta < PEBS_MIN_DELTA + PEBS_MARGIN: encoded distance would be
        // below the PDist threshold. Caller falls back to MTF stepping
        // for the entire remaining range.
        let target = 100 + PEBS_MIN_DELTA + get_pebs_margin() - 1;
        let r = arm_precise_exit(&mut p, 100, target, PebsAction::InjectInterrupt(0x20), 0, 0);
        assert_eq!(r, ArmResult::BelowMinDelta);
        assert!(p.armed_action.is_none());
    }

    #[test]
    fn arm_minimum_delta_writes_correct_counter_reload() {
        let mut p = make_pebs_state();
        // Smallest delta that arms PEBS under Bedrock's conservative cutoff:
        // encoded distance = PEBS_MIN_DELTA.
        let delta = PEBS_MIN_DELTA + get_pebs_margin();
        let r = arm_precise_exit(
            &mut p,
            100,
            100 + delta,
            PebsAction::InjectInterrupt(0x20),
            0,
            0,
        );
        assert_eq!(r, ArmResult::Armed);
        let encoded = delta - get_pebs_margin();
        assert_eq!(p.counter_reload, encoded.wrapping_neg() & PMC_COUNTER_MASK);
        // armed_target_tsc tracks the PEBS firing point (target - margin),
        // not the requested target — so skid measures hardware imprecision.
        assert_eq!(p.armed_target_tsc, 100 + delta - get_pebs_margin());
        assert!(matches!(
            p.armed_action,
            Some(PebsAction::InjectInterrupt(0x20))
        ));
    }

    #[test]
    fn arm_large_delta_writes_correct_counter_reload() {
        let mut p = make_pebs_state();
        // delta = 1_000_000 → counter_reload encodes (delta - PEBS_MARGIN).
        let delta: u64 = 1_000_000;
        let r = arm_precise_exit(&mut p, 0, delta, PebsAction::InjectInterrupt(0x20), 0, 0);
        assert_eq!(r, ArmResult::Armed);
        let encoded = delta - get_pebs_margin();
        let expected = encoded.wrapping_neg() & PMC_COUNTER_MASK;
        assert_eq!(p.counter_reload, expected);
        // Sanity: counter wraps to zero after `encoded` increments.
        let wrapped = p.counter_reload.wrapping_add(encoded) & PMC_COUNTER_MASK;
        assert_eq!(wrapped, 0);
    }

    #[test]
    fn arm_overwrites_previous_action() {
        let mut p = make_pebs_state();
        let _ = arm_precise_exit(&mut p, 0, 1000, PebsAction::InjectInterrupt(0x20), 0, 0);
        let _ = arm_precise_exit(&mut p, 0, 1000, PebsAction::InjectInterrupt(0x30), 0, 0);
        assert!(matches!(
            p.armed_action,
            Some(PebsAction::InjectInterrupt(0x30))
        ));
    }

    #[test]
    fn disarm_clears_armed_action_idempotent() {
        let mut p = make_pebs_state();
        let _ = arm_precise_exit(&mut p, 0, 1000, PebsAction::InjectInterrupt(0x20), 0, 0);
        disarm_precise_exit(&mut p);
        assert!(p.armed_action.is_none());
        // Idempotent.
        disarm_precise_exit(&mut p);
        assert!(p.armed_action.is_none());
    }

    fn ept_qual(write: bool, asynchronous: bool) -> EptViolationQualification {
        EptViolationQualification {
            read: false,
            write,
            execute: false,
            readable: true,
            writable: false,
            executable: true,
            guest_linear_valid: false,
            asynchronous,
        }
    }

    #[test]
    fn is_pebs_induced_requires_async_and_write() {
        // Bit 16 = asynchronous, RW = write.
        assert!(is_pebs_induced(&ept_qual(true, true)));
        // Async without write — Intel PT trace output, user-interrupt
        // delivery, etc. Not a PEBS record write.
        assert!(!is_pebs_induced(&ept_qual(false, true)));
        // Write without async — normal CoW / MMIO fault.
        assert!(!is_pebs_induced(&ept_qual(true, false)));
        // Neither — instruction fetch, normal read fault.
        assert!(!is_pebs_induced(&ept_qual(false, false)));
    }
}

/// Handler invoked from `handle_ept_violation` when an exit is identified as
/// PEBS-induced. Consumes the armed action (one-shot) and either injects an
/// external interrupt or exits to userspace; PEBS gets disarmed by clearing
/// `armed_action` so the next VM-entry's MSR-load list will write a zero
/// `IA32_PEBS_ENABLE` (wired in stage 4).
pub fn handle_pebs_precise_exit<C: VmContext>(ctx: &mut C) -> ExitHandlerResult {
    // One-shot log of the first PEBS exit: helps identify hangs in the
    // exit-handler loop vs hangs that occur before the first exit.
    #[cfg(not(feature = "cargo"))]
    {
        use core::sync::atomic::{AtomicBool, Ordering};
        static LOGGED: AtomicBool = AtomicBool::new(false);
        if !LOGGED.swap(true, Ordering::Relaxed) {
            log_info!(
                "PEBS first-exit: tsc={} action={:?}\n",
                ctx.state().emulated_tsc,
                ctx.state()
                    .pebs_state
                    .as_deref()
                    .and_then(|p| p.armed_action),
            );
        }
    }
    // Record diagnostics on the EPT_VIOLATION_PEBS log entry (non-
    // deterministic, since asynchronous + write) before consuming the
    // armed action. The skid (= current_tsc - target) plus three
    // breakdown components let us distinguish hardware imprecision from
    // hypervisor bugs:
    //   pebs_inst_delta      = INST_RETIRED gain since arming (PMC0 ticks
    //                          should equal this minus host-side ticks).
    //   pebs_tsc_offset_delta = HLT/MWAIT clamps that advanced emulated_tsc
    //                          without retiring guest instructions. Should
    //                          be 0 — PEBS exits aren't preceded by idle
    //                          clamps within the same iter.
    //   pebs_iters_since_arm  = run-loop iterations the firing arming
    //                          persisted across. > 0 means the arming
    //                          carried through one or more non-PEBS exits
    //                          (e.g., external interrupts) before firing.
    //
    // Skid uses `last_instruction_count + tsc_offset`, not `emulated_tsc`:
    // PEBS-induced EPT violations are non-deterministic, so the dispatcher
    // doesn't refresh `emulated_tsc` before the handler runs. Reading it
    // here would compare the previous deterministic exit's TSC against
    // the current target and produce a meaningless (large negative)
    // skid. The fresh `inst_count + offset` composition is always
    // current.
    let inst_count_now = ctx.state().last_instruction_count;
    let tsc_offset_now = ctx.state().tsc_offset;
    let current_tsc = inst_count_now.saturating_add(tsc_offset_now);
    let (armed_target, armed_inst, armed_offset, iters) = ctx
        .state()
        .pebs_state
        .as_deref()
        .map(|p| {
            (
                p.armed_target_tsc,
                p.armed_inst_count,
                p.armed_tsc_offset,
                p.iters_since_arm,
            )
        })
        .unwrap_or((0, 0, 0, 0));
    if armed_target != 0 {
        // Reconstruct the arm-time delta: at arming, current_tsc was
        // `armed_inst + armed_offset`, so the requested distance was
        // `target - (armed_inst + armed_offset)`. Used by the skid
        // histogram to correlate outliers with arming regime.
        let arm_current = armed_inst.saturating_add(armed_offset);
        let arm_delta = armed_target.saturating_sub(arm_current);
        let state = ctx.state_mut();
        let skid = (current_tsc as i64) - (armed_target as i64);
        state.last_pebs_skid = skid;
        state.exit_stats.max_pebs_skid = state.exit_stats.max_pebs_skid.max(skid);
        state.last_pebs_inst_delta = (inst_count_now as i64) - (armed_inst as i64);
        state.last_pebs_tsc_offset_delta = (tsc_offset_now as i64) - (armed_offset as i64);
        state.last_pebs_iters_since_arm = iters;
        state.last_pebs_arm_delta = arm_delta;
    }

    // `take()` consumes the armed action *and* clears it, so the disarm step
    // is implicit: with `armed_action == None`, the next VM-entry's PEBS
    // load path becomes a no-op and the counter stays parked.
    let action = ctx
        .state_mut()
        .pebs_state
        .as_deref_mut()
        .and_then(|p| p.armed_action.take());
    match action {
        Some(PebsAction::InjectInterrupt(_vector)) => {
            // PEBS fired near the APIC timer deadline, normally at
            // `target - PEBS_MARGIN`. Continue through the normal pre-entry
            // path so `update_mtf_state` can single-step the remaining margin
            // and `inject_pending_interrupt` / `check_apic_timer` can set IRR
            // and inject exactly at the deadline. We don't bypass that path
            // because it also re-arms PEBS for the next periodic deadline and
            // updates APIC ISR/IRR state correctly. The vector argument is
            // informational (kept for future non-APIC-timer uses).
            ExitHandlerResult::Continue
        }
        None => {
            // Spurious PEBS-induced exit (no action armed). Could happen if
            // PEBS was pending across a disarm; just continue.
            log_warn!("unexpected PEBS-induced EPT violation with no armed action\n");
            ExitHandlerResult::Continue
        }
    }
}
