// SPDX-License-Identifier: GPL-2.0

//! VM Exit handling for Intel VMX.
//!
//! This module provides abstractions for handling VM exits in a testable manner.
//! The key abstraction is the `VmContext` trait which allows mocking the VMCS
//! and guest state for unit testing.
//!
//! # Module Organization
//!
//! - `reasons`: Exit reason enum and parsing
//! - `qualifications`: Exit qualification types (CR access, I/O, EPT, interrupts)
//! - `helpers`: Error types and shared helper functions
//! - `cpuid`: CPUID exit handler
//! - `msr`: MSR read/write handlers
//! - `cr`: Control register access handler
//! - `io`: I/O port instruction handler
//! - `ept`: EPT violation handler and GVA translation
//! - `apic`: Local APIC and I/O APIC MMIO emulation
//! - `interrupts`: Interrupt injection and APIC timer handling
//! - `misc`: Exception handlers, XSETBV, triple fault debugging

mod apic;
mod cpuid;
mod cr;
mod ept;
mod helpers;
mod interrupts;
mod io;
mod misc;
mod msr;
mod pebs;
mod qualifications;
mod rdrand;
mod reasons;
mod time;
mod vmcall;

// Re-export public types
pub use apic::{APIC_BASE, APIC_SIZE, IOAPIC_BASE, IOAPIC_SIZE};
pub use helpers::{ExitError, ExitHandlerResult};
pub use interrupts::{
    check_io_channel, inject_pending_interrupt, reinject_vectored_event, IO_CHANNEL_IRQ,
};
pub use pebs::{
    arm_for_next_iteration, arm_precise_exit, disarm_precise_exit, pebs_post_vm_exit,
    pebs_pre_vm_entry, ArmResult, DsManagementArea, PebsAction, PebsState, PEBS_MARGIN,
    PEBS_MIN_DELTA, PERF_GLOBAL_CTRL_FIXED_CTR0,
};
pub use qualifications::{
    CrAccessQualification, EptViolationQualification, IoQualification, RdrandInstructionInfo,
    RdrandOperandSize,
};
pub use reasons::ExitReason;
pub use vmcall::{
    FB_ERR_BAD_ID_LEN, FB_ERR_BAD_SIZE, FB_ERR_BUFFER_NOT_RESIDENT, FB_ERR_ID_NOT_RESIDENT,
    FB_ERR_NO_SLOTS,
};

// Internal imports for handle_exit
use cpuid::handle_cpuid;
use cr::handle_cr_access;
use ept::handle_ept_violation;
use helpers::{advance_rip, read_exit_qualification, read_exit_reason, ExitError as EE};
use interrupts::{disable_interrupt_window_exiting, handle_external_interrupt};
use io::handle_io;
use misc::{dump_triple_fault_state, handle_exception_nmi, handle_xsetbv};
use msr::{handle_msr_read, handle_msr_write};
use rdrand::{handle_rdrand, handle_rdseed};
use time::{handle_idle, handle_rdpmc, handle_rdtsc, handle_rdtscp};
use vmcall::handle_vmcall;

#[cfg(not(feature = "cargo"))]
use super::prelude::*;
#[cfg(feature = "cargo")]
use crate::prelude::*;

/// Compute the retired-instruction count at which the next pending APIC
/// timer would fire (= `timer_deadline - tsc_offset`). Returns `None` if
/// the timer is disarmed, the APIC is software-disabled, or the LVT entry
/// is masked.
fn next_timer_exit_count<C: VmContext>(ctx: &C) -> Option<u64> {
    let state = ctx.state();
    let apic = &state.devices.apic;
    if apic.timer_deadline == 0 {
        return None;
    }
    if (apic.svr & (1 << 8)) == 0 {
        return None;
    }
    if (apic.lvt_timer & (1 << 16)) != 0 {
        return None;
    }
    Some(apic.timer_deadline.saturating_sub(state.tsc_offset))
}

/// Target emulated TSC at which the pending I/O channel request should
/// fire. Returns `None` if there's nothing armable:
/// - no request queued, or already delivered;
/// - no target TSC (`request_target_tsc == 0` means "fire ASAP", which
///   doesn't need PEBS precision — the normal IRR-setting path covers
///   it);
/// - the guest module hasn't wired up its IRQ yet (IOAPIC entry masked
///   or vector < 16);
/// - the page isn't registered (the GET_REQUEST hypercall would fail
///   so there's no point in firing).
///
/// Shared between `next_io_channel_exit_count` (MTF/margin logic, which
/// works in instruction-count space) and `arm_for_next_iteration` (which
/// works in TSC space) so the readiness predicate has exactly one
/// definition.
pub(super) fn next_io_channel_target_tsc<C: VmContext>(ctx: &C) -> Option<u64> {
    let chan = &ctx.state().io_channel;
    if chan.page_gpa == 0 {
        return None;
    }
    if chan.request_len == 0 || chan.request_delivered {
        return None;
    }
    if chan.request_target_tsc == 0 {
        return None;
    }
    let entry = ctx.state().devices.ioapic.redtbl[interrupts::IO_CHANNEL_IRQ as usize];
    if (entry >> 16) & 1 != 0 || (entry & 0xFF) < 16 {
        return None;
    }
    Some(chan.request_target_tsc)
}

/// Compute the retired-instruction count at which the pending I/O
/// channel request should fire, mirroring `next_timer_exit_count` for
/// the deterministic I/O channel target.
pub(super) fn next_io_channel_exit_count<C: VmContext>(ctx: &C) -> Option<u64> {
    next_io_channel_target_tsc(ctx).map(|t| t.saturating_sub(ctx.state().tsc_offset))
}

/// Emulated-TSC target at which single-stepping should *begin* for the
/// configured single-step TSC range, or `None` if no range is configured
/// or the window has already been entered.
///
/// Activating single-step lazily — "enable MTF on the first exit whose
/// `count + tsc_offset` has crossed `start`" — makes the start point
/// non-deterministic: whichever exit happens to cross the boundary first
/// wins, and that can be a non-deterministic host-interrupt VM-exit which
/// lands at a different instruction count in each fork. The forks then
/// begin logging at different counts and their per-instruction streams
/// compare as divergent even though the guest executed identically.
///
/// Treating the window start as a precise-exit target — armed by
/// `arm_for_next_iteration` and approached via the MTF margin in
/// `update_mtf_state`, exactly like the APIC timer / I/O channel /
/// `stop_at_tsc` targets — lands the first single-step VM-exit on
/// `count + tsc_offset == start` deterministically across forks.
pub(super) fn next_single_step_start_tsc<C: VmContext>(ctx: &C) -> Option<u64> {
    let (start, _end) = ctx.state().single_step_tsc_range?;
    let current = ctx.state().last_instruction_count + ctx.state().tsc_offset;
    (current < start).then_some(start)
}

/// Instruction-count-space counterpart of `next_single_step_start_tsc`,
/// for the MTF margin / boundary checks (which work in count space).
fn next_single_step_start_count<C: VmContext>(ctx: &C) -> Option<u64> {
    next_single_step_start_tsc(ctx).map(|t| t.saturating_sub(ctx.state().tsc_offset))
}

/// Width of the MTF single-step window approaching an APIC timer deadline.
///
/// PEBS arms to fire at `target - PEBS_MARGIN`. When the encoded distance
/// is too short for PDist (`delta < PEBS_MIN_DELTA + PEBS_MARGIN` in
/// `arm_precise_exit`), PEBS doesn't arm at all — but the count is by
/// construction within `PEBS_MIN_DELTA + PEBS_MARGIN` of the target, so
/// MTF single-stepping starting at the entering exit lands on the
/// boundary in at most that many steps. Sized to cover both the normal
/// case (PEBS lands inside the window, MTF steps the final
/// `PEBS_MARGIN`) and the BelowMinDelta case (no PEBS, MTF steps the
/// full window). Without this width, a non-deterministic exit landing
/// close to the deadline produces a `BelowMinDelta` arming, no PEBS
/// trap, and the timer fires at whatever natural deterministic exit
/// happens past the deadline — which differs across runs.
const MTF_MARGIN: u64 = PEBS_MIN_DELTA + PEBS_MARGIN;

/// Update MTF (Monitor Trap Flag) state.
///
/// Enables MTF (one VM-exit per retired guest instruction) when either:
///
/// 1. Single-stepping is configured and the current TSC is within the
///    configured range, or
/// 2. PEBS is registered (`pebs_state.is_some()`) and the retired-
///    instruction count is within `MTF_MARGIN` of the next APIC timer
///    deadline. In the normal case PEBS fires at `target - PEBS_MARGIN`
///    and MTF single-steps the final `PEBS_MARGIN` instructions; in the
///    short-delta case PEBS doesn't arm and MTF steps the entire
///    remaining range. Either way the boundary MTF (count == target)
///    lands deterministically and `inject_pending_interrupt` delivers
///    the timer at the exact instruction.
///
/// The PEBS-registered gate on (2) prevents a determinism trap before
/// the guest registers the PEBS scratch page: with no PEBS arming, the
/// margin window only ever engages when some non-deterministic exit
/// (e.g., a host external interrupt) happens to land inside it. One run
/// gets that exit and lands the boundary MTF precisely; the other run
/// doesn't and falls through to a late inject at the next deterministic
/// exit past the deadline. Suppressing the margin while PEBS is
/// unregistered forces both runs onto the same late-inject path.
///
/// Uses `last_instruction_count + tsc_offset` rather than `emulated_tsc`
/// so the check is correct on non-deterministic exits (where
/// `emulated_tsc` is stale) and on intermediate MTF margin steps.
pub fn update_mtf_state<C: VmContext>(ctx: &mut C) -> Result<(), ExitError> {
    let count = ctx.state().last_instruction_count;
    let tsc = count + ctx.state().tsc_offset;
    let range = ctx.state().single_step_tsc_range;
    let currently_enabled = ctx.state().mtf_enabled;
    let pebs_registered = ctx.state().pebs_state.is_some();

    let in_single_step = match range {
        Some((start, end)) => tsc >= start && tsc < end,
        None => false,
    };

    // The PEBS margin gate fires whenever we're inside the
    // [target - MTF_MARGIN, target) window of *any* precise-exit target:
    // the APIC timer, the I/O channel target, or `stop_at_tsc`. Each gets
    // the same MTF treatment so the final approach single-steps onto the
    // exact boundary, regardless of which target PEBS itself happened to
    // arm for this iteration (PEBS is a single counter; the others get
    // covered by MTF stepping when their windows are entered).
    let in_margin = |target_opt: Option<u64>| match target_opt {
        Some(target) => count >= target.saturating_sub(MTF_MARGIN) && count < target,
        None => false,
    };
    let stop_at_count = ctx
        .state()
        .stop_at_tsc
        .map(|t| t.saturating_sub(ctx.state().tsc_offset));
    let in_pebs_margin = pebs_registered
        && (in_margin(next_timer_exit_count(ctx))
            || in_margin(next_io_channel_exit_count(ctx))
            || in_margin(stop_at_count)
            || in_margin(next_single_step_start_count(ctx)));

    let should_enable = in_single_step || in_pebs_margin;

    if should_enable != currently_enabled {
        // Toggle MTF in primary processor-based controls
        let mut controls = ctx
            .state()
            .vmcs
            .read32(VmcsField32::PrimaryProcBasedVmExecControls)
            .map_err(|_| EE::Fatal("Failed to read primary controls for MTF"))?;

        if should_enable {
            controls |= cpu_based::MONITOR_TRAP_FLAG;
        } else {
            controls &= !cpu_based::MONITOR_TRAP_FLAG;
        }

        ctx.state()
            .vmcs
            .write32(VmcsField32::PrimaryProcBasedVmExecControls, controls)
            .map_err(|_| EE::Fatal("Failed to write primary controls for MTF"))?;

        ctx.state_mut().mtf_enabled = should_enable;
    }

    Ok(())
}

/// Handle a VM exit.
///
/// This is the main entry point for VM exit handling. It reads the exit reason
/// and dispatches to the appropriate handler.
///
/// # Returns
///
/// - `ExitHandlerResult::Continue` if the exit was handled and guest execution should continue
/// - `ExitHandlerResult::ExitToUserspace(reason)` if control should return to userspace
/// - `ExitHandlerResult::Error(e)` if a fatal error occurred
pub fn handle_exit<C: VmContext, K: Kernel, A: CowAllocator<C::CowPage>>(
    ctx: &mut C,
    kernel: &K,
    allocator: &mut A,
) -> ExitHandlerResult {
    // Start timing the exit handler
    let start_tsc = rdtsc();

    let reason = match read_exit_reason(ctx) {
        Ok(r) => r,
        Err(e) => return ExitHandlerResult::Error(e),
    };

    let qual = match read_exit_qualification(ctx) {
        Ok(q) => q,
        Err(e) => return ExitHandlerResult::Error(e),
    };

    let non_deterministic_exit = match reason {
        ExitReason::ExternalInterrupt
        | ExitReason::VmxPreemptionTimer
        | ExitReason::ExceptionNmi => true,
        // EPT violations are deterministic only when they correspond to
        // APIC/IOAPIC MMIO emulation. PEBS-induced exits (bit 16 of the
        // exit qualification) fire at `target - PEBS_MARGIN` with possible
        // PDist skid, so they're treated as non-deterministic — only the
        // boundary MTF (count == target) below is deterministic. Other
        // EPT violations (COW faults, stale TLB hits, unmapped pages) are
        // non-deterministic.
        ExitReason::EptViolation => {
            let ept_qual = EptViolationQualification::from(qual);
            if ept_qual.asynchronous && ept_qual.write {
                true
            } else {
                let gpa = ctx
                    .state()
                    .vmcs
                    .read64(VmcsField64::GuestPhysicalAddr)
                    .unwrap_or(0);
                !((APIC_BASE..APIC_BASE + APIC_SIZE).contains(&gpa)
                    || (IOAPIC_BASE..IOAPIC_BASE + IOAPIC_SIZE).contains(&gpa))
            }
        }
        // MTF exits are deterministic only when they land on the next
        // APIC-timer-deadline boundary or the I/O channel target
        // boundary (the precise-injection use cases) or inside a
        // configured single-step TSC range. Intermediate margin-window
        // steps fire at instruction counts that depend on PEBS skid, so
        // they're non-deterministic.
        ExitReason::MonitorTrapFlag => {
            let count = ctx.state().last_instruction_count;
            let tsc = count + ctx.state().tsc_offset;
            let on_target = |t: Option<u64>| matches!(t, Some(target) if count == target);
            let stop_at_count = ctx
                .state()
                .stop_at_tsc
                .map(|t| t.saturating_sub(ctx.state().tsc_offset));
            let on_boundary = on_target(next_timer_exit_count(ctx))
                || on_target(next_io_channel_exit_count(ctx))
                || on_target(stop_at_count);
            let in_single_step_range = match ctx.state().single_step_tsc_range {
                Some((start, end)) => tsc >= start && tsc < end,
                None => false,
            };
            !(on_boundary || in_single_step_range)
        }
        _ => false,
    };

    ctx.state_mut().last_exit_deterministic = !non_deterministic_exit;

    // Update emulated TSC from instruction count + offset for deterministic exits.
    // This ensures RDTSC/RDTSCP return values that correlate with guest progress.
    // The offset is increased by time-advancing exits like HLT/MWAIT.
    if !non_deterministic_exit {
        let tsc = ctx.state().last_instruction_count + ctx.state().tsc_offset;
        ctx.state_mut().emulated_tsc = tsc;
    }

    // Handle the exit FIRST, before any logging or threshold checks.
    // This ensures device state is fully updated before we potentially
    // return to userspace (e.g., for forked VMs to get clean state).
    let result = match reason {
        ExitReason::Cpuid => handle_cpuid(ctx),
        ExitReason::MsrRead => handle_msr_read(ctx),
        ExitReason::MsrWrite => handle_msr_write(ctx),
        ExitReason::CrAccess => handle_cr_access(ctx, CrAccessQualification::from(qual)),
        ExitReason::IoInstruction => handle_io(ctx, IoQualification::from(qual)),
        ExitReason::EptViolation => {
            handle_ept_violation(ctx, EptViolationQualification::from(qual), allocator)
        }
        ExitReason::ExceptionNmi => handle_exception_nmi(ctx),
        ExitReason::Xsetbv => handle_xsetbv(ctx),

        // Time-related exits for deterministic emulation
        ExitReason::Rdtsc => handle_rdtsc(ctx),
        ExitReason::Rdtscp => handle_rdtscp(ctx),
        ExitReason::Rdpmc => handle_rdpmc(ctx),

        // RDRAND/RDSEED exits for random number emulation
        ExitReason::Rdrand => handle_rdrand(ctx),
        ExitReason::Rdseed => handle_rdseed(ctx),

        // Monitor Trap Flag - VM exit after each guest instruction (single-step mode)
        // The exit is already logged above; just continue executing.
        ExitReason::MonitorTrapFlag => ExitHandlerResult::Continue,

        ExitReason::Hlt => handle_idle(ctx),

        ExitReason::Mwait => handle_idle(ctx),

        ExitReason::Monitor => {
            // MONITOR sets up address-range monitoring hardware for use with MWAIT.
            // We intercept it (MONITOR_EXITING=1) to ensure deterministic behavior:
            // by not actually arming the monitor hardware, MWAIT exit qualification
            // will always be 0 (not armed), regardless of external interrupt timing.
            // This is safe because our MWAIT handler advances TSC to the timer deadline
            // anyway - we don't rely on memory store wakeups.
            if let Err(e) = advance_rip(ctx) {
                return ExitHandlerResult::Error(e);
            }
            ExitHandlerResult::Continue
        }

        ExitReason::TripleFault => {
            // Dump detailed VMCS state for debugging
            dump_triple_fault_state(ctx);
            ExitHandlerResult::Error(EE::TripleFault)
        }

        ExitReason::InvalidGuestState => ExitHandlerResult::Error(EE::InvalidGuestState),

        // VMCALL - hypercall interface
        ExitReason::Vmcall => handle_vmcall(ctx, allocator),

        // Other VMX instructions - exit to userspace (guest shouldn't use nested VMX)
        ExitReason::Vmclear
        | ExitReason::Vmlaunch
        | ExitReason::Vmptrld
        | ExitReason::Vmptrst
        | ExitReason::Vmread
        | ExitReason::Vmresume
        | ExitReason::Vmwrite
        | ExitReason::Vmxoff
        | ExitReason::Vmxon => {
            // Exit to userspace. Could inject #UD instead.
            ExitHandlerResult::ExitToUserspace(reason)
        }

        // VMX preemption timer - return to userspace to give it a heartbeat.
        // This allows userspace to receive serial output periodically and
        // check for signals. Userspace should just call RUN again.
        ExitReason::VmxPreemptionTimer => {
            // Reset the preemption timer for the next run (~10ms)
            if ctx
                .state()
                .vmcs
                .write32(VmcsField32::VmxPreemptionTimerValue, 0x100000)
                .is_err()
            {
                return ExitHandlerResult::Error(EE::Fatal("Failed to reset preemption timer"));
            }
            ExitHandlerResult::ExitToUserspace(reason)
        }

        // External interrupt - handled in-kernel by briefly enabling interrupts.
        // The pending interrupt is delivered through the IDT.
        ExitReason::ExternalInterrupt => {
            handle_external_interrupt(kernel);
            ExitHandlerResult::Continue
        }

        // Interrupt window opened - guest is now interruptible
        // Disable interrupt-window exiting; inject_pending_interrupt() will inject on next VM entry
        ExitReason::InterruptWindow => {
            if let Err(e) = disable_interrupt_window_exiting(ctx) {
                return ExitHandlerResult::Error(e);
            }
            ExitHandlerResult::Continue
        }

        // Other external events that should return to userspace
        ExitReason::Init
        | ExitReason::Sipi
        | ExitReason::NmiWindow
        | ExitReason::TprBelowThreshold
        | ExitReason::ApicAccess
        | ExitReason::ApicWrite => ExitHandlerResult::ExitToUserspace(reason),

        // Unhandled exits - return to userspace
        _ => ExitHandlerResult::ExitToUserspace(reason),
    };

    // Record exit handler timing statistics. Non-deterministic margin-
    // window MTF steps go to a separate bucket so `mtf.count` stays
    // reproducible across runs (the determinism harness compares it).
    let end_tsc = rdtsc();
    let cycles = end_tsc.saturating_sub(start_tsc);
    if reason == ExitReason::MonitorTrapFlag && non_deterministic_exit {
        ctx.state_mut().exit_stats.pebs_margin_steps += 1;
    } else {
        ctx.state_mut().exit_stats.record(reason, cycles);
    }

    // Now that the exit is handled, do logging and threshold checks.
    // These happen AFTER exit handling so device state is clean.

    // Update MTF state after the handler. Runs unconditionally because the
    // PEBS-margin window needs to enable on the PEBS-induced EPT violation
    // (non-deterministic) and stay enabled across the intermediate MTF
    // margin steps (also non-deterministic) until the count lands on the
    // boundary (count == target, deterministic). Time-advancing exits
    // (MWAIT/HLT via handle_idle) update emulated_tsc and tsc_offset; we
    // use last_instruction_count + tsc_offset directly so the check is
    // correct regardless.
    if let Err(e) = update_mtf_state(ctx) {
        return ExitHandlerResult::Error(e);
    }

    // Check if stop-at-tsc threshold is reached (deterministic exits only)
    if !non_deterministic_exit {
        if let Some(stop_tsc) = ctx.state().stop_at_tsc {
            if ctx.state().emulated_tsc >= stop_tsc {
                // Log what exit triggered stop-at-tsc and full APIC state
                let apic = &ctx.state().devices.apic;
                log_err!(
                    "STOP-AT-TSC: exit={:?}, tsc={}, deadline={}, initial={}, lvt_timer={:#x}, irr[7]={:#x}, isr[7]={:#x}\n",
                    reason,
                    ctx.state().emulated_tsc,
                    apic.timer_deadline,
                    apic.timer_initial,
                    apic.lvt_timer,
                    apic.irr[7],
                    apic.isr[7]
                );
                // Log state if AtShutdown mode is enabled (treat stop-at-tsc like shutdown)
                ctx.state_mut().capture_exit_at_shutdown();
                return ExitHandlerResult::ExitToUserspace(ExitReason::StopTscReached);
            }
        }
    }

    // Emit an `Exit` event if logging is enabled (both deterministic and
    // non-deterministic exits). A full event buffer is handled by the
    // `event_buffer_full` check below.
    //
    // We do this after the stop_at_tsc check so the guest is not re-entered
    // after returning to userspace (to drain a full buffer), which would make
    // the StopTscReached exit non-deterministic.
    if ctx.state().exit_capture_enabled() {
        ctx.state_mut()
            .capture_exit(reason, qual, !non_deterministic_exit);
    }

    // If event emission filled the event buffer during this exit and the exit
    // would otherwise re-enter the guest, force a drain round-trip to userspace;
    // the staged record is re-appended on the next RUN via `event_clear()`. When
    // `result` already exits to userspace, the buffer is drained there anyway,
    // so the original reason is left intact. Pure host-side — guest state is
    // unchanged, so this is deterministic.
    if ctx.state().event_buffer_full() && matches!(result, ExitHandlerResult::Continue) {
        return ExitHandlerResult::ExitToUserspace(ExitReason::EventBufferFull);
    }

    result
}

#[cfg(test)]
mod single_step_target_tests {
    use super::*;
    use crate::tests::MockVmContext;

    /// The single-step window start is armed as a precise-exit target only
    /// while the guest is still *before* the window, so the first
    /// single-step exit lands on `count + tsc_offset == start`
    /// deterministically. Once at/inside the window the range check in
    /// `update_mtf_state` keeps MTF on and the target falls away.
    #[test]
    fn single_step_start_armed_before_window_only() {
        let mut ctx = MockVmContext::new();
        // Window: emulated-TSC [10_000, 20_000). With tsc_offset = 1_000 the
        // count-space start is 10_000 - 1_000 = 9_000.
        ctx.state_mut().single_step_tsc_range = Some((10_000, 20_000));
        ctx.state_mut().tsc_offset = 1_000;

        // Before the window: armed at the start in both spaces.
        ctx.state_mut().last_instruction_count = 5_000; // emulated_tsc = 6_000
        assert_eq!(next_single_step_start_tsc(&ctx), Some(10_000));
        assert_eq!(next_single_step_start_count(&ctx), Some(9_000));

        // Exactly at the start: already entered, nothing left to arm.
        ctx.state_mut().last_instruction_count = 9_000; // emulated_tsc = 10_000
        assert_eq!(next_single_step_start_tsc(&ctx), None);
        assert_eq!(next_single_step_start_count(&ctx), None);

        // Inside the window: not armed (the range check keeps MTF on).
        ctx.state_mut().last_instruction_count = 14_000; // emulated_tsc = 15_000
        assert_eq!(next_single_step_start_tsc(&ctx), None);

        // No range configured: never armed.
        ctx.state_mut().single_step_tsc_range = None;
        ctx.state_mut().last_instruction_count = 5_000;
        assert_eq!(next_single_step_start_tsc(&ctx), None);
        assert_eq!(next_single_step_start_count(&ctx), None);
    }
}
