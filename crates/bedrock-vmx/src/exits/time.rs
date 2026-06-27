// SPDX-License-Identifier: GPL-2.0

//! Time-related VM exit handlers (RDTSC, RDTSCP, RDPMC, MWAIT, HLT).
//!
//! These handlers provide deterministic time emulation by intercepting
//! time-related instructions and returning controlled values.

#[cfg(not(feature = "cargo"))]
use super::super::prelude::*;
#[cfg(feature = "cargo")]
use crate::prelude::*;

use super::helpers::{advance_rip, ExitHandlerResult};

/// Handle RDTSC VM exit.
///
/// Returns the emulated TSC value in EDX:EAX and advances RIP.
/// The TSC value is derived from instruction count for determinism.
pub fn handle_rdtsc<C: VmContext>(ctx: &mut C) -> ExitHandlerResult {
    let tsc = ctx.state().emulated_tsc;

    // RDTSC returns TSC in EDX:EAX
    let gprs = &mut ctx.state_mut().gprs;
    gprs.rax = tsc & 0xFFFF_FFFF;
    gprs.rdx = tsc >> 32;

    // Advance past RDTSC instruction (2 bytes: 0x0F 0x31)
    if let Err(e) = advance_rip(ctx) {
        return ExitHandlerResult::Error(e);
    }

    ExitHandlerResult::Continue
}

/// Handle RDTSCP VM exit.
///
/// Returns the emulated TSC value in EDX:EAX, and TSC_AUX in ECX.
/// Then advances RIP.
pub fn handle_rdtscp<C: VmContext>(ctx: &mut C) -> ExitHandlerResult {
    let tsc = ctx.state().emulated_tsc;
    let tsc_aux = ctx.state().msr_state.tsc_aux;

    // RDTSCP returns TSC in EDX:EAX and TSC_AUX in ECX
    let gprs = &mut ctx.state_mut().gprs;
    gprs.rax = tsc & 0xFFFF_FFFF;
    gprs.rdx = tsc >> 32;
    gprs.rcx = tsc_aux & 0xFFFF_FFFF; // TSC_AUX is 32-bit

    // Advance past RDTSCP instruction (3 bytes: 0x0F 0x01 0xF9)
    if let Err(e) = advance_rip(ctx) {
        return ExitHandlerResult::Error(e);
    }

    ExitHandlerResult::Continue
}

/// Handle RDPMC VM exit.
///
/// Since we report no PMU support in CPUID.0AH, RDPMC should inject #GP(0).
/// However, for simplicity we just return 0 and continue.
pub fn handle_rdpmc<C: VmContext>(ctx: &mut C) -> ExitHandlerResult {
    // Return 0 for all performance counters
    let gprs = &mut ctx.state_mut().gprs;
    gprs.rax = 0;
    gprs.rdx = 0;

    // Advance past RDPMC instruction (2 bytes: 0x0F 0x33)
    if let Err(e) = advance_rip(ctx) {
        return ExitHandlerResult::Error(e);
    }

    ExitHandlerResult::Continue
}

/// Handle HLT/MWAIT VM exit.
///
/// Both idle until an interrupt. We advance the emulated TSC to the next wake
/// source so it fires on the next VM entry. Only an armed APIC timer is a wake
/// source; the I/O-channel request is host-scheduled and can sit far in the
/// guest's future, so it is folded in only as a *nearer bound* on the timer's
/// deadline, never as a wake source on its own. When no timer is armed we don't
/// advance — jumping to a far I/O deadline during the brief window where a
/// one-shot timer has fired but not yet been re-armed would overshoot the near
/// timer the guest is about to set. Instead the guest re-arms and the next idle
/// jumps to that timer; `inject_pending_interrupt` delivers any already-pending
/// IRR meanwhile.
///
/// `stop_at_tsc` is folded into the target but is not itself a wake source.
/// PEBS can't help here: no guest instructions retire while idle, so the
/// emulated TSC has to jump deterministically.
pub fn handle_idle<C: VmContext>(ctx: &mut C) -> ExitHandlerResult {
    let current_tsc = ctx.state().emulated_tsc;
    let timer_deadline = ctx.state().devices.apic.timer_deadline;
    let io_channel_deadline = super::next_io_channel_target_tsc(ctx);
    let stop_at_tsc = ctx.state().stop_at_tsc;

    // Advance only when an APIC timer is armed, bounding its deadline by the
    // I/O-channel deadline when that is nearer. With the timer disarmed
    // (one-shot fired, re-arm pending) we don't advance, so a far I/O deadline
    // can't overshoot the near timer the guest is about to re-arm.
    let wake = (timer_deadline > 0).then(|| match io_channel_deadline {
        Some(i) => timer_deadline.min(i),
        None => timer_deadline,
    });
    if let Some(wake) = wake {
        let target = match stop_at_tsc {
            Some(s) => wake.min(s),
            None => wake,
        };
        if target > current_tsc {
            let delta = target - current_tsc;
            ctx.state_mut().tsc_offset += delta;
            ctx.state_mut().emulated_tsc = target;
        }
    }

    if let Err(e) = advance_rip(ctx) {
        return ExitHandlerResult::Error(e);
    }

    // Continue execution - wake-source interrupt will be injected on next VM entry
    ExitHandlerResult::Continue
}

#[cfg(test)]
#[path = "time_tests.rs"]
mod tests;
