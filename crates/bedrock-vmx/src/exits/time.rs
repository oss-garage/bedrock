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
/// Both are idle instructions that wait for an interrupt. For deterministic
/// execution, we advance the TSC offset so emulated_tsc reaches the
/// earliest pending wake-source deadline — the APIC timer, the
/// deterministic I/O channel, or `stop_at_tsc` — causing that event to
/// fire on the next VM entry.
///
/// The clamp is gated on having at least one real wake source. With no
/// timer *and* no pending I/O channel request, the wake source is
/// open-ended (IPI from another vCPU, device interrupt that's about to
/// arrive, the guest re-arming the timer, etc.) so we don't advance —
/// `stop_at_tsc` alone is not a wake source, and jumping to it during
/// brief Linux idle windows where the timer is momentarily disarmed
/// (one-shot just fired, about to be re-armed via TSC_DEADLINE) would
/// terminate the run early on every such idle even though the guest is
/// about to do real work. With no advance, the next iteration's
/// `inject_pending_interrupt` delivers any pending IRR (e.g. the timer
/// that just fired) and the guest resumes.
///
/// PEBS-precise arming can't help during idle: after HLT/MWAIT there are
/// no further retired guest instructions until the guest is woken, so the
/// emulated TSC has to jump deterministically here.
pub fn handle_idle<C: VmContext>(ctx: &mut C) -> ExitHandlerResult {
    let current_tsc = ctx.state().emulated_tsc;
    let timer_deadline = ctx.state().devices.apic.timer_deadline;
    let io_channel_deadline = super::next_io_channel_target_tsc(ctx);
    let stop_at_tsc = ctx.state().stop_at_tsc;

    // Only advance when there's a real wake source (timer or I/O channel
    // request). `stop_at_tsc` is folded into the min target when we do
    // advance, but isn't itself a wake source.
    let timer = (timer_deadline > 0).then_some(timer_deadline);
    let wake = match (timer, io_channel_deadline) {
        (Some(t), Some(i)) => Some(t.min(i)),
        (Some(t), None) => Some(t),
        (None, Some(i)) => Some(i),
        (None, None) => None,
    };
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
