// SPDX-License-Identifier: GPL-2.0

//! Interrupt injection and APIC timer handling.

use core::arch::asm;

use super::helpers::{inject_exception, ExitError};
use super::pebs::arm_for_next_iteration;
use super::qualifications::InterruptionInfo;

/// IOAPIC pin used for the deterministic hypervisor↔guest I/O channel.
///
/// The MP table advertises this pin as a routable ISA interrupt so the
/// guest's `bedrock-io.ko` can `request_irq()` it through the normal Linux
/// IRQ subsystem (the kernel then programs the IOAPIC redirection-table
/// entry with a chosen vector). The hypervisor injects via
/// [`ioapic_deliver_irq`], reusing the same path the emulated serial port
/// uses for IRQ 4.
///
/// Pin 9 is not used by the emulated platform's other devices (PIT is on
/// pin 0, serial COM1 on pin 4, RTC would be on pin 8) and corresponds to
/// ISA IRQ 9, which is conventionally reserved for ACPI on real hardware —
/// since bedrock guests are ACPI-less, it's free for us to claim.
pub const IO_CHANNEL_IRQ: u8 = 9;

#[cfg(not(feature = "cargo"))]
use super::super::prelude::*;
#[cfg(feature = "cargo")]
use crate::prelude::*;

#[cfg(test)]
#[path = "interrupts_tests.rs"]
mod tests;

/// Check if APIC timer has expired and set IRR bit if so.
/// Uses emulated TSC for determinism.
pub fn check_apic_timer<C: VmContext>(ctx: &mut C) {
    let current_tsc = ctx.state().emulated_tsc;
    let timer_deadline = ctx.state().devices.apic.timer_deadline;
    let svr = ctx.state().devices.apic.svr;
    let lvt_timer_init = ctx.state().devices.apic.lvt_timer;

    if timer_deadline == 0 {
        return;
    }
    if current_tsc < timer_deadline {
        return;
    }
    if (svr & (1 << 8)) == 0 {
        return;
    }
    if (lvt_timer_init & (1 << 16)) != 0 {
        return;
    }

    // Diagnostic: count timer firings that arrive past the deadline. The
    // precise PEBS+MTF boundary lands `current_tsc == timer_deadline`;
    // anything strictly greater means PEBS didn't fire at the
    // `target - PEBS_MARGIN` point and the timer is being delivered late
    // on whatever deterministic exit happened past the deadline.
    //
    // A late inject breaks determinism: the timer lands at a different
    // instruction than the deadline, so the guest sees the interrupt at the
    // wrong point. Unless the run opted into tolerating it
    // (BEDROCK_IGNORE_LATE_INJECT / EXIT_FLAG_IGNORE_LATE_INJECT), record the
    // abort figures and return without setting IRR: `inject_pending_interrupt`
    // reads the recorded lateness and tears the run down. This mirrors the
    // strict PEBS-margin abort in `handle_pebs_precise_exit`, but catches the
    // late delivery at the injection point even when the skid path didn't fire.
    if current_tsc > timer_deadline {
        ctx.state_mut().exit_stats.apic_timer_late_inject += 1;
        if !ctx.state().ignore_late_inject {
            let lateness = (current_tsc as i64) - (timer_deadline as i64);
            let stats = &mut ctx.state_mut().exit_stats;
            // Set only here, so a non-zero value uniquely identifies this abort.
            stats.late_inject_abort_lateness = lateness;
            stats.late_inject_abort_deadline = timer_deadline as i64;
            return;
        }
    }

    let apic = &mut ctx.state_mut().devices.apic;

    // Get vector from LVT timer (bits 7:0)
    let vector = (apic.lvt_timer & 0xFF) as u8;

    // Set bit in IRR
    let irr_index = (vector / 32) as usize;
    let irr_bit = 1u32 << (vector % 32);
    apic.irr[irr_index] |= irr_bit;

    // Handle periodic vs one-shot mode (bit 17 of lvt_timer)
    if (apic.lvt_timer & (1 << 17)) != 0 {
        // Periodic: reset deadline for next period
        let divisor = apic_timer_divisor(apic.timer_divide);
        let ticks = u64::from(apic.timer_initial) * u64::from(divisor);
        apic.timer_deadline = current_tsc.wrapping_add(ticks);
    } else {
        // One-shot: stop timer
        apic.timer_deadline = 0;
    }

    // Record the injection on the event stream. `target_tsc` is the deadline
    // this firing was scheduled for; pairing it with the header's actual emit
    // tsc (== current_tsc) exposes scheduled-vs-delivered drift — the key
    // signal for interrupt-timing divergence. Buffer-full is handled centrally
    // by the exit dispatcher, so the return value is ignored.
    let payload = InjectPayload {
        vector,
        source: InjectSource::Timer as u8,
        _pad: [0; 6],
        target_tsc: timer_deadline,
    };
    let _ = ctx
        .state_mut()
        .event_append(EventKind::Inject, payload.as_bytes());
}

/// Deterministic instruction-granular preemption.
///
/// The in-guest scheduler only runs, and so only switches threads, when it is
/// entered: a timer tick, a syscall, a block/yield. A data race whose two
/// conflicting accesses have no scheduler entry between them is therefore never
/// interleaved -- the racing thread runs that stretch to completion on every
/// run and every seed, so sweeping the seed cannot expose the bug. This injects
/// an *extra* interrupt roughly every `preempt_period` retired instructions,
/// handing the guest scheduler a preemption point it would not otherwise have.
///
/// It fires on the first deterministic exit at or after `preempt_deadline`.
/// Because this runs only on the `last_exit_deterministic` path, that firing
/// point is reproducible across runs -- a pure function of the seed -- so
/// determinism holds WITHOUT arming the single per-CPU PEBS counter. Keeping
/// preemption out of the PEBS/MTF precise-landing machinery is deliberate: an
/// earlier version armed PEBS for the preempt deadline too, which stole the
/// counter from the real APIC timer (usually the farther target) and made the
/// timer deliver late -- fatal under a strict scored run, where every RaceBench
/// fork aborted. The tradeoff is coarser placement: preemption lands at the next
/// deterministic-exit boundary, not an exact instruction, so it cannot switch
/// inside a long exit-free stretch.
///
/// Disabled unless `apic.preempt_period != 0`. Reuses the guest's LVT timer
/// vector, i.e. a forced preemption looks to the guest like an extra timer tick
/// (empirically this does drive reschedules under the sched_ext workload).
fn check_preempt<C: VmContext>(ctx: &mut C) {
    let apic = &ctx.state().devices.apic;
    if apic.preempt_period == 0 {
        return; // feature disabled
    }
    // Only inject once the guest has wired up a usable LVT timer vector: APIC
    // software-enabled (SVR bit 8), the LVT entry unmasked (bit 16 clear), and
    // a deliverable vector (>= 16). Before that (early boot) the injection
    // would target a reserved or masked vector and be dropped, and the deadline
    // would never advance. `next_preempt_target_tsc` gates on the same
    // conditions, so PEBS doesn't arm for a preemption we would refuse to fire.
    if (apic.svr & (1 << 8)) == 0 {
        return;
    }
    if (apic.lvt_timer & (1 << 16)) != 0 {
        return;
    }
    let vector = (apic.lvt_timer & 0xFF) as u8;
    if vector < 16 {
        return;
    }

    let current_tsc = ctx.state().emulated_tsc;
    let deadline = ctx.state().devices.apic.preempt_deadline;

    // Lazy arm: on the first eligible pass, schedule the first preemption and
    // return. `arm_for_next_iteration` (called just after us) reads the freshly
    // set deadline and arms PEBS for it.
    if deadline == 0 {
        let apic = &mut ctx.state_mut().devices.apic;
        let interval = apic.next_preempt_interval();
        apic.preempt_deadline = current_tsc.saturating_add(interval);
        return;
    }

    if current_tsc < deadline {
        return;
    }

    // Due: raise the vector in IRR (idempotent if a real timer fires on the
    // same instruction -- both set the same bit) and schedule the next one.
    let irr_index = (vector / 32) as usize;
    let irr_bit = 1u32 << (vector % 32);
    let apic = &mut ctx.state_mut().devices.apic;
    apic.irr[irr_index] |= irr_bit;
    let interval = apic.next_preempt_interval();
    apic.preempt_deadline = current_tsc.saturating_add(interval);
}

/// Check whether an I/O channel request is queued and not yet delivered to
/// the guest, and if so, raise the I/O channel IRQ via the emulated IOAPIC.
///
/// The guest module is responsible for two prerequisites before we can
/// fire:
///   1. It registered the shared page (sets `io_channel.page_gpa != 0`).
///   2. It `request_irq`'d the channel IRQ, which causes Linux to write an
///      unmasked, valid-vector entry into `ioapic.redtbl[IO_CHANNEL_IRQ]`.
///
/// Until both are true the request just sits in `VmState`; once they're
/// both true `ioapic_deliver_irq` flips the APIC IRR bit and the normal
/// `inject_pending_interrupt` path delivers it on the next interruptible
/// VM-entry. We set `request_delivered = true` only after we've actually
/// raised the IRR (i.e. the IOAPIC entry was unmasked) so a request that
/// arrives before the guest module is ready isn't silently dropped.
pub fn check_io_channel<C: VmContext>(ctx: &mut C) {
    let chan = &ctx.state().io_channel;
    if chan.page_gpa == 0 {
        return;
    }
    if chan.request_len == 0 {
        return;
    }
    if chan.request_delivered {
        return;
    }
    // When the request was queued with a target TSC, defer until the
    // emulated TSC has caught up. `arm_for_next_iteration` arms PEBS for
    // this target so we exit precisely at the requested instruction
    // count; `check_io_channel` then fires on the boundary MTF step
    // where `emulated_tsc == request_target_tsc` (and on any later exit
    // as a safety net for the AlreadyPast / BelowMinDelta cases).
    if chan.request_target_tsc != 0 && ctx.state().emulated_tsc < chan.request_target_tsc {
        return;
    }

    let entry = ctx.state().devices.ioapic.redtbl[IO_CHANNEL_IRQ as usize];
    // Masked (bit 16) or vector < 16: the guest module hasn't wired up the
    // IRQ yet. Leave the request pending and try again next iteration.
    if (entry >> 16) & 1 != 0 || (entry & 0xFF) < 16 {
        return;
    }

    ioapic_deliver_irq(ctx, IO_CHANNEL_IRQ);
    ctx.state_mut().io_channel.request_delivered = true;

    // Record the request-signal on the event stream. Its own category so the
    // request firing (a determinism-relevant point) is capturable without the
    // heavyweight `Exit` capture. The metadata is followed by the actual request
    // bytes (the injected command); `target_tsc` is the scheduled request target;
    // `status`/`exit_code` are 0 on a request. Buffer-full handled centrally.
    let target_tsc = ctx.state().io_channel.request_target_tsc;
    let payload = IoChannelPayload {
        phase: IoChannelPhase::Request as u8,
        _pad: [0; 7],
        target_tsc,
    };
    let _ = ctx.state_mut().event_emit_io_channel(&payload);
}

/// Calculate APIC timer divisor from the Divide Configuration Register (DCR).
fn apic_timer_divisor(dcr: u32) -> u32 {
    let encoded = ((dcr >> 1) & 0b100) | (dcr & 0b11);
    match encoded {
        0b000 => 2,
        0b001 => 4,
        0b010 => 8,
        0b011 => 16,
        0b100 => 32,
        0b101 => 64,
        0b110 => 128,
        0b111 => 1,
        _ => 1,
    }
}

/// Find the highest priority pending interrupt in the APIC IRR.
/// Returns the vector number if an interrupt is pending, None otherwise.
fn apic_pending_vector<C: VmContext>(ctx: &C) -> Option<u8> {
    let apic = &ctx.state().devices.apic;

    // Check if APIC is enabled (SVR bit 8)
    if (apic.svr & (1 << 8)) == 0 {
        return None;
    }

    // Find highest priority pending interrupt (highest vector number)
    for i in (0..8).rev() {
        if apic.irr[i] != 0 {
            // Find highest bit set in this word
            let bit = 31 - apic.irr[i].leading_zeros();
            return Some((i * 32 + bit as usize) as u8);
        }
    }
    None
}

/// Enable interrupt-window exiting so we get a VM exit when the guest becomes interruptible.
pub fn enable_interrupt_window_exiting<C: VmContext>(ctx: &mut C) -> Result<(), ExitError> {
    let controls = ctx
        .state()
        .vmcs
        .read32(VmcsField32::PrimaryProcBasedVmExecControls)
        .map_err(ExitError::VmcsReadError)?;
    if controls & cpu_based::INTR_WINDOW_EXITING == 0 {
        ctx.state()
            .vmcs
            .write32(
                VmcsField32::PrimaryProcBasedVmExecControls,
                controls | cpu_based::INTR_WINDOW_EXITING,
            )
            .map_err(ExitError::VmcsWriteError)?;
    }
    Ok(())
}

/// Disable interrupt-window exiting.
pub fn disable_interrupt_window_exiting<C: VmContext>(ctx: &mut C) -> Result<(), ExitError> {
    let controls = ctx
        .state()
        .vmcs
        .read32(VmcsField32::PrimaryProcBasedVmExecControls)
        .map_err(ExitError::VmcsReadError)?;
    if controls & cpu_based::INTR_WINDOW_EXITING != 0 {
        ctx.state()
            .vmcs
            .write32(
                VmcsField32::PrimaryProcBasedVmExecControls,
                controls & !cpu_based::INTR_WINDOW_EXITING,
            )
            .map_err(ExitError::VmcsWriteError)?;
    }
    Ok(())
}

/// Check IDT-vectoring information and re-inject if an event was interrupted during delivery.
///
/// Per Intel SDM Vol 3C Section 29.2.4: When a VM exit occurs during delivery of an event
/// through the IDT (e.g., EPT violation while pushing interrupt frame to stack), the event
/// info is saved in IdtVectoringInfo. The hypervisor must re-inject this event by copying
/// it to VmEntryInterruptionInfo.
///
/// Returns Ok(true) if an event was re-injected, Ok(false) if no event needs re-injection.
pub fn reinject_vectored_event<C: VmContext>(ctx: &mut C) -> Result<bool, ExitError> {
    let idt_info = ctx
        .state()
        .vmcs
        .read32(VmcsField32::IdtVectoringInfo)
        .map_err(ExitError::VmcsReadError)?;

    // Check if valid (bit 31) - if not set, no event was interrupted
    if idt_info & (1 << 31) == 0 {
        return Ok(false);
    }

    let vector = (idt_info & 0xFF) as u8;
    let int_type = (idt_info >> 8) & 0x7;

    log_info!(
        "IDT-vectoring: re-injecting interrupted event vector={} type={}\n",
        vector,
        int_type
    );

    // Copy IDT-vectoring info to VM-entry interruption-info for re-injection.
    // The formats are identical per Intel SDM (Table 26-18 and Table 26-21).
    ctx.state()
        .vmcs
        .write32(VmcsField32::VmEntryInterruptionInfo, idt_info)
        .map_err(ExitError::VmcsWriteError)?;

    // If error code is valid (bit 11), copy that too
    if idt_info & (1 << 11) != 0 {
        let error_code = ctx
            .state()
            .vmcs
            .read32(VmcsField32::IdtVectoringErrorCode)
            .map_err(ExitError::VmcsReadError)?;
        ctx.state()
            .vmcs
            .write32(VmcsField32::VmEntryExceptionErrorCode, error_code)
            .map_err(ExitError::VmcsWriteError)?;
    }

    Ok(true)
}

/// Inject any pending interrupt into the guest before VM entry.
/// This should be called before each VMLAUNCH/VMRESUME.
pub fn inject_pending_interrupt<C: VmContext>(ctx: &mut C) -> Result<(), ExitError> {
    // Decide whether a fresh APIC-timer interrupt is eligible for injection
    // this iteration. The PEBS re-arm at the end runs unconditionally, so
    // every branch here is a "what about the pending-interrupt side" decision.
    //
    // Three reasons to skip new injection:
    //
    //   - `reinject_vectored_event` returned true: an interrupt or exception
    //     delivery was aborted (e.g. CoW EPT violation while pushing the
    //     interrupt frame) and must complete first. Per Intel SDM Vol 3C
    //     §29.2.4, we re-inject before handling new events. Runs
    //     unconditionally — the event was already in flight.
    //
    //   - Last exit was non-deterministic (host NMI, external interrupt, VMX
    //     preemption timer): we'd risk setting IRR / re-injecting at a
    //     non-deterministic boundary, e.g. a host NMI landing at the same
    //     instruction where hardware would have fired an interrupt-window VM
    //     exit, silently absorbing the IWE exit and shortening the determ log
    //     by one entry.
    //
    //   - `VmEntryInterruptionInfo` already has an exception pending (e.g.
    //     reinjected #PF): don't overwrite it with an interrupt; it gets
    //     handled on the next exit.
    //
    // For the surviving deterministic path we run `check_apic_timer` to set
    // IRR and (for periodic timers) auto-reload `apic.timer_deadline`.
    // The PEBS re-arm below reads that deadline, so the timer-expiry check
    // must run before re-arming or we'd arm against the already-fired
    // deadline.
    let inject_eligible =
        !reinject_vectored_event(ctx)? && ctx.state().last_exit_deterministic && {
            let pending = ctx
                .state()
                .vmcs
                .read32(VmcsField32::VmEntryInterruptionInfo)
                .unwrap_or(0);
            if pending & (1 << 31) != 0 {
                false
            } else {
                check_apic_timer(ctx);
                // Raise the I/O channel IRQ if a host-queued request is
                // pending and the guest module has wired up its IRQ
                // handler. Sequenced after `check_apic_timer` so that when
                // both are eligible the timer (typically higher vector,
                // higher priority) wins selection in `apic_pending_vector`
                // and ours queues behind it via the sticky IRR bit.
                check_io_channel(ctx);
                // Raise a forced-preemption interrupt at the seed-chosen
                // instruction count (no-op unless preemption is configured).
                // Uses the LVT timer vector, so it shares the sticky IRR bit
                // with a real timer firing on the same instruction.
                check_preempt(ctx);
                true
            }
        };

    // Re-arm PEBS for the next APIC timer deadline regardless of which branch
    // above we took. After a non-deterministic exit, the previous iteration's
    // `counter_reload` no longer matches "instructions remaining to deadline":
    // the interrupted iter retired some instructions toward the overflow
    // target, but FIXED_CTR0 resets to the same `counter_reload` on the next
    // VM-entry, so PEBS would fire `delta - 1` instructions into the *new*
    // iter — past the original deadline by exactly however many instructions
    // were burned in the interrupted iter. Re-arming recomputes the remaining
    // delta from the current `last_instruction_count + tsc_offset` (fresh on
    // every VM-exit, unlike `emulated_tsc` which only updates on deterministic
    // exits) and keeps the precise emulated_tsc landing point intact.
    arm_for_next_iteration(ctx);

    // A late APIC-timer injection (recorded by `check_apic_timer` above) means
    // the timer was delivered past its deadline and the run has diverged. Tear
    // it down here so the failure surfaces at the source. handle_run collapses
    // every VmRunError to EIO, so the `late_inject_abort_*` stats are the
    // reliable channel: userspace reads them back over GET_EXIT_STATS on the
    // failure path and renders the message there. Only reachable in strict
    // mode: `check_apic_timer` leaves the stat at 0 when `ignore_late_inject`.
    if ctx.state().exit_stats.late_inject_abort_lateness != 0 {
        return Err(ExitError::Fatal(
            "APIC timer injected late (set BEDROCK_IGNORE_LATE_INJECT to bypass)",
        ));
    }

    if !inject_eligible {
        return Ok(());
    }

    // Find highest priority pending interrupt
    let vector = match apic_pending_vector(ctx) {
        Some(v) => v,
        None => return Ok(()), // No pending interrupt
    };

    // Check if guest is interruptible (RFLAGS.IF = 1)
    let rflags = ctx
        .state()
        .vmcs
        .read_natural(VmcsFieldNatural::GuestRflags)
        .map_err(ExitError::VmcsReadError)?;
    if (rflags & (1 << 9)) == 0 {
        // IF=0, enable interrupt-window exiting to inject later
        enable_interrupt_window_exiting(ctx)?;
        return Ok(());
    }

    // Check interruptibility state (blocking by STI or MOV SS)
    let interruptibility = ctx
        .state()
        .vmcs
        .read32(VmcsField32::GuestInterruptibilityState)
        .map_err(ExitError::VmcsReadError)?;
    if (interruptibility & 0x3) != 0 {
        // Blocked by STI or MOV SS
        enable_interrupt_window_exiting(ctx)?;
        return Ok(());
    }

    // Guest is interruptible - inject the interrupt
    let info = InterruptionInfo::external_interrupt(vector);
    inject_exception(ctx, info, None)?;

    // Clear IRR bit, set ISR bit (interrupt now in service)
    {
        let apic = &mut ctx.state_mut().devices.apic;
        let irr_index = (vector / 32) as usize;
        let bit = 1u32 << (vector % 32);
        apic.irr[irr_index] &= !bit;
        apic.isr[irr_index] |= bit;
    }

    // Disable interrupt-window exiting if it was enabled
    disable_interrupt_window_exiting(ctx)?;

    Ok(())
}

/// Deliver an interrupt through the I/O APIC to the local APIC.
///
/// This looks up the redirection table entry for the given IRQ pin,
/// and if not masked, sets the corresponding bit in the local APIC's IRR.
pub fn ioapic_deliver_irq<C: VmContext>(ctx: &mut C, irq: u8) {
    if irq as usize >= IOAPIC_NUM_PINS {
        return;
    }

    let entry = ctx.state().devices.ioapic.redtbl[irq as usize];

    // Check if masked (bit 16)
    if (entry >> 16) & 1 != 0 {
        return;
    }

    let vector = (entry & 0xFF) as u8;
    if vector < 16 {
        // Vectors 0-15 are reserved
        return;
    }

    // Set the bit in local APIC's IRR
    let irr_idx = (vector / 32) as usize;
    let irr_bit = 1u32 << (vector % 32);

    if irr_idx < 8 {
        ctx.state_mut().devices.apic.irr[irr_idx] |= irr_bit;
    }
}

/// Handle external interrupt by briefly enabling interrupts.
///
/// This uses the SVM-style approach: enable interrupts to allow the pending
/// interrupt to be delivered through the IDT, then disable interrupts before
/// returning to re-enter the guest.
#[inline]
pub fn handle_external_interrupt<K: Kernel>(kernel: &K) {
    let _irq_window = ReverseIrqGuard::new(kernel);
    // SAFETY: NOP is a safe instruction; the IRQ window opened by ReverseIrqGuard
    // allows pending host interrupts to be delivered through the IDT.
    unsafe {
        asm!("nop", options(nomem, nostack, preserves_flags));
    }
}
