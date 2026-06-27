// SPDX-License-Identifier: GPL-2.0

use super::*;
use crate::exits::interrupts::IO_CHANNEL_IRQ;
use crate::exits::reasons::ExitReason;
use crate::tests::MockVmContext;

/// Make `next_io_channel_target_tsc` return `Some(target)`: register the shared
/// page, queue an undelivered request with the given target TSC, and wire up an
/// unmasked IOAPIC entry (vector ≥ 16) for the channel IRQ.
fn arm_io_request(ctx: &mut MockVmContext, target_tsc: u64) {
    let chan = &mut ctx.state_mut().io_channel;
    chan.page_gpa = 0x1000;
    chan.request_len = 1;
    chan.request_delivered = false;
    chan.request_target_tsc = target_tsc;
    // Unmasked (bit 16 clear), vector 0x20 (≥ 16) so the request is deliverable.
    ctx.state_mut().devices.ioapic.redtbl[IO_CHANNEL_IRQ as usize] = 0x20;
}

/// Drive one HLT exit through `handle_idle` with RIP/instruction-length set up
/// so `advance_rip` succeeds.
fn step_idle(ctx: &mut MockVmContext) {
    ctx.set_exit_reason(ExitReason::Hlt);
    ctx.set_instruction_len(1); // HLT is 1 byte (0xF4)
    ctx.set_guest_rip(0x2000);
    let result = handle_idle(ctx);
    assert!(matches!(result, ExitHandlerResult::Continue));
}

#[test]
fn test_rdtsc_handler() {
    let mut ctx = MockVmContext::new();
    ctx.set_emulated_tsc(0x1234_5678_9ABC_DEF0);
    // Set up VMCS fields needed for advance_rip
    ctx.set_exit_reason(ExitReason::Rdtsc);
    ctx.set_instruction_len(2); // RDTSC is 2 bytes (0x0F 0x31)
    ctx.set_guest_rip(0x1000);

    let result = handle_rdtsc(&mut ctx);
    assert!(matches!(result, ExitHandlerResult::Continue));

    // Check that TSC was split into EDX:EAX correctly
    assert_eq!(ctx.state().gprs.rax, 0x9ABC_DEF0);
    assert_eq!(ctx.state().gprs.rdx, 0x1234_5678);
    // Check RIP was advanced
    assert_eq!(ctx.get_guest_rip(), Some(0x1002));
}

#[test]
fn test_rdtscp_handler() {
    let mut ctx = MockVmContext::new();
    ctx.set_emulated_tsc(0xAABB_CCDD_EEFF_0011);
    ctx.state_mut().msr_state.tsc_aux = 0x42;
    // Set up VMCS fields needed for advance_rip
    ctx.set_exit_reason(ExitReason::Rdtscp);
    ctx.set_instruction_len(3); // RDTSCP is 3 bytes (0x0F 0x01 0xF9)
    ctx.set_guest_rip(0x1000);

    let result = handle_rdtscp(&mut ctx);
    assert!(matches!(result, ExitHandlerResult::Continue));

    // Check that TSC was split into EDX:EAX correctly
    assert_eq!(ctx.state().gprs.rax, 0xEEFF_0011);
    assert_eq!(ctx.state().gprs.rdx, 0xAABB_CCDD);
    // Check TSC_AUX in ECX
    assert_eq!(ctx.state().gprs.rcx, 0x42);
    // Check RIP was advanced
    assert_eq!(ctx.get_guest_rip(), Some(0x1003));
}

#[test]
fn test_rdpmc_handler() {
    let mut ctx = MockVmContext::new();
    ctx.state_mut().gprs.rcx = 0; // Counter index
                                  // Set up VMCS fields needed for advance_rip
    ctx.set_exit_reason(ExitReason::Rdpmc);
    ctx.set_instruction_len(2); // RDPMC is 2 bytes (0x0F 0x33)
    ctx.set_guest_rip(0x1000);

    let result = handle_rdpmc(&mut ctx);
    assert!(matches!(result, ExitHandlerResult::Continue));

    // RDPMC should return 0
    assert_eq!(ctx.state().gprs.rax, 0);
    assert_eq!(ctx.state().gprs.rdx, 0);
    // Check RIP was advanced
    assert_eq!(ctx.get_guest_rip(), Some(0x1002));
}

#[test]
fn idle_jumps_to_armed_timer() {
    let mut ctx = MockVmContext::new();
    ctx.set_emulated_tsc(1_000);
    ctx.state_mut().devices.apic.timer_deadline = 1_000 + 500;

    step_idle(&mut ctx);

    assert_eq!(ctx.state().emulated_tsc, 1_500);
}

#[test]
fn idle_bounds_armed_timer_by_nearer_io() {
    // Armed timer farther than the I/O request: advance only to the nearer
    // I/O deadline so the request is delivered on time.
    let mut ctx = MockVmContext::new();
    ctx.set_emulated_tsc(1_000);
    ctx.state_mut().devices.apic.timer_deadline = 1_000 + 5_000;
    arm_io_request(&mut ctx, 1_000 + 500);

    step_idle(&mut ctx);

    assert_eq!(ctx.state().emulated_tsc, 1_500, "min(timer, io) wins");
}

#[test]
fn idle_does_not_advance_to_io_when_timer_disarmed() {
    // Timer disarmed, only a far I/O request pending: do NOT leap to it. The
    // guest re-arms a nearer timer and the next idle jumps to that instead.
    let mut ctx = MockVmContext::new();
    ctx.set_emulated_tsc(1_000);
    ctx.state_mut().devices.apic.timer_deadline = 0; // disarmed
    arm_io_request(&mut ctx, 1_000 + 1_000_000_000);

    step_idle(&mut ctx);
    assert_eq!(
        ctx.state().emulated_tsc,
        1_000,
        "no leap to the far I/O target"
    );

    // Guest re-arms a near timer; the I/O deadline now only bounds it.
    ctx.state_mut().devices.apic.timer_deadline = 1_000 + 600;
    step_idle(&mut ctx);
    assert_eq!(
        ctx.state().emulated_tsc,
        1_600,
        "jumped to the re-armed timer"
    );
}

#[test]
fn idle_no_advance_without_armed_timer() {
    // No timer armed and no I/O request: nothing to advance to.
    let mut ctx = MockVmContext::new();
    ctx.set_emulated_tsc(1_000);
    ctx.state_mut().devices.apic.timer_deadline = 0;

    step_idle(&mut ctx);

    assert_eq!(ctx.state().emulated_tsc, 1_000);
}
