// SPDX-License-Identifier: GPL-2.0

//! Tests for deterministic instruction-granular preemption (`check_preempt`)
//! and the `ApicState` preemption helpers.

use super::*;
use crate::tests::MockVmContext;

/// Software-enable the APIC and give the LVT timer an unmasked, deliverable
/// vector so `check_preempt` / `next_preempt_target_tsc` treat it as usable.
fn enable_apic_timer_vector(ctx: &mut MockVmContext, vector: u8) {
    let apic = &mut ctx.state_mut().devices.apic;
    apic.svr |= 1 << 8; // APIC software-enabled
    apic.lvt_timer = u32::from(vector); // unmasked (bit 16 clear), not periodic
}

/// Read the IRR bit for a vector.
fn irr_set(ctx: &MockVmContext, vector: u8) -> bool {
    let apic = &ctx.state().devices.apic;
    apic.irr[(vector / 32) as usize] & (1 << (vector % 32)) != 0
}

#[test]
fn preempt_interval_is_deterministic_and_in_range() {
    let mut a = crate::prelude::ApicState::default();
    a.configure_preempt(1000, 0x1234_5678);
    let mut b = crate::prelude::ApicState::default();
    b.configure_preempt(1000, 0x1234_5678);

    for _ in 0..64 {
        let ia = a.next_preempt_interval();
        let ib = b.next_preempt_interval();
        assert_eq!(ia, ib, "same seed must produce the same interval stream");
        assert!(
            (1000..2000).contains(&ia),
            "interval {ia} out of [period, 2*period)"
        );
    }
}

#[test]
fn configure_preempt_forces_nonzero_seed_and_can_disable() {
    let mut a = crate::prelude::ApicState::default();
    a.configure_preempt(1000, 0); // 0 is a xorshift fixed point; must be bumped
    assert_ne!(a.preempt_seed, 0);
    assert_ne!(a.next_preempt_interval(), 0);

    a.configure_preempt(0, 42); // period 0 disables
    assert_eq!(a.preempt_period, 0);
}

#[test]
fn check_preempt_noop_when_disabled() {
    let mut ctx = MockVmContext::new();
    enable_apic_timer_vector(&mut ctx, 0x40);
    // preempt_period defaults to 0 -> feature off.
    ctx.set_emulated_tsc(1_000_000);
    check_preempt(&mut ctx);
    assert_eq!(ctx.state().devices.apic.preempt_deadline, 0);
    assert!(!irr_set(&ctx, 0x40));
}

#[test]
fn check_preempt_lazy_arms_then_fires_and_reschedules() {
    let mut ctx = MockVmContext::new();
    enable_apic_timer_vector(&mut ctx, 0x40);
    ctx.state_mut()
        .devices
        .apic
        .configure_preempt(1000, 0x9e37_79b9);

    // First eligible pass arms the deadline but injects nothing.
    ctx.set_emulated_tsc(0);
    check_preempt(&mut ctx);
    let first_deadline = ctx.state().devices.apic.preempt_deadline;
    assert!(
        first_deadline >= 1000,
        "lazy-armed deadline in interval range"
    );
    assert!(!irr_set(&ctx, 0x40), "no injection on the arming pass");

    // Not yet at the deadline: nothing fires.
    ctx.set_emulated_tsc(first_deadline - 1);
    check_preempt(&mut ctx);
    assert!(!irr_set(&ctx, 0x40));
    assert_eq!(ctx.state().devices.apic.preempt_deadline, first_deadline);

    // On the boundary: inject the timer vector and schedule the next one.
    ctx.set_emulated_tsc(first_deadline);
    check_preempt(&mut ctx);
    assert!(
        irr_set(&ctx, 0x40),
        "preemption raises the LVT timer vector"
    );
    let second_deadline = ctx.state().devices.apic.preempt_deadline;
    assert!(
        second_deadline > first_deadline,
        "next deadline advances past the one that fired"
    );
}

#[test]
fn check_preempt_holds_off_until_vector_usable() {
    let mut ctx = MockVmContext::new();
    ctx.state_mut().devices.apic.configure_preempt(1000, 0x1);
    // APIC left software-disabled and LVT timer masked (defaults): not usable.
    ctx.set_emulated_tsc(5000);
    check_preempt(&mut ctx);
    assert_eq!(
        ctx.state().devices.apic.preempt_deadline,
        0,
        "must not arm while the guest has no deliverable timer vector"
    );

    // Once the guest wires up a vector, the next pass arms.
    enable_apic_timer_vector(&mut ctx, 0x40);
    check_preempt(&mut ctx);
    assert_ne!(ctx.state().devices.apic.preempt_deadline, 0);
}
