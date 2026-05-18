// SPDX-License-Identifier: GPL-2.0

use super::*;

#[test]
fn test_seeded_rng_deterministic() {
    let mut state1 = RdrandState::seeded_rng(12345);
    let mut state2 = RdrandState::seeded_rng(12345);

    // Same seed should produce same sequence
    for _ in 0..100 {
        assert_eq!(state1.generate(), state2.generate());
    }
}

#[test]
fn test_seeded_rng_different_seeds() {
    let mut state1 = RdrandState::seeded_rng(12345);
    let mut state2 = RdrandState::seeded_rng(54321);

    // Different seeds should produce different sequences
    let mut same_count = 0;
    for _ in 0..100 {
        if state1.generate() == state2.generate() {
            same_count += 1;
        }
    }
    // Statistically very unlikely to have many collisions
    assert!(same_count < 10);
}

#[test]
fn test_exit_to_userspace_mode() {
    let mut state = RdrandState::exit_to_userspace();

    // No pending value, should return None
    assert!(state.needs_userspace_exit());
    assert_eq!(state.generate(), None);

    // Set pending value
    state.set_pending_value(0x1234);
    assert!(!state.needs_userspace_exit());
    assert_eq!(state.generate(), Some(0x1234));

    // Pending value consumed
    assert!(state.needs_userspace_exit());
    assert_eq!(state.generate(), None);
}

#[test]
fn test_configure() {
    let mut state = RdrandState::default();

    state.configure(RdrandMode::SeededRng, 100);
    assert_eq!(state.mode, RdrandMode::SeededRng);
    let first = state.generate();
    let second = state.generate();
    assert_ne!(first, second); // RNG should produce different values

    state.configure(RdrandMode::ExitToUserspace, 0);
    assert_eq!(state.mode, RdrandMode::ExitToUserspace);
    assert!(state.needs_userspace_exit());
}

#[test]
fn test_zero_seed_handled() {
    let state = RdrandState::seeded_rng(0);
    // Zero seed should be converted to 1 to avoid xorshift stuck at 0
    assert_eq!(state.value, 1);
}
