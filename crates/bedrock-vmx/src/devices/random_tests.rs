// SPDX-License-Identifier: GPL-2.0

//! Unit tests for [`RandomState`] — the unified RDRAND / RDSEED / GET_RANDOM
//! device.

use super::*;

// --- Seeded PRNG (shared by all channels) ---

#[test]
fn seeded_is_deterministic_and_nonzero_seed() {
    let mut a = RandomState::default();
    a.configure(RdrandMode::SeededRng, 0); // 0 must be coerced to a valid seed
    assert_ne!(a.seed, 0);

    let mut b = RandomState::default();
    b.configure(RdrandMode::SeededRng, 0);

    // Same seed → same stream.
    for _ in 0..16 {
        assert_eq!(a.next_seeded_u64(), b.next_seeded_u64());
    }
}

#[test]
fn seeded_streams_differ_by_seed() {
    let mut a = RandomState::default();
    a.configure(RdrandMode::SeededRng, 1);
    let mut b = RandomState::default();
    b.configure(RdrandMode::SeededRng, 2);
    // Vanishingly unlikely to match across several draws.
    let mut sa = [0u64; 8];
    let mut sb = [0u64; 8];
    for i in 0..8 {
        sa[i] = a.next_seeded_u64();
        sb[i] = b.next_seeded_u64();
    }
    assert_ne!(sa, sb);
}

#[test]
fn zero_seed_coerced_to_nonzero() {
    // Zero seed must become non-zero or xorshift sticks at 0.
    assert_eq!(RandomState::seeded_rng(0).seed, 1);
}

// --- RDRAND / RDSEED value path ---

#[test]
fn generate_seeded_is_deterministic() {
    let mut a = RandomState::seeded_rng(12345);
    let mut b = RandomState::seeded_rng(12345);
    for _ in 0..100 {
        assert_eq!(a.generate(), b.generate());
    }
    // Consecutive draws differ.
    let mut s = RandomState::seeded_rng(100);
    assert_ne!(s.generate(), s.generate());
}

#[test]
fn generate_exit_to_userspace_consumes_pending_value() {
    let mut s = RandomState::exit_to_userspace();
    // No pending value → must exit, generate yields None.
    assert!(s.needs_rdrand_exit());
    assert_eq!(s.generate(), None);

    s.set_pending_value(0x1234);
    assert!(!s.needs_rdrand_exit());
    assert_eq!(s.generate(), Some(0x1234));

    // Consumed once.
    assert!(s.needs_rdrand_exit());
    assert_eq!(s.generate(), None);
}

#[test]
fn configure_resets_mode_and_pending_value() {
    let mut s = RandomState::default();
    s.set_pending_value(0xAA);
    s.configure(RdrandMode::ExitToUserspace, 0);
    assert_eq!(s.mode, RdrandMode::ExitToUserspace);
    assert!(s.needs_rdrand_exit(), "pending value cleared by configure");
}

// --- HYPERCALL_GET_RANDOM buffer path ---

#[test]
fn get_random_exit_only_in_source_mode_without_reply() {
    let mut s = RandomState::default();
    s.configure(RdrandMode::SeededRng, 7);
    assert!(
        !s.needs_get_random_exit(),
        "seeded never exits to userspace"
    );

    s.configure(RdrandMode::ExitToUserspace, 0);
    assert!(
        s.needs_get_random_exit(),
        "source mode with no staged reply"
    );

    s.begin_request(0xdead_0000, 32, 1234);
    assert!(s.awaiting);
    assert!(s.needs_get_random_exit(), "still awaiting before staging");

    s.stage_reply(&[0xAB; 32]);
    assert!(s.reply_valid);
    assert_eq!(s.reply_len, 32);
    assert!(!s.needs_get_random_exit(), "reply staged → no further exit");
    assert_eq!(&s.reply[..4], &[0xAB, 0xAB, 0xAB, 0xAB]);
}

#[test]
fn stage_reply_caps_at_max() {
    let mut s = RandomState::default();
    s.configure(RdrandMode::ExitToUserspace, 0);
    let big = [0x5A_u8; RANDOM_REPLY_MAX * 2];
    s.stage_reply(&big);
    assert_eq!(s.reply_len as usize, RANDOM_REPLY_MAX);
}

#[test]
fn clear_request_resets_in_flight_state() {
    let mut s = RandomState::default();
    s.configure(RdrandMode::ExitToUserspace, 0);
    s.begin_request(0x1000, 16, 42);
    s.stage_reply(&[1, 2, 3, 4]);
    s.clear_request();
    assert!(!s.awaiting);
    assert!(!s.reply_valid);
    assert_eq!(s.reply_len, 0);
    assert_eq!(s.buf_gva, 0);
    assert_eq!(s.req_len, 0);
    assert_eq!(s.pid, 0);
    // Re-enters the userspace-exit path after a clear.
    assert!(s.needs_get_random_exit());
}
