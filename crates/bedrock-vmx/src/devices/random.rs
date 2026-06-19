// SPDX-License-Identifier: GPL-2.0

//! Controlled-randomness device.
//!
//! One device backs every channel by which randomness reaches the guest —
//! RDRAND, RDSEED, and the `HYPERCALL_GET_RANDOM` `/dev/urandom` / `/dev/random`
//! / `getrandom()` chokepoint (`get_random_bytes_user`, patched to issue the
//! hypercall instead of trapping RDRAND). All three share one mode and one
//! xorshift64 PRNG, so guest randomness is either consistently seeded
//! (deterministic standalone runs) or consistently fuzzer-served.
//!
//! Two modes:
//!
//! 1. **SeededRng**: serve from the in-VM PRNG — fully deterministic, no
//!    userspace round-trip. RDRAND/RDSEED take one value; GET_RANDOM fills a
//!    buffer.
//! 2. **ExitToUserspace**: exit on each request so userspace (the fuzzer) can
//!    supply the exact value/bytes — every byte handed to the guest is then
//!    fuzzer-controlled and replayable. For GET_RANDOM the request's *size* and
//!    *PID* are surfaced too (which a bare RDRAND trap cannot communicate).
//!
//! The instruction path (RDRAND/RDSEED) and the hypercall path (GET_RANDOM)
//! stage their userspace replies separately — a single register value vs. a
//! byte buffer attributed to a PID — because they are genuinely different
//! request shapes served through different exits and ioctls.

#[cfg(not(feature = "cargo"))]
use super::super::prelude::*;
#[cfg(feature = "cargo")]
use crate::prelude::*;

/// Randomness emulation mode (shared by RDRAND, RDSEED and GET_RANDOM).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RdrandMode {
    /// Serve from a seeded PRNG (xorshift64).
    #[default]
    SeededRng,
    /// Exit to userspace for each request; userspace provides the value/bytes.
    ExitToUserspace,
}

/// Maximum bytes served by a single `HYPERCALL_GET_RANDOM`. Larger guest reads
/// are split into chunks of this size by the guest loop, so one request never
/// needs an unbounded reply buffer. 256 bytes covers the common cases (key
/// material, nonces, Go-runtime reads) in one shot while keeping the reply
/// buffer small enough to live inline in `VmState`.
pub const RANDOM_REPLY_MAX: usize = 256;

/// State for the controlled-randomness device (RDRAND / RDSEED / GET_RANDOM).
#[derive(Debug, Clone)]
pub struct RandomState {
    /// Emulation mode for all randomness channels.
    pub mode: RdrandMode,
    /// xorshift64 state for `SeededRng` mode. Advanced by both the RDRAND/RDSEED
    /// value path and the GET_RANDOM buffer fill — one shared stream.
    pub seed: u64,

    // --- RDRAND/RDSEED instruction path (ExitToUserspace) ---
    /// Value staged by userspace for the next RDRAND/RDSEED; consumed once.
    pub pending_value: Option<u64>,

    // --- HYPERCALL_GET_RANDOM hypercall path (ExitToUserspace) ---
    /// Whether a GET_RANDOM request is awaiting userspace-supplied bytes.
    pub awaiting: bool,
    /// GVA of the guest destination buffer for the in-flight GET_RANDOM request.
    pub buf_gva: u64,
    /// Bytes requested by the in-flight request (capped at `RANDOM_REPLY_MAX`).
    pub req_len: u32,
    /// PID (tgid) of the process that issued the in-flight GET_RANDOM request.
    pub pid: u32,
    /// Reply bytes staged by userspace; valid slice is `reply[..reply_len]`.
    pub reply: [u8; RANDOM_REPLY_MAX],
    /// Number of valid bytes in `reply`.
    pub reply_len: u32,
    /// Whether `reply` has been staged for the in-flight GET_RANDOM request.
    pub reply_valid: bool,
}

impl Default for RandomState {
    fn default() -> Self {
        Self {
            mode: RdrandMode::SeededRng,
            seed: 0x9e37_79b9_7f4a_7c15,
            pending_value: None,
            awaiting: false,
            buf_gva: 0,
            req_len: 0,
            pid: 0,
            reply: [0u8; RANDOM_REPLY_MAX],
            reply_len: 0,
            reply_valid: false,
        }
    }
}

impl RandomState {
    /// Create a device in seeded-RNG mode (non-zero seed enforced).
    pub fn seeded_rng(seed: u64) -> Self {
        Self {
            mode: RdrandMode::SeededRng,
            seed: if seed == 0 { 1 } else { seed },
            ..Self::default()
        }
    }

    /// Create a device in exit-to-userspace mode.
    pub fn exit_to_userspace() -> Self {
        Self {
            mode: RdrandMode::ExitToUserspace,
            ..Self::default()
        }
    }

    /// Configure the mode and (for `SeededRng`) the PRNG seed. Forces a non-zero
    /// xorshift seed and clears any staged value / in-flight request.
    pub fn configure(&mut self, mode: RdrandMode, seed: u64) {
        self.mode = mode;
        self.seed = if seed == 0 { 1 } else { seed };
        self.pending_value = None;
        self.clear_request();
    }

    /// Advance the xorshift64 PRNG and return the next value.
    pub fn next_seeded_u64(&mut self) -> u64 {
        let mut x = self.seed;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.seed = x;
        x
    }

    // --- RDRAND / RDSEED ---

    /// Produce the value for an RDRAND/RDSEED instruction: the next PRNG value
    /// in `SeededRng`, or the staged value (consumed) in `ExitToUserspace`.
    /// Returns `None` when an exit-to-userspace is needed (no staged value).
    pub fn generate(&mut self) -> Option<u64> {
        match self.mode {
            RdrandMode::SeededRng => Some(self.next_seeded_u64()),
            RdrandMode::ExitToUserspace => self.pending_value.take(),
        }
    }

    /// Stage the value returned by the next [`generate`](Self::generate) call.
    pub fn set_pending_value(&mut self, value: u64) {
        self.pending_value = Some(value);
    }

    /// Whether an RDRAND/RDSEED must exit to userspace (source mode, no staged
    /// value).
    pub fn needs_rdrand_exit(&self) -> bool {
        self.mode == RdrandMode::ExitToUserspace && self.pending_value.is_none()
    }

    // --- HYPERCALL_GET_RANDOM ---

    /// Record the in-flight GET_RANDOM request before exiting to userspace.
    pub fn begin_request(&mut self, buf_gva: u64, req_len: u32, pid: u32) {
        self.buf_gva = buf_gva;
        self.req_len = req_len;
        self.pid = pid;
        self.awaiting = true;
        self.reply_valid = false;
        self.reply_len = 0;
    }

    /// Stage userspace-supplied reply bytes for the in-flight GET_RANDOM request.
    /// Bytes beyond `RANDOM_REPLY_MAX` are dropped (the request was capped anyway).
    pub fn stage_reply(&mut self, bytes: &[u8]) {
        let n = bytes.len().min(RANDOM_REPLY_MAX);
        self.reply[..n].copy_from_slice(&bytes[..n]);
        self.reply_len = n as u32;
        self.reply_valid = true;
    }

    /// Clear in-flight GET_RANDOM request state after completion (or on
    /// (re)configure).
    pub fn clear_request(&mut self) {
        self.awaiting = false;
        self.buf_gva = 0;
        self.req_len = 0;
        self.pid = 0;
        self.reply_len = 0;
        self.reply_valid = false;
    }

    /// Whether a GET_RANDOM request must exit to userspace to obtain bytes.
    pub fn needs_get_random_exit(&self) -> bool {
        self.mode == RdrandMode::ExitToUserspace && !self.reply_valid
    }
}

impl StateHash for RandomState {
    fn state_hash(&self) -> u64 {
        // Only the stable, determinism-relevant state: the mode, the PRNG
        // position, and any staged RDRAND value. The in-flight GET_RANDOM
        // request fields are transient (cleared at quiescent checkpoints, and
        // identical across replays at the same exit), so they're left out to
        // keep the hash a clean divergence signal.
        let mut h = Xxh64Hasher::new();
        h.write_u8(self.mode as u8);
        h.write_u64(self.seed);
        match self.pending_value {
            Some(pv) => {
                h.write_u8(1);
                h.write_u64(pv);
            }
            None => h.write_u8(0),
        }
        h.finish()
    }
}

#[cfg(test)]
#[path = "random_tests.rs"]
mod tests;
