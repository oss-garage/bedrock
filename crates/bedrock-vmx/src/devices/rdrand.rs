// SPDX-License-Identifier: GPL-2.0

//! RDRAND emulation state.
//!
//! This module provides state for emulating the RDRAND (and RDSEED) instructions.
//! Two modes are supported:
//!
//! 1. **Seeded RNG**: Use a simple xorshift64 PRNG seeded by userspace.
//! 2. **Exit to userspace**: Return to userspace on each RDRAND.

#[cfg(not(feature = "cargo"))]
use super::super::prelude::*;
#[cfg(feature = "cargo")]
use crate::prelude::*;

/// RDRAND emulation mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RdrandMode {
    /// Use a seeded PRNG (xorshift64).
    #[default]
    SeededRng,
    /// Exit to userspace for each RDRAND, let userspace provide value.
    ExitToUserspace,
}

/// State for RDRAND emulation.
#[derive(Debug, Clone)]
pub struct RdrandState {
    /// Current emulation mode.
    pub mode: RdrandMode,
    /// Value used for emulation:
    /// - SeededRng mode: the current RNG state (mutated on each call)
    /// - ExitToUserspace mode: the value to return (set by userspace)
    pub value: u64,
    /// Pending value for exit-to-userspace mode.
    /// When set, this value is used for the next RDRAND and then cleared.
    pub pending_value: Option<u64>,
}

impl Default for RdrandState {
    fn default() -> Self {
        Self {
            mode: RdrandMode::SeededRng,
            // Default seed for deterministic behavior
            value: 0x12345678_deadbeef,
            pending_value: None,
        }
    }
}

impl RdrandState {
    /// Create a new RdrandState with seeded RNG mode.
    pub fn seeded_rng(seed: u64) -> Self {
        Self {
            mode: RdrandMode::SeededRng,
            // Ensure seed is non-zero for xorshift
            value: if seed == 0 { 1 } else { seed },
            pending_value: None,
        }
    }

    /// Create a new RdrandState with exit-to-userspace mode.
    pub fn exit_to_userspace() -> Self {
        Self {
            mode: RdrandMode::ExitToUserspace,
            value: 0,
            pending_value: None,
        }
    }

    /// Configure the RDRAND emulation mode and value.
    pub fn configure(&mut self, mode: RdrandMode, value: u64) {
        self.mode = mode;
        self.value = if mode == RdrandMode::SeededRng && value == 0 {
            1 // Ensure non-zero seed for xorshift
        } else {
            value
        };
        self.pending_value = None;
    }

    /// Set the pending value for exit-to-userspace mode.
    ///
    /// This value will be returned by the next `generate()` call and then cleared.
    pub fn set_pending_value(&mut self, value: u64) {
        self.pending_value = Some(value);
    }

    /// Generate a random value based on the current mode.
    ///
    /// For SeededRng mode: returns and updates the xorshift64 state.
    /// For ExitToUserspace mode: returns the pending value if set, or None.
    ///
    /// Returns `Some(value)` if a value is available, `None` if we need to exit to userspace.
    pub fn generate(&mut self) -> Option<u64> {
        match self.mode {
            RdrandMode::SeededRng => {
                // xorshift64 algorithm
                let mut x = self.value;
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                self.value = x;
                Some(x)
            }
            RdrandMode::ExitToUserspace => self.pending_value.take(),
        }
    }

    /// Check if we need to exit to userspace (for ExitToUserspace mode without pending value).
    pub fn needs_userspace_exit(&self) -> bool {
        self.mode == RdrandMode::ExitToUserspace && self.pending_value.is_none()
    }
}

impl StateHash for RdrandState {
    fn state_hash(&self) -> u64 {
        let mut h = Xxh64Hasher::new();
        h.write_u8(self.mode as u8);
        h.write_u64(self.value);
        match self.pending_value {
            Some(pv) => {
                h.write_u8(1);
                h.write_u64(pv);
            }
            None => {
                h.write_u8(0);
            }
        }
        h.finish()
    }
}

#[cfg(test)]
#[path = "rdrand_tests.rs"]
mod tests;
