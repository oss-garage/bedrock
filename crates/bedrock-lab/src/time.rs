// SPDX-License-Identifier: GPL-2.0

//! Virtual time — the deterministic time currency of the hypervisor.
//!
//! The hypervisor's emulated TSC counts *retired guest instructions*, not
//! wall-clock time — that's what makes execution deterministic. [`VirtTime`]
//! is an *absolute moment* on this timeline; it pairs an instruction count
//! with the TSC frequency it was measured against, so it can convert cleanly
//! between counts, seconds, and `std::time::Duration`.
//!
//! [`VirtDuration`] is a *delta* between two moments at the same frequency.
//! The two types compose with the obvious arithmetic:
//!
//! ```ignore
//! let t0: VirtTime = ...;
//! let t1: VirtTime = ...;
//! let dt: VirtDuration = t1 - t0;
//! let t2: VirtTime = t0 + dt;
//! ```
//!
//! Mixing frequencies is a programming error; arithmetic between different
//! frequencies panics (see [`VirtTime::checked_sub`] for the fallible form).

use std::time::Duration;

/// An absolute moment in emulated virtual time.
///
/// Internally a retired-instruction count paired with the TSC frequency
/// (instructions per emulated second) it was measured against.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VirtTime {
    instructions: u64,
    frequency: u64,
}

/// A delta between two virtual-time moments.
///
/// Internally a retired-instruction delta paired with its TSC frequency.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VirtDuration {
    instructions: u64,
    frequency: u64,
}

impl VirtTime {
    /// Construct a moment from a raw retired-instruction count and the TSC
    /// frequency (instructions per emulated second).
    pub const fn from_instructions(instructions: u64, frequency: u64) -> Self {
        Self {
            instructions,
            frequency,
        }
    }

    pub fn from_secs_f64(secs: f64, frequency: u64) -> Self {
        Self::from_instructions((secs * frequency as f64) as u64, frequency)
    }

    pub fn from_millis(ms: u64, frequency: u64) -> Self {
        Self::from_instructions(ms.saturating_mul(frequency) / 1_000, frequency)
    }

    pub fn from_millis_f64(ms: f64, frequency: u64) -> Self {
        Self::from_instructions((ms * 1e-3 * frequency as f64) as u64, frequency)
    }

    pub fn from_secs(s: u64, frequency: u64) -> Self {
        Self::from_instructions(s.saturating_mul(frequency), frequency)
    }

    /// The raw retired-instruction count.
    pub const fn instructions(&self) -> u64 {
        self.instructions
    }

    /// The TSC frequency, in instructions per emulated second.
    pub const fn frequency(&self) -> u64 {
        self.frequency
    }

    pub fn as_secs_f64(&self) -> f64 {
        self.instructions as f64 / self.frequency as f64
    }

    pub fn as_duration(&self) -> Duration {
        Duration::from_secs_f64(self.as_secs_f64())
    }

    /// Subtract two moments without panicking on frequency mismatch.
    pub fn checked_sub(self, rhs: Self) -> Option<VirtDuration> {
        if self.frequency != rhs.frequency {
            return None;
        }
        let instructions = self.instructions.checked_sub(rhs.instructions)?;
        Some(VirtDuration {
            instructions,
            frequency: self.frequency,
        })
    }
}

impl VirtDuration {
    /// Construct a duration from a retired-instruction count and the TSC
    /// frequency (instructions per emulated second).
    pub const fn from_instructions(instructions: u64, frequency: u64) -> Self {
        Self {
            instructions,
            frequency,
        }
    }

    pub fn from_millis(ms: u64, frequency: u64) -> Self {
        Self::from_instructions(ms.saturating_mul(frequency) / 1_000, frequency)
    }

    pub fn from_millis_f64(ms: f64, frequency: u64) -> Self {
        Self::from_instructions((ms * 1e-3 * frequency as f64) as u64, frequency)
    }

    pub fn from_secs(s: u64, frequency: u64) -> Self {
        Self::from_instructions(s.saturating_mul(frequency), frequency)
    }

    pub fn from_secs_f64(secs: f64, frequency: u64) -> Self {
        Self::from_instructions((secs * frequency as f64) as u64, frequency)
    }

    /// The raw retired-instruction count.
    pub const fn instructions(&self) -> u64 {
        self.instructions
    }

    /// The TSC frequency, in instructions per emulated second.
    pub const fn frequency(&self) -> u64 {
        self.frequency
    }

    pub fn as_secs_f64(&self) -> f64 {
        self.instructions as f64 / self.frequency as f64
    }

    pub fn as_duration(&self) -> Duration {
        Duration::from_secs_f64(self.as_secs_f64())
    }
}

impl std::ops::Add<VirtDuration> for VirtTime {
    type Output = VirtTime;
    fn add(self, rhs: VirtDuration) -> VirtTime {
        assert_eq!(
            self.frequency, rhs.frequency,
            "TSC frequency mismatch in VirtTime + VirtDuration"
        );
        VirtTime {
            instructions: self.instructions.saturating_add(rhs.instructions),
            frequency: self.frequency,
        }
    }
}

impl std::ops::Sub<VirtDuration> for VirtTime {
    type Output = VirtTime;
    fn sub(self, rhs: VirtDuration) -> VirtTime {
        assert_eq!(
            self.frequency, rhs.frequency,
            "TSC frequency mismatch in VirtTime - VirtDuration"
        );
        VirtTime {
            instructions: self.instructions.saturating_sub(rhs.instructions),
            frequency: self.frequency,
        }
    }
}

impl std::ops::Sub<VirtTime> for VirtTime {
    type Output = VirtDuration;
    fn sub(self, rhs: VirtTime) -> VirtDuration {
        self.checked_sub(rhs)
            .expect("TSC frequency mismatch in VirtTime - VirtTime")
    }
}

/// Define `vt!`, `tsc!`, `vt_dur!`, and `tsc_dur!` bound to a TSC frequency,
/// so callers don't have to thread the frequency through every construction.
///
/// `vt!` / `tsc!` produce [`VirtTime`]; `vt_dur!` / `tsc_dur!` produce
/// [`VirtDuration`]. The `vt*!` forms take a numeric literal with an `s` or
/// `ms` suffix (integer or float — both flow through the f64 constructors);
/// the `tsc*!` forms take a raw retired-instruction count.
///
/// The first argument must be a literal `$` — the standard stable-Rust
/// workaround that lets the outer macro define inner macros.
///
/// ```ignore
/// bedrock_lab::define_virt_time_macros!($, 2_995_200_000);
///
/// let t  = vt!(1.5 s);         // VirtTime at 1.5 emulated seconds
/// let u  = vt!(500 ms);        // VirtTime at 500 ms (integer literal)
/// let v  = vt!(0.25 ms);       // VirtTime at 250 µs (float literal)
/// let i  = tsc!(1_000_000);    // VirtTime from raw instruction count
/// let d  = vt_dur!(2 s);       // VirtDuration of 2 emulated seconds
/// let dd = tsc_dur!(42);       // VirtDuration from raw instruction count
/// ```
#[macro_export]
macro_rules! define_virt_time_macros {
    ($d:tt, $freq:expr) => {
        macro_rules! vt {
                    ($d n:literal s)  => { $crate::VirtTime::from_secs_f64($d n as f64, $freq) };
                    ($d n:literal ms) => { $crate::VirtTime::from_millis_f64($d n as f64, $freq) };
                }
        macro_rules! tsc {
                    ($d n:expr) => { $crate::VirtTime::from_instructions($d n, $freq) };
                }
        macro_rules! vt_dur {
                    ($d n:literal s)  => { $crate::VirtDuration::from_secs_f64($d n as f64, $freq) };
                    ($d n:literal ms) => { $crate::VirtDuration::from_millis_f64($d n as f64, $freq) };
                }
        macro_rules! tsc_dur {
                    ($d n:expr) => { $crate::VirtDuration::from_instructions($d n, $freq) };
                }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    const FREQ: u64 = 2_995_200_000;

    #[test]
    fn from_and_to_secs_roundtrip() {
        let t = VirtTime::from_secs_f64(1.5, FREQ);
        assert!((t.as_secs_f64() - 1.5).abs() < 1e-6);
    }

    #[test]
    fn arithmetic() {
        let t0 = VirtTime::from_secs(1, FREQ);
        let t1 = VirtTime::from_secs(3, FREQ);
        let dt = t1 - t0;
        assert_eq!(dt.instructions(), 2 * FREQ);
        assert_eq!((t0 + dt).instructions(), t1.instructions());
    }

    #[test]
    fn bound_macros() {
        crate::define_virt_time_macros!($, FREQ);

        let t_int: VirtTime = vt!(2 s);
        assert_eq!(t_int, VirtTime::from_secs(2, FREQ));

        let t_flt: VirtTime = vt!(1.5 s);
        assert_eq!(t_flt, VirtTime::from_secs_f64(1.5, FREQ));

        let t_ms: VirtTime = vt!(500 ms);
        assert_eq!(t_ms, VirtTime::from_millis(500, FREQ));

        let t_ms_flt: VirtTime = vt!(0.5 ms);
        assert_eq!(t_ms_flt, VirtTime::from_millis_f64(0.5, FREQ));

        let t_tsc: VirtTime = tsc!(1_234_567);
        assert_eq!(t_tsc, VirtTime::from_instructions(1_234_567, FREQ));

        let d_s: VirtDuration = vt_dur!(2 s);
        assert_eq!(d_s, VirtDuration::from_secs(2, FREQ));

        let d_ms: VirtDuration = vt_dur!(500 ms);
        assert_eq!(d_ms, VirtDuration::from_millis(500, FREQ));

        let d_ms_flt: VirtDuration = vt_dur!(0.25 ms);
        assert_eq!(d_ms_flt, VirtDuration::from_millis_f64(0.25, FREQ));

        let d_tsc: VirtDuration = tsc_dur!(42);
        assert_eq!(d_tsc, VirtDuration::from_instructions(42, FREQ));
    }
}
