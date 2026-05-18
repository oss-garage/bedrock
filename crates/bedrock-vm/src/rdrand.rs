// SPDX-License-Identifier: GPL-2.0

//! RDRAND emulation configuration types.
//!
//! This module defines the configuration structures for RDRAND instruction
//! emulation. Two modes are supported:
//!
//! 1. **Seeded RNG**: Use a simple non-cryptographic PRNG seeded by userspace.
//! 2. **Exit to userspace**: Return to userspace on each RDRAND, allowing
//!    userspace to provide the value.

/// RDRAND emulation mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum RdrandMode {
    /// Use a seeded PRNG (xorshift64).
    SeededRng = 0,
    /// Exit to userspace for each RDRAND, let userspace provide value.
    ExitToUserspace = 1,
}

impl TryFrom<u32> for RdrandMode {
    type Error = ();

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(RdrandMode::SeededRng),
            1 => Ok(RdrandMode::ExitToUserspace),
            _ => Err(()),
        }
    }
}

/// Configuration for RDRAND emulation passed to the kernel via ioctl.
///
/// This structure is used with the SET_RDRAND_CONFIG ioctl to configure
/// how RDRAND instructions are emulated in the guest.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RdrandConfig {
    /// Emulation mode (see RdrandMode enum).
    pub mode: u32,
    /// Reserved for alignment.
    pub _reserved: u32,
    /// Value used by the emulation mode:
    /// - For SeededRng mode: the seed for the PRNG
    /// - For ExitToUserspace mode: ignored
    pub value: u64,
}

impl RdrandConfig {
    /// Create a configuration that uses a seeded PRNG.
    pub fn seeded_rng(seed: u64) -> Self {
        Self {
            mode: RdrandMode::SeededRng as u32,
            _reserved: 0,
            value: seed,
        }
    }

    /// Create a configuration that exits to userspace on each RDRAND.
    pub fn exit_to_userspace() -> Self {
        Self {
            mode: RdrandMode::ExitToUserspace as u32,
            _reserved: 0,
            value: 0,
        }
    }
}

impl Default for RdrandConfig {
    fn default() -> Self {
        // Default: seeded RNG with seed 0 for deterministic behavior
        Self::seeded_rng(0x12345678_deadbeef)
    }
}

/// RDRAND exit information returned to userspace.
///
/// When in ExitToUserspace mode, this structure provides information about
/// the RDRAND instruction that caused the exit. Userspace must set the
/// return value and call the VM run ioctl again to resume.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct RdrandExitInfo {
    /// Destination register index (0=RAX, 1=RCX, 2=RDX, 3=RBX, 4=RSP, 5=RBP, 6=RSI, 7=RDI, 8-15=R8-R15).
    pub dest_reg: u8,
    /// Operand size: 0=16-bit, 1=32-bit, 2=64-bit.
    pub operand_size: u8,
    /// Reserved for alignment.
    pub _reserved: [u8; 6],
}

/// Response from userspace for RDRAND exit.
///
/// When RDRAND exits to userspace, userspace must provide the value to return
/// via the SET_RDRAND_VALUE ioctl before resuming the VM.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RdrandValue {
    /// The value to return from RDRAND.
    pub value: u64,
}
