// SPDX-License-Identifier: GPL-2.0

//! Serial port (8250/16550 UART) emulation for COM1 at 0x3F8.
//!
//! The 8250 driver probes the UART by testing registers, particularly the
//! scratch register (SCR). We need to track writable registers so reads
//! return previously written values.

#[cfg(not(feature = "cargo"))]
use super::super::prelude::*;
#[cfg(feature = "cargo")]
use crate::prelude::*;

/// Serial port (8250/16550 UART) state for COM1 at 0x3F8.
///
/// The 8250 driver probes the UART by testing registers, particularly the
/// scratch register (SCR). We need to track writable registers so reads
/// return previously written values.
#[derive(Clone, Debug, Default)]
pub struct SerialState {
    /// Interrupt Enable Register (0x3F9) - controls which interrupts are enabled
    pub ier: u8,
    /// Line Control Register (0x3FB) - controls data format
    pub lcr: u8,
    /// Modem Control Register (0x3FC) - controls modem signals
    pub mcr: u8,
    /// Scratch Register (0x3FF) - general purpose, used for UART detection
    pub scr: u8,
    /// Divisor Latch Low (when DLAB=1, 0x3F8)
    pub dll: u8,
    /// Divisor Latch High (when DLAB=1, 0x3F9)
    pub dlh: u8,
}

impl StateHash for SerialState {
    fn state_hash(&self) -> u64 {
        let mut h = Xxh64Hasher::new();
        h.write_u8(self.ier);
        h.write_u8(self.lcr);
        h.write_u8(self.mcr);
        h.write_u8(self.scr);
        h.write_u8(self.dll);
        h.write_u8(self.dlh);
        h.finish()
    }
}
