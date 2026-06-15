// SPDX-License-Identifier: GPL-2.0

//! I/O instruction exit handler.
//!
//! Handles IN/OUT instructions for serial port, CMOS RTC, and PCI config space.

use super::helpers::{advance_rip, ExitHandlerResult};
use super::interrupts::ioapic_deliver_irq;
use super::qualifications::{IoDirection, IoQualification};
use super::reasons::ExitReason;

#[cfg(not(feature = "cargo"))]
use super::super::prelude::*;
#[cfg(feature = "cargo")]
use crate::prelude::*;

/// Handle I/O instruction exit.
pub fn handle_io<C: VmContext>(ctx: &mut C, qual: IoQualification) -> ExitHandlerResult {
    if qual.string {
        // String I/O not implemented - exit to userspace
        return ExitHandlerResult::ExitToUserspace(ExitReason::IoInstruction);
    }

    let size = qual.size as usize;

    // DLAB (Divisor Latch Access Bit) is bit 7 of LCR
    // When set, ports 0x3F8 and 0x3F9 access divisor latch registers
    let dlab = (ctx.state().devices.serial.lcr & 0x80) != 0;

    match qual.direction {
        IoDirection::Out => {
            let value = ctx.state().gprs.rax as u32 & ((1u64 << (size * 8)) - 1) as u32;
            let byte = (value & 0xFF) as u8;

            match qual.port {
                0x3F8 => {
                    if dlab {
                        // Divisor Latch Low
                        ctx.state_mut().devices.serial.dll = byte;
                    } else {
                        // Transmit data (the `earlyprintk=serial` per-byte path).
                        // Feed the line accumulator, which emits one `Serial`
                        // event per line (on `\n` or when its fixed buffer fills)
                        // instead of one event per byte. No-op unless the Serial
                        // category is enabled. A full event buffer is handled
                        // centrally by the dispatcher (`event_buffer_full`), so
                        // the return value is ignored.
                        let _ = ctx.state_mut().event_serial_byte(byte);
                    }
                }
                0x3F9 => {
                    if dlab {
                        // Divisor Latch High
                        ctx.state_mut().devices.serial.dlh = byte;
                    } else {
                        // Interrupt Enable Register
                        ctx.state_mut().devices.serial.ier = byte & 0x0F;
                        // If THRE interrupt enabled (bit 1) and TX is empty (always true),
                        // deliver IRQ 4 through I/O APIC
                        if (byte & 0x02) != 0 {
                            ioapic_deliver_irq(ctx, 4);
                        }
                    }
                }
                0x3FB => {
                    // Line Control Register
                    ctx.state_mut().devices.serial.lcr = byte;
                }
                0x3FC => {
                    // Modem Control Register
                    ctx.state_mut().devices.serial.mcr = byte & 0x1F;
                }
                0x3FF => {
                    // Scratch Register - used by driver to detect UART
                    ctx.state_mut().devices.serial.scr = byte;
                }
                0x3FA => {
                    // FCR (write-only) - ignore, we don't emulate FIFOs
                }
                0x80 => {
                    // POST diagnostic port - ignore
                }
                0xCF8 => {
                    // PCI configuration address - ignore for now
                }
                0xCFC..=0xCFF => {
                    // PCI configuration data - ignore
                }
                0x70 => {
                    // CMOS RTC index register - store selected register
                    // Bit 7 is NMI disable, bits 6:0 are register index
                    ctx.state_mut().devices.rtc.index = byte & 0x7F;
                }
                _ => {
                    // Unknown port - ignore
                }
            }
        }
        IoDirection::In => {
            let value: u32 = match qual.port {
                0x3F8 => {
                    if dlab {
                        // Divisor Latch Low
                        u32::from(ctx.state().devices.serial.dll)
                    } else {
                        // RX data (RBR) - no host->guest serial input, always 0
                        0
                    }
                }
                0x3F9 => {
                    if dlab {
                        // Divisor Latch High
                        u32::from(ctx.state().devices.serial.dlh)
                    } else {
                        // Interrupt Enable Register
                        u32::from(ctx.state().devices.serial.ier)
                    }
                }
                0x3FA => {
                    // Interrupt Identification Register (IIR)
                    // Bit 0: 0 = interrupt pending, 1 = no interrupt pending
                    // Bits 1-3: Interrupt ID (001 = THRE)
                    // Bits 6-7 = 11 (FIFOs enabled)
                    let ier = ctx.state().devices.serial.ier;
                    if (ier & 0x02) != 0 {
                        // THRE interrupt enabled and TX is always empty
                        // Return 0xC2 = THRE interrupt pending
                        0xC2
                    } else {
                        // No interrupt pending
                        0xC1
                    }
                }
                0x3FB => {
                    // Line Control Register
                    u32::from(ctx.state().devices.serial.lcr)
                }
                0x3FC => {
                    // Modem Control Register
                    u32::from(ctx.state().devices.serial.mcr)
                }
                0x3FD => {
                    // Line Status Register (LSR)
                    // Bit 0: Data Ready (never set — no host->guest serial input)
                    // Bit 5: Transmitter holding register empty
                    // Bit 6: Transmitter empty
                    0x60
                }
                0x3FE => {
                    // Modem Status Register (MSR)
                    // DCD | DSR | CTS - must be set or tty open blocks
                    0xB0
                }
                0x3FF => {
                    // Scratch Register - return what was written
                    u32::from(ctx.state().devices.serial.scr)
                }
                0xCFC..=0xCFF => {
                    // PCI config data - no device
                    0xFFFFFFFF >> ((4 - size) * 8)
                }
                0x60 => {
                    // Keyboard controller data port - no data
                    0
                }
                0x64 => {
                    // Keyboard controller status port
                    // Return 0xFF to indicate no controller present.
                    // This makes Linux i8042 probing fail immediately
                    // instead of timing out waiting for the controller.
                    0xFF
                }
                0x71 => {
                    // CMOS RTC data register - read from selected register
                    // Use emulated TSC for deterministic time
                    let emulated_tsc = ctx.state().emulated_tsc;
                    let tsc_frequency = ctx.state().tsc_frequency;
                    u32::from(
                        ctx.state()
                            .devices
                            .rtc
                            .read_register_with_tsc(emulated_tsc, tsc_frequency),
                    )
                }
                _ => 0,
            };

            let mask = (1u64 << (size * 8)) - 1;
            let gprs = &mut ctx.state_mut().gprs;
            gprs.rax = (gprs.rax & !mask) | (u64::from(value) & mask);
        }
    }

    if let Err(e) = advance_rip(ctx) {
        return ExitHandlerResult::Error(e);
    }

    ExitHandlerResult::Continue
}
