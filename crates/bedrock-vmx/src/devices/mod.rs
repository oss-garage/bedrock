// SPDX-License-Identifier: GPL-2.0

//! Emulated device state for the hypervisor.
//!
//! This module contains the state structures for all emulated devices.
//! Device emulation logic (exit handlers) is in the `exits/` module,
//! which accesses device state through the `VmContext` trait.

mod apic;
mod ioapic;
mod mtrr;
mod random;
mod rtc;
mod serial;

pub use apic::{ApicState, APIC_BASE_DEFAULT};
pub use ioapic::{IoApicState, IOAPIC_NUM_PINS};
pub use mtrr::{MtrrState, MTRR_VAR_MAX};
pub use random::{RandomState, RdrandMode, RANDOM_REPLY_MAX};
pub use rtc::RtcState;
pub use serial::SerialState;
