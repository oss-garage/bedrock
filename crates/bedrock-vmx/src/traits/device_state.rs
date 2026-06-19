// SPDX-License-Identifier: GPL-2.0

//! Device and MSR state structures for VM emulation.
//!
//! These structures group related emulated device states for cleaner
//! trait interfaces.

#[cfg(not(feature = "cargo"))]
use super::super::prelude::*;
#[cfg(feature = "cargo")]
use crate::prelude::*;

/// Grouped device emulation states for cleaner trait interface.
///
/// This struct bundles all the device states that the exit handler needs
/// to access during VM operation. Using a single struct reduces the number
/// of methods on the `VmContext` trait.
#[derive(Clone)]
pub struct DeviceStates {
    /// Local APIC state for interrupt emulation.
    pub apic: ApicState,
    /// Serial port (8250/16550 UART) state.
    pub serial: SerialState,
    /// I/O APIC state for interrupt routing.
    pub ioapic: IoApicState,
    /// RTC (CMOS clock) state.
    pub rtc: RtcState,
    /// Memory Type Range Registers state.
    pub mtrr: MtrrState,
    /// Controlled-randomness device: RDRAND, RDSEED, and the
    /// `HYPERCALL_GET_RANDOM` (`/dev/urandom` / `getrandom()`) chokepoint.
    pub random: RandomState,
}

impl DeviceStates {
    /// Create a new DeviceStates with default values for all devices.
    pub fn new() -> Self {
        Self {
            apic: ApicState::default(),
            serial: SerialState::default(),
            ioapic: IoApicState::default(),
            rtc: RtcState::default(),
            mtrr: MtrrState::default(),
            random: RandomState::default(),
        }
    }
}

impl Default for DeviceStates {
    fn default() -> Self {
        Self::new()
    }
}

/// Grouped guest MSR state for cleaner trait interface.
///
/// This struct bundles MSRs that are emulated by the hypervisor rather than
/// passed through to hardware.
#[derive(Clone, Copy)]
pub struct GuestMsrState {
    /// IA32_PAT (0x277) - Page Attribute Table.
    pub pat: u64,
    /// IA32_TSC_AUX (0xC0000103) - auxiliary value for RDTSCP.
    pub tsc_aux: u64,
    /// SYSCALL/SYSRET MSRs (STAR, LSTAR, CSTAR, FMASK).
    pub syscall: SyscallMsrs,
}

impl GuestMsrState {
    /// Create a new GuestMsrState with default values.
    pub fn new() -> Self {
        Self {
            pat: 0x0007_0406_0007_0406, // Default PAT value after reset
            tsc_aux: 0,
            syscall: SyscallMsrs::default(),
        }
    }
}

impl Default for GuestMsrState {
    fn default() -> Self {
        Self::new()
    }
}
