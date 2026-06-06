// SPDX-License-Identifier: GPL-2.0

//! Direct MSR-based instruction counter using `IA32_PMC0`.
//!
//! Counts guest instructions retired (`INST_RETIRED.ANY_P`, event 0xC0) on
//! general-purpose counter 0, programmed directly via MSRs. Determinism is
//! achieved by hooking the counter MSR into the VMCS VM-exit MSR-store list
//! and VM-entry MSR-load list pointing at the same memory entry, so:
//!
//! * On VM exit, the CPU atomically saves `IA32_PMC0` into the entry before
//!   any host code runs.
//! * On the next VM entry, the CPU atomically reloads `IA32_PMC0` from the
//!   entry, wiping any ticks the host counter accumulated in between.
//!
//! `IA32_PMC0` is used here (rather than the more obvious `IA32_FIXED_CTR0`)
//! because the precise-VM-exit PEBS facility wants `IA32_FIXED_CTR0` for its
//! own arming (see `exits/pebs.rs`); putting the IC on a GP counter frees the
//! fixed counter for PEBS.
//!
//! Userspace must pin the thread to the desired CPU before creating the VM;
//! on hybrid CPUs that should be a P-core (where general-purpose counter 0
//! supports `INST_RETIRED.ANY_P`).

use super::page::{alloc_zeroed_page, KernelPage};
use crate::c_helpers;
use crate::vmx::traits::{InstructionCounter, InstructionCounterError};

/// Full-width-write alias for general-purpose counter 0 (`IA32_PMC0`,
/// MSR `0xC1`). `WRMSR` to `IA32_PMC0` itself truncates the input to 32
/// bits and sign-extends from bit 31, which garbles the counter once
/// the value crosses ~2.1 billion. Writing through `IA32_A_PMC0` writes
/// all 48 counter bits directly. Available when
/// `IA32_PERF_CAPABILITIES.FULL_WRITE` (bit 13) is set; required by the
/// VMCS auto-load round-trip the IC depends on. See SDM Vol 3B Section
/// 21.2.8.
const IA32_A_PMC0: u32 = 0x4C1;
/// Performance event-select register for `IA32_PMC0`.
const IA32_PERFEVTSEL0: u32 = 0x186;
/// Global enable for performance counters (SDM Vol 4 Table 2-2).
const IA32_PERF_GLOBAL_CTRL: u32 = 0x38F;

/// `IA32_PERFEVTSEL0` programming for `INST_RETIRED.ANY_P`: event select
/// 0xC0, unit mask 0x00, USR (bit 16), OS (bit 17), EN (bit 22). Counts
/// every retired instruction.
const PERFEVTSEL0_INST_RETIRED_ANY_P: u64 = (1u64 << 16) | (1u64 << 17) | (1u64 << 22) | 0xC0;
/// Bit 0 in `IA32_PERF_GLOBAL_CTRL` enables `IA32_PMC0`.
const PERF_GLOBAL_CTRL_PMC0: u64 = 1;

/// VMCS MSR-list entry layout (SDM Vol 3C Table 26-16).
#[repr(C)]
struct MsrListEntry {
    msr_index: u32,
    reserved: u32,
    msr_data: u64,
}

#[inline]
fn rdmsr(addr: u32) -> Result<u64, InstructionCounterError> {
    let mut value = 0;
    // SAFETY: `value` is a valid output pointer. The kernel helper catches
    // the #GP raised when the MSR is unavailable.
    let ret = unsafe { c_helpers::bedrock_rdmsr_safe(addr, &mut value) };
    if ret != 0 {
        return Err(InstructionCounterError::Unavailable);
    }
    Ok(value)
}

#[inline]
fn wrmsr(addr: u32, value: u64) -> Result<(), InstructionCounterError> {
    // SAFETY: The kernel helper catches the #GP raised when the MSR or value
    // is unavailable.
    let ret = unsafe { c_helpers::bedrock_wrmsr_safe(addr, value) };
    if ret != 0 {
        return Err(InstructionCounterError::ProgramFailed);
    }
    Ok(())
}

/// Direct MSR-based instruction counter for general-purpose counter 0.
pub(crate) struct LinuxInstructionCounter {
    /// Backing page for the VMCS MSR-list entry. The first 16 bytes are the
    /// entry; the rest is unused. None on null counters.
    msr_entry_page: Option<KernelPage>,
    /// Saved `IA32_PERFEVTSEL0`, captured in `prepare`, restored in `finish`.
    saved_perfevtsel0: u64,
    /// Value the CPU loads into `IA32_PERF_GLOBAL_CTRL` on VM entry.
    guest_perf_global_ctrl: u64,
    /// Value the CPU loads into `IA32_PERF_GLOBAL_CTRL` on VM exit.
    host_perf_global_ctrl: u64,
    /// Whether `prepare` has run since the last `finish`.
    armed: bool,
}

// SAFETY: KernelPage is itself Send (its only state is a kernel `Page` and
// physical/virtual addresses). The MSR list entry it backs is accessed only
// while preemption is disabled inside the run loop, on the CPU that owns the
// VMCS, so there is no concurrent access.
unsafe impl Send for LinuxInstructionCounter {}

impl LinuxInstructionCounter {
    pub(crate) fn new() -> Self {
        let msr_entry_page = alloc_zeroed_page().inspect(|page| {
            // SAFETY: the page is freshly allocated, zeroed, and not aliased.
            // We initialize the first 16 bytes as a single MSR list entry
            // pointing at IA32_A_PMC0 (full-width-write alias).
            unsafe {
                let entry = page.virt.as_u64() as *mut MsrListEntry;
                core::ptr::write(
                    entry,
                    MsrListEntry {
                        msr_index: IA32_A_PMC0,
                        reserved: 0,
                        msr_data: 0,
                    },
                );
            }
        });

        Self {
            msr_entry_page,
            saved_perfevtsel0: 0,
            guest_perf_global_ctrl: 0,
            host_perf_global_ctrl: 0,
            armed: false,
        }
    }

    /// Read the MSR-data field of the VMCS list entry. The CPU writes this
    /// atomically on VM exit, so it's the counter value at exit time.
    #[inline]
    fn entry_msr_data(&self) -> u64 {
        match self.msr_entry_page.as_ref() {
            Some(page) => {
                // SAFETY: the entry was initialized in `new` and lives as
                // long as `self`. The CPU writes it on VM exit (under our
                // VMCS configuration) and we read it from the host between
                // exits; there is no concurrent access while preemption is
                // disabled.
                unsafe {
                    let entry = page.virt.as_u64() as *const MsrListEntry;
                    core::ptr::read_volatile(&(*entry).msr_data)
                }
            }
            None => 0,
        }
    }
}

impl InstructionCounter for LinuxInstructionCounter {
    fn prepare(&mut self) -> Result<(), InstructionCounterError> {
        if self.msr_entry_page.is_none() {
            return Ok(());
        }

        // Compute PERF_GLOBAL_CTRL values for VMCS auto-load. These act as a
        // first-line gate: bit 0 is cleared on host so the counter is disabled
        // outside of guest execution. NMI handlers can still flip this bit,
        // but the VMCS auto-save/load of IA32_PMC0 makes any host-side ticks
        // irrelevant — they're overwritten on the next VM entry.
        let current_global = rdmsr(IA32_PERF_GLOBAL_CTRL)?;
        self.host_perf_global_ctrl = current_global & !PERF_GLOBAL_CTRL_PMC0;
        self.guest_perf_global_ctrl = self.host_perf_global_ctrl | PERF_GLOBAL_CTRL_PMC0;

        // Save the host's IA32_PERFEVTSEL0 and program ours.
        let saved = rdmsr(IA32_PERFEVTSEL0)?;
        self.saved_perfevtsel0 = saved;
        wrmsr(IA32_PERFEVTSEL0, PERFEVTSEL0_INST_RETIRED_ANY_P)?;

        self.armed = true;
        Ok(())
    }

    fn finish(&mut self) -> Result<(), InstructionCounterError> {
        if !self.armed {
            return Ok(());
        }
        // Restore the host's IA32_PERFEVTSEL0. PERF_GLOBAL_CTRL was already
        // loaded by hardware on the most recent VM exit.
        if wrmsr(IA32_PERFEVTSEL0, self.saved_perfevtsel0).is_err() {
            return Err(InstructionCounterError::RestoreFailed);
        }
        self.armed = false;
        Ok(())
    }

    fn read(&self) -> u64 {
        // The MSR-data field grows monotonically across iterations and across
        // run loops: each VM entry reloads `IA32_PMC0` from this entry, so
        // guest ticks land back here on the next VM exit's auto-save and host
        // ticks (between exits) get overwritten on the next entry.
        self.entry_msr_data()
    }

    fn is_configured(&self) -> bool {
        self.msr_entry_page.is_some()
    }

    fn perf_global_ctrl_values(&self) -> Option<(u64, u64)> {
        if self.armed {
            Some((self.guest_perf_global_ctrl, self.host_perf_global_ctrl))
        } else {
            None
        }
    }

    fn msr_save_load_entry_phys(&self) -> Option<u64> {
        self.msr_entry_page.as_ref().map(|p| p.phys.as_u64())
    }
}
