// SPDX-License-Identifier: GPL-2.0

//! VMX (Virtual Machine Extensions) support for x86-64 virtualization.
//!
//! This crate provides platform-agnostic VMX abstractions including:
//! - VMCS field encodings organized by width (16-bit, 32-bit, 64-bit, natural-width)
//! - Traits for VMCS operations

#![no_std]

pub mod compat;
pub mod cow;
pub mod decoder;
pub mod devices;
pub mod events;
pub mod exit_record;
pub mod exits;
pub mod fields;
pub mod handler;
pub mod host;
pub mod hypercalls;
mod prelude;
pub mod registers;
pub mod timing;
pub mod traits;
pub mod vm;
pub mod vm_state;

pub use fields::{VmcsField16, VmcsField32, VmcsField64, VmcsFieldNatural};
pub use host::HostState;
pub use registers::GeneralPurposeRegisters;
pub use traits::{
    cpu_based, pin_based, secondary_exec, vm_entry, vm_exit, InveptError, InvvpidError,
    MemoryError, VirtualMachineControlStructure, VmContext, VmEntryError, VmRunner, VmcsReadError,
    VmcsReadResult, VmcsWriteError, VmcsWriteResult, Vmx, VmxCapabilities, VmxContext,
    VmxInitError, VmxoffError, VmxonError,
};

// VM implementation
pub use traits::VmRunError;
pub use vm::{ForkableVm, ForkedVm, ForkedVmError, ParentVm, RootVm, RootVmError};
pub use vm_state::{
    AllExitStats, ExitStats, ExitTrigger, SyscallMsrs, VmState, VmStateError,
    DEFAULT_TSC_FREQUENCY, EVENT_BUFFER_MMAP_OFFSET, FEEDBACK_BUFFER_SLOT_SIZE, PAT_DEFAULT,
};

// Handler
#[cfg(feature = "cargo")]
pub use handler::VmRef;
pub use handler::{BedrockHandler, VmEntry};

// COW support
pub use cow::CowPageMap;

// Exit handling types
pub use exits::{
    handle_exit, CrAccessQualification, EptViolationQualification, ExitError, ExitHandlerResult,
    ExitReason, IoQualification, IO_CHANNEL_IRQ,
};

/// Test mocks for use in other crates' tests.
/// Available when the `test-utils` feature is enabled.
#[cfg(any(test, feature = "test-utils"))]
pub mod test_mocks;

#[cfg(test)]
mod handler_tests;

#[cfg(test)]
mod tests;
