// SPDX-License-Identifier: GPL-2.0

//! Common imports for bedrock-vmx internal modules.
//!
//! This prelude centralizes the conditional imports needed for dual cargo/kernel builds,
//! reducing boilerplate in individual module files. Instead of having multiple
//! `#[cfg(feature = "cargo")]` blocks in each file, modules can simply import from
//! this prelude.

// Re-exports are used by modules that import `prelude::*`
#![allow(unused_imports)]

// =============================================================================
// VMCS field types
// =============================================================================
#[cfg(not(feature = "cargo"))]
pub use super::fields::{VmcsField16, VmcsField32, VmcsField64, VmcsFieldNatural};
#[cfg(feature = "cargo")]
pub use crate::fields::{VmcsField16, VmcsField32, VmcsField64, VmcsFieldNatural};

// =============================================================================
// Host state
// =============================================================================
#[cfg(not(feature = "cargo"))]
pub use super::host::HostState;
#[cfg(feature = "cargo")]
pub use crate::host::HostState;

// =============================================================================
// Register types and traits
// =============================================================================
#[cfg(not(feature = "cargo"))]
pub use super::registers::{
    msr, xcr0, ControlRegisters, Cr0, Cr2, Cr3, Cr4, Cr8, CrAccess, CrError, Cstar, DebugRegisters,
    DescriptorTableAccess, DescriptorTableRegisters, Efer, ExtendedControlRegisters, Fmask, Gdtr,
    GeneralPurposeRegisters, GuestRegisters, Idtr, Lstar, MiscEnable, MsrAccess, MsrError,
    SegmentRegister, SegmentRegisters, Star,
};
#[cfg(feature = "cargo")]
pub use crate::registers::{
    msr, xcr0, ControlRegisters, Cr0, Cr2, Cr3, Cr4, Cr8, CrAccess, CrError, Cstar, DebugRegisters,
    DescriptorTableAccess, DescriptorTableRegisters, Efer, ExtendedControlRegisters, Fmask, Gdtr,
    GeneralPurposeRegisters, GuestRegisters, Idtr, Lstar, MiscEnable, MsrAccess, MsrError,
    SegmentRegister, SegmentRegisters, Star,
};

// =============================================================================
// Memory address types
// =============================================================================
#[cfg(not(feature = "cargo"))]
pub use crate::memory::{GuestPhysAddr, HostPhysAddr, VirtAddr};
#[cfg(feature = "cargo")]
pub use memory::{GuestPhysAddr, HostPhysAddr, VirtAddr};

// =============================================================================
// Device state for emulation
// =============================================================================
#[cfg(not(feature = "cargo"))]
pub use super::devices::{
    ApicState, IoApicState, MtrrState, RdrandMode, RdrandState, RtcState, SerialState,
    IOAPIC_NUM_PINS, MTRR_VAR_MAX,
};
#[cfg(feature = "cargo")]
pub use crate::devices::{
    ApicState, IoApicState, MtrrState, RdrandMode, RdrandState, RtcState, SerialState,
    IOAPIC_NUM_PINS, MTRR_VAR_MAX,
};

// =============================================================================
// Core traits - VMX, VMCS, and kernel abstractions
// =============================================================================
#[cfg(not(feature = "cargo"))]
pub use super::traits::{
    allocate_vpid, cpu_based, deallocate_vpid, secondary_exec, vm_entry, vm_exit, CowAllocator,
    DeviceStates, GuestMemory, GuestMsrState, InstructionCounter, IrqGuard, Kernel, Machine,
    MemoryError, Page, ReverseIrqGuard, VirtualMachineControlStructure, VmContext, VmEntryError,
    VmcsGuard, VmcsReadError, VmcsSetupError, VmcsWriteError, Vmx, VmxContext, VmxCpu,
    VmxInitError,
};
#[cfg(feature = "cargo")]
pub use crate::traits::{
    allocate_vpid, cpu_based, deallocate_vpid, secondary_exec, vm_entry, vm_exit, CowAllocator,
    DeviceStates, GuestMemory, GuestMsrState, InstructionCounter, IrqGuard, Kernel, Machine,
    MemoryError, Page, ReverseIrqGuard, VirtualMachineControlStructure, VmContext, VmEntryError,
    VmcsReadError, VmcsSetupError, VmcsWriteError, Vmx, VmxContext, VmxCpu, VmxInitError,
};

// =============================================================================
// EPT (Extended Page Tables)
// =============================================================================
#[cfg(not(feature = "cargo"))]
pub use crate::ept::{EptMemoryType, EptPageTable, EptPermissions, FrameAllocator};
#[cfg(feature = "cargo")]
pub use bedrock_ept::{EptMemoryType, EptPageTable, EptPermissions, FrameAllocator};

// =============================================================================
// Exit handling
// =============================================================================
#[cfg(not(feature = "cargo"))]
pub use super::exits::{
    arm_for_next_iteration, arm_precise_exit, check_io_channel, disarm_precise_exit,
    get_pebs_margin, handle_exit, inject_pending_interrupt, pebs_post_vm_exit, pebs_pre_vm_entry,
    update_mtf_state, ArmResult, DsManagementArea, ExitError, ExitHandlerResult, ExitReason,
    PebsAction, PebsState, APIC_BASE, APIC_SIZE, IOAPIC_BASE, IOAPIC_SIZE, IO_CHANNEL_IRQ,
    PEBS_MIN_DELTA, PERF_GLOBAL_CTRL_FIXED_CTR0,
};
#[cfg(feature = "cargo")]
pub use crate::exits::{
    arm_for_next_iteration, arm_precise_exit, check_io_channel, disarm_precise_exit,
    get_pebs_margin, handle_exit, inject_pending_interrupt, pebs_post_vm_exit, pebs_pre_vm_entry,
    update_mtf_state, ArmResult, DsManagementArea, ExitError, ExitHandlerResult, ExitReason,
    PebsAction, PebsState, APIC_BASE, APIC_SIZE, IOAPIC_BASE, IOAPIC_SIZE, IO_CHANNEL_IRQ,
    PEBS_MIN_DELTA, PERF_GLOBAL_CTRL_FIXED_CTR0,
};

// =============================================================================
// Logging
// =============================================================================
#[cfg(not(feature = "cargo"))]
pub use super::exit_record::{ExitRecord, StateHash, Xxh64Hasher, EXIT_RECORD_FLAG_DETERMINISTIC};
#[cfg(feature = "cargo")]
pub use crate::exit_record::{ExitRecord, StateHash, Xxh64Hasher, EXIT_RECORD_FLAG_DETERMINISTIC};

// Logging macros - in kernel builds, macros are available via #[macro_use] on mod log
#[cfg(feature = "cargo")]
pub use bedrock_log::{log_debug, log_err, log_info, log_warn};

// =============================================================================
// Event stream (wire-format types)
// =============================================================================
#[cfg(not(feature = "cargo"))]
pub use super::events::{
    align_up, EventCategories, EventHeader, EventKind, InjectPayload, InjectSource,
    IoChannelPayload, IoChannelPhase, RandomPayload, RandomSource, EVENT_BUFFER_SIZE,
    EVENT_FLAG_DETERMINISTIC, EVENT_HEADER_SIZE,
};
#[cfg(feature = "cargo")]
pub use crate::events::{
    align_up, EventCategories, EventHeader, EventKind, InjectPayload, InjectSource,
    IoChannelPayload, IoChannelPhase, RandomPayload, RandomSource, EVENT_BUFFER_SIZE,
    EVENT_FLAG_DETERMINISTIC, EVENT_HEADER_SIZE,
};

// =============================================================================
// Instruction decoder
// =============================================================================
#[cfg(not(feature = "cargo"))]
pub use super::decoder::decode_instruction;
#[cfg(feature = "cargo")]
pub use crate::decoder::decode_instruction;

// =============================================================================
// Hypercalls
// =============================================================================
#[cfg(not(feature = "cargo"))]
pub use super::hypercalls::{
    HYPERCALL_FILE_FETCH, HYPERCALL_IO_GET_REQUEST, HYPERCALL_IO_PUT_RESPONSE,
    HYPERCALL_IO_REGISTER_PAGE, HYPERCALL_READY, HYPERCALL_REGISTER_FEEDBACK_BUFFER,
    HYPERCALL_REGISTER_PEBS_PAGE, HYPERCALL_SERIAL_REGISTER_PAGE, HYPERCALL_SERIAL_WRITE,
    HYPERCALL_SHUTDOWN, HYPERCALL_SNAPSHOT,
};
#[cfg(feature = "cargo")]
pub use crate::hypercalls::{
    HYPERCALL_FILE_FETCH, HYPERCALL_IO_GET_REQUEST, HYPERCALL_IO_PUT_RESPONSE,
    HYPERCALL_IO_REGISTER_PAGE, HYPERCALL_READY, HYPERCALL_REGISTER_FEEDBACK_BUFFER,
    HYPERCALL_REGISTER_PEBS_PAGE, HYPERCALL_SERIAL_REGISTER_PAGE, HYPERCALL_SERIAL_WRITE,
    HYPERCALL_SHUTDOWN, HYPERCALL_SNAPSHOT,
};

// =============================================================================
// COW (Copy-on-Write) memory management
// =============================================================================
#[cfg(not(feature = "cargo"))]
pub use super::cow::CowPageMap;
#[cfg(feature = "cargo")]
pub use crate::cow::CowPageMap;

// =============================================================================
// VM state
// =============================================================================
#[cfg(not(feature = "cargo"))]
pub use super::vm_state::{
    box_vm_state, AllExitStats, EnqueueResult, ExitStats, ExitTrigger, FeedbackBufferInfo,
    FeedbackBuffers, IoChannelState, PendingIoAction, SerialConsoleState, SyscallMsrs, VmState,
    VmStateBox, VmStateError, DEFAULT_TSC_FREQUENCY, FEEDBACK_BUFFER_ID_MAX_LEN,
    FEEDBACK_BUFFER_MAX_PAGES, IO_CHANNEL_BUF_SIZE, PENDING_IO_QUEUE_CAP, SERIAL_CONSOLE_PAGE_SIZE,
};
#[cfg(feature = "cargo")]
pub use crate::vm_state::{
    box_vm_state, AllExitStats, EnqueueResult, ExitStats, ExitTrigger, FeedbackBufferInfo,
    FeedbackBuffers, IoChannelState, PendingIoAction, SerialConsoleState, SyscallMsrs, VmState,
    VmStateBox, VmStateError, DEFAULT_TSC_FREQUENCY, FEEDBACK_BUFFER_ID_MAX_LEN,
    FEEDBACK_BUFFER_MAX_PAGES, IO_CHANNEL_BUF_SIZE, PENDING_IO_QUEUE_CAP, SERIAL_CONSOLE_PAGE_SIZE,
};

// =============================================================================
// Kernel VM file handles
// =============================================================================
#[cfg(not(feature = "cargo"))]
pub(crate) use crate::vm_file::ParentVmArc;

// =============================================================================
// Timing utilities
// =============================================================================
#[cfg(not(feature = "cargo"))]
pub use super::timing::rdtsc;
#[cfg(feature = "cargo")]
pub use crate::timing::rdtsc;

// =============================================================================
// Platform compatibility (allocation helpers)
// =============================================================================
#[cfg(not(feature = "cargo"))]
pub use super::compat::{
    heap_box, heap_box_copy_from, heap_box_try, heap_vec_push, heap_vec_remove_front,
    heap_vec_with_capacity, AllocError, HeapBox, HeapVec, VmallocBox,
};
#[cfg(feature = "cargo")]
pub use crate::compat::{
    heap_box, heap_box_copy_from, heap_box_try, heap_vec_push, heap_vec_remove_front,
    heap_vec_with_capacity, AllocError, HeapBox, HeapVec, VmallocBox,
};
