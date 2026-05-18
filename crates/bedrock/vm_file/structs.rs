// SPDX-License-Identifier: GPL-2.0

//! User ABI structures and ioctl definitions for VM file descriptors.
//!
//! This module defines the data structures passed between userspace and kernel
//! via ioctl commands, as well as the ioctl command numbers.

use core::mem::MaybeUninit;

use kernel::bindings;
use kernel::ioctl::{_IOR, _IOW};

use super::super::vmx::registers::{
    ControlRegisters, DebugRegisters, DescriptorTableRegisters, ExtendedControlRegisters,
    GeneralPurposeRegisters, SegmentRegisters,
};

/// Ioctl magic number for bedrock ('B' for Bedrock).
pub(crate) const BEDROCK_IOC_MAGIC: u32 = b'B' as u32;

/// Ioctl number for GET_REGS command - read all VM registers.
pub(crate) const BEDROCK_VM_GET_REGS: u32 = _IOR::<BedrockRegs>(BEDROCK_IOC_MAGIC, 1);

/// Ioctl number for SET_REGS command - write all VM registers.
pub(crate) const BEDROCK_VM_SET_REGS: u32 = _IOW::<BedrockRegs>(BEDROCK_IOC_MAGIC, 2);

/// Ioctl number for RUN command - run the VM until exit.
pub(crate) const BEDROCK_VM_RUN: u32 = _IOR::<BedrockVmExit>(BEDROCK_IOC_MAGIC, 3);

/// Ioctl number for SET_INPUT command - set serial input buffer.
pub(crate) const BEDROCK_VM_SET_INPUT: u32 = _IOW::<BedrockSerialInput>(BEDROCK_IOC_MAGIC, 4);

/// Ioctl number for SET_RDRAND_CONFIG command - configure RDRAND emulation.
pub(crate) const BEDROCK_VM_SET_RDRAND_CONFIG: u32 =
    _IOW::<BedrockRdrandConfig>(BEDROCK_IOC_MAGIC, 5);

/// Ioctl number for SET_RDRAND_VALUE command - set pending RDRAND value.
pub(crate) const BEDROCK_VM_SET_RDRAND_VALUE: u32 = _IOW::<u64>(BEDROCK_IOC_MAGIC, 6);

/// Ioctl number for SET_LOG_CONFIG command - unified logging configuration.
/// Replaces ENABLE_LOGGING, DISABLE_LOGGING, SET_LOG_MODE, SET_LOG_THRESHOLD, SET_LOG_START_TSC.
pub(crate) const BEDROCK_VM_SET_LOG_CONFIG: u32 = _IOW::<BedrockLogConfig>(BEDROCK_IOC_MAGIC, 7);

/// Ioctl number for SET_SINGLE_STEP command - configure MTF single-stepping.
pub(crate) const BEDROCK_VM_SET_SINGLE_STEP: u32 =
    _IOW::<BedrockSingleStepConfig>(BEDROCK_IOC_MAGIC, 8);

/// Ioctl number for GET_EXIT_STATS command - retrieve exit handler performance statistics.
pub(crate) const BEDROCK_VM_GET_EXIT_STATS: u32 = _IOR::<BedrockExitStats>(BEDROCK_IOC_MAGIC, 9);

/// Ioctl number for SET_STOP_TSC command - stop VM when TSC reaches this value.
pub(crate) const BEDROCK_VM_SET_STOP_TSC: u32 = _IOW::<u64>(BEDROCK_IOC_MAGIC, 10);

/// Ioctl number for GET_VM_ID command - get the VM's unique identifier.
pub(crate) const BEDROCK_VM_GET_VM_ID: u32 = _IOR::<u64>(BEDROCK_IOC_MAGIC, 11);

/// Ioctl number for GET_FEEDBACK_BUFFER_INFO command - get feedback buffer registration info.
/// Takes BedrockFeedbackBufferInfoRequest with index, returns BedrockFeedbackBufferInfo.
pub(crate) const BEDROCK_VM_GET_FEEDBACK_BUFFER_INFO: u32 =
    _IOR::<BedrockFeedbackBufferInfoRequest>(BEDROCK_IOC_MAGIC, 12);

/// Ioctl number for QUEUE_IO_ACTION command - queue an I/O channel request.
pub(crate) const BEDROCK_VM_QUEUE_IO_ACTION: u32 =
    _IOW::<BedrockIoActionPayload>(BEDROCK_IOC_MAGIC, 13);

/// Ioctl number for DRAIN_IO_RESPONSE command - drain the most recent I/O channel response.
pub(crate) const BEDROCK_VM_DRAIN_IO_RESPONSE: u32 =
    _IOR::<BedrockIoActionPayload>(BEDROCK_IOC_MAGIC, 14);

/// Maximum I/O channel payload size (one 4KB page).
pub(crate) const BEDROCK_IO_CHANNEL_BUF_SIZE: usize = 4096;

/// Header fields of an I/O channel ioctl payload. The full payload is this
/// header followed by `BEDROCK_IO_CHANNEL_BUF_SIZE` bytes of data;
/// handlers stage the header through the stack (16 bytes) and copy the
/// payload directly into / out of VmState to avoid a 4KB stack burst.
#[repr(C)]
pub(crate) struct BedrockIoActionHeader {
    /// For QUEUE: number of valid bytes in the payload.
    /// For DRAIN: on input, capacity available in the user buffer; on output,
    /// the number of bytes the kernel wrote.
    pub len: u32,
    /// Reserved for alignment.
    pub _reserved: u32,
    /// Earliest emulated-TSC value at which the queued request may fire
    /// (QUEUE only; ignored by DRAIN). Zero means "fire as soon as the
    /// guest is interruptible". When non-zero, the hypervisor arms PEBS
    /// so the IRQ lands at the precise instruction count corresponding to
    /// this TSC.
    pub target_tsc: u64,
}

/// I/O channel ioctl payload (header + data buffer).
///
/// Stored as a single contiguous struct so the userspace ABI is
/// self-contained. Never instantiated on the kernel stack — the handlers
/// only read/write the header eagerly and use partial copies for the data
/// section.
#[repr(C)]
pub(crate) struct BedrockIoActionPayload {
    pub header: BedrockIoActionHeader,
    pub data: [u8; BEDROCK_IO_CHANNEL_BUF_SIZE],
}

/// Request structure for GET_FEEDBACK_BUFFER_INFO ioctl.
///
/// Userspace passes this structure to specify which feedback buffer index to query.
#[repr(C)]
pub(crate) struct BedrockFeedbackBufferInfoRequest {
    /// Buffer index to query (0-15).
    pub index: u32,
    /// Reserved for alignment.
    pub _reserved: u32,
}

/// Feedback buffer info returned to userspace.
///
/// This structure tells userspace about a feedback buffer registered by the guest
/// via the HYPERCALL_REGISTER_FEEDBACK_BUFFER hypercall.
#[repr(C)]
pub(crate) struct BedrockFeedbackBufferInfo {
    /// Original guest virtual address.
    pub gva: u64,
    /// Size in bytes.
    pub size: u64,
    /// Number of pages.
    pub num_pages: u64,
    /// Whether a feedback buffer is registered (0 = no, 1 = yes).
    pub registered: u32,
    /// Buffer index (0-15).
    pub index: u32,
    /// Reserved for alignment.
    pub _reserved: u32,
}

/// Maximum size of serial input buffer.
pub(crate) const SERIAL_INPUT_MAX_SIZE: usize = 256;

/// Serial input buffer passed from userspace via ioctl.
#[repr(C)]
pub(crate) struct BedrockSerialInput {
    /// Length of valid data in buf.
    pub len: u32,
    /// Reserved for alignment.
    pub _reserved: u32,
    /// Input data buffer.
    pub buf: [u8; SERIAL_INPUT_MAX_SIZE],
}

/// RDRAND emulation configuration passed from userspace.
#[repr(C)]
pub(crate) struct BedrockRdrandConfig {
    /// Mode: 0 = SeededRng, 1 = ExitToUserspace.
    pub mode: u32,
    /// Reserved for alignment.
    pub _reserved: u32,
    /// Value: seed for mode 0, unused for mode 1.
    pub value: u64,
}

/// Single-step (MTF) configuration passed from userspace.
#[repr(C)]
pub(crate) struct BedrockSingleStepConfig {
    /// Whether single-stepping is enabled (0 = disabled, non-zero = enabled).
    pub enabled: u64,
    /// Start of TSC range (inclusive).
    pub tsc_start: u64,
    /// End of TSC range (exclusive).
    pub tsc_end: u64,
}

/// Unified logging configuration passed from userspace.
///
/// This struct combines all logging-related settings into a single ioctl:
/// - Buffer allocation (enabled)
/// - Logging mode (mode)
/// - Mode-specific target (target_tsc)
/// - Universal start threshold (start_tsc)
/// - Flags bitfield for optional behavior
#[repr(C)]
pub(crate) struct BedrockLogConfig {
    /// Whether logging is enabled. When transitioning from disabled to enabled,
    /// allocates the log buffer. When transitioning from enabled to disabled,
    /// frees the buffer.
    pub enabled: u32,
    /// Mode: 0 = Disabled, 1 = AllExits, 2 = AtTsc, 3 = AtShutdown, 4 = Checkpoints, 5 = TscRange.
    pub mode: u32,
    /// Target TSC value (threshold for AllExits, trigger for AtTsc, interval for Checkpoints).
    pub target_tsc: u64,
    /// Universal start threshold - no logging occurs until TSC reaches this value.
    /// Set to 0 to log from the start.
    pub start_tsc: u64,
    /// Flags bitfield. Bit 0: skip memory hashing (LOG_FLAG_NO_MEMORY_HASH).
    /// Bit 1: intercept guest #PF (LOG_FLAG_INTERCEPT_PF).
    pub flags: u32,
    /// Reserved for alignment.
    pub _reserved: u32,
}

/// Per-exit-type statistics for userspace.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(crate) struct BedrockExitStatEntry {
    /// Number of exits of this type.
    pub count: u64,
    /// Total CPU cycles spent handling this exit type.
    pub cycles: u64,
}

/// Exit handler performance statistics passed to userspace.
///
/// This struct mirrors AllExitStats from bedrock-vmx for ABI compatibility.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(crate) struct BedrockExitStats {
    /// CPUID instruction exits.
    pub cpuid: BedrockExitStatEntry,
    /// MSR read (RDMSR) exits.
    pub msr_read: BedrockExitStatEntry,
    /// MSR write (WRMSR) exits.
    pub msr_write: BedrockExitStatEntry,
    /// Control register access exits.
    pub cr_access: BedrockExitStatEntry,
    /// I/O instruction exits.
    pub io_instruction: BedrockExitStatEntry,
    /// EPT violation exits.
    pub ept_violation: BedrockExitStatEntry,
    /// External interrupt exits.
    pub external_interrupt: BedrockExitStatEntry,
    /// RDTSC instruction exits.
    pub rdtsc: BedrockExitStatEntry,
    /// RDTSCP instruction exits.
    pub rdtscp: BedrockExitStatEntry,
    /// RDPMC instruction exits.
    pub rdpmc: BedrockExitStatEntry,
    /// MWAIT instruction exits.
    pub mwait: BedrockExitStatEntry,
    /// VMCALL hypercall exits.
    pub vmcall: BedrockExitStatEntry,
    /// APIC access exits.
    pub apic_access: BedrockExitStatEntry,
    /// Monitor trap flag (MTF) exits.
    pub mtf: BedrockExitStatEntry,
    /// XSETBV instruction exits.
    pub xsetbv: BedrockExitStatEntry,
    /// RDRAND instruction exits.
    pub rdrand: BedrockExitStatEntry,
    /// RDSEED instruction exits.
    pub rdseed: BedrockExitStatEntry,
    /// Exception/NMI exits.
    pub exception_nmi: BedrockExitStatEntry,
    /// All other exit types combined.
    pub other: BedrockExitStatEntry,
    /// Total cycles in VM run loop (including guest time).
    pub total_run_cycles: u64,
    /// Total cycles in guest mode.
    pub guest_cycles: u64,
    /// Cycles spent in run loop setup before VM entry.
    pub vmentry_overhead_cycles: u64,
    /// Cycles spent after VM exit before exit handler (excluding IRQ window).
    pub vmexit_overhead_cycles: u64,
    /// Cycles spent in the IRQ window between VM exits.
    pub irq_window_cycles: u64,
    /// PEBS arm returned BelowMinDelta.
    pub pebs_arm_below_min_delta: u64,
    /// PEBS arm returned AlreadyPast.
    pub pebs_arm_already_past: u64,
    /// Iters that VM-entered with PEBS armed but didn't fire.
    pub pebs_armed_iter_no_fire: u64,
    /// Timer fires where emulated_tsc > deadline (silent-PEBS late path).
    pub apic_timer_late_inject: u64,
}

/// VM exit information returned to userspace from RUN ioctl.
///
/// Serial output is accessed via mmap at offset = guest_memory_size.
/// Log buffer is accessed via mmap at offset = guest_memory_size + 4096.
#[repr(C)]
pub(crate) struct BedrockVmExit {
    /// Exit reason (ExitReason as u32).
    pub exit_reason: u32,
    /// Number of valid bytes in the serial buffer (mmap'd separately).
    pub serial_len: u32,
    /// Exit qualification (interpretation depends on exit reason).
    pub exit_qualification: u64,
    /// Guest physical address (for EPT violations).
    pub guest_physical_addr: u64,
    /// Number of log entries in the log buffer (if logging enabled).
    pub log_entry_count: u32,
    /// Reserved for alignment.
    pub _reserved: u32,
    /// Current emulated TSC value.
    pub emulated_tsc: u64,
    /// TSC frequency in Hz.
    pub tsc_frequency: u64,
}

/// Complete VM register state for userspace transfer.
///
/// This struct combines all register types needed to fully describe guest state.
/// All component structs are `#[repr(C)]` making this safe for userspace transfer.
#[repr(C)]
pub(crate) struct BedrockRegs {
    /// General-purpose registers (RAX, RCX, ..., R15).
    pub gprs: GeneralPurposeRegisters,
    /// Control registers (CR0, CR2, CR3, CR4, CR8).
    pub control_regs: ControlRegisters,
    /// Debug registers (DR0-DR3, DR6, DR7).
    pub debug_regs: DebugRegisters,
    /// Segment registers (CS, DS, ES, FS, GS, SS, TR, LDTR).
    pub segment_regs: SegmentRegisters,
    /// Descriptor table registers (GDTR, IDTR).
    pub descriptor_tables: DescriptorTableRegisters,
    /// Extended control registers (EFER).
    pub extended_control: ExtendedControlRegisters,
    /// Instruction pointer.
    pub rip: u64,
    /// Flags register.
    pub rflags: u64,
}

/// Wrapper around file_operations to implement Sync.
///
/// The file_operations struct only contains function pointers and
/// a module owner pointer. The function pointers are safe to share between
/// threads, and the owner is null (set by kernel).
pub(crate) struct SyncFileOps(pub bindings::file_operations);

// SAFETY: file_operations with null owner and only function pointers is safe
// to share between threads.
unsafe impl Sync for SyncFileOps {}

impl SyncFileOps {
    /// Create a new zeroed file_operations struct.
    ///
    /// # Safety
    ///
    /// All zeros is valid for file_operations. Caller must set the required
    /// function pointers before use.
    pub(crate) const unsafe fn zeroed() -> bindings::file_operations {
        // SAFETY: Caller promises all zeros is valid for file_operations
        unsafe { MaybeUninit::zeroed().assume_init() }
    }
}
