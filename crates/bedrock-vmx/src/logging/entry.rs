// SPDX-License-Identifier: GPL-2.0

//! Log entry structures for deterministic VM exit logging.

/// Log buffer size: 1MB (256 pages).
pub const LOG_BUFFER_SIZE: usize = 1024 * 1024;

/// Number of pages in the log buffer.
pub const LOG_BUFFER_PAGES: usize = LOG_BUFFER_SIZE / 4096;

/// Size of a single log entry in bytes.
pub const LOG_ENTRY_SIZE: usize = 512;

/// Maximum number of log entries that fit in the buffer.
pub const MAX_LOG_ENTRIES: usize = LOG_BUFFER_SIZE / LOG_ENTRY_SIZE;

/// Flag bit: entry represents a deterministic exit.
pub const LOG_ENTRY_FLAG_DETERMINISTIC: u32 = 1;

/// A single log entry for VM exit logging.
///
/// Fixed at 512 bytes to allow ~2048 entries in a 1MB buffer.
/// All fields are aligned for efficient access.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct LogEntry {
    // Exit info (24 bytes)
    /// TSC value at time of exit (from emulated_tsc).
    pub tsc: u64,
    /// Exit reason (ExitReason as u32).
    pub exit_reason: u32,
    /// Flags bitfield. Bit 0 = deterministic exit.
    pub flags: u32,
    /// Exit qualification value.
    pub exit_qualification: u64,

    // Guest registers (144 bytes)
    /// RAX register.
    pub rax: u64,
    /// RCX register.
    pub rcx: u64,
    /// RDX register.
    pub rdx: u64,
    /// RBX register.
    pub rbx: u64,
    /// RSP register.
    pub rsp: u64,
    /// RBP register.
    pub rbp: u64,
    /// RSI register.
    pub rsi: u64,
    /// RDI register.
    pub rdi: u64,
    /// R8 register.
    pub r8: u64,
    /// R9 register.
    pub r9: u64,
    /// R10 register.
    pub r10: u64,
    /// R11 register.
    pub r11: u64,
    /// R12 register.
    pub r12: u64,
    /// R13 register.
    pub r13: u64,
    /// R14 register.
    pub r14: u64,
    /// R15 register.
    pub r15: u64,
    /// RIP (instruction pointer).
    pub rip: u64,
    /// RFLAGS register.
    pub rflags: u64,

    // Device state hashes (56 bytes)
    /// Hash of APIC state.
    pub apic_hash: u64,
    /// Hash of serial port state.
    pub serial_hash: u64,
    /// Hash of I/O APIC state.
    pub ioapic_hash: u64,
    /// Hash of RTC state.
    pub rtc_hash: u64,
    /// Hash of MTRR state.
    pub mtrr_hash: u64,
    /// Hash of RDRAND state.
    pub rdrand_hash: u64,
    /// Hash of guest memory.
    pub memory_hash: u64,

    // Additional guest state (80 bytes)
    /// FS base address from VMCS.
    pub fs_base: u64,
    /// GS base address from VMCS.
    pub gs_base: u64,
    /// Kernel GS base (IA32_KERNEL_GS_BASE MSR).
    pub kernel_gs_base: u64,
    /// CR3 (page table root) from VMCS.
    pub cr3: u64,
    /// CS base address from VMCS.
    pub cs_base: u64,
    /// DS base address from VMCS.
    pub ds_base: u64,
    /// ES base address from VMCS.
    pub es_base: u64,
    /// SS base address from VMCS.
    pub ss_base: u64,
    /// Pending debug exceptions from VMCS.
    pub pending_dbg_exceptions: u64,
    /// Guest interruptibility state from VMCS.
    pub interruptibility_state: u32,
    /// Number of COW pages at time of exit.
    pub cow_page_count: u32,

    /// Skid of a PEBS-induced EPT-violation exit, in TSC ticks
    /// (= retired guest instructions) past the PEBS firing target
    /// (`target_tsc - PEBS_MARGIN`). Non-zero only on EPT_VIOLATION_PEBS
    /// entries; zero everywhere else. With PDist this should usually be 0.
    pub pebs_skid: i64,
    /// Guest INST_RETIRED gain between the arming and the firing of this
    /// PEBS exit. Non-zero only on EPT_VIOLATION_PEBS entries.
    pub pebs_inst_delta: i64,
    /// Tsc_offset gain (HLT/MWAIT clamps) between arming and firing.
    /// Should be 0 for a well-behaved PEBS exit. Non-zero only on
    /// EPT_VIOLATION_PEBS entries.
    pub pebs_tsc_offset_delta: i64,
    /// Run-loop iterations the firing arming persisted across (0 if armed
    /// fresh in the firing iter, > 0 if stale across non-PEBS exits).
    /// Non-zero only on EPT_VIOLATION_PEBS entries.
    pub pebs_iters_since_arm: u32,
    /// PEBS firing target minus current TSC at arming time, in retired guest
    /// instructions. Lets
    /// post-mortem tooling correlate skid against arm delta.
    pub pebs_arm_delta: u64,

    // --- Determinism debugging fields (mirrored from bedrock-vm). ---
    /// `last_instruction_count` at exit time (fresh PMC0 read).
    pub last_instruction_count: u64,
    /// `apic.timer_deadline` at exit time. 0 if no timer pending.
    pub apic_timer_deadline: u64,
    /// `io_channel.request_target_tsc` at exit time.
    pub io_channel_target_tsc: u64,
    /// `pebs.armed_target_tsc` at exit time. 0 if PEBS not armed.
    pub pebs_armed_target_tsc: u64,
    /// Packed VMX state flags: bit 0 = mtf_enabled, bit 1 = last_exit_deterministic.
    pub vmx_state_flags: u64,

    /// Padding to reach 512 bytes.
    pub _padding: [u64; 16],
}

// Compile-time assertion that LogEntry is exactly LOG_ENTRY_SIZE bytes.
const _: () = assert!(core::mem::size_of::<LogEntry>() == LOG_ENTRY_SIZE);

impl LogEntry {
    /// Create a new empty log entry.
    pub const fn new() -> Self {
        Self {
            tsc: 0,
            exit_reason: 0,
            flags: 0,
            exit_qualification: 0,
            rax: 0,
            rcx: 0,
            rdx: 0,
            rbx: 0,
            rsp: 0,
            rbp: 0,
            rsi: 0,
            rdi: 0,
            r8: 0,
            r9: 0,
            r10: 0,
            r11: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
            rip: 0,
            rflags: 0,
            apic_hash: 0,
            serial_hash: 0,
            ioapic_hash: 0,
            rtc_hash: 0,
            mtrr_hash: 0,
            rdrand_hash: 0,
            memory_hash: 0,
            fs_base: 0,
            gs_base: 0,
            kernel_gs_base: 0,
            cr3: 0,
            cs_base: 0,
            ds_base: 0,
            es_base: 0,
            ss_base: 0,
            pending_dbg_exceptions: 0,
            interruptibility_state: 0,
            cow_page_count: 0,
            pebs_skid: 0,
            pebs_inst_delta: 0,
            pebs_tsc_offset_delta: 0,
            pebs_iters_since_arm: 0,
            pebs_arm_delta: 0,
            last_instruction_count: 0,
            apic_timer_deadline: 0,
            io_channel_target_tsc: 0,
            pebs_armed_target_tsc: 0,
            vmx_state_flags: 0,
            _padding: [0; 16],
        }
    }
}

#[cfg(test)]
#[path = "entry_tests.rs"]
mod tests;
