// SPDX-License-Identifier: GPL-2.0

//! VM exit information returned from the RUN ioctl.

use super::Vm;

/// Categorized VM exit types for cleaner pattern matching.
///
/// This enum provides a higher-level categorization of VM exits,
/// making it easier to handle exits in a `match` expression.
///
/// # Example
///
/// ```ignore
/// use bedrock_vm::{Vm, ExitKind};
///
/// let exit = vm.run()?;
/// if exit.serial_len > 0 {
///     print!("{}", exit.serial_output(&vm));
/// }
/// match exit.kind() {
///     ExitKind::VmcallShutdown => println!("Clean shutdown"),
///     ExitKind::Continue | ExitKind::LogBufferFull => continue,
///     kind => println!("Unexpected exit: {:?}", kind),
/// }
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitKind {
    /// VMCALL shutdown hypercall.
    VmcallShutdown,
    /// VMCALL snapshot hypercall.
    VmcallSnapshot {
        /// Snapshot tag from guest.
        tag: u64,
    },
    /// VMCALL ready hypercall — guest signaled it has finished its
    /// boot/initialization and is ready for the host's workload.
    VmcallReady,
    /// Stop-at-TSC threshold reached.
    StopTscReached,
    /// VMCALL feedback buffer registration hypercall.
    FeedbackBufferRegistered,
    /// I/O channel response delivered by the guest.
    ///
    /// The guest's `bedrock-io.ko` workqueue has finished executing an
    /// action and written the response into the registered shared page.
    /// The hypervisor has copied the response bytes into VmState; userspace
    /// should call `Vm::drain_io_response()` to consume them and optionally
    /// queue the next request via `Vm::queue_io_action()`.
    IoResponse,
    /// RDRAND instruction (ExitToUserspace mode).
    Rdrand,
    /// RDSEED instruction (ExitToUserspace mode).
    Rdseed,
    /// Log buffer is full - userspace must drain the log buffer.
    LogBufferFull,
    /// Continuable exit - userspace should call run() again.
    ///
    /// Includes: preemption timer, need_resched, MWAIT, MONITOR,
    /// I/O instruction (serial buffer full), pool exhausted.
    Continue,
    /// Unhandled VM exit (error condition).
    ///
    /// The hypervisor did not handle this exit. Use `VmExit::reason_str()`
    /// and the raw `VmExit` fields for diagnostics.
    UnhandledExit {
        /// Raw exit reason code.
        reason: u32,
    },
}

/// VM exit information returned from the RUN ioctl.
///
/// Serial output is accessed via mmap at offset = guest_memory_size.
/// Log buffer is accessed via mmap at offset = guest_memory_size + 4096.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct VmExit {
    /// Exit reason (corresponds to ExitReason enum in kernel).
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

impl VmExit {
    /// Get the exit reason as a string (for common reasons).
    pub fn reason_str(&self) -> &'static str {
        match self.exit_reason {
            0 => "EXCEPTION_NMI",
            1 => "EXTERNAL_INTERRUPT",
            2 => "TRIPLE_FAULT",
            10 => "CPUID",
            28 => "CR_ACCESS",
            30 => "IO_INSTRUCTION",
            31 => "MSR_READ",
            32 => "MSR_WRITE",
            33 => "INVALID_GUEST_STATE",
            36 => "MWAIT",
            39 => "MONITOR",
            48 => "EPT_VIOLATION",
            49 => "EPT_MISCONFIGURATION",
            52 => "VMX_PREEMPTION_TIMER",
            57 => "RDRAND",
            61 => "RDSEED",
            256 => "NEED_RESCHED",
            257 => "LOG_BUFFER_FULL",
            258 => "VMCALL_SHUTDOWN",
            259 => "STOP_TSC_REACHED",
            260 => "VMCALL_SNAPSHOT",
            261 => "VMCALL_FEEDBACK_BUFFER",
            262 => "POOL_EXHAUSTED",
            263 => "VMCALL_PEBS_PAGE",
            264 => "VMCALL_IO_REGISTER_PAGE",
            265 => "VMCALL_IO_RESPONSE",
            266 => "VMCALL_READY",
            _ => "UNKNOWN",
        }
    }

    /// Get the categorized exit kind for pattern matching.
    pub fn kind(&self) -> ExitKind {
        match self.exit_reason {
            258 => ExitKind::VmcallShutdown,
            260 => ExitKind::VmcallSnapshot {
                tag: self.exit_qualification,
            },
            259 => ExitKind::StopTscReached,
            261 => ExitKind::FeedbackBufferRegistered,
            265 => ExitKind::IoResponse,
            266 => ExitKind::VmcallReady,
            57 => ExitKind::Rdrand,
            61 => ExitKind::Rdseed,
            257 => ExitKind::LogBufferFull,
            // Continuable: preemption timer, need_resched, mwait, monitor,
            // I/O instruction, pool exhausted, PEBS scratch-page registration,
            // I/O channel page registration (no userspace action needed —
            // bookkeeping is entirely between the guest and the kernel
            // module).
            52 | 256 | 36 | 39 | 30 | 262 | 263 | 264 => ExitKind::Continue,
            reason => ExitKind::UnhandledExit { reason },
        }
    }

    /// Check if this exit should be followed by another run() call.
    ///
    /// Returns true for exits that are handled internally and don't require
    /// userspace intervention beyond draining the serial buffer.
    pub fn is_continue(&self) -> bool {
        matches!(self.kind(), ExitKind::Continue | ExitKind::LogBufferFull)
    }

    /// Get the serial output for this exit from the given VM.
    ///
    /// This is a convenience method that extracts the serial output string
    /// from the VM using the serial_len from this exit.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let exit = vm.run()?;
    /// if exit.serial_len > 0 {
    ///     println!("Output: {}", exit.serial_output(&vm));
    /// }
    /// ```
    pub fn serial_output<'a>(&self, vm: &'a Vm) -> &'a str {
        vm.serial_output_str(self.serial_len as usize)
    }
}
