// SPDX-License-Identifier: GPL-2.0

//! VM exit information returned from the RUN ioctl.

/// Categorized VM exit types.
///
/// # Example
///
/// ```ignore
/// use bedrock_vm::{Vm, ExitKind};
///
/// let exit = vm.run()?;
/// match exit.kind() {
///     ExitKind::VmcallShutdown => println!("Clean shutdown"),
///     ExitKind::Continue | ExitKind::EventBufferFull => continue,
///     kind => println!("Unexpected exit: {:?}", kind),
/// }
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitKind {
    VmcallShutdown,
    VmcallSnapshot {
        tag: u64,
    },
    /// Guest finished booting and is ready for the host's workload.
    VmcallReady,
    StopTscReached,
    FeedbackBufferRegistered,
    /// I/O channel response ready; consume it with `Vm::drain_io_response()`.
    IoResponse,
    /// RDRAND instruction (ExitToUserspace mode).
    Rdrand,
    /// RDSEED instruction (ExitToUserspace mode).
    Rdseed,
    /// `HYPERCALL_GET_RANDOM` in ExitToUserspace mode: read the request with
    /// `Vm::random_request()`, reply with `Vm::set_random_bytes()`, run again.
    VmcallGetRandom,
    /// Drain the event buffer, then run again.
    EventBufferFull,
    /// `HYPERCALL_FILE_FETCH`: serve the next chunk with
    /// [`crate::file_xfer::FileServer`], then run again.
    FileFetch,
    /// Handled internally; just run again.
    Continue,
    /// The hypervisor did not handle this exit.
    UnhandledExit {
        reason: u32,
    },
    /// Guest sent the next chunk of a guest file (`HYPERCALL_FILE_STORE`).
    FileStore,
    /// Guest harness requested the next fuzzer input (`HYPERCALL_FUZZ_NEXT_INPUT`).
    ///
    /// The host should write the next testcase into the guest's registered
    /// `fuzz-input` feedback buffer — see [`crate::fuzz_input::InputServer`]
    /// — and call `run()` again. A snapshot fuzzer takes its `Checkpoint` at
    /// this exit and forks one branch per testcase.
    FuzzNextInput,
}

/// VM exit information returned from the RUN ioctl.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct VmExit {
    /// Kernel `ExitReason`.
    pub exit_reason: u32,
    pub _reserved: u32,
    pub exit_qualification: u64,
    /// For EPT violations.
    pub guest_physical_addr: u64,
    /// Valid bytes in `event_buffer()` for this run.
    pub event_len: u32,
    pub _pad: u32,
    pub emulated_tsc: u64,
    pub tsc_frequency: u64,
}

impl VmExit {
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
            258 => "VMCALL_SHUTDOWN",
            259 => "STOP_TSC_REACHED",
            260 => "VMCALL_SNAPSHOT",
            261 => "VMCALL_FEEDBACK_BUFFER",
            262 => "POOL_EXHAUSTED",
            263 => "VMCALL_PEBS_PAGE",
            264 => "VMCALL_IO_REGISTER_PAGE",
            265 => "VMCALL_IO_RESPONSE",
            266 => "VMCALL_READY",
            267 => "EVENT_BUFFER_FULL",
            268 => "VMCALL_FILE_FETCH",
            269 => "VMCALL_GET_RANDOM",
            270 => "VMCALL_FILE_STORE",
            271 => "VMCALL_FUZZ_NEXT_INPUT",
            _ => "UNKNOWN",
        }
    }

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
            267 => ExitKind::EventBufferFull,
            268 => ExitKind::FileFetch,
            269 => ExitKind::VmcallGetRandom,
            270 => ExitKind::FileStore,
            271 => ExitKind::FuzzNextInput,
            // Preemption timer, need_resched, mwait, monitor, I/O instruction,
            // pool exhausted, PEBS page and I/O page registration.
            52 | 256 | 36 | 39 | 30 | 262 | 263 | 264 => ExitKind::Continue,
            reason => ExitKind::UnhandledExit { reason },
        }
    }

    /// Whether to just run again (after draining events).
    pub fn is_continue(&self) -> bool {
        matches!(self.kind(), ExitKind::Continue | ExitKind::EventBufferFull)
    }
}
