#[cfg(not(feature = "cargo"))]
use super::super::prelude::*;
#[cfg(feature = "cargo")]
use crate::prelude::*;

use super::instruction_counter::InstructionCounterError;

/// Error returned during VMX initialization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmxInitError {
    /// VMX is not supported on this CPU.
    Unsupported,
    /// Failed to read VMX basic info MSR.
    FailedToReadBasicInfo(MsrError),
    /// Failed to enable VMX operation.
    FailedToEnableCPU { core: usize, error: VmxCpuInitError },
    /// Failed to allocate memory.
    MemoryAllocationFailed,
}

/// Error returned during VMX feature control configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmxConfigureFeatureControlError {
    /// The IA32_FEATURE_CONTROL MSR is locked and VMX is not enabled.
    Locked,
    MsrReadFailed(MsrError),
    MsrWriteFailed(MsrError),
}

/// Error returned by VMXON instruction.
///
/// VMXON signals errors via RFLAGS (CF and ZF):
/// - CF=1, ZF=0 (VMfailInvalid): Invalid VMXON pointer
/// - CF=0, ZF=1 (VMfailValid): Already in VMX operation
///
/// See Intel SDM Vol 3C, Section 32.2 and "VMXON—Enter VMX Operation".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmxonError {
    /// VMfailInvalid: The VMXON pointer is invalid (CF=1).
    /// Possible causes:
    /// - Address not 4KB aligned
    /// - Address sets bits beyond physical-address width
    /// - VMCS revision identifier mismatch
    /// - Bit 31 of revision identifier is set
    InvalidPointer,

    /// VMfailValid (error 15): VMXON executed in VMX root operation (ZF=1).
    /// The processor is already in VMX root operation.
    AlreadyInVmxOperation,
}

/// Error returned by VMXOFF instruction.
///
/// VMXOFF signals errors via RFLAGS (CF and ZF):
/// - CF=0, ZF=1 (VMfailValid): Cannot leave VMX under dual-monitor treatment
///
/// See Intel SDM Vol 3C, Section 32.2 and "VMXOFF—Leave VMX Operation".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmxoffError {
    /// VMfailValid (error 23): VMXOFF under dual-monitor treatment of SMIs and SMM (ZF=1).
    /// Cannot leave VMX operation while dual-monitor treatment is active.
    DualMonitorTreatmentActive,
}

/// Error returned by INVEPT instruction.
///
/// INVEPT signals errors via RFLAGS (CF and ZF):
/// - CF=1, ZF=0 (VMfailInvalid): Invalid operand
/// - CF=0, ZF=1 (VMfailValid): Operation failed
///
/// See Intel SDM Vol 3C, "INVEPT—Invalidate Translations Derived from EPT".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InveptError {
    /// VMfailInvalid: Invalid operand (CF=1).
    /// Possible causes:
    /// - Not in VMX operation
    /// - Invalid INVEPT type in register operand
    InvalidOperand,
    /// VMfailValid: Operation failed (ZF=1).
    /// The INVEPT type is not supported.
    NotSupported,
}

/// Error from the INVVPID instruction.
///
/// See Intel SDM Vol 3C, "INVVPID—Invalidate Translations Based on VPID".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvvpidError {
    /// VMfailInvalid: Invalid operand (CF=1).
    /// Possible causes:
    /// - Not in VMX operation
    /// - Invalid INVVPID type in register operand
    InvalidOperand,
    /// VMfailValid: Operation failed (ZF=1).
    /// The INVVPID type is not supported.
    NotSupported,
}

/// Error returned during VMXON region allocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmxonAllocError {
    /// Failed to allocate memory for the VMXON region.
    MemoryAllocationFailed,
    /// VMXON instruction failed.
    VmxonFailed(VmxonError),
}

/// Error returned during VmxCpu initialization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmxCpuInitError {
    /// Failed to configure feature control MSR.
    FeatureControlConfigFailed(VmxConfigureFeatureControlError),
    /// Failed to enable VMX via CR4.
    FailedToEnableVMX(CrError),
    /// Failed to allocate VMXON region.
    VmxonAllocFailed(VmxonAllocError),
}

/// Error returned by VMREAD instruction.
///
/// VMREAD signals errors via RFLAGS (Carry and Zero flags):
/// - CF=1, ZF=0 (VMfailInvalid): No valid VMCS pointer
/// - CF=0, ZF=1 (VMfailValid): Valid VMCS but operation failed, error number in VM-instruction error field
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmcsReadError {
    /// VMfailInvalid: The current-VMCS pointer is not valid (CF=1).
    /// No VMCS is loaded, so the operation cannot proceed.
    VmcsNotLoaded,
    /// VMfailValid with error 12: The VMCS field encoding is not recognized (ZF=1).
    /// The source operand does not correspond to any VMCS field.
    InvalidField,
}

pub type VmcsReadResult<T> = Result<T, VmcsReadError>;

/// Error returned by VMWRITE instruction.
///
/// VMWRITE signals errors via RFLAGS (Carry and Zero flags):
/// - CF=1, ZF=0 (VMfailInvalid): No valid VMCS pointer
/// - CF=0, ZF=1 (VMfailValid): Valid VMCS but operation failed, error number in VM-instruction error field
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmcsWriteError {
    /// VMfailInvalid: The current-VMCS pointer is not valid (CF=1).
    /// No VMCS is loaded, so the operation cannot proceed.
    VmcsNotLoaded,
    /// VMfailValid with error 12: The VMCS field encoding is not recognized (ZF=1).
    /// The secondary source operand does not correspond to any VMCS field.
    InvalidField,
    /// VMfailValid with error 13: Attempt to write to a read-only VMCS component (ZF=1).
    /// VM-exit information fields are read-only (unless IA32_VMX_MISC indicates otherwise).
    ReadOnlyField,
}

pub type VmcsWriteResult = Result<(), VmcsWriteError>;

/// Error returned during VMCS creation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmcsAllocError {
    /// Failed to allocate memory for the VMCS.
    MemoryAllocationFailed,
}

/// Error returned during VMCS setup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmcsSetupError {
    Clear(&'static str),
    Guard(&'static str),
    HostState(VmcsWriteError),
    Controls(VmcsWriteError),
    EptPointer(VmcsWriteError),
}

/// Error type for memory access operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryError {
    /// Address out of range.
    OutOfRange,
    /// Memory not mapped.
    NotMapped,
    /// Permission denied.
    PermissionDenied,
}

/// Error returned during register setting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmSetRegistersError {
    VmcsGuard(&'static str),
    VmcsWrite(VmcsWriteError),
}

/// Error returned during register getting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmGetRegistersError {
    VmcsGuard(&'static str),
    VmcsRead(VmcsReadError),
}

/// Error from VM run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmRunError {
    /// Failed to prepare or restore the guest instruction counter.
    InstructionCounter(InstructionCounterError),
    /// VM entry failed (VMLAUNCH/VMRESUME error).
    VmEntry(VmEntryError),
    /// Exit handler encountered a fatal error.
    ExitHandler(ExitError),
    /// VMCS load/clear error.
    VmcsLoad(&'static str),
    /// VMCS clear error.
    VmcsClear(&'static str),
    /// Failed to write host RSP to VMCS.
    WriteHostRsp(VmcsWriteError),
    /// Failed to read host CR3.
    ReadHostCr3,
    /// Failed to write host CR3 to VMCS.
    WriteHostCr3(VmcsWriteError),
    /// Failed to write host FS base to VMCS.
    WriteHostFsBase(VmcsWriteError),
    /// Failed to write host GS base to VMCS.
    WriteHostGsBase(VmcsWriteError),
    /// Failed to write host TR base to VMCS.
    WriteHostTrBase(VmcsWriteError),
    /// Failed to write host GDTR base to VMCS.
    WriteHostGdtrBase(VmcsWriteError),
    /// INVEPT failed when invalidating stale EPT TLB entries on cross-CPU
    /// migration into the run loop.
    InveptFailed(InveptError),
}
