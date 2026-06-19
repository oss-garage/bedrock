// SPDX-License-Identifier: GPL-2.0

//! Helper functions and error types for exit handling.

use super::qualifications::InterruptionInfo;
use super::reasons::{ExitReason, UnknownExitReason};

#[cfg(not(feature = "cargo"))]
use super::super::prelude::*;
#[cfg(feature = "cargo")]
use crate::prelude::*;

/// Error type for exit handling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitError {
    /// Failed to read VMCS field.
    VmcsReadError(VmcsReadError),
    /// Failed to write VMCS field.
    VmcsWriteError(VmcsWriteError),
    /// Unknown exit reason.
    UnknownExitReason(u32),
    /// Triple fault - unrecoverable.
    TripleFault,
    /// Invalid guest state.
    InvalidGuestState,
    /// Fatal error during exit handling.
    Fatal(&'static str),
}

impl From<VmcsReadError> for ExitError {
    fn from(e: VmcsReadError) -> Self {
        Self::VmcsReadError(e)
    }
}

impl From<VmcsWriteError> for ExitError {
    fn from(e: VmcsWriteError) -> Self {
        Self::VmcsWriteError(e)
    }
}

impl From<UnknownExitReason> for ExitError {
    fn from(e: UnknownExitReason) -> Self {
        Self::UnknownExitReason(e.0)
    }
}

/// Result of handling a VM exit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitHandlerResult {
    /// Continue guest execution (exit was fully handled), without exiting to userspace. This
    /// should be the most common case.
    Continue,
    /// Exit to userspace with the given reason.
    ExitToUserspace(ExitReason),
    /// Fatal error - cannot continue.
    Error(ExitError),
}

/// Read the VM exit reason from VMCS.
pub fn read_exit_reason<C: VmContext>(ctx: &C) -> Result<ExitReason, ExitError> {
    let raw = ctx.state().vmcs.read32(VmcsField32::VmExitReason)?;
    Ok(ExitReason::try_from(raw)?)
}

/// Read the exit qualification from VMCS.
pub fn read_exit_qualification<C: VmContext>(ctx: &C) -> Result<u64, ExitError> {
    Ok(ctx
        .state()
        .vmcs
        .read_natural(VmcsFieldNatural::ExitQualification)?)
}

/// Read guest RIP from VMCS.
pub fn read_guest_rip<C: VmContext>(ctx: &C) -> Result<u64, ExitError> {
    Ok(ctx.state().vmcs.read_natural(VmcsFieldNatural::GuestRip)?)
}

/// Read instruction length from VMCS.
pub fn read_instruction_len<C: VmContext>(ctx: &C) -> Result<u32, ExitError> {
    Ok(ctx.state().vmcs.read32(VmcsField32::VmExitInstructionLen)?)
}

/// Advance guest RIP by the instruction length.
pub fn advance_rip<C: VmContext>(ctx: &mut C) -> Result<(), ExitError> {
    let rip = read_guest_rip(ctx)?;
    let len = read_instruction_len(ctx)?;
    ctx.state()
        .vmcs
        .write_natural(VmcsFieldNatural::GuestRip, rip + u64::from(len))
        .map_err(|_| ExitError::Fatal("Failed to write guest RIP"))?;
    Ok(())
}

/// Record one controlled-randomness value on the unified event stream.
///
/// The single emit path shared by RDRAND/RDSEED (`source` carries the value
/// inline in the [`RandomPayload`], `bytes` empty) and `HYPERCALL_GET_RANDOM`
/// (`source = GetRandom`, the served buffer in `bytes` trailing the header). One
/// [`EventKind::Randomness`] record, source-labelled — there is no separate
/// event kind per randomness channel.
///
/// A full event buffer is handled centrally by the exit dispatcher, so the
/// append result is ignored (as elsewhere for randomness records).
pub fn emit_randomness_event<C: VmContext>(ctx: &mut C, payload: &RandomPayload, bytes: &[u8]) {
    let header = payload.as_bytes();
    let n = bytes.len().min(RANDOM_REPLY_MAX);
    let mut buf = [0u8; core::mem::size_of::<RandomPayload>() + RANDOM_REPLY_MAX];
    buf[..header.len()].copy_from_slice(header);
    buf[header.len()..header.len() + n].copy_from_slice(&bytes[..n]);
    let _ = ctx
        .state_mut()
        .event_append(EventKind::Randomness, &buf[..header.len() + n]);
}

/// Inject an exception into the guest.
pub fn inject_exception<C: VmContext>(
    ctx: &mut C,
    info: InterruptionInfo,
    error_code: Option<u32>,
) -> Result<(), ExitError> {
    ctx.state()
        .vmcs
        .write32(VmcsField32::VmEntryInterruptionInfo, info.encode())
        .map_err(|_| ExitError::Fatal("Failed to write interruption info"))?;

    if let Some(ec) = error_code {
        ctx.state()
            .vmcs
            .write32(VmcsField32::VmEntryExceptionErrorCode, ec)
            .map_err(|_| ExitError::Fatal("Failed to write error code"))?;
    }
    Ok(())
}
