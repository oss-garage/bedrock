// SPDX-License-Identifier: GPL-2.0

//! Error types for `bedrock-lab`.

use std::fmt;

use bedrock_vm::ExitKind;

use crate::{BashTarget, VirtTime};

/// Errors returned by lab operations.
#[derive(Debug)]
pub enum LabError {
    /// The underlying VM operation failed.
    Vm(bedrock_vm::VmError),

    /// `run_until(t)` was called with `t` earlier than the branch's current
    /// time. To move backward, take a checkpoint and call
    /// [`Checkpoint::rewind`](crate::Checkpoint::rewind).
    TargetInPast { current: VirtTime, target: VirtTime },

    /// [`Checkpoint::rewind`](crate::Checkpoint::rewind) was called but no
    /// ancestor checkpoint exists at or before the target time.
    NoCheckpointBefore { target: VirtTime },

    /// Two times were combined with mismatched TSC frequencies.
    FrequencyMismatch { lhs: u64, rhs: u64 },

    /// A `bash` call saw an unexpected exit while waiting for the I/O channel
    /// response (e.g. the guest halted or shut down before replying).
    UnexpectedExit { at: VirtTime, kind: ExitKind },

    /// Queueing an I/O action supplied by an [`InputSource`](crate::InputSource)
    /// failed.
    QueueInputIo {
        at: VirtTime,
        target: BashTarget,
        command: String,
        source: std::io::Error,
    },

    /// The I/O channel returned bytes the lab couldn't decode.
    BadResponse(String),
}

impl fmt::Display for LabError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Vm(e) => write!(f, "vm error: {e}"),
            Self::TargetInPast { current, target } => write!(
                f,
                "run_until target {target:?} is before current time {current:?}; use Checkpoint::rewind to move backward"
            ),
            Self::NoCheckpointBefore { target } => write!(
                f,
                "no ancestor checkpoint at or before {target:?}"
            ),
            Self::FrequencyMismatch { lhs, rhs } => {
                write!(f, "TSC frequency mismatch: {lhs} vs {rhs}")
            }
            Self::UnexpectedExit { at, kind } => write!(
                f,
                "unexpected exit while waiting for I/O response at {at:?}: {kind:?}"
            ),
            Self::QueueInputIo {
                at,
                target,
                command,
                source,
            } => write!(
                f,
                "failed to queue InputSource I/O at {at:?} for {target:?} command {command:?}: {source}"
            ),
            Self::BadResponse(msg) => write!(f, "bad I/O channel response: {msg}"),
        }
    }
}

impl std::error::Error for LabError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::QueueInputIo { source, .. } => Some(source),
            Self::Vm(e) => Some(e),
            _ => None,
        }
    }
}

impl From<bedrock_vm::VmError> for LabError {
    fn from(e: bedrock_vm::VmError) -> Self {
        Self::Vm(e)
    }
}

impl From<std::io::Error> for LabError {
    fn from(e: std::io::Error) -> Self {
        Self::Vm(bedrock_vm::VmError::Io(e))
    }
}

/// Result alias used throughout the crate.
pub type Result<T> = std::result::Result<T, LabError>;
