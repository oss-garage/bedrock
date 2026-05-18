// SPDX-License-Identifier: GPL-2.0

//! Event sink — how lab consumers observe what's happening inside the tree.
//!
//! Every tree owns a single [`EventSink`]. Branches forward serial output
//! (one event per complete line), branch creation, and checkpoint creation
//! to the sink so the consumer can persist, stream, or discard the data
//! however it likes (BigQuery, a local database, stdout, or `/dev/null`).

use bedrock_vm::{parse_line_tsc_entries, LogEntry, Vm};

use crate::branch::BranchId;
use crate::checkpoint::CheckpointId;
use crate::time::VirtTime;

/// An observable event in the lab's execution tree.
///
/// `#[non_exhaustive]` so new variants can be added without breaking sinks.
#[non_exhaustive]
#[derive(Debug)]
pub enum Event<'a> {
    /// One complete line of serial output from a branch's guest.
    ///
    /// `line` is the bytes between line starts (trailing `\n` stripped) and
    /// borrows from a per-branch buffer for the duration of the `on_event`
    /// call — copy out if the sink needs to retain it. `at` is the emulated
    /// TSC at which the *first* byte of this line was written (carried
    /// across `vm.run()` drains and across `Checkpoint::branch` so a line
    /// continued from a parent checkpoint keeps its original start time).
    ///
    /// Partial lines pending at branch drop are silently discarded;
    /// partial lines pending at `Branch::checkpoint` are propagated into
    /// the new checkpoint so descendant branches glue onto the same line.
    /// [`BranchId(0)`](crate::BranchId) is reserved for root-VM boot/setup
    /// output emitted before the ready checkpoint exists.
    SerialLine {
        branch: BranchId,
        at: VirtTime,
        line: &'a [u8],
    },
    /// A new branch was forked from `origin`.
    BranchCreated {
        branch: BranchId,
        origin: CheckpointId,
        at: VirtTime,
    },
    /// A checkpoint was created. `from_branch` is `None` for the root
    /// checkpoint; `parent` is `None` for the root.
    CheckpointCreated {
        checkpoint: CheckpointId,
        from_branch: Option<BranchId>,
        parent: Option<CheckpointId>,
        at: VirtTime,
    },
    /// The guest registered a feedback buffer at `index` of `size` bytes.
    /// Fires once per successful `HYPERCALL_REGISTER_FEEDBACK_BUFFER` call.
    /// The buffer is readable on the originating branch via
    /// [`Branch::feedback_buffer`](crate::Branch::feedback_buffer); descendant
    /// branches inherit the registration through CoW. [`BranchId(0)`](crate::BranchId)
    /// is reserved for registrations that occur during root-VM boot/setup
    /// before the ready checkpoint exists.
    FeedbackBufferRegistered {
        branch: BranchId,
        at: VirtTime,
        index: usize,
        size: u64,
    },
    /// A VM exit captured by the determinism-debugging exit logger. Fires
    /// once per kernel-written [`LogEntry`] for branches that have been
    /// configured via [`Branch::set_log_config`](crate::Branch::set_log_config).
    ///
    /// The logger captures guest registers and device-state hashes at each
    /// covered exit; diffing two runs' streams pinpoints where execution
    /// diverged. `entry` borrows from the kernel-mapped log buffer for the
    /// duration of the `on_event` call — copy out if the sink needs to
    /// retain it.
    ExitLogged {
        branch: BranchId,
        entry: &'a LogEntry,
    },
}

/// Receives every [`Event`] produced by the tree.
///
/// Implementations must be cheap and non-blocking; `on_event` runs on the
/// thread driving the branch and any long wait stalls guest execution.
/// Offload heavy work (DB writes, network) to a background worker.
///
/// Internal scratch branches created by
/// [`Checkpoint::rewind`](crate::Checkpoint::rewind) emit events like any
/// other branch — filter on `BranchId` if you only want user-visible work.
pub trait EventSink: Send + Sync {
    fn on_event(&self, event: Event<'_>);
}

/// Default sink used when the caller doesn't supply one — discards everything.
pub(crate) struct Discard;

impl EventSink for Discard {
    fn on_event(&self, _event: Event<'_>) {}
}

/// Per-branch partial-line state. A line that doesn't see its trailing
/// `\n` within one `vm.run()` drain (or within one branch's lifetime
/// before checkpointing) survives here until completion.
#[derive(Default, Clone, Debug)]
pub(crate) struct PartialLine {
    pub(crate) bytes: Vec<u8>,
    /// Emulated TSC at which the first byte of `bytes` was written.
    /// Meaningful only when `bytes.is_empty() == false`.
    pub(crate) start_tsc: u64,
}

/// Drain `serial_len` bytes from `vm`'s serial buffer, split them into
/// complete lines using per-line TSC metadata for accurate start timestamps,
/// and forward each completed line to `sink`. Bytes that don't terminate in
/// `\n` accumulate onto `partial` until a future drain completes them.
pub(crate) fn drain_serial_into_sink(
    vm: &Vm,
    serial_len: usize,
    exit_at: VirtTime,
    branch: BranchId,
    sink: &dyn EventSink,
    partial: &mut PartialLine,
) {
    if serial_len == 0 {
        return;
    }
    let serial_bytes = &vm.serial_buffer()[..serial_len];
    let line_entries = parse_line_tsc_entries(vm.serial_tsc_buffer()).unwrap_or_default();
    let freq = exit_at.frequency();
    let fallback_tsc = exit_at.instructions();
    let mut next_entry = 0usize;
    for (i, &byte) in serial_bytes.iter().enumerate() {
        if partial.bytes.is_empty() {
            while next_entry < line_entries.len() && (line_entries[next_entry].offset as usize) < i
            {
                next_entry += 1;
            }
            partial.start_tsc = match line_entries.get(next_entry) {
                Some(e) if e.offset as usize == i => e.tsc,
                _ => fallback_tsc,
            };
        }
        if byte == b'\n' {
            let at = VirtTime::from_instructions(partial.start_tsc, freq);
            sink.on_event(Event::SerialLine {
                branch,
                at,
                line: &partial.bytes,
            });
            partial.bytes.clear();
        } else {
            partial.bytes.push(byte);
        }
    }
}

/// Read the guest GPRs after a successful `HYPERCALL_REGISTER_FEEDBACK_BUFFER`
/// exit and emit an [`Event::FeedbackBufferRegistered`].
pub(crate) fn emit_feedback_buffer_registered(
    vm: &Vm,
    at: VirtTime,
    branch: BranchId,
    sink: &dyn EventSink,
) -> Result<(usize, u64), bedrock_vm::VmError> {
    let regs = vm.get_regs()?;
    let index = regs.gprs.rdx as usize;
    let size = regs.gprs.rcx;
    sink.on_event(Event::FeedbackBufferRegistered {
        branch,
        at,
        index,
        size,
    });
    Ok((index, size))
}
