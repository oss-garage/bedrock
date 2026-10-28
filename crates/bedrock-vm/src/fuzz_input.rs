// SPDX-License-Identifier: GPL-2.0

//! Fuzz-input channel — the host half of the `HYPERCALL_FUZZ_NEXT_INPUT` ABI.
//!
//! This is how a guest harness receives testcases from a host-side fuzzer. The
//! guest registers one feedback buffer and the host writes into that buffer's
//! CoW pages before resuming the VM.
//!
//! 1. During its one-time setup the guest registers a buffer under the id
//!    `fuzz-input`, sized for the largest testcase it expects plus the header
//!    length. A buffer larger than one feedback slot is registered as several
//!    consecutive `fuzz-input` slots, which the host treats as one buffer in
//!    registration order.
//! 2. The guest issues `HYPERCALL_FUZZ_NEXT_INPUT`, which exits to userspace as
//!    ExitKind::FuzzNextInput.
//! 3. The host overwrites the buffer with a response header (length of testcase
//!    bytes or -1) followed by the input bytes, and runs the VM again.
//! 4. The guest reads the response out of the buffer and executes that input.
//!
//! ## Fork-per-testcase TODO: Revisit / delete
//!
//! The reason this is worth a hypercall of its own rather than a file fetch is
//! where the *checkpoint* lands. The host runs the guest once, up to the first
//! `FuzzNextInput` exit, and checkpoints there — with the guest parked just
//! after the VMCALL, all of its expensive setup already done. Every subsequent
//! testcase is a fork of that checkpoint: map the fork's buffer, write a
//! different input into it, resume. Setup is paid once for the whole campaign,
//! and no two testcases can contaminate each other, because each one runs in a
//! VM that is bit-identical at the moment it receives its input.

use std::io;

use crate::Vm;

/// Identifier the guest registers its fuzz-input buffer under.
pub const FUZZ_INPUT_BUFFER_ID: &[u8] = b"fuzz-input";

/// Bytes reserved at the start of the shared buffer for the header. Payload
/// begins at this offset.
///
/// The header carries both directions of the exchange, because both happen at
/// the same hypercall:
///
/// | range      | writer | meaning                                          |
/// |------------|--------|--------------------------------------------------|
/// | `[0..8)`   | host   | `u64` result: input length                       |
/// | `[8..16)`  | guest  | `u64` status of the *previous* testcase          |
/// | `[16..24)` | guest  | `u64` aux: message length when status is `Fail`  |
/// | `[24..32)` | —      | reserved (zero)                                  |
///
/// The payload after the header is the input bytes (host→guest) or, when the
/// guest reports `Fail`, its message (guest→host).
pub const FUZZ_INPUT_HEADER_LEN: usize = 32;

/// What the guest reported about the testcase it just finished.
///
/// The guest writes this into the header before asking for its next
/// input
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FuzzOutcome {
    /// The testcase ran to completion without the harness detecting a bug.
    Ok,
    /// The harness could not use this testcase (e.g. it failed to decode).
    /// The fuzzer should not count it as an execution.
    Skip,
    /// The harness detected a bug, with this message.
    Fail(String),
    /// The guest wrote a status word this host build does not know.
    Unknown(u64),
}

/// Status word values the guest writes into `[8..16)`.
const STATUS_OK: u64 = 0;
const STATUS_SKIP: u64 = 1;
const STATUS_FAIL: u64 = 2;

/// Writes fuzzer testcases into a guest's registered input buffer.
#[derive(Debug, Default)]
pub struct InputServer {
    /// Cached feedback-buffer slots in registration order, resolved on first
    /// use. Registration happens during guest setup, before the first
    /// `FuzzNextInput` exit.
    slots: Option<Vec<usize>>,
}

impl InputServer {
    #[must_use]
    pub fn new() -> Self {
        Self { slots: None }
    }

    pub fn capacity(&mut self, vm: &mut Vm) -> io::Result<usize> {
        let slots = self.resolve_slots(vm)?;
        let mut total = 0;
        for slot in slots {
            total += slot_buffer(vm, slot)?.len();
        }
        Ok(total - FUZZ_INPUT_HEADER_LEN)
    }

    /// Write one testcase into the guest's input buffer. Call this on a
    /// `ExitKind::FuzzNextInput` exit, then run the VM again.
    pub fn serve(&mut self, vm: &mut Vm, input: &[u8]) -> io::Result<()> {
        let cap = self.capacity(vm)?;
        if input.len() > cap {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "fuzz input of {} bytes exceeds the guest's {cap}-byte input buffer",
                    input.len()
                ),
            ));
        }

        write_result(self.buffer(vm)?, input.len() as u64);

        let mut input = input;
        let mut start = FUZZ_INPUT_HEADER_LEN;
        for slot in self.resolve_slots(vm)? {
            let buf = slot_buffer(vm, slot)?;
            let n = input.len().min(buf.len() - start);
            buf[start..start + n].copy_from_slice(&input[..n]);
            input = &input[n..];
            start = 0;
        }
        Ok(())
    }

    /// Read back what the guest reported about the testcase it just finished.
    pub fn outcome(&mut self, vm: &mut Vm) -> io::Result<FuzzOutcome> {
        let buf = self.buffer(vm)?;
        let status = u64::from_le_bytes(buf[8..16].try_into().unwrap());
        Ok(match status {
            STATUS_OK => FuzzOutcome::Ok,
            STATUS_SKIP => FuzzOutcome::Skip,
            STATUS_FAIL => {
                let len = u64::from_le_bytes(buf[16..24].try_into().unwrap()) as usize;
                let end = FUZZ_INPUT_HEADER_LEN.saturating_add(len).min(buf.len());
                let msg = String::from_utf8_lossy(&buf[FUZZ_INPUT_HEADER_LEN..end]).into_owned();
                FuzzOutcome::Fail(msg)
            }
            other => FuzzOutcome::Unknown(other),
        })
    }

    /// Map and return the first slot, which holds the header.
    fn buffer<'a>(&mut self, vm: &'a mut Vm) -> io::Result<&'a mut [u8]> {
        let slot = self.resolve_slots(vm)?[0];
        let buf = slot_buffer(vm, slot)?;
        if buf.len() < FUZZ_INPUT_HEADER_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "fuzz-input buffer smaller than header",
            ));
        }
        Ok(buf)
    }

    /// Resolve and cache the feedback-buffer slots the guest registered the
    /// input buffer under.
    fn resolve_slots(&mut self, vm: &Vm) -> io::Result<Vec<usize>> {
        if let Some(slots) = &self.slots {
            return Ok(slots.clone());
        }
        let slots = vm.feedback_buffer_slots_for_id(FUZZ_INPUT_BUFFER_ID)?;
        if slots.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "guest issued HYPERCALL_FUZZ_NEXT_INPUT but registered no fuzz-input buffer",
            ));
        }
        self.slots = Some(slots.clone());
        Ok(slots)
    }
}

/// Map (once per VM) and return one slot read-write, so writes land in the
/// guest's pages.
fn slot_buffer(vm: &mut Vm, slot: usize) -> io::Result<&mut [u8]> {
    if vm.feedback_buffer_mut_at(slot).is_none() {
        vm.map_feedback_buffer_mut_at(slot)?;
    }
    vm.feedback_buffer_mut_at(slot)
        .ok_or_else(|| io::Error::other("fuzz-input buffer disappeared after mapping"))
}

/// Write the response `result` word into the buffer header and zero the rest of
/// the header.
fn write_result(buf: &mut [u8], result: u64) {
    buf[0..8].copy_from_slice(&result.to_le_bytes());
    buf[8..FUZZ_INPUT_HEADER_LEN].fill(0);
}
