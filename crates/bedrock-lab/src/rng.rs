// SPDX-License-Identifier: GPL-2.0

//! RDRAND/RDSEED emulation modes available to a lab experiment.
//!
//! The RNG mode is picked once when constructing the tree (via [`LabOpts`])
//! and applies to every branch forked from any checkpoint in the tree. Two
//! kernel-side modes (`Seeded` and `Inherit`) run entirely inside the
//! hypervisor with no userspace round-trip per RDRAND. The third
//! ([`RngMode::Source`]) pulls fresh values from a userspace
//! [`InputSource`] on every `RDRAND`/`RDSEED` — handy when you want guest
//! randomness to come from `/dev/urandom` (via [`SystemRng`]) or from a
//! fuzzer's byte stream (via a `FnMut() -> Option<u64> + Send` closure).

use std::fs::File;
use std::io::Read;

use bedrock_vm::events::{IoChannelPhase, RandomSource};
use bedrock_vm::io_channel::{decode_request, IoTarget};
use bedrock_vm::{Event, EventRecord};

use crate::bash::BashTarget;
use crate::time::VirtTime;

/// One host-driven I/O action supplied by an [`InputSource`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IoInput {
    /// Virtual time at which the command should be injected.
    pub at: VirtTime,
    /// Where the command should run.
    pub target: BashTarget,
    /// Command to run.
    pub command: String,
    /// Whether to capture the command's output into the output feedback
    /// buffer (surfaced on the [`BashOutput`](crate::BashOutput) of the
    /// resulting [`ActionResponse`](crate::RunOutcome::ActionResponse)).
    pub record_output: bool,
}

/// One controlled-randomness value fed to a branch — whatever the guest pulled
/// from any randomness channel: an RDRAND/RDSEED instruction value or a
/// `HYPERCALL_GET_RANDOM` (`/dev/urandom` / `getrandom()`) reply. One type for
/// all of them; [`source`](Self::source) says which channel and the served
/// [`bytes`](Self::bytes) are the payload (for RDRAND/RDSEED, the value's
/// little-endian bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RandomInput {
    /// Virtual time at which the bytes were served.
    pub at: VirtTime,
    /// Which channel served it (RDRAND, RDSEED, or GET_RANDOM).
    pub source: RandomSource,
    /// PID (`current->tgid`) of the requesting process for GET_RANDOM; 0 for
    /// RDRAND/RDSEED (served at an instruction exit, no process context).
    pub pid: u32,
    /// Bytes handed to the guest. For GET_RANDOM, the served buffer; for
    /// RDRAND/RDSEED, the instruction value's little-endian bytes.
    pub bytes: Vec<u8>,
}

/// Inputs consumed by a branch, suitable for replay.
///
/// The recording is reconstructed from the branch's unified event stream rather
/// than tracked separately: a branch with an [`InputSource`] forces on the
/// [`Randomness`](bedrock_vm::Event::Randomness) and
/// [`IoChannel`](bedrock_vm::Event::IoChannel) event categories, and every
/// drained record is fed through [`record_event`](Self::record_event). The
/// stream is therefore the single source of truth for what reached the guest.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InputRecording {
    random_inputs: Vec<RandomInput>,
    io_inputs: Vec<IoInput>,
}

impl InputRecording {
    /// Create an empty recording.
    pub fn new() -> Self {
        Self::default()
    }

    /// Controlled-randomness values fed to the branch — RDRAND, RDSEED and
    /// `HYPERCALL_GET_RANDOM` replies in one stream, in consumption order. Tell
    /// them apart by [`RandomInput::source`].
    pub fn random_inputs(&self) -> &[RandomInput] {
        &self.random_inputs
    }

    /// I/O actions queued from the branch's [`InputSource`], in queue order.
    pub fn io_inputs(&self) -> &[IoInput] {
        &self.io_inputs
    }

    /// Extract the determinism *input* carried by one event-stream record and
    /// append it to the recording. A [`Randomness`](bedrock_vm::Event::Randomness)
    /// record (RDRAND, RDSEED, or GET_RANDOM) yields one [`RandomInput`]; an
    /// [`IoChannel`](bedrock_vm::Event::IoChannel) *request* yields one
    /// [`IoInput`]. Every other kind — including I/O channel *responses*, which
    /// carry host-derived output — is ignored.
    ///
    /// `freq` converts the record's emulated-TSC timestamp into [`VirtTime`].
    /// For I/O the record's own emit TSC (the moment the request was signaled to
    /// the guest) is used, not the request's scheduled `target_tsc`: source-driven
    /// requests are queued "fire as soon as interruptible" (target 0), so the
    /// emit TSC is the point a replay must stop at to re-inject the command.
    pub(crate) fn record_event(&mut self, record: &EventRecord<'_>, freq: u64) {
        match record.event() {
            // One unified randomness stream. RDRAND/RDSEED carry their value
            // inline (stored as its little-endian bytes); GET_RANDOM carries the
            // served buffer + the requesting PID.
            Event::Randomness(p, bytes) => {
                let at = VirtTime::from_instructions(record.tsc(), freq);
                let source = RandomSource::from_u8(p.source);
                let (pid, bytes) = if source == RandomSource::GetRandom {
                    (p.pid, bytes.to_vec())
                } else {
                    (0, p.value.to_le_bytes().to_vec())
                };
                self.random_inputs.push(RandomInput {
                    at,
                    source,
                    pid,
                    bytes,
                });
            }
            Event::IoChannel(meta, data) if meta.phase == IoChannelPhase::Request as u8 => {
                let Some(req) = decode_request(data) else {
                    return;
                };
                self.io_inputs.push(IoInput {
                    at: VirtTime::from_instructions(record.tsc(), freq),
                    target: match req.target {
                        IoTarget::Host => BashTarget::Host,
                        IoTarget::Container(name) => BashTarget::Container(name.into_owned()),
                    },
                    command: req.command.into_owned(),
                    record_output: req.record_output,
                });
            }
            _ => {}
        }
    }
}

/// Replay source backed by an [`InputRecording`].
#[derive(Debug, Clone)]
pub struct RecordedInputSource {
    recording: InputRecording,
    /// Cursor into the one randomness stream, shared by RDRAND/RDSEED and
    /// GET_RANDOM replay so the values come back in the exact recorded order.
    random_pos: usize,
    io_pos: usize,
}

impl RecordedInputSource {
    /// Replay a previously captured recording.
    pub fn new(recording: InputRecording) -> Self {
        Self {
            recording,
            random_pos: 0,
            io_pos: 0,
        }
    }

    /// Access the underlying recording.
    pub fn recording(&self) -> &InputRecording {
        &self.recording
    }
}

impl From<InputRecording> for RecordedInputSource {
    fn from(recording: InputRecording) -> Self {
        Self::new(recording)
    }
}

/// A userspace source of lab inputs.
///
/// The RNG side is used to serve guest RDRAND/RDSEED instructions when a
/// tree is configured with [`RngMode::Source`]. The I/O side lets callers
/// keep deterministic host-driven I/O inputs in the same forked stream.
///
/// Sources must be cloneable: every checkpoint captures the source state
/// at its creation point, and every branch forks off its own clone. That
/// way `cp.branch()` twice produces two branches whose input streams are
/// independent of the order in which they're driven — same model as VM
/// state itself.
///
/// For closures, this means the captured state must be `Clone`: a plain
/// `move ||` that captures `let mut pos: usize = 0` works (it just copies
/// the cursor), but anything carrying a `&mut` borrow or non-Clone state
/// will need a hand-rolled struct.
pub trait InputSource: Send + Sync {
    /// Pull the next RNG `u64` from the source.
    ///
    /// Return `None` to signal exhaustion: the lab will surface the trapping
    /// `RDRAND`/`RDSEED` as [`RunOutcome::RngExhausted`](crate::RunOutcome::RngExhausted)
    /// so the caller can drop the branch and move on. Once `None` is
    /// returned, future calls should keep returning `None`.
    fn next_rng_u64(&mut self) -> Option<u64>;

    /// Serve the bytes for one `HYPERCALL_GET_RANDOM` request of `len` bytes from
    /// process `pid` (the guest's `/dev/urandom` / `getrandom()` path). Must
    /// always return exactly `len` bytes.
    ///
    /// The default synthesizes them from [`next_rng_u64`](Self::next_rng_u64) so
    /// any RNG source works unchanged; sources that record/replay exact byte
    /// streams (or want to steer per-PID) override it.
    fn next_random(&mut self, len: usize, _pid: u32) -> Vec<u8> {
        let mut out = Vec::with_capacity(len);
        while out.len() < len {
            let v = self.next_rng_u64().unwrap_or(0);
            out.extend_from_slice(&v.to_le_bytes());
        }
        out.truncate(len);
        out
    }

    /// Pull the next I/O input from the source.
    ///
    /// Return `None` to signal that no more I/O input is available from this
    /// source.
    fn next_io_input(&mut self) -> Option<IoInput> {
        None
    }

    /// Produce an independent copy of this source. Future input pulls on the
    /// clone must not affect this source's stream, and vice versa.
    /// See the [`InputSource`] type docs for why this exists.
    fn clone_box(&self) -> Box<dyn InputSource>;
}

impl<F: FnMut() -> Option<u64> + Send + Sync + Clone + 'static> InputSource for F {
    fn next_rng_u64(&mut self) -> Option<u64> {
        self()
    }
    fn clone_box(&self) -> Box<dyn InputSource> {
        Box::new(self.clone())
    }
}

impl Clone for Box<dyn InputSource> {
    fn clone(&self) -> Self {
        self.clone_box()
    }
}

impl InputSource for RecordedInputSource {
    fn next_rng_u64(&mut self) -> Option<u64> {
        // Pull the next entry of the one randomness stream and reconstruct the
        // instruction value from its little-endian bytes. `None` past the
        // recording signals exhaustion (the lab surfaces `RngExhausted`).
        let input = self.recording.random_inputs.get(self.random_pos)?;
        self.random_pos += 1;
        let mut buf = [0u8; 8];
        let n = input.bytes.len().min(8);
        buf[..n].copy_from_slice(&input.bytes[..n]);
        Some(u64::from_le_bytes(buf))
    }

    fn next_random(&mut self, len: usize, _pid: u32) -> Vec<u8> {
        // Serve the recorded reply for this slot of the same stream; zero-fill
        // past the recording (and top up a recorded reply shorter than now asked
        // for) so replay stays deterministic. Always returns exactly `len` bytes.
        let mut bytes = self
            .recording
            .random_inputs
            .get(self.random_pos)
            .map(|input| input.bytes.clone())
            .unwrap_or_default();
        self.random_pos += 1;
        bytes.resize(len, 0);
        bytes
    }

    fn next_io_input(&mut self) -> Option<IoInput> {
        let input = self.recording.io_inputs.get(self.io_pos).cloned();
        if input.is_some() {
            self.io_pos += 1;
        }
        input
    }

    fn clone_box(&self) -> Box<dyn InputSource> {
        Box::new(self.clone())
    }
}

/// How a tree should serve guest `RDRAND`/`RDSEED` instructions.
///
/// Set once on the root checkpoint via [`LabOpts::rng`](crate::LabOpts::rng);
/// the mode is applied to the root VM's RDRAND state and inherited by every
/// forked branch via the standard COW VM-state fork.
#[derive(Default)]
pub enum RngMode {
    /// Don't touch the VM's RDRAND config — use whatever the caller set up
    /// on the [`Vm`](bedrock_vm::Vm) before handing it to
    /// [`Checkpoint::initial_when_ready_with`](crate::Checkpoint::initial_when_ready_with). The
    /// default.
    #[default]
    Inherit,
    /// Kernel-side `xorshift64` PRNG starting from `seed`. Each branch's
    /// kernel state forks at branch creation, so two branches with no extra
    /// RDRANDs between fork and use start producing the same sequence.
    Seeded(u64),
    /// Exit to userspace on every guest `RDRAND`/`RDSEED` and serve the
    /// value from this source. The source is shared across every branch in
    /// the tree.
    Source(Box<dyn InputSource>),
}

/// An [`InputSource`] backed by the kernel's `/dev/urandom`.
///
/// Non-deterministic by design — useful when you specifically *want* the
/// tree to see real-world entropy. For deterministic exploration use
/// [`RngMode::Seeded`] or a custom closure source seeded with a known value.
/// Cloning opens a fresh fd to `/dev/urandom` (kernel-managed state, so the
/// clone is independent in the only sense that matters).
pub struct SystemRng {
    file: File,
}

impl SystemRng {
    /// Open `/dev/urandom`. Fails only if the device can't be opened.
    pub fn new() -> std::io::Result<Self> {
        Ok(Self {
            file: File::open("/dev/urandom")?,
        })
    }
}

impl InputSource for SystemRng {
    fn next_rng_u64(&mut self) -> Option<u64> {
        let mut buf = [0u8; 8];
        // /dev/urandom never short-reads for tiny requests; if it does, the
        // kernel is in such a broken state that zero-padding is fine.
        let _ = self.file.read_exact(&mut buf);
        Some(u64::from_le_bytes(buf))
    }
    fn clone_box(&self) -> Box<dyn InputSource> {
        Box::new(Self::new().expect("/dev/urandom"))
    }
}

#[cfg(test)]
#[path = "rng_tests.rs"]
mod tests;
