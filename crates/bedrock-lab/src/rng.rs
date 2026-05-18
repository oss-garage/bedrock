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
}

/// One RDRAND/RDSEED value fed to a branch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RngInput {
    /// Virtual time at which the value was fed.
    pub at: VirtTime,
    /// Value returned to the guest instruction.
    pub value: u64,
}

/// Inputs consumed by a branch, suitable for replay.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InputRecording {
    rng_inputs: Vec<RngInput>,
    io_inputs: Vec<IoInput>,
}

impl InputRecording {
    /// Create an empty recording.
    pub fn new() -> Self {
        Self::default()
    }

    /// RDRAND/RDSEED values fed to the branch, in consumption order.
    pub fn rng_inputs(&self) -> &[RngInput] {
        &self.rng_inputs
    }

    /// I/O actions queued from the branch's [`InputSource`], in queue order.
    pub fn io_inputs(&self) -> &[IoInput] {
        &self.io_inputs
    }

    pub(crate) fn push_rng(&mut self, input: RngInput) {
        self.rng_inputs.push(input);
    }

    pub(crate) fn push_io(&mut self, input: IoInput) {
        self.io_inputs.push(input);
    }
}

/// Replay source backed by an [`InputRecording`].
#[derive(Debug, Clone)]
pub struct RecordedInputSource {
    recording: InputRecording,
    rng_pos: usize,
    io_pos: usize,
}

impl RecordedInputSource {
    /// Replay a previously captured recording.
    pub fn new(recording: InputRecording) -> Self {
        Self {
            recording,
            rng_pos: 0,
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
        let input = self.recording.rng_inputs.get(self.rng_pos);
        if input.is_some() {
            self.rng_pos += 1;
        }
        input.map(|entry| entry.value)
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
