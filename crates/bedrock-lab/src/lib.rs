// SPDX-License-Identifier: GPL-2.0

//! High-level testing and debugging API for the bedrock hypervisor.
//!
//! - [`VirtTime`] / [`VirtDuration`] — all "when" arguments are virtual time.
//! - [`Checkpoint`] — an immutable halted VM that branches fork from.
//! - [`Branch`] — a line of execution; advance with [`Branch::run_until`],
//!   snapshot with [`Branch::checkpoint`], go back with [`Checkpoint::rewind`].
//! - [`Tree`] — a read-only view of the checkpoint/branch genealogy.
//!
//! The tree lives as long as any handle into it.
//!
//! # Example
//!
//! ```ignore
//! use bedrock_lab::{BashTarget, Checkpoint, VirtTime, VirtDuration};
//! use bedrock_vm::VmBuilder;
//!
//! let vm = VmBuilder::new().memory_mb(64).build()?;
//! // ... load kernel, setup_linux_boot, etc. ...
//! let cp0 = Checkpoint::initial_when_ready(
//!     vm,
//!     VirtTime::from_secs(120, bedrock_vm::DEFAULT_TSC_FREQUENCY),
//! )?;
//! let freq = cp0.tsc_frequency();
//!
//! let mut a = cp0.branch()?;
//! a.run_until(VirtTime::from_millis(500, freq))?;
//! let cp1 = a.checkpoint()?;
//!
//! let mut a = cp1.branch()?;
//! a.run_until(VirtTime::from_secs(2, freq))?;
//! a.bash(BashTarget::host(), "uname -a")?;
//!
//! // Rewind from any checkpoint to get an earlier one (without disturbing `a`).
//! let earlier = cp1.rewind(VirtDuration::from_millis(100, freq))?;
//!
//! // Sibling branch exploring an alternate future from cp1
//! let mut b = cp1.branch()?;
//! b.run_until(VirtTime::from_secs(1, freq))?;
//!
//! println!("{}", cp0.tree().dot());
//! ```

mod bash;
mod branch;
mod checkpoint;
mod error;
mod event;
mod inner;
mod rng;
mod time;
mod tree;

pub use bash::{BashOutput, BashTarget};
pub use bedrock_vm::fuzz_input::FuzzOutcome;
pub use bedrock_vm::{EventCategories, EventRecord};
pub use branch::{Branch, BranchId, EventConfig, ExitCapture, RunOutcome};
pub use checkpoint::{Checkpoint, CheckpointId, LabOpts};
pub use error::LabError;
pub use event::{Event, EventSink};
pub use rng::{
    InputRecording, InputSource, IoInput, RandomInput, RecordedInputSource, RngMode, SystemRng,
};
pub use time::{VirtDuration, VirtTime};
pub use tree::{BranchView, Tree};
