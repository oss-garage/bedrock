// SPDX-License-Identifier: GPL-2.0

//! Checkpoints — immutable moments in virtual time.

use std::sync::{Arc, Weak};

use bedrock_vm::file_xfer::FileServer;
use bedrock_vm::{
    EventCategories, EventConfig as VmEventConfig, ExitKind, RdrandConfig, Vm, VmError,
};

use crate::branch::{Branch, BranchId};
use crate::error::{LabError, Result};
use crate::event::{
    drain_serial_events, emit_feedback_buffer_registered, Discard, Event, EventSink, PartialLine,
};
use crate::inner::LabInner;
use crate::rng::{InputRecording, InputSource, IoInput, RngMode};
use crate::time::{VirtDuration, VirtTime};
use crate::tree::Tree;

/// Tree-wide options passed to [`Checkpoint::initial_when_ready_with`]:
///
/// ```ignore
/// use bedrock_lab::{Checkpoint, LabOpts, RngMode};
/// let cp = Checkpoint::initial_when_ready_with(vm, deadline, LabOpts {
///     rng: RngMode::Seeded(0xC0FFEE),
///     ..Default::default()
/// })?;
/// ```
pub struct LabOpts {
    /// Emulated TSC frequency in Hz; must match the [`Vm`]'s.
    pub tsc_frequency: u64,
    /// Defaults to discarding everything.
    pub sink: Arc<dyn EventSink>,
    pub rng: RngMode,
    /// `(guest_name, host_path)` pairs served over `HYPERCALL_FILE_FETCH`
    /// during boot (e.g. the podman initrd's `compose.yaml` / `images.tar`).
    /// Only served before the ready hypercall.
    pub files: Vec<(String, String)>,
    pub file_store_dir: Option<std::path::PathBuf>,
}

impl Default for LabOpts {
    fn default() -> Self {
        Self {
            tsc_frequency: bedrock_vm::DEFAULT_TSC_FREQUENCY,
            sink: Arc::new(Discard),
            rng: RngMode::Inherit,
            files: Vec::new(),
            file_store_dir: None,
        }
    }
}

/// A stable identifier for a checkpoint within its tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CheckpointId(pub(crate) u64);

/// An immutable moment in virtual time: a halted VM that can be forked into
/// [`Branch`]es. Cheap to clone (`Arc`); the VM is dropped with the last handle
/// or descendant pinning it.
#[derive(Clone)]
pub struct Checkpoint {
    pub(crate) inner: Arc<CheckpointInner>,
}

pub(crate) struct CheckpointInner {
    pub(crate) id: CheckpointId,
    pub(crate) time: VirtTime,
    /// Only ever used as a `vm.fork()` source; never run again.
    pub(crate) vm: Vm,
    /// The checkpoint whose VM was forked to build this one (fixed; may differ
    /// from the logical tree parent after a rewind).
    pub(crate) _vm_parent: Option<Weak<CheckpointInner>>,
    pub(crate) lab: Arc<LabInner>,
    /// Serial line in progress, prepended to descendant branches.
    pub(crate) partial_line: PartialLine,
    /// Cloned into each branch. `None` for kernel-side RNG modes, whose state
    /// propagates through the VM fork.
    pub(crate) input_source: Option<Box<dyn InputSource>>,
    pub(crate) pending_input_io: Option<IoInput>,
    pub(crate) input_io_exhausted: bool,
    pub(crate) input_recording: InputRecording,
}

impl Checkpoint {
    /// Boot a fully set-up root [`Vm`] (unforked, like `bedrock-cli`) until
    /// `HYPERCALL_READY` and make the initial checkpoint there. Errors if
    /// `deadline` (at [`bedrock_vm::DEFAULT_TSC_FREQUENCY`]) passes first or on
    /// an unexpected exit.
    ///
    /// Pre-ready serial output and feedback-buffer registrations are emitted
    /// under reserved [`BranchId(0)`](crate::BranchId).
    pub fn initial_when_ready(vm: Vm, deadline: VirtTime) -> Result<Self> {
        Self::initial_when_ready_with(vm, deadline, LabOpts::default())
    }

    /// [`initial_when_ready`](Self::initial_when_ready) with [`LabOpts`].
    ///
    /// The RNG mode is configured before first run. A [`RngMode::Source`] is
    /// not consumed during boot: pre-ready `RDRAND`/`RDSEED` exits are errors.
    pub fn initial_when_ready_with(mut vm: Vm, deadline: VirtTime, opts: LabOpts) -> Result<Self> {
        Self::check_frequency(deadline.frequency(), opts.tsc_frequency)?;
        let (mut opts, input_source) = Self::configure_rng(&vm, opts)?;
        let mut file_server = FileServer::new(std::mem::take(&mut opts.files));
        vm.set_event_config(&VmEventConfig::enabled(EventCategories::SERIAL))
            .map_err(|source| {
                LabError::Vm(VmError::Ioctl {
                    operation: "SET_EVENT_CONFIG",
                    source,
                })
            })?;
        vm.set_stop_at_tsc(Some(deadline.instructions()))?;
        let mut partial_line = PartialLine::default();
        loop {
            let exit = vm.run()?;
            let at = VirtTime::from_instructions(exit.emulated_tsc, opts.tsc_frequency);
            let event_len = exit.event_len as usize;
            if event_len > 0 {
                if let Some(buffer) = vm.event_buffer() {
                    drain_serial_events(
                        &buffer[..event_len.min(buffer.len())],
                        opts.tsc_frequency,
                        BranchId(0),
                        opts.sink.as_ref(),
                        &mut partial_line,
                    );
                }
            }
            match exit.kind() {
                ExitKind::VmcallReady => {
                    vm.set_stop_at_tsc(None)?;
                    return Self::initial_at_with_configured_rng(
                        vm,
                        at,
                        opts,
                        partial_line,
                        input_source,
                    );
                }
                ExitKind::FeedbackBufferRegistered => {
                    emit_feedback_buffer_registered(&vm, at, BranchId(0), opts.sink.as_ref())?;
                    continue;
                }
                ExitKind::FileFetch => {
                    file_server.serve(&mut vm).map_err(|source| {
                        LabError::Vm(VmError::Ioctl {
                            operation: "FILE_FETCH",
                            source,
                        })
                    })?;
                    continue;
                }
                ExitKind::Continue | ExitKind::EventBufferFull => continue,
                kind => return Err(LabError::UnexpectedExit { at, kind }),
            }
        }
    }

    fn check_frequency(lhs: u64, rhs: u64) -> Result<()> {
        if lhs != rhs {
            return Err(LabError::FrequencyMismatch { lhs, rhs });
        }
        Ok(())
    }

    fn configure_rng(vm: &Vm, opts: LabOpts) -> Result<(LabOpts, Option<Box<dyn InputSource>>)> {
        let LabOpts {
            tsc_frequency,
            sink,
            rng,
            files,
            file_store_dir,
        } = opts;

        let (rdrand_config, input_source) = match rng {
            RngMode::Inherit => (None, None),
            RngMode::Seeded(seed) => (Some(RdrandConfig::seeded_rng(seed)), None),
            RngMode::Source(source) => (Some(RdrandConfig::exit_to_userspace()), Some(source)),
        };
        if let Some(config) = rdrand_config {
            vm.set_rdrand_config(&config)?;
        }
        Ok((
            LabOpts {
                tsc_frequency,
                sink,
                rng: RngMode::Inherit,
                files,
                file_store_dir,
            },
            input_source,
        ))
    }

    fn initial_at_with_configured_rng(
        vm: Vm,
        time: VirtTime,
        opts: LabOpts,
        partial_line: PartialLine,
        input_source: Option<Box<dyn InputSource>>,
    ) -> Result<Self> {
        let LabOpts {
            tsc_frequency,
            sink,
            rng: _,
            files: _,
            file_store_dir,
        } = opts;

        let lab = LabInner::new(tsc_frequency, sink, file_store_dir);
        let id = CheckpointId(lab.next_checkpoint_id());
        let inner = Arc::new(CheckpointInner {
            id,
            time,
            vm,
            _vm_parent: None,
            lab: lab.clone(),
            partial_line,
            input_source,
            pending_input_io: None,
            input_io_exhausted: false,
            input_recording: InputRecording::new(),
        });
        lab.graph.lock().unwrap().register_checkpoint(&inner, None);
        lab.sink.on_event(Event::CheckpointCreated {
            checkpoint: id,
            from_branch: None,
            parent: None,
            at: time,
        });
        Ok(Self { inner })
    }

    /// This checkpoint's ID, stable for the lifetime of the tree.
    pub fn id(&self) -> CheckpointId {
        self.inner.id
    }

    /// The virtual time at which this checkpoint was taken.
    pub fn time(&self) -> VirtTime {
        self.inner.time
    }

    /// The TSC frequency of the tree this checkpoint belongs to.
    pub fn tsc_frequency(&self) -> u64 {
        self.inner.lab.tsc_frequency
    }

    /// Inputs consumed along the path to this checkpoint.
    pub fn input_recording(&self) -> &InputRecording {
        &self.inner.input_recording
    }

    /// Clone this checkpoint's consumed-input recording for replay.
    pub fn input_recording_to_source(&self) -> crate::RecordedInputSource {
        crate::RecordedInputSource::new(self.inner.input_recording.clone())
    }

    /// Fork a [`Branch`] with its own CoW VM and input-source clone.
    pub fn branch(&self) -> Result<Branch> {
        let input_source = self.inner.input_source.as_ref().map(|s| s.clone_box());
        self.branch_inner(input_source, false)
    }

    /// Fork a branch with `source` overriding the tree's input source and
    /// [`RngMode`](crate::RngMode) (e.g. one fuzz input per branch). Forces
    /// exit-to-userspace RDRAND on the new VM, which descendants inherit.
    pub fn branch_with_input_source<S: InputSource + 'static>(&self, source: S) -> Result<Branch> {
        self.branch_inner(Some(Box::new(source)), true)
    }

    fn branch_inner(
        &self,
        input_source: Option<Box<dyn InputSource>>,
        force_exit_to_userspace: bool,
    ) -> Result<Branch> {
        let child_vm = self.inner.vm.fork()?;
        if force_exit_to_userspace {
            child_vm.set_rdrand_config(&RdrandConfig::exit_to_userspace())?;
        }
        let id = BranchId(self.inner.lab.next_branch_id());
        let mut branch = Branch::new(
            id,
            self.clone(),
            child_vm,
            self.inner.time,
            self.inner.lab.clone(),
            self.inner.partial_line.clone(),
            input_source,
            self.inner.pending_input_io.clone(),
            self.inner.input_io_exhausted,
            self.inner.input_recording.clone(),
        );
        branch.enable_event_capture()?;
        Ok(branch)
    }

    /// Logical parent in the [`Tree`](crate::Tree); `None` for the root. May
    /// differ from the VM fork parent after [`Checkpoint::rewind`].
    pub fn parent(&self) -> Option<Checkpoint> {
        self.inner
            .lab
            .graph
            .lock()
            .unwrap()
            .parent(self.inner.id)
            .map(|inner| Checkpoint { inner })
    }

    /// A checkpoint at `self.time() - by`, made by replaying from the latest
    /// ancestor at or before that time. An ancestor exactly at the target is
    /// returned as-is. Errors with [`LabError::NoCheckpointBefore`] if none is
    /// early enough.
    pub fn rewind(&self, by: VirtDuration) -> Result<Checkpoint> {
        if by.frequency() != self.inner.lab.tsc_frequency {
            return Err(LabError::FrequencyMismatch {
                lhs: by.frequency(),
                rhs: self.inner.lab.tsc_frequency,
            });
        }
        let target = self.inner.time - by;

        let candidates = self.rewind_candidates(target);
        if let Some(cp) = candidates.iter().find(|cp| cp.time() == target) {
            return Ok(cp.clone());
        }
        let Some(best) = candidates.into_iter().max_by_key(|cp| (cp.time(), cp.id())) else {
            return Err(LabError::NoCheckpointBefore { target });
        };

        let mut tmp = best.branch()?;
        tmp.run_until(target)?;
        let cp = tmp.checkpoint()?;
        let child = self
            .logical_child_after(target, &best)
            .unwrap_or_else(|| self.clone());
        self.inner
            .lab
            .graph
            .lock()
            .unwrap()
            .reparent(child.id(), cp.id());
        Ok(cp)
    }

    fn rewind_candidates(&self, target: VirtTime) -> Vec<Checkpoint> {
        let mut candidates = Vec::new();

        let mut walk = Some(self.clone());
        while let Some(cp) = walk {
            if cp.time() <= target {
                candidates.push(cp.clone());
            }
            walk = cp.parent();
        }

        candidates
    }

    fn logical_child_after(&self, target: VirtTime, ancestor: &Checkpoint) -> Option<Checkpoint> {
        let mut child = self.clone();
        loop {
            let parent = child.parent()?;
            if parent.time() <= target && target < child.time() {
                return Some(child);
            }
            if parent.id() == ancestor.id() {
                return None;
            }
            child = parent;
        }
    }

    /// Take a read-only snapshot of the entire tree this checkpoint belongs to.
    pub fn tree(&self) -> Tree {
        Tree::from_lab(&self.inner.lab)
    }
}

impl std::fmt::Debug for Checkpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Checkpoint")
            .field("id", &self.inner.id)
            .field("time", &self.inner.time)
            .finish()
    }
}
