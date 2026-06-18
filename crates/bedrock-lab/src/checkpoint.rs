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

/// Tree-wide options passed to [`Checkpoint::initial_when_ready_with`].
///
/// All fields have sensible defaults; use struct-update syntax for the ones
/// you want to override:
///
/// ```ignore
/// use bedrock_lab::{Checkpoint, LabOpts, RngMode};
/// let cp = Checkpoint::initial_when_ready_with(vm, deadline, LabOpts {
///     rng: RngMode::Seeded(0xC0FFEE),
///     ..Default::default()
/// })?;
/// ```
pub struct LabOpts {
    /// Emulated TSC frequency in Hz. Must match the value the [`Vm`] was
    /// built with.
    pub tsc_frequency: u64,
    /// Where to forward serial lines, branch creations, and checkpoint
    /// creations. Defaults to a sink that discards everything.
    pub sink: Arc<dyn EventSink>,
    /// How guest `RDRAND`/`RDSEED` is served for every branch in this tree.
    pub rng: RngMode,
    /// Host files exposed to the guest over the file-transmission hypercall
    /// (`HYPERCALL_FILE_FETCH`), as `(guest_name, host_path)` pairs. The
    /// generic podman initrd downloads its workload files (`compose.yaml` /
    /// `images.tar`) by name during boot, so callers booting such an initrd
    /// must supply them here. Files are only fetched before the ready
    /// hypercall, so they are served during this constructor's boot loop and
    /// need not persist into the tree.
    pub files: Vec<(String, String)>,
}

impl Default for LabOpts {
    fn default() -> Self {
        Self {
            tsc_frequency: bedrock_vm::DEFAULT_TSC_FREQUENCY,
            sink: Arc::new(Discard),
            rng: RngMode::Inherit,
            files: Vec::new(),
        }
    }
}

/// A stable identifier for a checkpoint within its tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CheckpointId(pub(crate) u64);

/// An immutable moment in virtual time — a halted VM that can be forked into
/// one or more [`Branch`]es.
///
/// `Checkpoint` is a cheap-to-clone handle (`Arc` under the hood). All clones
/// of the same checkpoint refer to the same frozen VM and share the same tree
/// registry. The underlying VM is dropped automatically when the last handle
/// (and any descendant branch/checkpoint that pinned it) goes away.
#[derive(Clone)]
pub struct Checkpoint {
    pub(crate) inner: Arc<CheckpointInner>,
}

pub(crate) struct CheckpointInner {
    pub(crate) id: CheckpointId,
    pub(crate) time: VirtTime,
    /// The halted VM. Used only as a `vm.fork()` source — never run again.
    pub(crate) vm: Vm,
    /// VM replay parent. This is the checkpoint whose VM state was forked to
    /// construct this checkpoint's VM state. It never changes.
    pub(crate) _vm_parent: Option<Weak<CheckpointInner>>,
    pub(crate) lab: Arc<LabInner>,
    /// Serial line in progress at the moment this checkpoint was taken.
    /// Descendant branches start with this prepended so a line that
    /// straddles `Branch::checkpoint` is not split across two events.
    pub(crate) partial_line: PartialLine,
    /// Userspace input source captured at this checkpoint's virtual time.
    /// Branches fork their own clone, so the order in which sibling branches
    /// run does not affect the RNG or I/O inputs any individual branch sees.
    /// `None` for kernel-side RNG modes without a userspace source — those
    /// propagate through the VM-state COW like everything else.
    pub(crate) input_source: Option<Box<dyn InputSource>>,
    /// Next source-provided I/O action not yet queued because it was beyond
    /// the last run target or the VM queue was full.
    pub(crate) pending_input_io: Option<IoInput>,
    /// True once the input source has no more I/O actions.
    pub(crate) input_io_exhausted: bool,
    /// Inputs consumed along the path to this checkpoint.
    pub(crate) input_recording: InputRecording,
}

impl Checkpoint {
    /// Run a fully-set-up root [`Vm`] directly until the guest issues the
    /// ready hypercall, then create the initial checkpoint at that point.
    ///
    /// This is the usual constructor for Linux workload exploration: the VM is
    /// booted without forking, which matches `bedrock-cli`'s startup path, and
    /// only the ready guest is handed to the lab for branching. `deadline`
    /// bounds the boot in virtual time and must use
    /// [`bedrock_vm::DEFAULT_TSC_FREQUENCY`]; use
    /// [`Checkpoint::initial_when_ready_with`] to pick a different rate.
    ///
    /// The VM must already have its kernel/initramfs loaded and
    /// [`Vm::setup_linux_boot`](bedrock_vm::Vm::setup_linux_boot) applied.
    /// The guest must eventually issue `HYPERCALL_READY`; otherwise this
    /// returns an error when the deadline is reached or on any unexpected VM
    /// exit. Serial output and feedback-buffer registrations before ready are
    /// emitted through the configured [`EventSink`] using reserved
    /// [`BranchId(0)`](crate::BranchId), and the ready checkpoint inherits any
    /// feedback-buffer registrations.
    pub fn initial_when_ready(vm: Vm, deadline: VirtTime) -> Result<Self> {
        Self::initial_when_ready_with(vm, deadline, LabOpts::default())
    }

    /// One-stop ready constructor that takes a [`LabOpts`] for everything
    /// configurable about the tree.
    ///
    /// If `opts.rng` is [`RngMode::Seeded`] or [`RngMode::Source`], the VM's
    /// `RDRAND`/`RDSEED` mode is configured before the root VM is first run.
    /// If `opts.rng` is [`RngMode::Source`], the userspace source is not
    /// consumed during the root boot; root boot simply exits to userspace if
    /// the guest executes `RDRAND`/`RDSEED` before ready.
    pub fn initial_when_ready_with(mut vm: Vm, deadline: VirtTime, opts: LabOpts) -> Result<Self> {
        Self::check_frequency(deadline.frequency(), opts.tsc_frequency)?;
        let (mut opts, input_source) = Self::configure_rng(&vm, opts)?;
        // The guest downloads its workload files (compose.yaml / images.tar)
        // over `HYPERCALL_FILE_FETCH` during boot, before it issues
        // `HYPERCALL_READY`. Serve them from the host paths the caller supplied.
        // Take them out of `opts` (which is moved into the checkpoint below);
        // they need not persist past boot.
        let mut file_server = FileServer::new(std::mem::take(&mut opts.files));
        // Capture guest console output as `Serial` event records during boot,
        // the same channel branches use; the root VM gets reserved `BranchId(0)`.
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
        } = opts;

        let lab = LabInner::new(tsc_frequency, sink);
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

    /// Fork a fresh [`Branch`] from this checkpoint.
    ///
    /// Multiple branches can be forked from the same checkpoint; each gets
    /// its own COW VM, its own clone of any userspace input source, and
    /// explores forward independently. Two sibling branches see the same
    /// input stream regardless of the order in which they're driven.
    pub fn branch(&self) -> Result<Branch> {
        let input_source = self.inner.input_source.as_ref().map(|s| s.clone_box());
        self.branch_inner(input_source, false)
    }

    /// Fork a branch that *overrides* the checkpoint's userspace input
    /// source, regardless of the tree's original [`RngMode`](crate::RngMode).
    ///
    /// The source can provide both RDRAND/RDSEED values and caller-consumed
    /// I/O inputs. Intended for fuzzing loops: snapshot the guest at a
    /// "ready" point once, then call this per iteration with the next input
    /// wrapped in an [`InputSource`] so each iteration sees fresh bytes. The
    /// override forces the kernel into exit-to-userspace mode on the new
    /// branch's VM — descendants of *this* branch then inherit that mode via
    /// the usual VM-state COW.
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
        // Forked VMs start with the event stream disabled; turn on the lab's
        // always-on capture (SERIAL, plus the input-recording categories for a
        // sourced branch) from the first instruction.
        branch.enable_event_capture()?;
        Ok(branch)
    }

    /// Logical parent checkpoint in the lab tree, if any. `None` for the root.
    ///
    /// This is the user-facing ancestry used by [`Tree`](crate::Tree). It may
    /// differ from the underlying VM replay parent for checkpoints created by
    /// [`Checkpoint::rewind`].
    pub fn parent(&self) -> Option<Checkpoint> {
        self.inner
            .lab
            .graph
            .lock()
            .unwrap()
            .parent(self.inner.id)
            .map(|inner| Checkpoint { inner })
    }

    /// Take a new [`Checkpoint`] at `self.time() - by`.
    ///
    /// Walks `self`'s ancestry for the latest checkpoint whose time is at or
    /// before the target, forks a fresh VM from it, replays forward to the
    /// exact target time, and freezes the result into a new checkpoint.
    ///
    /// If a logical ancestor checkpoint or a prior rewind-created checkpoint
    /// already sits at exactly the target time, that checkpoint is returned
    /// directly without replaying or adding a new node.
    ///
    /// Errors with [`LabError::NoCheckpointBefore`] if no ancestor checkpoint
    /// is early enough.
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
