// SPDX-License-Identifier: GPL-2.0

//! Branches — live lines of execution.

use std::sync::Arc;

use bedrock_vm::events::EventKind;
use bedrock_vm::file_store::FileWriter;
use bedrock_vm::fuzz_input::{FuzzOutcome, InputServer};
use bedrock_vm::{
    EventCategories, EventConfig as VmEventConfig, EventStream, ExitKind, ExitTrigger, Vm, VmError,
};

use crate::bash::{self, BashOutput, BashTarget};
use crate::checkpoint::{Checkpoint, CheckpointId, CheckpointInner};
use crate::error::{LabError, Result};
use crate::event::{emit_feedback_buffer_registered, serial_record_into_sink, Event, PartialLine};
use crate::inner::{BranchMeta, LabInner};
use crate::rng::{InputRecording, InputSource, IoInput};
use crate::time::{VirtDuration, VirtTime};
use crate::tree::Tree;

/// Event categories forced on while a branch has an [`InputSource`]: its
/// [`InputRecording`] is reconstructed from these records, so they are captured
/// even when the caller's [`EventConfig`] asks for nothing.
const RECORDING_CATEGORIES: EventCategories =
    EventCategories::RANDOMNESS.union(EventCategories::IO_CHANNEL);

/// Which VM exits emit an `Exit` record. Anything other than
/// [`Disabled`](Self::Disabled) turns on the [`EXIT`](EventCategories::EXIT) category.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ExitCapture {
    /// Don't emit `Exit` records.
    #[default]
    Disabled,
    /// Emit a record for every exit. `memory_hash` adds a (slow) full
    /// guest-memory hash to each record.
    AllExits { memory_hash: bool },
    /// Emit one record every `interval` emulated-TSC ticks.
    Checkpoints { interval: u64, memory_hash: bool },
    /// Emit a single record at guest shutdown.
    AtShutdown { memory_hash: bool },
}

impl ExitCapture {
    /// Decompose into `(trigger, target_tsc, memory_hash)`; `target_tsc` is the
    /// `Checkpoints` interval (0 otherwise).
    fn to_trigger(self) -> (ExitTrigger, u64, bool) {
        match self {
            ExitCapture::Disabled => (ExitTrigger::Disabled, 0, false),
            ExitCapture::AllExits { memory_hash } => (ExitTrigger::AllExits, 0, memory_hash),
            ExitCapture::Checkpoints {
                interval,
                memory_hash,
            } => (ExitTrigger::Checkpoints, interval, memory_hash),
            ExitCapture::AtShutdown { memory_hash } => (ExitTrigger::AtShutdown, 0, memory_hash),
        }
    }
}

/// What a branch captures into its event stream: the category mask plus the
/// `Exit`-record trigger policy. `Default` captures nothing.
///
/// The [`EXIT`](EventCategories::EXIT) category is governed entirely by
/// [`exits`](Self::exits), never by [`categories`](Self::categories):
///
/// ```ignore
/// // Randomness only (a cheap determinism input):
/// branch.set_event_config(&EventConfig {
///     categories: EventCategories::RANDOMNESS,
///     ..Default::default()
/// })?;
///
/// // Every exit, no memory hashing:
/// branch.set_event_config(&EventConfig {
///     exits: ExitCapture::AllExits { memory_hash: false },
///     ..Default::default()
/// })?;
/// ```
#[derive(Clone, Copy, Debug, Default)]
pub struct EventConfig {
    /// Non-exit kinds to capture. Any [`EXIT`](EventCategories::EXIT) bit set
    /// here is ignored.
    pub categories: EventCategories,
    /// `Exit`-record trigger policy.
    pub exits: ExitCapture,
}

impl EventConfig {
    /// `categories` with the `EXIT` bit forced to match `exits`.
    fn effective_categories(&self) -> EventCategories {
        let non_exit = EventCategories(self.categories.0 & !EventCategories::EXIT.0);
        if self.exits == ExitCapture::Disabled {
            non_exit
        } else {
            non_exit.union(EventCategories::EXIT)
        }
    }

    /// Lower to the kernel ioctl payload, OR-ing in `extra` categories. An empty
    /// mask yields a disabled config (frees the buffer).
    fn to_vm_config_with(self, extra: EventCategories) -> VmEventConfig {
        let categories = self.effective_categories().union(extra);
        if categories == EventCategories::empty() {
            return VmEventConfig::disabled();
        }
        let (trigger, target_tsc, memory_hash) = self.exits.to_trigger();
        let mut config = VmEventConfig::enabled(categories).with_exit_trigger(trigger, target_tsc);
        if !memory_hash {
            config = config.with_no_memory_hash();
        }
        config
    }
}

/// A stable identifier for a branch within its tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BranchId(pub(crate) u64);

/// Why a [`Branch::run_until`] call paused.
#[derive(Debug, Clone)]
pub enum RunOutcome {
    /// The branch reached the requested virtual time.
    ReachedTime,
    /// The guest issued the ready hypercall.
    Ready,
    /// A scheduled bash command's response arrived.
    ActionResponse { output: BashOutput },
    /// The attached [`InputSource`](crate::InputSource) ran out of randomness.
    /// The branch is paused on the trapping instruction; running again re-traps.
    RngExhausted,
    /// The VM exited for a reason the lab did not handle internally.
    Yielded { kind: ExitKind },
}

/// A live line of execution descending from a [`Checkpoint`].
///
/// An owning, single-driver handle. To preserve a moment for later forking or
/// rewinding, call [`Branch::checkpoint`], which consumes the branch.
pub struct Branch {
    id: BranchId,
    origin: Checkpoint,
    /// `None` only inside `checkpoint(self)` after the VM moved out.
    vm: Option<Vm>,
    current_time: VirtTime,
    lab: Arc<LabInner>,
    /// Unterminated serial line bytes, seeded from the origin checkpoint so a
    /// line straddling `Branch::checkpoint` is emitted once.
    partial: PartialLine,
    /// Private clone of the tree's input source; moves into the checkpoint on
    /// [`Branch::checkpoint`] so descendants start from the consumed state.
    input_source: Option<Box<dyn InputSource>>,
    /// Next source I/O action not yet queued (beyond the run target, or the VM
    /// queue was full).
    pending_input_io: Option<IoInput>,
    input_io_exhausted: bool,
    input_recording: InputRecording,
    /// Cache of the last `vm.set_stop_at_tsc` value; `None` = unknown
    /// (post-fork), so the next `set_stop_at` always sends the ioctl.
    last_stop_at: Option<Option<u64>>,
    /// Restored by [`Branch::disable_single_step`].
    event_config: EventConfig,
    /// Extracts files from the guest to the host.
    file_writer: FileWriter,
    /// Serves fuzzer testcases into the guest's registered `fuzz-input`
    /// buffer.
    input_server: InputServer,
}

impl Branch {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        id: BranchId,
        origin: Checkpoint,
        vm: Vm,
        current_time: VirtTime,
        lab: Arc<LabInner>,
        partial: PartialLine,
        input_source: Option<Box<dyn InputSource>>,
        pending_input_io: Option<IoInput>,
        input_io_exhausted: bool,
        input_recording: InputRecording,
    ) -> Self {
        lab.live_branches.lock().unwrap().insert(
            id,
            BranchMeta {
                id,
                origin: origin.id(),
                current_time,
            },
        );
        let origin_id = origin.id();
        let branch = Self {
            id,
            origin,
            vm: Some(vm),
            current_time,
            lab: lab.clone(),
            partial,
            input_source,
            pending_input_io,
            input_io_exhausted,
            input_recording,
            last_stop_at: None,
            event_config: EventConfig::default(),
            file_writer: FileWriter::new(),
            input_server: InputServer::new(),
        };
        lab.sink.on_event(Event::BranchCreated {
            branch: id,
            origin: origin_id,
            at: current_time,
        });
        branch
    }

    fn vm_mut(&mut self) -> &mut Vm {
        self.vm.as_mut().expect("Branch.vm taken")
    }

    fn vm(&self) -> &Vm {
        self.vm.as_ref().expect("Branch.vm taken")
    }

    pub fn id(&self) -> BranchId {
        self.id
    }

    /// The branch's current virtual time (the emulated TSC of its VM).
    pub fn current_time(&self) -> VirtTime {
        self.current_time
    }

    pub fn tsc_frequency(&self) -> u64 {
        self.lab.tsc_frequency
    }

    /// The checkpoint this branch was forked from.
    pub fn origin(&self) -> &Checkpoint {
        &self.origin
    }

    /// Configure the event stream (see [`EventConfig`]). Records are forwarded
    /// to the tree's [`EventSink`](crate::EventSink) as [`Event::Record`].
    ///
    /// With an [`InputSource`] attached, `RANDOMNESS` and `IO_CHANNEL` stay on
    /// regardless of `config` so input recording keeps working.
    pub fn set_event_config(&mut self, config: &EventConfig) -> Result<()> {
        self.event_config = *config;
        self.apply_event_config()
    }

    /// Install `event_config` plus the always-on categories: `SERIAL` (for
    /// [`Event::SerialLine`]) and, with an input source, `RECORDING_CATEGORIES`.
    /// Every path that (re)installs the capture config must go through here.
    fn apply_event_config(&mut self) -> Result<()> {
        let mut extra = EventCategories::SERIAL;
        if self.input_source.is_some() {
            extra = extra.union(RECORDING_CATEGORIES);
        }
        let vm_config = self.event_config.to_vm_config_with(extra);
        self.send_event_config(&vm_config)
    }

    /// Called once at branch creation: forked VMs start with the event stream
    /// disabled, so this turns on the always-on categories.
    pub(crate) fn enable_event_capture(&mut self) -> Result<()> {
        self.apply_event_config()
    }

    fn send_event_config(&mut self, config: &VmEventConfig) -> Result<()> {
        self.vm_mut().set_event_config(config).map_err(|source| {
            LabError::Vm(VmError::Ioctl {
                operation: "SET_EVENT_CONFIG",
                source,
            })
        })
    }

    /// Single-step (MTF) within virtual time `[start, end)`, emitting an `Exit`
    /// record for every instruction in the window.
    ///
    /// Temporarily overrides [`set_event_config`](Self::set_event_config);
    /// [`disable_single_step`](Self::disable_single_step) restores it. Costs ~1
    /// vmexit per guest instruction, so keep the range small.
    pub fn single_step(&mut self, start: VirtTime, end: VirtTime) -> Result<()> {
        self.check_freq(start.frequency())?;
        self.check_freq(end.frequency())?;
        if end < start {
            return Err(LabError::TargetInPast {
                current: start,
                target: end,
            });
        }
        self.vm_mut()
            .set_single_step_range(start.instructions(), end.instructions())
            .map_err(|source| {
                LabError::Vm(VmError::Ioctl {
                    operation: "SET_SINGLE_STEP",
                    source,
                })
            })?;
        // No memory hashing: it would dominate run time, and register state
        // already pins down divergence at instruction granularity.
        let mut categories = EventCategories::EXIT.union(EventCategories::SERIAL);
        if self.input_source.is_some() {
            categories = categories.union(RECORDING_CATEGORIES);
        }
        let config = VmEventConfig::enabled(categories)
            .with_exit_trigger(ExitTrigger::TscRange, 0)
            .with_no_memory_hash();
        self.send_event_config(&config)
    }

    /// Disable single-step and restore the prior
    /// [`set_event_config`](Self::set_event_config) capture.
    pub fn disable_single_step(&mut self) -> Result<()> {
        self.vm_mut().disable_single_step().map_err(|source| {
            LabError::Vm(VmError::Ioctl {
                operation: "SET_SINGLE_STEP",
                source,
            })
        })?;
        self.apply_event_config()
    }

    fn check_freq(&self, freq: u64) -> Result<()> {
        if freq != self.lab.tsc_frequency {
            return Err(LabError::FrequencyMismatch {
                lhs: freq,
                rhs: self.lab.tsc_frequency,
            });
        }
        Ok(())
    }

    /// Cached `vm.set_stop_at_tsc`: `run_until` calls this every iteration, so
    /// skipping unchanged values saves one ioctl per VM exit.
    fn set_stop_at(&mut self, value: Option<u64>) -> Result<()> {
        if self.last_stop_at == Some(value) {
            return Ok(());
        }
        self.vm_mut().set_stop_at_tsc(value).map_err(|source| {
            LabError::Vm(VmError::Ioctl {
                operation: "SET_STOP_TSC",
                source,
            })
        })?;
        self.last_stop_at = Some(value);
        Ok(())
    }

    /// Update `current_time` and mirror it into the lab's live-branch map.
    fn advance_time(&mut self, t: VirtTime) {
        self.current_time = t;
        if let Some(m) = self.lab.live_branches.lock().unwrap().get_mut(&self.id) {
            m.current_time = t;
        }
    }

    /// Drain the event stream after a `vm.run()`. `Serial` records become
    /// [`Event::SerialLine`]s; all others feed the
    /// [`InputRecording`](Self::input_recording) (only while a source is
    /// attached) and are forwarded as [`Event::Record`].
    ///
    /// `event_len` is `VmExit::event_len`, which is per-call: the kernel resets
    /// the event cursor at the start of every `vm.run()` ioctl.
    fn drain_events(&mut self, event_len: usize) {
        if event_len == 0 {
            return;
        }
        // Disjoint field borrows: read the buffer inside `vm` while mutating
        // `input_recording` and `partial`.
        let Self {
            vm,
            lab,
            id,
            input_source,
            input_recording,
            partial,
            ..
        } = self;
        let vm = vm.as_ref().expect("Branch.vm taken");
        let Some(buffer) = vm.event_buffer() else {
            return;
        };
        let drained = &buffer[..event_len.min(buffer.len())];
        let record_inputs = input_source.is_some();
        let freq = lab.tsc_frequency;
        for record in EventStream::new(drained) {
            if record.kind() == EventKind::Serial.as_u16() {
                serial_record_into_sink(
                    record.payload,
                    record.tsc(),
                    freq,
                    *id,
                    lab.sink.as_ref(),
                    partial,
                );
                continue;
            }
            if record_inputs {
                input_recording.record_event(&record, freq);
            }
            lab.sink.on_event(Event::Record {
                branch: *id,
                record,
            });
        }
    }

    /// Emit an [`Event::FeedbackBufferRegistered`] after a (successful)
    /// registration exit. Surfaced only as an event, never as a [`RunOutcome`].
    fn on_feedback_buffer_registered(&mut self, at: VirtTime) -> Result<()> {
        emit_feedback_buffer_registered(
            self.vm.as_ref().expect("Branch.vm taken"),
            at,
            self.id,
            self.lab.sink.as_ref(),
        )?;
        Ok(())
    }

    /// Every feedback buffer registered under `id`, in ascending slot order.
    ///
    /// IDs are not unique: several guest processes may register under the same
    /// id (typically a build-id), and the caller merges the slices (usually
    /// byte-wise OR). Slots are lazily mmapped and cached for the branch's
    /// lifetime; each fork sees its own copy-on-write view.
    pub fn feedback_buffers(&mut self, id: &[u8]) -> Result<Vec<&[u8]>> {
        let vm = self.vm.as_mut().expect("Branch.vm taken");
        let slots = vm.feedback_buffer_slots_for_id(id)?;
        for &slot in &slots {
            if vm.feedback_buffer_at(slot).is_none() {
                vm.map_feedback_buffer_at(slot)?;
            }
        }
        // Second loop so the mutable borrow is released before handing out
        // shared references.
        let mut out = Vec::with_capacity(slots.len());
        for &slot in &slots {
            if let Some(bytes) = vm.feedback_buffer_at(slot) {
                out.push(bytes);
            }
        }
        Ok(out)
    }

    /// Owned-copy variant of [`feedback_buffers`](Self::feedback_buffers).
    pub fn feedback_buffers_to_vec(&mut self, id: &[u8]) -> Result<Vec<Vec<u8>>> {
        Ok(self
            .feedback_buffers(id)?
            .into_iter()
            .map(|s| s.to_vec())
            .collect())
    }

    /// Write one fuzzer testcase into the guest's registered `fuzz-input`
    /// buffer.
    pub fn serve_fuzz_input(&mut self, input: &[u8]) -> Result<()> {
        let vm = self.vm.as_mut().expect("Branch.vm taken");
        self.input_server.serve(vm, input).map_err(LabError::from)
    }

    /// Read back what the guest reported about the testcase it just finished.
    pub fn fuzz_outcome(&mut self) -> Result<FuzzOutcome> {
        let vm = self.vm.as_mut().expect("Branch.vm taken");
        self.input_server.outcome(vm).map_err(LabError::from)
    }

    /// The largest testcase the guest's input buffer can hold in bytes.
    pub fn fuzz_input_capacity(&mut self) -> Result<usize> {
        let vm = self.vm.as_mut().expect("Branch.vm taken");
        self.input_server.capacity(vm).map_err(LabError::from)
    }

    /// Every distinct registered feedback-buffer id, in order of first slot.
    /// Issues one ioctl per slot.
    pub fn feedback_buffer_ids(&self) -> Result<Vec<Vec<u8>>> {
        let vm = self.vm.as_ref().expect("Branch.vm taken");
        let mut seen = std::collections::HashSet::new();
        let mut ids = Vec::new();
        // Registration is append-only and contiguous, so iterate until the
        // first unregistered slot.
        let mut slot = 0;
        while let Some(info) = vm.get_feedback_buffer_info_at(slot)? {
            let id = info.id_bytes().to_vec();
            if seen.insert(id.clone()) {
                ids.push(id);
            }
            slot += 1;
        }
        Ok(ids)
    }

    /// Run until virtual time reaches `target`, returning where and why the
    /// branch paused. Errors with [`LabError::TargetInPast`] if `target` is
    /// before [`Branch::current_time`]; use [`Checkpoint::rewind`] to go back.
    pub fn run_until(&mut self, target: VirtTime) -> Result<(VirtTime, RunOutcome)> {
        self.check_freq(target.frequency())?;
        if target < self.current_time {
            return Err(LabError::TargetInPast {
                current: self.current_time,
                target,
            });
        }
        if target == self.current_time {
            return Ok((target, RunOutcome::ReachedTime));
        }

        loop {
            let stop_at = self.prepare_next_io_input(target)?;
            self.set_stop_at(Some(stop_at.instructions()))?;
            let exit = self.vm_mut().run().map_err(|source| {
                LabError::Vm(VmError::Ioctl {
                    operation: "RUN",
                    source,
                })
            })?;
            let at = VirtTime::from_instructions(exit.emulated_tsc, self.lab.tsc_frequency);
            self.advance_time(at);
            self.drain_events(exit.event_len as usize);
            match exit.kind() {
                ExitKind::StopTscReached => {
                    if at >= target {
                        return Ok((at, RunOutcome::ReachedTime));
                    }
                    continue;
                }
                ExitKind::VmcallReady => return Ok((at, RunOutcome::Ready)),
                ExitKind::IoResponse => {
                    let bytes = self.vm_mut().drain_io_response().map_err(|source| {
                        LabError::Vm(VmError::Ioctl {
                            operation: "DRAIN_IO_RESPONSE",
                            source,
                        })
                    })?;
                    let output = self.bash_output_from_response(&bytes)?;
                    return Ok((at, RunOutcome::ActionResponse { output }));
                }
                ExitKind::FeedbackBufferRegistered => {
                    self.on_feedback_buffer_registered(at)?;
                    continue;
                }
                ExitKind::Rdrand | ExitKind::Rdseed => match self.feed_rng()? {
                    FeedRng::Fed => continue,
                    FeedRng::Exhausted => return Ok((at, RunOutcome::RngExhausted)),
                    FeedRng::NoSource => {
                        return Ok((at, RunOutcome::Yielded { kind: exit.kind() }))
                    }
                },
                ExitKind::VmcallGetRandom => match self.feed_random()? {
                    FeedRng::Fed => continue,
                    FeedRng::Exhausted => return Ok((at, RunOutcome::RngExhausted)),
                    FeedRng::NoSource => {
                        return Ok((at, RunOutcome::Yielded { kind: exit.kind() }))
                    }
                },
                ExitKind::FileStore => {
                    let vm = self.vm.as_mut().expect("Branch.vm taken");
                    self.file_writer
                        .write(vm)
                        .map_err(|source| LabError::FileStoreFailed { at, source })?;
                    continue;
                }
                ExitKind::Continue | ExitKind::EventBufferFull => continue,
                kind => return Ok((at, RunOutcome::Yielded { kind })),
            }
        }
    }

    /// [`run_until`](Self::run_until) `current_time + by`.
    pub fn run_for(&mut self, by: VirtDuration) -> Result<(VirtTime, RunOutcome)> {
        self.run_until(self.current_time + by)
    }

    /// Queue an I/O action and run until its raw response arrives.
    fn run_io_action(&mut self, request: &[u8]) -> Result<Vec<u8>> {
        // A leftover stop_at_tsc could otherwise fire before the response.
        self.set_stop_at(None)?;
        self.vm_mut()
            .queue_io_action(request, 0)
            .map_err(|source| {
                LabError::Vm(VmError::Ioctl {
                    operation: "QUEUE_IO_ACTION",
                    source,
                })
            })?;
        loop {
            let exit = self.vm_mut().run().map_err(|source| {
                LabError::Vm(VmError::Ioctl {
                    operation: "RUN",
                    source,
                })
            })?;
            let at = VirtTime::from_instructions(exit.emulated_tsc, self.lab.tsc_frequency);
            self.advance_time(at);
            self.drain_events(exit.event_len as usize);
            match exit.kind() {
                ExitKind::IoResponse => {
                    return self.vm_mut().drain_io_response().map_err(|source| {
                        LabError::Vm(VmError::Ioctl {
                            operation: "DRAIN_IO_RESPONSE",
                            source,
                        })
                    })
                }
                ExitKind::FeedbackBufferRegistered => {
                    self.on_feedback_buffer_registered(at)?;
                    continue;
                }
                ExitKind::FileStore => {
                    let vm = self.vm.as_mut().expect("Branch.vm taken");
                    self.file_writer
                        .write(vm)
                        .map_err(|source| LabError::FileStoreFailed { at, source })?;
                    continue;
                }
                ExitKind::Rdrand | ExitKind::Rdseed => match self.feed_rng()? {
                    FeedRng::Fed => continue,
                    FeedRng::Exhausted | FeedRng::NoSource => {
                        return Err(LabError::UnexpectedExit {
                            at,
                            kind: exit.kind(),
                        })
                    }
                },
                ExitKind::Continue | ExitKind::EventBufferFull | ExitKind::VmcallReady => continue,
                kind => return Err(LabError::UnexpectedExit { at, kind }),
            }
        }
    }

    /// Stage the source's next RNG `u64` so the next `vm.run()` re-executes the
    /// trapped `RDRAND`/`RDSEED` with it. Recording happens via the resulting
    /// `Randomness` event in [`drain_events`](Self::drain_events).
    fn feed_rng(&mut self) -> Result<FeedRng> {
        let Some(source) = self.input_source.as_mut() else {
            return Ok(FeedRng::NoSource);
        };
        let Some(value) = source.next_rng_u64() else {
            return Ok(FeedRng::Exhausted);
        };
        self.vm_mut().set_rdrand_value(value).map_err(|source| {
            LabError::Vm(VmError::Ioctl {
                operation: "SET_RDRAND_VALUE",
                source,
            })
        })?;
        Ok(FeedRng::Fed)
    }

    /// Serve a pending `HYPERCALL_GET_RANDOM` request (guest `getrandom()`)
    /// from the [`InputSource`], staging the bytes for the re-executed VMCALL.
    /// Recording happens via the stream's `Randomness` record, as in `feed_rng`.
    fn feed_random(&mut self) -> Result<FeedRng> {
        let req = self.vm_mut().random_request().map_err(|source| {
            LabError::Vm(VmError::Ioctl {
                operation: "GET_RANDOM_REQUEST",
                source,
            })
        })?;
        let len = req.len as usize;
        let pid = req.pid;

        let bytes = {
            let Some(source) = self.input_source.as_mut() else {
                return Ok(FeedRng::NoSource);
            };
            source.next_random(len, pid)
        };

        self.vm_mut().set_random_bytes(&bytes).map_err(|source| {
            LabError::Vm(VmError::Ioctl {
                operation: "SET_RANDOM_BYTES",
                source,
            })
        })?;
        Ok(FeedRng::Fed)
    }

    /// Queue the next source-provided bash action once its virtual time is
    /// reached, returning the next stop hint (the following input's time,
    /// capped at `target`). Two actions at the same time both get queued: the
    /// second iteration fires immediately since `B.at == current_time`.
    fn prepare_next_io_input(&mut self, target: VirtTime) -> Result<VirtTime> {
        if self.input_io_exhausted {
            return Ok(target);
        }

        if self.pending_input_io.is_none() {
            let Some(source) = self.input_source.as_mut() else {
                return Ok(target);
            };
            self.pending_input_io = source.next_io_input();
            if self.pending_input_io.is_none() {
                self.input_io_exhausted = true;
                return Ok(target);
            }
        }

        let input = self
            .pending_input_io
            .as_ref()
            .expect("pending_input_io was set above");
        self.check_freq(input.at.frequency())?;
        if input.at > target {
            return Ok(target);
        }
        if input.at > self.current_time {
            return Ok(input.at);
        }

        let input = self
            .pending_input_io
            .take()
            .expect("pending_input_io was checked above");
        let request = bash::encode_request(&input.target, &input.command, input.record_output);
        match self.vm().queue_io_action(&request, 0) {
            // Recorded later from its `IoChannel` event, not at queue time.
            Ok(()) => {}
            Err(source) if source.kind() == std::io::ErrorKind::ResourceBusy => {
                self.pending_input_io = Some(input);
                return Ok(target);
            }
            Err(source) => {
                return Err(LabError::QueueInputIo {
                    at: input.at,
                    target: input.target,
                    command: input.command,
                    source,
                })
            }
        }

        // Stop at the next input's time so StopTscReached re-enters here.
        let Some(source) = self.input_source.as_mut() else {
            return Ok(target);
        };
        self.pending_input_io = source.next_io_input();
        match self.pending_input_io.as_ref() {
            None => {
                self.input_io_exhausted = true;
                Ok(target)
            }
            Some(next) => {
                self.check_freq(next.at.frequency())?;
                Ok(next.at.min(target))
            }
        }
    }

    /// Pull the next I/O input from the source. It is not queued; callers may
    /// pass it to [`Self::sched_bash`].
    pub fn next_io_input(&mut self) -> Option<IoInput> {
        self.input_source.as_mut()?.next_io_input()
    }

    /// Inputs consumed by this branch so far.
    pub fn input_recording(&self) -> &InputRecording {
        &self.input_recording
    }

    /// Clone this branch's consumed-input recording for replay elsewhere.
    pub fn input_recording_to_source(&self) -> crate::RecordedInputSource {
        crate::RecordedInputSource::new(self.input_recording.clone())
    }

    /// Run a bash command (on the guest host or in a container) and block until
    /// it responds; virtual time advances meanwhile. Requires `bedrock-io.ko`.
    ///
    /// With [`sched_bash`](Self::sched_bash) actions still pending, the response
    /// may be for one of those — drain them via `run_until` first.
    ///
    /// Output always goes to the guest journal; with `record_output` it is also
    /// returned in [`BashOutput::output`].
    pub fn bash(
        &mut self,
        target: BashTarget,
        cmd: &str,
        record_output: bool,
    ) -> Result<BashOutput> {
        let request = bash::encode_request(&target, cmd, record_output);
        let bytes = self.run_io_action(&request)?;
        self.bash_output_from_response(&bytes)
    }

    /// Schedule a bash command at virtual time `at`; the response arrives as
    /// [`RunOutcome::ActionResponse`]. `at == 0` means "as soon as the guest is
    /// interruptible".
    pub fn sched_bash(
        &mut self,
        at: VirtTime,
        target: BashTarget,
        cmd: &str,
        record_output: bool,
    ) -> Result<()> {
        self.check_freq(at.frequency())?;
        let request = bash::encode_request(&target, cmd, record_output);
        self.vm_mut().queue_io_action(&request, at.instructions())?;
        Ok(())
    }

    /// Decode an I/O channel response and, when the command recorded its
    /// output, read it back from the output feedback buffer.
    fn bash_output_from_response(&mut self, resp: &[u8]) -> Result<BashOutput> {
        let r = bedrock_vm::io_channel::decode_response(resp)
            .ok_or_else(|| LabError::BadResponse("malformed I/O channel response".to_string()))?;
        let output = if r.output_len > 0 {
            let want = r.output_len as usize;
            let bufs = self.feedback_buffers(bedrock_vm::io_channel::IO_OUTPUT_BUFFER_ID)?;
            bufs.first()
                .map(|b| b[..want.min(b.len())].to_vec())
                .unwrap_or_default()
        } else {
            Vec::new()
        };
        Ok(BashOutput {
            status: r.status,
            // `r.exit_code` is a raw wait-status from call_usermodehelper.
            exit_code: bedrock_vm::io_channel::exit_code_from_wait_status(r.exit_code),
            output,
        })
    }

    /// Consume this branch into an immutable [`Checkpoint`] whose VM becomes
    /// the frozen fork source; continue via [`Checkpoint::branch`].
    pub fn checkpoint(mut self) -> Result<Checkpoint> {
        let vm = self.vm.take().expect("Branch.vm taken");
        let id = CheckpointId(self.lab.next_checkpoint_id());
        let time = self.current_time;
        let parent_id = self.origin.id();
        let from_branch = self.id;
        let inner = Arc::new(CheckpointInner {
            id,
            time,
            vm,
            _vm_parent: Some(Arc::downgrade(&self.origin.inner)),
            lab: self.lab.clone(),
            partial_line: core::mem::take(&mut self.partial),
            input_source: self.input_source.take(),
            pending_input_io: self.pending_input_io.take(),
            input_io_exhausted: self.input_io_exhausted,
            input_recording: core::mem::take(&mut self.input_recording),
        });
        self.lab
            .graph
            .lock()
            .unwrap()
            .register_checkpoint(&inner, Some(parent_id));
        self.lab.sink.on_event(Event::CheckpointCreated {
            checkpoint: id,
            from_branch: Some(from_branch),
            parent: Some(parent_id),
            at: time,
        });
        Ok(Checkpoint { inner })
        // self drops here, removing this branch from lab.live_branches.
    }

    /// Take a read-only snapshot of the entire tree this branch belongs to.
    pub fn tree(&self) -> Tree {
        Tree::from_lab(&self.lab)
    }
}

/// Outcome of [`Branch::feed_rng`].
enum FeedRng {
    Fed,
    /// No userspace source (kernel-side RDRAND mode).
    NoSource,
    Exhausted,
}

impl Drop for Branch {
    fn drop(&mut self) {
        if let Ok(mut live) = self.lab.live_branches.lock() {
            live.remove(&self.id);
        }
    }
}

impl std::fmt::Debug for Branch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Branch")
            .field("id", &self.id)
            .field("current_time", &self.current_time)
            .finish()
    }
}
