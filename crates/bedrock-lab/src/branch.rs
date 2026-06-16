// SPDX-License-Identifier: GPL-2.0

//! Branches — live lines of execution.

use std::sync::Arc;

use bedrock_vm::events::EventKind;
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

/// Event categories the lab forces on while a branch has an [`InputSource`]
/// attached. The deterministic *inputs* a branch consumes — served RDRAND/RDSEED
/// values and queued I/O requests — are reconstructed from these records into
/// the branch's [`InputRecording`], so they must be captured even when the
/// caller's [`EventConfig`] asks for nothing. They are cheap: one small record
/// per consumed input, far below the cost of `Exit` capture.
const RECORDING_CATEGORIES: EventCategories =
    EventCategories::RANDOMNESS.union(EventCategories::IO_CHANNEL);

/// `Exit`-record trigger policy for a branch — which VM exits emit an `Exit`
/// event into the stream. Set as the [`exits`](EventConfig::exits) field of an
/// [`EventConfig`]: choosing anything other than [`Disabled`](Self::Disabled)
/// turns on the [`EXIT`](EventCategories::EXIT) category and decides which exits
/// emit a record.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ExitCapture {
    /// Don't emit `Exit` records.
    #[default]
    Disabled,
    /// Emit a record for every exit. `memory_hash` adds a full guest-memory
    /// hash to each record — thorough for divergence detection but slow;
    /// disable it when register and device-state hashes are enough.
    AllExits { memory_hash: bool },
    /// Emit one record every `interval` emulated-TSC ticks.
    Checkpoints { interval: u64, memory_hash: bool },
    /// Emit a single record at guest shutdown.
    AtShutdown { memory_hash: bool },
}

impl ExitCapture {
    /// Decompose into the kernel trigger fields: `(trigger, target_tsc, memory_hash)`.
    /// `target_tsc` is the `Checkpoints` interval (0 for the other policies);
    /// `memory_hash` is whether to hash full guest memory into each record.
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

/// What a branch captures into its unified event stream.
///
/// One config drives both halves of capture: the category mask (which kinds of
/// records to emit) and the `Exit`-record trigger policy. Apply it with
/// [`Branch::set_event_config`]. `Default` captures nothing.
///
/// The [`EXIT`](EventCategories::EXIT) category is governed entirely by
/// [`exits`](Self::exits) — you never set it in [`categories`](Self::categories).
/// Use `categories` for the cheap always-on-or-off kinds (`SERIAL`, `INJECT`,
/// `RANDOMNESS`, `IO_CHANNEL`) and `exits` for the heavyweight, policy-driven
/// `Exit` records:
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
    /// Non-exit kinds to capture: [`SERIAL`](EventCategories::SERIAL),
    /// [`INJECT`](EventCategories::INJECT),
    /// [`RANDOMNESS`](EventCategories::RANDOMNESS), and
    /// [`IO_CHANNEL`](EventCategories::IO_CHANNEL). Any
    /// [`EXIT`](EventCategories::EXIT) bit set here is ignored — exits are
    /// governed by [`exits`](Self::exits).
    pub categories: EventCategories,
    /// `Exit`-record trigger policy. Anything other than
    /// [`ExitCapture::Disabled`] (the default) turns on the `EXIT` category.
    pub exits: ExitCapture,
}

impl EventConfig {
    /// The effective category mask sent to the kernel: `categories` with the
    /// `EXIT` bit forced to match `exits`.
    fn effective_categories(&self) -> EventCategories {
        let non_exit = EventCategories(self.categories.0 & !EventCategories::EXIT.0);
        if self.exits == ExitCapture::Disabled {
            non_exit
        } else {
            non_exit.union(EventCategories::EXIT)
        }
    }

    /// Lower to the kernel ioctl payload: the effective category mask (plus
    /// `extra`, which the lab uses to force on `RECORDING_CATEGORIES` for
    /// branches that reconstruct their [`InputRecording`](crate::InputRecording)
    /// from the stream) and the exit trigger fields. An empty mask yields a
    /// disabled config (frees the buffer); otherwise the stream is enabled with
    /// the exit trigger applied.
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

/// The outcome of a [`Branch::run_until`] call.
///
/// Returned alongside the [`VirtTime`] at which the branch paused — see
/// [`Branch::run_until`]'s return signature.
#[derive(Debug, Clone)]
pub enum RunOutcome {
    /// The branch reached the requested virtual time.
    ReachedTime,
    /// The guest signaled it has finished boot/initialization and is ready
    /// for host-driven workload (VMCALL with the ready hypercall).
    Ready,
    /// A scheduled bash command's response arrived. The branch is paused at
    /// the moment the response landed; call `run_until` again to keep going.
    ActionResponse { output: BashOutput },
    /// The guest executed `RDRAND`/`RDSEED` and the attached [`InputSource`](crate::InputSource)
    /// returned `None` — out of randomness. The branch is paused on the trapping instruction;
    /// Calling `run_until` again will just re-trap on the same instruction.
    RngExhausted,
    /// The VM exited for a reason the lab did not handle internally.
    Yielded { kind: ExitKind },
}

/// A live line of execution descending from a [`Checkpoint`].
///
/// `Branch` is an owning, single-driver handle: it cannot be cloned, and
/// execution-advancing methods take `&mut self`. To preserve a moment in time
/// for later forking or rewinding, call [`Branch::checkpoint`] — that consumes
/// the branch and returns a [`Checkpoint`] you can branch off of again or
/// [`Checkpoint::rewind`] from.
pub struct Branch {
    id: BranchId,
    origin: Checkpoint,
    /// `Some` while the branch is live. `None` only during `checkpoint(self)`
    /// after the VM has been moved into the new checkpoint; the value is
    /// dropped at end of scope without `Drop for Branch` needing to do
    /// anything.
    vm: Option<Vm>,
    current_time: VirtTime,
    lab: Arc<LabInner>,
    /// Bytes of the current serial line not yet terminated by `\n`. Seeded
    /// from the origin checkpoint so a line that straddles
    /// `Branch::checkpoint` is emitted as a single `Event::SerialLine`.
    partial: PartialLine,
    /// This branch's private clone of the tree's userspace input source.
    /// `Some` only when the tree was built with an input source. Moves into
    /// the new checkpoint on [`Branch::checkpoint`] so descendant branches
    /// start from the post-consumption state.
    input_source: Option<Box<dyn InputSource>>,
    /// Next source-provided I/O action not yet queued because it is beyond
    /// the current run target or the VM queue was full.
    pending_input_io: Option<IoInput>,
    /// True once `input_source.next_io_input()` has returned `None`.
    input_io_exhausted: bool,
    /// Inputs consumed along this branch's path.
    input_recording: InputRecording,
    /// Last value passed to `vm.set_stop_at_tsc`. `None` means the VM's
    /// current stop_at_tsc setting is unknown (post-fork, or never set on
    /// this branch); the next `set_stop_at` call always sends an ioctl.
    last_stop_at: Option<Option<u64>>,
    /// The capture config last set via [`Branch::set_event_config`]. Tracked so
    /// [`Branch::disable_single_step`] can restore it after the temporary
    /// single-step override. Defaults to "capture nothing".
    event_config: EventConfig,
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

    /// The checkpoint this branch was forked from. Fixed for the lifetime of
    /// the branch.
    pub fn origin(&self) -> &Checkpoint {
        &self.origin
    }

    /// Configure the unified event stream on this branch: which categories it
    /// captures and the `Exit`-record trigger policy, in one call (see
    /// [`EventConfig`]).
    ///
    /// Captured records are forwarded to the tree's [`EventSink`](crate::EventSink)
    /// as [`Event::Record`]. Forked VMs start with the stream disabled
    /// regardless of the parent's setting, so each branch enables it explicitly.
    ///
    /// On a branch with an [`InputSource`], the `RANDOMNESS` and `IO_CHANNEL`
    /// categories are always added on top of `config` so the branch's
    /// [`InputRecording`](crate::InputRecording) keeps being reconstructed from
    /// the stream — passing a `config` that omits them does not turn recording
    /// off.
    pub fn set_event_config(&mut self, config: &EventConfig) -> Result<()> {
        self.event_config = *config;
        self.apply_event_config()
    }

    /// Lower [`self.event_config`](Self::event_config) to the kernel, forcing on
    /// the lab's always-captured categories: `SERIAL` on every branch (so guest
    /// console output surfaces as [`Event::SerialLine`]), plus
    /// `RECORDING_CATEGORIES` while this branch has an [`InputSource`] so its
    /// [`InputRecording`](crate::InputRecording) can be reconstructed from the
    /// stream. Every path that (re)installs the branch's capture config goes
    /// through here so these categories are never accidentally dropped.
    fn apply_event_config(&mut self) -> Result<()> {
        let mut extra = EventCategories::SERIAL;
        if self.input_source.is_some() {
            extra = extra.union(RECORDING_CATEGORIES);
        }
        let vm_config = self.event_config.to_vm_config_with(extra);
        self.send_event_config(&vm_config)
    }

    /// Enable the lab's always-on event capture on a freshly forked branch:
    /// turn on `SERIAL` (for [`Event::SerialLine`]) and, when the branch carries
    /// an [`InputSource`], `RECORDING_CATEGORIES` (so consumed RDRAND/RDSEED
    /// values and I/O requests are captured into
    /// [`input_recording`](Self::input_recording)). Called once at branch
    /// creation. Forked VMs start with the stream disabled, so this is what
    /// turns it on.
    pub(crate) fn enable_event_capture(&mut self) -> Result<()> {
        self.apply_event_config()
    }

    /// Send a lowered kernel event config to the VM. Internal: the public
    /// surface is [`EventConfig`].
    fn send_event_config(&mut self, config: &VmEventConfig) -> Result<()> {
        self.vm_mut().set_event_config(config).map_err(|source| {
            LabError::Vm(VmError::Ioctl {
                operation: "SET_EVENT_CONFIG",
                source,
            })
        })
    }

    /// Enable single-step (MTF) execution within the half-open virtual time
    /// range `[start, end)`, capturing an `Exit` record for every instruction
    /// in the window.
    ///
    /// The kernel sets the VMCS Monitor-Trap-Flag whenever
    /// `emulated_tsc ∈ [start, end)`, so the guest exits after every retired
    /// instruction in that window and each one is emitted as an
    /// [`Event::Record`] — the highest-resolution divergence-debugging tool
    /// available. The event stream's `EXIT` category is enabled automatically.
    ///
    /// This is a temporary override of the branch's [`set_event_config`](Self::set_event_config)
    /// capture; [`disable_single_step`](Self::disable_single_step) restores it.
    ///
    /// Single-stepping is expensive (~1 vmexit per guest instruction); pick the
    /// smallest range that brackets the suspected divergence point. Disable with
    /// [`Self::disable_single_step`] when done.
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
        // Capture every exit within the range via the `TscRange` trigger. Memory
        // hashing on every single-stepped instruction would dominate run time
        // and adds no signal — register state already pins down divergence at
        // instruction granularity. Keep `SERIAL` on (and the input-recording
        // categories, when sourced) so console output and consumed randomness/IO
        // inside the window still surface.
        let mut categories = EventCategories::EXIT.union(EventCategories::SERIAL);
        if self.input_source.is_some() {
            categories = categories.union(RECORDING_CATEGORIES);
        }
        let config = VmEventConfig::enabled(categories)
            .with_exit_trigger(ExitTrigger::TscRange, 0)
            .with_no_memory_hash();
        self.send_event_config(&config)
    }

    /// Disable single-step execution and restore the branch's prior
    /// [`set_event_config`](Self::set_event_config) capture (which defaults to
    /// capturing nothing).
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

    /// Wrap `vm.set_stop_at_tsc` with a cache so we skip the ioctl when the
    /// value hasn't changed. Branch::run_until calls this every loop
    /// iteration; without the cache that's one extra ioctl per VM exit.
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

    /// Update self.current_time and mirror it into the lab's live-branch map
    /// so tree views stay in sync.
    fn advance_time(&mut self, t: VirtTime) {
        self.current_time = t;
        if let Some(m) = self.lab.live_branches.lock().unwrap().get_mut(&self.id) {
            m.current_time = t;
        }
    }

    /// Drain the branch's event stream after a `vm.run()`. For each record:
    /// `Serial` records are reassembled into complete lines and surfaced as
    /// [`Event::SerialLine`] (see [`serial_record_into_sink`]); every other
    /// record reconstructs the branch's
    /// [`InputRecording`](Self::input_recording) (served randomness, queued I/O
    /// requests) and is forwarded to the sink as [`Event::Record`]. `event_len`
    /// is `VmExit::event_len` from the just-returned `vm.run()` ioctl — the
    /// number of valid bytes in the event buffer.
    ///
    /// Inputs are captured only while a source is attached, matching the old
    /// imperative path (kernel-side RNG and direct `bash`/`sched_bash` on a
    /// sourceless branch leave the recording empty).
    ///
    /// The kernel resets the event cursor at the start of every `vm.run()`
    /// ioctl (`handlers.rs` `event_clear`), so `event_len` is *per-call*, not
    /// cumulative.
    fn drain_events(&mut self, event_len: usize) {
        if event_len == 0 {
            return;
        }
        // Destructure into disjoint field borrows so we can read the event
        // buffer (inside `self.vm`) while appending to `self.input_recording`
        // and `self.partial` — the borrow checker only allows these together
        // when the fields are borrowed separately rather than through `&mut self`.
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
                // Console output: reassemble into `SerialLine` rather than
                // forwarding the raw record, preserving the historical surface.
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

    /// Read the guest GPRs after a successful `HYPERCALL_REGISTER_FEEDBACK_BUFFER`
    /// exit and emit an [`Event::FeedbackBufferRegistered`]. The run loop
    /// transparently continues after this — registrations are surfaced only
    /// as events, never as a [`RunOutcome`].
    ///
    /// The kernel-side handler only returns this exit when registration
    /// succeeds; failure cases are swallowed as `Continue` (see
    /// `crates/bedrock-vmx/src/exits/vmcall.rs`).
    fn on_feedback_buffer_registered(&mut self, at: VirtTime) -> Result<()> {
        emit_feedback_buffer_registered(
            self.vm.as_ref().expect("Branch.vm taken"),
            at,
            self.id,
            self.lab.sink.as_ref(),
        )?;
        Ok(())
    }

    /// Read every feedback buffer this branch's VM has registered under
    /// `id`. Returns one `&[u8]` per matching slot, in ascending slot
    /// order. Empty result if no registration matches.
    ///
    /// IDs are not unique by design (see [`Event::FeedbackBufferRegistered`](crate::Event)
    /// docs): multiple guest processes can register coverage maps under the
    /// same id (typically a build-id) and the caller is responsible for
    /// merging — usually a byte-wise OR — the resulting slices.
    ///
    /// Each backing slot is lazily mmapped on first read and the mapping is
    /// cached for the branch's lifetime. The slices stay valid until the
    /// branch is dropped or consumed by [`Branch::checkpoint`]. Forked
    /// branches see their own copy-on-write view of every buffer, so reads
    /// from sibling branches are independent.
    ///
    /// # Errors
    ///
    /// - The mmap or info-query ioctl fails
    pub fn feedback_buffers(&mut self, id: &[u8]) -> Result<Vec<&[u8]>> {
        let vm = self.vm.as_mut().expect("Branch.vm taken");
        let slots = vm.feedback_buffer_slots_for_id(id)?;
        for &slot in &slots {
            if vm.feedback_buffer_at(slot).is_none() {
                vm.map_feedback_buffer_at(slot)?;
            }
        }
        // Re-borrow to get the slices now that all mappings exist. Done in a
        // second loop so the mutable borrow above is released before we hand
        // out shared references.
        let mut out = Vec::with_capacity(slots.len());
        for &slot in &slots {
            if let Some(bytes) = vm.feedback_buffer_at(slot) {
                out.push(bytes);
            }
        }
        Ok(out)
    }

    /// Convenience: read every feedback buffer matching `id` into owned
    /// `Vec`s. Useful when the caller needs to hold the bytes across other
    /// `&mut self` operations on the branch.
    pub fn feedback_buffers_to_vec(&mut self, id: &[u8]) -> Result<Vec<Vec<u8>>> {
        Ok(self
            .feedback_buffers(id)?
            .into_iter()
            .map(|s| s.to_vec())
            .collect())
    }

    /// Return every distinct identifier currently registered on this
    /// branch's VM, in slot-ascending order (first time each id is seen).
    ///
    /// Issues one info-query ioctl per slot. Cheap but not free; cache the
    /// result if you call it on a hot path.
    pub fn feedback_buffer_ids(&self) -> Result<Vec<Vec<u8>>> {
        let vm = self.vm.as_ref().expect("Branch.vm taken");
        let mut seen = std::collections::HashSet::new();
        let mut ids = Vec::new();
        for slot in 0..bedrock_vm::MAX_FEEDBACK_BUFFERS {
            if let Some(info) = vm.get_feedback_buffer_info_at(slot)? {
                let id = info.id_bytes().to_vec();
                if seen.insert(id.clone()) {
                    ids.push(id);
                }
            }
        }
        Ok(ids)
    }

    /// Run the branch forward until its virtual time reaches `target`.
    ///
    /// Returns the [`VirtTime`] at which the branch is now paused, together
    /// with the [`RunOutcome`] that describes *why* it paused.
    ///
    /// Errors with [`LabError::TargetInPast`] if `target` is earlier than
    /// [`Branch::current_time`]. To move backward, take a [`Checkpoint`] via
    /// [`Branch::checkpoint`] and call [`Checkpoint::rewind`] on it.
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
                ExitKind::Continue | ExitKind::EventBufferFull => continue,
                kind => return Ok((at, RunOutcome::Yielded { kind })),
            }
        }
    }

    /// Run the branch forward by `by` virtual time, relative to its current
    /// time.
    ///
    /// Convenience wrapper over [`run_until`](Self::run_until): advances to
    /// [`current_time`](Self::current_time)` + by` and returns the same
    /// `(VirtTime, RunOutcome)` pair. `by`'s frequency must match the tree's.
    pub fn run_for(&mut self, by: VirtDuration) -> Result<(VirtTime, RunOutcome)> {
        self.run_until(self.current_time + by)
    }

    /// Queue an I/O action and pump the VM until the response arrives.
    /// Returns the raw response bytes for the caller to decode.
    fn run_io_action(&mut self, request: &[u8]) -> Result<Vec<u8>> {
        // Run unbounded — any leftover stop_at_tsc from a previous run_until
        // could otherwise fire before the I/O response lands.
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

    /// If this branch has a userspace input source, pull the next RNG `u64`
    /// from it and feed it to the VM via `SET_RDRAND_VALUE` so the next
    /// `vm.run()` re-executes the trapped `RDRAND`/`RDSEED` with that
    /// value. See [`FeedRng`] for the three possible outcomes.
    ///
    /// The served value is not recorded here: the re-execution emits a
    /// `Randomness` event, which [`drain_events`](Self::drain_events) captures
    /// into the branch's [`InputRecording`](Self::input_recording).
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

    /// Pull one source-provided bash action, stop at its virtual time, and
    /// queue it as an immediate I/O action once that time is reached.
    ///
    /// After queueing, peek the *next* source input (without consuming) and
    /// return its virtual time as the VM run-loop stop hint. The next
    /// `StopTscReached` exit then re-enters this method so the next action
    /// can be queued. Two actions at the same virtual time therefore both
    /// enter the kernel worker pool: the first iteration queues A and sets
    /// stop_at to B.at; the second iteration fires immediately (since
    /// B.at == current_time) and queues B.
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
            // The recording captures this request when its `IoChannel` request
            // event is signaled to the guest and drained, not here at queue time
            // (see `drain_events`).
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

        // Peek the next input to set the VM's stop_at: when its start vt
        // arrives we'll be re-entered via StopTscReached to queue it.
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

    /// Pull the next deterministic I/O input from this branch's source, if
    /// one is attached.
    ///
    /// The returned input is not queued automatically; callers can inspect
    /// or transform it before deciding whether to pass it to
    /// [`Self::sched_bash`].
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

    /// Inject a bash command and block until the response arrives.
    ///
    /// The `target` selects whether the command runs on the guest host
    /// (outside any container) or inside a named container.
    ///
    /// Drives the VM forward through any intervening exits — the branch's
    /// virtual time advances by however long the guest takes to execute the
    /// command and reply.
    ///
    /// Requires the guest to have `bedrock-io.ko` loaded and registered.
    ///
    /// Note: if there are previously [`sched_bash`](Self::sched_bash)'d
    /// actions still pending, the next response may be for one of *those*
    /// and not this blocking call. Avoid mixing blocking and scheduled bash
    /// calls without first draining all pending responses via `run_until`.
    ///
    /// The command's combined stdout+stderr always streams to the guest
    /// journal. When `record_output` is set it is *also* captured into the
    /// output feedback buffer and returned in [`BashOutput::output`]; otherwise
    /// `output` is empty.
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

    /// Schedule a bash command to fire at virtual time `at`.
    ///
    /// Returns immediately; the response is delivered asynchronously when
    /// [`Branch::run_until`] reaches the I/O response exit and yields
    /// [`RunOutcome::ActionResponse`]. `record_output` behaves as in
    /// [`bash`](Self::bash).
    ///
    /// `at.instructions() == 0` is the special "fire as soon as the guest is
    /// interruptible" value the hypervisor's I/O channel honors. For non-zero
    /// values the action lands at exactly that emulated-TSC.
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
            // `r.exit_code` is the raw wait-status the guest got back from
            // call_usermodehelper; decode it into a conventional exit code.
            exit_code: bedrock_vm::io_channel::exit_code_from_wait_status(r.exit_code),
            output,
        })
    }

    /// Carve out an immutable [`Checkpoint`] at the current point, consuming
    /// this branch.
    ///
    /// The branch's VM becomes the checkpoint's frozen fork source. To
    /// continue execution from this point, call [`Checkpoint::branch`] on the
    /// returned checkpoint.
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

/// Outcome of [`Branch::feed_rng`]. Internal — branches translate this into
/// either a `continue` or one of the public surfacing variants of
/// [`RunOutcome`].
enum FeedRng {
    /// Value fed; caller should `continue` the run loop.
    Fed,
    /// Branch has no userspace source attached (kernel-side RDRAND mode).
    NoSource,
    /// Source returned `None` — no more randomness available.
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
