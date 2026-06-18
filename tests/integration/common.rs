//! Shared harness for the bedrock integration tests.
//!
//! The expensive part of every test is booting a Linux guest to its ready
//! hypercall. We pay that cost once: the first test to call
//! [`ready_checkpoint`] boots the guest and stores the resulting
//! [`Checkpoint`] in a process-global `OnceLock`; every other test (running
//! on its own cargo test thread) reuses it and forks an independent branch.
//! Branches are COW-forked VMs with no shared execution-time state, so they
//! run on parallel threads without interfering.
//!
//! # Running
//!
//! These tests drive a real VM through `bedrock-lab`, which talks to
//! `/dev/bedrock` — so they require the bedrock kernel module loaded and the
//! guest images supplied via environment:
//!
//! ```text
//! BEDROCK_VMLINUX=/path/to/vmlinux \
//! BEDROCK_INITRAMFS=/path/to/integration-tests-initrd \
//!     cargo test -p bedrock-integration-tests
//! ```
//!
//! The `integration-tests` CI job wires this up against the Nix-built guest
//! kernel and `integration-testsInitrd`. When the device or the env vars are
//! absent (e.g. a plain `just test` on a dev box), [`ready_checkpoint`]
//! returns `None` and each test early-returns as a skip, keeping
//! `cargo test` green.

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock};

use bedrock_lab::{BranchId, Checkpoint, Event, EventSink, LabOpts, RngMode};
use bedrock_vm::{boot::defaults, load_kernel, LinuxBootConfig, VmBuilder};

/// Guest RAM. Matches the Nix integration test (`-m 5120`): the podman initrd
/// runs podman + journald, so it needs real headroom.
const MEMORY_MB: usize = 5120;

/// Fixed RDRAND/RDSEED seed for the whole tree. A constant seed is what makes
/// the determinism assertions meaningful — every branch forks from the same
/// seeded kernel RNG state.
const BOOT_RNG_SEED: u64 = 0xbed0_0001;

static READY: OnceLock<Checkpoint> = OnceLock::new();
static SINK: OnceLock<Arc<CaptureSink>> = OnceLock::new();

/// Tree-wide [`EventSink`] that retains each branch's `Exit` records (so
/// determinism tests can compare guest state across sibling branches) and its
/// serial-console lines (so tests can observe guest output — e.g. the assertion
/// pipeline's journald JSON records — the way the host oracle does).
///
/// One sink serves the whole tree (every branch, across parallel test
/// threads), so records are bucketed by [`BranchId`]. Only branches that turn
/// on exit capture via
/// [`Branch::set_event_config`](bedrock_lab::Branch::set_event_config) produce
/// `Exit` records, so that map stays empty for tests that don't ask for it;
/// serial capture is always on, so [`serial_lines`](Self::serial_lines)
/// reflects every branch.
#[derive(Default)]
pub struct CaptureSink {
    records: Mutex<HashMap<BranchId, Vec<serde_json::Value>>>,
    serial: Mutex<HashMap<BranchId, Vec<String>>>,
}

impl CaptureSink {
    /// Drain and return the `Exit` records captured for `branch`, normalized
    /// for run-vs-run comparison: only records flagged `deterministic` are
    /// kept, and the fields that vary with host timing rather than guest
    /// execution are stripped. Two sibling branches that did identical work
    /// return equal vectors.
    ///
    /// Stripped fields (kept in sync with `contrib/determ-divergence.py`):
    /// - `real_tsc` — the host TSC at the exit.
    /// - `seq` — the per-VM event counter. It counts *all* events, including
    ///   non-deterministic ones (external-interrupt exits, serial bytes), so
    ///   it drifts between branches even when the deterministic exits match.
    /// - the PEBS diagnostic fields inside `data` — host-timing-dependent
    ///   armings/skid that the divergence tool also ignores.
    pub fn take_deterministic(&self, branch: BranchId) -> Vec<serde_json::Value> {
        /// `data` fields recorded for diagnostics only; see
        /// `DIAGNOSTIC_FIELDS` in `contrib/determ-divergence.py`.
        const PEBS_DIAGNOSTIC_FIELDS: &[&str] = &[
            "pebs_skid",
            "pebs_inst_delta",
            "pebs_tsc_offset_delta",
            "pebs_iters_since_arm",
            "pebs_arm_delta",
        ];
        let raw = self
            .records
            .lock()
            .unwrap()
            .remove(&branch)
            .unwrap_or_default();
        raw.into_iter()
            .filter(|r| r.get("deterministic").and_then(|d| d.as_bool()) == Some(true))
            .map(|mut r| {
                if let Some(obj) = r.as_object_mut() {
                    obj.remove("real_tsc");
                    obj.remove("seq");
                    if let Some(data) = obj.get_mut("data").and_then(|d| d.as_object_mut()) {
                        for field in PEBS_DIAGNOSTIC_FIELDS {
                            data.remove(*field);
                        }
                    }
                }
                r
            })
            .collect()
    }

    /// Snapshot, in order, the serial-console lines captured for `branch` so
    /// far. Non-draining: repeated calls during a poll loop see the growing
    /// log. Trailing `\n` is already stripped by the lab's line reassembler.
    pub fn serial_lines(&self, branch: BranchId) -> Vec<String> {
        self.serial
            .lock()
            .unwrap()
            .get(&branch)
            .cloned()
            .unwrap_or_default()
    }
}

impl EventSink for CaptureSink {
    fn on_event(&self, event: Event<'_>) {
        match event {
            // Exit records: the borrowed `EventRecord` is serialized to an
            // owned JSON value here since it can't outlive this call.
            Event::Record { branch, record } => {
                if let Ok(value) = serde_json::to_value(record.to_json()) {
                    self.records
                        .lock()
                        .unwrap()
                        .entry(branch)
                        .or_default()
                        .push(value);
                }
            }
            // Serial output: SERIAL capture is forced on for every branch, so
            // each complete console line — including the assertion pipeline's
            // journald JSON records — surfaces here. Retain per branch so tests
            // can observe it. `line` borrows a per-branch buffer; copy it out.
            Event::SerialLine { branch, line, .. } => {
                self.serial
                    .lock()
                    .unwrap()
                    .entry(branch)
                    .or_default()
                    .push(String::from_utf8_lossy(line).into_owned());
            }
            _ => {}
        }
    }
}

/// The tree-wide capture sink (see [`CaptureSink`]).
pub fn capture_sink() -> Arc<CaptureSink> {
    SINK.get_or_init(|| Arc::new(CaptureSink::default()))
        .clone()
}

/// Whether the environment can actually run a VM: the bedrock device node is
/// present and both guest-image paths are set.
fn can_run() -> Option<(String, String)> {
    if !Path::new(bedrock_vm::BEDROCK_DEVICE_PATH).exists() {
        return None;
    }
    let vmlinux = std::env::var("BEDROCK_VMLINUX").ok()?;
    let initramfs = std::env::var("BEDROCK_INITRAMFS").ok()?;
    Some((vmlinux, initramfs))
}

/// The shared ready checkpoint, booted on first use, or `None` if this
/// environment can't run VMs (no `/dev/bedrock` or image env vars unset).
///
/// Tests should treat `None` as "skip":
///
/// ```ignore
/// let Some(ready) = common::ready_checkpoint() else {
///     return common::skip("boot to ready");
/// };
/// ```
pub fn ready_checkpoint() -> Option<Checkpoint> {
    let (vmlinux, initramfs) = can_run()?;
    // get_or_init blocks concurrent first-callers until the boot completes,
    // so the guest boots exactly once even under parallel test threads.
    let cp = READY
        .get_or_init(|| boot_ready(&vmlinux, &initramfs).expect("boot guest to ready checkpoint"));
    Some(cp.clone())
}

/// Print a skip notice. Visible under `cargo test -- --nocapture`.
pub fn skip(what: &str) {
    eprintln!(
        "SKIP {what}: set BEDROCK_VMLINUX + BEDROCK_INITRAMFS and load the \
         bedrock module to run this test"
    );
}

fn boot_ready(vmlinux: &str, initramfs: &str) -> Result<Checkpoint, Box<dyn std::error::Error>> {
    let mut vm = VmBuilder::new().memory_mb(MEMORY_MB).build()?;
    let kernel = std::fs::read(vmlinux)?;
    let initrd = std::fs::read(initramfs)?;

    let (kernel_entry, kernel_end) = {
        let memory = vm.memory_mut()?;
        load_kernel(memory, &kernel)?
    };

    let boot = LinuxBootConfig::new(kernel_entry, kernel_end)
        .cmdline(defaults::CMDLINE)
        .initramfs(&initrd);
    vm.setup_linux_boot(&boot)?;

    // Give the guest a generous window to issue its ready hypercall — the
    // podman initrd has to load images and bring up the container.
    let deadline = vt!(120 s);
    let cp = Checkpoint::initial_when_ready_with(
        vm,
        deadline,
        LabOpts {
            sink: capture_sink(),
            rng: RngMode::Seeded(BOOT_RNG_SEED),
            ..Default::default()
        },
    )?;
    Ok(cp)
}
