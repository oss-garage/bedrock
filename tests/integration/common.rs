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
//! guest images supplied via environment. The initrd is the generic podman
//! initrd, which downloads its workload files at boot over the file-transmission
//! hypercall, so the workload's `compose.yaml` and `images.tar` host paths must
//! also be supplied (the harness serves them):
//!
//! ```text
//! BEDROCK_VMLINUX=/path/to/vmlinux \
//! BEDROCK_INITRAMFS=/path/to/podman-initrd \
//! BEDROCK_COMPOSE=/path/to/workloads/integration-tests/compose.yaml \
//! BEDROCK_IMAGES=/path/to/workloads/integration-tests/images.tar \
//!     cargo test -p bedrock-integration-tests
//! ```
//!
//! The `integration-tests` nix app wires all four up against the Nix-built
//! guest kernel, the generic `podmanInitrd`, and the staged workload files.
//! When the device or any of these env vars is absent (e.g. a plain
//! `just test` on a dev box), [`ready_checkpoint`] returns `None` and each test
//! early-returns as a skip (printing exactly what is missing), keeping
//! `cargo test` green.

use std::collections::HashMap;
use std::path::Path;
use std::process::Command;
use std::sync::{Arc, Mutex, OnceLock};

use bedrock_lab::{BashTarget, Branch, BranchId, Checkpoint, Event, EventSink, LabOpts, RngMode};
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

/// The guest-image environment needed to boot a VM.
struct GuestEnv {
    vmlinux: String,
    initramfs: String,
    /// Workload files served to the guest over the file-transmission hypercall
    /// (the generic podman initrd downloads them at boot): `compose.yaml` and
    /// `images.tar` host paths.
    compose: String,
    images: String,
}

/// Whether the environment can actually run a VM: the bedrock device node is
/// present, the kernel + initrd paths are set, and the workload files the guest
/// downloads at boot are set.
fn can_run() -> Option<GuestEnv> {
    if !Path::new(bedrock_vm::BEDROCK_DEVICE_PATH).exists() {
        return None;
    }
    Some(GuestEnv {
        vmlinux: std::env::var("BEDROCK_VMLINUX").ok()?,
        initramfs: std::env::var("BEDROCK_INITRAMFS").ok()?,
        compose: std::env::var("BEDROCK_COMPOSE").ok()?,
        images: std::env::var("BEDROCK_IMAGES").ok()?,
    })
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
///
/// The generic podman initrd downloads its workload files (`compose.yaml` /
/// `images.tar`) over the file-transmission hypercall during boot, so the boot
/// loop serves them from the host paths in `BEDROCK_COMPOSE` / `BEDROCK_IMAGES`
/// (wired up by the `integration-tests` nix app).
pub fn ready_checkpoint() -> Option<Checkpoint> {
    let env = can_run()?;
    // get_or_init blocks concurrent first-callers until the boot completes,
    // so the guest boots exactly once even under parallel test threads.
    let cp = READY.get_or_init(|| boot_ready(&env).expect("boot guest to ready checkpoint"));
    Some(cp.clone())
}

/// Print a skip notice naming exactly what is missing, so a partially
/// configured run (e.g. kernel + initrd set but the workload files unset) is
/// obvious rather than looking like a silent pass. Visible under
/// `cargo test -- --nocapture`.
pub fn skip(what: &str) {
    let mut missing: Vec<String> = Vec::new();
    if !Path::new(bedrock_vm::BEDROCK_DEVICE_PATH).exists() {
        missing.push(format!(
            "the bedrock module loaded ({} absent)",
            bedrock_vm::BEDROCK_DEVICE_PATH
        ));
    }
    for var in [
        "BEDROCK_VMLINUX",
        "BEDROCK_INITRAMFS",
        "BEDROCK_COMPOSE",
        "BEDROCK_IMAGES",
    ] {
        if std::env::var(var).is_err() {
            missing.push(var.to_string());
        }
    }
    eprintln!("SKIP {what}: needs {}", missing.join(", "));
}

fn boot_ready(env: &GuestEnv) -> Result<Checkpoint, Box<dyn std::error::Error>> {
    let mut vm = VmBuilder::new().memory_mb(MEMORY_MB).build()?;
    let kernel = std::fs::read(&env.vmlinux)?;
    let initrd = std::fs::read(&env.initramfs)?;

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
            // The guest downloads these over the file-transmission hypercall
            // during boot; the boot loop serves them.
            files: vec![
                ("compose.yaml".to_string(), env.compose.clone()),
                ("images.tar".to_string(), env.images.clone()),
            ],
            ..Default::default()
        },
    )?;
    Ok(cp)
}

/// sha256 of a host file as a lowercase hex string, via the `sha256sum` CLI
/// (coreutils, present in CI). Panics on failure — the originals must exist for
/// the comparison to mean anything.
pub fn host_sha256(path: &str) -> String {
    let out = Command::new("sha256sum")
        .arg(path)
        .output()
        .unwrap_or_else(|e| panic!("run sha256sum {path} on host: {e}"));
    assert!(out.status.success(), "host sha256sum {path} failed");
    let stdout = String::from_utf8(out.stdout).expect("sha256sum utf8");
    first_token(&stdout)
}

/// Hash a guest file with the same tool, dispatched over the deterministic bash
/// I/O channel, and return its hex digest. Fails the test if the command didn't
/// run cleanly — `sha256sum` exits non-zero when the file is missing, so this
/// also covers the "file exists in the workload" check.
pub fn guest_sha256(branch: &mut Branch, path: &str) -> String {
    let out = branch
        .bash(BashTarget::host(), &format!("sha256sum {path}"), true)
        .expect("dispatch sha256sum in guest");
    assert!(
        out.success(),
        "guest `sha256sum {path}` failed (status={} exit={}) — file missing? output: {:?}",
        out.status,
        out.exit_code,
        out.output_lossy(),
    );

    first_token(&out.output_lossy())
}

/// The first whitespace-delimited token — `sha256sum` prints `<hex>  <path>`.
pub fn first_token(s: &str) -> String {
    s.split_whitespace().next().unwrap_or_default().to_string()
}
