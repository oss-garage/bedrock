// SPDX-License-Identifier: GPL-2.0

//! Boot a Linux guest and drive it from an `InputSource`.
//!
//! Run with:
//!
//! ```text
//! cargo run -p bedrock-lab --example lab_branching -- <vmlinux> <initramfs>
//! ```
//!
//! The guest is expected to load `bedrock-io.ko` and issue the ready
//! hypercall before the ready deadline. After that, the example forks one
//! branch with a custom `InputSource`. The lab uses that source to serve
//! guest RDRAND/RDSEED exits and to schedule bash commands on the
//! deterministic I/O channel.
//!
//! Pass `--events-dir <dir>` to capture each run's event stream to
//! `<dir>/run-NNN/events.jsonl` for divergence debugging.

use std::error::Error;
use std::fs;
use std::io::{BufWriter, Write};
use std::sync::{Arc, Mutex};

use bedrock_lab::{
    BashOutput, BashTarget, BranchId, Checkpoint, Event, EventConfig, EventSink, ExitCapture,
    InputSource, IoInput, LabError, LabOpts, RngMode, RunOutcome, VirtDuration, VirtTime,
};
use bedrock_vm::{boot::defaults, load_kernel, LinuxBootConfig, VmBuilder};
use clap::Parser;

bedrock_lab::define_virt_time_macros!($, bedrock_vm::DEFAULT_TSC_FREQUENCY);

const MEMORY_MB: usize = 5120;
const BOOT_RNG_SEED: u64 = 0xbed0_0001;

fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();

    let mut vm = VmBuilder::new().memory_mb(MEMORY_MB).build()?;
    let kernel = fs::read(&args.vmlinux)?;
    let initramfs = fs::read(&args.initramfs)?;

    let (kernel_entry, kernel_end) = {
        let memory = vm.memory_mut()?;
        load_kernel(memory, &kernel)?
    };

    let mut boot = LinuxBootConfig::new(kernel_entry, kernel_end).cmdline(defaults::CMDLINE);
    boot = boot.initramfs(&initramfs);
    vm.setup_linux_boot(&boot)?;

    let sink = Arc::new(LabSink::new());
    let ready_cp = Checkpoint::initial_when_ready_with(
        vm,
        vt!(120 s),
        LabOpts {
            sink: sink.clone(),
            rng: RngMode::Seeded(BOOT_RNG_SEED),
            ..Default::default()
        },
    )?;
    println!(
        "ready checkpoint {:?} at {:.3}s",
        ready_cp.id(),
        ready_cp.time().as_secs_f64()
    );

    // Advance an idle branch up to the first I/O time and re-checkpoint
    // there. The input-driven branch then forks from this point, so the
    // captured exits only cover the part the lab is actively driving — the
    // pre-I/O idle window (which is uninteresting for divergence
    // debugging) doesn't end up in the JSONL.
    let first_io_time = ready_cp.time() + VirtDuration::from_secs(1, ready_cp.tsc_frequency());
    let mut idle = ready_cp.branch()?;
    idle.run_until(first_io_time)?;
    let pre_io_cp = idle.checkpoint()?;
    println!(
        "pre-IO checkpoint {:?} at {:.3}s",
        pre_io_cp.id(),
        pre_io_cp.time().as_secs_f64()
    );

    let deadline = pre_io_cp.time() + VirtDuration::from_secs(5, pre_io_cp.tsc_frequency());
    for iter in 0..args.iterations {
        if let Some(dir) = &args.events_dir {
            sink.open_events(&format!("{dir}/run-{iter:03}"))?;
        }
        println!("=== iteration {iter} ===");

        // Use ready_cp.time() as the source base so the first I/O fires at
        // pre_io_cp.time() (i.e. immediately when run_until starts pumping
        // the input-driven branch), rather than another 1s in the future.
        let source = DemoInputSource::new(ready_cp.time());
        let mut branch = pre_io_cp.branch_with_input_source(source)?;
        if args.events_dir.is_some() {
            // Capture every exit (deterministic and non-deterministic). Memory
            // hashing is skipped — register state already pins down divergence,
            // and hashing every exit dominates run time.
            branch.set_event_config(&EventConfig {
                exits: ExitCapture::AllExits { memory_hash: false },
                ..Default::default()
            })?;
        }

        loop {
            let (at, outcome) = branch.run_until(deadline)?;
            match outcome {
                RunOutcome::ReachedTime => {
                    println!("reached deadline at {:.3}s", at.as_secs_f64());
                    break;
                }
                RunOutcome::ActionResponse { output } => {
                    print_action_response(branch.id(), at, output)
                }
                RunOutcome::Ready => continue,
                RunOutcome::RngExhausted => {
                    println!("input source ran out of RDRAND/RDSEED values");
                    break;
                }
                RunOutcome::Yielded { kind } => {
                    return Err(LabError::UnexpectedExit { at, kind }.into());
                }
            }
        }
        print_input_recording(branch.input_recording());
        sink.close_events();
        // `branch` drops here, releasing its slot in `lab.live_branches`
        // so the next iteration's fork starts from a clean slate.
    }

    Ok(())
}

#[derive(Parser, Debug)]
#[command(name = "lab_branching")]
#[command(about = "Boot a Linux guest and drive it from a bedrock-lab InputSource")]
struct Args {
    /// Path to the vmlinux ELF image.
    vmlinux: String,

    /// Path to an initramfs/initrd image.
    initramfs: String,

    /// If set, capture the input-driven branch's event stream to
    /// `<dir>/run-NNN/events.jsonl` (one dir per iteration), which
    /// `contrib/determ-divergence.py` reads to locate where two runs diverge.
    /// Without this flag the branch runs without capture.
    #[arg(long)]
    events_dir: Option<String>,

    /// Re-run the input-driven phase this many times from the same pre-IO
    /// checkpoint, each into its own `run-NNN/` under `--events-dir`. The
    /// boot + pre-IO phase happens once and is shared across iterations.
    #[arg(long, default_value_t = 1)]
    iterations: u32,
}

#[derive(Clone)]
struct DemoInputSource {
    rng_state: u64,
    io_inputs: Vec<IoInput>,
    io_pos: usize,
}

impl DemoInputSource {
    fn new(base: VirtTime) -> Self {
        Self {
            rng_state: 0x1111_2222_3333_4444,
            io_inputs: vec![
                IoInput {
                    at: base + VirtDuration::from_secs(1, base.frequency()),
                    target: BashTarget::Host,
                    command: "echo input-source: first command".to_string(),
                    // Record this command's output so it comes back on the
                    // resulting `ActionResponse` (via the output feedback buffer).
                    record_output: true,
                },
                IoInput {
                    at: base + VirtDuration::from_secs(1, base.frequency()),
                    target: BashTarget::Host,
                    command: "printf 'input-source: second command\\n'".to_string(),
                    record_output: true,
                },
            ],
            io_pos: 0,
        }
    }
}

impl InputSource for DemoInputSource {
    fn next_rng_u64(&mut self) -> Option<u64> {
        self.rng_state = self
            .rng_state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1);
        Some(self.rng_state)
    }

    fn next_io_input(&mut self) -> Option<IoInput> {
        let input = self.io_inputs.get(self.io_pos).cloned();
        if input.is_some() {
            self.io_pos += 1;
        }
        input
    }

    fn clone_box(&self) -> Box<dyn InputSource> {
        Box::new(self.clone())
    }
}

fn print_action_response(branch: BranchId, at: VirtTime, out: BashOutput) {
    println!(
        "[br {branch:?} vt {:>8.3}] bash status={} exit={} output={:?}",
        at.as_secs_f64(),
        out.status,
        out.exit_code,
        out.output_lossy(),
    );
}

fn print_input_recording(recording: &bedrock_lab::InputRecording) {
    println!("input recording:");
    println!("  randomness inputs: {}", recording.random_inputs().len());
    for (i, input) in recording.random_inputs().iter().enumerate() {
        println!(
            "    {i:04}: vt {:>8.3} source {:?} pid {} {} bytes",
            input.at.as_secs_f64(),
            input.source,
            input.pid,
            input.bytes.len(),
        );
    }

    println!("  io actions: {}", recording.io_inputs().len());
    for (i, input) in recording.io_inputs().iter().enumerate() {
        println!(
            "    {i:04}: vt {:>8.3} target {:?} command {:?}",
            input.at.as_secs_f64(),
            input.target,
            input.command
        );
    }
}

/// Lab sink: serial lines go to stdout; `Record` events are written to an
/// `events.jsonl` that can be swapped between iterations via
/// [`LabSink::open_events`] / [`LabSink::close_events`], so a single tree (and a
/// single boot) produces N independent run dirs.
struct LabSink {
    events: Mutex<Option<BufWriter<fs::File>>>,
}

impl LabSink {
    fn new() -> Self {
        Self {
            events: Mutex::new(None),
        }
    }

    /// Direct subsequent `Record` events into `<dir>/events.jsonl`, closing any
    /// previously-open file first. The `dir` is created if it doesn't exist.
    fn open_events(&self, dir: &str) -> std::io::Result<()> {
        fs::create_dir_all(dir)?;
        let events = fs::File::create(format!("{dir}/events.jsonl"))?;
        let mut g = self.events.lock().unwrap();
        *g = Some(BufWriter::new(events));
        Ok(())
    }

    /// Flush and drop the current file so the next iteration starts with a
    /// fresh `--events-dir`. Subsequent `Record` events are dropped until the
    /// next `open_events` call.
    fn close_events(&self) {
        let mut g = self.events.lock().unwrap();
        if let Some(mut events) = g.take() {
            let _ = events.flush();
        }
    }
}

impl EventSink for LabSink {
    fn on_event(&self, event: Event<'_>) {
        match event {
            Event::SerialLine { branch, at, line } => {
                println!(
                    "[br {branch:?} vt {:>8.3}] {}",
                    at.as_secs_f64(),
                    String::from_utf8_lossy(line)
                );
            }
            Event::FeedbackBufferRegistered {
                branch,
                at,
                id,
                slot,
                size,
            } => {
                eprintln!(
                    "[br {branch:?} vt {:>8.3}] feedback buffer slot={slot} id={:?} registered ({size} bytes)",
                    at.as_secs_f64(),
                    String::from_utf8_lossy(id),
                );
            }
            Event::Record { record, .. } => {
                let mut g = self.events.lock().unwrap();
                if let Some(w) = g.as_mut() {
                    let _ = serde_json::to_writer(&mut *w, &record.to_json());
                    let _ = writeln!(w);
                }
            }
            other => eprintln!("lab event: {other:?}"),
        }
    }
}
