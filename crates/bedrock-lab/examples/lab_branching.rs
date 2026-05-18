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

use std::error::Error;
use std::fs;
use std::io::{BufWriter, Write};
use std::sync::{Arc, Mutex};

use bedrock_lab::{
    ActionResponse, BashTarget, BranchId, Checkpoint, Event, EventSink, InputSource, IoInput,
    LabError, LabOpts, LogConfig, RngMode, RunOutcome, VirtDuration, VirtTime,
};
use bedrock_vm::{boot::defaults, load_kernel, write_jsonl, LinuxBootConfig, VmBuilder};
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
    // exit log only covers the part the lab is actively driving — the
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
        if let Some(dir) = &args.exit_log_dir {
            sink.open_exit_log(&format!("{dir}/run-{iter:03}"))?;
        }
        println!("=== iteration {iter} ===");

        // Use ready_cp.time() as the source base so the first I/O fires at
        // pre_io_cp.time() (i.e. immediately when run_until starts pumping
        // the input-driven branch), rather than another 1s in the future.
        let source = DemoInputSource::new(ready_cp.time());
        let mut branch = pre_io_cp.branch_with_input_source(source)?;
        if args.exit_log_dir.is_some() {
            // AllExits captures every deterministic exit (used by
            // `scripts/determ-divergence.py` to find the divergence point)
            // and routes non-deterministic exits + PEBS diagnostic entries
            // to `exit-log-nondeterm.jsonl` for use in the divergence
            // window. Memory hashing is skipped — register state already
            // pins down divergence and hashing every exit dominates run
            // time.
            branch.set_log_config(LogConfig::all_exits(0).with_no_memory_hash())?;
        }

        loop {
            let (at, outcome) = branch.run_until(deadline)?;
            match outcome {
                RunOutcome::ReachedTime => {
                    println!("reached deadline at {:.3}s", at.as_secs_f64());
                    break;
                }
                RunOutcome::ActionResponse { response } => {
                    print_action_response(branch.id(), at, response)
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
        sink.close_exit_log();
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

    /// If set, capture every VM exit on the input-driven branch and write
    /// them as JSONL to two files under this directory:
    ///
    /// - `exit-log.jsonl` — deterministic exits (used by
    ///   `scripts/determ-divergence.py` to find the divergence point)
    /// - `exit-log-nondeterm.jsonl` — non-deterministic exits + PEBS
    ///   diagnostic entries (used to show what happened around the
    ///   divergence window; these are not compared directly because PEBS
    ///   skid fields and host-timing-dependent counts drift across runs)
    ///
    /// Boot-phase exits are not captured.
    #[arg(long)]
    exit_log_dir: Option<String>,

    /// Run the input-driven phase this many times from the same pre-IO
    /// checkpoint. Each iteration's exit log lands in
    /// `<exit-log-dir>/run-NNN/` so `scripts/determ-divergence.py` can
    /// diff any two. The boot+pre-IO phase happens once and is shared.
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
                },
                IoInput {
                    at: base + VirtDuration::from_secs(1, base.frequency()),
                    target: BashTarget::Host,
                    command: "printf 'input-source: second command\\n'".to_string(),
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

fn print_action_response(branch: BranchId, at: VirtTime, response: ActionResponse) {
    match response {
        ActionResponse::Bash(out) => {
            println!(
                "[br {branch:?} vt {:>8.3}] bash status={} exit={}",
                at.as_secs_f64(),
                out.status,
                out.exit_code,
            );
        }
        ActionResponse::WorkloadDetails(drivers) => {
            println!(
                "[br {branch:?} vt {:>8.3}] workload details: {} drivers",
                at.as_secs_f64(),
                drivers.len()
            );
        }
    }
}

fn print_input_recording(recording: &bedrock_lab::InputRecording) {
    println!("input recording:");
    println!("  rng values: {}", recording.rng_inputs().len());
    for (i, input) in recording.rng_inputs().iter().enumerate() {
        println!(
            "    {i:04}: vt {:>8.3} value {:#018x}",
            input.at.as_secs_f64(),
            input.value
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

/// Lab sink: serial lines to stdout; `ExitLogged` entries split by the
/// determinism flag into two JSONL files (consumed by
/// `scripts/determ-divergence.py`). The exit-log file pair can be swapped
/// between iterations via [`LabSink::open_exit_log`] / [`LabSink::close_exit_log`]
/// so a single tree (and a single boot) can produce N independent run dirs.
struct LabSink {
    exit_logs: Mutex<Option<ExitLogs>>,
}

struct ExitLogs {
    determ: BufWriter<fs::File>,
    nondeterm: BufWriter<fs::File>,
}

impl LabSink {
    fn new() -> Self {
        Self {
            exit_logs: Mutex::new(None),
        }
    }

    /// Direct subsequent `ExitLogged` entries into `<dir>/exit-log.jsonl`
    /// and `<dir>/exit-log-nondeterm.jsonl`. Closes any previously-open
    /// pair first. The `dir` is created if it doesn't exist.
    fn open_exit_log(&self, dir: &str) -> std::io::Result<()> {
        fs::create_dir_all(dir)?;
        let determ = fs::File::create(format!("{dir}/exit-log.jsonl"))?;
        let nondeterm = fs::File::create(format!("{dir}/exit-log-nondeterm.jsonl"))?;
        let mut g = self.exit_logs.lock().unwrap();
        *g = Some(ExitLogs {
            determ: BufWriter::new(determ),
            nondeterm: BufWriter::new(nondeterm),
        });
        Ok(())
    }

    /// Flush and drop the current file pair so the next iteration starts
    /// with a fresh `--exit-log-dir`. Subsequent `ExitLogged` events are
    /// dropped until the next `open_exit_log` call.
    fn close_exit_log(&self) {
        let mut g = self.exit_logs.lock().unwrap();
        if let Some(mut logs) = g.take() {
            let _ = logs.determ.flush();
            let _ = logs.nondeterm.flush();
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
                index,
                size,
            } => {
                eprintln!(
                    "[br {branch:?} vt {:>8.3}] feedback buffer {index} registered ({size} bytes)",
                    at.as_secs_f64()
                );
            }
            Event::ExitLogged { entry, .. } => {
                let mut g = self.exit_logs.lock().unwrap();
                if let Some(logs) = g.as_mut() {
                    let target = if entry.is_deterministic() {
                        &mut logs.determ
                    } else {
                        &mut logs.nondeterm
                    };
                    let _ = write_jsonl(target, std::slice::from_ref(entry));
                }
            }
            other => eprintln!("lab event: {other:?}"),
        }
    }
}
