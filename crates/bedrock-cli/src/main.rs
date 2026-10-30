// SPDX-License-Identifier: GPL-2.0

//! Command-line interface for the bedrock hypervisor.
//!
//! Loads vmlinux ELF images and boots them using the Linux 64-bit boot protocol.

mod args;
use std::fs::File;
use std::io::{self, Read, Write};
use std::process;

use clap::Parser;
use log::{debug, info, trace, warn};

use bedrock_vm::events::EventKind;
use bedrock_vm::file_store::FileWriter;
use bedrock_vm::file_xfer::FileServer;
use bedrock_vm::fuzz_input::InputServer;
use bedrock_vm::io_channel;
use bedrock_vm::{
    load_kernel, ConsoleLine, EventCategories, EventConfig, EventStream, ExitKind, ExitStatsReport,
    ExitTrigger, LinuxBootConfig, RdrandConfig, Vm, VmBuilder, BEDROCK_DEVICE_PATH,
    DEFAULT_TSC_FREQUENCY,
};

use args::{Args, IoAction, RdrandMode, ScheduledIoAction};

/// Line-buffered console output prefixed with `[vt x.xxx]` (virtual seconds).
struct LineBufferedOutput {
    buffer: String,
    /// Emulated TSC at the start of the line in `buffer`.
    line_tsc: u64,
    /// Raw output without timestamps.
    log_file: Option<File>,
}

impl LineBufferedOutput {
    fn new(log_file: Option<File>) -> Self {
        Self {
            buffer: String::new(),
            line_tsc: 0,
            log_file,
        }
    }

    /// Print each completed line of a `Serial` record. A line continued across
    /// records keeps its first record's TSC.
    fn write_serial_record(&mut self, bytes: &[u8], record_tsc: u64, tsc_frequency: u64) {
        if let Some(ref mut f) = self.log_file {
            let _ = f.write_all(bytes);
            let _ = f.flush();
        }

        for ch in String::from_utf8_lossy(bytes).chars() {
            if self.buffer.is_empty() {
                self.line_tsc = record_tsc;
            }
            if ch == '\n' {
                let secs = self.line_tsc as f64 / tsc_frequency as f64;
                println!("[vt {:>8.3}] {}", secs, render_console_line(&self.buffer));
                self.buffer.clear();
            } else {
                self.buffer.push(ch);
            }
        }

        let _ = std::io::stdout().flush();
    }

    /// Flush the partial line, without a timestamp.
    fn flush_partial(&mut self) {
        if !self.buffer.is_empty() {
            print!("{}", self.buffer);
            let _ = std::io::stdout().flush();
            self.buffer.clear();
        }
    }
}

/// Render journal records as a coloured `[source] | message`; raw lines
/// (e.g. early printk) verbatim.
fn render_console_line(line: &str) -> String {
    match ConsoleLine::parse(line) {
        ConsoleLine::Journal { source, message } => {
            let color = source_color(&source);
            format!(
                "[\u{1b}[{color}m{source}\u{1b}[0m] | {}",
                message.trim_end_matches('\n')
            )
        }
        ConsoleLine::Raw(raw) => raw,
    }
}

/// ANSI foreground colour (31..=36) from the sum of the label's chars.
fn source_color(label: &str) -> u32 {
    label.chars().map(|c| c as u32).sum::<u32>() % 6 + 31
}

fn main() {
    if let Err(e) = run() {
        eprintln!("Error: {}", e);
        process::exit(1);
    }
}

fn log_vm_exit(vm: &Vm, msg: &str) {
    let rip = vm.get_regs().map(|r| r.rip).unwrap_or(0);
    warn!("VM exit: {} at RIP {:#018x}", msg, rip);
}

fn encode_io_action(action: &IoAction) -> Vec<u8> {
    io_channel::encode_request(
        action.container.as_deref(),
        &action.command,
        action.record_output,
    )
}

/// Read `len` bytes of recorded command output from the output feedback buffer.
fn read_io_output(vm: &mut Vm, len: usize) -> io::Result<Vec<u8>> {
    let slots = vm.feedback_buffer_slots_for_id(io_channel::IO_OUTPUT_BUFFER_ID)?;
    let slot = match slots.first() {
        Some(&s) => s,
        None => return Ok(Vec::new()),
    };
    if vm.feedback_buffer_at(slot).is_none() {
        vm.map_feedback_buffer_at(slot)?;
    }
    Ok(vm
        .feedback_buffer_at(slot)
        .map(|b| b[..len.min(b.len())].to_vec())
        .unwrap_or_default())
}

fn maybe_wait_for_ctrl_c(wait: bool) {
    if wait {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;

        info!("Press Ctrl-C to exit...");

        let running = Arc::new(AtomicBool::new(true));
        let r = running.clone();

        ctrlc::set_handler(move || {
            r.store(false, Ordering::SeqCst);
        })
        .expect("Error setting Ctrl-C handler");

        while running.load(Ordering::SeqCst) {
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
    }
}

/// Log an optional configuration value at debug level.
macro_rules! debug_opt {
    ($label:expr, $value:expr) => {
        if let Some(ref v) = $value {
            debug!("  {:<14}{}", $label, v);
        }
    };
    ($label:expr, $value:expr, $fmt:expr) => {
        if let Some(ref v) = $value {
            debug!("  {:<14}{}", $label, format!($fmt, v));
        }
    };
}

fn build_rdrand_config(args: &Args) -> RdrandConfig {
    match args.rdrand_mode {
        RdrandMode::Seeded => RdrandConfig::seeded_rng(args.rdrand_seed),
        RdrandMode::Userspace => RdrandConfig::exit_to_userspace(),
    }
}

/// `--event-categories` selects non-exit kinds; `--exit-capture` /
/// `--single-step` own the `EXIT` category and trigger.
fn build_event_config(args: &Args) -> EventConfig {
    let mut categories = parse_event_categories(&args.event_categories);
    categories.0 &= !EventCategories::EXIT.0;
    // Serial is the console, so it is always on.
    categories = categories.union(EventCategories::SERIAL);

    let (trigger, target_tsc) = args.exit_trigger();
    if trigger != ExitTrigger::Disabled {
        categories = categories.union(EventCategories::EXIT);
    }

    let mut config = EventConfig::enabled(categories)
        .with_exit_trigger(trigger, target_tsc)
        .with_exit_start_tsc(args.capture_exits_after_tsc.unwrap_or(0));
    if args.no_memory_hash {
        config = config.with_no_memory_hash();
    }
    if args.intercept_pf {
        config = config.with_intercept_pf();
    }
    config
}

/// Parse a comma-separated list of event categories into a mask.
fn parse_event_categories(s: &str) -> EventCategories {
    let all = EventCategories::EXIT
        .union(EventCategories::SERIAL)
        .union(EventCategories::INJECT)
        .union(EventCategories::RANDOMNESS)
        .union(EventCategories::IO_CHANNEL)
        .union(EventCategories::DIAGNOSTIC);
    let mut mask = EventCategories::empty();
    for tok in s.split(',') {
        let tok = tok.trim();
        if tok.is_empty() {
            continue;
        }
        mask = mask.union(match tok.to_ascii_lowercase().as_str() {
            "exit" => EventCategories::EXIT,
            "serial" => EventCategories::SERIAL,
            "inject" => EventCategories::INJECT,
            "randomness" | "random" => EventCategories::RANDOMNESS,
            "io_channel" | "iochannel" | "io" => EventCategories::IO_CHANNEL,
            "diagnostic" | "diag" => EventCategories::DIAGNOSTIC,
            "all" => all,
            other => {
                warn!("unknown event category '{}', ignoring", other);
                EventCategories::empty()
            }
        });
    }
    mask
}

fn run() -> io::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let args = Args::parse();
    let memory_size = args.memory * 1024 * 1024;

    if args.parent_id.is_none() && args.vmlinux.is_none() {
        return Err(io::Error::other(
            "vmlinux path is required when creating a root VM (not using --parent-id)",
        ));
    }

    debug!("Configuration:");
    if let Some(ref vmlinux) = args.vmlinux {
        debug!("  {:<14}{}", "Kernel:", vmlinux);
    }
    debug!("  {:<14}{} MB", "Memory:", args.memory);
    debug!("  {:<14}\"{}\"", "Command line:", args.cmdline);
    debug_opt!("Initramfs:", args.initramfs);
    debug_opt!("Log file:", args.serial_log_file);
    debug!(
        "  {:<14}{}",
        "RDRAND mode:",
        match args.rdrand_mode {
            RdrandMode::Seeded => format!("seeded (seed: {:#x})", args.rdrand_seed),
            RdrandMode::Userspace => "userspace (exit to userspace)".to_string(),
        }
    );
    if args.should_capture_exits() {
        debug!("  {:<14}enabled", "Exit capture:");
    }
    debug_opt!("Events JSONL:", args.events_jsonl);
    debug_opt!(
        "Single-step:",
        args.single_step
            .map(|(s, e)| format!("TSC range [{}, {})", s, e))
    );
    debug_opt!("Stop at TSC:", args.stop_at_tsc);

    let log_file: Option<File> = args
        .serial_log_file
        .as_ref()
        .map(File::create)
        .transpose()?;
    let mut output = LineBufferedOutput::new(log_file);

    let rdrand_config = build_rdrand_config(&args);

    let mut builder = VmBuilder::new().rdrand(rdrand_config);

    let tsc_frequency = args.virt_tsc_frequency.unwrap_or(DEFAULT_TSC_FREQUENCY);

    if let Some(parent_id) = args.parent_id {
        debug!("  Parent VM ID: {}", parent_id);
        builder = builder.forked_from(parent_id);
    } else {
        builder = builder
            .memory_size(memory_size)
            .tsc_frequency(tsc_frequency);
    }

    if let Some((start, end)) = args.single_step {
        builder = builder.single_step(start, end);
    }
    let stop_at_tsc = args
        .stop_at_tsc
        .or_else(|| args.stop_at_vt.map(|vt| (vt * tsc_frequency as f64) as u64));
    if let Some(tsc) = stop_at_tsc {
        builder = builder.stop_at_tsc(tsc);
    }

    let mut vm: Vm = builder.build().map_err(|e| {
        io::Error::other(
            format!(
                "Failed to create VM: {}\nMake sure the bedrock kernel module is loaded:\n  sudo insmod bedrock.ko\nDevice path: {}",
                e, BEDROCK_DEVICE_PATH
            ),
        )
    })?;

    if let Some(parent_id) = args.parent_id {
        info!("Created forked VM (from parent {})", parent_id);
    } else {
        info!(
            "Created VM with {} MB guest memory",
            memory_size / (1024 * 1024)
        );
    }

    let mut events_jsonl_file: Option<std::io::BufWriter<File>> =
        if let Some(ref path) = args.events_jsonl {
            Some(std::io::BufWriter::new(File::create(path)?))
        } else {
            None
        };
    let mut total_event_count: usize = 0;

    // Always enabled: guest serial output flows through it.
    let event_config = build_event_config(&args);
    vm.set_event_config(&event_config)
        .map_err(|e| io::Error::other(format!("failed to enable event stream: {}", e)))?;
    info!(
        "Event stream enabled (categories={:#x})",
        event_config.categories
    );
    if args.should_capture_exits() && args.events_jsonl.is_none() {
        warn!("--exit-capture/--single-step capture exit records but --events-jsonl is not set; they will not be saved");
    }

    if vm.is_root() {
        let vmlinux = args.vmlinux.as_ref().expect("vmlinux required for root VM");

        let kernel_data = read_file(vmlinux)?;

        let initramfs_data = args.initramfs.as_ref().map(|p| read_file(p)).transpose()?;

        info!("Loading kernel from {}", vmlinux);
        let memory = vm.memory_mut().expect("Root VM must have memory");
        let (kernel_entry, kernel_end) = load_kernel(memory, &kernel_data)?;
        debug!("  Kernel entry point: {:#x}", kernel_entry);
        debug!("  Kernel ends at: {:#x}", kernel_end);

        let mut boot_config = LinuxBootConfig::new(kernel_entry, kernel_end).cmdline(&args.cmdline);

        if let Some(ref data) = initramfs_data {
            info!("Loading initramfs ({} bytes)", data.len());
            boot_config = boot_config.initramfs(data);
        }

        debug!("Setting up Linux boot structures...");
        let boot_info = vm.setup_linux_boot(&boot_config).map_err(io_error)?;
        trace!(
            "  GDT at {:#x}, limit {:#x}",
            boot_info.gdt_base,
            boot_info.gdt_limit
        );
        if let Some(addr) = boot_info.initramfs_addr {
            debug!("  Initramfs at {:#x}", addr);
        }
    }

    // Queue all I/O actions upfront into the hypervisor's FIFO; sorting keeps
    // the order deterministic when target_tscs tie.
    let mut io_schedule: Vec<ScheduledIoAction> = args.io_actions.clone();
    io_schedule.sort_by_key(|a| a.target_tsc);
    for (idx, sched) in io_schedule.iter().enumerate() {
        let bytes = encode_io_action(&sched.action);
        match vm.queue_io_action(&bytes, sched.target_tsc) {
            Ok(()) => debug!(
                "Queued I/O action {}/{} (target_tsc={}): {:?}",
                idx + 1,
                io_schedule.len(),
                sched.target_tsc,
                sched.action
            ),
            Err(e) => warn!("Failed to queue I/O action {}: {}", idx + 1, e),
        }
    }
    if !io_schedule.is_empty() {
        info!("Queued {} I/O actions", io_schedule.len());
    }

    // Serves `--file` mappings to the guest's file-fetch hypercall.
    let mut file_server =
        FileServer::new(args.files.iter().map(|f| (f.name.clone(), f.path.clone())));
    if !file_server.is_empty() {
        info!(
            "Serving {} file(s) over the file-transmission hypercall: {}",
            args.files.len(),
            file_server.names().collect::<Vec<_>>().join(", ")
        );
    }

    // Receives files the guest stores to the host.
    let mut file_writer = FileWriter::new();

    // Only used to answer HYPERCALL_FUZZ_NEXT_INPUT with eof.
    let mut input_server = InputServer::new();

    info!("Starting VM...");
    let wall_clock_start = std::time::Instant::now();
    let timeout_duration = args
        .wall_clock_timeout
        .map(std::time::Duration::from_secs_f64);

    loop {
        if let Some(timeout) = timeout_duration {
            if wall_clock_start.elapsed() >= timeout {
                info!("Wall-clock timeout reached ({:.1}s)", timeout.as_secs_f64());
                break;
            }
        }

        match vm.run() {
            Ok(exit) => {
                // Print `Serial` records; write all records to --events-jsonl.
                if exit.event_len > 0 {
                    if let Some(buffer) = vm.event_buffer() {
                        let drained = &buffer[..(exit.event_len as usize).min(buffer.len())];
                        for rec in EventStream::new(drained) {
                            if rec.kind() == EventKind::Serial.as_u16() {
                                output.write_serial_record(
                                    rec.payload,
                                    rec.tsc(),
                                    exit.tsc_frequency,
                                );
                            }
                            if let Some(ref mut w) = events_jsonl_file {
                                let _ = serde_json::to_writer(&mut *w, &rec.to_json());
                                let _ = writeln!(w);
                                total_event_count += 1;
                            }
                        }
                    }
                }

                match exit.kind() {
                    ExitKind::VmcallShutdown => {
                        info!("VM shutdown (VMCALL hypercall)");
                        break;
                    }
                    ExitKind::VmcallSnapshot { tag } => {
                        let vm_id = vm.get_vm_id().unwrap_or(0);
                        info!(
                            "VM snapshot: vm_id={}, tag={}, tsc={}",
                            vm_id, tag, exit.emulated_tsc
                        );
                        maybe_wait_for_ctrl_c(args.wait);
                        break;
                    }
                    ExitKind::StopTscReached => {
                        let vm_id = vm.get_vm_id().unwrap_or(0);
                        let vt = exit.emulated_tsc as f64 / exit.tsc_frequency as f64;
                        info!(
                            "VM stopped at TSC {} (vt {:.3}s, stop-at-tsc), vm_id={}",
                            exit.emulated_tsc, vt, vm_id
                        );

                        maybe_wait_for_ctrl_c(args.wait);
                        break;
                    }
                    ExitKind::FeedbackBufferRegistered => {
                        debug!("Feedback buffer registered");
                        continue;
                    }
                    ExitKind::IoResponse => {
                        match vm.drain_io_response() {
                            Ok(bytes) => match io_channel::decode_response(&bytes) {
                                Some(resp) => {
                                    info!(
                                        "I/O response: status={} exit_code={} output_len={}",
                                        resp.status, resp.exit_code, resp.output_len
                                    );
                                    if resp.output_len > 0 {
                                        match read_io_output(&mut vm, resp.output_len as usize) {
                                            Ok(out) => {
                                                print!("{}", String::from_utf8_lossy(&out));
                                                let _ = io::stdout().flush();
                                            }
                                            Err(e) => {
                                                warn!("Failed to read recorded output: {}", e)
                                            }
                                        }
                                    }
                                }
                                None => warn!("Failed to decode I/O response header"),
                            },
                            Err(e) => warn!("Failed to drain I/O response: {}", e),
                        }
                        continue;
                    }
                    ExitKind::VmcallReady => {
                        info!("VM ready (VMCALL hypercall) at tsc {}", exit.emulated_tsc);
                        continue;
                    }
                    ExitKind::FileFetch => {
                        match file_server.serve(&mut vm) {
                            Ok(n) => trace!("Served file chunk ({} bytes)", n),
                            Err(e) => warn!("Failed to serve file fetch: {}", e),
                        }
                        continue;
                    }
                    ExitKind::FileStore => {
                        match file_writer.write(&mut vm) {
                            Ok(n) => trace!("Wrote file chunk ({} bytes)", n),
                            Err(e) => warn!("Failed to write guest file chunk on host: {}", e),
                        }
                        continue;
                    }
                    ExitKind::FuzzNextInput => {
                        // bedrock-cli is not a fuzzer.
                        log::error!("bedrock-cli encountered ExitKind::FuzzNextInput!");
                        break;
                    }
                    ExitKind::Continue | ExitKind::EventBufferFull => continue,
                    ExitKind::Rdrand | ExitKind::Rdseed | ExitKind::VmcallGetRandom => {
                        warn!(
                            "VM exit: RDRAND/RDSEED/GET_RANDOM in userspace mode not supported by CLI"
                        );
                        break;
                    }
                    ExitKind::UnhandledExit { reason } => {
                        log_vm_exit(&vm, &format!("{} ({})", reason, exit.reason_str()));
                        if let Ok(regs) = vm.get_regs() {
                            // For MSR exits, RCX holds the MSR index
                            if reason == 31 || reason == 32 {
                                warn!("  MSR index: {:#x} (ECX)", regs.gprs.rcx as u32);
                            }
                            warn!(
                                "  RAX={:#018x} RCX={:#018x} RDX={:#018x}",
                                regs.gprs.rax, regs.gprs.rcx, regs.gprs.rdx
                            );
                        }
                        break;
                    }
                }
            }
            Err(e) => {
                if e.kind() == io::ErrorKind::Unsupported {
                    log::error!(
                        "VM run is unsupported by the loaded Bedrock module or host configuration"
                    );
                    return Err(e);
                }
                log::error!("VM run failed: {}", e);
                if let Ok(regs) = vm.get_regs() {
                    log::error!("  RIP: {:#018x}, RFLAGS: {:#018x}", regs.rip, regs.rflags);
                }
                return Err(io::Error::other(e.to_string()));
            }
        }
    }

    output.flush_partial();

    if let Some(ref mut w) = events_jsonl_file {
        let _ = w.flush();
    }
    if let Some(ref path) = args.events_jsonl {
        info!("Wrote {} event records to {}", total_event_count, path);
    }

    let wall_clock_elapsed = wall_clock_start.elapsed();
    if let Ok(stats) = vm.get_exit_stats() {
        if let Some(ref path) = args.exit_stats_json {
            let json = serde_json::to_string_pretty(&stats).map_err(io_error)?;
            std::fs::write(path, json)?;
            debug!("Wrote exit stats to {}", path);
        }

        println!(
            "{}",
            ExitStatsReport {
                stats: &stats,
                wall_clock: wall_clock_elapsed
            }
        );
    } else {
        warn!("Failed to retrieve exit statistics");
    }

    println!("{}", vm.get_ioctl_stats());

    Ok(())
}

fn read_file(path: &str) -> io::Result<Vec<u8>> {
    let mut file = File::open(path)?;
    let mut data = Vec::new();
    file.read_to_end(&mut data)?;
    Ok(data)
}

fn io_error<E: std::fmt::Display>(e: E) -> io::Error {
    io::Error::other(e.to_string())
}
