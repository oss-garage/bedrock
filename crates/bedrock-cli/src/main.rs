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

use bedrock_vm::{
    load_kernel, parse_line_tsc_entries, ExitKind, ExitStatsReport, LineTscEntry, LinuxBootConfig,
    LogConfig, LogEntry, RdrandConfig, Vm, VmBuilder, BEDROCK_DEVICE_PATH, DEFAULT_TSC_FREQUENCY,
};

use args::{Args, IoAction, RdrandMode, ScheduledIoAction};

/// Line-buffered output that prefixes each line with a virtual time timestamp.
///
/// The timestamp format is `[vt x.xxx]` where x.xxx is the emulated TSC
/// converted to seconds since VM start. Uses per-line TSC values from
/// serial buffer metadata when available for accurate timestamps.
struct LineBufferedOutput {
    /// Partial line buffer (content before newline received).
    buffer: String,
    /// Optional file to write raw output (without timestamps).
    log_file: Option<File>,
}

impl LineBufferedOutput {
    fn new(log_file: Option<File>) -> Self {
        Self {
            buffer: String::new(),
            log_file,
        }
    }

    /// Process output from the guest, adding timestamps to each complete line.
    ///
    /// If `line_entries` is provided, uses per-line TSC values for accurate timestamps.
    /// Otherwise falls back to using `fallback_tsc` for all lines.
    fn write_with_line_tsc(
        &mut self,
        output: &str,
        line_entries: Option<&[LineTscEntry]>,
        fallback_tsc: u64,
        tsc_frequency: u64,
    ) {
        // Write raw output to log file if present
        if let Some(ref mut f) = self.log_file {
            let _ = f.write_all(output.as_bytes());
            let _ = f.flush();
        }

        // Track current byte offset to match with line entries
        let mut byte_offset: usize = 0;
        let mut line_idx: usize = 0;

        // Process output character by character
        for ch in output.chars() {
            if ch == '\n' {
                // Complete line - find the TSC for this line
                let tsc = if let Some(entries) = line_entries {
                    // Find the entry whose offset matches the start of this line
                    // The buffer contains the line content (excluding newline)
                    // The line started at (byte_offset - buffer.len())
                    let line_start = byte_offset.saturating_sub(self.buffer.len());
                    entries
                        .iter()
                        .skip(line_idx)
                        .find(|e| e.offset as usize == line_start)
                        .map(|e| {
                            line_idx += 1;
                            e.tsc
                        })
                        .unwrap_or(fallback_tsc)
                } else {
                    fallback_tsc
                };

                let secs = tsc as f64 / tsc_frequency as f64;
                println!("[vt {:>8.3}] {}", secs, self.buffer);
                self.buffer.clear();
            } else {
                self.buffer.push(ch);
            }
            byte_offset += ch.len_utf8();
        }

        let _ = std::io::stdout().flush();
    }

    /// Flush any remaining partial line (without timestamp since it's incomplete).
    fn flush_partial(&mut self) {
        if !self.buffer.is_empty() {
            print!("{}", self.buffer);
            let _ = std::io::stdout().flush();
            self.buffer.clear();
        }
    }
}

fn main() {
    if let Err(e) = run() {
        eprintln!("Error: {}", e);
        process::exit(1);
    }
}

/// Log a VM exit warning with RIP.
fn log_vm_exit(vm: &Vm, msg: &str) {
    let rip = vm.get_regs().map(|r| r.rip).unwrap_or(0);
    warn!("VM exit: {} at RIP {:#018x}", msg, rip);
}

/// Request-side magic on the I/O channel shared page; must match the
/// `IO_REQUEST_MAGIC` constant in `bedrock-io.c`.
const IO_REQUEST_MAGIC: u32 = 0xB10C1010;
/// Response-side magic.
const IO_RESPONSE_MAGIC: u32 = 0x1010B10C;
/// Action ID for "list running containers".
const ACTION_GET_WORKLOAD_DETAILS: u32 = 0;
/// Action ID for "exec bash command in a container".
const ACTION_EXEC_BASH: u32 = 1;
/// Action ID for "exec bash command on the guest itself (outside any container)".
const ACTION_EXEC_HOST_BASH: u32 = 2;

/// Serialize an `IoAction` into the wire format the guest module parses.
///
/// Header layout: `u32 magic | u32 action_id | u32 payload_len`, followed
/// by `payload_len` bytes of action-specific payload. For `ExecBash` the
/// payload is two NUL-terminated strings (`container\0cmd\0`) so the guest
/// can use plain `strnlen` to find the boundary. For `ExecHostBash` the
/// payload is a single NUL-terminated `cmd\0`.
fn encode_io_action(action: &IoAction) -> Vec<u8> {
    let (action_id, payload) = match action {
        IoAction::GetWorkloadDetails => (ACTION_GET_WORKLOAD_DETAILS, Vec::new()),
        IoAction::ExecBash { container, cmd } => {
            let mut p = Vec::with_capacity(container.len() + cmd.len() + 2);
            p.extend_from_slice(container.as_bytes());
            p.push(0);
            p.extend_from_slice(cmd.as_bytes());
            p.push(0);
            (ACTION_EXEC_BASH, p)
        }
        IoAction::ExecHostBash { cmd } => {
            let mut p = Vec::with_capacity(cmd.len() + 1);
            p.extend_from_slice(cmd.as_bytes());
            p.push(0);
            (ACTION_EXEC_HOST_BASH, p)
        }
    };
    let mut bytes = Vec::with_capacity(12 + payload.len());
    bytes.extend_from_slice(&IO_REQUEST_MAGIC.to_le_bytes());
    bytes.extend_from_slice(&action_id.to_le_bytes());
    bytes.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&payload);
    bytes
}

/// Parse the response header out of the bytes drained from the I/O channel.
/// Returns `(status, exit_code, data)` where `data` is a borrow into the
/// caller's buffer covering only the payload region.
fn decode_io_response(bytes: &[u8]) -> Result<(i32, i32, &[u8]), String> {
    if bytes.len() < 16 {
        return Err(format!("response too short: {} bytes", bytes.len()));
    }
    let magic = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    if magic != IO_RESPONSE_MAGIC {
        return Err(format!("bad response magic {:#x}", magic));
    }
    let status = i32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    let exit_code = i32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
    let data_len = u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]) as usize;
    let data_end = 16 + data_len;
    if data_end > bytes.len() {
        return Err(format!(
            "response data overruns: {} > {}",
            data_end,
            bytes.len()
        ));
    }
    Ok((status, exit_code, &bytes[16..data_end]))
}

/// Dump the feedback buffer to a file.
fn dump_feedback_buffer(vm: &mut Vm, path: &str) -> io::Result<()> {
    // Check if feedback buffer is registered
    let info = match vm.get_feedback_buffer_info()? {
        Some(info) => info,
        None => {
            warn!("No feedback buffer registered, skipping dump");
            return Ok(());
        }
    };

    // Map the feedback buffer if not already mapped
    let buffer = match vm.feedback_buffer() {
        Some(buf) => buf,
        None => vm.map_feedback_buffer()?,
    };

    // Write to file
    let mut file = File::create(path)?;
    file.write_all(buffer)?;

    info!(
        "Dumped feedback buffer to {} ({} bytes, {} pages)",
        path,
        buffer.len(),
        info.num_pages
    );

    Ok(())
}

/// Wait for Ctrl-C if wait flag is set.
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

/// Build RDRAND config from command-line arguments.
fn build_rdrand_config(args: &Args) -> RdrandConfig {
    match args.rdrand_mode {
        RdrandMode::Seeded => RdrandConfig::seeded_rng(args.rdrand_seed),
        RdrandMode::Userspace => RdrandConfig::exit_to_userspace(),
    }
}

/// Build log config from command-line arguments.
/// Returns None if logging is not enabled.
fn build_log_config(args: &Args) -> Option<LogConfig> {
    let log_start_tsc = args.log_after_tsc.unwrap_or(0);

    let config = if args.single_step.is_some() {
        // Single-step mode uses TscRange logging
        Some(LogConfig::tsc_range().with_start_tsc(log_start_tsc))
    } else if args.log_at_shutdown {
        Some(LogConfig::at_shutdown().with_start_tsc(log_start_tsc))
    } else if let Some(target_tsc) = args.log_at_tsc {
        Some(LogConfig::at_tsc(target_tsc).with_start_tsc(log_start_tsc))
    } else if let Some(interval) = args.log_checkpoints {
        Some(LogConfig::checkpoints(interval).with_start_tsc(log_start_tsc))
    } else if args.should_enable_log() {
        Some(LogConfig::all_exits(0).with_start_tsc(log_start_tsc))
    } else {
        None
    };

    let config = if args.no_memory_hash {
        config.map(|c| c.with_no_memory_hash())
    } else {
        config
    };

    if args.intercept_pf {
        config.map(|c| c.with_intercept_pf())
    } else {
        config
    }
}

fn run() -> io::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let args = Args::parse();
    let memory_size = args.memory * 1024 * 1024;

    // Validate: vmlinux is required for root VMs (not forked)
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
    debug_opt!("Log file:", args.log);
    debug_opt!(
        "Serial input:",
        args.input.as_ref().map(|i| format!("{} bytes", i.len()))
    );
    debug!(
        "  {:<14}{}",
        "RDRAND mode:",
        match args.rdrand_mode {
            RdrandMode::Seeded => format!("seeded (seed: {:#x})", args.rdrand_seed),
            RdrandMode::Userspace => "userspace (exit to userspace)".to_string(),
        }
    );
    if args.should_enable_log() {
        debug!("  {:<14}enabled", "Exit logging:");
        debug_opt!("Log JSONL:", args.log_jsonl);
    }
    debug_opt!(
        "Single-step:",
        args.single_step
            .map(|(s, e)| format!("TSC range [{}, {})", s, e))
    );
    debug_opt!("Stop at TSC:", args.stop_at_tsc);

    // Open log file if specified and create line-buffered output
    let log_file: Option<File> = args.log.as_ref().map(File::create).transpose()?;
    let mut output = LineBufferedOutput::new(log_file);

    // Build configs from args
    let rdrand_config = build_rdrand_config(&args);
    let log_config = build_log_config(&args);

    // Build VM configuration
    let mut builder = VmBuilder::new().rdrand(rdrand_config);

    let tsc_frequency = args.tsc_frequency.unwrap_or(DEFAULT_TSC_FREQUENCY);

    if let Some(parent_id) = args.parent_id {
        debug!("  Parent VM ID: {}", parent_id);
        builder = builder.forked_from(parent_id);
    } else {
        builder = builder
            .memory_size(memory_size)
            .tsc_frequency(tsc_frequency);
    }

    if let Some(config) = log_config {
        builder = builder.logging(config);
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

    // Create VM
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

        // For forked VMs, map feedback buffer immediately if it exists and dump is requested
        if args.dump_feedback.is_some() {
            if let Ok(Some(_info)) = vm.get_feedback_buffer_info() {
                if let Err(e) = vm.map_feedback_buffer() {
                    warn!("Failed to map feedback buffer: {}", e);
                } else {
                    info!("Feedback buffer mapped (inherited from parent)");
                }
            }
        }
    } else {
        info!(
            "Created VM with {} MB guest memory",
            memory_size / (1024 * 1024)
        );
    }

    // Open JSONL files for logging (deterministic + non-deterministic)
    let mut log_jsonl_file: Option<std::io::BufWriter<File>> =
        if let Some(ref path) = args.log_jsonl {
            let f = File::create(path)?;
            Some(std::io::BufWriter::new(f))
        } else {
            None
        };
    let mut log_jsonl_nondeterm_file: Option<std::io::BufWriter<File>> =
        if let Some(ref path) = args.log_jsonl {
            let nondeterm_path = if let Some(stem) = path.strip_suffix(".jsonl") {
                format!("{}-nondeterm.jsonl", stem)
            } else {
                format!("{}-nondeterm", path)
            };
            let f = File::create(&nondeterm_path)?;
            Some(std::io::BufWriter::new(f))
        } else {
            None
        };
    let mut total_log_count: usize = 0;
    let mut total_nondeterm_log_count: usize = 0;

    // Setup for new VMs (not forked)
    if vm.is_root() {
        let vmlinux = args.vmlinux.as_ref().expect("vmlinux required for root VM");

        // Read kernel file
        let kernel_data = read_file(vmlinux)?;

        // Read initramfs if provided
        let initramfs_data = args.initramfs.as_ref().map(|p| read_file(p)).transpose()?;

        // Load kernel into guest memory
        info!("Loading kernel from {}", vmlinux);
        let memory = vm.memory_mut().expect("Root VM must have memory");
        let (kernel_entry, kernel_end) = load_kernel(memory, &kernel_data)?;
        debug!("  Kernel entry point: {:#x}", kernel_entry);
        debug!("  Kernel ends at: {:#x}", kernel_end);

        // Build Linux boot configuration
        let mut boot_config = LinuxBootConfig::new(kernel_entry, kernel_end).cmdline(&args.cmdline);

        if let Some(ref data) = initramfs_data {
            info!("Loading initramfs ({} bytes)", data.len());
            boot_config = boot_config.initramfs(data);
        }

        if let Some(ref input) = args.input {
            debug!("Serial input: {} bytes queued", input.len());
            boot_config = boot_config.serial_input(input.as_bytes());
        }

        // Setup Linux boot (GDT, page tables, MP tables, boot_params, registers)
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

    // Queue all I/O actions upfront. The hypervisor owns the pending
    // FIFO and the guest module spawns parallel workers, so the CLI's
    // job is just to push every scheduled action into the queue before
    // the VM starts running. Sorting by target_tsc keeps the FIFO order
    // deterministic when target_tscs are identical or zero.
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

    // Run VM
    info!("Starting VM...");
    let wall_clock_start = std::time::Instant::now();
    let timeout_duration = args.timeout.map(std::time::Duration::from_secs_f64);

    loop {
        // Check wall-clock timeout
        if let Some(timeout) = timeout_duration {
            if wall_clock_start.elapsed() >= timeout {
                info!("Wall-clock timeout reached ({:.1}s)", timeout.as_secs_f64());
                break;
            }
        }

        match vm.run() {
            Ok(exit) => {
                // Print serial output with timestamps
                if exit.serial_len > 0 {
                    let serial_str = vm.serial_output_str(exit.serial_len as usize);
                    // Parse line TSC entries from the TSC metadata page for accurate per-line timestamps
                    let line_entries = parse_line_tsc_entries(vm.serial_tsc_buffer());
                    output.write_with_line_tsc(
                        serial_str,
                        line_entries.as_deref(),
                        exit.emulated_tsc,
                        exit.tsc_frequency,
                    );
                }

                // Write log entries to JSONL (split by deterministic flag)
                if exit.log_entry_count > 0 {
                    if let Some(buffer) = vm.log_buffer() {
                        let entries = LogEntry::from_buffer(buffer, exit.log_entry_count as usize);
                        for entry in entries {
                            if entry.is_deterministic() {
                                if let Some(ref mut w) = log_jsonl_file {
                                    let _ = serde_json::to_writer(&mut *w, entry);
                                    let _ = writeln!(w);
                                }
                                total_log_count += 1;
                            } else {
                                if let Some(ref mut w) = log_jsonl_nondeterm_file {
                                    let _ = serde_json::to_writer(&mut *w, entry);
                                    let _ = writeln!(w);
                                }
                                total_nondeterm_log_count += 1;
                            }
                        }
                    }
                }

                // Use the new ExitKind enum for cleaner matching
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

                        // Dump feedback buffer if requested
                        if let Some(ref path) = args.dump_feedback {
                            dump_feedback_buffer(&mut vm, path)?;
                        }

                        maybe_wait_for_ctrl_c(args.wait);
                        break;
                    }
                    ExitKind::FeedbackBufferRegistered => {
                        // Map the feedback buffer for later dumping
                        if args.dump_feedback.is_some() {
                            if let Err(e) = vm.map_feedback_buffer() {
                                warn!("Failed to map feedback buffer: {}", e);
                            } else {
                                info!("Feedback buffer registered and mapped");
                            }
                        } else {
                            debug!(
                                "Feedback buffer registered (not mapping, --dump-feedback not set)"
                            );
                        }
                        continue;
                    }
                    ExitKind::IoResponse => {
                        match vm.drain_io_response() {
                            Ok(bytes) => match decode_io_response(&bytes) {
                                Ok((status, exit_code, data)) => {
                                    info!(
                                        "I/O response: status={} exit_code={} ({} bytes)",
                                        status,
                                        exit_code,
                                        data.len()
                                    );
                                    if !data.is_empty() {
                                        print!("{}", String::from_utf8_lossy(data));
                                        let _ = io::stdout().flush();
                                    }
                                }
                                Err(e) => warn!("Failed to decode I/O response: {}", e),
                            },
                            Err(e) => warn!("Failed to drain I/O response: {}", e),
                        }
                        continue;
                    }
                    ExitKind::VmcallReady => {
                        info!("VM ready (VMCALL hypercall) at tsc {}", exit.emulated_tsc);
                        continue;
                    }
                    ExitKind::Continue | ExitKind::LogBufferFull => continue,
                    ExitKind::Rdrand | ExitKind::Rdseed => {
                        warn!("VM exit: RDRAND/RDSEED in userspace mode not supported by CLI");
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
                log::error!("VM run failed: {}", e);
                if let Ok(regs) = vm.get_regs() {
                    log::error!("  RIP: {:#018x}, RFLAGS: {:#018x}", regs.rip, regs.rflags);
                }
                return Err(io::Error::other(e.to_string()));
            }
        }
    }

    // Flush any partial line from guest output
    output.flush_partial();

    // Flush JSONL files
    if let Some(ref mut jsonl_writer) = log_jsonl_file {
        let _ = jsonl_writer.flush();
    }
    if let Some(ref mut jsonl_writer) = log_jsonl_nondeterm_file {
        let _ = jsonl_writer.flush();
    }
    if let Some(ref path) = args.log_jsonl {
        if total_log_count > 0 {
            info!(
                "Wrote {} deterministic log entries to {}",
                total_log_count, path
            );
        } else {
            debug!("No deterministic log entries written to {}", path);
        }
        if total_nondeterm_log_count > 0 {
            let nondeterm_path = if let Some(stem) = path.strip_suffix(".jsonl") {
                format!("{}-nondeterm.jsonl", stem)
            } else {
                format!("{}-nondeterm", path)
            };
            info!(
                "Wrote {} non-deterministic log entries to {}",
                total_nondeterm_log_count, nondeterm_path
            );
        }
    }

    // Display exit statistics after VM shutdown
    let wall_clock_elapsed = wall_clock_start.elapsed();
    if let Ok(stats) = vm.get_exit_stats() {
        // Write exit stats JSON if requested
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

    // Display userspace ioctl timing statistics
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
