// SPDX-License-Identifier: GPL-2.0

//! Determinism checker - invokes bedrock-cli multiple times and compares output.
//!
//! All run data is persisted to a work directory for later analysis.

use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use clap::Parser;

use bedrock_vm::{ExitRecord, ExitStats, Vm, DEFAULT_TSC_FREQUENCY};

const DEFAULT_RUNS: usize = 10;
// Sourced from bedrock-cli's default so the two tools stay in lockstep.
const DEFAULT_MEMORY_MB: usize = bedrock_vm::boot::defaults::MEMORY_MB;

#[derive(Parser, Debug)]
#[command(name = "bedrock-determinism")]
#[command(about = "Determinism checker for the bedrock hypervisor")]
struct Args {
    /// Path to vmlinux ELF image (not required with --parent-id)
    vmlinux: Option<String>,

    /// Top-level directory for storing test results (a timestamped subdirectory is created automatically)
    #[arg(short = 'w', long)]
    workdir: PathBuf,

    /// Optional name for the test subdirectory (default: auto-generated timestamp)
    #[arg(long)]
    test_name: Option<String>,

    /// Path to initramfs/initrd image
    #[arg(short = 'i', long)]
    initramfs: Option<String>,

    /// Guest memory size in MB
    #[arg(short = 'm', long, default_value_t = DEFAULT_MEMORY_MB)]
    memory: usize,

    /// Kernel command line
    #[arg(short = 'c', long)]
    cmdline: Option<String>,

    /// Number of runs
    #[arg(short = 'n', long, default_value_t = DEFAULT_RUNS)]
    runs: usize,

    /// Seed/value for RDRAND
    #[arg(short = 's', long = "rdrand-seed")]
    rdrand_seed: Option<u64>,

    /// Stop VM when emulated TSC reaches this value
    #[arg(long = "stop-at-tsc", conflicts_with = "stop_at_vt")]
    stop_at_tsc: Option<u64>,

    /// Stop VM when virtual time reaches this value (seconds, e.g. 3374.539)
    #[arg(long = "stop-at-vt", conflicts_with = "stop_at_tsc")]
    stop_at_vt: Option<f64>,

    /// Number of parallel jobs (default: 1, sequential)
    #[arg(short = 'j', long, default_value_t = 1)]
    parallel: usize,

    /// Quiet mode (no serial output)
    #[arg(short = 'q', long)]
    quiet: bool,

    /// Capture exit records at TSC intervals instead of at shutdown.
    /// Periodic state snapshots help locate the divergence window.
    #[arg(long = "checkpoint-interval")]
    checkpoint_interval: Option<u64>,

    /// Single-step (MTF) for TSC range (e.g., 12580000000-12590000000)
    #[arg(long = "single-step", value_parser = parse_tsc_range)]
    single_step: Option<(u64, u64)>,

    /// Capture exit records only after emulated TSC reaches this threshold.
    /// Applies to all capture modes (checkpoints, single-step, etc.)
    #[arg(long = "capture-exits-after-tsc")]
    capture_exits_after_tsc: Option<u64>,

    /// Parent VM ID for forked VM testing (passes --parent-id to CLI)
    #[arg(long = "parent-id", value_parser = parse_u64)]
    parent_id: Option<u64>,

    /// Wall-clock timeout in seconds for each VM run (default: 10)
    #[arg(long = "wall-clock-timeout", default_value_t = 10.0)]
    wall_clock_timeout: f64,

    /// Capture every deterministic exit (high overhead, large event streams)
    #[arg(long = "all-exits")]
    all_exits: bool,

    /// Skip memory hashing in exit records (memory_hash will be 0)
    #[arg(long = "no-memory-hash")]
    no_memory_hash: bool,

    /// Intercept guest #PF exceptions (logged and reinjected for determinism analysis)
    #[arg(long = "intercept-pf")]
    intercept_pf: bool,

    /// Pushover API token for divergence notifications
    #[arg(long = "pushover-token")]
    pushover_token: Option<String>,

    /// Pushover user key for divergence notifications
    #[arg(long = "pushover-user")]
    pushover_user: Option<String>,
}

/// Parse a u64 value from a string, supporting hex (0x prefix) and decimal.
fn parse_u64(s: &str) -> Result<u64, String> {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).map_err(|_| format!("Invalid hex value: {}", s))
    } else {
        s.parse().map_err(|_| format!("Invalid number: {}", s))
    }
}

/// Parse a TSC range in the format "START-END".
fn parse_tsc_range(s: &str) -> Result<(u64, u64), String> {
    let parts: Vec<&str> = s.split('-').collect();
    if parts.len() != 2 {
        return Err(format!(
            "Invalid TSC range '{}'. Expected format: START-END",
            s
        ));
    }
    let start: u64 = parts[0]
        .parse()
        .map_err(|_| format!("Invalid start: {}", parts[0]))?;
    let end: u64 = parts[1]
        .parse()
        .map_err(|_| format!("Invalid end: {}", parts[1]))?;
    if end <= start {
        return Err(format!("end ({}) must be > start ({})", end, start));
    }
    Ok((start, end))
}

/// Send a Pushover notification. Errors are printed to stderr but not propagated.
fn send_pushover_notification(token: &str, user: &str, message: &str) {
    let params = [("token", token), ("user", user), ("message", message)];
    let client = reqwest::blocking::Client::new();
    if let Err(e) = client
        .post("https://api.pushover.net/1/messages.json")
        .form(&params)
        .send()
    {
        eprintln!("Failed to send pushover notification: {e}");
    }
}

/// Result from a single VM run.
struct RunResult {
    run_num: usize,
    /// For single-entry modes (AtShutdown), this contains the single entry.
    /// For checkpoint mode, this is empty and checkpoint_entries is used instead.
    exit_record: Option<ExitRecord>,
    /// Checkpoint entries (only used when --checkpoint-interval is set).
    checkpoint_entries: Vec<ExitRecord>,
    /// Path to the run directory containing all artifacts.
    run_dir: PathBuf,
    /// Exit statistics from the VM run.
    exit_stats: Option<ExitStats>,
    /// Wall-clock time for this run.
    wall_time: Duration,
}

/// Format a run failure with context from the run directory.
fn format_run_error(run_num: usize, run_dir: &Path, message: &str) -> String {
    let mut msg = format!(
        "Run {} failed: {}\n  Run directory: {:?}",
        run_num, message, run_dir
    );

    // Include stderr tail if available
    let stderr_file = run_dir.join("stderr.txt");
    if let Ok(content) = fs::read_to_string(&stderr_file) {
        let content = content.trim();
        if !content.is_empty() {
            let tail: Vec<&str> = content.lines().rev().take(10).collect();
            let tail: Vec<&str> = tail.into_iter().rev().collect();
            msg.push_str("\n  stderr (last 10 lines):\n");
            for line in tail {
                msg.push_str(&format!("    {}\n", line));
            }
        }
    }

    msg
}

/// Generate a descriptive test directory name from args and current time.
fn generate_test_dir_name(args: &Args, vmlinux: &str) -> String {
    let ts = unix_timestamp();
    // Format as YYYYMMDD-HHMMSS from unix timestamp
    let secs_per_day = 86400u64;
    let days = ts / secs_per_day;
    let day_secs = ts % secs_per_day;
    let hours = day_secs / 3600;
    let minutes = (day_secs % 3600) / 60;
    let seconds = day_secs % 60;

    // Simple days-since-epoch to date conversion
    let (year, month, day) = days_to_ymd(days);

    let mut parts = Vec::new();

    // Kernel basename (without path and extension)
    let kernel_name = Path::new(vmlinux)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("kernel");
    parts.push(kernel_name.to_string());

    // Memory
    parts.push(format!("{}mb", args.memory));

    // Stop condition
    if let Some(tsc) = args.stop_at_tsc {
        parts.push(format!("tsc{}", tsc));
    } else if let Some(vt) = args.stop_at_vt {
        parts.push(format!("vt{:.1}s", vt));
    }

    // Seed
    if let Some(seed) = args.rdrand_seed {
        parts.push(format!("seed{:#x}", seed));
    }

    // Run count
    parts.push(format!("n{}", args.runs));

    // Timestamp
    parts.push(format!(
        "{:04}{:02}{:02}-{:02}{:02}{:02}",
        year, month, day, hours, minutes, seconds
    ));

    parts.join("_")
}

/// Convert days since Unix epoch to (year, month, day).
fn days_to_ymd(days: u64) -> (u64, u64, u64) {
    // Algorithm from http://howardhinnant.github.io/date_algorithms.html
    let z = days + 719468;
    let era = z / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

// ── Progress display ─────────────────────────────────────────────────────────

/// Format a large number with commas (e.g., 1,000,000).
fn format_count(n: usize) -> String {
    let s = n.to_string();
    let mut result = String::new();
    for (i, c) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            result.push(',');
        }
        result.push(c);
    }
    result.chars().rev().collect()
}

/// Format a Duration as HH:MM:SS or MM:SS or SS.Xs depending on magnitude.
fn format_duration(d: Duration) -> String {
    let total_secs = d.as_secs();
    if total_secs >= 3600 {
        let h = total_secs / 3600;
        let m = (total_secs % 3600) / 60;
        let s = total_secs % 60;
        format!("{:02}:{:02}:{:02}", h, m, s)
    } else if total_secs >= 60 {
        let m = total_secs / 60;
        let s = total_secs % 60;
        format!("{:02}:{:02}", m, s)
    } else {
        format!("{:.1}s", d.as_secs_f64())
    }
}

/// Format a Duration as a short human string for per-run times.
fn format_run_time(d: Duration) -> String {
    let ms = d.as_millis();
    if ms >= 60_000 {
        format!("{:.1}m", d.as_secs_f64() / 60.0)
    } else if ms >= 1000 {
        format!("{:.2}s", d.as_secs_f64())
    } else {
        format!("{}ms", ms)
    }
}

/// Live-updating progress display using ANSI escape codes.
struct ProgressDisplay {
    total: usize,
    completed: usize,
    ok: usize,
    divergent: usize,
    failed: usize,
    start: Instant,
    lines_printed: usize,
    run_times: Vec<Duration>,
    bar_width: usize,
}

impl ProgressDisplay {
    fn new(total: usize) -> Self {
        Self {
            total,
            completed: 0,
            ok: 0,
            divergent: 0,
            failed: 0,
            start: Instant::now(),
            lines_printed: 0,
            run_times: Vec::new(),
            bar_width: 40,
        }
    }

    fn update(&mut self, ok: usize, divergent: usize, failed: usize, run_time: Option<Duration>) {
        self.completed = ok + divergent + failed + 1; // +1 for reference
        self.ok = ok;
        self.divergent = divergent;
        self.failed = failed;
        if let Some(t) = run_time {
            self.run_times.push(t);
        }
        self.render();
    }

    fn render(&mut self) {
        let elapsed = self.start.elapsed();
        let pct = if self.total > 0 {
            (self.completed as f64 / self.total as f64) * 100.0
        } else {
            0.0
        };

        // Progress bar
        let filled = (self.completed * self.bar_width)
            .checked_div(self.total)
            .unwrap_or(0);
        let empty = self.bar_width - filled;
        let bar: String = format!(
            "\x1b[32m{}\x1b[90m{}\x1b[0m",
            "\u{2588}".repeat(filled),
            "\u{2591}".repeat(empty),
        );

        // Rate and ETA
        let rate = if elapsed.as_secs_f64() > 0.0 {
            self.completed as f64 / elapsed.as_secs_f64()
        } else {
            0.0
        };
        let eta = if rate > 0.0 && self.completed > 0 {
            let remaining = self.total.saturating_sub(self.completed) as f64 / rate;
            format_duration(Duration::from_secs_f64(remaining))
        } else {
            "--:--".to_string()
        };

        // Average run time
        let avg_run = if !self.run_times.is_empty() {
            let total: Duration = self.run_times.iter().sum();
            format_run_time(total / self.run_times.len() as u32)
        } else {
            "-".to_string()
        };

        // Move cursor up to overwrite previous output
        if self.lines_printed > 0 {
            eprint!("\x1b[{}A", self.lines_printed);
        }

        // Line 1: progress bar + counts
        eprintln!(
            "\x1b[K  {} {}/{} ({:.1}%)",
            bar,
            format_count(self.completed),
            format_count(self.total),
            pct,
        );

        // Line 2: timing info
        eprintln!(
            "\x1b[K  \x1b[90mElapsed:\x1b[0m {:<10} \x1b[90mETA:\x1b[0m {:<10} \x1b[90mRate:\x1b[0m {:.1}/s   \x1b[90mAvg:\x1b[0m {}/run",
            format_duration(elapsed),
            eta,
            rate,
            avg_run,
        );

        // Line 3: results breakdown
        let ok_str = format!("\x1b[32m{} ok\x1b[0m", format_count(self.ok));
        let div_str = if self.divergent > 0 {
            format!("\x1b[31m{} divergent\x1b[0m", format_count(self.divergent))
        } else {
            "\x1b[90m0 divergent\x1b[0m".to_string()
        };
        let fail_str = if self.failed > 0 {
            format!("\x1b[31m{} failed\x1b[0m", format_count(self.failed))
        } else {
            "\x1b[90m0 failed\x1b[0m".to_string()
        };
        eprintln!(
            "\x1b[K  {}  \x1b[90m|\x1b[0m  {}  \x1b[90m|\x1b[0m  {}",
            ok_str, div_str, fail_str,
        );

        self.lines_printed = 3;
    }
}

/// Print a final summary after all runs complete.
fn print_final_summary(
    total: usize,
    ok: usize,
    divergent: usize,
    failed: usize,
    elapsed: Duration,
    run_times: &[Duration],
    workdir: &Path,
) {
    let rate = if elapsed.as_secs_f64() > 0.0 {
        total as f64 / elapsed.as_secs_f64()
    } else {
        0.0
    };

    let avg_run = if !run_times.is_empty() {
        let total_t: Duration = run_times.iter().sum();
        format_run_time(total_t / run_times.len() as u32)
    } else {
        "-".to_string()
    };

    let (min_run, max_run) = if !run_times.is_empty() {
        let min = run_times.iter().min().unwrap();
        let max = run_times.iter().max().unwrap();
        (format_run_time(*min), format_run_time(*max))
    } else {
        ("-".to_string(), "-".to_string())
    };

    eprintln!();
    eprintln!("  \x1b[90m{}\x1b[0m", "\u{2500}".repeat(50));

    if divergent == 0 && failed == 0 {
        eprintln!(
            "  \x1b[1;32mPASS\x1b[0m  \x1b[90m- all {} runs identical\x1b[0m",
            format_count(total)
        );
    } else if divergent > 0 {
        eprintln!(
            "  \x1b[1;31mFAIL\x1b[0m  \x1b[90m- {} of {} runs divergent\x1b[0m",
            format_count(divergent),
            format_count(total)
        );
    } else {
        eprintln!(
            "  \x1b[1;31mFAIL\x1b[0m  \x1b[90m- {} of {} runs failed\x1b[0m",
            format_count(failed),
            format_count(total)
        );
    }

    eprintln!("  \x1b[90m{}\x1b[0m", "\u{2500}".repeat(50));

    eprintln!(
        "  \x1b[90mDuration:\x1b[0m {}   \x1b[90mRate:\x1b[0m {:.1} runs/s",
        format_duration(elapsed),
        rate,
    );
    eprintln!(
        "  \x1b[90mPer run:\x1b[0m  avg {}  min {}  max {}",
        avg_run, min_run, max_run,
    );
    eprintln!(
        "  \x1b[90mResults:\x1b[0m  \x1b[32m{} ok\x1b[0m  \x1b[90m|\x1b[0m  {}  \x1b[90m|\x1b[0m  {}",
        format_count(ok),
        if divergent > 0 {
            format!("\x1b[31m{} divergent\x1b[0m", format_count(divergent))
        } else {
            "\x1b[90m0 divergent\x1b[0m".to_string()
        },
        if failed > 0 {
            format!("\x1b[31m{} failed\x1b[0m", format_count(failed))
        } else {
            "\x1b[90m0 failed\x1b[0m".to_string()
        },
    );

    eprintln!("  \x1b[90m{}\x1b[0m", "\u{2500}".repeat(50));
    eprintln!("  \x1b[90mSaved to {:?}\x1b[0m", workdir);
}

fn main() -> std::process::ExitCode {
    let _cleanup = TempRunCleanup;

    let mut args = Args::parse();

    let vmlinux = match (&args.vmlinux, args.parent_id) {
        (Some(v), _) => v.clone(),
        (None, Some(_)) => String::new(),
        (None, None) => {
            eprintln!("Error: <VMLINUX> is required when not using --parent-id");
            return std::process::ExitCode::FAILURE;
        }
    };

    // Find the CLI binary (same directory as this binary)
    let cli_path = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("bedrock-cli")))
        .unwrap_or_else(|| "bedrock-cli".into());

    if !cli_path.exists() {
        eprintln!("Error: bedrock-cli not found at {:?}", cli_path);
        eprintln!("Build it with: cargo build --release -p bedrock-cli");
        return std::process::ExitCode::FAILURE;
    }

    // Verify parent VM exists before doing any filesystem work.
    // Attempt a transient fork; drop it immediately on success.
    if let Some(parent_id) = args.parent_id {
        if let Err(e) = Vm::create_forked(parent_id) {
            eprintln!("Error: parent VM {} does not exist: {}", parent_id, e);
            return std::process::ExitCode::FAILURE;
        }
    }

    // Generate test subdirectory within workdir
    let test_dir_name = args
        .test_name
        .clone()
        .unwrap_or_else(|| generate_test_dir_name(&args, &vmlinux));
    let test_dir = args.workdir.join(&test_dir_name);
    // Replace workdir with the full test directory path for the rest of the run
    args.workdir = test_dir;

    // Create work directory
    if let Err(e) = fs::create_dir_all(&args.workdir) {
        eprintln!(
            "Error: Failed to create work directory {:?}: {}",
            args.workdir, e
        );
        return std::process::ExitCode::FAILURE;
    }

    // Write configuration file
    write_config_file(&args, &vmlinux, &cli_path).expect("Failed to write config file");

    eprintln!();
    eprintln!("  \x1b[1mBEDROCK DETERMINISM TEST\x1b[0m");
    eprintln!("  \x1b[90m{}\x1b[0m", "\u{2500}".repeat(40));
    eprintln!("  \x1b[90mCLI:\x1b[0m     {:?}", cli_path);
    eprintln!("  \x1b[90mWorkdir:\x1b[0m {:?}", args.workdir);
    if args.parallel > 1 {
        eprintln!(
            "  \x1b[90mRuns:\x1b[0m    {} \x1b[90m({} parallel)\x1b[0m",
            format_count(args.runs),
            args.parallel
        );
    } else {
        eprintln!(
            "  \x1b[90mRuns:\x1b[0m    {} \x1b[90m(sequential)\x1b[0m",
            format_count(args.runs)
        );
    }
    eprintln!("  \x1b[90m{}\x1b[0m", "\u{2500}".repeat(40));
    eprintln!();

    if args.parallel > 1 {
        run_parallel(&args, &vmlinux, &cli_path)
    } else {
        run_sequential(&args, &vmlinux, &cli_path)
    }
}

fn unix_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Write a configuration file summarizing the test parameters.
fn write_config_file(args: &Args, vmlinux: &str, cli_path: &Path) -> io::Result<()> {
    let config_path = args.workdir.join("config.txt");
    let mut f = File::create(&config_path)?;

    writeln!(f, "Bedrock Determinism Test Configuration")?;
    writeln!(f, "=======================================")?;
    writeln!(f, "Timestamp: {}", unix_timestamp())?;
    writeln!(f)?;
    writeln!(f, "CLI binary: {:?}", cli_path)?;
    writeln!(f, "vmlinux: {}", vmlinux)?;
    if let Some(ref initramfs) = args.initramfs {
        writeln!(f, "initramfs: {}", initramfs)?;
    }
    writeln!(f, "memory: {} MB", args.memory)?;
    if let Some(ref cmdline) = args.cmdline {
        writeln!(f, "cmdline: {}", cmdline)?;
    }
    writeln!(f, "runs: {}", args.runs)?;
    if let Some(seed) = args.rdrand_seed {
        writeln!(f, "seed: {:#x}", seed)?;
    }
    if let Some(stop_tsc) = args.stop_at_tsc {
        writeln!(f, "stop_at_tsc: {}", stop_tsc)?;
    }
    if let Some(stop_vt) = args.stop_at_vt {
        writeln!(f, "stop_at_vt: {}", stop_vt)?;
    }
    if let Some(interval) = args.checkpoint_interval {
        writeln!(f, "checkpoint_interval: {}", interval)?;
    }
    if let Some((start, end)) = args.single_step {
        writeln!(f, "single_step: {}-{}", start, end)?;
    }
    if let Some(tsc) = args.capture_exits_after_tsc {
        writeln!(f, "capture_exits_after_tsc: {}", tsc)?;
    }
    if let Some(parent_id) = args.parent_id {
        writeln!(f, "parent_id: {}", parent_id)?;
    }
    if args.all_exits {
        writeln!(f, "all_exits: true")?;
    }
    if args.no_memory_hash {
        writeln!(f, "no_memory_hash: true")?;
    }
    if args.intercept_pf {
        writeln!(f, "intercept_pf: true")?;
    }
    writeln!(f, "parallel: {}", args.parallel)?;
    writeln!(f, "wall_clock_timeout: {}s", args.wall_clock_timeout)?;

    Ok(())
}

fn run_sequential(args: &Args, vmlinux: &str, cli_path: &Path) -> std::process::ExitCode {
    let mut reference_result: Option<RunResult> = None;
    let mut summary_lines: Vec<String> = Vec::new();
    let mut ok_count = 0;
    let mut divergent_count = 0;
    let mut run_times: Vec<Duration> = Vec::new();
    let start = Instant::now();

    for run_num in 1..=args.runs {
        eprintln!("\x1b[1m=== Run {}/{} ===\x1b[0m", run_num, args.runs);

        let result = match run_vm(args, vmlinux, cli_path, run_num) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("\n{}", e);
                return std::process::ExitCode::FAILURE;
            }
        };

        run_times.push(result.wall_time);
        eprintln!(
            "  \x1b[90mWall time: {}\x1b[0m",
            format_run_time(result.wall_time)
        );

        // Print the exit record or checkpoint summary
        if let Some(ref entry) = result.exit_record {
            print_exit_record(entry);
        } else {
            eprintln!("  {} checkpoints captured", result.checkpoint_entries.len());
        }
        eprintln!("  Run data saved to: {:?}", result.run_dir);

        // Compare
        match &reference_result {
            None => {
                eprintln!("  \x1b[90m(reference run)\x1b[0m");
                summary_lines.push(format!("Run {:03}: REFERENCE", run_num));
                reference_result = Some(result);
            }
            Some(ref_result) => {
                let multi_entry = args.checkpoint_interval.is_some() || args.all_exits;
                let diff = compare_run_results(ref_result, &result, multi_entry);
                if let Some(diff) = diff {
                    divergent_count += 1;
                    summary_lines.push(format!("Run {:03}: DIVERGENT", run_num));
                    // Move divergent run directory into workdir for analysis
                    let dest = args.workdir.join(format!("run-{:03}", run_num));
                    let status = Command::new("mv").arg(&result.run_dir).arg(&dest).status();
                    match status {
                        Ok(s) if !s.success() => eprintln!(
                            "\nWarning: failed to move run-{:03} to {:?} (kept at {:?})",
                            run_num, dest, result.run_dir
                        ),
                        Err(e) => eprintln!(
                            "\nWarning: failed to move run-{:03} to {:?}: {} (kept at {:?})",
                            run_num, dest, e, result.run_dir
                        ),
                        _ => {}
                    }
                    write_summary_file(args, &summary_lines, Some(&diff));
                    if let (Some(token), Some(user)) = (&args.pushover_token, &args.pushover_user) {
                        send_pushover_notification(
                            token,
                            user,
                            &format!("Determinism divergence at run {}", run_num),
                        );
                    }
                    eprintln!(
                        "\n  \x1b[1;31mDIVERGENCE at run {}!\x1b[0m\n{}",
                        run_num, diff
                    );
                    print_final_summary(
                        run_num,
                        ok_count,
                        divergent_count,
                        0,
                        start.elapsed(),
                        &run_times,
                        &args.workdir,
                    );
                    return std::process::ExitCode::FAILURE;
                } else {
                    ok_count += 1;
                    eprintln!("  \x1b[32m(matches reference)\x1b[0m");
                    summary_lines.push(format!("Run {:03}: OK", run_num));
                    // Clean up matching run directory
                    let _ = fs::remove_dir_all(&result.run_dir);
                }
            }
        }
        eprintln!();
    }

    write_summary_file(args, &summary_lines, None);
    print_final_summary(
        args.runs,
        ok_count,
        0,
        0,
        start.elapsed(),
        &run_times,
        &args.workdir,
    );
    std::process::ExitCode::SUCCESS
}

/// Compare two run results (log entries + exit stats) and return a diff string if they diverge.
fn compare_run_results(
    reference: &RunResult,
    test: &RunResult,
    multi_entry: bool,
) -> Option<String> {
    let record_diff = if multi_entry {
        compare_checkpoint_results(reference, test)
    } else {
        compare_exit_records(
            reference.exit_record.as_ref().unwrap(),
            test.exit_record.as_ref().unwrap(),
        )
    };

    let stats_diff = match (&reference.exit_stats, &test.exit_stats) {
        (Some(ref_stats), Some(test_stats)) => compare_exit_stats(ref_stats, test_stats),
        _ => None,
    };

    match (record_diff, stats_diff) {
        (None, None) => None,
        (Some(ld), None) => Some(ld),
        (None, Some(sd)) => Some(sd),
        (Some(ld), Some(sd)) => Some(format!("{}\n{}", ld, sd)),
    }
}

/// Compare a run result against the reference, record the outcome, and clean up
/// matching run directories. Divergent runs are moved from their temp directory
/// into the workdir for later analysis.
fn compare_and_record(
    reference: &RunResult,
    run_result: RunResult,
    multi_entry: bool,
    workdir: &Path,
    ok_count: &mut usize,
    divergences: &mut Vec<(usize, String)>,
    summary_lines: &mut Vec<String>,
) {
    let run_num = run_result.run_num;
    let diff = compare_run_results(reference, &run_result, multi_entry);
    if let Some(diff) = diff {
        summary_lines.push(format!("Run {:03}: DIVERGENT", run_num));
        // Move divergent run directory into workdir for analysis
        let dest = workdir.join(format!("run-{:03}", run_num));
        let status = Command::new("mv")
            .arg(&run_result.run_dir)
            .arg(&dest)
            .status();
        match status {
            Ok(s) if !s.success() => eprintln!(
                "\nWarning: failed to move run-{:03} to {:?} (kept at {:?})",
                run_num, dest, run_result.run_dir
            ),
            Err(e) => eprintln!(
                "\nWarning: failed to move run-{:03} to {:?}: {} (kept at {:?})",
                run_num, dest, e, run_result.run_dir
            ),
            _ => {}
        }
        divergences.push((run_num, diff));
    } else {
        summary_lines.push(format!("Run {:03}: OK", run_num));
        *ok_count += 1;
        // Clean up matching run directory
        let _ = fs::remove_dir_all(&run_result.run_dir);
    }
}

fn run_parallel(args: &Args, vmlinux: &str, cli_path: &Path) -> std::process::ExitCode {
    let (tx, rx) = mpsc::channel::<Result<RunResult, String>>();

    // Spawn worker threads
    let mut next_run = 1;
    let mut active_threads = 0;

    let multi_entry = args.checkpoint_interval.is_some() || args.all_exits;

    // Compare results incrementally as they arrive to avoid accumulating all
    // results in memory (which would be catastrophic for large run counts with
    // multi-entry capture modes).
    let mut reference: Option<RunResult> = None;
    let mut pending: Vec<RunResult> = Vec::new();
    let mut completed = 0;
    let mut ok_count = 0;
    let mut divergences: Vec<(usize, String)> = Vec::new();
    let mut failures: Vec<String> = Vec::new();
    let mut summary_lines: Vec<String> = Vec::new();

    let mut progress = ProgressDisplay::new(args.runs);
    let mut notified = false;

    while completed < args.runs {
        // Spawn new threads up to the parallel limit
        while active_threads < args.parallel && next_run <= args.runs {
            let run_num = next_run;
            next_run += 1;
            active_threads += 1;

            let tx = tx.clone();
            let cli_path = cli_path.to_path_buf();
            let workdir = args.workdir.clone();

            // Clone args for the thread
            let vmlinux = vmlinux.to_string();
            let initramfs = args.initramfs.clone();
            let cmdline = args.cmdline.clone();
            let memory = args.memory;
            let seed = args.rdrand_seed;
            let stop_at_tsc = args.stop_at_tsc.or_else(|| {
                args.stop_at_vt
                    .map(|vt| (vt * DEFAULT_TSC_FREQUENCY as f64) as u64)
            });
            let checkpoint_interval = args.checkpoint_interval;
            let single_step = args.single_step;
            let exit_after_tsc = args.capture_exits_after_tsc;
            let parent_id = args.parent_id;
            let timeout = args.wall_clock_timeout;
            let all_exits = args.all_exits;
            let no_memory_hash = args.no_memory_hash;
            let intercept_pf = args.intercept_pf;

            thread::spawn(move || {
                let result = run_vm_inner(
                    &vmlinux,
                    initramfs.as_deref(),
                    cmdline.as_deref(),
                    memory,
                    seed,
                    stop_at_tsc,
                    checkpoint_interval,
                    single_step,
                    exit_after_tsc,
                    parent_id,
                    timeout,
                    all_exits,
                    no_memory_hash,
                    intercept_pf,
                    &cli_path,
                    &workdir,
                    run_num,
                );
                tx.send(result).ok();
            });
        }

        // Wait for a result
        if let Ok(result) = rx.recv() {
            active_threads -= 1;
            completed += 1;
            match result {
                Ok(run_result) => {
                    let run_time = run_result.wall_time;
                    if let Some(ref_result) = &reference {
                        compare_and_record(
                            ref_result,
                            run_result,
                            multi_entry,
                            &args.workdir,
                            &mut ok_count,
                            &mut divergences,
                            &mut summary_lines,
                        );
                        if !notified && !divergences.is_empty() {
                            if let (Some(token), Some(user)) =
                                (&args.pushover_token, &args.pushover_user)
                            {
                                let (run_num, _) = &divergences[0];
                                send_pushover_notification(
                                    token,
                                    user,
                                    &format!("Determinism divergence at run {}", run_num),
                                );
                                notified = true;
                            }
                        }
                    } else if run_result.run_num == 1 {
                        // Run 1 is always the reference
                        summary_lines.push("Run 001: REFERENCE".to_string());
                        reference = Some(run_result);
                        // Process any results that arrived before run 1
                        for buffered in pending.drain(..) {
                            compare_and_record(
                                reference.as_ref().unwrap(),
                                buffered,
                                multi_entry,
                                &args.workdir,
                                &mut ok_count,
                                &mut divergences,
                                &mut summary_lines,
                            );
                        }
                        if !notified && !divergences.is_empty() {
                            if let (Some(token), Some(user)) =
                                (&args.pushover_token, &args.pushover_user)
                            {
                                let (run_num, _) = &divergences[0];
                                send_pushover_notification(
                                    token,
                                    user,
                                    &format!("Determinism divergence at run {}", run_num),
                                );
                                notified = true;
                            }
                        }
                    } else {
                        // Buffer until run 1 arrives
                        pending.push(run_result);
                    }
                    progress.update(ok_count, divergences.len(), failures.len(), Some(run_time));
                }
                Err(e) => {
                    failures.push(e);
                    progress.update(ok_count, divergences.len(), failures.len(), None);
                }
            }
        }
    }
    eprintln!();

    if !failures.is_empty() {
        eprintln!("\n{} run(s) failed:", failures.len());
        for (i, failure) in failures.iter().enumerate() {
            eprintln!("\n--- Failure {} ---\n{}", i + 1, failure);
        }
        return std::process::ExitCode::FAILURE;
    }

    // Print divergence details if any
    if !divergences.is_empty() {
        eprintln!();
        for (run_num, diff) in &divergences {
            eprintln!("  \x1b[31m--- Run {} ---\x1b[0m", run_num);
            eprintln!("  {}", diff.replace('\n', "\n  "));
            eprintln!();
        }
    }

    let diff_summary = if divergences.is_empty() {
        None
    } else {
        Some(
            divergences
                .iter()
                .map(|(n, d)| format!("Run {}: {}", n, d))
                .collect::<Vec<_>>()
                .join("\n\n"),
        )
    };
    write_summary_file(args, &summary_lines, diff_summary.as_deref());

    print_final_summary(
        args.runs,
        ok_count,
        divergences.len(),
        failures.len(),
        progress.start.elapsed(),
        &progress.run_times,
        &args.workdir,
    );

    if divergences.is_empty() && failures.is_empty() {
        std::process::ExitCode::SUCCESS
    } else {
        std::process::ExitCode::FAILURE
    }
}

/// Write the summary file with overall results.
fn write_summary_file(args: &Args, summary_lines: &[String], divergence: Option<&str>) {
    let summary_path = args.workdir.join("summary.txt");
    let mut f = match File::create(&summary_path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Warning: Failed to write summary file: {}", e);
            return;
        }
    };

    let _ = writeln!(f, "Bedrock Determinism Test Summary");
    let _ = writeln!(f, "=================================");
    let _ = writeln!(f, "Timestamp: {}", unix_timestamp());
    let _ = writeln!(f);

    for line in summary_lines {
        let _ = writeln!(f, "{}", line);
    }

    let _ = writeln!(f);
    if let Some(diff) = divergence {
        let _ = writeln!(f, "RESULT: DIVERGENCE DETECTED");
        let _ = writeln!(f);
        let _ = writeln!(f, "First divergence:");
        let _ = writeln!(f, "{}", diff);
    } else {
        let _ = writeln!(f, "RESULT: ALL RUNS IDENTICAL");
    }
}

fn run_vm(
    args: &Args,
    vmlinux: &str,
    cli_path: &Path,
    run_num: usize,
) -> Result<RunResult, String> {
    run_vm_inner(
        vmlinux,
        args.initramfs.as_deref(),
        args.cmdline.as_deref(),
        args.memory,
        args.rdrand_seed,
        args.stop_at_tsc.or_else(|| {
            args.stop_at_vt
                .map(|vt| (vt * DEFAULT_TSC_FREQUENCY as f64) as u64)
        }),
        args.checkpoint_interval,
        args.single_step,
        args.capture_exits_after_tsc,
        args.parent_id,
        args.wall_clock_timeout,
        args.all_exits,
        args.no_memory_hash,
        args.intercept_pf,
        cli_path,
        &args.workdir,
        run_num,
    )
}

#[allow(clippy::too_many_arguments)]
fn run_vm_inner(
    vmlinux: &str,
    initramfs: Option<&str>,
    cmdline: Option<&str>,
    memory: usize,
    seed: Option<u64>,
    stop_at_tsc: Option<u64>,
    checkpoint_interval: Option<u64>,
    single_step: Option<(u64, u64)>,
    exit_after_tsc: Option<u64>,
    parent_id: Option<u64>,
    timeout: f64,
    all_exits: bool,
    no_memory_hash: bool,
    intercept_pf: bool,
    cli_path: &Path,
    workdir: &Path,
    run_num: usize,
) -> Result<RunResult, String> {
    // Create run directory: run-001 (reference) goes in workdir, others use a
    // temp directory to avoid cluttering the workdir with transient data.
    let run_dir = if run_num == 1 {
        workdir.join("run-001")
    } else {
        std::env::temp_dir().join(format!("{}{:03}", temp_run_prefix(), run_num))
    };
    fs::create_dir_all(&run_dir).map_err(|e| {
        format!(
            "Run {}: failed to create directory {:?}: {}",
            run_num, run_dir, e
        )
    })?;

    let events_file = run_dir.join("events.jsonl");
    let stdout_file = run_dir.join("stdout.txt");
    let stderr_file = run_dir.join("stderr.txt");
    let command_file = run_dir.join("command.txt");

    // Build CLI command with absolute paths
    let mut cmd = Command::new(cli_path);
    cmd.arg(make_absolute(vmlinux));

    // Capture Exit records into the event stream (`--exit-capture` implies the
    // `exit` category). Single-stepping drives its own `TscRange` capture, so
    // only set an explicit mode when not single-stepping.
    cmd.arg("--events-jsonl").arg(&events_file);
    if single_step.is_none() {
        if all_exits {
            cmd.arg("--exit-capture").arg("all");
        } else if let Some(interval) = checkpoint_interval {
            cmd.arg("--exit-capture")
                .arg(format!("checkpoints:{}", interval));
        } else {
            cmd.arg("--exit-capture").arg("at-shutdown");
        }
    }
    if no_memory_hash {
        cmd.arg("--no-memory-hash");
    }
    if intercept_pf {
        cmd.arg("--intercept-pf");
    }

    if let Some(initramfs) = initramfs {
        cmd.arg("-i").arg(make_absolute(initramfs));
    }
    cmd.arg("-m").arg(memory.to_string());
    if let Some(cmdline) = cmdline {
        cmd.arg("-c").arg(cmdline);
    }
    if let Some(seed) = seed {
        cmd.arg("-s").arg(format!("{:#x}", seed));
    }
    if let Some(stop_tsc) = stop_at_tsc {
        cmd.arg("--stop-at-tsc").arg(stop_tsc.to_string());
    }
    if let Some((start, end)) = single_step {
        cmd.arg("--single-step").arg(format!("{}-{}", start, end));
    }
    if let Some(tsc) = exit_after_tsc {
        cmd.arg("--capture-exits-after-tsc").arg(tsc.to_string());
    }
    if let Some(id) = parent_id {
        cmd.arg("--parent-id").arg(id.to_string());
    }
    cmd.arg("--wall-clock-timeout").arg(timeout.to_string());

    let exit_stats_file = run_dir.join("exit-stats.json");
    cmd.arg("--exit-stats-json").arg(&exit_stats_file);

    // Write command to file
    {
        let mut f = File::create(&command_file)
            .map_err(|e| format!("Run {}: failed to create command file: {}", run_num, e))?;
        writeln!(f, "{:?}", cmd).ok();
        let args_str: Vec<String> = std::iter::once(cli_path.to_string_lossy().to_string())
            .chain(cmd.get_args().map(|s| s.to_string_lossy().to_string()))
            .collect();
        writeln!(f, "\n# Copy-pasteable command:").ok();
        writeln!(f, "{}", args_str.join(" ")).ok();
    }

    // Set up output capture
    let stdout_handle = File::create(&stdout_file)
        .map_err(|e| format!("Run {}: failed to create stdout file: {}", run_num, e))?;
    let stderr_handle = File::create(&stderr_file)
        .map_err(|e| format!("Run {}: failed to create stderr file: {}", run_num, e))?;

    cmd.stdout(Stdio::from(stdout_handle));
    cmd.stderr(Stdio::from(stderr_handle));

    let run_start = Instant::now();
    let status = cmd
        .status()
        .map_err(|e| format!("Run {}: failed to execute bedrock-cli: {}", run_num, e))?;
    let wall_time = run_start.elapsed();

    // Write exit status to a status file
    {
        let status_file = run_dir.join("status.txt");
        if let Ok(mut f) = File::create(&status_file) {
            writeln!(f, "exit_code: {:?}", status.code()).ok();
            writeln!(f, "success: {}", status.success()).ok();
        }
    }

    if !status.success() {
        return Err(format_run_error(
            run_num,
            &run_dir,
            &format!("bedrock-cli exited with {}", status),
        ));
    }

    // Parse exit stats JSON
    let exit_stats = parse_exit_stats_file(&exit_stats_file).ok();

    // Parse log file (don't delete it - keep for analysis)
    let multi_entry = checkpoint_interval.is_some() || all_exits;
    if multi_entry {
        let entries = parse_events_file_entries(&events_file).map_err(|e| {
            let file_size = fs::metadata(&events_file).map(|m| m.len()).unwrap_or(0);
            format_run_error(
                run_num,
                &run_dir,
                &format!(
                    "failed to parse log file {:?} ({} bytes): {}",
                    events_file, file_size, e
                ),
            )
        })?;
        Ok(RunResult {
            run_num,
            exit_record: None,
            checkpoint_entries: entries,
            run_dir,
            exit_stats,
            wall_time,
        })
    } else {
        let exit_record = parse_events_file(&events_file).map_err(|e| {
            let file_size = fs::metadata(&events_file).map(|m| m.len()).unwrap_or(0);
            format_run_error(
                run_num,
                &run_dir,
                &format!(
                    "failed to parse log file {:?} ({} bytes): {}",
                    events_file, file_size, e
                ),
            )
        })?;
        Ok(RunResult {
            run_num,
            exit_record: Some(exit_record),
            checkpoint_entries: Vec::new(),
            run_dir,
            exit_stats,
            wall_time,
        })
    }
}

/// Parse one event-stream JSONL line. Returns the `ExitRecord` payload if the line
/// is a *deterministic* `Exit` record, else `None` (serial, randomness, or a
/// non-deterministic exit). The harness compares only deterministic exits.
fn exit_entry_from_line(line: &str) -> io::Result<Option<ExitRecord>> {
    let parse_err = |e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("JSON parse error: {}", e),
        )
    };
    let v: serde_json::Value = serde_json::from_str(line).map_err(parse_err)?;
    let is_exit = v.get("kind").and_then(|k| k.as_str()) == Some("exit");
    let is_det = v.get("deterministic").and_then(|d| d.as_bool()) == Some(true);
    if !is_exit || !is_det {
        return Ok(None);
    }
    let data = v
        .get("data")
        .cloned()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "exit event missing `data`"))?;
    let entry: ExitRecord = serde_json::from_value(data).map_err(parse_err)?;
    Ok(Some(entry))
}

/// Read the first deterministic `Exit` record from an event-stream JSONL file
/// (log-at-shutdown produces exactly one).
fn parse_events_file(path: &std::path::Path) -> io::Result<ExitRecord> {
    let content = fs::read_to_string(path)?;
    for line in content.lines() {
        if line.trim().is_empty() {
            continue;
        }
        if let Some(entry) = exit_entry_from_line(line)? {
            return Ok(entry);
        }
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "no deterministic exit record in event stream",
    ))
}

/// Read every deterministic `Exit` record from an event-stream JSONL file.
fn parse_events_file_entries(path: &std::path::Path) -> io::Result<Vec<ExitRecord>> {
    let content = fs::read_to_string(path)?;
    let mut entries = Vec::new();
    for line in content.lines() {
        if line.trim().is_empty() {
            continue;
        }
        if let Some(entry) = exit_entry_from_line(line)? {
            entries.push(entry);
        }
    }
    Ok(entries)
}

fn print_exit_record(entry: &ExitRecord) {
    eprintln!("  TSC: {}", entry.tsc);
    eprintln!("  RIP: {:#x}", entry.rip);
    eprintln!("  RFLAGS: {:#x}", entry.rflags);
    eprintln!(
        "  RAX: {:#x}  RBX: {:#x}  RCX: {:#x}  RDX: {:#x}",
        entry.rax, entry.rbx, entry.rcx, entry.rdx
    );
    eprintln!(
        "  RSI: {:#x}  RDI: {:#x}  RSP: {:#x}  RBP: {:#x}",
        entry.rsi, entry.rdi, entry.rsp, entry.rbp
    );
    eprintln!(
        "  R8:  {:#x}  R9:  {:#x}  R10: {:#x}  R11: {:#x}",
        entry.r8, entry.r9, entry.r10, entry.r11
    );
    eprintln!(
        "  R12: {:#x}  R13: {:#x}  R14: {:#x}  R15: {:#x}",
        entry.r12, entry.r13, entry.r14, entry.r15
    );
    eprintln!("  memory_hash: {:#x}", entry.memory_hash);
    eprintln!(
        "  apic_hash:   {:#x}  ioapic_hash: {:#x}",
        entry.apic_hash, entry.ioapic_hash
    );
    eprintln!(
        "  serial_hash: {:#x}  rtc_hash:    {:#x}",
        entry.serial_hash, entry.rtc_hash
    );
    eprintln!(
        "  mtrr_hash:   {:#x}  rdrand_hash: {:#x}",
        entry.mtrr_hash, entry.rdrand_hash
    );
}

fn compare_exit_records(a: &ExitRecord, b: &ExitRecord) -> Option<String> {
    let mut diffs = Vec::new();
    macro_rules! cmp {
        ($f:ident) => {
            if a.$f != b.$f {
                diffs.push(format!("  {}: {:#x} vs {:#x}", stringify!($f), a.$f, b.$f));
            }
        };
    }
    cmp!(tsc);
    cmp!(rip);
    cmp!(rflags);
    cmp!(rax);
    cmp!(rbx);
    cmp!(rcx);
    cmp!(rdx);
    cmp!(rsi);
    cmp!(rdi);
    cmp!(rsp);
    cmp!(rbp);
    cmp!(r8);
    cmp!(r9);
    cmp!(r10);
    cmp!(r11);
    cmp!(r12);
    cmp!(r13);
    cmp!(r14);
    cmp!(r15);
    cmp!(memory_hash);
    cmp!(apic_hash);
    cmp!(serial_hash);
    cmp!(ioapic_hash);
    cmp!(rtc_hash);
    cmp!(mtrr_hash);
    cmp!(rdrand_hash);
    cmp!(fs_base);
    cmp!(gs_base);
    cmp!(kernel_gs_base);
    cmp!(cr3);
    cmp!(cs_base);
    cmp!(ds_base);
    cmp!(es_base);
    cmp!(ss_base);
    cmp!(pending_dbg_exceptions);
    cmp!(interruptibility_state);
    cmp!(cow_page_count);
    if diffs.is_empty() {
        None
    } else {
        Some(diffs.join("\n"))
    }
}

/// Compare two sets of checkpoint results and find the first divergence.
///
/// Returns a string describing where and how the results diverged, or None if identical.
fn compare_checkpoint_results(ref_result: &RunResult, test_result: &RunResult) -> Option<String> {
    let ref_entries = &ref_result.checkpoint_entries;
    let test_entries = &test_result.checkpoint_entries;

    // Find first divergent checkpoint
    let min_len = ref_entries.len().min(test_entries.len());

    for i in 0..min_len {
        let ref_entry = &ref_entries[i];
        let test_entry = &test_entries[i];

        if let Some(diff) = compare_exit_records(ref_entry, test_entry) {
            // Get checkpoint index from exit_qualification
            let checkpoint_idx = ref_entry.exit_qualification;
            return Some(format!(
                "Divergence at checkpoint {} (index {}, TSC ~{}):\n{}",
                i, checkpoint_idx, ref_entry.tsc, diff
            ));
        }
    }

    // Check for different number of checkpoints
    if ref_entries.len() != test_entries.len() {
        return Some(format!(
            "Different number of checkpoints: {} vs {}",
            ref_entries.len(),
            test_entries.len()
        ));
    }

    None
}

fn parse_exit_stats_file(path: &Path) -> io::Result<ExitStats> {
    let content = fs::read_to_string(path)?;
    serde_json::from_str(&content).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("JSON parse error: {}", e),
        )
    })
}

/// Compare deterministic exit type counts between two runs.
///
/// Non-deterministic exits (external_interrupt, exception_nmi, ept_violation, other)
/// are excluded from comparison since they vary between runs by design.
fn compare_exit_stats(a: &ExitStats, b: &ExitStats) -> Option<String> {
    let mut diffs = Vec::new();

    // Deterministic exit types only
    let deterministic_exits: &[(&str, u64, u64)] = &[
        ("cpuid", a.cpuid.count, b.cpuid.count),
        ("msr_read", a.msr_read.count, b.msr_read.count),
        ("msr_write", a.msr_write.count, b.msr_write.count),
        ("cr_access", a.cr_access.count, b.cr_access.count),
        (
            "io_instruction",
            a.io_instruction.count,
            b.io_instruction.count,
        ),
        ("rdtsc", a.rdtsc.count, b.rdtsc.count),
        ("rdtscp", a.rdtscp.count, b.rdtscp.count),
        ("rdpmc", a.rdpmc.count, b.rdpmc.count),
        ("mwait", a.mwait.count, b.mwait.count),
        ("vmcall", a.vmcall.count, b.vmcall.count),
        ("apic_access", a.apic_access.count, b.apic_access.count),
        ("mtf", a.mtf.count, b.mtf.count),
        ("xsetbv", a.xsetbv.count, b.xsetbv.count),
        ("rdrand", a.rdrand.count, b.rdrand.count),
        ("rdseed", a.rdseed.count, b.rdseed.count),
    ];

    for (name, count_a, count_b) in deterministic_exits {
        if count_a != count_b {
            diffs.push(format!("  {}: {} vs {}", name, count_a, count_b));
        }
    }

    if diffs.is_empty() {
        None
    } else {
        Some(format!("Exit count differences:\n{}", diffs.join("\n")))
    }
}

/// Return the temp directory prefix for this process's run directories.
fn temp_run_prefix() -> String {
    format!("bedrock-run-{}-", std::process::id())
}

/// RAII guard that cleans up temp run directories when dropped.
struct TempRunCleanup;

impl Drop for TempRunCleanup {
    fn drop(&mut self) {
        let tmp = std::env::temp_dir();
        let prefix = temp_run_prefix();
        if let Ok(entries) = fs::read_dir(&tmp) {
            for entry in entries.flatten() {
                if let Some(name) = entry.file_name().to_str() {
                    if name.starts_with(&prefix) {
                        let _ = fs::remove_dir_all(entry.path());
                    }
                }
            }
        }
    }
}

fn make_absolute(path: &str) -> PathBuf {
    let p = PathBuf::from(path);
    if p.is_absolute() {
        p
    } else {
        std::env::current_dir().unwrap_or_default().join(p)
    }
}
