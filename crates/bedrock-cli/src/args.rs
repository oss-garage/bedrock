// SPDX-License-Identifier: GPL-2.0

//! CLI argument parsing using clap derive macros.

use clap::{Parser, ValueEnum};

use bedrock_vm::boot::defaults;
use bedrock_vm::DEFAULT_TSC_FREQUENCY;

/// Bedrock CLI - Linux Kernel Loader for the bedrock hypervisor.
#[derive(Parser, Debug)]
#[command(name = "bedrock-cli")]
#[command(about = "Linux Kernel Loader for the bedrock hypervisor")]
#[command(version)]
pub struct Args {
    /// Path to vmlinux ELF image (required for root VMs, unused for forked VMs)
    pub vmlinux: Option<String>,

    /// Guest memory size in MB
    #[arg(short = 'm', long, default_value_t = defaults::MEMORY_MB)]
    pub memory: usize,

    /// Kernel command line
    #[arg(short = 'c', long, default_value = defaults::CMDLINE)]
    pub cmdline: String,

    /// Path to initramfs/initrd image
    #[arg(short = 'i', long)]
    pub initramfs: Option<String>,

    /// Write serial output to file (in addition to stdout)
    #[arg(short = 'l', long)]
    pub log: Option<String>,

    /// Serial input to send to guest (use \n for newlines)
    #[arg(short = 'x', long, value_parser = parse_serial_input)]
    pub input: Option<String>,

    /// RDRAND emulation mode
    #[arg(short = 'r', long = "rdrand-mode", value_enum, default_value_t = RdrandMode::Seeded)]
    pub rdrand_mode: RdrandMode,

    /// Seed/value for RDRAND (hex with 0x prefix or decimal)
    #[arg(short = 's', long = "rdrand-seed", default_value_t = defaults::RDRAND_SEED, value_parser = parse_u64)]
    pub rdrand_seed: u64,

    /// Enable deterministic exit logging
    #[arg(short = 'L', long = "enable-log")]
    pub enable_log: bool,

    /// Write log entries to JSONL file (implies -L)
    #[arg(long = "log-jsonl")]
    pub log_jsonl: Option<String>,

    /// Single-step (MTF) for TSC range (e.g., 79800000-79810000)
    #[arg(long = "single-step", value_parser = parse_tsc_range)]
    pub single_step: Option<(u64, u64)>,

    /// Start logging only after emulated TSC reaches threshold
    #[arg(long = "log-after-tsc", value_parser = parse_u64)]
    pub log_after_tsc: Option<u64>,

    /// Log once at VM shutdown and hash full memory
    #[arg(long = "log-at-shutdown")]
    pub log_at_shutdown: bool,

    /// Log once when TSC reaches value and hash full memory
    #[arg(long = "log-at-tsc", value_parser = parse_u64)]
    pub log_at_tsc: Option<u64>,

    /// Stop VM when emulated TSC reaches this value
    #[arg(long = "stop-at-tsc", value_parser = parse_u64, conflicts_with = "stop_at_vt")]
    pub stop_at_tsc: Option<u64>,

    /// Stop VM when virtual time reaches this value (seconds, e.g. 3374.539)
    #[arg(long = "stop-at-vt", conflicts_with = "stop_at_tsc")]
    pub stop_at_vt: Option<f64>,

    /// Log checkpoints at TSC intervals (e.g., 1000000000 for every 1B ticks)
    #[arg(long = "log-checkpoints", value_parser = parse_u64)]
    pub log_checkpoints: Option<u64>,

    /// Skip memory hashing in log entries (memory_hash will be 0)
    #[arg(long = "no-memory-hash")]
    pub no_memory_hash: bool,

    /// Intercept guest #PF exceptions (logged and reinjected for determinism analysis)
    #[arg(long = "intercept-pf")]
    pub intercept_pf: bool,

    /// Create a forked VM from an existing parent VM ID
    #[arg(long = "parent-id", value_parser = parse_u64)]
    pub parent_id: Option<u64>,

    /// Wait for Ctrl-C at snapshot/stop-tsc points (for forked VM testing)
    #[arg(long = "wait")]
    pub wait: bool,

    /// Dump feedback buffer to file on stop-at-tsc
    #[arg(long = "dump-feedback")]
    pub dump_feedback: Option<String>,

    /// Wall-clock timeout in seconds (VM run ends after this duration)
    #[arg(long = "timeout", value_parser = parse_f64)]
    pub timeout: Option<f64>,

    /// Write exit statistics to a JSON file
    #[arg(long = "exit-stats-json")]
    pub exit_stats_json: Option<String>,

    /// Emulated TSC frequency in Hz (defaults to the kernel's built-in default)
    #[arg(long = "tsc-frequency", value_parser = parse_u64)]
    pub tsc_frequency: Option<u64>,

    /// Queue a deterministic I/O channel action for the guest's bedrock-io
    /// module. Repeatable; actions fire in `target_tsc` order at the first
    /// VM exit where `emulated_tsc >= target_tsc` and no prior action is
    /// still in flight.
    ///
    /// An optional scheduling prefix sets the earliest emulated TSC at
    /// which the action may fire:
    ///   `tsc=<N>:<action>`      — earliest fire-time as a raw TSC value.
    ///   `vt=<seconds>:<action>` — earliest fire-time as virtual time
    ///                             (converted via DEFAULT_TSC_FREQUENCY).
    /// Without a prefix, `target_tsc` defaults to 0 (queue immediately).
    ///
    /// Action body formats:
    ///   `list`                      — run `podman ps --format '{{.Names}}'`
    ///   `exec:<container>:<cmd>`    — run `podman exec <container> /bin/sh -c <cmd>`
    ///   `exec:host:<cmd>`           — run `/bin/sh -c <cmd>` on the guest itself
    ///                                 (outside any container)
    ///
    /// Examples:
    ///   --io-action 'list'
    ///   --io-action 'tsc=300000000:list'
    ///   --io-action 'vt=120.0:exec:bitcoind1:bitcoin-cli getblockchaininfo'
    ///   --io-action 'exec:host:uname -a'
    #[arg(long = "io-action", value_parser = parse_scheduled_io_action, verbatim_doc_comment)]
    pub io_actions: Vec<ScheduledIoAction>,
}

/// One scheduled I/O channel action. Parsed from the CLI's repeated
/// `--io-action` flag and serialised into the wire format the guest module
/// expects. `target_tsc == 0` means "queue at startup".
#[derive(Clone, Debug)]
pub struct ScheduledIoAction {
    /// Earliest emulated-TSC value at which this action may be queued
    /// with the kernel. The CLI's run-loop checks `exit.emulated_tsc`
    /// after each VM exit and queues the next eligible action.
    pub target_tsc: u64,
    /// The action body.
    pub action: IoAction,
}

/// Action body: which thing the guest module should do.
#[derive(Clone, Debug)]
pub enum IoAction {
    /// Enumerate running containers and the executables each one ships
    /// under `/opt/bedrock/drivers/`. Response is line-based with one
    /// record per line, each record having two tab-separated fields:
    ///
    /// - `<container>\t`           — header line, emitted once per
    ///   container (driver field empty).
    /// - `<container>\t<driver>`   — one such line per executable
    ///   found in that container.
    ///
    /// Consumers can parse the response with a single `split('\t', 1)`
    /// per line — no state machine. The fuzzer reads this list to
    /// choose (container, driver) targets.
    GetWorkloadDetails,
    /// `podman exec <container> /bin/sh -c <cmd>` — returns stdout+stderr.
    ExecBash { container: String, cmd: String },
    /// `/bin/sh -c <cmd>` run directly on the guest, outside any container.
    /// Returns stdout+stderr.
    ExecHostBash { cmd: String },
}

impl Args {
    /// Returns true if logging should be enabled (explicit flag or implied by other options).
    pub fn should_enable_log(&self) -> bool {
        self.enable_log
            || self.log_jsonl.is_some()
            || self.single_step.is_some()
            || self.log_after_tsc.is_some()
            || self.log_at_shutdown
            || self.log_at_tsc.is_some()
            || self.log_checkpoints.is_some()
    }
}

/// RDRAND emulation mode.
#[derive(ValueEnum, Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum RdrandMode {
    /// Use seeded PRNG (deterministic)
    #[default]
    Seeded,
    /// Exit to userspace
    Userspace,
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
            "Invalid TSC range '{}'. Expected format: START-END (e.g., 79800000-79810000)",
            s
        ));
    }
    let start = parse_u64(parts[0])?;
    let end = parse_u64(parts[1])?;
    if end <= start {
        return Err(format!(
            "Invalid TSC range: end ({}) must be greater than start ({})",
            end, start
        ));
    }
    Ok((start, end))
}

/// Parse an f64 value from a string.
fn parse_f64(s: &str) -> Result<f64, String> {
    s.trim()
        .parse()
        .map_err(|_| format!("Invalid number: {}", s))
}

/// Parse serial input, processing escape sequences.
fn parse_serial_input(s: &str) -> Result<String, String> {
    Ok(s.replace("\\n", "\n")
        .replace("\\r", "\r")
        .replace("\\t", "\t")
        .replace("\\\\", "\\"))
}

/// Parse a `--io-action` spec into a `ScheduledIoAction`.
///
/// Accepts an optional `tsc=<N>:` or `vt=<seconds>:` scheduling prefix
/// (the colon after the value separates the prefix from the action body),
/// then dispatches on the body via [`parse_io_action_body`].
fn parse_scheduled_io_action(s: &str) -> Result<ScheduledIoAction, String> {
    let (target_tsc, body) = if let Some(rest) = s.strip_prefix("tsc=") {
        let (value, body) = rest.split_once(':').ok_or_else(|| {
            format!(
                "Invalid scheduled action '{}'. Expected tsc=<N>:<action>",
                s
            )
        })?;
        (parse_u64(value)?, body)
    } else if let Some(rest) = s.strip_prefix("vt=") {
        let (value, body) = rest.split_once(':').ok_or_else(|| {
            format!(
                "Invalid scheduled action '{}'. Expected vt=<seconds>:<action>",
                s
            )
        })?;
        let secs: f64 = value
            .trim()
            .parse()
            .map_err(|_| format!("Invalid virtual time '{}' in '{}'", value, s))?;
        if secs < 0.0 {
            return Err(format!("Negative virtual time in '{}'", s));
        }
        // Conversion uses DEFAULT_TSC_FREQUENCY because the parser runs
        // before `--tsc-frequency` is applied to the VM. Users who pass
        // `--tsc-frequency` and want precise alignment should specify
        // `tsc=...` directly.
        let tsc = (secs * DEFAULT_TSC_FREQUENCY as f64) as u64;
        (tsc, body)
    } else {
        (0u64, s)
    };
    let action = parse_io_action_body(body)?;
    Ok(ScheduledIoAction { target_tsc, action })
}

/// Parse the body portion of an `--io-action` spec, after any scheduling
/// prefix has been stripped.
///
/// Accepts:
///   `list`                       → IoAction::GetWorkloadDetails
///   `exec:host:<cmd>`            → IoAction::ExecHostBash { cmd }
///   `exec:<container>:<cmd>`     → IoAction::ExecBash { container, cmd }
///
/// The split on the first `:` after `exec:` leaves the `<cmd>` part free
/// to contain colons of its own (`exec:bitcoind1:bitcoin-cli getinfo`).
/// `host` in the container slot is reserved for the guest-direct form, so
/// a container literally named `host` cannot be targeted via `exec:`.
fn parse_io_action_body(s: &str) -> Result<IoAction, String> {
    if s == "list" {
        return Ok(IoAction::GetWorkloadDetails);
    }
    if let Some(rest) = s.strip_prefix("exec:") {
        let (container, cmd) = rest.split_once(':').ok_or_else(|| {
            format!(
                "Invalid exec action '{}'. Expected exec:<container>:<cmd>",
                s
            )
        })?;
        if container.is_empty() {
            return Err(format!("Empty container name in '{}'", s));
        }
        if cmd.is_empty() {
            return Err(format!("Empty command in '{}'", s));
        }
        if container == "host" {
            return Ok(IoAction::ExecHostBash {
                cmd: cmd.to_string(),
            });
        }
        return Ok(IoAction::ExecBash {
            container: container.to_string(),
            cmd: cmd.to_string(),
        });
    }
    Err(format!(
        "Invalid I/O action '{}'. Expected `list`, `exec:host:<cmd>`, or `exec:<container>:<cmd>`",
        s
    ))
}
