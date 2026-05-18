// SPDX-License-Identifier: GPL-2.0

//! Statistics types for VM performance monitoring.

use std::fmt;
use std::time::Duration;

use serde::{Deserialize, Serialize};

const TABLE_SEP: &str =
    "─────────────────────────────────────────────────────────────────────────────";

/// Calculate percentage, returning 0.0 if denominator is zero.
fn pct(num: u64, denom: u64) -> f64 {
    if denom > 0 {
        (num as f64 / denom as f64) * 100.0
    } else {
        0.0
    }
}

/// Format a large number with commas for readability.
fn format_count(n: u64) -> String {
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

/// Format nanoseconds as a human-readable time string.
fn format_time_ns(ns: u64) -> String {
    if ns >= 1_000_000_000 {
        format!("{:.3} s", ns as f64 / 1_000_000_000.0)
    } else if ns >= 1_000_000 {
        format!("{:.3} ms", ns as f64 / 1_000_000.0)
    } else if ns >= 1_000 {
        format!("{:.3} µs", ns as f64 / 1_000.0)
    } else {
        format!("{} ns", ns)
    }
}

/// Per-exit-type statistics.
///
/// Tracks the count and total CPU cycles spent handling each exit type.
#[repr(C)]
#[derive(Clone, Copy, Default, Debug, Serialize, Deserialize)]
pub struct ExitStatEntry {
    /// Number of exits of this type.
    pub count: u64,
    /// Total CPU cycles spent handling this exit type (via RDTSC).
    pub cycles: u64,
}

impl ExitStatEntry {
    /// Get the average cycles per exit, or 0 if no exits occurred.
    #[inline]
    pub fn avg_cycles(&self) -> u64 {
        self.cycles.checked_div(self.count).unwrap_or(0)
    }
}

/// Exit handler performance statistics.
///
/// This structure tracks performance metrics for each type of VM exit,
/// allowing identification of which exits cause the most overhead.
#[repr(C)]
#[derive(Clone, Copy, Default, Debug, Serialize, Deserialize)]
pub struct ExitStats {
    /// CPUID instruction exits.
    pub cpuid: ExitStatEntry,
    /// MSR read (RDMSR) exits.
    pub msr_read: ExitStatEntry,
    /// MSR write (WRMSR) exits.
    pub msr_write: ExitStatEntry,
    /// Control register access exits.
    pub cr_access: ExitStatEntry,
    /// I/O instruction exits.
    pub io_instruction: ExitStatEntry,
    /// EPT violation exits.
    pub ept_violation: ExitStatEntry,
    /// External interrupt exits.
    pub external_interrupt: ExitStatEntry,
    /// RDTSC instruction exits.
    pub rdtsc: ExitStatEntry,
    /// RDTSCP instruction exits.
    pub rdtscp: ExitStatEntry,
    /// RDPMC instruction exits.
    pub rdpmc: ExitStatEntry,
    /// MWAIT instruction exits.
    pub mwait: ExitStatEntry,
    /// VMCALL hypercall exits.
    pub vmcall: ExitStatEntry,
    /// APIC access exits.
    pub apic_access: ExitStatEntry,
    /// Monitor trap flag (MTF) exits.
    pub mtf: ExitStatEntry,
    /// XSETBV instruction exits.
    pub xsetbv: ExitStatEntry,
    /// RDRAND instruction exits.
    pub rdrand: ExitStatEntry,
    /// RDSEED instruction exits.
    pub rdseed: ExitStatEntry,
    /// Exception/NMI exits.
    pub exception_nmi: ExitStatEntry,
    /// All other exit types combined.
    pub other: ExitStatEntry,
    /// Total cycles in VM run loop (including guest time).
    pub total_run_cycles: u64,
    /// Total cycles in guest mode (actual VMX non-root execution).
    pub guest_cycles: u64,
    /// Cycles spent in run loop setup before VM entry.
    pub vmentry_overhead_cycles: u64,
    /// Cycles spent after VM exit before exit handler (excluding IRQ window).
    pub vmexit_overhead_cycles: u64,
    /// Cycles spent in the IRQ window between VM exits.
    pub irq_window_cycles: u64,
    /// PEBS arm returned `BelowMinDelta` — target within `PEBS_MIN_DELTA + PEBS_MARGIN`
    /// of current count, so PEBS doesn't arm and MTF takes over.
    pub pebs_arm_below_min_delta: u64,
    /// PEBS arm returned `AlreadyPast` — target_tsc < current_tsc.
    pub pebs_arm_already_past: u64,
    /// Iterations that VM-entered with PEBS armed and exited without firing PEBS.
    pub pebs_armed_iter_no_fire: u64,
    /// Timer fires with `emulated_tsc > deadline` (the late-delivery safety net).
    pub apic_timer_late_inject: u64,
}

impl ExitStats {
    /// Get total exit count across all types.
    pub fn total_exit_count(&self) -> u64 {
        self.iter().map(|(_, e)| e.count).sum()
    }

    /// Get total exit handling cycles across all types.
    pub fn total_exit_cycles(&self) -> u64 {
        self.iter().map(|(_, e)| e.cycles).sum()
    }

    /// Iterate over all exit types with their names.
    pub fn iter(&self) -> impl Iterator<Item = (&'static str, &ExitStatEntry)> {
        [
            ("cpuid", &self.cpuid),
            ("msr_read", &self.msr_read),
            ("msr_write", &self.msr_write),
            ("cr_access", &self.cr_access),
            ("io_instruction", &self.io_instruction),
            ("ept_violation", &self.ept_violation),
            ("external_interrupt", &self.external_interrupt),
            ("rdtsc", &self.rdtsc),
            ("rdtscp", &self.rdtscp),
            ("rdpmc", &self.rdpmc),
            ("mwait", &self.mwait),
            ("vmcall", &self.vmcall),
            ("apic_access", &self.apic_access),
            ("mtf", &self.mtf),
            ("xsetbv", &self.xsetbv),
            ("rdrand", &self.rdrand),
            ("rdseed", &self.rdseed),
            ("exception_nmi", &self.exception_nmi),
            ("other", &self.other),
        ]
        .into_iter()
    }
}

/// Userspace timing statistics for ioctl calls.
#[derive(Clone, Copy, Default, Debug)]
pub struct IoctlStats {
    /// Total time spent in RUN ioctl (nanoseconds).
    pub run_ns: u64,
    /// Number of RUN ioctl calls.
    pub run_count: u64,
    /// Total time spent in GET_REGS ioctl (nanoseconds).
    pub get_regs_ns: u64,
    /// Number of GET_REGS ioctl calls.
    pub get_regs_count: u64,
    /// Total time spent in SET_REGS ioctl (nanoseconds).
    pub set_regs_ns: u64,
    /// Number of SET_REGS ioctl calls.
    pub set_regs_count: u64,
    /// Total time spent in other ioctls (nanoseconds).
    pub other_ns: u64,
    /// Number of other ioctl calls.
    pub other_count: u64,
}

impl IoctlStats {
    /// Get total time spent in all ioctls (nanoseconds).
    pub fn total_ns(&self) -> u64 {
        self.run_ns + self.get_regs_ns + self.set_regs_ns + self.other_ns
    }

    /// Get total ioctl call count.
    pub fn total_count(&self) -> u64 {
        self.run_count + self.get_regs_count + self.set_regs_count + self.other_count
    }

    fn iter(&self) -> impl Iterator<Item = (&'static str, u64, u64)> {
        [
            ("RUN", self.run_count, self.run_ns),
            ("GET_REGS", self.get_regs_count, self.get_regs_ns),
            ("SET_REGS", self.set_regs_count, self.set_regs_ns),
            ("OTHER", self.other_count, self.other_ns),
        ]
        .into_iter()
    }
}

impl fmt::Display for IoctlStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f)?;
        writeln!(f, "Userspace Ioctl Timing:")?;
        writeln!(f, "{TABLE_SEP}")?;
        writeln!(
            f,
            "{:<20} {:>12} {:>16} {:>12}",
            "Ioctl", "Count", "Total Time", "Avg Time"
        )?;
        writeln!(f, "{TABLE_SEP}")?;

        for (name, count, ns) in self.iter() {
            if count > 0 {
                writeln!(
                    f,
                    "{:<20} {:>12} {:>16} {:>12}",
                    name,
                    format_count(count),
                    format_time_ns(ns),
                    format_time_ns(ns / count),
                )?;
            }
        }

        writeln!(f, "{TABLE_SEP}")?;
        writeln!(
            f,
            "{:<20} {:>12} {:>16}",
            "TOTAL",
            format_count(self.total_count()),
            format_time_ns(self.total_ns()),
        )?;
        write!(f, "{TABLE_SEP}")
    }
}

/// Wraps `ExitStats` with wall clock duration for display.
pub struct ExitStatsReport<'a> {
    pub stats: &'a ExitStats,
    pub wall_clock: Duration,
}

impl fmt::Display for ExitStatsReport<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let stats = self.stats;
        let total_exit_cycles = stats.total_exit_cycles();
        let total_exits = stats.total_exit_count();

        writeln!(f)?;
        writeln!(f, "Exit Handler Statistics:")?;
        writeln!(f, "{TABLE_SEP}")?;
        writeln!(
            f,
            "{:<20} {:>12} {:>16} {:>12} {:>10}",
            "Exit Type", "Count", "Total Cycles", "Avg Cycles", "% Time"
        )?;
        writeln!(f, "{TABLE_SEP}")?;

        for (name, entry) in stats.iter() {
            if entry.count > 0 {
                writeln!(
                    f,
                    "{:<20} {:>12} {:>16} {:>12} {:>9.1}%",
                    name,
                    format_count(entry.count),
                    format_count(entry.cycles),
                    format_count(entry.avg_cycles()),
                    pct(entry.cycles, total_exit_cycles)
                )?;
            }
        }

        writeln!(f, "{TABLE_SEP}")?;
        let avg_per_exit = total_exit_cycles.checked_div(total_exits).unwrap_or(0);
        writeln!(
            f,
            "{:<20} {:>12} {:>16} {:>12} {:>10}",
            "TOTAL EXITS",
            format_count(total_exits),
            format_count(total_exit_cycles),
            format_count(avg_per_exit),
            "100.0%"
        )?;

        let wall_secs = self.wall_clock.as_secs_f64();
        let estimated_tsc_freq = if wall_secs > 0.0 {
            stats.total_run_cycles as f64 / wall_secs
        } else {
            0.0
        };

        let cycles_to_wall_pct = |cycles: u64| -> f64 {
            if estimated_tsc_freq > 0.0 && wall_secs > 0.0 {
                (cycles as f64 / estimated_tsc_freq / wall_secs) * 100.0
            } else {
                0.0
            }
        };

        let run = stats.total_run_cycles;

        writeln!(f)?;
        writeln!(f, "Time Breakdown:")?;
        writeln!(f, "{TABLE_SEP}")?;
        writeln!(
            f,
            "  VM entry overhead:  {:>16} cycles ({:>5.1}% of run loop)",
            format_count(stats.vmentry_overhead_cycles),
            pct(stats.vmentry_overhead_cycles, run)
        )?;
        writeln!(
            f,
            "  Guest execution:    {:>16} cycles ({:>5.1}% of run loop, {:>5.1}% of wall clock)",
            format_count(stats.guest_cycles),
            pct(stats.guest_cycles, run),
            cycles_to_wall_pct(stats.guest_cycles)
        )?;
        writeln!(
            f,
            "  VM exit overhead:   {:>16} cycles ({:>5.1}% of run loop)",
            format_count(stats.vmexit_overhead_cycles),
            pct(stats.vmexit_overhead_cycles, run)
        )?;
        writeln!(
            f,
            "  IRQ window:         {:>16} cycles ({:>5.1}% of run loop)",
            format_count(stats.irq_window_cycles),
            pct(stats.irq_window_cycles, run)
        )?;
        writeln!(
            f,
            "  Exit handling:      {:>16} cycles ({:>5.1}% of run loop, {:>5.1}% of wall clock)",
            format_count(total_exit_cycles),
            pct(total_exit_cycles, run),
            cycles_to_wall_pct(total_exit_cycles)
        )?;
        writeln!(
            f,
            "  Kernel run loop:    {:>16} cycles ({:>5.1}% of wall clock)",
            format_count(run),
            cycles_to_wall_pct(run)
        )?;
        writeln!(f, "  Wall clock time:    {:>16.3} seconds", wall_secs)?;
        writeln!(f, "{TABLE_SEP}")?;

        writeln!(f)?;
        writeln!(f, "PEBS Diagnostics:")?;
        writeln!(f, "{TABLE_SEP}")?;
        writeln!(
            f,
            "  arm BelowMinDelta:  {:>16}",
            format_count(stats.pebs_arm_below_min_delta)
        )?;
        writeln!(
            f,
            "  arm AlreadyPast:    {:>16}",
            format_count(stats.pebs_arm_already_past)
        )?;
        writeln!(
            f,
            "  armed iter no fire: {:>16}",
            format_count(stats.pebs_armed_iter_no_fire)
        )?;
        writeln!(
            f,
            "  timer late inject:  {:>16}",
            format_count(stats.apic_timer_late_inject)
        )?;
        write!(f, "{TABLE_SEP}")
    }
}
