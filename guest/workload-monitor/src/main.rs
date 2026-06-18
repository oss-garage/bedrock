//! Bedrock workload monitor.
//!
//! A long-lived service that runs in the guest's host namespace (outside the
//! workload containers). Started once at guest boot, it spawns
//! `podman events --format json` and tails the stream to derive assertions
//! about the workloads. It writes nothing to stdout.
//!
//! The invariant it documents: whenever a container's main process or one of
//! its `podman exec` sessions dies, the exit code should always be zero (a
//! clean exit). Each such death appends an [`Assertion`] recording the observed
//! exit code — serialized as one line of JSON — to the sink at
//! [`ASSERTIONS_PATH`], where a downstream collector can aggregate the results.

use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

use bedrock_assertions::always_eq;
use serde::Deserialize;

/// Default assertion sink: an append-only JSONL file, one assertion per line.
/// Override with the `BEDROCK_ASSERTIONS_PATH` environment variable (used by
/// tests/local runs).
const ASSERTIONS_PATH: &str = "/bedrock/assertions.jsonl";

/// A single `podman events --format json` record. Only the fields we act on are
/// declared; everything else in the line is ignored. Field names match podman's
/// JSON marshaling (capitalized), and all are optional so a record shape we
/// don't recognize parses rather than aborting the stream.
#[derive(Deserialize)]
struct Event {
    #[serde(rename = "Type")]
    type_: Option<String>,
    /// The event action, e.g. `"died"`, `"exec_died"`, `"start"`.
    #[serde(rename = "Status")]
    status: Option<String>,
    /// Process exit code. podman populates it on `"died"` (the container's main
    /// process) and `"exec_died"` (a `podman exec` session).
    #[serde(rename = "ContainerExitCode")]
    exit_code: Option<i64>,
    /// Container name — the container itself, or the one an exec ran in.
    #[serde(rename = "Name")]
    name: Option<String>,
}

/// Assertion message for a `podman exec` session dying.
const EXEC_DEATH_MSG: &str = "exec exit code is zero";

/// Exit code podman reports for an exec the `bedrock-io` module SIGKILLs when
/// quiescing the workload before an `eventually_` invariant check (128 + SIGKILL
/// = 137). These deaths are intentional barrier kills, not workload faults, so
/// the exec-exit-code invariant is not asserted for them — otherwise every
/// quiesce would surface a spurious "exec exit code is zero" failure. A driver
/// that means to report a real failure exits with an ordinary non-zero code (or
/// trips a `bedrock-assertion`), which is still asserted below. Trade-off: a
/// genuine SIGKILL/OOM exec death (also 137) is likewise ignored.
const BARRIER_KILL_EXIT_CODE: i64 = 137;

impl Event {
    /// For a container- or exec-death event we assert on, the exit code paired
    /// with the assertion message; else `None`. The container-death message
    /// names the container. Both `"died"` and `"exec_died"` carry
    /// `ContainerExitCode`; a missing code is treated as a clean `0` exit.
    fn death(&self) -> Option<(i64, String)> {
        if self.type_.as_deref() != Some("container") {
            return None;
        }
        let exit_code = self.exit_code.unwrap_or(0);
        match self.status.as_deref() {
            Some("died") => {
                let name = self.name.as_deref().unwrap_or("<unknown>");
                Some((exit_code, format!("container {name} exit code is zero")))
            }
            // Drivers SIGKILLed by the quiesce barrier exit 137; that's an
            // intentional kill, not a fault, so don't assert on it.
            Some("exec_died") if exit_code == BARRIER_KILL_EXIT_CODE => None,
            Some("exec_died") => Some((exit_code, EXEC_DEATH_MSG.to_string())),
            _ => None,
        }
    }
}

fn main() {
    if let Err(e) = run() {
        eprintln!("{e}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    // Open the shared assertion sink up front. Append mode + whole-line writes
    // keep concurrent writers (this monitor plus the containers that mount the
    // same file) from interleaving. A failure here is non-fatal: we keep
    // draining the event stream (so podman doesn't block on a full pipe), we
    // just can't record assertions.
    let path = std::env::var("BEDROCK_ASSERTIONS_PATH").unwrap_or_else(|_| ASSERTIONS_PATH.into());
    let mut sink = match OpenOptions::new().create(true).append(true).open(&path) {
        Ok(file) => Some(file),
        Err(e) => {
            eprintln!("cannot open assertion sink {path}: {e}; assertions will be dropped");
            None
        }
    };

    // Read events as they happen. `--stream` keeps the process attached and
    // emitting; without a `--filter` we receive every event podman reports.
    // `--format json` emits one self-contained JSON object per line (newline-
    // delimited), so each line parses on its own.
    let mut child = Command::new("podman")
        .args(["events", "--stream", "--format", "json"])
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|e| format!("failed to spawn podman events: {e}"))?;

    let stdout = child
        .stdout
        .take()
        .ok_or("podman events produced no stdout")?;

    for line in BufReader::new(stdout).lines() {
        let line = line.map_err(|e| format!("reading podman events: {e}"))?;

        // Best-effort: a line we can't parse is simply skipped.
        if let Ok(event) = serde_json::from_str::<Event>(&line) {
            if let Some((exit_code, message)) = event.death() {
                record_exit_code_assertion(sink.as_mut(), exit_code, &message);
            }
        }
    }

    let status = child
        .wait()
        .map_err(|e| format!("waiting on podman events: {e}"))?;
    Err(format!("podman events exited: {status}"))
}

/// Record the "exit code is always == 0" invariant for an observed container-
/// or exec-death by appending one line of serialized JSON to the assertion
/// sink. `message` distinguishes the two kinds: the container-death message
/// names the container; the exec-death one is [`EXEC_DEATH_MSG`].
fn record_exit_code_assertion(sink: Option<&mut File>, exit_code: i64, message: &str) {
    let Some(file) = sink else { return };

    let assertion = always_eq!(exit_code, 0, message);
    let mut line = match serde_json::to_string(&assertion) {
        Ok(json) => json,
        Err(e) => {
            eprintln!("failed to serialize exit-code assertion: {e}");
            return;
        }
    };
    // One write of a single sub-PIPE_BUF line keeps appends atomic across the
    // file's concurrent writers.
    line.push('\n');
    if let Err(e) = file.write_all(line.as_bytes()) {
        eprintln!("failed to append assertion to sink: {e}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(type_: &str, status: &str, exit_code: Option<i64>, name: &str) -> Event {
        Event {
            type_: Some(type_.to_string()),
            status: Some(status.to_string()),
            exit_code,
            name: Some(name.to_string()),
        }
    }

    #[test]
    fn exec_died_clean_and_failed_assert_but_barrier_kill_is_ignored() {
        // Normal clean exec exit: assert (and it holds).
        let (code, msg) = event("container", "exec_died", Some(0), "c1")
            .death()
            .expect("clean exec death asserts");
        assert_eq!((code, msg.as_str()), (0, EXEC_DEATH_MSG));

        // Ordinary non-zero exit (e.g. a failed eventually_ invariant): asserted.
        let (code, msg) = event("container", "exec_died", Some(1), "c1")
            .death()
            .expect("failed exec death asserts");
        assert_eq!((code, msg.as_str()), (1, EXEC_DEATH_MSG));

        // Barrier SIGKILL (137): suppressed, not a fault.
        assert!(
            event("container", "exec_died", Some(BARRIER_KILL_EXIT_CODE), "c1")
                .death()
                .is_none(),
            "SIGKILLed (137) execs must not assert"
        );
    }

    #[test]
    fn container_death_still_asserts_on_137() {
        // The 137 suppression is exec-only; a container main-process death with
        // any code (including 137) is still asserted.
        let (code, msg) = event("container", "died", Some(137), "btcd1")
            .death()
            .expect("container death asserts");
        assert_eq!(code, 137);
        assert_eq!(msg, "container btcd1 exit code is zero");
    }
}
