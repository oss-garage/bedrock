//! The deterministic bash I/O channel: commands dispatched through
//! `bedrock-io.ko` run in the guest and their output/exit status come back.

use bedrock_lab::{BashTarget, RunOutcome};

use crate::common;

#[test]
fn bash_host_runs_and_captures_output() {
    let Some(ready) = common::ready_checkpoint() else {
        return common::skip("bash_host_runs_and_captures_output");
    };

    let mut branch = ready.branch().expect("fork branch");
    let out = branch
        .bash(BashTarget::host(), "echo hello-bedrock", true)
        .expect("bash");

    assert!(
        out.success(),
        "command failed: status={} exit={}",
        out.status,
        out.exit_code,
    );
    assert!(
        out.output_lossy().contains("hello-bedrock"),
        "expected captured output to contain the echoed string, got {:?}",
        out.output_lossy(),
    );
}

#[test]
fn bash_propagates_exit_code() {
    let Some(ready) = common::ready_checkpoint() else {
        return common::skip("bash_propagates_exit_code");
    };

    let mut branch = ready.branch().expect("fork branch");
    // record_output=false: we only care about the exit status plumbing here.
    let out = branch
        .bash(BashTarget::host(), "exit 7", false)
        .expect("bash");

    assert_eq!(out.status, 0, "action should dispatch cleanly");
    assert_eq!(out.exit_code, 7, "guest exit code should propagate back");
    assert!(!out.success());
}

#[test]
fn bash_runs_in_idle_container() {
    let Some(ready) = common::ready_checkpoint() else {
        return common::skip("bash_runs_in_idle_container");
    };

    // The integration-tests compose brings up a single container named `idle`.
    let mut branch = ready.branch().expect("fork branch");
    let out = branch
        .bash(BashTarget::container("idle"), "echo from-container", true)
        .expect("bash in container");

    assert!(
        out.success(),
        "container command failed: status={} exit={}",
        out.status,
        out.exit_code,
    );
    assert!(
        out.output_lossy().contains("from-container"),
        "expected container output, got {:?}",
        out.output_lossy(),
    );
}

#[test]
fn sched_bash_fires_at_scheduled_time() {
    let Some(ready) = common::ready_checkpoint() else {
        return common::skip("sched_bash_fires_at_scheduled_time");
    };

    let mut branch = ready.branch().expect("fork branch");

    // Unlike `bash`, `sched_bash` returns immediately and the command fires
    // later, at a fixed virtual time. Queue one a little ahead of now.
    let fire_at = branch.current_time() + vt_dur!(10 ms);
    branch
        .sched_bash(fire_at, BashTarget::host(), "echo scheduled-probe", true)
        .expect("schedule bash");

    // Drive forward: the response surfaces as an ActionResponse once the guest
    // runs the command, which can't happen before the scheduled time. Stop
    // well past `fire_at` so a working dispatch always lands first.
    let deadline = fire_at + vt_dur!(1 s);
    let (at, out) = loop {
        let (at, outcome) = branch.run_until(deadline).expect("run_until");
        match outcome {
            RunOutcome::ActionResponse { output } => break (at, output),
            // A re-issued ready hypercall during the idle window is benign.
            RunOutcome::Ready => continue,
            RunOutcome::ReachedTime => {
                panic!("reached {deadline:?} before the scheduled bash responded")
            }
            other => panic!("unexpected outcome before response: {other:?}"),
        }
    };

    assert!(
        at >= fire_at,
        "response landed at {at:?}, before its scheduled time {fire_at:?}",
    );
    assert!(
        out.success(),
        "scheduled command failed: status={} exit={}",
        out.status,
        out.exit_code,
    );
    assert!(
        out.output_lossy().contains("scheduled-probe"),
        "expected scheduled output, got {:?}",
        out.output_lossy(),
    );
}
