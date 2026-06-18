//! Determinism of the execution tree: sibling branches forked from one
//! checkpoint produce bit-identical results, and rewinding a checkpoint
//! lands at an earlier — and reproducible — point.

use bedrock_lab::{BashTarget, Checkpoint, EventConfig, ExitCapture};

use crate::common;

/// Fork a fresh branch off `ready`, capture every exit, drive it through a
/// fixed deterministic workload, and return its normalized exit-record stream
/// (the per-exit guest state: register and device-state hashes, served
/// randomness, injected interrupts, I/O transactions). Two sibling branches
/// that ran this must return byte-identical streams.
fn exit_stream(ready: &Checkpoint) -> Vec<serde_json::Value> {
    let sink = common::capture_sink();
    let mut branch = ready.branch().expect("fork branch");

    // Capture a record for every exit. Memory hashing stays off: register and
    // device-state hashes already pin down divergence, and hashing multi-GB
    // guest memory on every exit would dominate the test's run time.
    branch
        .set_event_config(&EventConfig {
            exits: ExitCapture::AllExits { memory_hash: false },
            ..Default::default()
        })
        .expect("enable exit capture");
    let id = branch.id();

    // Identical deterministic work on both siblings: a bash command (exercises
    // the deterministic I/O channel and a guest-entropy read) followed by a
    // fixed idle advance (exercises deterministic timer-interrupt injection).
    branch
        .bash(
            BashTarget::host(),
            "echo determinism-probe; cat /proc/sys/kernel/random/boot_id",
            true,
        )
        .expect("bash");
    branch.run_for(vt_dur!(50 ms)).expect("idle advance");

    sink.take_deterministic(id)
}

#[test]
fn sibling_branches_are_bit_identical() {
    let Some(ready) = common::ready_checkpoint() else {
        return common::skip("sibling_branches_are_bit_identical");
    };

    let a = exit_stream(&ready);
    let b = exit_stream(&ready);

    assert!(
        !a.is_empty(),
        "expected exit records to be captured — is exit logging wired up?"
    );
    assert_eq!(
        a.len(),
        b.len(),
        "number of deterministic exit records diverged: {} vs {}",
        a.len(),
        b.len(),
    );
    // Compare record-by-record so the first divergence localizes the bug.
    for (i, (ra, rb)) in a.iter().zip(&b).enumerate() {
        assert_eq!(
            ra, rb,
            "guest state diverged at deterministic exit record {i}:\n a={ra}\n b={rb}",
        );
    }
}

#[test]
fn rewind_lands_earlier_and_reproduces() {
    let Some(ready) = common::ready_checkpoint() else {
        return common::skip("rewind_lands_earlier_and_reproduces");
    };

    // Advance a branch a full second past ready, then freeze it.
    let mut branch = ready.branch().expect("fork branch");
    branch.run_for(vt_dur!(1 s)).expect("advance 1s");
    let cp = branch.checkpoint().expect("checkpoint");

    // Rewind half a second. The result must sit strictly before the
    // checkpoint and no earlier than where we started.
    let earlier = cp.rewind(vt_dur!(500 ms)).expect("rewind");
    assert!(
        earlier.time() == cp.time() - vt_dur!(500 ms),
        "rewound checkpoint ({:.3}s) should be exactly 0.5s before cp ({:.3}s)",
        earlier.time().as_secs_f64(),
        cp.time().as_secs_f64(),
    );

    // A branch off the rewound point still runs — rewinding yields a live,
    // forkable checkpoint, not a dead handle.
    let mut resumed = earlier.branch().expect("fork rewound branch");
    let out = resumed
        .bash(BashTarget::host(), "echo post-rewind", true)
        .expect("bash after rewind");
    assert!(
        out.output_lossy().contains("post-rewind"),
        "expected command output after rewind, got {:?}",
        out.output_lossy(),
    );
}
