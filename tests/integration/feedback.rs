//! The feedback-buffer channel: a guest process registers a buffer via the
//! `HYPERCALL_REGISTER_FEEDBACK_BUFFER` hypercall and the lab reads its
//! contents back out of the guest's physical memory — including across a COW
//! fork, where a child branch inherits the same bytes.

use bedrock_lab::BashTarget;

use crate::common;

/// The driver inside the integration-tests container, the id and size it
/// registers, and the payload this test asks it to write. Kept in sync with
/// `workloads/integration-tests/ready/test_feedback_buffers.c`.
const DRIVER: &str = "/opt/bedrock/drivers/test_feedback_buffers";
const FB_ID: &[u8] = b"bedrock-test-fb";
const FB_SIZE: usize = 4096;
const PAYLOAD: &str = "bedrock-feedback-roundtrip";

#[test]
fn feedback_buffer_round_trips_from_guest() {
    let Some(ready) = common::ready_checkpoint() else {
        return common::skip("feedback_buffer_round_trips_from_guest");
    };

    let mut branch = ready.branch().expect("fork branch");

    // The driver ships in the workload image; expect it to be there.
    let probe = branch
        .bash(
            BashTarget::container("idle"),
            &format!("test -x {DRIVER}"),
            false,
        )
        .expect("probe driver");
    assert!(
        probe.success(),
        "expected the driver at {DRIVER} (rebuild the integration-tests workload \
         image): exit={}",
        probe.exit_code,
    );

    // Launch it detached: it writes our payload into a zeroed page, registers
    // it as a feedback buffer, and then stays alive forever so the pages stay
    // mapped and pinned (a dead driver would let the guest reallocate the GPA
    // and overwrite the buffer with junk). Redirect its stdio so it neither
    // holds the I/O channel's output-capture pipe open nor blocks this call.
    branch
        .bash(
            BashTarget::container("idle"),
            &format!("{DRIVER} {PAYLOAD} >/dev/null 2>&1 &"),
            false,
        )
        .expect("launch feedback-buffer driver");

    // The driver runs asynchronously; advance the guest until its registration
    // shows up. Deterministic execution means it lands at the same point every
    // run, so this is reproducible — the budget is just a safety net.
    let deadline = branch.current_time() + vt_dur!(5 s);
    while !registered(&branch) {
        assert!(
            branch.current_time() < deadline,
            "driver never registered a feedback buffer under {:?}",
            String::from_utf8_lossy(FB_ID),
        );
        branch.run_for(vt_dur!(50 ms)).expect("advance guest");
    }

    // Read it back: the bytes we asked the guest to write must survive the
    // GVA->GPA->host mapping, with the rest of the page left zeroed.
    let bufs = branch
        .feedback_buffers_to_vec(FB_ID)
        .expect("read feedback buffers");
    assert_eq!(bufs.len(), 1, "expected exactly one buffer under the id");
    assert!(
        bufs[0].len() >= FB_SIZE,
        "mapped buffer shorter than registered size: {} < {FB_SIZE}",
        bufs[0].len(),
    );

    let mut expected = vec![0u8; FB_SIZE];
    expected[..PAYLOAD.len()].copy_from_slice(PAYLOAD.as_bytes());
    assert_eq!(
        &bufs[0][..FB_SIZE],
        expected.as_slice(),
        "feedback buffer content did not match what the guest wrote",
    );

    // The registration and its contents are inherited through COW: a branch
    // forked off this point sees the same bytes without re-running the driver
    // (the pages were pre-COW'd at registration, so the child gets its own
    // stable copy). This holds even though nothing runs in the child — the
    // content lives in the snapshot, not in a live guest process.
    let checkpoint = branch.checkpoint().expect("checkpoint parent branch");
    let mut child = checkpoint.branch().expect("branch off checkpoint");
    let child_bufs = child
        .feedback_buffers_to_vec(FB_ID)
        .expect("read child feedback buffers");
    assert_eq!(
        child_bufs.len(),
        1,
        "child should inherit exactly one buffer under the id",
    );
    assert_eq!(
        child_bufs[0], bufs[0],
        "forked branch's feedback buffer diverged from its parent's",
    );
}

/// Whether a feedback buffer under [`FB_ID`] is registered on `branch`.
fn registered(branch: &bedrock_lab::Branch) -> bool {
    branch
        .feedback_buffer_ids()
        .expect("list feedback ids")
        .iter()
        .any(|id| id == FB_ID)
}
