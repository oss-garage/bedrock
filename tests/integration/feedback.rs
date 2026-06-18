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

/// The "counter" driver and its id: it registers a buffer and then bumps a
/// 64-bit little-endian counter at the front forever. Kept in sync with
/// `workloads/integration-tests/ready/test_feedback_buffer_counter.c`.
const COUNTER_DRIVER: &str = "/opt/bedrock/drivers/test_feedback_buffer_counter";
const COUNTER_FB_ID: &[u8] = b"bedrock-test-fb-counter";

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
    // forked off this point sees the same bytes without re-running the driver.
    // The child never writes the buffer, so its mapping resolves each page
    // straight through the COW chain to the shared snapshot's frame. This holds
    // even though nothing runs in the child — the content lives in the
    // snapshot, not in a live guest process.
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

/// The number of registerable feedback buffers is unbounded — there is no
/// fixed slot cap. Launching many instances of the driver, well past the old
/// hard limit of 16, registers a distinct buffer for each, and the lab can map
/// and read back every one.
#[test]
fn feedback_buffer_count_is_unbounded() {
    let Some(ready) = common::ready_checkpoint() else {
        return common::skip("feedback_buffer_count_is_unbounded");
    };

    let mut branch = ready.branch().expect("fork branch");

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

    // Spawn many instances, each registering its own pinned buffer under the
    // shared id (ids need not be unique — each registration gets a fresh slot).
    // COUNT is deliberately well above the legacy fixed cap of 16 to prove the
    // count is unbounded and grows on the heap. Each stays alive (`&`) so its
    // page stays pinned, exactly like the single-driver test above.
    const COUNT: usize = 20;
    branch
        .bash(
            BashTarget::container("idle"),
            &format!("for i in $(seq 1 {COUNT}); do {DRIVER} {PAYLOAD} >/dev/null 2>&1 & done"),
            false,
        )
        .expect("launch feedback-buffer drivers");

    // Advance until all COUNT registrations land. Deterministic execution makes
    // this reproducible; the budget is just a safety net.
    let deadline = branch.current_time() + vt_dur!(10 s);
    loop {
        let n = branch
            .feedback_buffers_to_vec(FB_ID)
            .expect("read feedback buffers")
            .len();
        if n >= COUNT {
            break;
        }
        assert!(
            branch.current_time() < deadline,
            "only {n}/{COUNT} feedback buffers registered before the deadline",
        );
        branch.run_for(vt_dur!(50 ms)).expect("advance guest");
    }

    // Every buffer must carry the payload the driver wrote — proving all of
    // them (not just the first 16) mapped and read back correctly through the
    // unbounded slot vector.
    let bufs = branch
        .feedback_buffers_to_vec(FB_ID)
        .expect("read feedback buffers");
    assert!(
        bufs.len() >= COUNT,
        "expected at least {COUNT} feedback buffers, got {}",
        bufs.len(),
    );

    let mut expected = vec![0u8; FB_SIZE];
    expected[..PAYLOAD.len()].copy_from_slice(PAYLOAD.as_bytes());
    for (i, buf) in bufs.iter().enumerate() {
        assert!(
            buf.len() >= FB_SIZE,
            "buffer {i} shorter than registered size: {} < {FB_SIZE}",
            buf.len(),
        );
        assert_eq!(
            &buf[..FB_SIZE],
            expected.as_slice(),
            "feedback buffer {i} content did not match what the guest wrote",
        );
    }
}

/// Each feedback buffer is independent: writing a *different* payload into
/// every buffer and reading them all back yields exactly the set of distinct
/// payloads, with no buffer aliasing another's pages. Combined with a count
/// past the legacy cap of 16, this exercises distinct content across the
/// unbounded slot vector.
#[test]
fn feedback_buffers_hold_distinct_content() {
    let Some(ready) = common::ready_checkpoint() else {
        return common::skip("feedback_buffers_hold_distinct_content");
    };

    let mut branch = ready.branch().expect("fork branch");

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

    // Launch one driver per distinct payload, all under the shared FB_ID. Each
    // writes its own payload into its own pinned page, so the buffers must come
    // back carrying different content. COUNT is past the legacy cap of 16.
    const COUNT: usize = 18;
    let expected: Vec<String> = (1..=COUNT).map(|i| format!("fb-distinct-{i}")).collect();
    branch
        .bash(
            BashTarget::container("idle"),
            &format!(
                "for i in $(seq 1 {COUNT}); do {DRIVER} \"fb-distinct-$i\" >/dev/null 2>&1 & done"
            ),
            false,
        )
        .expect("launch feedback-buffer drivers");

    // Advance until all COUNT registrations land.
    let deadline = branch.current_time() + vt_dur!(10 s);
    loop {
        let n = branch
            .feedback_buffers_to_vec(FB_ID)
            .expect("read feedback buffers")
            .len();
        if n >= COUNT {
            break;
        }
        assert!(
            branch.current_time() < deadline,
            "only {n}/{COUNT} feedback buffers registered before the deadline",
        );
        branch.run_for(vt_dur!(50 ms)).expect("advance guest");
    }

    // Read every buffer and recover its payload (the bytes up to the first NUL,
    // since the driver writes payload + zero padding). The multiset of recovered
    // payloads must equal the set we wrote — each buffer holds its own distinct
    // content, none aliases another's, and none is missing or duplicated.
    let bufs = branch
        .feedback_buffers_to_vec(FB_ID)
        .expect("read feedback buffers");
    let mut got: Vec<String> = bufs
        .iter()
        .map(|b| {
            let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
            String::from_utf8_lossy(&b[..end]).into_owned()
        })
        .collect();
    got.sort();

    let mut want = expected.clone();
    want.sort();

    assert_eq!(
        got, want,
        "feedback buffers did not hold the distinct per-buffer content that was written",
    );
}

/// A feedback buffer mapped once stays coherent with later guest writes, even
/// on a forked child that maps the buffer *before* it has written it: "map
/// once, keep running, re-read".
///
/// This is the case that needs the kernel to copy-on-write the buffer's pages
/// into the child at map time. A child forked off a checkpoint inherits the
/// buffer's pages shared (read-only) from its parent — none are COW'd in the
/// child. If the mapping just pointed at the parent's frames, the child's
/// later writes would COW each page to a *new* frame and the mapping would go
/// stale. The test maps the counter buffer in a fresh child, then runs the
/// child so the inherited driver keeps bumping the counter, and verifies the
/// value advances through the same mapping.
#[test]
fn feedback_buffer_reflects_writes_after_mapping() {
    let Some(ready) = common::ready_checkpoint() else {
        return common::skip("feedback_buffer_reflects_writes_after_mapping");
    };

    let mut parent = ready.branch().expect("fork parent branch");

    let probe = parent
        .bash(
            BashTarget::container("idle"),
            &format!("test -x {COUNTER_DRIVER}"),
            false,
        )
        .expect("probe driver");
    assert!(
        probe.success(),
        "expected the driver at {COUNTER_DRIVER} (rebuild the integration-tests \
         workload image): exit={}",
        probe.exit_code,
    );

    // Launch the counter driver in the parent branch: it registers the buffer
    // (COWing its page in this branch as it faults the page in) and then bumps
    // the counter forever.
    parent
        .bash(
            BashTarget::container("idle"),
            &format!("{COUNTER_DRIVER} >/dev/null 2>&1 &"),
            false,
        )
        .expect("launch counter driver");

    // Advance until the buffer is registered.
    let deadline = parent.current_time() + vt_dur!(5 s);
    while !registered_id(&parent, COUNTER_FB_ID) {
        assert!(
            parent.current_time() < deadline,
            "counter driver never registered its buffer",
        );
        parent.run_for(vt_dur!(50 ms)).expect("advance parent");
    }

    // Checkpoint the parent and fork a fresh child. The child inherits the
    // registration and the still-running driver, but NONE of the buffer's pages
    // are COW'd in the child yet — they're shared read-only from the parent.
    let checkpoint = parent.checkpoint().expect("checkpoint parent");
    let mut child = checkpoint.branch().expect("fork child");

    // Map the buffer in the child BEFORE it runs, and read the counter. The
    // kernel COWs the buffer's pages into the child at map time so this mapping
    // tracks the child's own frames.
    let c1 = read_counter(&mut child).expect("counter buffer mapped in child");

    // Let the inherited, still-running driver keep bumping the counter in the
    // child for a while.
    child.run_for(vt_dur!(200 ms)).expect("advance child");

    // Re-read THROUGH THE SAME MAPPING (no remap). It must reflect the child's
    // post-mapping writes — proving the mapping did not go stale.
    let c2 = read_counter(&mut child).expect("counter buffer still mapped");

    assert!(
        c2 > c1,
        "feedback buffer mapping did not reflect guest writes made after mapping: \
         c1={c1}, c2={c2} (the mapping went stale)",
    );
}

/// Whether a feedback buffer under `id` is registered on `branch`.
fn registered_id(branch: &bedrock_lab::Branch, id: &[u8]) -> bool {
    branch
        .feedback_buffer_ids()
        .expect("list feedback ids")
        .iter()
        .any(|i| i == id)
}

/// Map (lazily, once) the counter buffer and read its leading little-endian
/// u64. Subsequent calls re-read the same live mapping.
fn read_counter(branch: &mut bedrock_lab::Branch) -> Option<u64> {
    let bufs = branch
        .feedback_buffers_to_vec(COUNTER_FB_ID)
        .expect("read counter buffer");
    let b = bufs.first()?;
    if b.len() < 8 {
        return None;
    }
    Some(u64::from_le_bytes(b[..8].try_into().unwrap()))
}

/// Whether a feedback buffer under [`FB_ID`] is registered on `branch`.
fn registered(branch: &bedrock_lab::Branch) -> bool {
    branch
        .feedback_buffer_ids()
        .expect("list feedback ids")
        .iter()
        .any(|id| id == FB_ID)
}
