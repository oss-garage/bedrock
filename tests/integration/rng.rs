//! RNG determinism. The tree boots with `RngMode::Seeded`, so guest
//! randomness is a pure function of the seed and the (deterministic)
//! execution that consumes it. Two sibling branches forked from the same
//! checkpoint, doing the same work, must observe identical randomness —
//! right down to what the kernel CRNG hands out through `/dev/urandom`.

use bedrock_lab::{BashTarget, EventCategories, EventConfig};

use crate::common;

/// Read a fixed number of bytes from the guest's `/dev/urandom`, hex-encoded
/// so the captured output is plain ASCII.
fn read_urandom(ready: &bedrock_lab::Checkpoint) -> Vec<u8> {
    let mut branch = ready.branch().expect("fork branch");
    let out = branch
        .bash(
            BashTarget::host(),
            "head -c 32 /dev/urandom | od -An -tx1",
            true,
        )
        .expect("bash");
    assert!(
        out.success(),
        "urandom read failed: status={} exit={}",
        out.status,
        out.exit_code,
    );
    out.output
}

#[test]
fn seeded_rng_makes_urandom_deterministic() {
    let Some(ready) = common::ready_checkpoint() else {
        return common::skip("seeded_rng_makes_urandom_deterministic");
    };

    let a = read_urandom(&ready);
    let b = read_urandom(&ready);

    assert!(!a.is_empty(), "expected some random bytes to be captured");
    assert_eq!(
        a,
        b,
        "seeded RNG should make guest /dev/urandom byte-identical across \
         sibling branches:\n a={:?}\n b={:?}",
        String::from_utf8_lossy(&a),
        String::from_utf8_lossy(&b),
    );
}

/// The guest kernel is patched so `/dev/urandom`, `/dev/random` and
/// `getrandom()` source their bytes from `HYPERCALL_GET_RANDOM` instead of the
/// in-kernel CRNG. Prove the patch is actually in effect end-to-end: with
/// `RANDOMNESS` capture on, a guest `/dev/urandom` read must surface as
/// `Randomness` records carrying `source == GetRandom` on the event stream
/// (with the in-kernel CRNG, urandom would emit none). This exercises the whole
/// chain — guest patch → VMCALL → host handler → recorded event.
///
/// (Determinism is covered by `seeded_rng_makes_urandom_deterministic`; that
/// test alone can't distinguish the patch from the CRNG, which is also seeded-
/// deterministic. This one pins down the channel.)
#[test]
fn urandom_reads_route_through_get_random_hypercall() {
    let Some(ready) = common::ready_checkpoint() else {
        return common::skip("urandom_reads_route_through_get_random_hypercall");
    };

    let sink = common::capture_sink();
    let mut branch = ready.branch().expect("fork branch");
    branch
        .set_event_config(&EventConfig {
            categories: EventCategories::RANDOMNESS,
            ..Default::default()
        })
        .expect("enable randomness capture");
    let id = branch.id();

    let out = branch
        .bash(
            BashTarget::host(),
            "head -c 64 /dev/urandom | od -An -tx1",
            true,
        )
        .expect("bash");
    assert!(
        out.success(),
        "urandom read failed: status={} exit={}",
        out.status,
        out.exit_code,
    );

    // `RandomSource::GetRandom` serializes as source == 2 in the record body
    // ({"kind":"randomness","data":{"source":2,"len":N,..}}).
    let records = sink.take_deterministic(id);
    let get_random: Vec<_> = records
        .iter()
        .filter(|r| r.get("kind").and_then(|k| k.as_str()) == Some("randomness"))
        .filter(|r| r.pointer("/data/source").and_then(|s| s.as_u64()) == Some(2))
        .collect();

    assert!(
        !get_random.is_empty(),
        "reading /dev/urandom should emit HYPERCALL_GET_RANDOM (source=GetRandom) \
         randomness records — proving the getrandom() VMCALL patch routes the \
         guest CRNG through the hypervisor. Captured records: {records:?}",
    );

    // The served bytes cover at least the 64 requested (the guest may chunk a
    // read into several capped GET_RANDOM requests; other readers may add more).
    let served: u64 = get_random
        .iter()
        .filter_map(|r| r.pointer("/data/len").and_then(|l| l.as_u64()))
        .sum();
    assert!(
        served >= 64,
        "expected at least the 64 requested bytes served via GET_RANDOM, got {served}",
    );
}
