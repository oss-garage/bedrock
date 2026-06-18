//! RNG determinism. The tree boots with `RngMode::Seeded`, so guest
//! randomness is a pure function of the seed and the (deterministic)
//! execution that consumes it. Two sibling branches forked from the same
//! checkpoint, doing the same work, must observe identical randomness —
//! right down to what the kernel CRNG hands out through `/dev/urandom`.

use bedrock_lab::BashTarget;

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
