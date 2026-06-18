//! Boot reaches the ready checkpoint at a sane virtual time.

use crate::common;

#[test]
fn boots_to_ready_checkpoint() {
    let Some(ready) = common::ready_checkpoint() else {
        return common::skip("boots_to_ready_checkpoint");
    };

    // The guest had to boot Linux and bring up the workload before issuing
    // its ready hypercall, so the checkpoint must sit at a positive virtual
    // time well inside the boot deadline.
    assert!(
        ready.time().as_secs_f64() > 0.0,
        "ready checkpoint should be at a positive virtual time, got {:.3}s",
        ready.time().as_secs_f64()
    );

    // The tree reckons time against the deterministic emulated TSC.
    assert_eq!(ready.tsc_frequency(), bedrock_vm::DEFAULT_TSC_FREQUENCY);
}
