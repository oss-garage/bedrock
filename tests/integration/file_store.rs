//! File-store hypercall: a guest exporter (`bedrock-file-store`) reads a guest
//! file and chunks it out to the host via `HYPERCALL_FILE_STORE`. This test
//! compares the hashes on the guest and host as file_xfer.rs does.

use bedrock_lab::BashTarget;

use crate::common;

#[test]
fn stored_file_matches_guest_hash() {
    let Some(ready) = common::ready_checkpoint() else {
        return common::skip("stored_file_matches_guest_hash");
    };

    let mut branch = ready.branch().expect("fork branch");

    // Create a guest file larger than the maximum buffer size to test
    // multiple chunks.
    let file_name = "/tmp/export.bin";
    let total = 1_500_000usize;
    branch
        .bash(
            BashTarget::host(),
            &format!("head -c {total} /dev/urandom > {file_name}"),
            false,
        )
        .expect("seed guest file");

    let want = common::guest_sha256(&mut branch, file_name);

    // The guest will send chunks to the host which will store the chunks.
    let run = branch
        .bash(
            BashTarget::host(),
            &format!("/usr/local/bin/bedrock-file-store {file_name} {file_name}"),
            true,
        )
        .expect("dispatch bedrock-file-store in guest");
    assert!(
        run.success(),
        "guest exporter failed (status={} exit={}) output: {:?}",
        run.status,
        run.exit_code,
        run.output_lossy(),
    );

    // The host file the exporter produced must match the guest original.
    let got = common::host_sha256(file_name);
    assert_eq!(got, want, "host hash does not match guest hash",);

    let _ = std::fs::remove_file(file_name);
}
