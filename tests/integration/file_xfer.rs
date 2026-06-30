//! File-transmission hypercall: the generic podman initrd downloads its
//! workload files (`compose.yaml` / `images.tar`) from the host at boot over
//! `HYPERCALL_FILE_FETCH`.
//!
//! Rather than trust the boot log, this injects a command into the booted guest
//! that re-hashes the downloaded files and compares the digests against the
//! original host files — proving the transfer landed byte-for-byte.

use crate::common;

/// The two files the guest downloads at boot, as `(host_original, guest_path)`.
/// The host paths are set by the `integration-tests` nix app (and required by
/// `ready_checkpoint`, so they're present whenever a checkpoint is).
fn workload_files() -> [(String, &'static str); 2] {
    let compose = std::env::var("BEDROCK_COMPOSE").expect("BEDROCK_COMPOSE set");
    let images = std::env::var("BEDROCK_IMAGES").expect("BEDROCK_IMAGES set");
    [
        (compose, "/workload/compose.yaml"),
        (images, "/images/images.tar"),
    ]
}

#[test]
fn downloaded_files_match_host_originals() {
    let Some(ready) = common::ready_checkpoint() else {
        return common::skip("downloaded_files_match_host_originals");
    };

    let mut branch = ready.branch().expect("fork branch");

    for (host_path, guest_path) in workload_files() {
        let want = common::host_sha256(&host_path);
        let got = common::guest_sha256(&mut branch, guest_path);
        assert_eq!(
            got, want,
            "{guest_path} downloaded over the file-transmission hypercall does not \
             match the host original {host_path}",
        );
    }
}
