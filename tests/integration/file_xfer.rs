//! File-transmission hypercall: the generic podman initrd downloads its
//! workload files (`compose.yaml` / `images.tar`) from the host at boot over
//! `HYPERCALL_FILE_FETCH`.
//!
//! Rather than trust the boot log, this injects a command into the booted guest
//! that re-hashes the downloaded files and compares the digests against the
//! original host files — proving the transfer landed byte-for-byte.

use std::process::Command;

use bedrock_lab::{BashTarget, Branch};

use crate::common;

/// sha256 of a host file as a lowercase hex string, via the `sha256sum` CLI
/// (coreutils, present in CI). Panics on failure — the originals must exist for
/// the comparison to mean anything.
fn host_sha256(path: &str) -> String {
    let out = Command::new("sha256sum")
        .arg(path)
        .output()
        .unwrap_or_else(|e| panic!("run sha256sum {path} on host: {e}"));
    assert!(out.status.success(), "host sha256sum {path} failed");
    let stdout = String::from_utf8(out.stdout).expect("sha256sum utf8");
    first_token(&stdout)
}

/// Hash a guest file with the same tool, dispatched over the deterministic bash
/// I/O channel, and return its hex digest. Fails the test if the command didn't
/// run cleanly — `sha256sum` exits non-zero when the file is missing, so this
/// also covers the "file exists in the workload" check.
fn guest_sha256(branch: &mut Branch, path: &str) -> String {
    let out = branch
        .bash(BashTarget::host(), &format!("sha256sum {path}"), true)
        .expect("dispatch sha256sum in guest");
    assert!(
        out.success(),
        "guest `sha256sum {path}` failed (status={} exit={}) — file missing? output: {:?}",
        out.status,
        out.exit_code,
        out.output_lossy(),
    );

    first_token(&out.output_lossy())
}

/// The first whitespace-delimited token — `sha256sum` prints `<hex>  <path>`.
fn first_token(s: &str) -> String {
    s.split_whitespace().next().unwrap_or_default().to_string()
}

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
        let want = host_sha256(&host_path);
        let got = guest_sha256(&mut branch, guest_path);
        assert_eq!(
            got, want,
            "{guest_path} downloaded over the file-transmission hypercall does not \
             match the host original {host_path}",
        );
    }
}
