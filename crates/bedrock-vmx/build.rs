// SPDX-License-Identifier: GPL-2.0

use std::env;
use std::path::Path;
use std::process::Command;

/// Compile and run `contrib/gen_pebs_margin.rs` to regenerate `PEBS_MARGIN`
/// for the build host. The generator binary is built into `OUT_DIR`, which
/// Cargo owns and cleans, so there is nothing to delete by hand.
///
/// This runs only for the cargo build. The kernel-module build regenerates the
/// same file via the `all` rule in `crates/bedrock/Makefile`.
fn main() {
    let src = "../../contrib/gen_pebs_margin.rs";
    let generated = "src/exits/pebs_margin_generated.rs";

    let rustc = env::var("RUSTC").unwrap_or_else(|_| "rustc".into());
    let gen_bin = Path::new(&env::var("OUT_DIR").unwrap()).join("gen_pebs_margin");

    let status = Command::new(&rustc)
        .args(["-O", src, "-o"])
        .arg(&gen_bin)
        .status()
        .expect("failed to compile gen_pebs_margin.rs");
    assert!(status.success(), "rustc failed on gen_pebs_margin.rs");

    let status = Command::new(&gen_bin)
        .arg(generated)
        .status()
        .expect("failed to run gen_pebs_margin");
    assert!(status.success(), "gen_pebs_margin failed");

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed={src}");
}
