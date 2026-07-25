# Userland tools: bedrock-cli and bedrock-determinism
{ pkgs }:

let
  src = pkgs.lib.cleanSourceWith {
    src = ./..;
    # Only the Rust workspace affects these binaries. Exclude non-cargo dirs and
    # docs so unrelated repo churn -- e.g. run output saved under workloads/, a
    # rebuilt images.tar, or a README edit -- does not bump the input hash and
    # force a needless rebuild. Keep in sync with the workload-monitor filter in
    # podman-initrd.nix.
    filter = path: type:
      let baseName = builtins.baseNameOf path; in
      !(baseName == "target" ||
        baseName == ".git" ||
        baseName == ".claude" ||
        baseName == ".github" ||
        baseName == "nix" ||
        baseName == "workloads" ||
        baseName == "contrib" ||
        pkgs.lib.hasSuffix ".md" baseName ||
        # Exclude the kernel module crate (no Cargo.toml, breaks workspace)
        (type == "directory" && baseName == "bedrock" &&
         builtins.match ".*/crates/bedrock$" path != null));
  };
in
{
  bedrock-cli = pkgs.rustPlatform.buildRustPackage {
    pname = "bedrock-cli";
    version = "0.1.0";
    inherit src;
    cargoLock.lockFile = ../Cargo.lock;
    cargoBuildFlags = [ "-p" "bedrock-cli" ];
    meta.mainProgram = "bedrock-cli";
  };

  bedrock-determinism = pkgs.rustPlatform.buildRustPackage {
    pname = "bedrock-determinism";
    version = "0.1.0";
    inherit src;
    cargoLock.lockFile = ../Cargo.lock;
    cargoBuildFlags = [ "-p" "bedrock-determinism-tests" ];
    meta.mainProgram = "bedrock-determinism";
  };
}
