# Nix Build System

Nix flake for building and testing the bedrock hypervisor with nested KVM.

## Quick Start

```bash
nix run .#vm                    # Boot interactive dev VM (SSH on port 2222)
nix run .#test-vm               # NixOS-VM smoke test (nested virt)
nix run .#test-bitcoin-workload # Boot the trivial + bitcoin guests on the host
nix run .#integration-tests     # bedrock-lab integration suite (set BEDROCK_INITRAMFS)
```

## Packages

| Package | Description |
|---------|-------------|
| `kernel` | Linux 6.18 with `CONFIG_RUST=y` (no KVM) |
| `bedrockModule` | `bedrock.ko` kernel module |
| `guestKernel` | Linux 6.18 with determinism patches (TLB flush) + `vmlinux` |
| `guestInitrd` | Trivial initramfs (boots, VMCALL shutdown) |
| `podmanInitrd` | Generic podman initramfs (downloads its workload at boot) |
| `bedrock-cli` | CLI for loading and running guest VMs |
| `bedrock-determinism` | Determinism checker (multi-run comparison) |

There is one generic podman initrd, exposed both as the `podmanInitrd` package
and under `lib.<system>`. It serves every workload: the guest downloads its
`compose.yaml` and `images.tar` from the host at boot over the
file-transmission hypercall (`HYPERCALL_FILE_FETCH`). The host serves them at
runtime, so a workload is launched by handing those two files to bedrock-cli:

```sh
bedrock-cli -m 5120 -i <podmanInitrd> \
  --file compose.yaml=./compose.yaml \
  --file images.tar=./images.tar \
  <vmlinux>
```

or, from the lab/fuzzers, via `LabOpts.files`. Build any package with
`nix build .#<name>`.

## Host Requirements

### Nix Configuration (`/etc/nix/nix.conf`)

```
experimental-features = nix-command flakes
sandbox = relaxed
extra-sandbox-paths = /dev/kvm?
```

- **`nix-command flakes`**: Required for `nix build`, `nix run`, etc.
- **`sandbox = relaxed`**: Needed if any of your workload's image builds use
  `dockerTools.pullImage` or other fixed-output derivations that pull from a
  network. With `sandbox = true`, all network is blocked. `relaxed` allows
  FODs to access the network while keeping other builds sandboxed. The
  initrd builder itself does not need network access — it only consumes the
  `images.tar` you supply.
- **`extra-sandbox-paths = /dev/kvm?`**: Exposes KVM to the build sandbox for
  `nix run .#test-vm` (the only build that uses it). The trailing `?` makes the
  mount optional — required because bedrock owns VMX, so `/dev/kvm` is absent
  whenever the module is loaded, and without it every sandboxed build fails to
  set up.

Restart the daemon after changes: `systemctl restart nix-daemon`

### For `nix run .#test-vm` (NixOS VM tests)

- KVM-capable host with nested VMX support
- KVM modules loaded (`kvm`, `kvm_intel`) -- bedrock must NOT be loaded
  (it owns VMX exclusively; unload with `rmmod bedrock` first)

### For `nix run .#test-bitcoin-workload` and `nix run .#integration-tests` (host tests)

- Host kernel 6.18 with bedrock module loaded
- `/dev/bedrock` device present
- KVM must NOT be loaded (bedrock owns VMX)
- The workload's `images.tar` built on disk (`./workloads/<name>/build.sh`). The
  guest downloads it and `compose.yaml` at boot; both apps read them from the
  on-disk `workloads/<name>/` files at runtime, so no git staging is needed. Run
  these apps from the repo root. `.#integration-tests` serves them via
  `BEDROCK_COMPOSE` / `BEDROCK_IMAGES` and boots the generic `podmanInitrd`
  (override any of `BEDROCK_VMLINUX` / `BEDROCK_INITRAMFS` / `BEDROCK_COMPOSE` /
  `BEDROCK_IMAGES` to point elsewhere).

### For `nix run .#vm` (interactive dev VM)

- Same as `nix run .#test-vm` requirements
- SSH into the VM: `ssh -p 2222 dev@localhost` (password: `dev`)
- Root password: `root`

## Toolchain

The flake pins:

- **Rust 1.94.0** via `rust-overlay` (matches kernel.org recommendation for 6.18)
- **LLVM** from nixpkgs default (currently 21; clang, libclang, bindgen all match)
- **Linux 6.18** source from `github:torvalds/linux/v6.18`

## CI

The `nix.yml` workflow runs `nix run .#test-bitcoin-workload` (the "Run bitcoin
workload" job) and `nix run .#integration-tests` (the "Integration tests" job)
on self-hosted nested-virt runners. The runners need the same host requirements
listed above.

## Podman Initrd

The podman initrd is built entirely from nixpkgs packages (podman, crun,
netavark, journald, etc.). The Nix store closure is copied into the rootfs
with FHS symlinks so the init script and containers find their tools. The
only bedrock-specific bits the initrd ships are `bedrock-pebs-register`
(run at boot to enable precise EPT-friendly PEBS exits), `bedrock-file-fetch`
(run at boot to download the workload files — see below), and the
`bedrock-io.ko` kernel module (the deterministic I/O channel).

The initrd is generic, common to every workload. At boot, `bedrock-file-fetch`
downloads the workload's `compose.yaml` and `images.tar` from the host over the
file-transmission hypercall (`HYPERCALL_FILE_FETCH`): it registers a 1 MB
feedback buffer as the transport and pulls each file in chunks, the host
serving the bytes directly into that buffer. Anything else workload-specific
(helper binaries, driver scripts, configs) gets baked into one of the images.
Produce `images.tar` with whatever toolchain you like (`docker build` +
`docker save` outside Nix, or `dockerTools.buildLayeredImage` inside Nix).

### Workloads

Workloads live in `workloads/<name>/` (a `compose.yaml` plus a built
`images.tar`). There is one generic `podmanInitrd` for all of them; the
workload's two files are handed to the guest at runtime. Build a workload's
image tarball with:

```bash
just build-workload bitcoin    # builds images.tar, prints the generic initrd path
```

`build-workload` runs the workload's `build.sh` and builds the generic
`podmanInitrd`, printing its path. To boot the workload, pass its files to
bedrock-cli with `--file compose.yaml=… --file images.tar=…` (see the recipe's
comment); the files are read from disk at runtime, so the gitignored
`images.tar` needs no staging.

For the bitcoin workload specifically, `build.sh` does `docker pull` +
two `docker build`s (a miner image FROM `bitcoin/bitcoin:latest` with
`bedrock-miner` baked in, and an alpine image with `bedrock-shutdown`
baked in), then `docker save`s all three images into one archive. See
`workloads/bitcoin/build.sh` and the per-image `Dockerfile`s.

CI (`.github/workflows/nix.yml`) just runs `build.sh` before invoking the
test/workload app, which reads the on-disk files at runtime.
