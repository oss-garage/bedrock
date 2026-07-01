# Podman-based guest initramfs for bedrock VMs.
#
# Built entirely from Nix packages — no proot, no apt, no fixed-output hash.
# The Nix store closure of all runtime dependencies is copied into the rootfs,
# with FHS symlinks so that podman, init, and containers all find their tools.
#
# Args:
#   guestKernel  Patched 6.18 guest kernel (see nix/guest-kernel.nix). Its `dev`
#                output is used to build the bedrock-io kernel module out-of-tree
#                against the exact same configuration the guest boots.
#
# This initrd is fully generic — it carries no workload. The workload's
# compose file and image tarball are downloaded at boot over the
# file-transmission hypercall (HYPERCALL_FILE_FETCH) by `bedrock-file-fetch`,
# served by the host (e.g. `bedrock-cli --file compose.yaml=… --file
# images.tar=…`, or via the lab's `LabOpts.files`). The compose file should use
# `pull_policy: never` so podman doesn't try to fetch from a registry; produce
# the image tarball with `docker save img1 [img2 ...] -o images.tar` (multiple
# images in one archive is fine — `podman load` reads the embedded manifest to
# recover each one's name+tag).
#
# Anything else workload-specific — helper binaries, driver scripts, configs —
# must be baked into one of the images. The initrd ships only the generic podman
# / journald / kernel-module infrastructure plus `bedrock-pebs-register` (run at
# boot to enable precise EPT-friendly PEBS exits) and `bedrock-file-fetch` (run
# at boot to download the workload files).
{ pkgs, guestKernel }:

let
  bedrockPebsRegister = pkgs.pkgsStatic.stdenv.mkDerivation {
    name = "bedrock-pebs-register";
    dontUnpack = true;
    # -I${../guest} puts the header-only libvmcall.h on the include path so
    # pebs-register.c's `#include "libvmcall.h"` resolves.
    buildPhase = "$CC -O2 -static -I${../guest} -o bedrock-pebs-register ${../guest/pebs-register.c}";
    installPhase = "mkdir -p $out/bin && cp bedrock-pebs-register $out/bin/";
  };

  # Guest-side file downloader. Pulls the workload's compose.yaml / images.tar
  # from the host at boot over the file-transmission hypercall. Built the same
  # way as bedrock-pebs-register (static, header-only libvmcall.h on the include
  # path).
  bedrockFileFetch = pkgs.pkgsStatic.stdenv.mkDerivation {
    name = "bedrock-file-fetch";
    dontUnpack = true;
    buildPhase = "$CC -O2 -static -I${../guest} -o bedrock-file-fetch ${../guest/file-fetch.c}";
    installPhase = "mkdir -p $out/bin && cp bedrock-file-fetch $out/bin/";
  };

  # Guest-side file sender that chunks files from the guest to the host.
  bedrockFileStore = pkgs.pkgsStatic.stdenv.mkDerivation {
    name = "bedrock-file-store";
    dontUnpack = true;
    buildPhase = "$CC -O2 -static -I${../guest} -o bedrock-file-store ${../guest/file-store.c}";
    installPhase = "mkdir -p $out/bin && cp bedrock-file-store $out/bin/";
  };

  # Guest kernel module that drives the deterministic I/O channel. Built
  # against the patched 6.18 guest kernel's headers so its kbuild
  # configuration (LLVM=1, no CONFIG_RUST, etc.) matches what the running
  # guest expects. The module owns one 4KB shared page, registers it with
  # the hypervisor via VMCALL, and request_irq's IO_CHANNEL_IRQ (pin 9)
  # so it can receive host-queued actions.
  #
  # Mirrors `nix/module.nix`'s setup for the host module: use
  # `llvmPackages.stdenv` (the kernel was built LLVM=1; OOT modules must
  # match), suppress the cc-wrapper's
  # -Werror=unused-command-line-argument (kbuild passes -nostdlibinc which
  # is unused in some contexts), and skip strip / patchelf so the .ko
  # stays valid.
  bedrockIoModule = let
    llvmPackages = pkgs.llvmPackages;
  in llvmPackages.stdenv.mkDerivation {
    name = "bedrock-io-module";
    src = ../guest/bedrock-io;

    nativeBuildInputs = [
      llvmPackages.lld
      pkgs.gnumake
    ];

    dontStrip = true;
    dontPatchELF = true;

    NIX_CFLAGS_COMPILE = "-Wno-unused-command-line-argument";

    # The module shares the guest-side hypercall library. It is header-only
    # (static inline), so copying libvmcall.h into the build dir is enough for
    # `#include "libvmcall.h"` to resolve — no extra object to link.
    preBuild = "cp ${../guest/libvmcall.h} ./libvmcall.h";

    buildPhase = ''
      runHook preBuild
      make \
        KDIR=${guestKernel.dev}/lib/modules/${guestKernel.modDirVersion}/build \
        LLVM=1
      runHook postBuild
    '';

    installPhase = ''
      runHook preInstall
      mkdir -p $out
      cp bedrock-io.ko $out/
      runHook postInstall
    '';
  };

  # Guest module for the paravirtual batch console. Built out-of-tree the same
  # way as bedrockIoModule (LLVM=1 against the guest kernel build tree). Its
  # `struct console` ships whole printk records to the hypervisor in one VMCALL
  # each instead of one VMX I/O exit per byte through the emulated 8250.
  bedrockConsoleModule = let
    llvmPackages = pkgs.llvmPackages;
  in llvmPackages.stdenv.mkDerivation {
    name = "bedrock-console-module";
    src = ../guest/bedrock-console;

    nativeBuildInputs = [
      llvmPackages.lld
      pkgs.gnumake
    ];

    dontStrip = true;
    dontPatchELF = true;

    NIX_CFLAGS_COMPILE = "-Wno-unused-command-line-argument";

    # Shares the header-only guest hypercall library; see bedrockIoModule.
    preBuild = "cp ${../guest/libvmcall.h} ./libvmcall.h";

    buildPhase = ''
      runHook preBuild
      make \
        KDIR=${guestKernel.dev}/lib/modules/${guestKernel.modDirVersion}/build \
        LLVM=1
      runHook postBuild
    '';

    installPhase = ''
      runHook preInstall
      mkdir -p $out
      cp bedrock-console.ko $out/
      runHook postInstall
    '';
  };

  # Workload monitor (Rust). Tails `podman events` and records an exit-code
  # assertion to /bedrock/assertions.jsonl on each container/exec death; it does
  # not write to the guest log. Built as a static musl binary so it is
  # self-contained in the rootfs; it has no native deps, so no extra
  # buildInputs / pkg-config are needed. `-p workload-monitor` builds only that
  # crate's dependency tree (bedrock-assertions + serde), not the vmx/kernel
  # crates.
  workloadMonitor = pkgs.pkgsStatic.rustPlatform.buildRustPackage {
    pname = "workload-monitor";
    version = "0.1.0";
    src = pkgs.lib.cleanSourceWith {
      src = ./..;
      filter = path: type:
        let baseName = builtins.baseNameOf path; in
        !(baseName == "target" ||
          baseName == ".git" ||
          baseName == ".claude" ||
          baseName == "nix" ||
          (type == "directory" && baseName == "bedrock" &&
           builtins.match ".*/crates/bedrock$" path != null));
    };
    cargoLock.lockFile = ../Cargo.lock;
    cargoBuildFlags = [ "-p" "workload-monitor" ];
    doCheck = false;
    meta.mainProgram = "workload-monitor";
  };

  # All runtime packages needed in the guest rootfs
  runtimePackages = [
    pkgs.podman
    pkgs.conmon
    pkgs.crun
    pkgs.skopeo
    pkgs.netavark
    pkgs.aardvark-dns
    pkgs.slirp4netns
    pkgs.iproute2
    pkgs.iptables
    pkgs.procps
    pkgs.util-linux    # switch_root, mount, setsid, nsenter
    pkgs.kmod          # insmod (for loading bedrock-io.ko)
    pkgs.bashInteractive
    pkgs.coreutils
    pkgs.gnugrep
    pkgs.gnused
    pkgs.gawk
    pkgs.findutils
    pkgs.gnutar
    pkgs.gzip
    pkgs.jq
    pkgs.cacert
    pkgs.podman-compose
    # systemd-journald + journalctl + systemd-cat: structured log
    # capture for both container output (`--log-driver=journald` makes
    # conmon connect to the journal socket directly) and bedrock-io
    # exec output (piped through `systemd-cat` with a tag). Run
    # standalone — no PID 1 systemd — so we only consume the daemon
    # itself, not the full unit-management surface.
    pkgs.systemd
    bedrockPebsRegister
    bedrockFileFetch
    bedrockFileStore
  ];

  # Merged environment — creates a single store path with bin/, sbin/, etc.
  # containing symlinks to all packages above.
  runtimeEnv = pkgs.buildEnv {
    name = "bedrock-podman-env";
    paths = runtimePackages;
    pathsToLink = [ "/bin" "/sbin" "/lib" "/libexec" "/share" "/etc" ];
    # iproute2 and cni-plugins both provide a "bridge" binary
    ignoreCollisions = true;
  };

  closureInfo = pkgs.closureInfo { rootPaths = [ runtimeEnv ]; };

  # Containers.conf with absolute Nix store paths so podman finds its helpers
  # regardless of PATH or wrapper behaviour.
  containersConf = pkgs.writeText "containers.conf" ''
    [containers]
    # No global netns override — each container gets its own netns and
    # joins netavark's default bridge network. Per-container settings in
    # compose still take precedence if a workload needs `network_mode:
    # host` for a specific service.
    log_driver = "journald"

    # Bind-mount shared host-namespace paths into every container podman
    # creates, without touching any compose file:
    #   - the assertion sink (a single JSONL file appended to by the host-side
    #     workload monitor and by workload code inside containers, e.g.
    #     `eventually_` drivers); and
    #   - the coverage dir, where each instrumented process keeps its feedback
    #     bitmap as a file (see guest/libfeedback.c), so the pages outlive the
    #     container that produced them.
    # Each source must exist (the initrd pre-creates them) before a container
    # starts, else podman bind-mounts an auto-created path in its place.
    volumes = [
      "/bedrock/assertions.jsonl:/bedrock/assertions.jsonl",
      "/bedrock/coverage:/bedrock/coverage",
    ]

    [engine]
    cgroup_manager = "cgroupfs"
    runtime = "crun"

    [engine.runtimes]
    crun = ["${pkgs.crun}/bin/crun"]

    helper_binaries_dir = ["${pkgs.conmon}/bin", "${pkgs.netavark}/bin", "${pkgs.aardvark-dns}/bin"]

    [network]
    network_backend = "netavark"
    default_network = "bridge"
  '';

  # vfs driver works on any filesystem (including tmpfs/initrd); storage and
  # run dirs live under the conventional podman paths.
  storageConf = pkgs.writeText "storage.conf" ''
    [storage]
    driver = "vfs"
    graphroot = "/var/lib/containers/storage"
    runroot = "/run/containers/storage"
  '';

  # journald config: keep storage in /run (memory-only — we don't want
  # /var/log/journal persistence, which would grow the rootfs across a
  # long-running VM), and disable rate limiting so the daemon never
  # decides to drop log lines based on wall-clock thresholds — the
  # determinism contract requires every log line we'd otherwise see to
  # actually reach the journal.
  journaldConf = pkgs.writeText "journald.conf" ''
    [Journal]
    Storage=volatile
    RateLimitBurst=0
    RateLimitIntervalSec=0
    ForwardToSyslog=no
    ForwardToKMsg=no
    ForwardToConsole=no
    ForwardToWall=no
  '';

  # Guest init script. Kept as a standalone shell file at guest/init (rather
  # than inlined here) so it can be read, linted, and edited as a real script.
  # Its one build-time dependency is the systemd store path, used for the
  # standalone journald binary; replaceVars substitutes it into the
  # `@systemd@` placeholder.
  initScript = pkgs.replaceVars ../guest/init {
    systemd = pkgs.systemd;
  };

in
pkgs.stdenv.mkDerivation {
  name = "bedrock-podman-rootfs";

  nativeBuildInputs = [ pkgs.cpio pkgs.gzip ];

  dontUnpack = true;

  buildPhase = ''
    mkdir -p rootfs/{proc,sys,dev,tmp,run,images,workload,var/tmp}
    mkdir -p rootfs/{bin,sbin,usr/bin,usr/sbin,usr/local/bin}
    mkdir -p rootfs/nix/store
    mkdir -p rootfs/etc/{containers,ssl/certs}
    mkdir -p rootfs/var/lib/containers

    # Copy entire Nix store closure into the rootfs
    while IFS= read -r path; do
      cp -a "$path" rootfs"$path"
    done < ${closureInfo}/store-paths

    # FHS symlinks: make all env binaries available at standard paths
    for bin in ${runtimeEnv}/bin/*; do
      name=$(basename "$bin")
      ln -sf ${runtimeEnv}/bin/"$name" rootfs/usr/bin/"$name"
    done

    if [ -d "${runtimeEnv}/sbin" ]; then
      for bin in ${runtimeEnv}/sbin/*; do
        name=$(basename "$bin")
        ln -sf ${runtimeEnv}/sbin/"$name" rootfs/usr/sbin/"$name"
      done
    fi

    # Shell at /bin/sh and /bin/bash (needed by init shebang and containers)
    ln -sf ${runtimeEnv}/bin/bash rootfs/bin/sh
    ln -sf ${runtimeEnv}/bin/bash rootfs/bin/bash

    # bedrock-pebs-register at /usr/local/bin/ so the init script finds it
    # on PATH. Other bedrock helpers (shutdown, miner, etc.) are workload
    # concerns — workloads bake them into their own container images.
    ln -sf ${bedrockPebsRegister}/bin/bedrock-pebs-register rootfs/usr/local/bin/bedrock-pebs-register

    # bedrock-file-fetch at /usr/local/bin/ so the init script finds it on PATH.
    # It downloads the workload's compose.yaml / images.tar from the host at boot.
    ln -sf ${bedrockFileFetch}/bin/bedrock-file-fetch rootfs/usr/local/bin/bedrock-file-fetch

    # bedrock-file-store at /usr/local/bin/.
    ln -sf ${bedrockFileStore}/bin/bedrock-file-store rootfs/usr/local/bin/bedrock-file-store

    # workload-monitor: watches podman container/exec lifecycle events and
    # records exit-code assertions to /bedrock/assertions.jsonl. Lives on the
    # guest rootfs (not inside any container image) so it observes every
    # container from the host namespace.
    install -m 0755 ${workloadMonitor}/bin/workload-monitor \
        rootfs/usr/local/bin/workload-monitor

    # Guest kernel module for the deterministic I/O channel. Placed at a
    # stable path so the init script can insmod it without depending on
    # modules.dep / depmod machinery (which we don't build in this initrd).
    mkdir -p rootfs/lib/modules
    cp ${bedrockIoModule}/bedrock-io.ko rootfs/lib/modules/bedrock-io.ko
    cp ${bedrockConsoleModule}/bedrock-console.ko rootfs/lib/modules/bedrock-console.ko

    # SSL certificates
    mkdir -p rootfs/etc/ssl/certs
    ln -sf ${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt rootfs/etc/ssl/certs/ca-certificates.crt
    ln -sf ${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt rootfs/etc/ssl/certs/ca-bundle.crt

    # Podman configuration
    cp ${containersConf} rootfs/etc/containers/containers.conf
    cp ${storageConf} rootfs/etc/containers/storage.conf

    # journald configuration (volatile storage, no rate limiting, no
    # forwarding to ttys — journalctl is the only consumer).
    mkdir -p rootfs/etc/systemd
    cp ${journaldConf} rootfs/etc/systemd/journald.conf

    # Fixed /etc/machine-id so the journal's per-boot identifiers are
    # deterministic across runs. The value is arbitrary — journald
    # uses it as an opaque key — but it must be 32 hex chars.
    echo '00000000000000000000000000000001' > rootfs/etc/machine-id

    # Container image trust policy (required by podman for any image operation)
    cat > rootfs/etc/containers/policy.json << 'POLICY'
    {"default": [{"type": "insecureAcceptAnything"}]}
    POLICY

    # Minimal /etc files needed for podman
    echo 'root:x:0:0:root:/root:/bin/sh' > rootfs/etc/passwd
    echo 'root:x:0:' > rootfs/etc/group

    # Stub /etc/resolv.conf so aardvark-dns can open it (it's fatal if
    # the file doesn't exist, even when no upstream forwarding is
    # needed). The guest has no external network — container names are
    # resolved by aardvark directly off the netavark bridge.
    cat > rootfs/etc/resolv.conf << 'RESOLV'
    # bedrock guest: aardvark-dns serves container-name lookups locally;
    # there are no upstream nameservers.
    RESOLV

    # Workload files (compose.yaml / images.tar) are downloaded from the host at
    # boot by the init script via bedrock-file-fetch. The /images and /workload
    # directories are pre-created above so the downloads have somewhere to land.
    cp ${initScript} rootfs/init
    chmod +x rootfs/init
  '';

  installPhase = ''
    cd rootfs
    find . -print0 | cpio --null -o -H newc | gzip -9 > $out
  '';
}
