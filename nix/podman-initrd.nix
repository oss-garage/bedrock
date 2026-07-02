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

  # Manual-registration helper: thread-fuzz <cmd> switches itself to SCHED_EXT
  # and execs the command, so the command and its descendants are governed by
  # the fuzzing scheduler while everything else stays on the stock scheduler. It
  # runs inside the workload container (wrapping the process to fuzz), so it is
  # bind-mounted into every container via containers.conf below rather than baked
  # into any image. Built static (like the other guest helpers) so the single
  # binary can be bind-mounted with no library closure to carry along.
  threadFuzz = pkgs.pkgsStatic.stdenv.mkDerivation {
    name = "thread-fuzz";
    dontUnpack = true;
    buildPhase = "$CC -O2 -static -o thread-fuzz ${../guest/scx-fuzz/thread-fuzz.c}";
    installPhase = "mkdir -p $out/bin && cp thread-fuzz $out/bin/";
  };

  # scx headers (sched_ext BPF headers + bundled vmlinux.h for CO-RE). Pinned to
  # the same commit the workload image used to vendor, whose kfunc ABI matches
  # the bedrock guest kernel (6.18). This is the commit tag v1.0.18 points to.
  scxSrc = pkgs.fetchFromGitHub {
    owner = "sched-ext";
    repo = "scx";
    rev = "5bff813ccc5e56d0dd628632e4ca355305e77d94";
    hash = "sha256-RkTY7gDcKbkNUKl7NJDX3Ac/I+dRG1Gj8rRHynbbxUU=";
  };

  # The in-kernel concurrency-fuzz scheduler and its guest-side init service.
  # Lives in the generic initrd (not in any workload image): the scheduler is a
  # generic guest capability loaded once at boot, so it belongs to the guest,
  # not to the workload.
  #
  # scx-init links libbpf dynamically (static libbpf needs static elfutils,
  # which nixpkgs refuses to build); its runtime closure is pulled into the
  # rootfs via closureInfo below, like the rest of the dynamically-linked guest
  # userland (podman, crun, systemd).
  #
  # The BPF object is compiled CO-RE (-g for BTF); CO-RE relocations resolve at
  # load time against the guest kernel's /sys/kernel/btf/vmlinux, so scx's
  # bundled vmlinux.h need not match the guest exactly.
  scxFuzz = pkgs.stdenv.mkDerivation {
    name = "scx-fuzz";
    src = ../guest/scx-fuzz;

    nativeBuildInputs = [ pkgs.clang pkgs.bpftools pkgs.pkg-config ];
    buildInputs = [ pkgs.libbpf pkgs.elfutils pkgs.zlib ];

    # The nix cc-wrapper injects x86_64 hardening flags (-fstack-protector,
    # -fzero-call-used-regs) that the bpf target rejects. Disable hardening for
    # the whole derivation; the host helpers don't need it either. We keep the
    # wrapped clang (not clang-unwrapped) so libc / kernel-uapi / libbpf headers
    # are still on the include path via NIX_CFLAGS.
    hardeningDisable = [ "all" ];

    buildPhase = ''
      runHook preBuild

      # Compile the sched_ext BPF object. Include flags mirror scx's own
      # bpf_includes (meson.build): the bundled vmlinux.h lives under
      # scheds/vmlinux (+ a per-arch copy), not under scheds/include.
      clang -g -O2 -target bpf -D__TARGET_ARCH_x86 \
        -I${pkgs.lib.getDev pkgs.libbpf}/include \
        -I${scxSrc}/scheds/include \
        -I${scxSrc}/scheds/include/bpf-compat \
        -I${scxSrc}/scheds/include/lib \
        -I${scxSrc}/scheds/vmlinux \
        -I${scxSrc}/scheds/vmlinux/arch/x86 \
        -Ibpf \
        -c bpf/main.bpf.c -o main.bpf.o

      # Generate the libbpf skeleton the init service includes.
      bpftool gen skeleton main.bpf.o name fuzz_bpf > fuzz_bpf.skel.h

      # Init service, dynamically linked against libbpf.
      $CC -O2 -Ibpf -I. -o scx-init scx-init.c \
        $(pkg-config --cflags --libs libbpf)

      runHook postBuild
    '';

    installPhase = ''
      mkdir -p $out/bin
      cp scx-init $out/bin/
    '';
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

  # scxFuzz is added explicitly so its runtime closure (libbpf, elfutils, zlib,
  # glibc) is copied into the rootfs: scx-init is dynamically linked and
  # referenced by store path, not via runtimeEnv. threadFuzz is added so its
  # store path (bind-mounted into containers by containers.conf below) lands in
  # the rootfs too.
  closureInfo = pkgs.closureInfo { rootPaths = [ runtimeEnv scxFuzz threadFuzz ]; };

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
    #     container that produced them; and
    #   - thread-fuzz, the manual-registration helper (read-only): a workload
    #     opts a process into the fuzzing scheduler by wrapping it, e.g.
    #     `thread-fuzz /usr/local/bin/queue`. Mounting it here (from the guest
    #     store path) makes it available in every container with no per-image
    #     build; it does nothing unless a workload actually invokes it.
    # Each source must exist (the initrd pre-creates them, and the store path is
    # in the rootfs) before a container starts, else podman bind-mounts an
    # auto-created path in its place.
    volumes = [
      "/bedrock/assertions.jsonl:/bedrock/assertions.jsonl",
      "/bedrock/coverage:/bedrock/coverage",
      "${threadFuzz}/bin/thread-fuzz:/usr/local/bin/thread-fuzz:ro",
    ]

    [engine]
    cgroup_manager = "cgroupfs"
    # Stock crun. The fuzzing scheduler is opt-in per workload: a container's
    # command wraps the process to fuzz in thread-fuzz (bind-mounted above),
    # which switches that process into SCHED_EXT so scx-init's scheduler governs
    # it while everything else stays on the stock scheduler.
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

    # scx-init at /usr/local/bin/ so the init script can start the in-kernel
    # fuzzing scheduler at boot. thread-fuzz needs no rootfs symlink: it runs
    # inside containers and is bind-mounted there by store path (containers.conf).
    ln -sf ${scxFuzz}/bin/scx-init rootfs/usr/local/bin/scx-init

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
