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
#   composeYaml  Path (or derivation) for the workload's compose file. Copied to
#                /workload/compose.yaml and `podman-compose up -d`'d at boot.
#   imagesTar    Path (or derivation) for a docker-archive tarball containing
#                every image referenced from composeYaml. Produce it with
#                `docker save img1 [img2 ...] -o images.tar` (multiple images in
#                one archive is fine — `podman load` reads the embedded manifest
#                to recover each one's name+tag). The compose file should use
#                `pull_policy: never` so podman doesn't try to fetch from a
#                registry.
#
# Anything workload-specific — helper binaries, driver scripts, configs — must
# be baked into one of the images. The initrd ships only the generic podman /
# journald / kernel-module infrastructure plus `bedrock-pebs-register`, which it
# runs at boot to enable precise EPT-friendly PEBS exits.
{ pkgs, guestKernel, composeYaml, imagesTar }:

let
  bedrockPebsRegister = pkgs.pkgsStatic.stdenv.mkDerivation {
    name = "bedrock-pebs-register";
    dontUnpack = true;
    # -I${../guest} puts the header-only libvmcall.h on the include path so
    # pebs-register.c's `#include "libvmcall.h"` resolves.
    buildPhase = "$CC -O2 -static -I${../guest} -o bedrock-pebs-register ${../guest/pebs-register.c}";
    installPhase = "mkdir -p $out/bin && cp bedrock-pebs-register $out/bin/";
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

    # Bind-mount the shared assertion sink into every container podman creates,
    # without touching any compose file. It is a single JSONL file appended to
    # by the host-side workload monitor and by workload code inside containers
    # (e.g. `eventually_` drivers). The source must exist (the initrd
    # pre-creates it) before a container starts, else podman bind-mounts an
    # auto-created path in its place.
    volumes = [
      "/bedrock/assertions.jsonl:/bedrock/assertions.jsonl",
    ]

    [engine]
    cgroup_manager = "cgroupfs"
    events_logger = "journald"
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

  initScript = pkgs.writeScript "init" ''
    #!/bin/sh
    export PATH=/usr/local/bin:/usr/bin:/bin:/usr/local/sbin:/usr/sbin:/sbin

    # Stage 1: Switch from initramfs to real tmpfs root (required for pivot_root in containers)
    if [ ! -f /switched_root ]; then
        mount -t proc proc /proc
        mount -t sysfs sysfs /sys
        mount -t devtmpfs devtmpfs /dev

        mkdir -p /newroot
        mount -t tmpfs -o size=90% tmpfs /newroot

        # Copy filesystem to new root
        cp -a /bin /newroot/ 2>/dev/null || true
        cp -a /sbin /newroot/ 2>/dev/null || true
        cp -a /lib /newroot/ 2>/dev/null || true
        cp -a /lib64 /newroot/ 2>/dev/null || true
        cp -a /usr /newroot/ 2>/dev/null || true
        cp -a /etc /newroot/ 2>/dev/null || true
        cp -a /var /newroot/ 2>/dev/null || true
        cp -a /nix /newroot/ 2>/dev/null || true
        cp -a /images /newroot/ 2>/dev/null || true
        cp -a /workload /newroot/ 2>/dev/null || true
        cp -a /init /newroot/

        mkdir -p /newroot/proc /newroot/sys /newroot/dev /newroot/run /newroot/tmp
        mkdir -p /newroot/dev/shm /newroot/dev/pts /newroot/sys/fs/cgroup
        mkdir -p /newroot/var/lib/containers

        touch /newroot/switched_root
        exec switch_root /newroot /init
    fi

    # Stage 2: Setup after switch_root
    mount -t proc proc /proc
    mount -t sysfs sysfs /sys
    mount -t devtmpfs devtmpfs /dev
    mount -t tmpfs tmpfs /run
    mount -t tmpfs tmpfs /tmp
    mkdir -p /dev/shm /dev/pts
    mount -t tmpfs -o mode=1777 tmpfs /dev/shm
    mount -t devpts devpts /dev/pts
    mount -t cgroup2 cgroup2 /sys/fs/cgroup

    # Create directories needed for containers and networking
    mkdir -p /run/netns /var/run/netns /run/containers/storage /var/lib/cni /var/tmp

    # Load the paravirtual batch console as early as possible so that
    # kernel printk output for the rest of boot is shipped one line per
    # VMCALL instead of one byte per VMX I/O exit through the emulated
    # 8250. The cmdline selects it with console=hvc0; earlyprintk=serial
    # covers the pre-registration window. Failure is non-fatal — the guest
    # keeps logging through earlyprintk/8250. Userspace stdout is sent to
    # /dev/ttyS0 below (the 8250 tty, unchanged), since this console is a
    # write-only printk console with no tty backing /dev/console.
    insmod /lib/modules/bedrock-console.ko || \
        echo "bedrock-console: insmod failed (continuing without batch console)"

    # Register a PEBS scratch page with the hypervisor so precise VM exits
    # (timer interrupt injection, stop-at-tsc) can trap on EPT writes. The
    # program registers, then blocks forever to keep the page pinned, so we
    # background it. Failure is expected outside bedrock; the workload runs
    # regardless.
    bedrock-pebs-register &

    # Load the deterministic I/O channel module. Must come after the
    # filesystem is in place (kernel_read_file_from_path needs /tmp on
    # tmpfs) but before podman-compose, since the I/O actions exec into
    # the containers that compose brings up. Failure is non-fatal in case
    # the module ABI is mismatched against the running kernel.
    insmod /lib/modules/bedrock-io.ko || \
        echo "bedrock-io: insmod failed (continuing without I/O channel)"

    # Reset podman state
    podman system reset -f 2>/dev/null || true

    # Redirect output to the console. /dev/console now routes to the
    # paravirtual batch console (hvc0): bedrock-console.ko registers a tty
    # whose .write batches whole buffers to the hypervisor in one VMCALL, and
    # the console's .device points /dev/console at it. So both kernel printk
    # and this userspace output go through hvc0, one VM exit per line instead
    # of one per byte through the emulated 8250.
    exec >/dev/console 2>&1

    echo "=== Podman Initrd ==="

    # Set up loopback
    ip link set lo up

    # Start systemd-journald standalone (no PID 1 systemd). conmon
    # connects to its socket directly when `log_driver = "journald"`
    # is set in containers.conf, so every container's stdout/stderr
    # lands in the journal as a structured record (CONTAINER_NAME,
    # MESSAGE, PRIORITY, …). bedrock-io's exec output is piped
    # through `systemd-cat -t bedrock-exec` for the same treatment.
    # The unified journal becomes the single source the formatter
    # below tails — no per-container follower bookkeeping, no
    # re-attach loops on stop/start.
    mkdir -p /run/systemd/journal /run/log/journal
    ${pkgs.systemd}/lib/systemd/systemd-journald &
    # Wait for the socket so the first podman/conmon connect doesn't
    # race the daemon's bind.
    while [ ! -S /run/systemd/journal/socket ]; do
        sleep 0.05
    done

    # Shared assertion sink: an append-only JSONL file. The host-side workload
    # monitor appends to it, and containers.conf bind-mounts it into every
    # container so workload code (e.g. `eventually_` drivers) can append too.
    # Create it as a regular file now — before the monitor starts and before
    # `podman-compose up` — so the per-container bind mounts attach to the file
    # rather than to an auto-created directory.
    mkdir -p /bedrock
    : > /bedrock/assertions.jsonl

    # Surface the assertion sink in the guest log: follow it and pipe each line
    # through `systemd-cat` into the journal under the `assertions` tag, so the
    # journalctl formatter below renders every assertion (host- or
    # container-written) as `[assertions] | …` on the serial console — where the
    # host-side oracle reads it. `-F` re-follows across truncation/recreation
    # and `-n +1` replays existing lines so nothing written before this is missed.
    tail -n +1 -F /bedrock/assertions.jsonl 2>/dev/null | systemd-cat -t assertions &

    # Start the workload monitor. It tails `podman events` and, on each container
    # or exec death, appends an exit-code assertion to /bedrock/assertions.jsonl
    # (surfaced as `[assertions]` by the tail above). It prints nothing to
    # stdout; only its error diagnostics reach the journal via `systemd-cat`,
    # rendered as `[workload-monitor]`.
    workload-monitor 2>&1 | systemd-cat -t workload-monitor &

    # Load all workload images from the single docker-archive tarball.
    # `podman load` reads the embedded manifest to recover each image's
    # original name+tag, so a compose file referencing those names works
    # unchanged.
    podman load -i /images/images.tar
    rm -f /images/images.tar
    echo "Loaded images:"
    podman images

    # Run workload detached. Container output and lifecycle events both
    # flow into journald (log_driver = journald, events_logger =
    # journald in containers.conf); bedrock-io's exec actions feed it
    # via systemd-cat. journalctl -f -o json then drains the unified
    # stream, and a small jq filter renders each record back to the
    # `[name] | message` human format with a deterministic per-source
    # color (sum of label bytes modulo the 31..36 palette). This
    # replaces the previous per-container follow-loop entirely — restart
    # resilience is now journald's problem, not ours.
    cd /workload
    podman-compose up -d

    journalctl -f -o json --no-tail | jq -r --unbuffered '
        ((.CONTAINER_NAME // .SYSLOG_IDENTIFIER) // "kernel") as $label |
        (($label | explode | add // 0) % 6 + 31) as $color |
        ((.MESSAGE // "") | rtrimstr("\n")) as $msg |
        "[\u001b[\($color)m\($label)\u001b[0m] | \($msg)"
    ' &

    # Block until the shutdown VMCALL terminates the VM.
    wait

    # Drop to an interactive shell on the 8250 serial tty. The hvc0 batch
    # console is output-only (no get_chars/input path), so the interactive
    # fallback shell uses /dev/ttyS0, which carries host-fed serial input.
    # This only runs in manual sessions — under the fuzzer/determinism
    # harness the VM is terminated by the shutdown VMCALL before here.
    exec setsid sh -c 'exec sh </dev/ttyS0 >/dev/ttyS0 2>&1'
  '';

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

    # Workload: one docker-archive tarball + one compose file. `podman load`
    # recovers image names from the manifest, so the file name here is opaque.
    cp ${imagesTar} rootfs/images/images.tar
    cp ${composeYaml} rootfs/workload/compose.yaml
    cp ${initScript} rootfs/init
    chmod +x rootfs/init
  '';

  installPhase = ''
    cd rootfs
    find . -print0 | cpio --null -o -H newc | gzip -9 > $out
  '';
}
