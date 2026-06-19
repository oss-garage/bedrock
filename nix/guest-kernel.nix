# Guest kernel for running under the bedrock hypervisor.
#
# Same Linux 6.18 base as the host kernel, but with determinism patches applied
# (TLB flush fixes for VPID, and sourcing userspace randomness from a VMCALL).
# No CONFIG_RUST needed.
{ pkgs
, linux-src
}:

let
  version = "6.18.0";
  modDirVersion = "6.18.0";

  llvmPackages = pkgs.llvmPackages;

  # Patch the kernel source with guest determinism patches
  patchedSrc = pkgs.applyPatches {
    name = "linux-6.18-guest-patched";
    src = linux-src;
    patches = [
      ../guest/patches/0001-x86-mm-force-tlb-flush-on-pte-flag-change.patch
      ../guest/patches/0002-x86-mm-make-flush_tlb_fix_spurious_fault-flush.patch
      ../guest/patches/0003-x86-mm-force-tlb-flush-on-pmd-flag-change.patch
      # Source /dev/urandom, /dev/random and getrandom() from HYPERCALL_GET_RANDOM
      # (RAX=11) so guest userspace randomness is fuzzer-controlled and recorded.
      ../guest/patches/0004-random-source-urandom-getrandom-from-vmcall.patch
    ];
  };

  # Generate guest kernel config (no Rust, no KVM, minimal for guest use)
  configfile = pkgs.runCommand "linux-6.18-guest-config" {
    nativeBuildInputs = [
      llvmPackages.clang
      llvmPackages.llvm
      llvmPackages.lld
      pkgs.python3
      pkgs.gnumake
      pkgs.flex
      pkgs.bison
      pkgs.bc
      pkgs.perl
      pkgs.elfutils
      pkgs.openssl
    ];
  } ''
    cp -r ${patchedSrc} src
    chmod -R u+w src
    cd src

    patchShebangs scripts/

    make LLVM=1 ARCH=x86 defconfig

    # No Rust needed for guest kernel
    ./scripts/config --disable RUST

    # No KVM -- this kernel runs under bedrock
    ./scripts/config --disable KVM
    ./scripts/config --disable KVM_INTEL

    # Don't treat warnings as errors
    ./scripts/config --disable WERROR

    # Module support
    ./scripts/config --enable MODULES
    ./scripts/config --enable MODULE_UNLOAD

    # Networking (for guest workloads)
    ./scripts/config --enable NET
    ./scripts/config --enable INET
    ./scripts/config --enable NETDEVICES

    # Serial console (bedrock uses serial for guest output)
    ./scripts/config --enable SERIAL_8250
    ./scripts/config --enable SERIAL_8250_CONSOLE
    # Use COM1's hardwired IRQ 4 instead of auto-probing it. With
    # DETECT_IRQ set (the x86 default), STD_COMX_FLAGS gains UPF_AUTO_IRQ,
    # so the 8250 driver runs autoconfig_irq() — which writes a lone 0xFF to
    # the transmit register to provoke an IRQ. bedrock faithfully captures
    # that byte as console output, where it surfaces as a stray U+FFFD on the
    # serial log. bedrock already routes COM1 on IRQ 4 (see boot/mptable.rs),
    # so the probe is pointless; disabling it removes the spurious transmit.
    ./scripts/config --disable SERIAL_8250_DETECT_IRQ

    # Filesystems
    ./scripts/config --enable EXT4_FS
    ./scripts/config --enable TMPFS
    ./scripts/config --enable PROC_FS
    ./scripts/config --enable SYSFS

    # Initramfs support
    ./scripts/config --enable BLK_DEV_INITRD

    # Container support (needed by podman/crun)
    ./scripts/config --enable CGROUPS
    ./scripts/config --enable CGROUP_CPUACCT
    ./scripts/config --enable CGROUP_DEVICE
    ./scripts/config --enable CGROUP_FREEZER
    ./scripts/config --enable CGROUP_PIDS
    ./scripts/config --enable CGROUP_SCHED
    ./scripts/config --enable MEMCG
    ./scripts/config --enable NAMESPACES
    ./scripts/config --enable USER_NS
    ./scripts/config --enable PID_NS
    ./scripts/config --enable NET_NS
    ./scripts/config --enable IPC_NS
    ./scripts/config --enable UTS_NS
    ./scripts/config --enable DEVPTS_FS
    ./scripts/config --enable OVERLAY_FS
    ./scripts/config --enable VETH
    ./scripts/config --enable BRIDGE
    ./scripts/config --enable NETFILTER
    ./scripts/config --enable NETFILTER_ADVANCED
    ./scripts/config --enable NETFILTER_XTABLES
    ./scripts/config --enable NETFILTER_XT_MARK
    ./scripts/config --enable NETFILTER_XT_NAT
    ./scripts/config --enable NETFILTER_XT_MATCH_ADDRTYPE
    ./scripts/config --enable NETFILTER_XT_MATCH_COMMENT
    ./scripts/config --enable NETFILTER_XT_MATCH_CONNTRACK
    ./scripts/config --enable NETFILTER_XT_MATCH_MULTIPORT
    ./scripts/config --enable NETFILTER_XT_TARGET_MASQUERADE
    ./scripts/config --enable NF_CONNTRACK
    ./scripts/config --enable NF_NAT
    ./scripts/config --enable IP_NF_IPTABLES
    ./scripts/config --enable IP_NF_FILTER
    ./scripts/config --enable IP_NF_NAT
    # nftables backend — needed by modern iptables-nft (the default in
    # current nixpkgs) for netavark's NAT rules.
    ./scripts/config --enable NF_TABLES
    ./scripts/config --enable NF_TABLES_INET
    ./scripts/config --enable NF_TABLES_IPV4
    # iptables-over-nftables compat shim — netavark's default firewall
    # driver shells out to `iptables` (which is iptables-nft in current
    # nixpkgs), and iptables-nft needs NFT_COMPAT to translate some
    # extension targets (e.g. MASQUERADE) into nft expressions.
    ./scripts/config --enable NFT_COMPAT
    ./scripts/config --enable NFT_COUNTER
    ./scripts/config --enable NFT_NAT
    ./scripts/config --enable NFT_MASQ
    ./scripts/config --enable NFT_CHAIN_NAT
    ./scripts/config --enable NFT_REJECT
    ./scripts/config --enable NF_NAT_MASQUERADE
    ./scripts/config --enable NF_REJECT_IPV4
    ./scripts/config --enable BPF
    ./scripts/config --enable BPF_SYSCALL
    ./scripts/config --enable CGROUP_BPF

    # Disable unnecessary features
    ./scripts/config --disable SOUND
    ./scripts/config --disable DRM
    ./scripts/config --disable USB
    ./scripts/config --disable WIRELESS
    ./scripts/config --disable WLAN
    ./scripts/config --disable BLUETOOTH

    make LLVM=1 ARCH=x86 olddefconfig

    cp .config $out
  '';

  base = (pkgs.linuxManualConfig {
    inherit version modDirVersion configfile;
    src = patchedSrc;
    allowImportFromDerivation = true;
  }).override {
    stdenv = llvmPackages.stdenv;
  };

in
base.overrideAttrs (old: {
  postPatch = (old.postPatch or "") + ''
    sed -i '2iLLVM=1' Makefile
  '';

  # Install vmlinux ELF (bedrock-cli needs it, not just bzImage)
  postInstall = (old.postInstall or "") + ''
    cp $buildRoot/vmlinux $out/
  '';
})
