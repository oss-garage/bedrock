# NixOS integration tests for bedrock.
#
# Run with: nix run .#test
#
# NOTE: Requires a KVM-capable host with nested VMX support.
#
# `bitcoinInitrd` is optional. When non-null, an extra step boots the podman
# initrd to exercise the deterministic I/O channel. The flake passes it as
# null whenever workloads/bitcoin/images.tar isn't in the flake source.
{ pkgs, bedrockKernel, bedrockModule, bedrockCli, bedrockDeterminism
, guestKernel, guestInitrd, bitcoinInitrd ? null }:

let
  machineConfig = { config, pkgs, ... }: {
    boot.kernelPackages = pkgs.linuxPackagesFor bedrockKernel;
    boot.extraModulePackages = [ bedrockModule ];
    boot.kernelModules = [ "bedrock" ];

    # No KVM in the guest -- bedrock is the hypervisor
    boot.initrd.includeDefaultModules = false;
    boot.initrd.availableKernelModules = pkgs.lib.mkForce [ ];
    boot.initrd.kernelModules = pkgs.lib.mkForce [ ];

    services.udev.extraRules = ''
      KERNEL=="bedrock", MODE="0666"
    '';

    virtualisation = {
      cores = 2;
      memorySize = 10240;
      graphics = false;
      qemu.options = [
        "-enable-kvm"
        "-cpu" "host"
      ];
    };

    environment.systemPackages = [
      bedrockCli
      bedrockDeterminism
    ];
  };

  test = pkgs.testers.nixosTest {
    name = "bedrock-integration";
    nodes.machine = machineConfig;

    testScript = ''
      machine.wait_for_unit("multi-user.target")

      # Verify the bedrock module is loaded
      machine.succeed("lsmod | grep bedrock")

      # Verify the device node exists
      machine.succeed("test -c /dev/bedrock")

      # Boot trivial guest (VMCALL shutdown on init)
      machine.succeed(
        "bedrock-cli -m 5120"
        " -i ${guestInitrd}"
        " ${guestKernel}/vmlinux"
        " --stop-at-vt 10.0"
        " --timeout 300"
        " >&2"
      )
      ${pkgs.lib.optionalString (bitcoinInitrd != null) ''
        # Boot podman guest (runs workload, shuts down via VMCALL).
        # `--io-action vt=100.0:list` exercises the deterministic I/O
        # channel: at virtual-time 100s the host queues a "list running
        # containers" request, the guest module receives the IRQ on pin
        # 9, runs `podman ps`, and returns the container names to the
        # host.
        machine.succeed(
          "bedrock-cli -m 5120"
          " -i ${bitcoinInitrd}"
          " --io-action vt=100.0:list"
          " ${guestKernel}/vmlinux"
          " >&2"
        )
      ''}
    '';
  };
in
test.driver
