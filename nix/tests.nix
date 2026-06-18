# NixOS-VM smoke test for bedrock.
#
# Run with: nix run .#test-vm
#
# Boots a NixOS VM with the bedrock module loaded and confirms it can boot a
# trivial guest (VMCALL shutdown) — a quick "does the hypervisor work in a
# clean environment" check. The realistic bitcoin workload runs separately via
# `nix run .#test-bitcoin-workload`.
#
# NOTE: Requires a KVM-capable host with nested VMX support.
{ pkgs, bedrockKernel, bedrockModule, bedrockCli, bedrockDeterminism
, guestKernel, guestInitrd }:

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
        " --wall-clock-timeout 300"
        " >&2"
      )
    '';
  };
in
test.driver
