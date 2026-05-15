{
  description = "Bedrock hypervisor - deterministic x86-64 hypervisor as a Linux kernel module";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    # Linux 6.18 source -- pin to the exact tag
    linux-src = {
      url = "github:torvalds/linux/v6.18";
      flake = false;
    };
  };

  outputs = { self, nixpkgs, rust-overlay, linux-src }:
    let
      system = "x86_64-linux";

      pkgs = import nixpkgs {
        inherit system;
        overlays = [ rust-overlay.overlays.default ];
      };

      # Rust toolchain for kernel builds.
      # Must match what kernel.org recommends for Linux 6.18:
      # https://mirrors.edge.kernel.org/pub/tools/llvm/rust/
      # Includes rust-src (needed by kernel's Rust build for core/alloc).
      rustToolchain = pkgs.rust-bin.stable."1.94.0".default.override {
        extensions = [ "rust-src" "rustfmt" "clippy" ];
      };

      # -- Derivations --

      kernel = import ./nix/kernel.nix {
        inherit pkgs linux-src rustToolchain;
      };

      bedrockModule = import ./nix/module.nix {
        inherit pkgs kernel rustToolchain;
      };

      bedrockModuleClippy = import ./nix/module.nix {
        inherit pkgs kernel rustToolchain;
        clippy = true;
      };

      # Guest kernel with determinism patches (runs under bedrock)
      guestKernel = import ./nix/guest-kernel.nix {
        inherit pkgs linux-src;
      };

      # Trivial guest initramfs (boots and immediately shuts down via VMCALL)
      guestInitrd = import ./nix/trivial-initrd.nix { inherit pkgs; };

      # Builder for the podman initrd. Takes a compose.yaml and a single
      # docker-archive tarball (from `docker save`); see nix/podman-initrd.nix
      # for the schema. Workloads do their own image building outside Nix
      # and feed the resulting `images.tar` in here.
      mkPodmanInitrd = { composeYaml, imagesTar }:
        import ./nix/podman-initrd.nix {
          inherit pkgs guestKernel composeYaml imagesTar;
        };

      # Auto-discovered workloads. Each subdirectory of workloads/ becomes a
      # package <name>Initrd once its images.tar shows up in the flake source.
      # Run `just build-workload <name>` to produce + stage the tarball
      # transiently (it's gitignored and gets unstaged after the build).
      # Workloads without an images.tar are silently skipped so the rest of
      # the flake still evaluates cleanly.
      workloadInitrds = let
        workloadsDir = ./workloads;
      in pkgs.lib.mapAttrs' (name: _:
        pkgs.lib.nameValuePair "${name}Initrd" (mkPodmanInitrd {
          composeYaml = workloadsDir + "/${name}/compose.yaml";
          imagesTar   = workloadsDir + "/${name}/images.tar";
        })
      ) (pkgs.lib.filterAttrs (name: type:
        type == "directory"
        && builtins.pathExists (workloadsDir + "/${name}/images.tar")
      ) (builtins.readDir workloadsDir));

      userland = import ./nix/userland.nix { inherit pkgs; };

      rustfilt = let
        src = pkgs.fetchFromGitHub {
          owner = "luser";
          repo = "rustfilt";
          rev = "0.2.1";
          hash = "sha256-zb1tkeWmeMq7aM8hWssS/UpvGzGbfsaVYCOKBnAKwiQ=";
        };
      in pkgs.rustPlatform.buildRustPackage {
        pname = "rustfilt";
        version = "0.2.1";
        inherit src;
        cargoLock.lockFile = "${src}/Cargo.lock";
      };

      # Stack usage analysis on the built kernel module
      checkStack = let
        koPath = "${bedrockModule}/lib/modules/${kernel.modDirVersion}/extra/bedrock.ko";
      in pkgs.runCommand "bedrock-check-stack" {
        nativeBuildInputs = [ pkgs.python3 pkgs.binutils-unwrapped rustfilt ];
      } ''
        python3 ${./scripts/check_stack.py} ${koPath}
        touch $out
      '';

    in
    {
      packages.${system} = {
        inherit kernel bedrockModule guestKernel guestInitrd checkStack;
        clippy-kernel = bedrockModuleClippy;
        check-stack = checkStack;
        bedrock-cli = userland.bedrock-cli;
        bedrock-determinism = userland.bedrock-determinism;
        default = userland.bedrock-cli;
      } // workloadInitrds;

      # `mkPodmanInitrd` is a function — keep it out of `packages` (which
      # nix expects to be derivations) and expose it via `lib` so external
      # flakes can build their own workloads against this one.
      lib.${system} = {
        inherit mkPodmanInitrd;
      };

      apps.${system} = {
        # Dev VM: nix run .#vm
        vm = {
          type = "app";
          program = let
            vm = import ./nix/vm.nix {
              inherit pkgs bedrockModule;
              bedrockKernel = kernel;
              bedrockCli = userland.bedrock-cli;
              bedrockDeterminism = userland.bedrock-determinism;
            };
          in "${vm}/bin/run-bedrock-vm-vm";
        };

        # Integration tests in NixOS VM: nix run .#test
        test = let
          testDriver = import ./nix/tests.nix {
            inherit pkgs bedrockModule guestKernel guestInitrd;
            bedrockKernel = kernel;
            bedrockCli = userland.bedrock-cli;
            bedrockDeterminism = userland.bedrock-determinism;
            bitcoinInitrd = workloadInitrds.bitcoinInitrd or null;
          };
        in {
          type = "app";
          program = "${testDriver}/bin/nixos-test-driver";
        };

        # Native test (no NixOS VM, runs directly on host): nix run .#test-native
        # Requires: host kernel 6.18 with bedrock module loaded, /dev/bedrock present
        test-native = let
          script = pkgs.writeShellScript "bedrock-test-native" ''
            set -e
            export PATH=${pkgs.lib.makeBinPath [ userland.bedrock-cli userland.bedrock-determinism pkgs.coreutils ]}:$PATH

            echo "=== Bedrock native test ==="

            # Check module is loaded
            if ! lsmod | grep -q bedrock; then
              echo "ERROR: bedrock module not loaded. Run: insmod bedrock.ko"
              exit 1
            fi

            if [ ! -c /dev/bedrock ]; then
              echo "ERROR: /dev/bedrock not found"
              exit 1
            fi

            echo "Module loaded, /dev/bedrock present"

            # Boot trivial guest
            echo "--- Booting trivial guest (VMCALL shutdown) ---"
            bedrock-cli -m 5120 \
              -i ${guestInitrd} \
              ${guestKernel}/vmlinux \
              --stop-at-vt 10.0 \
              --timeout 300

            echo "--- Trivial guest: OK ---"
            ${pkgs.lib.optionalString (workloadInitrds ? bitcoinInitrd) ''
              echo "--- Booting podman guest ---"
              bedrock-cli -m 5120 \
                -i ${workloadInitrds.bitcoinInitrd} \
                ${guestKernel}/vmlinux
              echo "--- Podman guest: OK ---"
            ''}
            echo "=== All tests passed ==="
          '';
        in {
          type = "app";
          program = "${script}";
        };
      };

      checks.${system} = {

        # Clippy for kernel module (runs clippy-driver instead of rustc)
        clippy-kernel = bedrockModuleClippy;

        # Stack usage analysis (ensures 8KB kernel stack limit is respected)
        check-stack = checkStack;

        # Cargo tests (no KVM needed)
        cargo-test = pkgs.rustPlatform.buildRustPackage {
          pname = "bedrock-cargo-tests";
          version = "0.1.0";
          src = pkgs.lib.cleanSourceWith {
            src = ./.;
            filter = path: type:
              let baseName = builtins.baseNameOf path; in
              !(baseName == "target" || baseName == ".git" ||
                baseName == ".claude" || baseName == "nix" ||
                (type == "directory" && baseName == "bedrock" &&
                 builtins.match ".*/crates/bedrock$" path != null));
          };
          cargoLock.lockFile = ./Cargo.lock;
          # Just run tests, don't install anything
          doCheck = true;
          doInstall = false;
          installPhase = "mkdir -p $out";
        };
      };

      # Dev shell: nix develop
      devShells.${system}.default = pkgs.mkShell {
        nativeBuildInputs = [
          rustToolchain
          pkgs.rust-analyzer
          pkgs.rust-bindgen
          pkgs.llvmPackages.clang
          pkgs.llvmPackages.llvm
          pkgs.llvmPackages.lld
          pkgs.just
          pkgs.gnumake
        ];

        # Point KDIR at the Nix-built kernel so `just build` works
        KDIR = "${kernel.dev}/lib/modules/${kernel.modDirVersion}/build";

        # Help clang find the right includes
        LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";

        shellHook = ''
          echo "bedrock dev shell"
          echo "  KDIR=$KDIR"
          echo "  rustc: $(rustc --version)"
          echo "  clang: $(clang --version | head -1)"
          echo ""
          echo "Commands:"
          echo "  just test    - Run cargo tests"
          echo "  just build   - Build kernel module (against Nix kernel)"
          echo "  just vm      - Boot dev VM"
        '';
      };
    };
}
