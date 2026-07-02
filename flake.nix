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

      # The podman guest initramfs. One generic initrd serves every workload.
      # The workload's compose.yaml / images.tar are downloaded at boot over the
      # file-transmission hypercall (HYPERCALL_FILE_FETCH); the host serves them
      # at runtime (bedrock-cli --file …, or the lab's LabOpts.files). See
      # nix/podman-initrd.nix.
      podmanInitrd = import ./nix/podman-initrd.nix {
        inherit pkgs guestKernel;
      };

      # A workload is a directory under workloads/ holding a compose.yaml and a
      # built images.tar (`./workloads/<name>/build.sh`). Both are served to the
      # guest at runtime over the file-transmission hypercall — read from disk,
      # not from the flake source — so they need no git staging.

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
        python3 ${./contrib/check_stack.py} ${koPath}
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
        inherit podmanInitrd;
        default = userland.bedrock-cli;
      };

      # The generic podman initrd is exposed via `lib` too so external flakes
      # can boot their own workloads against it (handing the workload files to
      # bedrock-cli / the lab at runtime).
      lib.${system} = {
        inherit podmanInitrd;
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

        # NixOS-VM smoke test (nested virt): nix run .#test-vm
        test-vm = let
          testDriver = import ./nix/tests.nix {
            inherit pkgs bedrockModule guestKernel guestInitrd;
            bedrockKernel = kernel;
            bedrockCli = userland.bedrock-cli;
            bedrockDeterminism = userland.bedrock-determinism;
          };
        in {
          type = "app";
          program = "${testDriver}/bin/nixos-test-driver";
        };

        # Boot the bitcoin workload guest directly on the host:
        #   nix run .#test-bitcoin-workload
        # Requires the bedrock module loaded, /dev/bedrock present, and the
        # bitcoin images built (./workloads/bitcoin/build.sh).
        test-bitcoin-workload = let
          script = pkgs.writeShellScript "bedrock-test-bitcoin-workload" ''
            set -e
            export PATH=${pkgs.lib.makeBinPath [ userland.bedrock-cli pkgs.coreutils ]}:$PATH

            echo "=== Bedrock bitcoin workload ==="

            if ! lsmod | grep -q bedrock; then
              echo "ERROR: bedrock module not loaded. Run: insmod bedrock.ko"
              exit 1
            fi
            if [ ! -c /dev/bedrock ]; then
              echo "ERROR: /dev/bedrock not found"
              exit 1
            fi
            if [ ! -f workloads/bitcoin/images.tar ]; then
              echo "ERROR: workloads/bitcoin/images.tar not found." >&2
              echo "Build it first: ./workloads/bitcoin/build.sh" >&2
              exit 1
            fi

            echo "--- Booting bitcoin podman guest ---"
            bedrock-cli -m 5120 \
              -i ${podmanInitrd} \
              --file compose.yaml=workloads/bitcoin/compose.yaml \
              --file images.tar=workloads/bitcoin/images.tar \
              ${guestKernel}/vmlinux
            echo "=== Bitcoin workload: OK ==="
          '';
        in {
          type = "app";
          program = "${script}";
        };

        # Boot the concurrency-fuzz workload guest directly on the host:
        #   nix run .#test-concurrency-fuzz-workload
        # Requires the bedrock module loaded, /dev/bedrock present, and the
        # workload image built (./workloads/concurrency-fuzz/build.sh). The
        # guest kernel must have sched_ext + BTF (see nix/guest-kernel.nix).
        # Boot it twice and diff the output to check determinism.
        test-concurrency-fuzz-workload = let
          script = pkgs.writeShellScript "bedrock-test-concurrency-fuzz-workload" ''
            set -e
            export PATH=${pkgs.lib.makeBinPath [ userland.bedrock-cli pkgs.coreutils ]}:$PATH

            echo "=== Bedrock concurrency-fuzz workload ==="

            if ! lsmod | grep -q bedrock; then
              echo "ERROR: bedrock module not loaded. Run: insmod bedrock.ko"
              exit 1
            fi
            if [ ! -c /dev/bedrock ]; then
              echo "ERROR: /dev/bedrock not found"
              exit 1
            fi
            if [ ! -f workloads/concurrency-fuzz/images.tar ]; then
              echo "ERROR: workloads/concurrency-fuzz/images.tar not found." >&2
              echo "Build it first: ./workloads/concurrency-fuzz/build.sh" >&2
              exit 1
            fi

            echo "--- Booting concurrency-fuzz podman guest ---"
            bedrock-cli -m 5120 \
              -i ${podmanInitrd} \
              --file compose.yaml=workloads/concurrency-fuzz/compose.yaml \
              --file images.tar=workloads/concurrency-fuzz/images.tar \
              ${guestKernel}/vmlinux
            echo "=== Concurrency-fuzz workload: OK ==="
          '';
        in {
          type = "app";
          program = "${script}";
        };

        # bedrock-lab integration tests: nix run .#integration-tests
        #
        # The test binary is compiled hermetically by nix (cargo runs inside
        # the build sandbox with its own CARGO_HOME, so it never touches the
        # caller's ~/.cargo), then run on the host against a loaded bedrock
        # module / /dev/bedrock. Run from the repo root so the workload files
        # resolve; BEDROCK_VMLINUX / BEDROCK_INITRAMFS / BEDROCK_COMPOSE /
        # BEDROCK_IMAGES can override the guest kernel / initrd / workload files.
        integration-tests = let
          testBin = pkgs.rustPlatform.buildRustPackage {
            pname = "bedrock-integration-tests-bin";
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
            nativeBuildInputs = [ pkgs.jq ];
            # Compile the test harness but don't run it (there's no /dev/bedrock
            # in the sandbox); install the resulting binary for the host to run.
            buildPhase = ''
              runHook preBuild
              cargo test --no-run --release -p bedrock-integration-tests \
                --message-format=json \
                | jq -r 'select(.profile.test == true and .executable != null) | .executable' \
                > test-bins
              runHook postBuild
            '';
            installPhase = ''
              runHook preInstall
              install -Dm755 "$(head -n1 test-bins)" \
                "$out/bin/bedrock-integration-tests"
              runHook postInstall
            '';
            doCheck = false;
          };
          # The generic podman initrd downloads the workload's files at boot over
          # the file-transmission hypercall; the harness
          # (tests/integration/common.rs) serves them from BEDROCK_COMPOSE /
          # BEDROCK_IMAGES. These default to the on-disk workload files (built by
          # ./workloads/integration-tests/build.sh); override any of the four to
          # point elsewhere.
          script = pkgs.writeShellScript "bedrock-integration-tests" ''
            set -euo pipefail
            export BEDROCK_VMLINUX="''${BEDROCK_VMLINUX:-${guestKernel}/vmlinux}"
            export BEDROCK_INITRAMFS="''${BEDROCK_INITRAMFS:-${podmanInitrd}}"
            export BEDROCK_COMPOSE="''${BEDROCK_COMPOSE:-workloads/integration-tests/compose.yaml}"
            export BEDROCK_IMAGES="''${BEDROCK_IMAGES:-workloads/integration-tests/images.tar}"
            if [ ! -f "$BEDROCK_IMAGES" ]; then
              echo "ERROR: $BEDROCK_IMAGES not found." >&2
              echo "Build it first: ./workloads/integration-tests/build.sh" >&2
              exit 1
            fi
            exec ${testBin}/bin/bedrock-integration-tests "$@"
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
          pkgs.pahole
          pkgs.just
          pkgs.gnumake
        ];

        # Point KDIR at the Nix-built kernel so `just build` works
        KDIR = "${kernel.dev}/lib/modules/${kernel.modDirVersion}/build";

        # Help clang find the right includes
        LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";

        # The Nix clang wrapper adds flags that make the kernel's
        # -nostdlibinc argument appear unused for some module sources.
        NIX_CFLAGS_COMPILE = "-Wno-unused-command-line-argument";

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
