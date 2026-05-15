# Load environment variables from .env file
set dotenv-load

# Remote host for sync/build (configure in .env)
# Uses lazy evaluation so local commands work without remote config
remote_host := `echo ${REMOTE_HOST:-}`
remote_dir := `echo ${REMOTE_DIR:-}`

# Default: run tests
default: test

# Run tests
[group: 'local']
test:
    cargo test

# Format code
[group: 'local']
fmt:
    cargo fmt
    rustfmt --edition 2021 crates/bedrock/*.rs crates/bedrock/vm_file/*.rs

# Build the kernel module (pass kernel_log=1 to enable pr_* logging)
[group: 'local']
build kernel_log="":
    make -C crates/bedrock {{ if kernel_log != "" { "KERNEL_LOG=1" } else { "" } }}

# Clean kernel module build artifacts
[group: 'local']
clean:
    make clean -C crates/bedrock

# Load the kernel module
[group: 'local']
load:
    sudo make load -C crates/bedrock

# Count lines of Rust code (excluding tests)
[group: 'local']
count-lines:
    find . -type f -name '*.rs' -not -path '*/.*/*' -not -path './target/*' -not -name '*test*' -not -lname '*' -exec cat {} + | wc -l

# Sync to remote
[group: 'remote']
sync:
    rsync -avz --delete --exclude '.git' --exclude '.claude' --exclude target ./ {{remote_host}}:{{remote_dir}}

# Build on remote (sync then build, pass kernel_log=1 to enable pr_* logging)
[group: 'remote']
remote kernel_log="": sync
    ssh {{remote_host}} 'cd {{remote_dir}} && just build kernel_log={{kernel_log}}'

# Clean remote build artifacts
[group: 'remote']
remote-clean:
    ssh {{remote_host}} 'cd {{remote_dir}} && just clean'

# Reload netconsole (configure NETCONSOLE_IP in .env)
[group: 'local']
netconsole:
    rmmod netconsole 2>/dev/null; modprobe netconsole netconsole=@/eno1,@`echo $NETCONSOLE_IP`/

# Build a workload's images.tar via its build.sh, then build the
# resulting initrd derivation and print its /nix/store path. images.tar
# is staged transiently (git add -f → nix build → git reset HEAD) so it
# can't end up in a commit by accident even if the build is interrupted
# after the stage step — the trap on EXIT still runs.
#
# Usage: just build-workload <name>     # e.g. just build-workload bitcoin
[group: 'nix']
build-workload name:
    #!/usr/bin/env bash
    set -euo pipefail
    trap 'git reset HEAD workloads/{{name}}/images.tar 2>/dev/null || true' EXIT
    ./workloads/{{name}}/build.sh
    git add -f workloads/{{name}}/images.tar
    nix build --no-link --print-out-paths .#{{name}}Initrd

# Boot NixOS dev VM with nested KVM
[group: 'nix']
vm:
    nix run .#vm

# Run NixOS integration tests in VM (requires KVM, slow due to nested virt)
[group: 'nix']
nix-test:
    nix run .#test

# Run tests natively on host (requires bedrock module loaded)
[group: 'nix']
nix-test-native:
    nix run .#test-native
