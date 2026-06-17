# SPDX-License-Identifier: GPL-2.0

# On NixOS, set KDIR to kernel dev path:
#   nix-build '<nixpkgs>' -A linuxPackages.kernel.dev --no-out-link
# Then: make KDIR=/nix/store/...-linux-X.Y.Z-dev/lib/modules/X.Y.Z/build
KDIR ?= /lib/modules/$(shell uname -r)/build

# Use the unsuffixed LLVM tools supplied by the Nix development shell.
LLVM ?= 1

obj-m := bedrock.o

# Link the Rust module with our C helpers and assembly
bedrock-y := helpers.o vmx_support.o

# Host-specific PEBS margin, generated from CPUID by the shared generator that
# the cargo build (build.rs) also uses. `vmx` is a symlink to ../bedrock-vmx/src.
RUSTC ?= rustc
MARGIN_GEN := gen_pebs_margin
MARGIN_RS := vmx/exits/pebs_margin_generated.rs

# Keep `all` as the default goal: it must stay the first rule in this file, since
# `make` (with no target) builds whichever target appears first.
all: $(MARGIN_RS)
	$(MAKE) -C $(KDIR) M=$(CURDIR) LLVM=$(LLVM) \
		KCFLAGS=-Wno-error=unused-command-line-argument \
		KAFLAGS=-Wno-error=unused-command-line-argument modules

$(MARGIN_RS): ../../contrib/gen_pebs_margin.rs
	$(RUSTC) -O $< -o $(MARGIN_GEN)
	./$(MARGIN_GEN) $@

clean:
	$(MAKE) -C $(KDIR) M=$(CURDIR) clean
	rm -f $(MARGIN_GEN) $(MARGIN_RS)

load:
	@echo "Reloading bedrock kernel module..."
	@sudo rmmod bedrock 2>/dev/null || true
	@sudo insmod -f bedrock.ko
	@echo "Module loaded successfully. Recent kernel messages:"
	@sudo dmesg | tail -5
