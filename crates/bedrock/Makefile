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

all:
	$(MAKE) -C $(KDIR) M=$(CURDIR) LLVM=$(LLVM) \
		KCFLAGS=-Wno-error=unused-command-line-argument \
		KAFLAGS=-Wno-error=unused-command-line-argument modules

clean:
	$(MAKE) -C $(KDIR) M=$(CURDIR) clean

load:
	@echo "Reloading bedrock kernel module..."
	@sudo rmmod bedrock 2>/dev/null || true
	@sudo insmod -f bedrock.ko
	@echo "Module loaded successfully. Recent kernel messages:"
	@sudo dmesg | tail -5
