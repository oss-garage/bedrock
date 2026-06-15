// SPDX-License-Identifier: GPL-2.0

//! Constants for Linux x86-64 boot protocol.
//!
//! Organized by category for clarity and maintainability.

/// Memory layout constants for guest memory.
pub mod memory {
    pub const PAGE_SIZE: usize = 4096;
    pub const GDT_ADDR: u64 = 0x500;
    pub const TSS_ADDR: u64 = 0x600;
    pub const PML4_ADDR: u64 = 0x1000;
    pub const PDPT_LOW_ADDR: u64 = 0x2000;
    pub const PDPT_HIGH_ADDR: u64 = 0x3000;
    pub const BOOT_PARAMS_ADDR: u64 = 0x4000;
    pub const PD_ADDR: u64 = 0x8000;
    pub const CMDLINE_ADDR: u64 = 0x20000;
}

/// Page table entry flags.
pub mod pte {
    pub const PRESENT: u64 = 1 << 0;
    pub const WRITABLE: u64 = 1 << 1;
    pub const PAGE_SIZE_2MB: u64 = 1 << 7;
}

/// E820 memory map types.
pub mod e820 {
    pub const RAM: u32 = 1;
    pub const RESERVED: u32 = 2;
}

/// Linux boot protocol constants.
pub mod boot_protocol {
    pub const BOOT_FLAG: u16 = 0xAA55;
    pub const HDR_MAGIC: u32 = 0x53726448; // "HdrS"
    pub const VERSION_2_15: u16 = 0x020F;
    pub const LOADER_TYPE_UNDEFINED: u8 = 0xFF;

    pub mod loadflags {
        pub const LOADED_HIGH: u8 = 1 << 0;
        pub const CAN_USE_HEAP: u8 = 1 << 7;
    }
}

/// boot_params structure offsets (Linux kernel struct boot_params layout).
/// Reference: arch/x86/include/uapi/asm/bootparam.h
pub mod boot_params_offsets {
    pub const SETUP_SECTS: usize = 0x1F1;
    pub const BOOT_FLAG: usize = 0x1FE;
    pub const HEADER_MAGIC: usize = 0x202;
    pub const PROTOCOL_VERSION: usize = 0x206;
    pub const TYPE_OF_LOADER: usize = 0x210;
    pub const LOADFLAGS: usize = 0x211;
    pub const RAMDISK_IMAGE: usize = 0x218;
    pub const RAMDISK_SIZE: usize = 0x21C;
    pub const HEAP_END_PTR: usize = 0x224;
    pub const CMD_LINE_PTR: usize = 0x228;
    pub const CMDLINE_SIZE: usize = 0x238;
    pub const E820_ENTRIES: usize = 0x1E8;
    pub const E820_TABLE: usize = 0x2D0;
    pub const E820_ENTRY_SIZE: usize = 20;
}

/// MP Table constants (Intel MultiProcessor Specification).
pub mod mptable {
    pub const BASE_ADDR: usize = 0xF0000;
    pub const LAPIC_PADDR: u32 = 0xFEE00000;
    pub const LAPIC_VERSION: u8 = 0x14;
    pub const IOAPIC_PADDR: u32 = 0xFEC00000;
    pub const IOAPIC_ID: u8 = 1;
    pub const IOAPIC_VERSION: u8 = 0x11;
    pub const SPEC_REV: u8 = 4;
}

/// Default values for boot configuration.
pub mod defaults {
    pub const MEMORY_MB: usize = 5120;
    // The kernel console is the paravirtual batch console (hvc0), registered
    // by the guest `bedrock-console.ko` module — one VMCALL per printk line
    // instead of one VMX I/O exit per byte through the emulated 8250.
    // earlyprintk=serial still handles the early-boot window (before the
    // module loads) through the 8250; that output is bounded and fine.
    pub const CMDLINE: &str = "console=hvc0 earlyprintk=serial nopti nokaslr mitigations=off break";
    pub const RDRAND_SEED: u64 = 0x12345678_deadbeef;
}
