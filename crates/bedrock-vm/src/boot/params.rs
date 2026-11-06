// SPDX-License-Identifier: GPL-2.0

//! Linux boot_params (zero page) setup, per Documentation/arch/x86/boot.rst and
//! arch/x86/include/uapi/asm/bootparam.h.

use super::constants::boot_params_offsets as offsets;
use super::constants::boot_protocol::{self, loadflags};
use super::constants::e820;
use super::constants::memory::{BOOT_PARAMS_ADDR, CMDLINE_ADDR, PAGE_SIZE};
use bedrock_vmx::exits::{APIC_BASE, APIC_SIZE, IOAPIC_BASE};

/// E820 memory map entry (matches Linux struct e820_entry).
#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
pub struct E820Entry {
    pub addr: u64,
    pub size: u64,
    pub type_: u32,
}

/// Set up boot_params (zero page) at BOOT_PARAMS_ADDR.
pub fn setup_boot_params(
    memory: &mut [u8],
    memory_size: usize,
    cmdline: &str,
    initramfs_addr: Option<u64>,
    initramfs_size: Option<usize>,
) {
    let boot_params = &mut memory[BOOT_PARAMS_ADDR as usize..][..PAGE_SIZE];
    boot_params.fill(0);

    // Setup header
    write_u8(boot_params, offsets::SETUP_SECTS, 0);
    write_u16(boot_params, offsets::BOOT_FLAG, boot_protocol::BOOT_FLAG);
    write_u32(boot_params, offsets::HEADER_MAGIC, boot_protocol::HDR_MAGIC);
    write_u16(
        boot_params,
        offsets::PROTOCOL_VERSION,
        boot_protocol::VERSION_2_15,
    );
    write_u8(
        boot_params,
        offsets::TYPE_OF_LOADER,
        boot_protocol::LOADER_TYPE_UNDEFINED,
    );
    write_u8(
        boot_params,
        offsets::LOADFLAGS,
        loadflags::LOADED_HIGH | loadflags::CAN_USE_HEAP,
    );

    // Ramdisk (initramfs)
    if let Some(addr) = initramfs_addr {
        write_u32(boot_params, offsets::RAMDISK_IMAGE, addr as u32);
    }
    if let Some(size) = initramfs_size {
        write_u32(boot_params, offsets::RAMDISK_SIZE, size as u32);
    }

    // Heap and command line
    write_u16(boot_params, offsets::HEAP_END_PTR, 0xFE00);
    write_u32(boot_params, offsets::CMD_LINE_PTR, CMDLINE_ADDR as u32);
    write_u32(boot_params, offsets::CMDLINE_SIZE, cmdline.len() as u32);

    setup_e820_table(boot_params, memory_size);
}

fn setup_e820_table(boot_params: &mut [u8], memory_size: usize) {
    let mmio_start = IOAPIC_BASE;
    let mmio_end = APIC_BASE + APIC_SIZE;
    let mem_end = memory_size as u64;

    let mut entries = vec![
        // Entry 0: Low memory (0 - 0x9FC00) - conventional memory
        E820Entry {
            addr: 0,
            size: 0x9FC00,
            type_: e820::RAM,
        },
        // Entry 1: Reserved (0x9FC00 - 0xA0000) - EBDA
        E820Entry {
            addr: 0x9FC00,
            size: 0x400,
            type_: e820::RESERVED,
        },
        // Entry 2: Reserved (0xA0000 - 0x100000) - video memory + ROM
        E820Entry {
            addr: 0xA0000,
            size: 0x60000,
            type_: e820::RESERVED,
        },
        // Entry 3: Main RAM (1MB - min(memory_size, mmio_start))
        E820Entry {
            addr: 0x100000,
            size: mem_end.min(mmio_start) - 0x100000,
            type_: e820::RAM,
        },
    ];
    if mem_end > mmio_start {
        entries.push(E820Entry {
            addr: mmio_start,
            size: mem_end.min(mmio_end) - mmio_start,
            type_: e820::RESERVED,
        });
    }
    if mem_end > mmio_end {
        entries.push(E820Entry {
            addr: mmio_end,
            size: mem_end - mmio_end,
            type_: e820::RAM,
        });
    }

    write_u8(boot_params, offsets::E820_ENTRIES, entries.len() as u8);

    for (i, entry) in entries.iter().enumerate() {
        let offset = offsets::E820_TABLE + i * offsets::E820_ENTRY_SIZE;
        boot_params[offset..][..8].copy_from_slice(&entry.addr.to_le_bytes());
        boot_params[offset + 8..][..8].copy_from_slice(&entry.size.to_le_bytes());
        boot_params[offset + 16..][..4].copy_from_slice(&entry.type_.to_le_bytes());
    }
}

pub fn write_cmdline(memory: &mut [u8], cmdline: &str) {
    let cmdline_bytes = cmdline.as_bytes();
    let dest = &mut memory[CMDLINE_ADDR as usize..][..cmdline_bytes.len() + 1];
    dest[..cmdline_bytes.len()].copy_from_slice(cmdline_bytes);
    dest[cmdline_bytes.len()] = 0; // null terminator
}

fn write_u8(buf: &mut [u8], offset: usize, val: u8) {
    buf[offset] = val;
}

fn write_u16(buf: &mut [u8], offset: usize, val: u16) {
    buf[offset..][..2].copy_from_slice(&val.to_le_bytes());
}

fn write_u32(buf: &mut [u8], offset: usize, val: u32) {
    buf[offset..][..4].copy_from_slice(&val.to_le_bytes());
}
