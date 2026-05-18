// SPDX-License-Identifier: GPL-2.0

//! Linux x86-64 boot protocol support.
//!
//! This module provides everything needed to boot a Linux kernel in a VM:
//! - GDT setup for 64-bit mode
//! - Identity-mapped page tables
//! - boot_params (zero page) configuration
//! - MP tables for APIC discovery
//! - Initial register state
//!
//! # Example
//!
//! ```ignore
//! use bedrock_vm::{UserVm, boot};
//!
//! let mut vm = UserVm::create(memory_size)?;
//! let (gdt_base, gdt_limit) = boot::setup_gdt(vm.memory_mut());
//! boot::setup_page_tables(vm.memory_mut(), memory_size);
//! boot::setup_mptable(vm.memory_mut());
//! boot::setup_boot_params(vm.memory_mut(), memory_size, cmdline, None, None);
//! boot::write_cmdline(vm.memory_mut(), cmdline);
//! let regs = boot::linux_boot_regs(kernel_entry, gdt_base, gdt_limit);
//! vm.set_regs(&regs)?;
//! ```

pub mod constants;
mod elf;
mod gdt;
mod linux;
mod mptable;
mod page_tables;
mod params;
mod regs;

pub use constants::defaults;
pub use constants::memory::{BOOT_PARAMS_ADDR, CMDLINE_ADDR, PML4_ADDR};
pub use constants::mptable::BASE_ADDR as MPTABLE_BASE;
pub use elf::load_kernel;
pub use gdt::setup_gdt;
pub use linux::{LinuxBootConfig, LinuxBootInfo};
pub use mptable::setup_mptable;
pub use page_tables::setup_page_tables;
pub use params::{setup_boot_params, write_cmdline, E820Entry};
pub use regs::linux_boot_regs;
