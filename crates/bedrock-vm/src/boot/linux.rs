// SPDX-License-Identifier: GPL-2.0

//! Linux boot configuration and setup.
//!
//! Provides a convenient API for setting up Linux boot on a VM.

use crate::error::VmError;
use crate::vm::Vm;

use super::{
    linux_boot_regs, setup_boot_params, setup_gdt, setup_mptable, setup_page_tables, write_cmdline,
};

/// Configuration for Linux boot setup.
///
/// This struct holds all the information needed to configure a VM for Linux boot.
/// The kernel should already be loaded into guest memory before calling
/// [`Vm::setup_linux_boot`].
///
/// # Example
///
/// ```ignore
/// use bedrock_vm::{VmBuilder, LinuxBootConfig};
///
/// let mut vm = VmBuilder::new()
///     .memory_mb(64)
///     .build()?;
///
/// // Load kernel into memory first (ELF parsing is caller's responsibility)
/// let (kernel_entry, kernel_end) = bedrock_vm::load_kernel(vm.memory_mut()?, &kernel_data)?;
///
/// // Configure and setup Linux boot
/// let config = LinuxBootConfig::new(kernel_entry, kernel_end)
///     .cmdline("console=ttyS0")
///     .initramfs(&initramfs_data);
///
/// let info = vm.setup_linux_boot(&config)?;
/// println!("Initramfs loaded at {:#x}", info.initramfs_addr.unwrap());
/// ```
#[derive(Debug, Clone)]
pub struct LinuxBootConfig<'a> {
    /// Kernel entry point address (from ELF parsing).
    pub kernel_entry: u64,
    /// Highest address used by the kernel (for initramfs placement).
    pub kernel_end: usize,
    /// Optional initramfs data (will be placed after kernel, aligned to 2MB).
    pub initramfs: Option<&'a [u8]>,
    /// Kernel command line.
    pub cmdline: &'a str,
}

impl<'a> LinuxBootConfig<'a> {
    /// Create a new Linux boot configuration.
    ///
    /// # Arguments
    ///
    /// * `kernel_entry` - Entry point address from the kernel ELF
    /// * `kernel_end` - Highest address used by the kernel (for initramfs placement)
    pub fn new(kernel_entry: u64, kernel_end: usize) -> Self {
        Self {
            kernel_entry,
            kernel_end,
            initramfs: None,
            cmdline: "",
        }
    }

    /// Set the kernel command line.
    pub fn cmdline(mut self, cmdline: &'a str) -> Self {
        self.cmdline = cmdline;
        self
    }

    /// Set the initramfs data.
    ///
    /// The initramfs will be placed after the kernel, aligned to a 2MB boundary.
    pub fn initramfs(mut self, data: &'a [u8]) -> Self {
        self.initramfs = Some(data);
        self
    }
}

/// Information about the Linux boot setup.
///
/// Returned by [`Vm::setup_linux_boot`] with details about what was configured.
#[derive(Debug, Clone)]
pub struct LinuxBootInfo {
    /// GDT base address.
    pub gdt_base: u64,
    /// GDT limit.
    pub gdt_limit: u16,
    /// Address where initramfs was loaded (if any).
    pub initramfs_addr: Option<u64>,
    /// Size of the loaded initramfs (if any).
    pub initramfs_size: Option<usize>,
}

/// 2MB alignment mask for initramfs placement.
const ALIGN_2MB: usize = 0x1FFFFF;

impl Vm {
    /// Set up Linux boot structures and registers.
    ///
    /// This sets up:
    /// - GDT for 64-bit mode
    /// - Identity-mapped page tables covering all guest memory
    /// - MP tables for APIC discovery
    /// - boot_params structure (zero page) per Linux boot protocol
    /// - Command line
    /// - Initial CPU registers
    ///
    /// The kernel should already be loaded into guest memory before calling this.
    /// If initramfs is provided, it will be copied to guest memory after the kernel,
    /// aligned to a 2MB boundary.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - This is a forked VM (no direct memory access)
    /// - The initramfs would exceed guest memory bounds
    /// - Setting registers fails
    ///
    /// # Example
    ///
    /// ```ignore
    /// use bedrock_vm::{VmBuilder, LinuxBootConfig};
    ///
    /// let mut vm = VmBuilder::new().memory_mb(64).build()?;
    ///
    /// // Load kernel first
    /// let (entry, end) = bedrock_vm::load_kernel(vm.memory_mut()?, &kernel_elf)?;
    ///
    /// // Setup Linux boot
    /// let config = LinuxBootConfig::new(entry, end)
    ///     .cmdline("console=ttyS0 quiet");
    /// vm.setup_linux_boot(&config)?;
    ///
    /// // VM is ready to run
    /// loop {
    ///     let exit = vm.run()?;
    ///     // ...
    /// }
    /// ```
    pub fn setup_linux_boot(&mut self, config: &LinuxBootConfig) -> Result<LinuxBootInfo, VmError> {
        if !self.is_root() {
            return Err(VmError::InvalidConfiguration {
                reason: "cannot setup Linux boot on forked VM (no direct memory access)"
                    .to_string(),
            });
        }

        let memory_size = self.memory_size();

        // Get mutable memory reference
        let memory = self
            .memory_mut()
            .map_err(|e| VmError::InvalidConfiguration {
                reason: format!("failed to access guest memory: {}", e),
            })?;

        // Set up GDT
        let (gdt_base, gdt_limit) = setup_gdt(memory);

        // Set up identity-mapped page tables
        setup_page_tables(memory, memory_size);

        // Set up MP tables for APIC discovery
        setup_mptable(memory);

        // Load initramfs if provided
        let (initramfs_addr, initramfs_size) = if let Some(data) = config.initramfs {
            // Align to 2MB boundary after kernel end
            let addr = (config.kernel_end + ALIGN_2MB) & !ALIGN_2MB;
            let size = data.len();
            let end = addr + size;

            if end > memory_size {
                return Err(VmError::InvalidConfiguration {
                    reason: format!(
                        "initramfs too large: {} bytes would exceed guest memory (end {:#x} > {:#x})",
                        size, end, memory_size
                    ),
                });
            }

            memory[addr..end].copy_from_slice(data);
            (Some(addr as u64), Some(size))
        } else {
            (None, None)
        };

        // Set up boot_params structure and write command line
        setup_boot_params(
            memory,
            memory_size,
            config.cmdline,
            initramfs_addr,
            initramfs_size,
        );
        write_cmdline(memory, config.cmdline);

        // Set up initial registers
        let regs = linux_boot_regs(config.kernel_entry, gdt_base, gdt_limit);
        self.set_regs(&regs).map_err(|e| VmError::Ioctl {
            operation: "SET_REGS",
            source: e,
        })?;

        Ok(LinuxBootInfo {
            gdt_base,
            gdt_limit,
            initramfs_addr,
            initramfs_size,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_linux_boot_config_builder() {
        let config = LinuxBootConfig::new(0x1000000, 0x2000000)
            .cmdline("console=ttyS0")
            .initramfs(&[1, 2, 3]);

        assert_eq!(config.kernel_entry, 0x1000000);
        assert_eq!(config.kernel_end, 0x2000000);
        assert_eq!(config.cmdline, "console=ttyS0");
        assert!(config.initramfs.is_some());
    }

    #[test]
    fn test_linux_boot_config_defaults() {
        let config = LinuxBootConfig::new(0x1000000, 0x2000000);

        assert_eq!(config.kernel_entry, 0x1000000);
        assert_eq!(config.kernel_end, 0x2000000);
        assert_eq!(config.cmdline, "");
        assert!(config.initramfs.is_none());
    }
}
