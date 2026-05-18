// SPDX-License-Identifier: GPL-2.0

//! Builder pattern for VM creation.

use crate::error::VmError;
use crate::rdrand::RdrandConfig;
use crate::vm::{LogConfig, Vm, BEDROCK_DEVICE_PATH, DEFAULT_TSC_FREQUENCY};

/// Default guest memory size (4 GB).
const DEFAULT_MEMORY_SIZE: usize = 4 * 1024 * 1024 * 1024;

/// Builder for creating VMs with a fluent API.
///
/// # Example
///
/// ```ignore
/// use bedrock_vm::VmBuilder;
///
/// // Create a root VM
/// let vm = VmBuilder::new()
///     .memory_mb(32)
///     .rdrand(RdrandConfig::seeded_rng(0x12345678))
///     .build()?;
///
/// // Create a forked VM
/// let forked = VmBuilder::new()
///     .forked_from(parent_vm_id)
///     .build()?;
/// ```
pub struct VmBuilder {
    memory_size: usize,
    tsc_frequency: u64,
    device_path: String,
    rdrand_config: Option<RdrandConfig>,
    log_config: Option<LogConfig>,
    single_step: Option<(u64, u64)>,
    stop_at_tsc: Option<u64>,
    parent_id: Option<u64>,
}

impl VmBuilder {
    /// Create a new VM builder with default settings.
    ///
    /// Default settings:
    /// - Memory size: 4 GB (ignored for forked VMs)
    /// - Device path: /dev/bedrock
    /// - RDRAND: Not configured (uses kernel default)
    /// - Logging: Disabled
    /// - Single-step: Disabled
    /// - Stop-at-TSC: Disabled
    /// - Parent: None (creates root VM)
    pub fn new() -> Self {
        Self {
            memory_size: DEFAULT_MEMORY_SIZE,
            tsc_frequency: DEFAULT_TSC_FREQUENCY,
            device_path: BEDROCK_DEVICE_PATH.to_string(),
            rdrand_config: None,
            log_config: None,
            single_step: None,
            stop_at_tsc: None,
            parent_id: None,
        }
    }

    /// Create a forked VM from an existing parent VM.
    ///
    /// When this is set, `memory_size` is ignored as forked VMs share memory
    /// with their parent using copy-on-write semantics.
    pub fn forked_from(mut self, parent_id: u64) -> Self {
        self.parent_id = Some(parent_id);
        self
    }

    /// Set the guest memory size in bytes.
    ///
    /// This is ignored for forked VMs.
    pub fn memory_size(mut self, size: usize) -> Self {
        self.memory_size = size;
        self
    }

    /// Set the guest memory size in megabytes.
    ///
    /// This is ignored for forked VMs.
    pub fn memory_mb(mut self, mb: usize) -> Self {
        self.memory_size = mb * 1024 * 1024;
        self
    }

    /// Set the emulated TSC frequency in Hz.
    ///
    /// Defaults to [`DEFAULT_TSC_FREQUENCY`]. Ignored for forked VMs, which
    /// inherit the TSC frequency from their parent.
    pub fn tsc_frequency(mut self, hz: u64) -> Self {
        self.tsc_frequency = hz;
        self
    }

    /// Configure RDRAND/RDSEED emulation.
    pub fn rdrand(mut self, config: RdrandConfig) -> Self {
        self.rdrand_config = Some(config);
        self
    }

    /// Configure deterministic logging.
    pub fn logging(mut self, config: LogConfig) -> Self {
        self.log_config = Some(config);
        self
    }

    /// Set a custom device path (default: /dev/bedrock).
    pub fn device_path(mut self, path: &str) -> Self {
        self.device_path = path.to_string();
        self
    }

    /// Enable single-stepping (MTF) for a specific TSC range.
    pub fn single_step(mut self, tsc_start: u64, tsc_end: u64) -> Self {
        self.single_step = Some((tsc_start, tsc_end));
        self
    }

    /// Set the TSC value at which the VM should stop.
    pub fn stop_at_tsc(mut self, tsc: u64) -> Self {
        self.stop_at_tsc = Some(tsc);
        self
    }

    /// Build the VM with the configured settings.
    ///
    /// Creates either a root VM or a forked VM depending on whether
    /// `forked_from()` was called.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The device cannot be opened
    /// - VM creation fails
    /// - Memory mapping fails
    /// - Configuration fails
    pub fn build(self) -> Result<Vm, VmError> {
        let mut vm = if let Some(parent_id) = self.parent_id {
            // Create forked VM
            Vm::create_forked(parent_id).map_err(|e| VmError::Ioctl {
                operation: "CREATE_FORKED_VM",
                source: e,
            })?
        } else {
            // Create root VM
            use std::fs::OpenOptions;

            if self.memory_size == 0 {
                return Err(VmError::InvalidConfiguration {
                    reason: "memory size must be greater than 0".to_string(),
                });
            }

            let device = OpenOptions::new()
                .read(true)
                .write(true)
                .open(&self.device_path)?;

            Vm::create_from_device(&device, self.memory_size, self.tsc_frequency).map_err(|e| {
                VmError::Ioctl {
                    operation: "CREATE_ROOT_VM",
                    source: e,
                }
            })?
        };

        // Apply configuration (works for both root and forked VMs)
        if let Some(config) = self.rdrand_config {
            vm.set_rdrand_config(&config).map_err(|e| VmError::Ioctl {
                operation: "SET_RDRAND_CONFIG",
                source: e,
            })?;
        }

        if let Some(config) = self.log_config {
            vm.set_log_config(&config).map_err(|e| VmError::Ioctl {
                operation: "SET_LOG_CONFIG",
                source: e,
            })?;
        }

        if let Some((start, end)) = self.single_step {
            vm.set_single_step_range(start, end)
                .map_err(|e| VmError::Ioctl {
                    operation: "SET_SINGLE_STEP",
                    source: e,
                })?;
        }

        if let Some(tsc) = self.stop_at_tsc {
            vm.set_stop_at_tsc(Some(tsc)).map_err(|e| VmError::Ioctl {
                operation: "SET_STOP_TSC",
                source: e,
            })?;
        }

        Ok(vm)
    }
}

impl Default for VmBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builder_defaults() {
        let builder = VmBuilder::new();
        assert_eq!(builder.memory_size, DEFAULT_MEMORY_SIZE);
        assert_eq!(builder.tsc_frequency, DEFAULT_TSC_FREQUENCY);
        assert_eq!(builder.device_path, BEDROCK_DEVICE_PATH);
        assert!(builder.rdrand_config.is_none());
        assert!(builder.log_config.is_none());
        assert!(builder.single_step.is_none());
        assert!(builder.stop_at_tsc.is_none());
        assert!(builder.parent_id.is_none());
    }

    #[test]
    fn test_builder_memory_mb() {
        let builder = VmBuilder::new().memory_mb(32);
        assert_eq!(builder.memory_size, 32 * 1024 * 1024);
    }

    #[test]
    fn test_builder_memory_size() {
        let builder = VmBuilder::new().memory_size(1000);
        assert_eq!(builder.memory_size, 1000);
    }

    #[test]
    fn test_builder_rdrand() {
        let builder = VmBuilder::new().rdrand(RdrandConfig::seeded_rng(42));
        assert!(builder.rdrand_config.is_some());
    }

    #[test]
    fn test_builder_single_step() {
        let builder = VmBuilder::new().single_step(100, 200);
        assert_eq!(builder.single_step, Some((100, 200)));
    }

    #[test]
    fn test_builder_stop_at_tsc() {
        let builder = VmBuilder::new().stop_at_tsc(12345);
        assert_eq!(builder.stop_at_tsc, Some(12345));
    }

    #[test]
    fn test_builder_forked_from() {
        let builder = VmBuilder::new().forked_from(42);
        assert_eq!(builder.parent_id, Some(42));
    }

    #[test]
    fn test_builder_chaining() {
        let builder = VmBuilder::new()
            .memory_mb(64)
            .rdrand(RdrandConfig::seeded_rng(123))
            .single_step(100, 200)
            .stop_at_tsc(1000)
            .device_path("/dev/custom");

        assert_eq!(builder.memory_size, 64 * 1024 * 1024);
        assert_eq!(builder.device_path, "/dev/custom");
        assert!(builder.rdrand_config.is_some());
        assert_eq!(builder.single_step, Some((100, 200)));
        assert_eq!(builder.stop_at_tsc, Some(1000));
    }

    #[test]
    fn test_builder_zero_memory_error() {
        let result = VmBuilder::new().memory_size(0).build();
        assert!(matches!(result, Err(VmError::InvalidConfiguration { .. })));
    }
}
