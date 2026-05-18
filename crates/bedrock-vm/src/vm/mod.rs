// SPDX-License-Identifier: GPL-2.0

//! Vm - Userspace interface to a bedrock VM.

mod config;
mod exit;
mod ioctl;
mod serial;
mod stats;

pub use config::{LogConfig, LogMode, SingleStepConfig, EXIT_REASON_CHECKPOINT};
pub use exit::{ExitKind, VmExit};
pub use ioctl::{
    FeedbackBufferInfo, FeedbackBufferInfoRequest, IoActionPayload, IO_CHANNEL_BUF_SIZE,
    MAX_FEEDBACK_BUFFERS,
};
pub use serial::{
    parse_line_tsc_entries, LineTscEntry, SerialInput, LOG_BUFFER_SIZE, SERIAL_BUFFER_SIZE,
    SERIAL_INPUT_MAX_SIZE, SERIAL_TSC_PAGE_SIZE,
};
pub use stats::{ExitStatEntry, ExitStats, ExitStatsReport, IoctlStats};

use std::cell::Cell;
use std::fs::{File, OpenOptions};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::ptr::NonNull;
use std::slice;
use std::time::Instant;

use crate::rdrand::RdrandConfig;
use crate::Regs;
use ioctl::*;

/// Path to the bedrock device file.
pub const BEDROCK_DEVICE_PATH: &str = "/dev/bedrock";

/// Default guest memory size (4 GB).
pub const DEFAULT_MEMORY_SIZE: usize = 4 * 1024 * 1024 * 1024;

/// Default TSC frequency (2995.2 MHz) for deterministic time emulation.
pub use bedrock_vmx::DEFAULT_TSC_FREQUENCY;

/// A userspace handle to a bedrock VM.
///
/// This struct owns the VM file descriptor and provides access to VM operations.
/// When dropped, it automatically unmaps memory and closes the file descriptor,
/// which causes the kernel to release the VM.
///
/// VMs can be either "root" VMs (created with `create()`) or "forked" VMs
/// (created with `fork()` or `create_forked()`). Root VMs have direct access
/// to guest memory, while forked VMs share memory with their parent using
/// copy-on-write semantics.
///
/// Use `is_forked()` to check which type of VM this is. Some operations
/// (like direct memory access) are only available on root VMs.
pub struct Vm {
    /// The VM file descriptor.
    fd: OwnedFd,
    /// Mapped guest memory pointer (None for forked VMs).
    memory_ptr: Option<NonNull<u8>>,
    /// Size of guest memory (0 for forked VMs).
    memory_size: usize,
    /// Mapped serial buffer pointer.
    serial_ptr: NonNull<u8>,
    /// Mapped serial TSC metadata page.
    serial_tsc_ptr: NonNull<u8>,
    /// Mapped log buffer pointer (None if logging not enabled).
    log_ptr: Option<NonNull<u8>>,
    /// Offset for log buffer mmap (differs between root and forked VMs).
    log_mmap_offset: libc::off_t,
    /// Mapped feedback buffer pointers (None if not mapped).
    feedback_buffer_ptrs: [Option<NonNull<u8>>; MAX_FEEDBACK_BUFFERS],
    /// Sizes of mapped feedback buffers (0 if not mapped).
    feedback_buffer_sizes: [usize; MAX_FEEDBACK_BUFFERS],
    /// Userspace ioctl timing statistics.
    ioctl_stats: Cell<IoctlStats>,
    /// Whether this is a forked VM.
    forked: bool,
}

// SAFETY: The mapped memory is owned exclusively by Vm and can be
// safely sent between threads.
unsafe impl Send for Vm {}
unsafe impl Sync for Vm {}

impl Drop for Vm {
    fn drop(&mut self) {
        unsafe {
            // Unmap guest memory if this is a root VM
            if let Some(ptr) = self.memory_ptr {
                libc::munmap(ptr.as_ptr() as *mut libc::c_void, self.memory_size);
            }
            // Unmap serial buffers
            libc::munmap(
                self.serial_ptr.as_ptr() as *mut libc::c_void,
                SERIAL_BUFFER_SIZE,
            );
            libc::munmap(
                self.serial_tsc_ptr.as_ptr() as *mut libc::c_void,
                SERIAL_TSC_PAGE_SIZE,
            );
            // Unmap log buffer if mapped
            if let Some(log_ptr) = self.log_ptr {
                libc::munmap(log_ptr.as_ptr() as *mut libc::c_void, LOG_BUFFER_SIZE);
            }
            // Unmap feedback buffers if mapped
            for i in 0..MAX_FEEDBACK_BUFFERS {
                if let Some(fb_ptr) = self.feedback_buffer_ptrs[i] {
                    libc::munmap(
                        fb_ptr.as_ptr() as *mut libc::c_void,
                        self.feedback_buffer_sizes[i],
                    );
                }
            }
        }
        // fd is automatically closed by OwnedFd's Drop
    }
}

impl Vm {
    /// Create a new root VM with the specified guest memory size.
    ///
    /// Uses [`DEFAULT_TSC_FREQUENCY`] for the emulated TSC.
    ///
    /// This opens /dev/bedrock, creates a new root VM with the specified
    /// memory size, and maps the guest memory into this process's address space.
    ///
    /// # Arguments
    ///
    /// * `memory_size` - Size of guest memory to allocate in bytes
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The bedrock device cannot be opened (module not loaded, permissions)
    /// - The CREATE_ROOT_VM ioctl fails
    /// - Memory mapping fails
    pub fn create(memory_size: usize) -> io::Result<Self> {
        Self::create_with_tsc_frequency(memory_size, DEFAULT_TSC_FREQUENCY)
    }

    /// Create a new root VM with the specified guest memory size and TSC frequency.
    pub fn create_with_tsc_frequency(memory_size: usize, tsc_frequency: u64) -> io::Result<Self> {
        let device = OpenOptions::new()
            .read(true)
            .write(true)
            .open(BEDROCK_DEVICE_PATH)?;

        Self::create_from_device(&device, memory_size, tsc_frequency)
    }

    /// Create a new root VM with the default memory size (16 MB).
    pub fn create_default() -> io::Result<Self> {
        Self::create(DEFAULT_MEMORY_SIZE)
    }

    /// Create a new root VM from an already-opened bedrock device.
    pub fn create_from_device(
        device: &File,
        memory_size: usize,
        tsc_frequency: u64,
    ) -> io::Result<Self> {
        if memory_size == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "memory size must be greater than 0",
            ));
        }
        if tsc_frequency == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "tsc frequency must be greater than 0",
            ));
        }

        let config = CreateVmConfig {
            memory_size: memory_size as u64,
            tsc_frequency,
        };

        let fd = unsafe {
            libc::ioctl(
                device.as_raw_fd(),
                BEDROCK_CREATE_ROOT_VM as libc::c_ulong,
                &config as *const CreateVmConfig,
            )
        };

        if fd < 0 {
            return Err(io::Error::last_os_error());
        }

        let fd = unsafe { OwnedFd::from_raw_fd(fd) };

        // Map the guest memory
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                memory_size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd.as_raw_fd(),
                0,
            )
        };

        if ptr == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }

        let memory_ptr = Some(unsafe { NonNull::new_unchecked(ptr as *mut u8) });

        // Map the serial buffer
        let serial_ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                SERIAL_BUFFER_SIZE,
                libc::PROT_READ,
                libc::MAP_SHARED,
                fd.as_raw_fd(),
                memory_size as libc::off_t,
            )
        };

        if serial_ptr == libc::MAP_FAILED {
            unsafe { libc::munmap(ptr, memory_size) };
            return Err(io::Error::last_os_error());
        }

        let serial_ptr = unsafe { NonNull::new_unchecked(serial_ptr as *mut u8) };

        // Map the serial TSC metadata page
        let serial_tsc_offset = memory_size + SERIAL_BUFFER_SIZE + LOG_BUFFER_SIZE;
        let tsc_ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                SERIAL_TSC_PAGE_SIZE,
                libc::PROT_READ,
                libc::MAP_SHARED,
                fd.as_raw_fd(),
                serial_tsc_offset as libc::off_t,
            )
        };

        if tsc_ptr == libc::MAP_FAILED {
            unsafe {
                libc::munmap(ptr, memory_size);
                libc::munmap(serial_ptr.as_ptr() as *mut libc::c_void, SERIAL_BUFFER_SIZE);
            }
            return Err(io::Error::last_os_error());
        }

        let serial_tsc_ptr = unsafe { NonNull::new_unchecked(tsc_ptr as *mut u8) };
        let log_mmap_offset = (memory_size + SERIAL_BUFFER_SIZE) as libc::off_t;

        Ok(Self {
            fd,
            memory_ptr,
            memory_size,
            serial_ptr,
            serial_tsc_ptr,
            log_ptr: None,
            log_mmap_offset,
            feedback_buffer_ptrs: [None; MAX_FEEDBACK_BUFFERS],
            feedback_buffer_sizes: [0; MAX_FEEDBACK_BUFFERS],
            ioctl_stats: Cell::new(IoctlStats::default()),
            forked: false,
        })
    }

    /// Create a forked VM from a parent VM ID.
    ///
    /// The forked VM shares memory with the parent using copy-on-write semantics.
    /// The forked VM starts with the same state as the parent at the time of forking.
    ///
    /// Note: Parent VMs cannot be run while they have active forked children.
    pub fn create_forked(parent_vm_id: u64) -> io::Result<Self> {
        let device = OpenOptions::new()
            .read(true)
            .write(true)
            .open(BEDROCK_DEVICE_PATH)?;

        let fd = unsafe {
            libc::ioctl(
                device.as_raw_fd(),
                BEDROCK_CREATE_FORKED_VM as libc::c_ulong,
                parent_vm_id,
            )
        };

        if fd < 0 {
            return Err(io::Error::last_os_error());
        }

        let fd = unsafe { OwnedFd::from_raw_fd(fd) };

        // Map the serial buffer (forked VMs use offset 0)
        let serial_ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                SERIAL_BUFFER_SIZE,
                libc::PROT_READ,
                libc::MAP_SHARED,
                fd.as_raw_fd(),
                0,
            )
        };

        if serial_ptr == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }

        let serial_ptr = unsafe { NonNull::new_unchecked(serial_ptr as *mut u8) };

        // Map the serial TSC metadata page
        let tsc_offset = (SERIAL_BUFFER_SIZE + LOG_BUFFER_SIZE) as libc::off_t;
        let tsc_ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                SERIAL_TSC_PAGE_SIZE,
                libc::PROT_READ,
                libc::MAP_SHARED,
                fd.as_raw_fd(),
                tsc_offset,
            )
        };

        if tsc_ptr == libc::MAP_FAILED {
            unsafe { libc::munmap(serial_ptr.as_ptr() as *mut libc::c_void, SERIAL_BUFFER_SIZE) };
            return Err(io::Error::last_os_error());
        }

        let serial_tsc_ptr = unsafe { NonNull::new_unchecked(tsc_ptr as *mut u8) };
        let log_mmap_offset = SERIAL_BUFFER_SIZE as libc::off_t;

        Ok(Self {
            fd,
            memory_ptr: None,
            memory_size: 0,
            serial_ptr,
            serial_tsc_ptr,
            log_ptr: None,
            log_mmap_offset,
            feedback_buffer_ptrs: [None; MAX_FEEDBACK_BUFFERS],
            feedback_buffer_sizes: [0; MAX_FEEDBACK_BUFFERS],
            ioctl_stats: Cell::new(IoctlStats::default()),
            forked: true,
        })
    }

    /// Fork this VM, creating a new VM with copy-on-write semantics.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - This VM is already a forked VM (cannot fork a fork)
    /// - VM creation fails
    pub fn fork(&self) -> io::Result<Self> {
        let vm_id = self.get_vm_id()?;
        Self::create_forked(vm_id)
    }

    /// Returns true if this is a forked VM.
    pub fn is_forked(&self) -> bool {
        self.forked
    }

    /// Returns true if this is a root VM (not forked).
    pub fn is_root(&self) -> bool {
        !self.forked
    }

    /// Returns the raw file descriptor for this VM.
    pub fn as_raw_fd(&self) -> i32 {
        self.fd.as_raw_fd()
    }

    // --- Memory access (root VMs only) ---

    /// Returns a slice of the mapped guest memory.
    ///
    /// # Errors
    ///
    /// Returns an error if this is a forked VM (no direct memory access).
    pub fn memory(&self) -> io::Result<&[u8]> {
        match self.memory_ptr {
            Some(ptr) => Ok(unsafe { slice::from_raw_parts(ptr.as_ptr(), self.memory_size) }),
            None => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "forked VMs do not have direct memory access",
            )),
        }
    }

    /// Returns a mutable slice of the mapped guest memory.
    ///
    /// # Errors
    ///
    /// Returns an error if this is a forked VM (no direct memory access).
    pub fn memory_mut(&mut self) -> io::Result<&mut [u8]> {
        match self.memory_ptr {
            Some(ptr) => Ok(unsafe { slice::from_raw_parts_mut(ptr.as_ptr(), self.memory_size) }),
            None => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "forked VMs do not have direct memory access",
            )),
        }
    }

    /// Returns the size of guest memory.
    ///
    /// Returns 0 for forked VMs.
    pub fn memory_size(&self) -> usize {
        self.memory_size
    }

    // --- Serial I/O ---

    /// Returns the serial output as a string, given the length from VmExit.
    pub fn serial_output_str(&self, len: usize) -> &str {
        let len = len.min(SERIAL_BUFFER_SIZE);
        let bytes = unsafe { slice::from_raw_parts(self.serial_ptr.as_ptr(), len) };
        std::str::from_utf8(bytes).unwrap_or("<invalid utf8>")
    }

    /// Returns the raw serial buffer.
    pub fn serial_buffer(&self) -> &[u8] {
        unsafe { slice::from_raw_parts(self.serial_ptr.as_ptr(), SERIAL_BUFFER_SIZE) }
    }

    /// Returns the serial TSC metadata page.
    pub fn serial_tsc_buffer(&self) -> &[u8] {
        unsafe { slice::from_raw_parts(self.serial_tsc_ptr.as_ptr(), SERIAL_TSC_PAGE_SIZE) }
    }

    // --- Deterministic I/O channel ---

    /// Queue an I/O channel request the guest will pick up on its next IRQ.
    ///
    /// `target_tsc` controls when the hypervisor injects the IRQ:
    /// - `0`: fire as soon as the guest is interruptible after the QUEUE.
    /// - non-zero: arm PEBS so the IRQ lands at the precise instruction
    ///   count corresponding to this emulated-TSC value.
    ///
    /// The guest must have loaded `bedrock-io.ko` and registered its shared
    /// page (`HYPERCALL_IO_REGISTER_PAGE`); until then the hypervisor will
    /// hold the IRQ. Errors:
    /// - `InvalidInput` if `data.len() > IO_CHANNEL_BUF_SIZE`.
    /// - `EBUSY` (mapped to `io::Error::from_raw_os_error`) if a request is
    ///   already in flight — the caller must `drain_io_response()` first.
    pub fn queue_io_action(&self, data: &[u8], target_tsc: u64) -> io::Result<()> {
        if data.len() > IO_CHANNEL_BUF_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "I/O action too large: {} > {}",
                    data.len(),
                    IO_CHANNEL_BUF_SIZE
                ),
            ));
        }

        // Boxed so we don't put 4KB on the local stack — harmless in
        // userspace, but matches kernel-side discipline and keeps the
        // method usable from constrained contexts.
        let mut payload = Box::new(IoActionPayload::default());
        payload.len = data.len() as u32;
        payload.target_tsc = target_tsc;
        payload.data[..data.len()].copy_from_slice(data);

        let ret = unsafe {
            libc::ioctl(
                self.fd.as_raw_fd(),
                BEDROCK_VM_QUEUE_IO_ACTION as libc::c_ulong,
                payload.as_ref() as *const IoActionPayload,
            )
        };

        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Drain the most recent I/O channel response, returning the captured
    /// bytes.
    ///
    /// Should be called immediately after `ExitKind::IoResponse`. Returns
    /// an empty vector if there is no pending response (e.g. drained
    /// twice). The kernel resets its internal response slot after the
    /// drain, so a subsequent QUEUE will succeed.
    pub fn drain_io_response(&self) -> io::Result<Vec<u8>> {
        let mut payload = Box::new(IoActionPayload::default());
        // On input, `len` is the user buffer's capacity — set it to the
        // maximum so the kernel can return up to a full page.
        payload.len = IO_CHANNEL_BUF_SIZE as u32;

        let ret = unsafe {
            libc::ioctl(
                self.fd.as_raw_fd(),
                BEDROCK_VM_DRAIN_IO_RESPONSE as libc::c_ulong,
                payload.as_mut() as *mut IoActionPayload,
            )
        };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }

        let n = (payload.len as usize).min(IO_CHANNEL_BUF_SIZE);
        Ok(payload.data[..n].to_vec())
    }

    pub fn set_input(&self, input: &[u8]) -> io::Result<()> {
        if self.forked {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "forked VMs do not support serial input",
            ));
        }

        if input.len() > SERIAL_INPUT_MAX_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "input too large: {} > {}",
                    input.len(),
                    SERIAL_INPUT_MAX_SIZE
                ),
            ));
        }

        let mut serial_input = SerialInput {
            len: input.len() as u32,
            _reserved: 0,
            buf: [0u8; SERIAL_INPUT_MAX_SIZE],
        };
        serial_input.buf[..input.len()].copy_from_slice(input);

        let ret = unsafe {
            libc::ioctl(
                self.fd.as_raw_fd(),
                BEDROCK_VM_SET_INPUT as libc::c_ulong,
                &serial_input as *const SerialInput,
            )
        };

        if ret < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(())
    }

    // --- Registers ---

    /// Read all VM registers.
    pub fn get_regs(&self) -> io::Result<Regs> {
        let start = Instant::now();
        let mut regs = Regs::default();

        let ret = unsafe {
            libc::ioctl(
                self.fd.as_raw_fd(),
                BEDROCK_VM_GET_REGS as libc::c_ulong,
                &mut regs as *mut Regs,
            )
        };

        self.record_ioctl_time(|s| {
            s.get_regs_ns += start.elapsed().as_nanos() as u64;
            s.get_regs_count += 1;
        });

        if ret < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(regs)
    }

    /// Write all VM registers.
    pub fn set_regs(&self, regs: &Regs) -> io::Result<()> {
        let start = Instant::now();

        let ret = unsafe {
            libc::ioctl(
                self.fd.as_raw_fd(),
                BEDROCK_VM_SET_REGS as libc::c_ulong,
                regs as *const Regs,
            )
        };

        self.record_ioctl_time(|s| {
            s.set_regs_ns += start.elapsed().as_nanos() as u64;
            s.set_regs_count += 1;
        });

        if ret < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(())
    }

    // --- Execution ---

    /// Run the VM until it exits.
    pub fn run(&self) -> io::Result<VmExit> {
        let start = Instant::now();

        let mut exit = VmExit {
            exit_reason: 0,
            serial_len: 0,
            exit_qualification: 0,
            guest_physical_addr: 0,
            log_entry_count: 0,
            _reserved: 0,
            emulated_tsc: 0,
            tsc_frequency: 0,
        };

        let ret = unsafe {
            libc::ioctl(
                self.fd.as_raw_fd(),
                BEDROCK_VM_RUN as libc::c_ulong,
                &mut exit as *mut VmExit,
            )
        };

        self.record_ioctl_time(|s| {
            s.run_ns += start.elapsed().as_nanos() as u64;
            s.run_count += 1;
        });

        if ret < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(exit)
    }

    // --- RDRAND configuration ---

    /// Configure RDRAND/RDSEED instruction emulation.
    pub fn set_rdrand_config(&self, config: &RdrandConfig) -> io::Result<()> {
        let ret = unsafe {
            libc::ioctl(
                self.fd.as_raw_fd(),
                BEDROCK_VM_SET_RDRAND_CONFIG as libc::c_ulong,
                config as *const RdrandConfig,
            )
        };

        if ret < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(())
    }

    /// Set the value to return for the next RDRAND/RDSEED instruction.
    ///
    /// This is only used when RDRAND is configured in ExitToUserspace mode.
    pub fn set_rdrand_value(&self, value: u64) -> io::Result<()> {
        let ret = unsafe {
            libc::ioctl(
                self.fd.as_raw_fd(),
                BEDROCK_VM_SET_RDRAND_VALUE as libc::c_ulong,
                &value as *const u64,
            )
        };

        if ret < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(())
    }

    // --- Logging ---

    /// Configure logging with a unified configuration.
    pub fn set_log_config(&mut self, config: &LogConfig) -> io::Result<()> {
        let was_enabled = self.log_ptr.is_some();
        let want_enabled = config.enabled != 0;

        let ret = unsafe {
            libc::ioctl(
                self.fd.as_raw_fd(),
                BEDROCK_VM_SET_LOG_CONFIG as libc::c_ulong,
                config as *const LogConfig,
            )
        };

        if ret < 0 {
            return Err(io::Error::last_os_error());
        }

        // Handle userspace mmap state changes
        if want_enabled && !was_enabled {
            let log_ptr = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    LOG_BUFFER_SIZE,
                    libc::PROT_READ,
                    libc::MAP_SHARED,
                    self.fd.as_raw_fd(),
                    self.log_mmap_offset,
                )
            };

            if log_ptr == libc::MAP_FAILED {
                let disabled = LogConfig::disabled();
                unsafe {
                    libc::ioctl(
                        self.fd.as_raw_fd(),
                        BEDROCK_VM_SET_LOG_CONFIG as libc::c_ulong,
                        &disabled as *const LogConfig,
                    );
                }
                return Err(io::Error::last_os_error());
            }

            self.log_ptr = Some(unsafe { NonNull::new_unchecked(log_ptr as *mut u8) });
        } else if !want_enabled && was_enabled {
            if let Some(log_ptr) = self.log_ptr.take() {
                unsafe {
                    libc::munmap(log_ptr.as_ptr() as *mut libc::c_void, LOG_BUFFER_SIZE);
                }
            }
        }

        Ok(())
    }

    /// Check if logging is enabled.
    pub fn logging_enabled(&self) -> bool {
        self.log_ptr.is_some()
    }

    /// Returns the raw log buffer as a byte slice.
    pub fn log_buffer(&self) -> Option<&[u8]> {
        self.log_ptr
            .map(|ptr| unsafe { slice::from_raw_parts(ptr.as_ptr(), LOG_BUFFER_SIZE) })
    }

    // --- Feedback buffer ---

    /// Get feedback buffer registration info for a specific index.
    ///
    /// Returns `None` if no feedback buffer has been registered at the given index.
    pub fn get_feedback_buffer_info_at(
        &self,
        index: usize,
    ) -> io::Result<Option<FeedbackBufferInfo>> {
        if index >= MAX_FEEDBACK_BUFFERS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "invalid feedback buffer index: {} (max {})",
                    index,
                    MAX_FEEDBACK_BUFFERS - 1
                ),
            ));
        }

        // Allocate space for the full response. The kernel reads the request from
        // the first 8 bytes and writes the larger response struct to the same address.
        let mut info = std::mem::MaybeUninit::<FeedbackBufferInfo>::uninit();

        // Write the request portion (first 8 bytes match FeedbackBufferInfoRequest layout)
        let request = FeedbackBufferInfoRequest {
            index: index as u32,
            _reserved: 0,
        };
        unsafe {
            std::ptr::copy_nonoverlapping(
                &request as *const FeedbackBufferInfoRequest as *const u8,
                info.as_mut_ptr() as *mut u8,
                std::mem::size_of::<FeedbackBufferInfoRequest>(),
            );
        }

        let ret = unsafe {
            libc::ioctl(
                self.fd.as_raw_fd(),
                BEDROCK_VM_GET_FEEDBACK_BUFFER_INFO as libc::c_ulong,
                info.as_mut_ptr(),
            )
        };

        if ret < 0 {
            return Err(io::Error::last_os_error());
        }

        // SAFETY: The ioctl succeeded and the kernel wrote FeedbackBufferInfo to the buffer
        let info = unsafe { info.assume_init() };

        if info.registered == 0 {
            Ok(None)
        } else {
            Ok(Some(info))
        }
    }

    /// Get feedback buffer registration info for index 0.
    ///
    /// This is a convenience method for backward compatibility.
    /// Returns `None` if no feedback buffer has been registered at index 0.
    pub fn get_feedback_buffer_info(&self) -> io::Result<Option<FeedbackBufferInfo>> {
        self.get_feedback_buffer_info_at(0)
    }

    /// Map the feedback buffer at the specified index into this process's address space.
    ///
    /// The guest must have registered a feedback buffer at this index via the
    /// HYPERCALL_REGISTER_FEEDBACK_BUFFER hypercall before calling this.
    ///
    /// For forked VMs, the feedback buffer pages are pre-COW'd (copied from parent)
    /// either at fork time (if registered before fork) or at registration time
    /// (if registered after fork). This ensures the mapped pages are stable and
    /// all guest writes are visible through the mapping without needing to remap.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Index is out of range (>= 16)
    /// - No feedback buffer has been registered at this index
    /// - The buffer is already mapped
    /// - The mmap syscall fails
    pub fn map_feedback_buffer_at(&mut self, index: usize) -> io::Result<&[u8]> {
        if index >= MAX_FEEDBACK_BUFFERS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "invalid feedback buffer index: {} (max {})",
                    index,
                    MAX_FEEDBACK_BUFFERS - 1
                ),
            ));
        }

        if self.feedback_buffer_ptrs[index].is_some() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("feedback buffer {} is already mapped", index),
            ));
        }

        let info = self.get_feedback_buffer_info_at(index)?.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("no feedback buffer registered at index {}", index),
            )
        })?;

        let size = info.num_pages as usize * 4096;
        let offset = self.feedback_buffer_mmap_offset_at(index);

        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                size,
                libc::PROT_READ,
                libc::MAP_SHARED,
                self.fd.as_raw_fd(),
                offset,
            )
        };

        if ptr == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }

        let ptr = unsafe { NonNull::new_unchecked(ptr as *mut u8) };
        self.feedback_buffer_ptrs[index] = Some(ptr);
        self.feedback_buffer_sizes[index] = size;

        Ok(unsafe { slice::from_raw_parts(ptr.as_ptr(), size) })
    }

    /// Map the feedback buffer at index 0 into this process's address space.
    ///
    /// This is a convenience method for backward compatibility.
    pub fn map_feedback_buffer(&mut self) -> io::Result<&[u8]> {
        self.map_feedback_buffer_at(0)
    }

    /// Unmap the feedback buffer at the specified index if mapped.
    ///
    /// This is called automatically when the VM is dropped, but can be called
    /// manually to free the mapping early.
    pub fn unmap_feedback_buffer_at(&mut self, index: usize) {
        if index >= MAX_FEEDBACK_BUFFERS {
            return;
        }

        if let Some(ptr) = self.feedback_buffer_ptrs[index].take() {
            unsafe {
                libc::munmap(
                    ptr.as_ptr() as *mut libc::c_void,
                    self.feedback_buffer_sizes[index],
                );
            }
            self.feedback_buffer_sizes[index] = 0;
        }
    }

    /// Unmap the feedback buffer at index 0 if mapped.
    ///
    /// This is a convenience method for backward compatibility.
    pub fn unmap_feedback_buffer(&mut self) {
        self.unmap_feedback_buffer_at(0);
    }

    /// Get the feedback buffer at the specified index as a slice, if mapped.
    pub fn feedback_buffer_at(&self, index: usize) -> Option<&[u8]> {
        if index >= MAX_FEEDBACK_BUFFERS {
            return None;
        }

        self.feedback_buffer_ptrs[index].map(|ptr| unsafe {
            slice::from_raw_parts(ptr.as_ptr(), self.feedback_buffer_sizes[index])
        })
    }

    /// Get the feedback buffer at index 0 as a slice, if mapped.
    ///
    /// This is a convenience method for backward compatibility.
    pub fn feedback_buffer(&self) -> Option<&[u8]> {
        self.feedback_buffer_at(0)
    }

    /// Compute the mmap offset for the feedback buffer at the specified index.
    fn feedback_buffer_mmap_offset_at(&self, index: usize) -> libc::off_t {
        const FEEDBACK_BUFFER_SLOT_SIZE: usize = 1024 * 1024; // 1MB per slot

        let base_offset = if self.forked {
            // Forked VM layout: serial(0) + log(4096) + tsc(4096+1MB) + feedback_base(4096+1MB+4096)
            SERIAL_BUFFER_SIZE + LOG_BUFFER_SIZE + SERIAL_TSC_PAGE_SIZE
        } else {
            // Root VM layout: mem(0) + serial(mem_size) + log(mem_size+4096) + tsc(mem_size+4096+1MB) + feedback_base(...)
            self.memory_size + SERIAL_BUFFER_SIZE + LOG_BUFFER_SIZE + SERIAL_TSC_PAGE_SIZE
        };

        (base_offset + index * FEEDBACK_BUFFER_SLOT_SIZE) as libc::off_t
    }

    // --- Execution control ---

    /// Set the TSC value at which the VM should stop.
    pub fn set_stop_at_tsc(&self, tsc: Option<u64>) -> io::Result<()> {
        let value = tsc.unwrap_or(0);

        let ret = unsafe {
            libc::ioctl(
                self.fd.as_raw_fd(),
                BEDROCK_VM_SET_STOP_TSC as libc::c_ulong,
                &value as *const u64,
            )
        };

        if ret < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(())
    }

    /// Enable single-stepping (MTF) for a specific TSC range.
    pub fn set_single_step_range(&self, tsc_start: u64, tsc_end: u64) -> io::Result<()> {
        let config = SingleStepConfig {
            enabled: 1,
            tsc_start,
            tsc_end,
        };

        let ret = unsafe {
            libc::ioctl(
                self.fd.as_raw_fd(),
                BEDROCK_VM_SET_SINGLE_STEP as libc::c_ulong,
                &config as *const SingleStepConfig,
            )
        };

        if ret < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(())
    }

    /// Disable single-stepping (MTF).
    pub fn disable_single_step(&self) -> io::Result<()> {
        let config = SingleStepConfig {
            enabled: 0,
            tsc_start: 0,
            tsc_end: 0,
        };

        let ret = unsafe {
            libc::ioctl(
                self.fd.as_raw_fd(),
                BEDROCK_VM_SET_SINGLE_STEP as libc::c_ulong,
                &config as *const SingleStepConfig,
            )
        };

        if ret < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(())
    }

    // --- Statistics ---

    /// Get the unique VM identifier.
    pub fn get_vm_id(&self) -> io::Result<u64> {
        let mut vm_id: u64 = 0;

        let ret = unsafe {
            libc::ioctl(
                self.fd.as_raw_fd(),
                BEDROCK_VM_GET_VM_ID as libc::c_ulong,
                &mut vm_id as *mut u64,
            )
        };

        if ret < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(vm_id)
    }

    /// Retrieve exit handler performance statistics.
    pub fn get_exit_stats(&self) -> io::Result<ExitStats> {
        let mut stats = ExitStats::default();

        let ret = unsafe {
            libc::ioctl(
                self.fd.as_raw_fd(),
                BEDROCK_VM_GET_EXIT_STATS as libc::c_ulong,
                &mut stats as *mut ExitStats,
            )
        };

        if ret < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(stats)
    }

    /// Get userspace ioctl timing statistics.
    pub fn get_ioctl_stats(&self) -> IoctlStats {
        self.ioctl_stats.get()
    }

    /// Record ioctl timing using a closure.
    fn record_ioctl_time<F: FnOnce(&mut IoctlStats)>(&self, f: F) {
        let mut stats = self.ioctl_stats.get();
        f(&mut stats);
        self.ioctl_stats.set(stats);
    }

    // --- Convenience methods ---

    /// Get log entries from the log buffer.
    ///
    /// Returns a slice of the first `count` log entries, or all entries if
    /// `count` exceeds the available entries.
    pub fn log_entries(&self, count: usize) -> &[crate::LogEntry] {
        self.log_buffer()
            .map(|buf| crate::LogEntry::from_buffer(buf, count))
            .unwrap_or(&[])
    }

    /// Modify registers using a closure.
    ///
    /// This is a convenience method that reads registers, applies the closure,
    /// and writes them back.
    pub fn modify_regs<F: FnOnce(&mut Regs)>(&self, f: F) -> io::Result<()> {
        let mut regs = self.get_regs()?;
        f(&mut regs);
        self.set_regs(&regs)
    }

    /// Get the current instruction pointer (RIP).
    pub fn rip(&self) -> io::Result<u64> {
        Ok(self.get_regs()?.rip)
    }

    /// Set the instruction pointer (RIP).
    pub fn set_rip(&self, value: u64) -> io::Result<()> {
        self.modify_regs(|r| r.rip = value)
    }

    /// Get the current stack pointer (RSP).
    pub fn rsp(&self) -> io::Result<u64> {
        Ok(self.get_regs()?.gprs.rsp)
    }

    /// Set the stack pointer (RSP).
    pub fn set_rsp(&self, value: u64) -> io::Result<()> {
        self.modify_regs(|r| r.gprs.rsp = value)
    }

    /// Get the RAX register.
    pub fn rax(&self) -> io::Result<u64> {
        Ok(self.get_regs()?.gprs.rax)
    }

    /// Set the RAX register.
    pub fn set_rax(&self, value: u64) -> io::Result<()> {
        self.modify_regs(|r| r.gprs.rax = value)
    }

    /// Get the RBX register.
    pub fn rbx(&self) -> io::Result<u64> {
        Ok(self.get_regs()?.gprs.rbx)
    }

    /// Set the RBX register.
    pub fn set_rbx(&self, value: u64) -> io::Result<()> {
        self.modify_regs(|r| r.gprs.rbx = value)
    }

    /// Get the RCX register.
    pub fn rcx(&self) -> io::Result<u64> {
        Ok(self.get_regs()?.gprs.rcx)
    }

    /// Set the RCX register.
    pub fn set_rcx(&self, value: u64) -> io::Result<()> {
        self.modify_regs(|r| r.gprs.rcx = value)
    }

    /// Get the RDX register.
    pub fn rdx(&self) -> io::Result<u64> {
        Ok(self.get_regs()?.gprs.rdx)
    }

    /// Set the RDX register.
    pub fn set_rdx(&self, value: u64) -> io::Result<()> {
        self.modify_regs(|r| r.gprs.rdx = value)
    }

    /// Get the RDI register.
    pub fn rdi(&self) -> io::Result<u64> {
        Ok(self.get_regs()?.gprs.rdi)
    }

    /// Set the RDI register.
    pub fn set_rdi(&self, value: u64) -> io::Result<()> {
        self.modify_regs(|r| r.gprs.rdi = value)
    }

    /// Get the RSI register.
    pub fn rsi(&self) -> io::Result<u64> {
        Ok(self.get_regs()?.gprs.rsi)
    }

    /// Set the RSI register.
    pub fn set_rsi(&self, value: u64) -> io::Result<()> {
        self.modify_regs(|r| r.gprs.rsi = value)
    }

    /// Get the RFLAGS register.
    pub fn rflags(&self) -> io::Result<u64> {
        Ok(self.get_regs()?.rflags)
    }

    /// Set the RFLAGS register.
    pub fn set_rflags(&self, value: u64) -> io::Result<()> {
        self.modify_regs(|r| r.rflags = value)
    }
}

#[cfg(test)]
#[path = "vm_tests.rs"]
mod tests;
