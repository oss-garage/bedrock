// SPDX-License-Identifier: GPL-2.0

//! Userland API for interacting with bedrock VMs.
//!
//! This crate provides a safe Rust interface for userspace programs to interact
//! with VMs created by the bedrock kernel module. It handles:
//!
//! - VM creation (root and forked with copy-on-write)
//! - Memory mapping of guest physical memory
//! - Register access via ioctls
//! - Deterministic execution (RDRAND emulation, TSC control, logging)
//! - Proper cleanup on drop
//!
//! # Creating a VM with VmBuilder
//!
//! The recommended way to create VMs is using [`VmBuilder`]:
//!
//! ```ignore
//! use bedrock_vm::{VmBuilder, RdrandConfig, LogConfig};
//!
//! let mut vm = VmBuilder::new()
//!     .memory_mb(64)
//!     .rdrand(RdrandConfig::seeded_rng(0xdeadbeef))
//!     .logging(LogConfig::all_exits(0))
//!     .build()?;
//!
//! // Write code to guest memory
//! let memory = vm.memory_mut()?;
//! memory[0x1000..0x1010].copy_from_slice(&guest_code);
//!
//! // Set initial registers
//! vm.set_rip(0x1000)?;
//! ```
//!
//! # Forking VMs
//!
//! Forked VMs share memory with their parent using copy-on-write:
//!
//! ```ignore
//! // Create parent VM and run to a snapshot point
//! let parent = VmBuilder::new()
//!     .memory_mb(64)
//!     .stop_at_tsc(1_000_000)
//!     .build()?;
//!
//! // ... run parent to snapshot point ...
//!
//! let parent_id = parent.get_vm_id()?;
//!
//! // Fork from parent - shares memory via COW
//! let child = VmBuilder::new()
//!     .forked_from(parent_id)
//!     .rdrand(RdrandConfig::seeded_rng(42))
//!     .build()?;
//! ```
//!
//! # Run Loop with ExitKind
//!
//! Use [`ExitKind`] for clean exit handling:
//!
//! ```ignore
//! use bedrock_vm::ExitKind;
//!
//! loop {
//!     let exit = vm.run()?;
//!
//!     // Handle serial output
//!     if exit.serial_len > 0 {
//!         print!("{}", vm.serial_output_str(exit.serial_len as usize));
//!     }
//!
//!     match exit.kind() {
//!         ExitKind::VmcallShutdown => {
//!             println!("Clean shutdown");
//!             break;
//!         }
//!         ExitKind::Continue | ExitKind::LogBufferFull => continue,
//!         kind => {
//!             println!("Unexpected exit: {:?}", kind);
//!             break;
//!         }
//!     }
//! }
//! ```
//!
//! # Deterministic Execution
//!
//! Configure RDRAND for reproducible execution:
//!
//! ```ignore
//! use bedrock_vm::RdrandConfig;
//!
//! // Use a seeded PRNG for reproducible sequences
//! let config = RdrandConfig::seeded_rng(seed);
//!
//! // Exit to userspace for custom handling
//! let config = RdrandConfig::exit_to_userspace();
//! ```
//!
//! # Logging and Debugging
//!
//! Enable exit logging for debugging:
//!
//! ```ignore
//! use bedrock_vm::LogConfig;
//!
//! // Log all exits
//! let config = LogConfig::all_exits(0);
//!
//! // Log only at specific TSC
//! let config = LogConfig::at_tsc(target_tsc);
//!
//! // Log at regular intervals
//! let config = LogConfig::checkpoints(interval);
//!
//! // Single-step through a TSC range
//! let vm = VmBuilder::new()
//!     .single_step(start_tsc, end_tsc)
//!     .logging(LogConfig::tsc_range())
//!     .build()?;
//! ```

pub mod boot;
mod builder;
mod error;
mod logging;
mod rdrand;
mod registers;
mod vm;

pub use boot::{load_kernel, LinuxBootConfig, LinuxBootInfo};
pub use builder::VmBuilder;
pub use error::VmError;
pub use logging::{
    write_jsonl, write_jsonl_file, LogEntry, LOG_ENTRY_FLAG_DETERMINISTIC, LOG_ENTRY_SIZE,
    MAX_LOG_ENTRIES,
};
pub use rdrand::{RdrandConfig, RdrandExitInfo, RdrandMode, RdrandValue};
pub use registers::*;
pub use vm::{
    parse_line_tsc_entries, ExitKind, ExitStatEntry, ExitStats, ExitStatsReport,
    FeedbackBufferInfo, IoctlStats, LineTscEntry, LogConfig, LogMode, SingleStepConfig, Vm, VmExit,
    BEDROCK_DEVICE_PATH, DEFAULT_MEMORY_SIZE, DEFAULT_TSC_FREQUENCY, EXIT_REASON_CHECKPOINT,
    LOG_BUFFER_SIZE, MAX_FEEDBACK_BUFFERS, SERIAL_BUFFER_SIZE,
};
