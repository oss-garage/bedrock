// SPDX-License-Identifier: GPL-2.0

//! Userland API for interacting with bedrock VMs.
//!
//! This crate provides a safe Rust interface for userspace programs to interact
//! with VMs created by the bedrock kernel module. It handles:
//!
//! - VM creation (root and forked with copy-on-write)
//! - Memory mapping of guest physical memory
//! - Register access via ioctls
//! - Deterministic execution (RDRAND emulation, TSC control, event capture)
//! - Proper cleanup on drop
//!
//! # Creating a VM with VmBuilder
//!
//! The recommended way to create VMs is using [`VmBuilder`]:
//!
//! ```ignore
//! use bedrock_vm::{VmBuilder, RdrandConfig};
//!
//! let mut vm = VmBuilder::new()
//!     .memory_mb(64)
//!     .rdrand(RdrandConfig::seeded_rng(0xdeadbeef))
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
//!     // Guest serial output arrives as `Serial` records in the event buffer
//!     // (`buffer[0..exit.event_len]`); see the `events` module.
//!     match exit.kind() {
//!         ExitKind::VmcallShutdown => {
//!             println!("Clean shutdown");
//!             break;
//!         }
//!         ExitKind::Continue | ExitKind::EventBufferFull => continue,
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
//! # Capturing exits via the event stream
//!
//! `Exit` records are part of the unified event stream. Enable the stream with
//! the [`EXIT`](EventCategories::EXIT) category and an [`ExitTrigger`]:
//!
//! ```ignore
//! use bedrock_vm::{EventCategories, EventConfig, ExitTrigger};
//!
//! // Capture every exit:
//! let config = EventConfig::enabled(EventCategories::EXIT)
//!     .with_exit_trigger(ExitTrigger::AllExits, 0);
//!
//! // Capture one record at a target TSC:
//! let config = EventConfig::enabled(EventCategories::EXIT)
//!     .with_exit_trigger(ExitTrigger::AtTsc, target_tsc);
//!
//! // Capture checkpoints at regular intervals:
//! let config = EventConfig::enabled(EventCategories::EXIT)
//!     .with_exit_trigger(ExitTrigger::Checkpoints, interval);
//!
//! vm.set_event_config(&config)?;
//! ```

pub mod boot;
mod builder;
pub mod console;
mod error;
pub mod events;
pub mod file_store;
pub mod file_xfer;
pub mod io_channel;
mod rdrand;
mod registers;
mod vm;

pub use bedrock_vmx::exit_record::{ExitRecord, EXIT_RECORD_FLAG_DETERMINISTIC, EXIT_RECORD_SIZE};
pub use boot::{load_kernel, LinuxBootConfig, LinuxBootInfo};
pub use builder::VmBuilder;
pub use console::ConsoleLine;
pub use error::VmError;
pub use events::{
    category_of, write_jsonl as write_events_jsonl,
    write_jsonl_filtered as write_events_jsonl_filtered, Event, EventBody, EventCategories,
    EventJson, EventRecord, EventStream,
};
pub use rdrand::{RdrandConfig, RdrandExitInfo, RdrandMode, RdrandValue};
pub use registers::*;
pub use vm::{
    EventConfig, ExitKind, ExitStatEntry, ExitStats, ExitStatsReport, ExitTrigger,
    FeedbackBufferInfo, IoctlStats, SingleStepConfig, Vm, VmExit, BEDROCK_DEVICE_PATH,
    DEFAULT_MEMORY_SIZE, DEFAULT_TSC_FREQUENCY, EVENT_BUFFER_SIZE, EXIT_REASON_CHECKPOINT,
};
