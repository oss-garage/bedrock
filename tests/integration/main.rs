//! bedrock high-level integration tests.
//!
//! All tests live in this single binary so the guest boots exactly once and
//! every test forks its own branch off the shared ready checkpoint. See
//! [`common`] for the harness, how the guest is sourced, and how tests skip
//! when no VM is available.

// Define the virtual-time macros (`vt!`, `vt_dur!`, `tsc!`, `tsc_dur!`) at
// crate root, before the modules below, so every test module sees them via
// textual macro scoping. All times are reckoned against the emulated TSC.
bedrock_lab::define_virt_time_macros!($, bedrock_vm::DEFAULT_TSC_FREQUENCY);

mod common;

mod bash_io;
mod boot;
mod coverage;
mod determinism;
mod feedback;
mod file_store;
mod file_xfer;
mod rng;
mod workload_monitor;
