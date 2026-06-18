// SPDX-License-Identifier: GPL-2.0

//! Assertion primitives for bedrock.
//!
//! An [`Assertion`] checks a [`Condition`] about guest execution. The
//! assertion variant ([`Assertion::Always`] / [`Assertion::Sometimes`])
//! determines how the condition is interpreted across evaluations. Each record
//! is self-describing: alongside the [`Condition`]'s operands it carries the
//! evaluated result, an obligatory message, and the source [`Location`] of the
//! macro that built it (all in [`AssertionData`]).
//!
//! Build them with the `always_*` / `sometimes_*` macros, which take a trailing
//! message and capture the call site. All types are serializable via serde.
//! This crate does not run inside the kernel module.

#[macro_use]
mod macros;
mod assertion;
mod condition;

pub use assertion::{Assertion, AssertionData, Location};
pub use condition::Condition;
