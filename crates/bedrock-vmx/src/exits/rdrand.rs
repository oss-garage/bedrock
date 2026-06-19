// SPDX-License-Identifier: GPL-2.0

//! RDRAND/RDSEED VM exit handlers.
//!
//! These handlers emulate the RDRAND and RDSEED instructions based on the
//! configured emulation mode in the VM's RandomState.

#[cfg(not(feature = "cargo"))]
use super::super::prelude::*;
#[cfg(feature = "cargo")]
use crate::prelude::*;

use super::helpers::{advance_rip, emit_randomness_event, ExitError, ExitHandlerResult};
use super::qualifications::{RdrandInstructionInfo, RdrandOperandSize};
use super::reasons::ExitReason;

/// Read the instruction information for RDRAND/RDSEED from VMCS.
fn read_instruction_info<C: VmContext>(ctx: &C) -> Result<RdrandInstructionInfo, ExitError> {
    let info = ctx
        .state()
        .vmcs
        .read32(VmcsField32::VmExitInstructionInfo)
        .map_err(|_| ExitError::Fatal("Failed to read VM-exit instruction info"))?;
    Ok(RdrandInstructionInfo::from(info))
}

/// Write a value to a general-purpose register by index.
///
/// The value is masked and zero-extended based on the operand size.
fn write_gpr_by_index(
    gprs: &mut GeneralPurposeRegisters,
    index: u8,
    value: u64,
    size: RdrandOperandSize,
) {
    // Apply mask based on operand size
    let masked_value = match size {
        RdrandOperandSize::Size16 => value & 0xFFFF,
        RdrandOperandSize::Size32 => value & 0xFFFF_FFFF,
        RdrandOperandSize::Size64 => value,
    };

    // For 32-bit operations, the upper 32 bits are zeroed
    // For 16-bit operations, we preserve the upper bits
    let reg = match index {
        0 => &mut gprs.rax,
        1 => &mut gprs.rcx,
        2 => &mut gprs.rdx,
        3 => &mut gprs.rbx,
        4 => &mut gprs.rsp,
        5 => &mut gprs.rbp,
        6 => &mut gprs.rsi,
        7 => &mut gprs.rdi,
        8 => &mut gprs.r8,
        9 => &mut gprs.r9,
        10 => &mut gprs.r10,
        11 => &mut gprs.r11,
        12 => &mut gprs.r12,
        13 => &mut gprs.r13,
        14 => &mut gprs.r14,
        15 => &mut gprs.r15,
        _ => return, // Invalid register, shouldn't happen
    };

    match size {
        RdrandOperandSize::Size16 => {
            // Preserve upper 48 bits, update lower 16 bits
            *reg = (*reg & !0xFFFF) | masked_value;
        }
        RdrandOperandSize::Size32 => {
            // Zero-extend 32-bit result to 64 bits
            *reg = masked_value;
        }
        RdrandOperandSize::Size64 => {
            // Full 64-bit value
            *reg = masked_value;
        }
    }
}

/// Set the CF flag in RFLAGS to indicate RDRAND success.
///
/// RDRAND sets CF=1 on success, CF=0 on failure (underflow).
/// We always succeed, so we set CF=1.
fn set_cf_flag<C: VmContext>(ctx: &mut C, cf: bool) -> Result<(), ExitError> {
    let rflags = ctx
        .state()
        .vmcs
        .read_natural(VmcsFieldNatural::GuestRflags)
        .map_err(|_| ExitError::Fatal("Failed to read guest RFLAGS"))?;

    // CF is bit 0 of RFLAGS
    let new_rflags = if cf { rflags | 0x1 } else { rflags & !0x1 };

    ctx.state()
        .vmcs
        .write_natural(VmcsFieldNatural::GuestRflags, new_rflags)
        .map_err(|_| ExitError::Fatal("Failed to write guest RFLAGS"))?;

    Ok(())
}

/// Handle RDRAND VM exit.
///
/// Emulates the RDRAND instruction based on the VM's RandomState configuration.
/// Returns a generated random value and advances RIP on success.
/// If the mode is ExitToUserspace and no pending value is available,
/// exits to userspace to let it provide the value.
pub fn handle_rdrand<C: VmContext>(ctx: &mut C) -> ExitHandlerResult {
    handle_random(ctx, RandomSource::Rdrand)
}

/// Shared RDRAND/RDSEED emulation, parameterized by which instruction faulted
/// so the emitted `Randomness` event records the correct source.
fn handle_random<C: VmContext>(ctx: &mut C, source: RandomSource) -> ExitHandlerResult {
    let info = match read_instruction_info(ctx) {
        Ok(i) => i,
        Err(e) => return ExitHandlerResult::Error(e),
    };

    // Check if we need to exit to userspace (ExitToUserspace mode without pending value)
    if ctx.state().devices.random.needs_rdrand_exit() {
        // Don't advance RIP - userspace will provide the value and we'll re-execute
        return ExitHandlerResult::ExitToUserspace(ExitReason::Rdrand);
    }

    // Generate the random value
    let value = match ctx.state_mut().devices.random.generate() {
        Some(v) => v,
        None => {
            // This shouldn't happen if needs_rdrand_exit() was checked above
            return ExitHandlerResult::ExitToUserspace(ExitReason::Rdrand);
        }
    };

    // Record the served value as a determinism *input* on the unified
    // randomness event stream (RDRAND/RDSEED carry the value inline; no trailing
    // bytes). Same emit path as HYPERCALL_GET_RANDOM — only the source differs.
    let width: u8 = match info.operand_size {
        RdrandOperandSize::Size16 => 2,
        RdrandOperandSize::Size32 => 4,
        RdrandOperandSize::Size64 => 8,
    };
    let payload = RandomPayload {
        value,
        source: source as u8,
        width,
        ..RandomPayload::default()
    };
    emit_randomness_event(ctx, &payload, &[]);

    // Write the value to the destination register
    write_gpr_by_index(
        &mut ctx.state_mut().gprs,
        info.dest_reg,
        value,
        info.operand_size,
    );

    // Set CF=1 to indicate success
    if let Err(e) = set_cf_flag(ctx, true) {
        return ExitHandlerResult::Error(e);
    }

    // Advance RIP past the RDRAND instruction
    if let Err(e) = advance_rip(ctx) {
        return ExitHandlerResult::Error(e);
    }

    ExitHandlerResult::Continue
}

/// Handle RDSEED VM exit.
///
/// RDSEED is handled identically to RDRAND in our emulation.
/// The only difference is that RDSEED is intended to return true random
/// seeds, while RDRAND returns pseudo-random values. Since we're emulating
/// both with the same RNG, they behave the same.
pub fn handle_rdseed<C: VmContext>(ctx: &mut C) -> ExitHandlerResult {
    // RDSEED uses the same logic as RDRAND; only the recorded source differs.
    handle_random(ctx, RandomSource::Rdseed)
}

#[cfg(test)]
#[path = "rdrand_tests.rs"]
mod tests;
