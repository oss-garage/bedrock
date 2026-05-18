// SPDX-License-Identifier: GPL-2.0

use super::*;
use crate::tests::MockVmContext;

#[test]
fn test_rdrand_instruction_info_parsing() {
    // Test parsing for RDRAND EAX (32-bit, register 0)
    // Bits 6:3 = 0 (RAX), Bits 12:11 = 1 (32-bit)
    // Value = (1 << 11) | (0 << 3) = 0x800
    let info = RdrandInstructionInfo::from(0x800);
    assert_eq!(info.dest_reg, 0);
    assert_eq!(info.operand_size, RdrandOperandSize::Size32);

    // Test parsing for RDRAND RCX (64-bit, register 1)
    // Bits 6:3 = 1 (RCX), Bits 12:11 = 2 (64-bit)
    // Value = (2 << 11) | (1 << 3) = 0x1000 | 0x8 = 0x1008
    let info = RdrandInstructionInfo::from(0x1008);
    assert_eq!(info.dest_reg, 1);
    assert_eq!(info.operand_size, RdrandOperandSize::Size64);

    // Test parsing for RDRAND R8W (16-bit, register 8)
    // Bits 6:3 = 8 (R8), Bits 12:11 = 0 (16-bit)
    // Value = (0 << 11) | (8 << 3) = 0x40
    let info = RdrandInstructionInfo::from(0x40);
    assert_eq!(info.dest_reg, 8);
    assert_eq!(info.operand_size, RdrandOperandSize::Size16);
}

#[test]
fn test_rdrand_seeded_rng_mode() {
    let mut ctx = MockVmContext::new();
    ctx.state_mut()
        .devices
        .rdrand
        .configure(RdrandMode::SeededRng, 12345);
    ctx.set_exit_reason(ExitReason::Rdrand);
    ctx.set_instruction_len(3);
    ctx.set_guest_rip(0x1000);
    ctx.set_instruction_info(0x1000); // RDRAND RAX 64-bit: (2 << 11) | (0 << 3)
    ctx.set_guest_rflags(0x2);

    let result = handle_rdrand(&mut ctx);
    assert!(matches!(result, ExitHandlerResult::Continue));

    let first_value = ctx.state().gprs.rax;

    // Reset for second call
    ctx.set_guest_rip(0x1003);
    let result = handle_rdrand(&mut ctx);
    assert!(matches!(result, ExitHandlerResult::Continue));

    let second_value = ctx.state().gprs.rax;

    // Values should be different (RNG advancing)
    assert_ne!(first_value, second_value);
}

#[test]
fn test_rdrand_exit_to_userspace_mode() {
    let mut ctx = MockVmContext::new();
    ctx.state_mut()
        .devices
        .rdrand
        .configure(RdrandMode::ExitToUserspace, 0);
    ctx.set_exit_reason(ExitReason::Rdrand);
    ctx.set_instruction_len(3);
    ctx.set_guest_rip(0x1000);
    ctx.set_instruction_info(0x1000); // RDRAND RAX 64-bit: (2 << 11) | (0 << 3)
    ctx.set_guest_rflags(0x2);

    // First call should exit to userspace (no pending value)
    let result = handle_rdrand(&mut ctx);
    assert!(matches!(
        result,
        ExitHandlerResult::ExitToUserspace(ExitReason::Rdrand)
    ));
    // RIP should NOT be advanced
    assert_eq!(ctx.get_guest_rip(), Some(0x1000));

    // Set pending value and try again
    ctx.state_mut().devices.rdrand.set_pending_value(0x42424242);
    let result = handle_rdrand(&mut ctx);
    assert!(matches!(result, ExitHandlerResult::Continue));

    // Now RAX should have the pending value
    assert_eq!(ctx.state().gprs.rax, 0x42424242);
    // RIP should be advanced
    assert_eq!(ctx.get_guest_rip(), Some(0x1003));
}

#[test]
fn test_rdrand_32bit_operation() {
    let mut ctx = MockVmContext::new();
    ctx.state_mut()
        .devices
        .rdrand
        .configure(RdrandMode::ExitToUserspace, 0);
    ctx.state_mut()
        .devices
        .rdrand
        .set_pending_value(0xFFFFFFFF_DEADBEEF);
    ctx.set_exit_reason(ExitReason::Rdrand);
    ctx.set_instruction_len(3);
    ctx.set_guest_rip(0x1000);
    // RDRAND EAX (32-bit, register 0): Bits 6:3 = 0, Bits 12:11 = 1
    // Value = (1 << 11) | (0 << 3) = 0x800
    ctx.set_instruction_info(0x800);
    ctx.set_guest_rflags(0x2);

    // Set RAX to have some upper bits set
    ctx.state_mut().gprs.rax = 0x12345678_00000000;

    let result = handle_rdrand(&mut ctx);
    assert!(matches!(result, ExitHandlerResult::Continue));

    // For 32-bit operation, result should be zero-extended (upper 32 bits cleared)
    assert_eq!(ctx.state().gprs.rax, 0xDEADBEEF);
}

#[test]
fn test_rdrand_16bit_operation() {
    let mut ctx = MockVmContext::new();
    ctx.state_mut()
        .devices
        .rdrand
        .configure(RdrandMode::ExitToUserspace, 0);
    ctx.state_mut()
        .devices
        .rdrand
        .set_pending_value(0xFFFFFFFF_DEADBEEF);
    ctx.set_exit_reason(ExitReason::Rdrand);
    ctx.set_instruction_len(4); // 16-bit RDRAND may be longer with prefix
    ctx.set_guest_rip(0x1000);
    // RDRAND AX (16-bit, register 0): Bits 6:3 = 0, Bits 12:11 = 0
    // Value = (0 << 11) | (0 << 3) = 0x0
    ctx.set_instruction_info(0x0);
    ctx.set_guest_rflags(0x2);

    // Set RAX to have upper bits set
    ctx.state_mut().gprs.rax = 0x12345678_AABBCCDD;

    let result = handle_rdrand(&mut ctx);
    assert!(matches!(result, ExitHandlerResult::Continue));

    // For 16-bit operation, upper 48 bits should be preserved
    assert_eq!(ctx.state().gprs.rax, 0x12345678_AABBBEEF);
}

#[test]
fn test_rdrand_r8_register() {
    let mut ctx = MockVmContext::new();
    ctx.state_mut()
        .devices
        .rdrand
        .configure(RdrandMode::ExitToUserspace, 0);
    ctx.state_mut().devices.rdrand.set_pending_value(0xCAFEBABE);
    ctx.set_exit_reason(ExitReason::Rdrand);
    ctx.set_instruction_len(4); // R8-R15 need REX prefix
    ctx.set_guest_rip(0x1000);
    // RDRAND R8D (32-bit, register 8): Bits 6:3 = 8, Bits 12:11 = 1
    // Value = (1 << 11) | (8 << 3) = 0x800 | 0x40 = 0x840
    ctx.set_instruction_info(0x840);
    ctx.set_guest_rflags(0x2);

    let result = handle_rdrand(&mut ctx);
    assert!(matches!(result, ExitHandlerResult::Continue));

    assert_eq!(ctx.state().gprs.r8, 0xCAFEBABE);
}
