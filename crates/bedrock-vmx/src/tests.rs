// SPDX-License-Identifier: GPL-2.0

//! Tests for VM exit handling.
//!
//! This module uses mock implementations from test_mocks for testing
//! exit handlers in userland.

extern crate std;

use std::string::String;
use std::vec::Vec;

use memory::GuestPhysAddr;

use crate::exits::{handle_exit, ExitError, ExitHandlerResult, ExitReason};
use crate::fields::{VmcsField32, VmcsFieldNatural};
use crate::registers::GeneralPurposeRegisters;
use crate::test_mocks::{MockFrameAllocator, MockKernel, MockPage, MockVmcs, MockVmx};
use crate::traits::{Kernel, MemoryError, NullInstructionCounter, VmContext};
use crate::vm_state::VmState;

/// Mock VM context for testing.
pub struct MockVmContext {
    state: VmState<MockVmcs, NullInstructionCounter>,
    /// Guest memory for reading/writing during tests.
    pub memory: std::vec::Vec<u8>,
}

impl MockVmContext {
    pub fn new() -> Self {
        let vmcs = MockVmcs::new();
        let mut allocator = MockFrameAllocator::new();
        let state = VmState::new_mock(vmcs, &mut allocator, &MockKernel, NullInstructionCounter)
            .expect("Failed to create mock VmState");

        Self {
            state,
            memory: std::vec![0u8; 0x10000], // 64KB of guest memory
        }
    }

    /// Set the emulated TSC value for testing.
    pub fn set_emulated_tsc(&mut self, value: u64) {
        self.state.emulated_tsc = value;
    }

    /// Set up exit reason in VMCS.
    pub fn set_exit_reason(&self, reason: ExitReason) {
        self.state
            .vmcs
            .set_field32(VmcsField32::VmExitReason, reason as u32);
    }

    /// Set up exit qualification in VMCS.
    pub fn set_exit_qualification(&self, qual: u64) {
        self.state
            .vmcs
            .set_field_natural(VmcsFieldNatural::ExitQualification, qual);
    }

    /// Set up guest RIP.
    pub fn set_guest_rip(&self, rip: u64) {
        self.state
            .vmcs
            .set_field_natural(VmcsFieldNatural::GuestRip, rip);
    }

    /// Get guest RIP.
    pub fn get_guest_rip(&self) -> Option<u64> {
        self.state
            .vmcs
            .get_field_natural(VmcsFieldNatural::GuestRip)
    }

    /// Set instruction length for current exit.
    pub fn set_instruction_len(&self, len: u32) {
        self.state
            .vmcs
            .set_field32(VmcsField32::VmExitInstructionLen, len);
    }

    /// Direct access to VMCS for test setup.
    pub fn vmcs_setup(&self) -> &MockVmcs {
        &self.state.vmcs
    }

    /// Set instruction information for current exit (for RDRAND/RDSEED testing).
    pub fn set_instruction_info(&self, info: u32) {
        self.state
            .vmcs
            .set_field32(VmcsField32::VmExitInstructionInfo, info);
    }

    /// Set guest RFLAGS.
    pub fn set_guest_rflags(&self, rflags: u64) {
        self.state
            .vmcs
            .set_field_natural(VmcsFieldNatural::GuestRflags, rflags);
    }

    /// Get mutable reference to GPRs.
    pub fn gprs_mut(&mut self) -> &mut GeneralPurposeRegisters {
        &mut self.state.gprs
    }

    /// Get reference to GPRs.
    pub fn gprs(&self) -> &GeneralPurposeRegisters {
        &self.state.gprs
    }
}

impl VmContext for MockVmContext {
    type Vmcs = MockVmcs;
    type V = MockVmx;
    type I = NullInstructionCounter;
    type CowPage = MockPage;

    fn state(&self) -> &VmState<Self::Vmcs, Self::I> {
        &self.state
    }

    fn state_mut(&mut self) -> &mut VmState<Self::Vmcs, Self::I> {
        &mut self.state
    }

    fn read_guest_memory(&self, gpa: GuestPhysAddr, buf: &mut [u8]) -> Result<(), MemoryError> {
        let start = gpa.as_u64() as usize;
        let end = start + buf.len();
        if end > self.memory.len() {
            return Err(MemoryError::OutOfRange);
        }
        buf.copy_from_slice(&self.memory[start..end]);
        Ok(())
    }

    fn write_guest_memory(&mut self, gpa: GuestPhysAddr, buf: &[u8]) -> Result<(), MemoryError> {
        let start = gpa.as_u64() as usize;
        let end = start + buf.len();
        if end > self.memory.len() {
            return Err(MemoryError::OutOfRange);
        }
        self.memory[start..end].copy_from_slice(buf);
        Ok(())
    }

    fn finalize_exit_record<K: Kernel>(&mut self, _kernel: &K) {
        // Mock does nothing for log finalization
    }
}

// =============================================================================
// Tests
// =============================================================================

#[test]
fn test_cpuid_exit_basic() {
    let mut ctx = MockVmContext::new();

    // Set up CPUID exit
    ctx.set_exit_reason(ExitReason::Cpuid);
    ctx.set_exit_qualification(0);
    ctx.set_guest_rip(0x1000);
    ctx.set_instruction_len(2); // CPUID is 2 bytes (0F A2)

    // Request leaf 0 (vendor ID)
    ctx.gprs_mut().rax = 0;
    ctx.gprs_mut().rcx = 0;

    let result = handle_exit(&mut ctx, &MockKernel, &mut MockFrameAllocator::new());

    // Should continue guest execution
    assert_eq!(result, ExitHandlerResult::Continue);

    // RIP should be advanced
    assert_eq!(ctx.get_guest_rip(), Some(0x1002));

    // EAX should have max supported leaf
    assert!(ctx.gprs().rax > 0);
}

#[test]
fn test_cpuid_leaf_1_feature_flags() {
    let mut ctx = MockVmContext::new();

    ctx.set_exit_reason(ExitReason::Cpuid);
    ctx.set_exit_qualification(0);
    ctx.set_guest_rip(0x1000);
    ctx.set_instruction_len(2);
    ctx.gprs_mut().rax = 1;
    ctx.gprs_mut().rcx = 0;

    let result = handle_exit(&mut ctx, &MockKernel, &mut MockFrameAllocator::new());
    assert_eq!(result, ExitHandlerResult::Continue);

    // Check ECX feature flags
    let ecx = ctx.gprs().rcx as u32;
    assert_eq!(ecx & (1 << 5), 0, "VMX bit should be hidden from guest");
    assert_ne!(ecx & (1 << 31), 0, "Hypervisor bit should be set");

    // Check EAX processor signature: Family 6, Model 85, Stepping 7
    let eax = ctx.gprs().rax as u32;
    let stepping = eax & 0xF;
    let model = ((eax >> 4) & 0xF) | (((eax >> 16) & 0xF) << 4);
    let family = (eax >> 8) & 0xF;
    assert_eq!(stepping, 7, "Stepping should be 7");
    assert_eq!(model, 85, "Model should be 85 (0x55)");
    assert_eq!(family, 6, "Family should be 6");
}

#[test]
fn test_cpuid_brand_string() {
    let mut ctx = MockVmContext::new();

    ctx.set_exit_reason(ExitReason::Cpuid);
    ctx.set_exit_qualification(0);
    ctx.set_guest_rip(0x1000);
    ctx.set_instruction_len(2);

    // Request brand string leafs
    let brand_leaves = [0x80000002, 0x80000003, 0x80000004];
    let mut brand_bytes = Vec::new();

    for &leaf in &brand_leaves {
        ctx.gprs_mut().rax = leaf;
        ctx.gprs_mut().rcx = 0;

        let result = handle_exit(&mut ctx, &MockKernel, &mut MockFrameAllocator::new());
        assert_eq!(result, ExitHandlerResult::Continue);

        // Collect EAX, EBX, ECX, EDX (lower 32 bits only)
        brand_bytes.extend_from_slice(&(ctx.gprs().rax as u32).to_le_bytes());
        brand_bytes.extend_from_slice(&(ctx.gprs().rbx as u32).to_le_bytes());
        brand_bytes.extend_from_slice(&(ctx.gprs().rcx as u32).to_le_bytes());
        brand_bytes.extend_from_slice(&(ctx.gprs().rdx as u32).to_le_bytes());
    }

    let brand_string = String::from_utf8(brand_bytes).unwrap();
    let expected_brand = "Bedrock VM CPU";
    assert!(
        brand_string.contains(expected_brand),
        "Brand string should contain expected: got '{}'",
        brand_string.trim_end_matches('\0').trim()
    );
}

#[test]
fn test_msr_read_exits_to_userspace() {
    let mut ctx = MockVmContext::new();

    ctx.set_exit_reason(ExitReason::MsrRead);
    ctx.set_exit_qualification(0);
    ctx.set_guest_rip(0x1000);
    ctx.set_instruction_len(2); // RDMSR is 2 bytes

    // Request IA32_EFER (0xC0000080)
    ctx.gprs_mut().rcx = 0xC0000080;

    let result = handle_exit(&mut ctx, &MockKernel, &mut MockFrameAllocator::new());

    // Should exit to userspace for MSR handling
    assert_eq!(
        result,
        ExitHandlerResult::ExitToUserspace(ExitReason::MsrRead)
    );

    // RIP should be advanced past the instruction
    assert_eq!(ctx.get_guest_rip(), Some(0x1002));
}

#[test]
fn test_msr_write_exits_to_userspace() {
    let mut ctx = MockVmContext::new();

    ctx.set_exit_reason(ExitReason::MsrWrite);
    ctx.set_exit_qualification(0);
    ctx.set_guest_rip(0x1000);
    ctx.set_instruction_len(2); // WRMSR is 2 bytes

    // Write to IA32_EFER
    ctx.gprs_mut().rcx = 0xC0000080;
    ctx.gprs_mut().rax = 0x501; // LME, LMA, SCE
    ctx.gprs_mut().rdx = 0;

    let result = handle_exit(&mut ctx, &MockKernel, &mut MockFrameAllocator::new());

    // Should exit to userspace for MSR handling
    assert_eq!(
        result,
        ExitHandlerResult::ExitToUserspace(ExitReason::MsrWrite)
    );

    // RIP should be advanced past the instruction
    assert_eq!(ctx.get_guest_rip(), Some(0x1002));
}

#[test]
fn test_cr_access_mov_to_cr3() {
    let mut ctx = MockVmContext::new();

    ctx.set_exit_reason(ExitReason::CrAccess);
    // Exit qualification: CR3, MOV to CR, register RAX
    // Bits 3:0 = 3 (CR3), bits 5:4 = 0 (MOV to CR), bits 11:8 = 0 (RAX)
    ctx.set_exit_qualification(0x3);
    ctx.set_guest_rip(0x1000);
    ctx.set_instruction_len(3);

    // RAX contains new CR3 value
    ctx.gprs_mut().rax = 0x12345000;

    let result = handle_exit(&mut ctx, &MockKernel, &mut MockFrameAllocator::new());
    assert_eq!(result, ExitHandlerResult::Continue);

    // Verify CR3 was updated
    let cr3 = ctx
        .vmcs_setup()
        .get_field_natural(VmcsFieldNatural::GuestCr3);
    assert_eq!(cr3, Some(0x12345000));
}

#[test]
fn test_cr_access_mov_from_cr0() {
    let mut ctx = MockVmContext::new();

    // Set CR0 value
    ctx.vmcs_setup()
        .set_field_natural(VmcsFieldNatural::GuestCr0, 0x80000011);

    ctx.set_exit_reason(ExitReason::CrAccess);
    // Exit qualification: CR0, MOV from CR, register RBX
    // Bits 3:0 = 0 (CR0), bits 5:4 = 1 (MOV from CR), bits 11:8 = 3 (RBX)
    ctx.set_exit_qualification(0x310);
    ctx.set_guest_rip(0x1000);
    ctx.set_instruction_len(3);

    let result = handle_exit(&mut ctx, &MockKernel, &mut MockFrameAllocator::new());
    assert_eq!(result, ExitHandlerResult::Continue);

    // Verify RBX contains CR0 value
    assert_eq!(ctx.gprs().rbx, 0x80000011);
}

#[test]
fn test_io_in_serial_status() {
    let mut ctx = MockVmContext::new();

    ctx.set_exit_reason(ExitReason::IoInstruction);
    // Exit qualification for IN from port 0x3FD (serial line status), 1 byte
    // Bits 2:0 = 0 (1 byte), bit 3 = 1 (IN), bits 31:16 = 0x3FD
    ctx.set_exit_qualification(0x03FD0008);
    ctx.set_guest_rip(0x1000);
    ctx.set_instruction_len(2);

    let result = handle_exit(&mut ctx, &MockKernel, &mut MockFrameAllocator::new());
    assert_eq!(result, ExitHandlerResult::Continue);

    // Should return 0x60 (transmitter empty and ready)
    assert_eq!(ctx.gprs().rax & 0xFF, 0x60);
}

#[test]
fn test_hlt_exit() {
    let mut ctx = MockVmContext::new();

    ctx.set_exit_reason(ExitReason::Hlt);
    ctx.set_exit_qualification(0);
    ctx.set_guest_rip(0x1000);
    ctx.set_instruction_len(1); // HLT is 1 byte

    let result = handle_exit(&mut ctx, &MockKernel, &mut MockFrameAllocator::new());

    // HLT should continue (like MWAIT) - advances TSC to timer deadline
    assert_eq!(result, ExitHandlerResult::Continue);

    // RIP should be advanced past HLT
    assert_eq!(ctx.get_guest_rip(), Some(0x1001));
}

#[test]
fn test_triple_fault() {
    let mut ctx = MockVmContext::new();

    ctx.set_exit_reason(ExitReason::TripleFault);
    ctx.set_exit_qualification(0);
    ctx.set_guest_rip(0x1000);
    ctx.set_instruction_len(0);

    let result = handle_exit(&mut ctx, &MockKernel, &mut MockFrameAllocator::new());

    // Triple fault should be an error
    assert!(matches!(
        result,
        ExitHandlerResult::Error(ExitError::TripleFault)
    ));
}

#[test]
fn test_ept_violation_exits_to_userspace() {
    let mut ctx = MockVmContext::new();

    ctx.set_exit_reason(ExitReason::EptViolation);
    // EPT violation qualification: read access, page not present
    ctx.set_exit_qualification(0x1);
    ctx.set_guest_rip(0x1000);
    ctx.set_instruction_len(0);

    let result = handle_exit(&mut ctx, &MockKernel, &mut MockFrameAllocator::new());

    // EPT violation should exit to userspace
    assert_eq!(
        result,
        ExitHandlerResult::ExitToUserspace(ExitReason::EptViolation)
    );
}

#[test]
fn test_vmcall_shutdown_hypercall() {
    let mut ctx = MockVmContext::new();

    ctx.set_exit_reason(ExitReason::Vmcall);
    ctx.set_exit_qualification(0);
    ctx.set_guest_rip(0x1000);
    ctx.set_instruction_len(3);
    ctx.gprs_mut().rax = 0; // HYPERCALL_SHUTDOWN

    let result = handle_exit(&mut ctx, &MockKernel, &mut MockFrameAllocator::new());

    // Shutdown hypercall should exit to userspace with VmcallShutdown
    assert_eq!(
        result,
        ExitHandlerResult::ExitToUserspace(ExitReason::VmcallShutdown)
    );
    // RIP should be advanced past the VMCALL instruction
    assert_eq!(ctx.get_guest_rip(), Some(0x1003));
}

#[test]
fn test_vmcall_unknown_hypercall() {
    let mut ctx = MockVmContext::new();

    ctx.set_exit_reason(ExitReason::Vmcall);
    ctx.set_exit_qualification(0);
    ctx.set_guest_rip(0x1000);
    ctx.set_instruction_len(3);
    ctx.gprs_mut().rax = 0xDEAD; // Unknown hypercall number

    let result = handle_exit(&mut ctx, &MockKernel, &mut MockFrameAllocator::new());

    // Unknown hypercall should exit to userspace with generic Vmcall
    assert_eq!(
        result,
        ExitHandlerResult::ExitToUserspace(ExitReason::Vmcall)
    );
}

#[test]
fn test_vmcall_snapshot_hypercall() {
    let mut ctx = MockVmContext::new();

    ctx.set_exit_reason(ExitReason::Vmcall);
    ctx.set_exit_qualification(0);
    ctx.set_guest_rip(0x1000);
    ctx.set_instruction_len(3); // VMCALL is 3 bytes
    ctx.gprs_mut().rax = 1; // HYPERCALL_SNAPSHOT

    let result = handle_exit(&mut ctx, &MockKernel, &mut MockFrameAllocator::new());

    // Snapshot hypercall should exit to userspace with VmcallSnapshot
    assert_eq!(
        result,
        ExitHandlerResult::ExitToUserspace(ExitReason::VmcallSnapshot)
    );

    // RIP should be advanced past the VMCALL instruction
    assert_eq!(ctx.get_guest_rip(), Some(0x1003));
}

/// Attach a fresh event buffer to the VM and enable the `EXIT` category, so
/// `Exit` records are captured. Returns the backing buffer (keep it alive for
/// the test's duration).
fn attach_exit_event_buffer(ctx: &mut MockVmContext) -> std::vec::Vec<u8> {
    use crate::events::{EventCategories, EVENT_BUFFER_SIZE};
    let buffer = std::vec![0u8; EVENT_BUFFER_SIZE];
    let ptr = buffer.as_ptr() as *mut u8;
    ctx.state_mut().set_event_buffer(ptr);
    ctx.state_mut().set_event_categories(EventCategories::EXIT);
    buffer
}

/// Read the first event record's kind and its `ExitRecord` payload from a drained
/// event buffer. Panics if there is no record.
fn first_exit_entry(buffer: &[u8]) -> &crate::exit_record::ExitRecord {
    use crate::events::{EventKind, EVENT_HEADER_SIZE};
    let kind = u16::from_le_bytes([buffer[24], buffer[25]]);
    assert_eq!(
        kind,
        EventKind::Exit.as_u16(),
        "first record is not an Exit"
    );
    // SAFETY: an Exit payload is a 512-byte ExitRecord beginning right after the
    // 32-byte header; the buffer is at least that large.
    unsafe { &*(buffer.as_ptr().add(EVENT_HEADER_SIZE) as *const crate::exit_record::ExitRecord) }
}

#[test]
fn test_vmcall_snapshot_with_logging_enabled() {
    use crate::vm_state::ExitTrigger;

    let mut ctx = MockVmContext::new();

    // Capture Exit records via the unified event stream.
    let event_buffer = attach_exit_event_buffer(&mut ctx);

    // Use AtShutdown mode - this skips automatic per-exit capture but still
    // allows explicit snapshot logging via capture_exit_at_snapshot()
    ctx.state_mut().exit_trigger = ExitTrigger::AtShutdown;
    // Set last_instruction_count and tsc_offset so that emulated_tsc is computed correctly
    // (emulated_tsc = last_instruction_count + tsc_offset)
    ctx.state_mut().last_instruction_count = 1000;
    ctx.state_mut().tsc_offset = 0;

    ctx.set_exit_reason(ExitReason::Vmcall);
    ctx.set_exit_qualification(0);
    ctx.set_guest_rip(0x2000);
    ctx.set_instruction_len(3);
    ctx.gprs_mut().rax = 1; // HYPERCALL_SNAPSHOT

    let result = handle_exit(&mut ctx, &MockKernel, &mut MockFrameAllocator::new());

    assert_eq!(
        result,
        ExitHandlerResult::ExitToUserspace(ExitReason::VmcallSnapshot)
    );

    // One Exit event should have been emitted (the snapshot).
    assert!(ctx.state().event_buffer_len() > 0);
    let entry = first_exit_entry(&event_buffer);
    assert_eq!(entry.exit_reason, ExitReason::VmcallSnapshot as u32);
    assert_eq!(entry.tsc, 1000);
}

#[test]
fn test_vmcall_snapshot_requires_exit_category() {
    // With the EXIT category disabled, capture_exit_at_snapshot captures nothing — the
    // event-stream analog of "log buffer not allocated".
    use crate::events::EventCategories;
    use crate::vm_state::ExitTrigger;

    let mut ctx = MockVmContext::new();
    let _event_buffer = attach_exit_event_buffer(&mut ctx);
    // Disable EXIT capture again.
    ctx.state_mut()
        .set_event_categories(EventCategories::empty());

    ctx.state_mut().exit_trigger = ExitTrigger::AtShutdown;
    ctx.state_mut().emulated_tsc = 2000;

    ctx.state_mut().capture_exit_at_snapshot();

    // Nothing written because EXIT is not in the category mask.
    assert_eq!(ctx.state().event_buffer_len(), 0);
}

#[test]
fn test_vmcall_snapshot_respects_log_start_tsc() {
    // Test capture_exit_at_snapshot directly to verify TSC threshold is respected.
    use crate::vm_state::ExitTrigger;

    let mut ctx = MockVmContext::new();
    let event_buffer = attach_exit_event_buffer(&mut ctx);

    // Enable logging with a start threshold
    ctx.state_mut().exit_trigger = ExitTrigger::AtShutdown;
    ctx.state_mut().exit_start_tsc = 5000; // Don't log until TSC >= 5000
    ctx.state_mut().emulated_tsc = 1000; // Current TSC is below threshold

    // Call capture_exit_at_snapshot directly - should skip logging due to threshold
    ctx.state_mut().capture_exit_at_snapshot();

    // No Exit event should have been written.
    assert_eq!(ctx.state().event_buffer_len(), 0);

    // Now set TSC above threshold and try again
    ctx.state_mut().emulated_tsc = 6000;
    ctx.state_mut().capture_exit_at_snapshot();

    // Now an Exit event should have been written.
    assert!(ctx.state().event_buffer_len() > 0);
    let entry = first_exit_entry(&event_buffer);
    assert_eq!(entry.exit_reason, ExitReason::VmcallSnapshot as u32);
    assert_eq!(entry.tsc, 6000);
}

// =============================================================================
// Feedback buffer tests
// =============================================================================

#[test]
fn test_vmcall_register_feedback_buffer_success() {
    use crate::hypercalls::HYPERCALL_REGISTER_FEEDBACK_BUFFER;

    let mut ctx = MockVmContext::new();

    // Set up a simple page table structure in guest memory for GVA translation.
    // We'll set up an identity mapping so GVA == GPA for simplicity.
    // The page table walk reads from guest memory, so we need to set up valid entries.

    // For this test, we simulate successful GVA translation by pre-populating
    // the guest memory with valid page table entries.

    // CR3 points to PML4 at physical address 0x1000
    ctx.vmcs_setup()
        .set_field_natural(VmcsFieldNatural::GuestCr3, 0x1000);

    // Set up PML4 -> PDPT -> PD -> PT identity mapping for address 0x2000.
    // PML4[0] at 0x1000 -> points to PDPT at 0x2000
    // PDPT[0] at 0x2000 -> points to PD at 0x3000
    // PD[0] at 0x3000 -> points to PT at 0x4000
    // PT[0] at 0x4000 -> points to page at 0x5000 (identity mapped)

    // For simplicity, use 1GB pages (PDPT entry with PS bit set).
    // PML4 entry: present, writable, points to PDPT
    let pml4_entry: u64 = 0x2003; // Present + Writable + address 0x2000
    ctx.memory[0x1000..0x1008].copy_from_slice(&pml4_entry.to_le_bytes());

    // PDPT entry with 1GB page (PS bit set): maps GVA 0x0-0x40000000 to GPA 0x0
    let pdpt_entry: u64 = 0x83; // Present + Writable + PS (1GB page) + address 0x0
    ctx.memory[0x2000..0x2008].copy_from_slice(&pdpt_entry.to_le_bytes());

    // Set up VMCALL exit
    ctx.set_exit_reason(ExitReason::Vmcall);
    ctx.set_exit_qualification(0);
    ctx.set_guest_rip(0x1000);
    ctx.set_instruction_len(3); // VMCALL is 3 bytes

    // Stash the identifier bytes inside the guest's 1GB identity window.
    let id_bytes = b"build-id-abcd";
    ctx.memory[0x6000..0x6000 + id_bytes.len()].copy_from_slice(id_bytes);

    // Set hypercall number and arguments. New ABI: RDX = id GVA, RSI = id len.
    ctx.gprs_mut().rax = HYPERCALL_REGISTER_FEEDBACK_BUFFER;
    ctx.gprs_mut().rbx = 0x5000; // GVA of buffer
    ctx.gprs_mut().rcx = 4096; // Size: 1 page
    ctx.gprs_mut().rdx = 0x6000; // GVA of id bytes
    ctx.gprs_mut().rsi = id_bytes.len() as u64;

    let result = handle_exit(&mut ctx, &MockKernel, &mut MockFrameAllocator::new());

    // Should exit to userspace so it can map the feedback buffer
    assert_eq!(
        result,
        ExitHandlerResult::ExitToUserspace(ExitReason::VmcallFeedbackBuffer)
    );

    // RAX should be the assigned slot index (0 on first registration)
    assert_eq!(ctx.gprs().rax, 0);

    // RIP should be advanced
    assert_eq!(ctx.get_guest_rip(), Some(0x1003));

    // Feedback buffer should be registered at slot 0 (the first free slot)
    let fb = ctx.state().feedback_buffers[0]
        .as_ref()
        .expect("feedback buffer should be registered at slot 0");
    assert_eq!(fb.gva, 0x5000);
    assert_eq!(fb.size, 4096);
    assert_eq!(fb.num_pages, 1);
    assert_eq!(fb.gpas[0], 0x5000); // With identity mapping, GPA == GVA
    assert_eq!(fb.id_bytes(), id_bytes);
}

#[test]
fn test_vmcall_register_feedback_buffer_invalid_size() {
    use crate::hypercalls::HYPERCALL_REGISTER_FEEDBACK_BUFFER;

    let mut ctx = MockVmContext::new();

    ctx.set_exit_reason(ExitReason::Vmcall);
    ctx.set_exit_qualification(0);
    ctx.set_guest_rip(0x1000);
    ctx.set_instruction_len(3);

    // Test with size = 0
    ctx.gprs_mut().rax = HYPERCALL_REGISTER_FEEDBACK_BUFFER;
    ctx.gprs_mut().rbx = 0x5000;
    ctx.gprs_mut().rcx = 0; // Invalid: size is 0

    let result = handle_exit(&mut ctx, &MockKernel, &mut MockFrameAllocator::new());

    // Should continue (error is reported via return value)
    assert_eq!(result, ExitHandlerResult::Continue);

    // RAX carries the differentiated bad-size code.
    assert_eq!(ctx.gprs().rax, crate::exits::FB_ERR_BAD_SIZE);

    // Feedback buffer should NOT be registered at index 0
    assert!(ctx.state().feedback_buffers[0].is_none());
}

#[test]
fn test_vmcall_register_feedback_buffer_size_too_large() {
    use crate::hypercalls::HYPERCALL_REGISTER_FEEDBACK_BUFFER;
    use crate::vm_state::FEEDBACK_BUFFER_MAX_PAGES;

    let mut ctx = MockVmContext::new();

    ctx.set_exit_reason(ExitReason::Vmcall);
    ctx.set_exit_qualification(0);
    ctx.set_guest_rip(0x1000);
    ctx.set_instruction_len(3);

    // Test with size > 1MB (256 pages * 4096)
    ctx.gprs_mut().rax = HYPERCALL_REGISTER_FEEDBACK_BUFFER;
    ctx.gprs_mut().rbx = 0x5000;
    ctx.gprs_mut().rcx = (FEEDBACK_BUFFER_MAX_PAGES as u64 + 1) * 4096; // Too large

    let result = handle_exit(&mut ctx, &MockKernel, &mut MockFrameAllocator::new());

    // Should continue (error is reported via return value)
    assert_eq!(result, ExitHandlerResult::Continue);

    // RAX carries the differentiated bad-size code.
    assert_eq!(ctx.gprs().rax, crate::exits::FB_ERR_BAD_SIZE);

    // Feedback buffer should NOT be registered at index 0
    assert!(ctx.state().feedback_buffers[0].is_none());
}

#[test]
fn test_vmcall_register_feedback_buffer_bad_id_len() {
    use crate::exits::FB_ERR_BAD_ID_LEN;
    use crate::hypercalls::HYPERCALL_REGISTER_FEEDBACK_BUFFER;

    let mut ctx = MockVmContext::new();
    ctx.set_exit_reason(ExitReason::Vmcall);
    ctx.set_exit_qualification(0);
    ctx.set_guest_rip(0x1000);
    ctx.set_instruction_len(3);

    // Valid size, but id length 0 — rejected before any translation.
    ctx.gprs_mut().rax = HYPERCALL_REGISTER_FEEDBACK_BUFFER;
    ctx.gprs_mut().rbx = 0x5000;
    ctx.gprs_mut().rcx = 4096;
    ctx.gprs_mut().rdx = 0x6000;
    ctx.gprs_mut().rsi = 0; // invalid id length

    let result = handle_exit(&mut ctx, &MockKernel, &mut MockFrameAllocator::new());

    assert_eq!(result, ExitHandlerResult::Continue);
    assert_eq!(ctx.gprs().rax, FB_ERR_BAD_ID_LEN);
    assert!(ctx.state().feedback_buffers[0].is_none());
}

#[test]
fn test_vmcall_register_feedback_buffer_id_not_resident() {
    use crate::exits::FB_ERR_ID_NOT_RESIDENT;
    use crate::hypercalls::HYPERCALL_REGISTER_FEEDBACK_BUFFER;

    let mut ctx = MockVmContext::new();
    install_identity_paging(&mut ctx); // maps only [0, 1GB)
    ctx.set_exit_reason(ExitReason::Vmcall);
    ctx.set_exit_qualification(0);
    ctx.set_guest_rip(0x1000);
    ctx.set_instruction_len(3);

    // Buffer is mapped, but the id pointer lands in the unmapped second 1GB
    // region (PDPT[1] not present) — the id translation fails first.
    ctx.gprs_mut().rax = HYPERCALL_REGISTER_FEEDBACK_BUFFER;
    ctx.gprs_mut().rbx = 0x5000; // mapped
    ctx.gprs_mut().rcx = 4096;
    ctx.gprs_mut().rdx = 0x4000_0000; // unmapped
    ctx.gprs_mut().rsi = 8;

    let result = handle_exit(&mut ctx, &MockKernel, &mut MockFrameAllocator::new());

    assert_eq!(result, ExitHandlerResult::Continue);
    assert_eq!(ctx.gprs().rax, FB_ERR_ID_NOT_RESIDENT);
    assert!(ctx.state().feedback_buffers[0].is_none());
}

#[test]
fn test_vmcall_register_feedback_buffer_buffer_not_resident() {
    use crate::exits::FB_ERR_BUFFER_NOT_RESIDENT;
    use crate::hypercalls::HYPERCALL_REGISTER_FEEDBACK_BUFFER;

    let mut ctx = MockVmContext::new();
    install_identity_paging(&mut ctx); // maps only [0, 1GB)
    ctx.set_exit_reason(ExitReason::Vmcall);
    ctx.set_exit_qualification(0);
    ctx.set_guest_rip(0x1000);
    ctx.set_instruction_len(3);

    // Id is mapped and resident; the buffer pointer is in the unmapped second
    // 1GB region — the id reads fine, then the buffer translation fails.
    let id_bytes = b"build-id-xyz";
    ctx.memory[0x6000..0x6000 + id_bytes.len()].copy_from_slice(id_bytes);
    ctx.gprs_mut().rax = HYPERCALL_REGISTER_FEEDBACK_BUFFER;
    ctx.gprs_mut().rbx = 0x4000_0000; // unmapped
    ctx.gprs_mut().rcx = 4096;
    ctx.gprs_mut().rdx = 0x6000; // mapped id
    ctx.gprs_mut().rsi = id_bytes.len() as u64;

    let result = handle_exit(&mut ctx, &MockKernel, &mut MockFrameAllocator::new());

    assert_eq!(result, ExitHandlerResult::Continue);
    assert_eq!(ctx.gprs().rax, FB_ERR_BUFFER_NOT_RESIDENT);
    assert!(ctx.state().feedback_buffers[0].is_none());
}

// =============================================================================
// I/O channel tests
// =============================================================================

/// Helper: install a 1GB identity-mapped page-table walk so any `GVA` in
/// `[0, 1GB)` translates to the same `GPA`. Matches what the feedback-buffer
/// tests above set up.
fn install_identity_paging(ctx: &mut MockVmContext) {
    ctx.vmcs_setup()
        .set_field_natural(VmcsFieldNatural::GuestCr3, 0x1000);
    let pml4_entry: u64 = 0x2003; // Present + Writable + address 0x2000
    ctx.memory[0x1000..0x1008].copy_from_slice(&pml4_entry.to_le_bytes());
    let pdpt_entry: u64 = 0x83; // Present + Writable + PS (1GB) + address 0
    ctx.memory[0x2000..0x2008].copy_from_slice(&pdpt_entry.to_le_bytes());
}

#[test]
fn test_vmcall_io_register_page_success() {
    use crate::hypercalls::HYPERCALL_IO_REGISTER_PAGE;

    let mut ctx = MockVmContext::new();
    install_identity_paging(&mut ctx);

    ctx.set_exit_reason(ExitReason::Vmcall);
    ctx.set_exit_qualification(0);
    ctx.set_guest_rip(0x1000);
    ctx.set_instruction_len(3);

    ctx.gprs_mut().rax = HYPERCALL_IO_REGISTER_PAGE;
    // 4KB-aligned address inside the 1GB identity-mapped window.
    ctx.gprs_mut().rbx = 0x5000;

    let result = handle_exit(&mut ctx, &MockKernel, &mut MockFrameAllocator::new());
    assert_eq!(
        result,
        ExitHandlerResult::ExitToUserspace(ExitReason::VmcallIoRegisterPage)
    );
    assert_eq!(ctx.gprs().rax, 0, "registration should succeed");
    assert_eq!(ctx.state().io_channel.page_gpa, 0x5000);
    assert_eq!(ctx.get_guest_rip(), Some(0x1003));
}

#[test]
fn test_vmcall_io_register_page_unaligned() {
    use crate::hypercalls::HYPERCALL_IO_REGISTER_PAGE;

    let mut ctx = MockVmContext::new();
    install_identity_paging(&mut ctx);

    ctx.set_exit_reason(ExitReason::Vmcall);
    ctx.set_exit_qualification(0);
    ctx.set_guest_rip(0x1000);
    ctx.set_instruction_len(3);

    ctx.gprs_mut().rax = HYPERCALL_IO_REGISTER_PAGE;
    ctx.gprs_mut().rbx = 0x5001; // 1 byte misaligned

    let result = handle_exit(&mut ctx, &MockKernel, &mut MockFrameAllocator::new());
    assert_eq!(
        result,
        ExitHandlerResult::ExitToUserspace(ExitReason::VmcallIoRegisterPage)
    );
    assert_eq!(ctx.gprs().rax, !0u64, "unaligned should return -1");
    assert_eq!(
        ctx.state().io_channel.page_gpa,
        0,
        "failed registration must not stash a GPA"
    );
}

#[test]
fn test_vmcall_io_get_request_no_pending() {
    use crate::hypercalls::{HYPERCALL_IO_GET_REQUEST, HYPERCALL_IO_REGISTER_PAGE};

    let mut ctx = MockVmContext::new();
    install_identity_paging(&mut ctx);

    // First register the page so page_gpa is set, otherwise GET would
    // return -1 and we couldn't distinguish "registered + no request" from
    // "not registered".
    ctx.set_exit_reason(ExitReason::Vmcall);
    ctx.set_exit_qualification(0);
    ctx.set_guest_rip(0x1000);
    ctx.set_instruction_len(3);
    ctx.gprs_mut().rax = HYPERCALL_IO_REGISTER_PAGE;
    ctx.gprs_mut().rbx = 0x5000;
    let _ = handle_exit(&mut ctx, &MockKernel, &mut MockFrameAllocator::new());

    ctx.set_exit_reason(ExitReason::Vmcall);
    ctx.set_exit_qualification(0);
    ctx.set_guest_rip(0x2000);
    ctx.set_instruction_len(3);
    ctx.gprs_mut().rax = HYPERCALL_IO_GET_REQUEST;
    let result = handle_exit(&mut ctx, &MockKernel, &mut MockFrameAllocator::new());
    assert_eq!(result, ExitHandlerResult::Continue);
    assert_eq!(
        ctx.gprs().rax,
        0,
        "GET_REQUEST with no pending request returns 0"
    );
}

#[test]
fn test_vmcall_io_get_request_writes_payload_to_guest() {
    use crate::hypercalls::{HYPERCALL_IO_GET_REQUEST, HYPERCALL_IO_REGISTER_PAGE};

    let mut ctx = MockVmContext::new();
    install_identity_paging(&mut ctx);

    // Register page.
    ctx.set_exit_reason(ExitReason::Vmcall);
    ctx.set_exit_qualification(0);
    ctx.set_guest_rip(0x1000);
    ctx.set_instruction_len(3);
    ctx.gprs_mut().rax = HYPERCALL_IO_REGISTER_PAGE;
    ctx.gprs_mut().rbx = 0x5000;
    let _ = handle_exit(&mut ctx, &MockKernel, &mut MockFrameAllocator::new());

    // Pre-load a fake request into VmState (mimics what the QUEUE ioctl
    // does on the kernel side). Use a non-trivial pattern that exercises
    // the chunked copy path past the first 256-byte boundary.
    let request: Vec<u8> = (0..600).map(|i| (i % 256) as u8).collect();
    {
        let chan = &mut ctx.state_mut().io_channel;
        chan.request_buf[..request.len()].copy_from_slice(&request);
        chan.request_len = request.len();
    }

    // Issue GET_REQUEST.
    ctx.set_exit_reason(ExitReason::Vmcall);
    ctx.set_exit_qualification(0);
    ctx.set_guest_rip(0x2000);
    ctx.set_instruction_len(3);
    ctx.gprs_mut().rax = HYPERCALL_IO_GET_REQUEST;
    let result = handle_exit(&mut ctx, &MockKernel, &mut MockFrameAllocator::new());
    assert_eq!(result, ExitHandlerResult::Continue);
    assert_eq!(ctx.gprs().rax, request.len() as u64);

    // Guest memory at the registered GPA should match the request payload.
    let written = &ctx.memory[0x5000..0x5000 + request.len()];
    assert_eq!(written, request.as_slice());
    // The in-flight slot is consumed by GET_REQUEST so the next IRQ can
    // fire as soon as another pending request is promoted (parallel
    // worker model). With no pending queue here, the slot is just empty.
    assert_eq!(ctx.state().io_channel.request_len, 0);
    assert!(!ctx.state().io_channel.request_delivered);
}

#[test]
fn test_vmcall_io_get_request_promotes_next_pending() {
    use crate::hypercalls::{HYPERCALL_IO_GET_REQUEST, HYPERCALL_IO_REGISTER_PAGE};
    use crate::vm_state::PendingIoAction;

    let mut ctx = MockVmContext::new();
    install_identity_paging(&mut ctx);

    // Register page.
    ctx.set_exit_reason(ExitReason::Vmcall);
    ctx.set_exit_qualification(0);
    ctx.set_guest_rip(0x1000);
    ctx.set_instruction_len(3);
    ctx.gprs_mut().rax = HYPERCALL_IO_REGISTER_PAGE;
    ctx.gprs_mut().rbx = 0x5000;
    let _ = handle_exit(&mut ctx, &MockKernel, &mut MockFrameAllocator::new());

    // In-flight slot: request A. Pending queue: [B, C].
    let req_a: Vec<u8> = (0..100).map(|_| 0xAAu8).collect();
    let req_b: Vec<u8> = (0..50).map(|_| 0xBBu8).collect();
    let req_c: Vec<u8> = (0..75).map(|_| 0xCCu8).collect();
    {
        let chan = &mut ctx.state_mut().io_channel;
        chan.request_buf[..req_a.len()].copy_from_slice(&req_a);
        chan.request_len = req_a.len();
        chan.request_target_tsc = 0;
        let _ = chan.enqueue_pending(PendingIoAction {
            target_tsc: 100,
            data: {
                let mut v = Vec::with_capacity(req_b.len());
                v.extend_from_slice(&req_b);
                v
            },
        });
        let _ = chan.enqueue_pending(PendingIoAction {
            target_tsc: 200,
            data: {
                let mut v = Vec::with_capacity(req_c.len());
                v.extend_from_slice(&req_c);
                v
            },
        });
    }

    // GET_REQUEST should consume A and promote B.
    ctx.set_exit_reason(ExitReason::Vmcall);
    ctx.set_exit_qualification(0);
    ctx.set_guest_rip(0x2000);
    ctx.set_instruction_len(3);
    ctx.gprs_mut().rax = HYPERCALL_IO_GET_REQUEST;
    let result = handle_exit(&mut ctx, &MockKernel, &mut MockFrameAllocator::new());
    assert_eq!(result, ExitHandlerResult::Continue);
    assert_eq!(ctx.gprs().rax, req_a.len() as u64);

    let chan = &ctx.state().io_channel;
    assert_eq!(chan.request_len, req_b.len(), "B promoted into slot");
    assert_eq!(chan.request_target_tsc, 100);
    assert_eq!(&chan.request_buf[..req_b.len()], req_b.as_slice());
    assert_eq!(chan.pending.len(), 1, "C still in pending queue");
}

#[test]
fn test_vmcall_io_put_response_captures_response() {
    use crate::hypercalls::{HYPERCALL_IO_PUT_RESPONSE, HYPERCALL_IO_REGISTER_PAGE};

    let mut ctx = MockVmContext::new();
    install_identity_paging(&mut ctx);

    // Register page.
    ctx.set_exit_reason(ExitReason::Vmcall);
    ctx.set_exit_qualification(0);
    ctx.set_guest_rip(0x1000);
    ctx.set_instruction_len(3);
    ctx.gprs_mut().rax = HYPERCALL_IO_REGISTER_PAGE;
    ctx.gprs_mut().rbx = 0x5000;
    let _ = handle_exit(&mut ctx, &MockKernel, &mut MockFrameAllocator::new());

    // PUT_RESPONSE no longer needs to clear the in-flight slot — that
    // happened in GET_REQUEST so the next pending could be promoted
    // immediately. Here we just verify it captures the response bytes
    // and exits to userspace.
    let response: Vec<u8> = (0..500).map(|i| ((i * 7) % 256) as u8).collect();
    ctx.memory[0x5000..0x5000 + response.len()].copy_from_slice(&response);

    ctx.set_exit_reason(ExitReason::Vmcall);
    ctx.set_exit_qualification(0);
    ctx.set_guest_rip(0x2000);
    ctx.set_instruction_len(3);
    ctx.gprs_mut().rax = HYPERCALL_IO_PUT_RESPONSE;
    ctx.gprs_mut().rbx = response.len() as u64;
    let result = handle_exit(&mut ctx, &MockKernel, &mut MockFrameAllocator::new());
    assert_eq!(
        result,
        ExitHandlerResult::ExitToUserspace(ExitReason::VmcallIoResponse)
    );
    assert_eq!(ctx.gprs().rax, 0);

    let chan = &ctx.state().io_channel;
    assert_eq!(chan.response_len, response.len());
    assert_eq!(&chan.response_buf[..response.len()], response.as_slice());
}

#[test]
fn test_check_io_channel_skips_when_ioapic_masked() {
    use crate::exits::{check_io_channel, IO_CHANNEL_IRQ};

    let mut ctx = MockVmContext::new();

    // Pretend a request was queued and the page is already registered.
    ctx.state_mut().io_channel.page_gpa = 0x5000;
    ctx.state_mut().io_channel.request_len = 32;
    ctx.state_mut().io_channel.request_delivered = false;

    // Default IoApicState initialises redtbl entries with the masked bit
    // set (bit 16), so check_io_channel must hold off until the guest
    // module has wired up the IRQ.
    check_io_channel(&mut ctx);
    assert!(
        !ctx.state().io_channel.request_delivered,
        "must not mark delivered while IOAPIC pin is masked"
    );

    // Unmask + valid vector → check_io_channel marks delivered and sets
    // the APIC IRR bit for that vector.
    let vector: u8 = 0x80;
    let entry: u64 = vector as u64; // mask bit clear, vector valid
    ctx.state_mut().devices.ioapic.redtbl[IO_CHANNEL_IRQ as usize] = entry;
    check_io_channel(&mut ctx);
    assert!(
        ctx.state().io_channel.request_delivered,
        "should mark delivered after asserting IRQ"
    );
    let irr_index = (vector / 32) as usize;
    let irr_bit = 1u32 << (vector % 32);
    assert!(
        ctx.state().devices.apic.irr[irr_index] & irr_bit != 0,
        "APIC IRR should reflect the queued I/O channel IRQ"
    );
}

#[test]
fn test_check_io_channel_defers_until_target_tsc() {
    use crate::exits::{check_io_channel, IO_CHANNEL_IRQ};

    let mut ctx = MockVmContext::new();

    let vector: u8 = 0x90;
    ctx.state_mut().io_channel.page_gpa = 0x5000;
    ctx.state_mut().io_channel.request_len = 16;
    ctx.state_mut().io_channel.request_delivered = false;
    ctx.state_mut().io_channel.request_target_tsc = 1_000_000;
    // Unmasked, valid vector — module has wired up the IRQ.
    ctx.state_mut().devices.ioapic.redtbl[IO_CHANNEL_IRQ as usize] = vector as u64;

    // emulated_tsc below target → must not fire yet (this is the
    // PEBS-precise path: arm_for_next_iteration arms PEBS for the
    // target, and check_io_channel only flips the IRR on the boundary
    // step or later).
    ctx.state_mut().emulated_tsc = 999_999;
    check_io_channel(&mut ctx);
    assert!(
        !ctx.state().io_channel.request_delivered,
        "must defer firing while emulated_tsc < request_target_tsc"
    );

    // At-or-past target → fire.
    ctx.state_mut().emulated_tsc = 1_000_000;
    check_io_channel(&mut ctx);
    assert!(
        ctx.state().io_channel.request_delivered,
        "should fire once emulated_tsc reaches target"
    );
    let irr_index = (vector / 32) as usize;
    let irr_bit = 1u32 << (vector % 32);
    assert!(
        ctx.state().devices.apic.irr[irr_index] & irr_bit != 0,
        "APIC IRR should be set on the boundary step"
    );
}

// =============================================================================
// Paravirtual batch console tests
// =============================================================================

#[test]
fn test_vmcall_serial_register_page_success() {
    use crate::hypercalls::HYPERCALL_SERIAL_REGISTER_PAGE;

    let mut ctx = MockVmContext::new();
    install_identity_paging(&mut ctx);

    ctx.set_exit_reason(ExitReason::Vmcall);
    ctx.set_exit_qualification(0);
    ctx.set_guest_rip(0x1000);
    ctx.set_instruction_len(3);

    ctx.gprs_mut().rax = HYPERCALL_SERIAL_REGISTER_PAGE;
    // 4KB-aligned address inside the 1GB identity-mapped window.
    ctx.gprs_mut().rbx = 0x5000;

    let result = handle_exit(&mut ctx, &MockKernel, &mut MockFrameAllocator::new());
    // Registration is purely host-internal, so it continues the guest rather
    // than exiting to userspace.
    assert_eq!(result, ExitHandlerResult::Continue);
    assert_eq!(ctx.gprs().rax, 0, "registration should succeed");
    assert_eq!(ctx.state().serial_console.page_gpa, 0x5000);
    assert_eq!(ctx.get_guest_rip(), Some(0x1003));
}

#[test]
fn test_vmcall_serial_register_page_unaligned() {
    use crate::hypercalls::HYPERCALL_SERIAL_REGISTER_PAGE;

    let mut ctx = MockVmContext::new();
    install_identity_paging(&mut ctx);

    ctx.set_exit_reason(ExitReason::Vmcall);
    ctx.set_exit_qualification(0);
    ctx.set_guest_rip(0x1000);
    ctx.set_instruction_len(3);

    ctx.gprs_mut().rax = HYPERCALL_SERIAL_REGISTER_PAGE;
    ctx.gprs_mut().rbx = 0x5001; // 1 byte misaligned

    let result = handle_exit(&mut ctx, &MockKernel, &mut MockFrameAllocator::new());
    assert_eq!(result, ExitHandlerResult::Continue);
    assert_eq!(ctx.gprs().rax, !0u64, "unaligned should return -1");
    assert_eq!(
        ctx.state().serial_console.page_gpa,
        0,
        "failed registration must not stash a GPA"
    );
}

#[test]
fn test_vmcall_serial_register_page_untranslatable() {
    use crate::hypercalls::HYPERCALL_SERIAL_REGISTER_PAGE;

    let mut ctx = MockVmContext::new();
    install_identity_paging(&mut ctx);

    ctx.set_exit_reason(ExitReason::Vmcall);
    ctx.set_exit_qualification(0);
    ctx.set_guest_rip(0x1000);
    ctx.set_instruction_len(3);

    ctx.gprs_mut().rax = HYPERCALL_SERIAL_REGISTER_PAGE;
    // 4KB-aligned, but exactly at the 1GB boundary — the identity window only
    // covers [0, 1GB) via a single 1GB PDPT entry, so PDPT[1] is absent and
    // the page-table walk fails to translate.
    ctx.gprs_mut().rbx = 0x4000_0000;

    let result = handle_exit(&mut ctx, &MockKernel, &mut MockFrameAllocator::new());
    assert_eq!(result, ExitHandlerResult::Continue);
    assert_eq!(ctx.gprs().rax, !0u64, "untranslatable GVA should return -1");
    assert_eq!(
        ctx.state().serial_console.page_gpa,
        0,
        "failed registration must not stash a GPA"
    );
}

#[test]
fn test_vmcall_serial_write_emits_serial_event() {
    use crate::events::{EventCategories, EventKind, EVENT_BUFFER_SIZE, EVENT_HEADER_SIZE};
    use crate::hypercalls::{HYPERCALL_SERIAL_REGISTER_PAGE, HYPERCALL_SERIAL_WRITE};

    let mut ctx = MockVmContext::new();
    install_identity_paging(&mut ctx);

    // Capture the console output on the unified event stream.
    let buffer = std::vec![0u8; EVENT_BUFFER_SIZE];
    let ptr = buffer.as_ptr() as *mut u8;
    ctx.state_mut().set_event_buffer(ptr);
    ctx.state_mut()
        .set_event_categories(EventCategories::SERIAL);

    // Register the console page at GVA/GPA 0x5000.
    ctx.set_exit_reason(ExitReason::Vmcall);
    ctx.set_exit_qualification(0);
    ctx.set_guest_rip(0x1000);
    ctx.set_instruction_len(3);
    ctx.gprs_mut().rax = HYPERCALL_SERIAL_REGISTER_PAGE;
    ctx.gprs_mut().rbx = 0x5000;
    let _ = handle_exit(&mut ctx, &MockKernel, &mut MockFrameAllocator::new());

    // Place a console record in the registered page. Span more than one
    // IO_COPY_CHUNK (256 bytes) so the chunked guest->pending copy is
    // exercised past its first boundary.
    let mut record: Vec<u8> = Vec::new();
    record.extend_from_slice(b"hello bedrock console\n");
    record.extend(core::iter::repeat_n(b'x', 400));
    ctx.memory[0x5000..0x5000 + record.len()].copy_from_slice(&record);

    // Issue SERIAL_WRITE with the record length.
    ctx.set_exit_reason(ExitReason::Vmcall);
    ctx.set_exit_qualification(0);
    ctx.set_guest_rip(0x2000);
    ctx.set_instruction_len(3);
    ctx.gprs_mut().rax = HYPERCALL_SERIAL_WRITE;
    ctx.gprs_mut().rbx = record.len() as u64;
    let result = handle_exit(&mut ctx, &MockKernel, &mut MockFrameAllocator::new());

    assert_eq!(result, ExitHandlerResult::Continue);
    assert_eq!(ctx.gprs().rax, 0, "SERIAL_WRITE should succeed");
    assert_eq!(ctx.get_guest_rip(), Some(0x2003));

    // The record was emitted as a single Serial event carrying its bytes verbatim.
    let len = ctx.state().event_buffer_len();
    assert_eq!(
        len,
        EVENT_HEADER_SIZE + crate::events::align_up(record.len(), 8)
    );
    let kind = u16::from_le_bytes([buffer[24], buffer[25]]);
    let payload_len = u32::from_le_bytes([buffer[28], buffer[29], buffer[30], buffer[31]]) as usize;
    assert_eq!(kind, EventKind::Serial.as_u16());
    assert_eq!(payload_len, record.len());
    assert_eq!(
        &buffer[EVENT_HEADER_SIZE..EVENT_HEADER_SIZE + record.len()],
        record.as_slice()
    );
}

#[test]
fn test_vmcall_serial_write_not_registered() {
    use crate::events::{EventCategories, EVENT_BUFFER_SIZE};
    use crate::hypercalls::HYPERCALL_SERIAL_WRITE;

    let mut ctx = MockVmContext::new();
    install_identity_paging(&mut ctx);

    let buffer = std::vec![0u8; EVENT_BUFFER_SIZE];
    ctx.state_mut().set_event_buffer(buffer.as_ptr() as *mut u8);
    ctx.state_mut()
        .set_event_categories(EventCategories::SERIAL);

    ctx.set_exit_reason(ExitReason::Vmcall);
    ctx.set_exit_qualification(0);
    ctx.set_guest_rip(0x1000);
    ctx.set_instruction_len(3);
    ctx.gprs_mut().rax = HYPERCALL_SERIAL_WRITE;
    ctx.gprs_mut().rbx = 8;

    let result = handle_exit(&mut ctx, &MockKernel, &mut MockFrameAllocator::new());
    assert_eq!(result, ExitHandlerResult::Continue);
    assert_eq!(
        ctx.gprs().rax,
        !0u64,
        "SERIAL_WRITE before registration returns -1"
    );
    assert_eq!(
        ctx.state().event_buffer_len(),
        0,
        "no Serial event emitted on failure"
    );
}
