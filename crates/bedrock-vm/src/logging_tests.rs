// SPDX-License-Identifier: GPL-2.0

use super::*;

#[test]
fn test_log_entry_size() {
    assert_eq!(std::mem::size_of::<LogEntry>(), LOG_ENTRY_SIZE);
}

#[test]
fn test_from_buffer_empty() {
    let entries = LogEntry::from_buffer(&[], 0);
    assert!(entries.is_empty());
}

#[test]
fn test_write_jsonl() {
    let entry = LogEntry {
        tsc: 1000,
        exit_reason: 30,
        flags: 0,
        exit_qualification: 0x3f8,
        rax: 0x100,
        rcx: 0x200,
        rdx: 0x300,
        rbx: 0x400,
        rsp: 0x500,
        rbp: 0x600,
        rsi: 0x700,
        rdi: 0x800,
        r8: 0x900,
        r9: 0xa00,
        r10: 0xb00,
        r11: 0xc00,
        r12: 0xd00,
        r13: 0xe00,
        r14: 0xf00,
        r15: 0x1000,
        rip: 0xffff8000,
        rflags: 0x246,
        apic_hash: 0x1234,
        serial_hash: 0x5678,
        ioapic_hash: 0x9abc,
        rtc_hash: 0xdef0,
        mtrr_hash: 0x1111,
        rdrand_hash: 0x2222,
        memory_hash: 0x3333,
        fs_base: 0,
        gs_base: 0,
        kernel_gs_base: 0,
        cr3: 0,
        cs_base: 0,
        ds_base: 0,
        es_base: 0,
        ss_base: 0,
        pending_dbg_exceptions: 0,
        interruptibility_state: 0,
        cow_page_count: 0,
        pebs_skid: 0,
        pebs_inst_delta: 0,
        pebs_tsc_offset_delta: 0,
        pebs_iters_since_arm: 0,
        pebs_arm_delta: 0,
        last_instruction_count: 0,
        apic_timer_deadline: 0,
        io_channel_target_tsc: 0,
        pebs_armed_target_tsc: 0,
        vmx_state_flags: 0,
        _padding: [0; 16],
    };

    let mut output = Vec::new();
    let count = write_jsonl(&mut output, &[entry]).unwrap();
    assert_eq!(count, 1);

    let json = String::from_utf8(output).unwrap();
    assert!(json.contains("\"tsc\":1000"));
    assert!(json.contains("\"exit_reason\":30"));
    assert!(json.contains("\"exit_qualification\":1016"));
    // Verify flags is included and padding is not
    assert!(json.contains("\"flags\":"));
    assert!(!json.contains("_padding"));
}
