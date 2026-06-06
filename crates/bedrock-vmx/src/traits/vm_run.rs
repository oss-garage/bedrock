// SPDX-License-Identifier: GPL-2.0

//! VM run loop implementation.
//!
//! This module provides the main VM execution loop, GPR synchronization,
//! and related functionality for running guests.

#[cfg(not(feature = "cargo"))]
use super::super::prelude::*;
#[cfg(feature = "cargo")]
use crate::prelude::*;

use super::{
    CowAllocator, InstructionCounter, IrqGuard, Kernel, Machine, Page, ReverseIrqGuard,
    VirtualMachineControlStructure, VmContext, VmRunError, VmRunner,
};

// ========== GPR Sync Methods ==========

/// Copy GPRs from GeneralPurposeRegisters to VmxContext guest registers.
/// Also sets up XSAVE area pointers for extended state management.
pub fn sync_gprs_to_vmx_ctx<V, I>(state: &mut VmState<V, I>)
where
    V: VirtualMachineControlStructure,
    I: InstructionCounter,
{
    state.vmx_ctx.guest_rax = state.gprs.rax;
    state.vmx_ctx.guest_rbx = state.gprs.rbx;
    state.vmx_ctx.guest_rcx = state.gprs.rcx;
    state.vmx_ctx.guest_rdx = state.gprs.rdx;
    state.vmx_ctx.guest_rsi = state.gprs.rsi;
    state.vmx_ctx.guest_rdi = state.gprs.rdi;
    state.vmx_ctx.guest_rbp = state.gprs.rbp;
    state.vmx_ctx.guest_r8 = state.gprs.r8;
    state.vmx_ctx.guest_r9 = state.gprs.r9;
    state.vmx_ctx.guest_r10 = state.gprs.r10;
    state.vmx_ctx.guest_r11 = state.gprs.r11;
    state.vmx_ctx.guest_r12 = state.gprs.r12;
    state.vmx_ctx.guest_r13 = state.gprs.r13;
    state.vmx_ctx.guest_r14 = state.gprs.r14;
    state.vmx_ctx.guest_r15 = state.gprs.r15;
    // Note: RSP is handled by VMCS, not VmxContext

    // Set up XSAVE area pointers for extended state (FPU/SSE/AVX) save/restore
    state.vmx_ctx.guest_xsave_ptr = state.guest_xsave_page.virtual_address().as_u64();
    state.vmx_ctx.host_xsave_ptr = state.host_xsave_page.virtual_address().as_u64();
    state.vmx_ctx.xcr0_mask = state.xcr0_mask;
}

/// Copy GPRs from VmxContext guest registers to GeneralPurposeRegisters.
pub fn sync_gprs_from_vmx_ctx<V, I>(state: &mut VmState<V, I>)
where
    V: VirtualMachineControlStructure,
    I: InstructionCounter,
{
    state.gprs.rax = state.vmx_ctx.guest_rax;
    state.gprs.rbx = state.vmx_ctx.guest_rbx;
    state.gprs.rcx = state.vmx_ctx.guest_rcx;
    state.gprs.rdx = state.vmx_ctx.guest_rdx;
    state.gprs.rsi = state.vmx_ctx.guest_rsi;
    state.gprs.rdi = state.vmx_ctx.guest_rdi;
    state.gprs.rbp = state.vmx_ctx.guest_rbp;
    state.gprs.r8 = state.vmx_ctx.guest_r8;
    state.gprs.r9 = state.vmx_ctx.guest_r9;
    state.gprs.r10 = state.vmx_ctx.guest_r10;
    state.gprs.r11 = state.vmx_ctx.guest_r11;
    state.gprs.r12 = state.vmx_ctx.guest_r12;
    state.gprs.r13 = state.vmx_ctx.guest_r13;
    state.gprs.r14 = state.vmx_ctx.guest_r14;
    state.gprs.r15 = state.vmx_ctx.guest_r15;
    // Note: RSP is handled by VMCS, not VmxContext
}

// ========== VM Run Methods ==========

/// Run the VM until an exit requiring userspace handling.
///
/// This is the main entry point for running the VM. It:
/// 1. Saves host MSRs (KERNEL_GS_BASE, SYSCALL/SYSRET MSRs)
/// 2. Loads guest MSRs that don't have VMCS fields
/// 3. Loads the VMCS and runs the VM loop
/// 4. Restores host MSRs on exit
///
/// # Safety
///
/// Caller must ensure:
/// - VMCS is properly configured
/// - Interrupts are in appropriate state
/// - HOST_RIP is correctly set in VMCS
/// - Preemption is disabled to prevent migration during VM entry/exit
pub unsafe fn run<Ctx, R, M, A>(
    ctx: &mut Ctx,
    runner: &mut R,
    machine: &M,
    allocator: &mut A,
) -> Result<ExitReason, VmRunError>
where
    Ctx: VmContext,
    R: VmRunner<Vmcs = Ctx::Vmcs>,
    M: Machine,
    A: CowAllocator<Ctx::CowPage>,
{
    let msr = machine.msr_access();

    // Save host KERNEL_GS_BASE (per-thread, changes between runs).
    let host_kernel_gs_base = msr.read_msr(msr::IA32_KERNEL_GS_BASE).unwrap_or(0);

    // Load guest MSRs that don't have VMCS fields.
    // SYSCALL/SYSRET and SWAPGS read these directly from hardware.
    ctx.state().msr_state.syscall.load(msr);

    // Load the VMCS
    ctx.state().vmcs.load().map_err(VmRunError::VmcsLoad)?;

    // Cross-CPU EPT TLB invalidation. VM entries/exits are not required to
    // invalidate guest-physical mappings (Intel SDM Vol 3C §30.4.3.2), and
    // EPT TLB entries are per-logical-processor — propagating EPT changes to
    // other LPs is software's responsibility (§30.4.3.4). Within one ioctl
    // preempt is disabled so we stay on one CPU, but between ioctls the
    // thread can migrate; CoW remappings done on the intermediate CPU may
    // leave this CPU's EPT TLB pointing at parent HPAs. Auto-invalidation
    // on EPT violations only saves us when the cached entry's permissions
    // would block the access — a permitted read through a stale entry
    // silently returns the parent's data (§30.4.2). Issue INVEPT
    // single-context whenever the run thread is on a different CPU than
    // it last ran on for this VM.
    let cur_cpu = machine.kernel().current_cpu_id() as u32;
    if ctx.state().last_cpu != Some(cur_cpu) {
        let eptp = ctx.state().ept.eptp();
        <Ctx::V as Vmx>::invept_single_context(eptp).map_err(VmRunError::InveptFailed)?;
        ctx.state_mut().last_cpu = Some(cur_cpu);
    }

    // Apply #PF interception to exception bitmap (requires VMCS to be loaded).
    ctx.state().apply_intercept_pf();

    // Initialize MTF state before the first VM entry. Without this, single-stepping
    // won't be active until the first deterministic exit triggers update_mtf_state(),
    // leaving a window of untracked guest execution at the start.
    update_mtf_state(ctx).map_err(VmRunError::ExitHandler)?;

    // SAFETY: Caller guarantees VMCS is properly configured
    let result = unsafe { run_loop(ctx, runner, machine, allocator, host_kernel_gs_base) };

    // Clear the VMCS - this MUST succeed for safe re-entry
    let clear_result = ctx.state().vmcs.clear();

    // Reset launched flag since VMCLEAR transitions VMCS to "clear" state.
    // Next VM entry will need VMLAUNCH, not VMRESUME.
    ctx.state_mut().vmx_ctx.launched = 0;

    // Save guest MSRs from hardware after VM exit.
    // Note: kernel_gs_base is already saved by run_loop on every VM exit.
    ctx.state_mut().msr_state.syscall = SyscallMsrs::capture(msr);

    // Restore host MSRs before returning to userspace.
    // This must happen regardless of VMCLEAR success to ensure safe return.
    ctx.state().host_state.syscall_msrs.load(msr);
    let _ = msr.write_msr(msr::IA32_KERNEL_GS_BASE, host_kernel_gs_base);

    // If VMCLEAR failed, return fatal error - the VMCS is in an undefined state
    // and re-entry would likely cause a host crash.
    if let Err(e) = clear_result {
        log_err!("VMCLEAR failed - VMCS in undefined state, cannot continue\n");
        return Err(VmRunError::VmcsClear(e));
    }

    result
}

/// Internal run loop - separated to ensure VMCS clear happens on all exit paths.
///
/// `host_kernel_gs_base` is the host's IA32_KERNEL_GS_BASE value, saved by the
/// caller before loading the guest's value. We restore it after each VM exit so
/// that host interrupt handlers (serviced during IRQ windows) see the correct
/// value, then reload the guest's value before each VM entry.
unsafe fn run_loop<Ctx, R, M, A>(
    ctx: &mut Ctx,
    runner: &mut R,
    machine: &M,
    allocator: &mut A,
    host_kernel_gs_base: u64,
) -> Result<ExitReason, VmRunError>
where
    Ctx: VmContext,
    R: VmRunner<Vmcs = Ctx::Vmcs>,
    M: Machine,
    A: CowAllocator<Ctx::CowPage>,
{
    // Disable interrupts for the duration of the run loop. The assembly
    // (vmx_run_guest) switches XCR0 to the guest value before VMRESUME; if a
    // host interrupt fires in that window, any handler using AVX-512 would #UD
    // because the guest XCR0 lacks the AVX-512 bits. On VM exit the assembly
    // restores host XCR0 before returning, so brief IRQ windows between exits
    // are safe — those are opened via ReverseIrqGuard below.
    let _irq_guard = IrqGuard::new(machine.kernel());

    // Write host state that is constant for the entire run loop. Preemption
    // is disabled by the caller, so we cannot migrate to a different CPU —
    // CR3, per-CPU segment bases, TR, and GDTR are all stable. Writing these
    // once instead of every iteration avoids per-exit VMWRITE overhead, which
    // is especially costly in nested virtualisation (each VMWRITE traps to L0).
    let cr3 = machine
        .cr_access()
        .read_cr3()
        .map_err(|_| VmRunError::ReadHostCr3)?
        .bits();
    ctx.state()
        .vmcs
        .write_natural(VmcsFieldNatural::HostCr3, cr3)
        .map_err(VmRunError::WriteHostCr3)?;

    {
        let msr = machine.msr_access();
        let fs_base = msr.read_msr(msr::IA32_FS_BASE).unwrap_or(0);
        ctx.state()
            .vmcs
            .write_natural(VmcsFieldNatural::HostFsBase, fs_base)
            .map_err(VmRunError::WriteHostFsBase)?;
        let gs_base = msr.read_msr(msr::IA32_GS_BASE).unwrap_or(0);
        ctx.state()
            .vmcs
            .write_natural(VmcsFieldNatural::HostGsBase, gs_base)
            .map_err(VmRunError::WriteHostGsBase)?;
    }

    let dta = machine.descriptor_table_access();
    ctx.state()
        .vmcs
        .write_natural(VmcsFieldNatural::HostTrBase, dta.read_tr_base())
        .map_err(VmRunError::WriteHostTrBase)?;
    ctx.state()
        .vmcs
        .write_natural(VmcsFieldNatural::HostGdtrBase, dta.read_gdtr().base)
        .map_err(VmRunError::WriteHostGdtrBase)?;

    // HOST_RSP points to VmxContext which is at a fixed address for the
    // duration of the run loop.
    let host_rsp = core::ptr::from_mut(&mut ctx.state_mut().vmx_ctx) as u64;
    ctx.state()
        .vmcs
        .write_natural(VmcsFieldNatural::HostRsp, host_rsp)
        .map_err(VmRunError::WriteHostRsp)?;

    // Program host PMU state (e.g. IA32_FIXED_CTR_CTRL) and reset the
    // counter. Must run with preemption disabled and on the CPU the loop
    // will execute on — both guaranteed by our caller.
    ctx.state_mut()
        .instruction_counter
        .prepare()
        .map_err(VmRunError::InstructionCounter)?;

    // Configure VMCS auto-save/load of the instruction counter MSR. The CPU
    // stores the counter into the entry on VM exit and reloads it on VM
    // entry, so any host-side ticks (e.g. from a perf NMI re-enabling
    // PERF_GLOBAL_CTRL.bit32) are wiped on the next entry. Without this, the
    // count between VM exits is non-deterministic when perf's NMI handler
    // runs, since perf's `__intel_pmu_enable_all` rewrites GLOBAL_CTRL based
    // on `intel_ctrl_guest_mask` — which doesn't include our counter when
    // we're not registered with perf.
    if let Some(entry_phys) = ctx.state().instruction_counter.msr_save_load_entry_phys() {
        let _ = ctx
            .state()
            .vmcs
            .write64(VmcsField64::VmExitMsrStoreAddr, entry_phys);
        let _ = ctx
            .state()
            .vmcs
            .write32(VmcsField32::VmExitMsrStoreCount, 1);
        let _ = ctx
            .state()
            .vmcs
            .write64(VmcsField64::VmEntryMsrLoadAddr, entry_phys);
        let _ = ctx
            .state()
            .vmcs
            .write32(VmcsField32::VmEntryMsrLoadCount, 1);
    }

    // Configure hardware-assisted perf counter switching if available.
    // The perf_global_ctrl values and entry/exit control bits are constant
    // for the entire run loop — write them once to avoid per-exit VMCS
    // operations (each VMWRITE traps to L0 in nested virt).
    //
    // When PEBS is registered, OR in bit 32 (`IA32_FIXED_CTR0` enable) on
    // the guest side: PEBS uses `IA32_FIXED_CTR0` as its event counter, and
    // the host's `IA32_PERF_GLOBAL_CTRL` snapshot the IC reads in
    // `prepare()` doesn't include that bit. Without this,
    // `register_pebs_page`'s one-shot OR gets clobbered the next time
    // `run_loop` is entered, leaving `IA32_FIXED_CTR0` disabled in the
    // guest — PEBS never overflows, no record write, no EPT violation.
    let pebs_registered = ctx.state().pebs_state.is_some();
    if let Some((mut guest_val, host_val)) =
        ctx.state().instruction_counter.perf_global_ctrl_values()
    {
        if pebs_registered {
            guest_val |= PERF_GLOBAL_CTRL_FIXED_CTR0;
        }
        let _ = ctx
            .state()
            .vmcs
            .write64(VmcsField64::GuestIa32PerfGlobalCtrl, guest_val);
        let _ = ctx
            .state()
            .vmcs
            .write64(VmcsField64::HostIa32PerfGlobalCtrl, host_val);

        if let Ok(entry_ctrl) = ctx.state().vmcs.read32(VmcsField32::VmEntryControls) {
            let _ = ctx.state().vmcs.write32(
                VmcsField32::VmEntryControls,
                entry_ctrl | vm_entry::LOAD_IA32_PERF_GLOBAL_CTRL,
            );
        }
        if let Ok(exit_ctrl) = ctx.state().vmcs.read32(VmcsField32::PrimaryVmExitControls) {
            let _ = ctx.state().vmcs.write32(
                VmcsField32::PrimaryVmExitControls,
                exit_ctrl | vm_exit::LOAD_IA32_PERF_GLOBAL_CTRL,
            );
        }
    }

    let loop_result = loop {
        // Track total time in run loop (guest + exit handling)
        let loop_start_tsc = rdtsc();

        // Sync GPRs to VmxContext before entry
        ctx.sync_gprs_to_vmx_ctx();

        // Inject any pending APIC interrupts before VM entry
        inject_pending_interrupt(ctx).map_err(VmRunError::ExitHandler)?;

        // Record VM entry overhead (time from loop start to just before VM entry)
        let pre_entry_tsc = rdtsc();
        ctx.state_mut().exit_stats.vmentry_overhead_cycles +=
            pre_entry_tsc.saturating_sub(loop_start_tsc);

        // Load guest KERNEL_GS_BASE before VM entry. IA32_KERNEL_GS_BASE has
        // no VMCS field so VMX does not swap it automatically.
        let msr = machine.msr_access();
        let _ = msr.write_msr(msr::IA32_KERNEL_GS_BASE, ctx.state().kernel_gs_base);

        // Swap PEBS PMU MSRs around guest execution if a precise exit is
        // armed for this iteration. IA32_DS_AREA has no dedicated guest VMCS
        // field, so we save the host value, write the guest value, run the
        // guest, then restore the host value. `pebs_armed_this_iter` is
        // captured before VM-entry because the exit handler may clear
        // `armed_action`.
        let pebs_armed_this_iter = ctx
            .state()
            .pebs_state
            .as_deref()
            .is_some_and(|p| p.armed_action.is_some());
        if pebs_armed_this_iter {
            pebs_pre_vm_entry(ctx, msr);
        }

        // Enter the guest.
        // We need to split the borrow here to get mutable access to vmx_ctx
        // while keeping immutable access to vmcs.
        let state = ctx.state_mut();
        // SAFETY: Caller guarantees VMCS is properly configured and loaded,
        // interrupts are disabled, and preemption cannot migrate us.
        let run_result = unsafe { runner.run(&mut state.vmx_ctx, &state.vmcs) };

        // Restore host PMU MSRs immediately after VM exit if we loaded our
        // PEBS state on entry. This must precede any other host-side MSR
        // reads (e.g. KERNEL_GS_BASE below) only in spirit — the order
        // doesn't matter for correctness, but doing PMU first matches the
        // load order to keep the diff symmetric.
        if pebs_armed_this_iter {
            pebs_post_vm_exit(ctx, msr);
        }

        // Save guest KERNEL_GS_BASE immediately after VM exit, before any IRQ
        // window can let a host interrupt handler overwrite the MSR. Then
        // restore the host value so interrupt handlers see correct per-CPU data.
        ctx.state_mut().kernel_gs_base = msr.read_msr(msr::IA32_KERNEL_GS_BASE).unwrap_or(0);
        let _ = msr.write_msr(msr::IA32_KERNEL_GS_BASE, host_kernel_gs_base);

        // Record guest execution time (includes VMX entry/exit transitions)
        let post_exit_tsc = rdtsc();
        ctx.state_mut().exit_stats.guest_cycles += post_exit_tsc.saturating_sub(pre_entry_tsc);

        // Order the instruction stream before reading the PMU counter.
        // LFENCE guarantees all prior instructions have completed locally and no
        // later instruction begins until it completes (SDM Vol 3A §10.3 footnote 3,
        // Vol 2A LFENCE description). This is sufficient for RDPMC which needs prior
        // instructions to have retired so their counter updates are visible.
        // CPUID would also work but causes an L0 VM exit in nested virt (~2000 cycles).
        // SAFETY: LFENCE is a safe ordering instruction that ensures prior
        // instructions complete locally before RDPMC reads the performance counter.
        #[cfg(not(feature = "cargo"))]
        unsafe {
            core::arch::asm!("lfence", options(preserves_flags, nostack));
        }

        // Briefly enable interrupts to service pending host interrupts (timer
        // ticks, IPIs) between VM exits. Host XCR0 is already restored by the
        // assembly exit handler, so AVX-512 is safe to use in interrupt context.
        let pre_irq_tsc = rdtsc();
        {
            let _irq_window = ReverseIrqGuard::new(machine.kernel());
            let count = ctx.state().instruction_counter.read();
            ctx.state_mut().last_instruction_count = count;
        }
        let post_irq_tsc = rdtsc();
        ctx.state_mut().exit_stats.irq_window_cycles += post_irq_tsc.saturating_sub(pre_irq_tsc);

        if let Err(ref e) = run_result {
            // VM entry failed - try to read error info from VMCS
            if let Ok(error) = ctx.state().vmcs.read32(VmcsField32::VmInstructionError) {
                log_err!("VM entry failed: {:?}, VM_INSTRUCTION_ERROR={}", e, error);
            } else {
                log_err!("VM entry failed: {:?}, couldn't read error field", e);
            }
            return Err(VmRunError::VmEntry(run_result.unwrap_err()));
        }

        // Sync GPRs from VmxContext after exit
        ctx.sync_gprs_from_vmx_ctx();

        // Record VM exit overhead excluding IRQ window time
        let pre_handler_tsc = rdtsc();
        let total_exit_overhead = pre_handler_tsc.saturating_sub(post_exit_tsc);
        let irq_window = post_irq_tsc.saturating_sub(pre_irq_tsc);
        ctx.state_mut().exit_stats.vmexit_overhead_cycles +=
            total_exit_overhead.saturating_sub(irq_window);

        // Handle the VM exit
        let kernel = machine.kernel();
        match handle_exit(ctx, kernel, allocator) {
            ExitHandlerResult::Continue => {
                // Finalize log entry with memory hash (if logging is enabled)
                ctx.finalize_log_entry(kernel);

                // Record total run loop time for this iteration
                let loop_end_tsc = rdtsc();
                ctx.state_mut().exit_stats.total_run_cycles +=
                    loop_end_tsc.saturating_sub(loop_start_tsc);

                // Exit was fully handled - check if scheduler needs to run before re-entering.
                // We cannot call cond_resched() here because:
                // 1. The VMCS is loaded and must stay on this CPU
                // 2. cond_resched() requires preemption enabled, which could migrate us
                // Instead, return to userspace - the ioctl return path allows scheduling.
                if kernel.need_resched() {
                    break Ok(ExitReason::NeedResched);
                }
                continue;
            }
            ExitHandlerResult::ExitToUserspace(reason) => {
                // Finalize log entry with memory hash (if logging is enabled)
                ctx.finalize_log_entry(machine.kernel());

                // Record total run loop time for this iteration
                let loop_end_tsc = rdtsc();
                ctx.state_mut().exit_stats.total_run_cycles +=
                    loop_end_tsc.saturating_sub(loop_start_tsc);

                // Exit requires userspace handling
                break Ok(reason);
            }
            ExitHandlerResult::Error(e) => {
                // Record total run loop time even on error
                let loop_end_tsc = rdtsc();
                ctx.state_mut().exit_stats.total_run_cycles +=
                    loop_end_tsc.saturating_sub(loop_start_tsc);

                // Fatal error
                break Err(VmRunError::ExitHandler(e));
            }
        }
    };

    // Restore host PMU state. Must happen before we leave the
    // preemption-disabled region so we are still on the same CPU as `prepare`.
    let finish_result = ctx
        .state_mut()
        .instruction_counter
        .finish()
        .map_err(VmRunError::InstructionCounter);

    // Save exit info for userspace (VMCS is still loaded).
    // Deferred to here to avoid 2 VMREAD per iteration — only needed on the
    // final exit, not the millions of Continue iterations.
    ctx.state_mut().last_exit_qualification = ctx
        .state()
        .vmcs
        .read_natural(VmcsFieldNatural::ExitQualification)
        .unwrap_or(0);
    ctx.state_mut().last_guest_physical_addr = ctx
        .state()
        .vmcs
        .read64(VmcsField64::GuestPhysicalAddr)
        .unwrap_or(0);

    finish_result?;
    loop_result
}
