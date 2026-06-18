// SPDX-License-Identifier: GPL-2.0

//! Shared VM ioctl handlers using trait abstraction.
//!
//! This module provides a `VmFileOps` trait that abstracts over `BedrockVmFile`
//! and `BedrockForkedVmFile`, allowing the same handler code to work with both.

use core::mem::size_of;
use core::sync::atomic::{AtomicBool, Ordering};

use kernel::bindings;

use super::super::c_helpers::{bedrock_copy_from_user, bedrock_copy_to_user, PreemptionGuard};
use super::super::factory::KernelFrameAllocator;
use super::super::machine::MACHINE;
use super::super::page::{EventBuffer, PagePool};
use super::super::vmx::registers::GuestRegisters;
use super::super::vmx::traits::{
    CowAllocator, InstructionCounterError, Machine, VmContext, VmRunError,
};
use super::super::vmx::ExitReason;
use super::super::vmx::{EventCategories, ExitTrigger, RdrandMode};
use super::super::vmx_asm::RealVmRunner;
use super::structs::*;

/// Trait abstracting VM file operations for both root and forked VMs.
///
/// This trait allows handlers to work generically with both VM types,
/// eliminating code duplication.
pub(crate) trait VmFileOps {
    /// The VmContext type this file wraps.
    type Vm: VmContext;

    /// Get a reference to the VM.
    fn vm(&self) -> &Self::Vm;

    /// Get a mutable reference to the VM.
    fn vm_mut(&mut self) -> &mut Self::Vm;

    /// Get the VM's unique identifier.
    fn vm_id(&self) -> u64;

    /// Get a reference to the running flag.
    fn running(&self) -> &AtomicBool;

    /// Get a reference to the optional unified event buffer.
    fn event_buffer(&self) -> Option<&EventBuffer>;

    /// Get a mutable reference to the optional unified event buffer.
    fn event_buffer_mut(&mut self) -> &mut Option<EventBuffer>;

    /// Check if this VM can be run (no children for forkable VMs).
    fn can_run(&self) -> bool;

    /// Get the children count (for error messages).
    fn children_count(&self) -> usize;

    /// Get mutable references to both the VM and page pool.
    /// Enables split-borrow: vm and pool are disjoint fields.
    fn vm_and_pool(&mut self) -> (&mut Self::Vm, &mut PagePool);
}

/// Handle GET_REGS ioctl - copy all VM registers to userspace.
pub(crate) fn handle_get_regs<F: VmFileOps>(vm_file: &F, arg: usize) -> isize {
    let vm = vm_file.vm();

    // Disable preemption to ensure we stay on the same CPU during VMCS operations
    let _preempt_guard = PreemptionGuard::new();

    // Use VmContext::get_registers_guarded to load VMCS, read registers, and clear VMCS
    let guest_regs = match vm.get_registers_guarded() {
        Ok(regs) => regs,
        Err(e) => {
            log_err!("GET_REGS failed: {:?}\n", e);
            return -(bindings::EINVAL as isize);
        }
    };

    let regs = BedrockRegs {
        gprs: guest_regs.gprs,
        control_regs: guest_regs.control_regs,
        debug_regs: guest_regs.debug_regs,
        segment_regs: guest_regs.segment_regs,
        descriptor_tables: guest_regs.descriptor_tables,
        extended_control: guest_regs.extended_control_regs,
        rip: guest_regs.rip,
        rflags: guest_regs.rflags,
    };

    // Copy to userspace
    // SAFETY: `arg` is a user-provided pointer passed from the ioctl syscall, and `regs`
    // is a valid stack-local struct. bedrock_copy_to_user performs a bounded copy of
    // size_of::<BedrockRegs>() bytes and returns the number of bytes not copied.
    let not_copied = unsafe {
        bedrock_copy_to_user(
            arg as *mut core::ffi::c_void,
            core::ptr::from_ref(&regs).cast::<core::ffi::c_void>(),
            size_of::<BedrockRegs>() as core::ffi::c_ulong,
        )
    };

    if not_copied != 0 {
        return -(bindings::EFAULT as isize);
    }

    0
}

/// Handle SET_REGS ioctl - copy all VM registers from userspace.
pub(crate) fn handle_set_regs<F: VmFileOps>(vm_file: &mut F, arg: usize) -> isize {
    let mut regs = core::mem::MaybeUninit::<BedrockRegs>::uninit();

    // Copy from userspace
    // SAFETY: `arg` is a user-provided pointer from the ioctl syscall. `regs.as_mut_ptr()`
    // points to valid, aligned, writable memory for a BedrockRegs. bedrock_copy_from_user
    // performs a bounded copy and returns the number of bytes not copied.
    let not_copied = unsafe {
        bedrock_copy_from_user(
            regs.as_mut_ptr().cast::<core::ffi::c_void>(),
            arg as *const core::ffi::c_void,
            size_of::<BedrockRegs>() as core::ffi::c_ulong,
        )
    };

    if not_copied != 0 {
        return -(bindings::EFAULT as isize);
    }

    // SAFETY: bedrock_copy_from_user succeeded (returned 0), so all bytes of `regs`
    // have been written and it is now fully initialized.
    let regs = unsafe { regs.assume_init() };

    // Disable preemption to ensure we stay on the same CPU during VMCS operations
    let _preempt_guard = PreemptionGuard::new();

    // Use VmContext::set_registers_guarded to load VMCS, set registers, and clear VMCS
    let vm = vm_file.vm_mut();
    let guest_regs = GuestRegisters {
        gprs: regs.gprs,
        control_regs: regs.control_regs,
        debug_regs: regs.debug_regs,
        segment_regs: regs.segment_regs,
        descriptor_tables: regs.descriptor_tables,
        extended_control_regs: regs.extended_control,
        rip: regs.rip,
        rflags: regs.rflags,
    };
    match vm.set_registers_guarded(&guest_regs) {
        Ok(()) => 0,
        Err(e) => {
            log_err!("SET_REGS failed: {:?}\n", e);
            -(bindings::EINVAL as isize)
        }
    }
}

use super::super::vmcs::RealVmcs;

/// Handle RUN ioctl - run the VM until it exits to userspace.
///
/// Uses a refill loop: before each VM entry, the page pool is refilled in
/// sleepable context. If the pool is exhausted mid-run (PoolExhausted exit),
/// the run loop exits back to sleepable context, refills, and re-enters.
pub(crate) fn handle_run<F: VmFileOps>(vm_file: &mut F, arg: usize) -> isize
where
    F::Vm: VmContext<Vmcs = RealVmcs>,
    for<'a> KernelFrameAllocator<'a>: CowAllocator<<F::Vm as VmContext>::CowPage>,
{
    // Get running flag pointer upfront to avoid borrow conflicts
    let running_ptr = core::ptr::from_ref(vm_file.running());

    // Check for concurrent access
    // SAFETY: running_ptr was derived from a valid reference to vm_file.running() and
    // remains valid for the lifetime of vm_file. We dereference it to call atomic
    // compare_exchange, which is inherently thread-safe.
    if unsafe { &*running_ptr }
        .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        log_err!(
            "CONCURRENT ACCESS DETECTED: VM {} RUN called while already running!\n",
            vm_file.vm_id()
        );
        return -(bindings::EBUSY as isize);
    }

    // VMs with children cannot be run
    if !vm_file.can_run() {
        log_err!(
            "VM {} has {} children and cannot be run\n",
            vm_file.vm_id(),
            vm_file.children_count()
        );
        // SAFETY: running_ptr is valid
        unsafe { &*running_ptr }.store(false, Ordering::Release);
        return -(bindings::EBUSY as isize);
    }

    // Use a guard to ensure we clear the running flag on all exit paths
    struct RunningGuard(*const AtomicBool);
    impl Drop for RunningGuard {
        fn drop(&mut self) {
            // SAFETY: The pointer was valid when the guard was created
            // and remains valid until the function returns
            unsafe { &*self.0 }.store(false, Ordering::Release);
        }
    }
    let _running_guard = RunningGuard(running_ptr);

    let mut first_iteration = true;
    // Only refill the pool if we hit PoolExhausted - safeguards against non-deterministic refills
    let mut pool_exhausted = false;
    let exit_reason = loop {
        // Refill pool in sleepable context (before disabling preemption)
        if pool_exhausted {
            let (_, pool) = vm_file.vm_and_pool();
            if !pool.refill() {
                return -(bindings::ENOMEM as isize);
            }
        }

        let _preempt_guard = PreemptionGuard::new();
        let (vm, pool) = vm_file.vm_and_pool();

        if first_iteration {
            // Clear the event buffer only on first entry (after userspace has
            // drained the previous run's output). `event_clear` also re-appends
            // any event staged when the buffer filled mid-run.
            vm.state_mut().event_clear();
            first_iteration = false;
        }

        let mut runner = RealVmRunner::new();
        let mut allocator = KernelFrameAllocator::new_with_pool(MACHINE.kernel(), pool);

        // SAFETY: vm.run executes the guest via VMLAUNCH/VMRESUME. Preemption is disabled
        // (via _preempt_guard) so the VMCS stays on the current CPU. The runner, machine,
        // and allocator are valid for the duration of the call.
        match unsafe { vm.run(&mut runner, &MACHINE, &mut allocator) } {
            Ok(ExitReason::PoolExhausted) => {
                // PreemptionGuard drops here — back in sleepable context
                // Loop will refill at the top
                pool_exhausted = true;
                continue;
            }
            Ok(reason) => break reason,
            Err(e) => {
                log_err!("VM run failed: {:?}\n", e);
                return match e {
                    VmRunError::InstructionCounter(InstructionCounterError::Unavailable) => {
                        -(bindings::EOPNOTSUPP as isize)
                    }
                    _ => -(bindings::EIO as isize),
                };
            }
        }
    };

    // Get exit info
    let vm = vm_file.vm();
    let exit_qualification = vm.state().last_exit_qualification;
    let guest_physical_addr = vm.state().last_guest_physical_addr;
    let event_len = vm.state().event_buffer_len();
    let emulated_tsc = vm.state().emulated_tsc;
    let tsc_frequency = vm.state().tsc_frequency;

    // Build exit info struct
    let exit_info = BedrockVmExit {
        exit_reason: exit_reason as u32,
        _reserved: 0,
        exit_qualification,
        guest_physical_addr,
        event_len: event_len as u32,
        _pad: 0,
        emulated_tsc,
        tsc_frequency,
    };

    // Copy to userspace
    // SAFETY: `arg` is a user-provided pointer from the ioctl syscall, and `exit_info`
    // is a valid stack-local struct. bedrock_copy_to_user performs a bounded copy.
    let not_copied = unsafe {
        bedrock_copy_to_user(
            arg as *mut core::ffi::c_void,
            core::ptr::from_ref(&exit_info).cast::<core::ffi::c_void>(),
            size_of::<BedrockVmExit>() as core::ffi::c_ulong,
        )
    };

    if not_copied != 0 {
        return -(bindings::EFAULT as isize);
    }

    0
}

/// Handle GET_VM_ID ioctl - return the VM's unique identifier.
pub(crate) fn handle_get_vm_id<F: VmFileOps>(vm_file: &F, arg: usize) -> isize {
    let vm_id = vm_file.vm_id();

    // SAFETY: `arg` is a user-provided pointer from the ioctl syscall, and `vm_id`
    // is a valid stack-local u64. bedrock_copy_to_user performs a bounded copy.
    let not_copied = unsafe {
        bedrock_copy_to_user(
            arg as *mut core::ffi::c_void,
            core::ptr::from_ref(&vm_id).cast::<core::ffi::c_void>(),
            size_of::<u64>() as core::ffi::c_ulong,
        )
    };

    if not_copied != 0 {
        return -(bindings::EFAULT as isize);
    }

    0
}

/// Handle SET_RDRAND_CONFIG ioctl - configure RDRAND emulation mode.
pub(crate) fn handle_set_rdrand_config<F: VmFileOps>(vm_file: &mut F, arg: usize) -> isize {
    let mut config = core::mem::MaybeUninit::<BedrockRdrandConfig>::uninit();

    // SAFETY: `config.as_mut_ptr()` points to valid, aligned, writable memory for a
    // BedrockRdrandConfig. `arg` is a user-provided pointer from the ioctl syscall.
    // bedrock_copy_from_user performs a bounded copy.
    let not_copied = unsafe {
        bedrock_copy_from_user(
            config.as_mut_ptr().cast::<core::ffi::c_void>(),
            arg as *const core::ffi::c_void,
            size_of::<BedrockRdrandConfig>() as core::ffi::c_ulong,
        )
    };

    if not_copied != 0 {
        return -(bindings::EFAULT as isize);
    }

    // SAFETY: bedrock_copy_from_user succeeded (returned 0), so all bytes of `config`
    // have been written and it is now fully initialized.
    let config = unsafe { config.assume_init() };

    // Convert mode value to RdrandMode enum
    let mode = match config.mode {
        0 => RdrandMode::SeededRng,
        1 => RdrandMode::ExitToUserspace,
        _ => {
            log_err!("SET_RDRAND_CONFIG: invalid mode {}\n", config.mode);
            return -(bindings::EINVAL as isize);
        }
    };

    // Configure the RDRAND state
    let vm = vm_file.vm_mut();
    vm.state_mut().devices.rdrand.configure(mode, config.value);

    log_info!(
        "SET_RDRAND_CONFIG: mode={:?}, value=0x{:x}\n",
        mode,
        config.value
    );
    0
}

/// Handle SET_RDRAND_VALUE ioctl - set pending RDRAND value.
pub(crate) fn handle_set_rdrand_value<F: VmFileOps>(vm_file: &mut F, arg: usize) -> isize {
    let mut value: u64 = 0;

    // SAFETY: `value` is a valid, aligned, writable stack-local u64. `arg` is a
    // user-provided pointer from the ioctl syscall. bedrock_copy_from_user performs
    // a bounded copy of size_of::<u64>() bytes.
    let not_copied = unsafe {
        bedrock_copy_from_user(
            core::ptr::from_mut(&mut value).cast::<core::ffi::c_void>(),
            arg as *const core::ffi::c_void,
            size_of::<u64>() as core::ffi::c_ulong,
        )
    };

    if not_copied != 0 {
        return -(bindings::EFAULT as isize);
    }

    let vm = vm_file.vm_mut();
    vm.state_mut().devices.rdrand.set_pending_value(value);

    0
}

/// Handle SET_EVENT_CONFIG ioctl — enable/disable the event stream (allocating
/// or freeing the 1 MB event buffer), install the category include mask, and set
/// the `Exit`-record trigger policy (`ExitTrigger`, target/start TSC thresholds,
/// and the memory-hash / #PF flags).
pub(crate) fn handle_set_event_config<F: VmFileOps>(vm_file: &mut F, arg: usize) -> isize {
    let mut config = core::mem::MaybeUninit::<BedrockEventConfig>::uninit();

    // SAFETY: `config.as_mut_ptr()` points to valid, aligned, writable memory for a
    // BedrockEventConfig. `arg` is a user-provided pointer from the ioctl syscall.
    // bedrock_copy_from_user performs a bounded copy.
    let not_copied = unsafe {
        bedrock_copy_from_user(
            config.as_mut_ptr().cast::<core::ffi::c_void>(),
            arg as *const core::ffi::c_void,
            size_of::<BedrockEventConfig>() as core::ffi::c_ulong,
        )
    };

    if not_copied != 0 {
        return -(bindings::EFAULT as isize);
    }

    // SAFETY: bedrock_copy_from_user succeeded (returned 0), so all bytes of `config`
    // have been written and it is now fully initialized.
    let config = unsafe { config.assume_init() };

    let was_enabled = vm_file.event_buffer().is_some();
    let want_enabled = config.enabled != 0;

    // Handle buffer allocation state changes.
    if want_enabled && !was_enabled {
        let buffer = match EventBuffer::new() {
            Some(b) => b,
            None => {
                log_err!("SET_EVENT_CONFIG: failed to allocate event buffer\n");
                return -(bindings::ENOMEM as isize);
            }
        };

        // Set the buffer pointer in the VM. The buffer is kept alive in
        // vm_file.event_buffer for the lifetime of the VM (or until disabled).
        vm_file
            .vm_mut()
            .state_mut()
            .set_event_buffer(buffer.as_ptr());
        *vm_file.event_buffer_mut() = Some(buffer);
    } else if !want_enabled && was_enabled {
        vm_file.vm_mut().state_mut().clear_event_buffer_ptr();
        *vm_file.event_buffer_mut() = None;
    }

    // Install the category mask regardless of the enable transition (lets a
    // caller adjust categories while the stream stays enabled).
    vm_file
        .vm_mut()
        .state_mut()
        .set_event_categories(EventCategories(config.categories));

    // Apply the `Exit`-record trigger policy. The stream's `enabled` flag gates
    // the buffer; capturing exits additionally needs the EXIT category (above)
    // and a non-Disabled trigger.
    let trigger = match config.exit_trigger {
        0 => ExitTrigger::Disabled,
        1 => ExitTrigger::AllExits,
        2 => ExitTrigger::AtTsc,
        3 => ExitTrigger::AtShutdown,
        4 => ExitTrigger::Checkpoints,
        5 => ExitTrigger::TscRange,
        _ => {
            log_err!(
                "SET_EVENT_CONFIG: invalid exit_trigger {}\n",
                config.exit_trigger
            );
            return -(bindings::EINVAL as isize);
        }
    };
    let trigger = if want_enabled {
        trigger
    } else {
        ExitTrigger::Disabled
    };
    let state = vm_file.vm_mut().state_mut();
    state.set_exit_trigger(trigger, config.exit_target_tsc);
    state.set_exit_start_tsc(config.exit_start_tsc);
    state.skip_memory_hash = (config.exit_flags & 1) != 0;
    state.set_intercept_pf((config.exit_flags & 2) != 0);

    log_info!(
        "SET_EVENT_CONFIG: enabled={}, categories={:#x}, exit_trigger={:?}, exit_flags={:#x} for VM {}\n",
        want_enabled,
        config.categories,
        trigger,
        config.exit_flags,
        vm_file.vm_id()
    );
    0
}

/// Handle GET_EXIT_STATS ioctl - retrieve exit handler performance statistics.
pub(crate) fn handle_get_exit_stats<F: VmFileOps>(vm_file: &F, arg: usize) -> isize {
    let stats = &vm_file.vm().state().exit_stats;

    // Helper to convert ExitStats to BedrockExitStatEntry
    let convert = |s: &super::super::vmx::vm_state::ExitStats| BedrockExitStatEntry {
        count: s.count,
        cycles: s.cycles,
    };

    // Build the userspace-compatible stats struct
    let exit_stats = BedrockExitStats {
        cpuid: convert(&stats.cpuid),
        msr_read: convert(&stats.msr_read),
        msr_write: convert(&stats.msr_write),
        cr_access: convert(&stats.cr_access),
        io_instruction: convert(&stats.io_instruction),
        ept_violation: convert(&stats.ept_violation),
        external_interrupt: convert(&stats.external_interrupt),
        rdtsc: convert(&stats.rdtsc),
        rdtscp: convert(&stats.rdtscp),
        rdpmc: convert(&stats.rdpmc),
        mwait: convert(&stats.mwait),
        vmcall: convert(&stats.vmcall),
        apic_access: convert(&stats.apic_access),
        mtf: convert(&stats.mtf),
        xsetbv: convert(&stats.xsetbv),
        rdrand: convert(&stats.rdrand),
        rdseed: convert(&stats.rdseed),
        exception_nmi: convert(&stats.exception_nmi),
        other: convert(&stats.other),
        total_run_cycles: stats.total_run_cycles,
        guest_cycles: stats.guest_cycles,
        vmentry_overhead_cycles: stats.vmentry_overhead_cycles,
        vmexit_overhead_cycles: stats.vmexit_overhead_cycles,
        irq_window_cycles: stats.irq_window_cycles,
        pebs_arm_below_min_delta: stats.pebs_arm_below_min_delta,
        pebs_arm_already_past: stats.pebs_arm_already_past,
        pebs_armed_iter_no_fire: stats.pebs_armed_iter_no_fire,
        apic_timer_late_inject: stats.apic_timer_late_inject,
    };

    // SAFETY: `arg` is a user-provided pointer from the ioctl syscall, and `exit_stats`
    // is a valid stack-local struct. bedrock_copy_to_user performs a bounded copy.
    let not_copied = unsafe {
        bedrock_copy_to_user(
            arg as *mut core::ffi::c_void,
            core::ptr::from_ref(&exit_stats).cast::<core::ffi::c_void>(),
            size_of::<BedrockExitStats>() as core::ffi::c_ulong,
        )
    };

    if not_copied != 0 {
        return -(bindings::EFAULT as isize);
    }

    0
}

/// Handle SET_STOP_TSC ioctl - set TSC value at which VM should stop.
pub(crate) fn handle_set_stop_tsc<F: VmFileOps>(vm_file: &mut F, arg: usize) -> isize {
    let mut value = core::mem::MaybeUninit::<u64>::uninit();

    // SAFETY: `value.as_mut_ptr()` points to valid, aligned, writable memory for a u64.
    // `arg` is a user-provided pointer from the ioctl syscall. bedrock_copy_from_user
    // performs a bounded copy.
    let not_copied = unsafe {
        bedrock_copy_from_user(
            value.as_mut_ptr().cast::<core::ffi::c_void>(),
            arg as *const core::ffi::c_void,
            size_of::<u64>() as core::ffi::c_ulong,
        )
    };

    if not_copied != 0 {
        return -(bindings::EFAULT as isize);
    }

    // SAFETY: bedrock_copy_from_user succeeded (returned 0), so the u64 is fully initialized.
    let value = unsafe { value.assume_init() };

    // 0 means disabled, any other value is the stop TSC
    let vm = vm_file.vm_mut();
    if value == 0 {
        vm.state_mut().stop_at_tsc = None;
        log_info!("SET_STOP_TSC: disabled for VM {}\n", vm_file.vm_id());
    } else {
        vm.state_mut().stop_at_tsc = Some(value);
        log_info!(
            "SET_STOP_TSC: set to {} for VM {}\n",
            value,
            vm_file.vm_id()
        );
    }

    0
}

/// Handle SET_SINGLE_STEP ioctl - configure MTF single-stepping.
pub(crate) fn handle_set_single_step<F: VmFileOps>(vm_file: &mut F, arg: usize) -> isize {
    let mut config = core::mem::MaybeUninit::<BedrockSingleStepConfig>::uninit();

    // SAFETY: `config.as_mut_ptr()` points to valid, aligned, writable memory for a
    // BedrockSingleStepConfig. `arg` is a user-provided pointer from the ioctl syscall.
    // bedrock_copy_from_user performs a bounded copy.
    let not_copied = unsafe {
        bedrock_copy_from_user(
            config.as_mut_ptr().cast::<core::ffi::c_void>(),
            arg as *const core::ffi::c_void,
            size_of::<BedrockSingleStepConfig>() as core::ffi::c_ulong,
        )
    };

    if not_copied != 0 {
        return -(bindings::EFAULT as isize);
    }

    // SAFETY: bedrock_copy_from_user succeeded (returned 0), so all bytes of `config`
    // have been written and it is now fully initialized.
    let config = unsafe { config.assume_init() };
    let vm = vm_file.vm_mut();

    if config.enabled != 0 {
        vm.state_mut().single_step_tsc_range = Some((config.tsc_start, config.tsc_end));
        log_info!(
            "SET_SINGLE_STEP: enabled for TSC range [{}, {}) for VM {}\n",
            config.tsc_start,
            config.tsc_end,
            vm_file.vm_id()
        );
    } else {
        vm.state_mut().single_step_tsc_range = None;
        vm.state_mut().mtf_enabled = false;
        log_info!("SET_SINGLE_STEP: disabled for VM {}\n", vm_file.vm_id());
    }

    0
}

/// Handle GET_FEEDBACK_BUFFER_INFO ioctl - return feedback buffer registration info.
///
/// Takes a BedrockFeedbackBufferInfoRequest with the buffer index, returns
/// BedrockFeedbackBufferInfo for that index.
pub(crate) fn handle_get_feedback_buffer_info<F: VmFileOps>(vm_file: &F, arg: usize) -> isize {
    // First read the request to get the buffer index
    let mut request = core::mem::MaybeUninit::<BedrockFeedbackBufferInfoRequest>::uninit();

    // SAFETY: `request.as_mut_ptr()` points to valid, aligned, writable memory for a
    // BedrockFeedbackBufferInfoRequest. `arg` is a user-provided pointer from the ioctl
    // syscall. bedrock_copy_from_user performs a bounded copy.
    let not_copied = unsafe {
        bedrock_copy_from_user(
            request.as_mut_ptr().cast::<core::ffi::c_void>(),
            arg as *const core::ffi::c_void,
            size_of::<BedrockFeedbackBufferInfoRequest>() as core::ffi::c_ulong,
        )
    };

    if not_copied != 0 {
        return -(bindings::EFAULT as isize);
    }

    // SAFETY: bedrock_copy_from_user succeeded (returned 0), so all bytes of `request`
    // have been written and it is now fully initialized.
    let request = unsafe { request.assume_init() };
    let index = request.index as usize;

    let vm = vm_file.vm();
    // The number of feedback buffers is unbounded; an unregistered or
    // out-of-range index is reported as not-registered (registered = 0) so
    // userspace can enumerate buffers by querying until the first gap.
    let info = match vm.state().feedback_buffers.get(index) {
        Some(buffer) => BedrockFeedbackBufferInfo {
            gva: buffer.gva,
            size: buffer.size,
            num_pages: buffer.num_pages as u64,
            registered: 1,
            index: index as u32,
            id_len: buffer.id_len,
            _reserved: 0,
            id: buffer.id,
        },
        None => BedrockFeedbackBufferInfo {
            gva: 0,
            size: 0,
            num_pages: 0,
            registered: 0,
            index: index as u32,
            id_len: 0,
            _reserved: 0,
            id: [0u8; super::structs::FEEDBACK_BUFFER_ID_MAX_LEN],
        },
    };

    // SAFETY: `arg` is a user-provided pointer from the ioctl syscall, and `info`
    // is a valid stack-local struct. bedrock_copy_to_user performs a bounded copy.
    let not_copied = unsafe {
        bedrock_copy_to_user(
            arg as *mut core::ffi::c_void,
            core::ptr::from_ref(&info).cast::<core::ffi::c_void>(),
            size_of::<BedrockFeedbackBufferInfo>() as core::ffi::c_ulong,
        )
    };

    if not_copied != 0 {
        return -(bindings::EFAULT as isize);
    }

    0
}

/// Offset of the data payload past the header in a `BedrockIoActionPayload`.
const IO_ACTION_DATA_OFFSET: usize = size_of::<BedrockIoActionHeader>();

/// Handle `BEDROCK_VM_QUEUE_IO_ACTION` ioctl — userspace pushes a request
/// onto the hypervisor's pending queue. The guest's `bedrock-io.ko` is
/// free to fire long-running commands in parallel: this ioctl returns
/// immediately once the request is queued, and `HYPERCALL_IO_GET_REQUEST`
/// promotes the next pending entry as soon as the previous one has been
/// consumed (independent of when the guest worker calls
/// `HYPERCALL_IO_PUT_RESPONSE`).
///
/// The header is staged through the stack (16 bytes); the payload bytes
/// are copied directly from userspace into a per-pending `HeapVec<u8>`,
/// avoiding the 4KB stack burst a single `BedrockIoActionPayload` would
/// cost. Returns `EBUSY` only if the pending queue is at
/// `PENDING_IO_QUEUE_CAP` capacity.
pub(crate) fn handle_queue_io_action<F: VmFileOps>(vm_file: &mut F, arg: usize) -> isize {
    let mut header = core::mem::MaybeUninit::<BedrockIoActionHeader>::uninit();

    // SAFETY: `header.as_mut_ptr()` points to valid, aligned, writable memory
    // for a `BedrockIoActionHeader` (16 bytes). `arg` is a user-provided
    // pointer from the ioctl syscall; `bedrock_copy_from_user` performs a
    // bounded copy.
    let not_copied = unsafe {
        bedrock_copy_from_user(
            header.as_mut_ptr().cast::<core::ffi::c_void>(),
            arg as *const core::ffi::c_void,
            size_of::<BedrockIoActionHeader>() as core::ffi::c_ulong,
        )
    };
    if not_copied != 0 {
        return -(bindings::EFAULT as isize);
    }
    // SAFETY: `bedrock_copy_from_user` returned 0, so all bytes of `header`
    // have been written.
    let header = unsafe { header.assume_init() };

    let len = header.len as usize;
    if len > BEDROCK_IO_CHANNEL_BUF_SIZE {
        return -(bindings::EINVAL as isize);
    }

    // Allocate the per-request data Vec tightly-sized to `len`. This keeps
    // the per-pending heap footprint proportional to the actual request
    // size rather than a fixed 4KB.
    let mut data = match super::super::vmx::heap_vec_with_capacity::<u8>(len) {
        Ok(v) => v,
        Err(_) => return -(bindings::ENOMEM as isize),
    };
    if len > 0 {
        // KVec doesn't have a `resize_with_zero` we can use cheaply, so
        // push zeros first then overwrite via `bedrock_copy_from_user`
        // (which only writes; doesn't require uninit memory). Pushing one
        // byte at a time is acceptable for the queue depths we target.
        // The capacity was reserved above, so push cannot grow the vector
        // and `Err` here means a real allocation failure mid-fill.
        for _ in 0..len {
            if super::super::vmx::heap_vec_push(&mut data, 0u8).is_err() {
                return -(bindings::ENOMEM as isize);
            }
        }
        // SAFETY: `data` has exactly `len` bytes of valid, writable
        // storage now; `arg + IO_ACTION_DATA_OFFSET` is a userspace
        // pointer past the header.
        let not_copied = unsafe {
            bedrock_copy_from_user(
                data.as_mut_ptr().cast::<core::ffi::c_void>(),
                (arg + IO_ACTION_DATA_OFFSET) as *const core::ffi::c_void,
                len as core::ffi::c_ulong,
            )
        };
        if not_copied != 0 {
            return -(bindings::EFAULT as isize);
        }
    }

    let action = super::super::vmx::PendingIoAction {
        target_tsc: header.target_tsc,
        data,
    };

    let chan = &mut vm_file.vm_mut().state_mut().io_channel;
    match chan.enqueue_pending(action) {
        super::super::vmx::EnqueueResult::Queued => {}
        super::super::vmx::EnqueueResult::Full => return -(bindings::EBUSY as isize),
        super::super::vmx::EnqueueResult::OutOfMemory => return -(bindings::ENOMEM as isize),
    }
    // Fast-path: if the in-flight slot is currently free, promote
    // immediately so the next `inject_pending_interrupt` can fire the
    // IRQ without waiting for another VM exit.
    chan.promote_next_pending();

    0
}

/// Handle `BEDROCK_VM_DRAIN_IO_RESPONSE` ioctl — userspace fetches the
/// most recent response captured from the guest via `HYPERCALL_IO_PUT_RESPONSE`.
///
/// Behaves like a single-shot consume: after the response bytes are
/// copied to userspace, the kernel resets `response_len` to 0 so a
/// subsequent drain returns an empty payload (and the next QUEUE can
/// proceed).
pub(crate) fn handle_drain_io_response<F: VmFileOps>(vm_file: &mut F, arg: usize) -> isize {
    let mut header = core::mem::MaybeUninit::<BedrockIoActionHeader>::uninit();
    // SAFETY: `header.as_mut_ptr()` points to 8 bytes of stack memory.
    // `arg` is a user-provided pointer.
    let not_copied = unsafe {
        bedrock_copy_from_user(
            header.as_mut_ptr().cast::<core::ffi::c_void>(),
            arg as *const core::ffi::c_void,
            size_of::<BedrockIoActionHeader>() as core::ffi::c_ulong,
        )
    };
    if not_copied != 0 {
        return -(bindings::EFAULT as isize);
    }
    // SAFETY: `bedrock_copy_from_user` returned 0, so the header is initialized.
    let header = unsafe { header.assume_init() };

    let user_capacity = header.len as usize;
    if user_capacity > BEDROCK_IO_CHANNEL_BUF_SIZE {
        return -(bindings::EINVAL as isize);
    }

    let chan = &mut vm_file.vm_mut().state_mut().io_channel;
    let response_len = chan.response_len.min(user_capacity);

    if response_len > 0 {
        // SAFETY: `chan.response_buf` is a `Box<[u8; IO_CHANNEL_BUF_SIZE]>`
        // so its pointer is valid for `response_len <= IO_CHANNEL_BUF_SIZE`
        // bytes. The destination pointer is in userspace and validated by
        // `bedrock_copy_to_user`.
        let not_copied = unsafe {
            bedrock_copy_to_user(
                (arg + IO_ACTION_DATA_OFFSET) as *mut core::ffi::c_void,
                chan.response_buf.as_ptr().cast::<core::ffi::c_void>(),
                response_len as core::ffi::c_ulong,
            )
        };
        if not_copied != 0 {
            return -(bindings::EFAULT as isize);
        }
    }

    // Write the actual length back into the header.
    let out_header = BedrockIoActionHeader {
        len: response_len as u32,
        _reserved: 0,
        // target_tsc is QUEUE-only; the DRAIN reply leaves it zero.
        target_tsc: 0,
    };
    // SAFETY: `arg` points to a `BedrockIoActionPayload` whose first
    // `size_of::<BedrockIoActionHeader>()` bytes are the header; we
    // overwrite those bytes only.
    let not_copied = unsafe {
        bedrock_copy_to_user(
            arg as *mut core::ffi::c_void,
            core::ptr::from_ref(&out_header).cast::<core::ffi::c_void>(),
            size_of::<BedrockIoActionHeader>() as core::ffi::c_ulong,
        )
    };
    if not_copied != 0 {
        return -(bindings::EFAULT as isize);
    }

    chan.response_len = 0;
    0
}
