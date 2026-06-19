// SPDX-License-Identifier: GPL-2.0

//! Forked VM file operations and handlers.
//!
//! This module provides the file_operations callbacks for bedrock forked-vm
//! anonymous inodes. Forked VMs share most handlers with root VMs via the
//! `VmFileOps` trait.

use core::ffi::c_int;
use core::sync::atomic::AtomicBool;

use kernel::bindings;
use kernel::sync::Arc;

use super::super::c_helpers::{
    bedrock_kva_to_phys, bedrock_remap_pages, bedrock_remap_vmalloc_range, bedrock_vma_end,
    bedrock_vma_pgoff, bedrock_vma_start,
};
use super::super::factory::KernelFrameAllocator;
use super::super::machine::MACHINE;
use super::super::page::{EventBuffer, PagePool, EVENT_BUFFER_SIZE};
use super::super::vmx::traits::{Machine, Page, VmContext};
use super::super::vmx::{CowPageMap, ForkableVm, ParentVm, VmState};
use super::super::HANDLER;
use super::core::BedrockForkedVmFile;
use super::handlers::{self, VmFileOps};
use super::structs::*;
use crate::memory::GuestPhysAddr;

/// Implement VmFileOps for BedrockForkedVmFile.
impl VmFileOps for BedrockForkedVmFile {
    type Vm = super::super::vmx::ForkedVm<
        super::super::vmcs::RealVmcs,
        super::super::page::KernelPage,
        super::super::instruction_counter::LinuxInstructionCounter,
    >;

    fn vm(&self) -> &Self::Vm {
        &self.vm
    }

    fn vm_mut(&mut self) -> &mut Self::Vm {
        &mut self.vm
    }

    fn vm_id(&self) -> u64 {
        self.vm_id
    }

    fn running(&self) -> &AtomicBool {
        &self.running
    }

    fn event_buffer(&self) -> Option<&EventBuffer> {
        self.event_buffer.as_ref()
    }

    fn event_buffer_mut(&mut self) -> &mut Option<EventBuffer> {
        &mut self.event_buffer
    }

    fn can_run(&self) -> bool {
        self.vm.can_run()
    }

    fn children_count(&self) -> usize {
        self.vm.children_count()
    }

    fn vm_and_pool(&mut self) -> (&mut Self::Vm, &mut PagePool) {
        (&mut self.vm, &mut self.page_pool)
    }
}

impl ParentVm for BedrockForkedVmFile {
    fn read_page(&self, gpa: GuestPhysAddr) -> Option<*const u8> {
        self.vm.read_page(gpa)
    }

    fn memory_size(&self) -> usize {
        self.vm.memory_size()
    }

    fn remove_child(&self) {
        ForkableVm::remove_child(&self.vm);
    }
}

impl
    ForkableVm<
        super::super::vmcs::RealVmcs,
        super::super::instruction_counter::LinuxInstructionCounter,
    > for BedrockForkedVmFile
{
    type Page = super::super::page::KernelPage;

    fn vm_state(
        &self,
    ) -> &VmState<
        super::super::vmcs::RealVmcs,
        super::super::instruction_counter::LinuxInstructionCounter,
    > {
        self.vm.vm_state()
    }

    fn vm_state_mut(
        &mut self,
    ) -> &mut VmState<
        super::super::vmcs::RealVmcs,
        super::super::instruction_counter::LinuxInstructionCounter,
    > {
        self.vm.vm_state_mut()
    }

    fn add_child(&self) {
        self.vm.add_child();
    }

    fn remove_child(&self) {
        ForkableVm::remove_child(&self.vm);
    }

    fn children_count(&self) -> usize {
        self.vm.children_count()
    }
}

/// File operations for bedrock forked-vm anonymous inodes.
pub(crate) static BEDROCK_FORKED_VM_FOPS: SyncFileOps = {
    // SAFETY: SyncFileOps::zeroed() produces an all-zeros file_operations, which is valid.
    // We immediately set the required function pointers below.
    let mut fops: bindings::file_operations = unsafe { SyncFileOps::zeroed() };
    fops.owner = core::ptr::null_mut();
    fops.release = Some(bedrock_forked_vm_release);
    fops.unlocked_ioctl = Some(bedrock_forked_vm_ioctl);
    fops.mmap = Some(bedrock_forked_vm_mmap);
    SyncFileOps(fops)
};

/// Release callback for bedrock forked-vm files.
///
/// # Safety
///
/// - `file` must be a valid pointer to a file struct
/// - `file->private_data` must be a valid pointer to a `KBox<BedrockForkedVmFile>`
unsafe extern "C" fn bedrock_forked_vm_release(
    _inode: *mut bindings::inode,
    file: *mut bindings::file,
) -> c_int {
    // SAFETY: `file` is a valid pointer to a file struct, guaranteed by the kernel
    // VFS layer which calls this release callback.
    let private_data = unsafe { (*file).private_data };

    if private_data.is_null() {
        log_err!("bedrock_forked_vm_release: null private_data\n");
        return 0;
    }

    let vm_ptr = private_data.cast::<BedrockForkedVmFile>();
    // SAFETY: We verified private_data is non-null above, and it was set to a valid
    // KBox<BedrockForkedVmFile> pointer when the fd was created in create_forked_vm_fd.
    let vm_id = unsafe { (*vm_ptr).vm_id };
    log_info!("Releasing forked VM {} (fd closed)\n", vm_id);

    // Remove from global vm_list
    {
        let mut guard = HANDLER.lock();
        if let Some(handler) = guard.as_mut() {
            handler.remove_vm(vm_ptr);
        }
    }

    // Drop the file descriptor's Arc reference. Nested forked children may still
    // hold cloned parent Arcs; in that case the allocation is reclaimed when the
    // last child drops.
    // SAFETY: vm_ptr was created by Arc::into_raw in create_forked_vm_fd. This
    // release callback consumes the fd-owned reference exactly once.
    let _ = unsafe { Arc::from_raw(vm_ptr) };

    log_info!("Forked VM {} released successfully\n", vm_id);
    0
}

/// Mmap callback for bedrock forked-vm files.
///
/// Forked VMs support mapping auxiliary buffers (feedback buffers and the
/// unified event buffer). Guest memory cannot be mapped as one contiguous
/// region because it uses COW from the parent.
///
/// # Safety
///
/// - `file` must be a valid pointer to a file struct
/// - `file->private_data` must be a valid pointer to a `BedrockForkedVmFile`
/// - `vma` must be a valid pointer to a vm_area_struct
unsafe extern "C" fn bedrock_forked_vm_mmap(
    file: *mut bindings::file,
    vma: *mut bindings::vm_area_struct,
) -> c_int {
    // SAFETY: `file` is a valid pointer guaranteed by the kernel VFS layer.
    let private_data = unsafe { (*file).private_data };

    if private_data.is_null() {
        return -(bindings::EBADF as i32);
    }

    // SAFETY: private_data is non-null (checked above) and was set to a valid
    // BedrockForkedVmFile pointer when the fd was created. We hold exclusive access
    // because the kernel serializes mmap calls per file.
    let vm_file = unsafe { &mut *(private_data.cast::<BedrockForkedVmFile>()) };

    // SAFETY: `vma` is a valid pointer to a vm_area_struct, guaranteed by the kernel
    // VFS/mmap layer. These helpers read standard VMA fields.
    let vma_start = unsafe { bedrock_vma_start(vma) };
    // SAFETY: Same as above — `vma` is a valid VMA pointer from the kernel mmap layer.
    let vma_end = unsafe { bedrock_vma_end(vma) };
    // SAFETY: Same as above — `vma` is a valid VMA pointer from the kernel mmap layer.
    let vma_pgoff = unsafe { bedrock_vma_pgoff(vma) };

    let requested_size = vma_end - vma_start;
    let offset_bytes = vma_pgoff * 4096;

    // ForkedVm doesn't have contiguous guest memory - it uses COW from parent.
    // We only allow mapping:
    // - offset 0: feedback buffer 0 (up to 1MB)
    // - ... (each feedback slot reserves 1MB)
    // - past the feedback region: the unified event buffer (1MB)
    //
    // Guest serial output flows through the event buffer as `Serial` records,
    // so there is no dedicated serial/TSC page in the layout.
    let feedback_buffer_base_offset: u64 = 0;
    // 1MB per feedback slot; sourced from vmx so userspace and kernel never
    // drift. Per-buffer size is capped but the number of buffers is unbounded.
    let feedback_buffer_slot_size: u64 = super::super::vmx::FEEDBACK_BUFFER_SLOT_SIZE;
    // Event buffer sits at a fixed sentinel offset above the (unbounded)
    // feedback-buffer region (see root.rs). Checked before the feedback
    // catch-all since its offset is also `>= feedback_buffer_base_offset`.
    let event_buffer_offset: u64 = super::super::vmx::EVENT_BUFFER_MMAP_OFFSET;

    if offset_bytes == event_buffer_offset {
        // Event buffer mapping
        if requested_size as usize != EVENT_BUFFER_SIZE {
            log_err!(
                "mmap: event buffer must be exactly {} bytes, got {}\n",
                EVENT_BUFFER_SIZE,
                requested_size
            );
            return -(bindings::EINVAL as i32);
        }

        let event_buffer = match &vm_file.event_buffer {
            Some(buf) => buf,
            None => {
                log_err!("mmap: event buffer not allocated (event stream not enabled)\n");
                return -(bindings::EINVAL as i32);
            }
        };

        let addr = event_buffer.as_ptr().cast::<core::ffi::c_void>();
        // SAFETY: `vma` is a valid VMA pointer from the kernel. `addr` is a valid
        // vmalloc'd pointer to the event buffer. Offset 0 maps from the start.
        let ret = unsafe { bedrock_remap_vmalloc_range(vma, addr, 0) };

        if ret != 0 {
            log_err!("mmap: event buffer remap failed with {}\n", ret);
        } else {
            log_info!("mmap: mapped event buffer for VM {}\n", vm_file.vm_id);
        }

        ret
    } else if offset_bytes >= feedback_buffer_base_offset {
        let relative_offset = offset_bytes - feedback_buffer_base_offset;
        let buffer_index = (relative_offset / feedback_buffer_slot_size) as usize;

        // Check alignment within slot
        if !relative_offset.is_multiple_of(feedback_buffer_slot_size) {
            log_err!("mmap: feedback buffer offset not aligned to slot boundary\n");
            return -(bindings::EINVAL as i32);
        }

        // COW this buffer's pages into the VM now, so the frames we map are the
        // ones the guest will write to. Without this, a forked child mapped
        // before it writes the buffer would later COW each written page to a
        // new frame, leaving this mapping stale ("map once, keep running,
        // re-read"). A no-op for pages already COW'd and for an unregistered /
        // out-of-range index (handled by the `.get()` below). mmap runs in
        // sleepable context, so direct GFP_KERNEL allocation (pool = None) is
        // fine.
        {
            let mut allocator = KernelFrameAllocator::new(MACHINE.kernel());
            vm_file
                .vm
                .cow_feedback_buffer_for_mapping(buffer_index, &mut allocator);
        }

        // Feedback buffer mapping. An unregistered or out-of-range index has no
        // entry in the (unbounded) buffer vector.
        let feedback_buffer = match vm_file.vm.state.feedback_buffers.get(buffer_index) {
            Some(fb) => fb,
            None => {
                log_err!("mmap: feedback buffer {} not registered\n", buffer_index);
                return -(bindings::EINVAL as i32);
            }
        };

        let expected_size = feedback_buffer.num_pages * 4096;
        if requested_size as usize != expected_size {
            log_err!(
                "mmap: feedback buffer {} size mismatch: expected {}, got {}\n",
                buffer_index,
                expected_size,
                requested_size
            );
            return -(bindings::EINVAL as i32);
        }

        // For forked VM, resolve each GPA to HPA:
        // 1. Check COW pages first (if guest wrote to this page, it's in COW map)
        // 2. Otherwise, get from parent chain (walks through nested forks to root)
        let mut hpas = [0u64; 256]; // FEEDBACK_BUFFER_MAX_PAGES = 256

        for (i, hpa) in hpas.iter_mut().enumerate().take(feedback_buffer.num_pages) {
            let gpa = feedback_buffer.gpas[i];
            let page_gpa = GuestPhysAddr::new(gpa);

            // Check if this page is in our COW map
            if let Some(cow_page) =
                <CowPageMap<super::super::page::KernelPage>>::get(&vm_file.vm.cow_pages, page_gpa)
            {
                // Page is in COW map - use its physical address directly
                *hpa = Page::physical_address(cow_page).as_u64();
            } else {
                // Page is in parent chain - get virtual address and convert to physical
                let virt_ptr = match vm_file.vm.read_page(page_gpa) {
                    Some(ptr) => ptr,
                    None => {
                        log_err!(
                            "mmap: failed to resolve GPA {:#x} for feedback buffer {}\n",
                            gpa,
                            buffer_index
                        );
                        return -(bindings::EINVAL as i32);
                    }
                };
                // Convert kernel virtual address to physical
                // SAFETY: virt_ptr is a valid kernel virtual address obtained from
                // read_page, which returns a pointer into the parent's guest memory.
                // bedrock_kva_to_phys converts it to a physical address.
                let phys =
                    unsafe { bedrock_kva_to_phys(virt_ptr.cast::<core::ffi::c_void>().cast_mut()) };
                if phys == 0 {
                    log_err!(
                        "mmap: kva_to_phys failed for GPA {:#x} (virt {:#x})\n",
                        gpa,
                        virt_ptr as u64
                    );
                    return -(bindings::EINVAL as i32);
                }
                *hpa = phys;
            }
        }

        // SAFETY: `vma` is a valid VMA pointer from the kernel. `hpas` contains valid
        // physical addresses resolved from COW pages or parent memory. num_pages does
        // not exceed the array size (256).
        let ret =
            unsafe { bedrock_remap_pages(vma, hpas.as_ptr(), feedback_buffer.num_pages as i32) };

        if ret != 0 {
            log_err!(
                "mmap: feedback buffer {} remap failed with {}\n",
                buffer_index,
                ret
            );
        } else {
            log_info!(
                "mmap: mapped feedback buffer {} for forked VM {} ({} pages)\n",
                buffer_index,
                vm_file.vm_id,
                feedback_buffer.num_pages
            );
        }

        ret
    } else {
        log_err!("mmap: forked VM only supports feedback and event buffers\n");
        -(bindings::EINVAL as i32)
    }
}

/// Ioctl callback for bedrock forked-vm files.
///
/// # Safety
///
/// - `file` must be a valid pointer to a file struct
/// - `file->private_data` must be a valid pointer to a `BedrockForkedVmFile`
unsafe extern "C" fn bedrock_forked_vm_ioctl(
    file: *mut bindings::file,
    cmd: core::ffi::c_uint,
    arg: usize,
) -> isize {
    // SAFETY: `file` is a valid pointer guaranteed by the kernel VFS layer.
    let private_data = unsafe { (*file).private_data };

    if private_data.is_null() {
        return -(bindings::EBADF as isize);
    }

    // SAFETY: private_data is non-null (checked above) and was set to a valid
    // BedrockForkedVmFile pointer when the fd was created. The kernel serializes
    // ioctls per file descriptor.
    let vm_file = unsafe { &mut *(private_data.cast::<BedrockForkedVmFile>()) };

    match cmd {
        BEDROCK_VM_GET_REGS => handlers::handle_get_regs(vm_file, arg),
        BEDROCK_VM_SET_REGS => handlers::handle_set_regs(vm_file, arg),
        BEDROCK_VM_RUN => handlers::handle_run(vm_file, arg),
        BEDROCK_VM_SET_RDRAND_CONFIG => handlers::handle_set_rdrand_config(vm_file, arg),
        BEDROCK_VM_SET_RDRAND_VALUE => handlers::handle_set_rdrand_value(vm_file, arg),
        BEDROCK_VM_GET_RANDOM_REQUEST => handlers::handle_get_random_request(vm_file, arg),
        BEDROCK_VM_SET_RANDOM_BYTES => handlers::handle_set_random_bytes(vm_file, arg),
        BEDROCK_VM_SET_EVENT_CONFIG => handlers::handle_set_event_config(vm_file, arg),
        BEDROCK_VM_SET_SINGLE_STEP => handlers::handle_set_single_step(vm_file, arg),
        BEDROCK_VM_GET_EXIT_STATS => handlers::handle_get_exit_stats(vm_file, arg),
        BEDROCK_VM_SET_STOP_TSC => handlers::handle_set_stop_tsc(vm_file, arg),
        BEDROCK_VM_GET_VM_ID => handlers::handle_get_vm_id(vm_file, arg),
        BEDROCK_VM_GET_FEEDBACK_BUFFER_INFO => {
            handlers::handle_get_feedback_buffer_info(vm_file, arg)
        }
        BEDROCK_VM_QUEUE_IO_ACTION => handlers::handle_queue_io_action(vm_file, arg),
        BEDROCK_VM_DRAIN_IO_RESPONSE => handlers::handle_drain_io_response(vm_file, arg),
        _ => -(bindings::ENOTTY as isize),
    }
}
