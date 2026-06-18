// SPDX-License-Identifier: GPL-2.0

//! Root VM file operations and handlers.
//!
//! This module provides the file_operations callbacks and root-VM-specific
//! ioctl handlers for bedrock-vm anonymous inodes.

use core::ffi::c_int;
use core::sync::atomic::AtomicBool;

use kernel::bindings;
use kernel::sync::Arc;

use super::super::c_helpers::{
    bedrock_remap_pages, bedrock_remap_vmalloc_range, bedrock_vma_end, bedrock_vma_pgoff,
    bedrock_vma_start,
};
use super::super::page::{EventBuffer, PagePool, EVENT_BUFFER_SIZE};
use super::super::vmx::traits::GuestMemory;
use super::super::vmx::{ForkableVm, ParentVm, VmState};
use super::super::HANDLER;
use super::core::BedrockVmFile;
use super::handlers::{self, VmFileOps};
use super::structs::*;

/// Implement VmFileOps for BedrockVmFile.
impl VmFileOps for BedrockVmFile {
    type Vm = super::super::vmx::RootVm<
        super::super::vmcs::RealVmcs,
        super::super::page::KernelGuestMemory,
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

/// File operations for bedrock-vm anonymous inodes.
pub(crate) static BEDROCK_VM_FOPS: SyncFileOps = {
    // SAFETY: SyncFileOps::zeroed() produces an all-zeros file_operations, which is valid.
    // We immediately set the required function pointers below.
    let mut fops: bindings::file_operations = unsafe { SyncFileOps::zeroed() };
    fops.owner = core::ptr::null_mut();
    fops.release = Some(bedrock_vm_release);
    fops.unlocked_ioctl = Some(bedrock_vm_ioctl);
    fops.mmap = Some(bedrock_vm_mmap);
    SyncFileOps(fops)
};

impl ParentVm for BedrockVmFile {
    fn read_page(&self, gpa: super::super::memory::GuestPhysAddr) -> Option<*const u8> {
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
    > for BedrockVmFile
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

/// Release callback for bedrock-vm files.
///
/// # Safety
///
/// - `file` must be a valid pointer to a file struct
/// - `file->private_data` must be a valid pointer to a `KBox<BedrockVmFile>`
unsafe extern "C" fn bedrock_vm_release(
    _inode: *mut bindings::inode,
    file: *mut bindings::file,
) -> c_int {
    // SAFETY: `file` is a valid pointer to a file struct, guaranteed by the kernel
    // VFS layer which calls this release callback.
    let private_data = unsafe { (*file).private_data };

    if private_data.is_null() {
        log_err!("bedrock_vm_release: null private_data\n");
        return 0;
    }

    let vm_ptr = private_data.cast::<BedrockVmFile>();
    // SAFETY: We verified private_data is non-null above, and it was set to a valid
    // KBox<BedrockVmFile> pointer when the fd was created in create_vm_fd.
    let vm_id = unsafe { (*vm_ptr).vm_id };
    log_info!("Releasing VM {} (fd closed)\n", vm_id);

    // Remove from global vm_list
    {
        let mut guard = HANDLER.lock();
        if let Some(handler) = guard.as_mut() {
            handler.remove_vm(vm_ptr);
        }
    }

    // Drop the file descriptor's Arc reference. Forked children may still hold
    // cloned parent Arcs; in that case the allocation is reclaimed when the
    // last child drops.
    // SAFETY: vm_ptr was created by Arc::into_raw in create_vm_fd. This release
    // callback consumes the fd-owned reference exactly once.
    let _ = unsafe { Arc::from_raw(vm_ptr) };

    log_info!("VM {} released successfully\n", vm_id);
    0
}

/// Mmap callback for bedrock-vm files.
///
/// # Safety
///
/// - `file` must be a valid pointer to a file struct
/// - `file->private_data` must be a valid pointer to a `BedrockVmFile`
/// - `vma` must be a valid pointer to a vm_area_struct
unsafe extern "C" fn bedrock_vm_mmap(
    file: *mut bindings::file,
    vma: *mut bindings::vm_area_struct,
) -> c_int {
    // SAFETY: `file` is a valid pointer guaranteed by the kernel VFS layer.
    let private_data = unsafe { (*file).private_data };

    if private_data.is_null() {
        return -(bindings::EBADF as i32);
    }

    // SAFETY: private_data is non-null (checked above) and was set to a valid
    // BedrockVmFile pointer when the fd was created. We hold exclusive access
    // because the kernel serializes mmap calls per file.
    let vm_file = unsafe { &mut *(private_data.cast::<BedrockVmFile>()) };
    let memory = &mut vm_file.vm.memory;

    // Get VMA parameters
    // SAFETY: `vma` is a valid pointer to a vm_area_struct, guaranteed by the kernel
    // VFS/mmap layer. These helpers read standard VMA fields.
    let vma_start = unsafe { bedrock_vma_start(vma) };
    // SAFETY: Same as above — `vma` is a valid VMA pointer from the kernel mmap layer.
    let vma_end = unsafe { bedrock_vma_end(vma) };
    // SAFETY: Same as above — `vma` is a valid VMA pointer from the kernel mmap layer.
    let vma_pgoff = unsafe { bedrock_vma_pgoff(vma) };

    let requested_size = vma_end - vma_start;
    let offset_bytes = vma_pgoff * 4096;

    // Memory layout for mmap:
    // - Offset 0 to memory.size(): guest memory
    // - Offset memory.size(): feedback buffer 0 (up to 1MB)
    // - ... (each feedback slot reserves 1MB)
    // - past the feedback region: the unified event buffer (1MB)
    //
    // Guest serial output flows through the event buffer as `Serial` records,
    // so there is no dedicated serial/TSC page in the layout.
    let guest_mem_size = memory.size();
    let feedback_buffer_base_offset = guest_mem_size;
    // 1MB per feedback slot; sourced from vmx so userspace and kernel never
    // drift. The per-buffer size is capped but the *number* of buffers is
    // unbounded.
    let feedback_buffer_slot_size = super::super::vmx::FEEDBACK_BUFFER_SLOT_SIZE as usize;
    // The event buffer sits at a fixed sentinel offset above the (unbounded)
    // feedback-buffer region. It is checked *before* the feedback catch-all
    // below because its offset is also `>= feedback_buffer_base_offset`.
    let event_buffer_offset = super::super::vmx::EVENT_BUFFER_MMAP_OFFSET as usize;

    if offset_bytes as usize == event_buffer_offset {
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
    } else if offset_bytes as usize >= feedback_buffer_base_offset {
        let relative_offset = offset_bytes as usize - feedback_buffer_base_offset;
        let buffer_index = relative_offset / feedback_buffer_slot_size;

        // Check alignment within slot
        if !relative_offset.is_multiple_of(feedback_buffer_slot_size) {
            log_err!("mmap: feedback buffer offset not aligned to slot boundary\n");
            return -(bindings::EINVAL as i32);
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

        // For root VM, translate each GPA to HPA using the GuestMemory trait.
        // Since guest memory is vmalloc'd, each page may have a different physical address.
        let mut hpas = [0u64; 256]; // FEEDBACK_BUFFER_MAX_PAGES = 256

        for (i, hpa) in hpas.iter_mut().enumerate().take(feedback_buffer.num_pages) {
            let gpa = feedback_buffer.gpas[i];
            // GPA is the guest physical address, which for root VM equals the offset
            // into the vmalloc'd memory region.
            *hpa = match memory.page_phys_addr(gpa as usize) {
                Some(addr) => addr.as_u64(),
                None => {
                    log_err!(
                        "mmap: failed to resolve GPA {:#x} for feedback buffer {}\n",
                        gpa,
                        buffer_index
                    );
                    return -(bindings::EINVAL as i32);
                }
            };
        }

        // SAFETY: `vma` is a valid VMA pointer from the kernel. `hpas` contains valid
        // physical addresses resolved from guest memory. num_pages does not exceed the
        // array size (256).
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
                "mmap: mapped feedback buffer {} for VM {} ({} pages)\n",
                buffer_index,
                vm_file.vm_id,
                feedback_buffer.num_pages
            );
        }

        ret
    } else if (offset_bytes as usize) < guest_mem_size {
        // Guest memory mapping
        if (offset_bytes as usize) + (requested_size as usize) > guest_mem_size {
            log_err!(
                "mmap: offset {} + size {} exceeds memory size {}\n",
                offset_bytes,
                requested_size,
                guest_mem_size
            );
            return -(bindings::EINVAL as i32);
        }

        let addr = memory.as_mut_ptr().cast::<core::ffi::c_void>();
        // SAFETY: `vma` is a valid VMA pointer from the kernel. `addr` is a valid
        // vmalloc'd pointer to guest memory. `vma_pgoff` is the page offset within
        // the mapping, and we verified the range fits within guest_mem_size above.
        let ret = unsafe { bedrock_remap_vmalloc_range(vma, addr, vma_pgoff) };

        if ret != 0 {
            log_err!("mmap: remap_vmalloc_range failed with {}\n", ret);
        } else {
            log_info!(
                "mmap: mapped {} bytes at offset {} for VM {}\n",
                requested_size,
                offset_bytes,
                vm_file.vm_id
            );
        }

        ret
    } else {
        log_err!("mmap: invalid offset {}\n", offset_bytes);
        -(bindings::EINVAL as i32)
    }
}

/// Ioctl callback for bedrock-vm files.
///
/// # Safety
///
/// - `file` must be a valid pointer to a file struct
/// - `file->private_data` must be a valid pointer to a `BedrockVmFile`
unsafe extern "C" fn bedrock_vm_ioctl(
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
    // BedrockVmFile pointer when the fd was created. The kernel serializes ioctls
    // per file descriptor.
    let vm_file = unsafe { &mut *(private_data.cast::<BedrockVmFile>()) };

    match cmd {
        BEDROCK_VM_GET_REGS => handlers::handle_get_regs(vm_file, arg),
        BEDROCK_VM_SET_REGS => handlers::handle_set_regs(vm_file, arg),
        BEDROCK_VM_RUN => handlers::handle_run(vm_file, arg),
        BEDROCK_VM_SET_RDRAND_CONFIG => handlers::handle_set_rdrand_config(vm_file, arg),
        BEDROCK_VM_SET_RDRAND_VALUE => handlers::handle_set_rdrand_value(vm_file, arg),
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
