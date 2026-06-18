// SPDX-License-Identifier: GPL-2.0

//! ForkedVm - Copy-on-write VM derived from a parent.
//!
//! This module provides `ForkedVm`, which shares its parent's memory but
//! allocates new pages on write using copy-on-write semantics.

#[cfg(not(feature = "cargo"))]
use super::super::prelude::*;
#[cfg(feature = "cargo")]
use crate::prelude::*;

use super::{ForkableVm, ParentVm};
use core::sync::atomic::{AtomicUsize, Ordering};

const PAGE_SIZE: usize = 4096;

/// Error type for ForkedVm creation.
#[derive(Debug)]
pub enum ForkedVmError<E> {
    /// Parent VM has children and cannot be forked.
    ParentHasChildren,
    /// EPT clone failed.
    EptClone(E),
    /// VMCS allocation failed.
    VmcsAlloc,
    /// VmState creation failed.
    VmState(VmStateError<E>),
}

/// A forked VM using copy-on-write memory.
///
/// `ForkedVm` shares its parent's memory but allocates new pages on write.
/// The EPT is cloned from parent with R+X (no write) permissions, so
/// writes cause EPT violations that trigger COW page allocation.
///
/// # Parent Relationship
///
/// ForkedVm holds a trait object pointer to the parent VM. When reading
/// non-COW pages, it calls through to the parent's `ParentVm` implementation,
/// which may recursively check its own COW pages (for nested forks) before
/// reaching the root memory.
///
/// The parent must outlive the ForkedVm, which is enforced by the children
/// counter on the parent. When a ForkedVm is created, the parent's
/// children_count is incremented. When dropped, children_count is decremented.
///
/// # Type Parameters
///
/// * `V` - The VMCS type, must implement `VirtualMachineControlStructure`
/// * `P` - The page type for COW pages
/// * `I` - The instruction counter type
#[repr(C)]
pub struct ForkedVm<V: VirtualMachineControlStructure, P: Page, I: InstructionCounter> {
    /// VM state (VMCS, registers, devices, etc.). Boxed to reduce stack usage.
    pub state: VmStateBox<V, I>,

    /// Copy-on-write pages owned by this VM.
    pub cow_pages: CowPageMap<P>,

    /// Parent VM for reading non-COW pages (type-erased trait object).
    parent: *const dyn ParentVm,

    /// Number of child ForkedVms derived from this VM.
    /// Uses AtomicUsize for interior mutability (remove_child called via &self).
    children_count: AtomicUsize,
}

// SAFETY: ForkedVm can be sent between threads. The parent pointer is
// safe because the parent VM's memory is stable (children counter prevents
// the parent from being modified/dropped while children exist).
unsafe impl<V: VirtualMachineControlStructure + Send, P: Page + Send, I: InstructionCounter + Send>
    Send for ForkedVm<V, P, I>
{
}

// SAFETY: ForkedVm can be shared between threads for read access.
unsafe impl<V: VirtualMachineControlStructure + Sync, P: Page + Sync, I: InstructionCounter + Sync>
    Sync for ForkedVm<V, P, I>
{
}

impl<V: VirtualMachineControlStructure, P: Page, I: InstructionCounter> ForkedVm<V, P, I> {
    /// Create a new ForkedVm from a parent VM.
    ///
    /// This method:
    /// 1. Increments the parent's children count
    /// 2. Clones the parent's EPT with R+X (no write) permissions for COW
    /// 3. Creates a new VmState by copying parent's device/MSR/register state
    /// 4. Creates an empty COW page map
    /// 5. Stores a trait object pointer to the parent for COW chain traversal
    ///
    /// # Arguments
    ///
    /// * `parent` - The parent VM (RootVm or another ForkedVm)
    /// * `machine` - Machine for allocating pages and VMCS
    /// * `allocator` - Frame allocator for EPT cloning and COW pages
    /// * `exit_handler_rip` - Address of the VM exit handler
    /// * `instruction_counter` - Instruction counter for this VM
    ///
    /// # Type Parameters
    ///
    /// * `A` - Frame allocator type
    /// * `Parent` - Parent VM type (implements ForkableVm)
    #[inline(never)]
    pub fn new<
        A: FrameAllocator<Frame = V::P> + CowAllocator<P>,
        Parent: ForkableVm<V, I> + 'static,
    >(
        parent: &Parent,
        machine: &V::M,
        allocator: &mut A,
        exit_handler_rip: u64,
        instruction_counter: I,
    ) -> Result<Self, ForkedVmError<A::Error>>
    where
        V::P: Into<P>,
        V::M: Machine,
    {
        // Increment parent's children count (atomic operation)
        parent.add_child();

        Self::new_internal(
            parent,
            machine,
            allocator,
            exit_handler_rip,
            instruction_counter,
        )
    }

    /// Create a new ForkedVm from a parent VM whose children_count was already incremented.
    ///
    /// This is the parallel-fork-safe variant of `new()`. The caller is responsible for:
    /// 1. Incrementing the parent's children_count BEFORE calling this method
    /// 2. Decrementing children_count if this method returns an error
    ///
    /// This design allows the caller to increment children_count while holding a lock,
    /// release the lock, then call this method for the expensive work. Multiple threads
    /// can call this method concurrently for the same parent since all operations are
    /// read-only (the parent cannot run while children_count > 0).
    ///
    /// # Safety
    ///
    /// Caller must have already called `parent.add_child()` before calling this method.
    /// If this method returns an error, caller must call `parent.remove_child()`.
    #[inline(never)]
    pub fn new_with_incremented_parent<
        A: FrameAllocator<Frame = V::P> + CowAllocator<P>,
        Parent: ForkableVm<V, I> + 'static,
    >(
        parent: &Parent,
        machine: &V::M,
        allocator: &mut A,
        exit_handler_rip: u64,
        instruction_counter: I,
    ) -> Result<Self, ForkedVmError<A::Error>>
    where
        V::P: Into<P>,
        V::M: Machine,
    {
        // Note: caller has already incremented parent's children_count
        Self::new_internal(
            parent,
            machine,
            allocator,
            exit_handler_rip,
            instruction_counter,
        )
    }

    /// Internal constructor shared by `new` and `new_with_incremented_parent`.
    #[inline(never)]
    fn new_internal<
        A: FrameAllocator<Frame = V::P> + CowAllocator<P>,
        Parent: ForkableVm<V, I> + 'static,
    >(
        parent: &Parent,
        machine: &V::M,
        allocator: &mut A,
        exit_handler_rip: u64,
        instruction_counter: I,
    ) -> Result<Self, ForkedVmError<A::Error>>
    where
        V::P: Into<P>,
        V::M: Machine,
    {
        // Clone parent's EPT with R+X permissions (COW setup)
        let ept: EptPageTable<V::P> = parent
            .vm_state()
            .ept
            .clone_for_fork(allocator)
            .map_err(ForkedVmError::EptClone)?;

        // Create a new VMCS for this forked VM
        let vmcs = V::new(machine).map_err(|_| ForkedVmError::VmcsAlloc)?;

        // Create VmState by copying from parent
        let state = VmState::new_for_fork::<A, I>(
            vmcs,
            ept,
            parent.vm_state(),
            machine,
            exit_handler_rip,
            instruction_counter,
        )
        .map_err(ForkedVmError::VmState)?;

        // Store trait object pointer to parent for COW chain traversal.
        // Parent must outlive this ForkedVm, enforced by children_count.
        let parent_ptr: *const dyn ParentVm = parent as &dyn ParentVm;

        let mut forked_vm = Self {
            state: box_vm_state(state),
            cow_pages: CowPageMap::<P>::new(),
            parent: parent_ptr,
            children_count: AtomicUsize::new(0),
        };

        // Feedback buffers need no special handling at fork: their pages are
        // copied-on-write lazily through the normal EPT write-fault path
        // (`handle_cow_fault`) when the guest writes them. When userspace maps
        // a buffer, `cow_feedback_buffer_for_mapping` COWs its pages so the
        // mapping stays coherent with subsequent guest writes.

        // Pre-COW the I/O channel shared page if registered. Without this
        // any HYPERCALL_IO_GET_REQUEST that fires on the fork would hit
        // write_guest_memory's "page not COW'd yet" error path and the
        // request would never reach the guest module.
        forked_vm.pre_cow_io_channel_page(allocator);

        Ok(forked_vm)
    }

    /// Get a reference to the COW pages.
    pub fn cow_pages(&self) -> &CowPageMap<P> {
        &self.cow_pages
    }

    /// Get a mutable reference to the COW pages.
    pub fn cow_pages_mut(&mut self) -> &mut CowPageMap<P> {
        &mut self.cow_pages
    }

    /// Get the parent's memory size.
    fn parent_memory_size(&self) -> usize {
        // SAFETY: Parent is valid as long as this ForkedVm exists (enforced by children_count)
        unsafe { (*self.parent).memory_size() }
    }

    /// Read a page from the parent.
    fn parent_read_page(&self, gpa: GuestPhysAddr) -> Option<*const u8> {
        // SAFETY: Parent is valid as long as this ForkedVm exists (enforced by children_count)
        unsafe { (*self.parent).read_page(gpa) }
    }
}

impl<V: VirtualMachineControlStructure, P: Page, I: InstructionCounter> VmContext
    for ForkedVm<V, P, I>
{
    type Vmcs = V;
    type V = <V::M as Machine>::V;
    type I = I;
    type CowPage = P;

    fn state(&self) -> &VmState<Self::Vmcs, Self::I> {
        &self.state
    }

    fn state_mut(&mut self) -> &mut VmState<Self::Vmcs, Self::I> {
        &mut self.state
    }

    fn read_guest_memory(&self, gpa: GuestPhysAddr, buf: &mut [u8]) -> Result<(), MemoryError> {
        let page_gpa = GuestPhysAddr::new(gpa.as_u64() & !0xFFF);
        let page_offset = (gpa.as_u64() & 0xFFF) as usize;

        // Check if we have a COW page for this GPA
        if let Some(cow_page) = <CowPageMap<P>>::get(&self.cow_pages, page_gpa) {
            // Read from COW page
            let cow_ptr = Page::virtual_address(cow_page).as_u64() as *const u8;
            let available_in_page = PAGE_SIZE - page_offset;

            if buf.len() <= available_in_page {
                // Read fits in single page
                // SAFETY: cow_ptr points to a valid COW page; page_offset + buf.len() <= PAGE_SIZE.
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        cow_ptr.add(page_offset),
                        buf.as_mut_ptr(),
                        buf.len(),
                    );
                }
            } else {
                // Read spans pages - read what we can from this page
                // SAFETY: cow_ptr points to a valid COW page; page_offset + available_in_page == PAGE_SIZE.
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        cow_ptr.add(page_offset),
                        buf.as_mut_ptr(),
                        available_in_page,
                    );
                }
                // Recursively read the rest from next page(s)
                self.read_guest_memory(
                    GuestPhysAddr::new(page_gpa.as_u64() + PAGE_SIZE as u64),
                    &mut buf[available_in_page..],
                )?;
            }
        } else {
            // Read from parent (walks COW chain for nested forks)
            let parent_page = self
                .parent_read_page(page_gpa)
                .ok_or(MemoryError::OutOfRange)?;
            let available_in_page = PAGE_SIZE - page_offset;

            if buf.len() <= available_in_page {
                // SAFETY: parent_page points to a valid parent memory page; page_offset + buf.len() <= PAGE_SIZE.
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        parent_page.add(page_offset),
                        buf.as_mut_ptr(),
                        buf.len(),
                    );
                }
            } else {
                // Read spans pages
                // SAFETY: parent_page points to a valid parent memory page; page_offset + available_in_page == PAGE_SIZE.
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        parent_page.add(page_offset),
                        buf.as_mut_ptr(),
                        available_in_page,
                    );
                }
                self.read_guest_memory(
                    GuestPhysAddr::new(page_gpa.as_u64() + PAGE_SIZE as u64),
                    &mut buf[available_in_page..],
                )?;
            }
        }
        Ok(())
    }

    fn write_guest_memory(&mut self, gpa: GuestPhysAddr, buf: &[u8]) -> Result<(), MemoryError> {
        let page_gpa = GuestPhysAddr::new(gpa.as_u64() & !0xFFF);
        let page_offset = (gpa.as_u64() & 0xFFF) as usize;

        // Check if we have a COW page for this GPA
        if let Some(cow_page) = self.cow_pages.get_mut(page_gpa) {
            // Write to COW page
            let cow_ptr = cow_page.virtual_address().as_u64() as *mut u8;
            let available_in_page = PAGE_SIZE - page_offset;

            if buf.len() <= available_in_page {
                // SAFETY: cow_ptr points to a valid writable COW page; page_offset + buf.len() <= PAGE_SIZE.
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        buf.as_ptr(),
                        cow_ptr.add(page_offset),
                        buf.len(),
                    );
                }
            } else {
                // Write spans pages
                // SAFETY: cow_ptr points to a valid writable COW page; page_offset + available_in_page == PAGE_SIZE.
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        buf.as_ptr(),
                        cow_ptr.add(page_offset),
                        available_in_page,
                    );
                }
                self.write_guest_memory(
                    GuestPhysAddr::new(page_gpa.as_u64() + PAGE_SIZE as u64),
                    &buf[available_in_page..],
                )?;
            }
            Ok(())
        } else {
            // Page not COW'd yet - this shouldn't normally happen as writes
            // should go through EPT fault -> handle_cow_fault first.
            // Return an error to indicate the page needs COW handling.
            Err(MemoryError::PermissionDenied)
        }
    }

    fn handle_cow_fault<A: CowAllocator<Self::CowPage>>(
        &mut self,
        gpa: GuestPhysAddr,
        allocator: &mut A,
    ) -> Option<ExitHandlerResult> {
        let page_gpa = GuestPhysAddr::new(gpa.as_u64() & !0xFFF);

        // Check if we already have a COW page for this address
        if self.cow_pages.contains(page_gpa) {
            // Already copied - this means the EPT was already remapped to RWX but
            // the TLB still had a stale R+X entry. The EPT violation auto-invalidates
            // the stale entry, so the retry will use the correct mapping.
            self.state.exit_stats.cow.stale_tlb_faults += 1;
            if self.state.exit_stats.cow.stale_tlb_faults == 1 {
                log_err!(
                    "COW: stale TLB EPT violation for already-COW'd page GPA={:#x}\n",
                    page_gpa.as_u64()
                );
            }
            return Some(ExitHandlerResult::Continue);
        }

        // Allocate a new page for COW
        let new_page = match allocator.allocate_cow_page() {
            Ok(page) => page,
            Err(_) => {
                log_err!(
                    "COW: Failed to allocate page for GPA {:#x}\n",
                    page_gpa.as_u64()
                );
                return None;
            }
        };

        // Get virtual address for copying
        let new_page_virt = new_page.virtual_address().as_u64() as *mut u8;
        let new_page_phys = new_page.physical_address();

        // Copy content from parent (walks COW chain for nested forks)
        let parent_page = match self.parent_read_page(page_gpa) {
            Some(ptr) => ptr,
            None => {
                log_err!(
                    "COW: GPA {:#x} out of parent memory range\n",
                    page_gpa.as_u64()
                );
                return None;
            }
        };

        // SAFETY: parent_page points to a valid PAGE_SIZE parent page; new_page_virt
        // points to a freshly-allocated PAGE_SIZE page. The regions do not overlap.
        unsafe {
            core::ptr::copy_nonoverlapping(parent_page, new_page_virt, PAGE_SIZE);
        }

        // Insert into COW page map
        if self.cow_pages.insert(page_gpa, new_page).is_err() {
            log_err!("COW: Failed to insert page into COW map\n");
            return None;
        }

        // Remap EPT entry to point to the new page with RWX permissions
        if let Err(_e) = self.state.ept.remap_4k(
            allocator,
            page_gpa,
            new_page_phys,
            EptPermissions::READ_WRITE_EXECUTE,
            EptMemoryType::WriteBack,
        ) {
            log_err!(
                "COW: Failed to remap EPT for GPA {:#x}\n",
                page_gpa.as_u64()
            );
            return None;
        }

        // SDM Vol 3C §30.4.3.4 requires single-context INVEPT after changing
        // the HPA in an EPT leaf. The EPT-violation auto-invalidation only
        // covers the faulting linear address; combined mappings cached for
        // other GVAs that target this GPA (e.g. the kernel just faulted via
        // its tmpfs mapping, but a user-space mmap of the same file has its
        // own combined mapping in the TLB) would otherwise keep the old
        // HPA and read pre-COW data.
        let _ = <<V::M as Machine>::V as Vmx>::invept_single_context(self.state.ept.eptp());

        log_debug!(
            "COW: Copied page at GPA {:#x} -> HPA {:#x}\n",
            page_gpa.as_u64(),
            new_page_phys.as_u64()
        );

        // Return Continue to retry the faulting instruction
        Some(ExitHandlerResult::Continue)
    }

    fn is_forked(&self) -> bool {
        true
    }

    fn cow_feedback_buffer_for_mapping<A: CowAllocator<Self::CowPage>>(
        &mut self,
        index: usize,
        allocator: &mut A,
    ) {
        let feedback_buffer = match self.state.feedback_buffers.get(index) {
            Some(fb) => **fb,
            None => return,
        };

        for i in 0..feedback_buffer.num_pages {
            let page_gpa = GuestPhysAddr::new(feedback_buffer.gpas[i]);

            // Skip pages already COW'd in this VM: re-copying would clobber a
            // guest write that happened before the mapping.
            if self.cow_pages.contains(page_gpa) {
                continue;
            }

            // Allocate a child-owned page for COW.
            let new_page = match allocator.allocate_cow_page() {
                Ok(page) => page,
                Err(_) => {
                    log_err!(
                        "cow_feedback_buffer_for_mapping: failed to allocate page for GPA {:#x}\n",
                        page_gpa.as_u64()
                    );
                    continue;
                }
            };

            let new_page_virt = new_page.virtual_address().as_u64() as *mut u8;
            let new_page_phys = new_page.physical_address();

            // Copy current contents from the parent chain.
            let parent_page = match self.parent_read_page(page_gpa) {
                Some(ptr) => ptr,
                None => {
                    log_err!(
                        "cow_feedback_buffer_for_mapping: GPA {:#x} out of parent memory range\n",
                        page_gpa.as_u64()
                    );
                    continue;
                }
            };

            // SAFETY: parent_page points to a valid PAGE_SIZE parent page; new_page_virt
            // points to a freshly-allocated PAGE_SIZE page. The regions do not overlap.
            unsafe {
                core::ptr::copy_nonoverlapping(parent_page, new_page_virt, PAGE_SIZE);
            }

            if self.cow_pages.insert(page_gpa, new_page).is_err() {
                log_err!("cow_feedback_buffer_for_mapping: failed to insert page into COW map\n");
                continue;
            }

            // Remap the EPT entry to the new page with RWX permissions, so the
            // guest writes directly to this (now mapped) frame with no further
            // fault or re-COW.
            if let Err(_e) = self.state.ept.remap_4k(
                allocator,
                page_gpa,
                new_page_phys,
                EptPermissions::READ_WRITE_EXECUTE,
                EptMemoryType::WriteBack,
            ) {
                log_err!(
                    "cow_feedback_buffer_for_mapping: failed to remap EPT for GPA {:#x}\n",
                    page_gpa.as_u64()
                );
                continue;
            }

            // SDM Vol 3C §30.4.3.4: single-context INVEPT after changing a
            // leaf's HPA. See the matching comment in handle_cow_fault.
            let _ = <<V::M as Machine>::V as Vmx>::invept_single_context(self.state.ept.eptp());

            log_debug!(
                "cow_feedback_buffer_for_mapping: COW'd buffer {} page at GPA {:#x} -> HPA {:#x}\n",
                index,
                page_gpa.as_u64(),
                new_page_phys.as_u64()
            );
        }
    }

    fn pre_cow_io_channel_page<A: CowAllocator<Self::CowPage>>(&mut self, allocator: &mut A) {
        let page_gpa_raw = self.state.io_channel.page_gpa;
        if page_gpa_raw == 0 {
            return;
        }
        let page_gpa = GuestPhysAddr::new(page_gpa_raw & !0xFFF);

        // Already CoW'd — nothing to do.
        if self.cow_pages.contains(page_gpa) {
            return;
        }

        let new_page = match allocator.allocate_cow_page() {
            Ok(page) => page,
            Err(_) => {
                log_err!(
                    "pre_cow_io_channel_page: failed to allocate page for GPA {:#x}\n",
                    page_gpa.as_u64()
                );
                return;
            }
        };
        let new_page_virt = new_page.virtual_address().as_u64() as *mut u8;
        let new_page_phys = new_page.physical_address();

        // Copy current contents from parent so the guest module's view
        // of the page is preserved (the kernel module may have initial
        // bookkeeping on it).
        let parent_page = match self.parent_read_page(page_gpa) {
            Some(ptr) => ptr,
            None => {
                log_err!(
                    "pre_cow_io_channel_page: GPA {:#x} out of parent memory range\n",
                    page_gpa.as_u64()
                );
                return;
            }
        };
        // SAFETY: parent_page points to a valid PAGE_SIZE parent page;
        // new_page_virt points to a freshly-allocated PAGE_SIZE page. The
        // regions do not overlap.
        unsafe {
            core::ptr::copy_nonoverlapping(parent_page, new_page_virt, PAGE_SIZE);
        }

        if self.cow_pages.insert(page_gpa, new_page).is_err() {
            log_err!("pre_cow_io_channel_page: failed to insert page into COW map\n");
            return;
        }

        if let Err(_e) = self.state.ept.remap_4k(
            allocator,
            page_gpa,
            new_page_phys,
            EptPermissions::READ_WRITE_EXECUTE,
            EptMemoryType::WriteBack,
        ) {
            log_err!(
                "pre_cow_io_channel_page: failed to remap EPT for GPA {:#x}\n",
                page_gpa.as_u64()
            );
            return;
        }

        // SDM Vol 3C §30.4.3.4: single-context INVEPT after changing a leaf's
        // HPA. See the matching comment in handle_cow_fault.
        let _ = <<V::M as Machine>::V as Vmx>::invept_single_context(self.state.ept.eptp());

        log_debug!(
            "pre_cow_io_channel_page: pre-COW'd I/O channel page at GPA {:#x} -> HPA {:#x}\n",
            page_gpa.as_u64(),
            new_page_phys.as_u64()
        );
    }

    fn finalize_exit_record<K: Kernel>(&mut self, _kernel: &K) {
        // Nothing to do unless an `Exit` event awaits its deferred memory hash.
        if self.state.pending_exit_loc.is_none() {
            return;
        }

        let memory_hash = if self.state.skip_memory_hash {
            0
        } else {
            match self.state.exit_trigger {
                ExitTrigger::AtTsc
                | ExitTrigger::AtShutdown
                | ExitTrigger::AllExits
                | ExitTrigger::Checkpoints
                | ExitTrigger::TscRange => {
                    // Hash only COW (modified) pages for forked VMs.
                    // This captures the delta from parent, which is what matters
                    // for comparing forked VM states.
                    let mut hasher = Xxh64Hasher::new();

                    for (gpa, cow_page) in self.cow_pages.iter() {
                        // Include GPA in hash so page position matters
                        hasher.write_u64(gpa.as_u64());
                        let page_ptr = Page::virtual_address(cow_page).as_u64() as *const u8;
                        // SAFETY: page_ptr points to a valid COW page of PAGE_SIZE bytes.
                        let page = unsafe { core::slice::from_raw_parts(page_ptr, PAGE_SIZE) };
                        hasher.write_bytes(page);
                    }

                    hasher.finish()
                }
                ExitTrigger::Disabled => 0,
            }
        };

        // Patch the pending `Exit` record's memory_hash and cow_page_count in
        // the event buffer.
        let cow_page_count = self.cow_pages.len() as u32;
        self.state
            .finalize_exit_memory_hash(memory_hash, cow_page_count);
    }
}

impl<V: VirtualMachineControlStructure, P: Page, I: InstructionCounter> ParentVm
    for ForkedVm<V, P, I>
{
    fn read_page(&self, gpa: GuestPhysAddr) -> Option<*const u8> {
        // Align to page boundary
        let page_gpa = GuestPhysAddr::new(gpa.as_u64() & !0xFFF);

        // First check our COW pages
        if let Some(page) = <CowPageMap<P>>::get(&self.cow_pages, page_gpa) {
            Some(Page::virtual_address(page).as_u64() as *const u8)
        } else {
            // Delegate to parent (walks COW chain for nested forks)
            self.parent_read_page(page_gpa)
        }
    }

    fn memory_size(&self) -> usize {
        self.parent_memory_size()
    }

    fn remove_child(&self) {
        self.children_count.fetch_sub(1, Ordering::SeqCst);
    }
}

impl<V: VirtualMachineControlStructure, P: Page, I: InstructionCounter> ForkableVm<V, I>
    for ForkedVm<V, P, I>
{
    type Page = P;

    fn vm_state(&self) -> &VmState<V, I> {
        &self.state
    }

    fn vm_state_mut(&mut self) -> &mut VmState<V, I> {
        &mut self.state
    }

    fn add_child(&self) {
        self.children_count.fetch_add(1, Ordering::SeqCst);
    }

    fn remove_child(&self) {
        self.children_count.fetch_sub(1, Ordering::SeqCst);
    }

    fn children_count(&self) -> usize {
        self.children_count.load(Ordering::SeqCst)
    }
}

/// Ensure VMCS is cleared and parent notified when ForkedVm is dropped.
impl<V: VirtualMachineControlStructure, P: Page, I: InstructionCounter> Drop for ForkedVm<V, P, I> {
    fn drop(&mut self) {
        // Clear the VMCS to transition it to "clear" state
        if let Err(_e) = self.state.vmcs.clear() {
            log_err!("Failed to clear VMCS during ForkedVm drop\n");
        }
        // Return the VPID to the pool for reuse
        deallocate_vpid(self.state.vpid);
        // Decrement parent's children count
        // SAFETY: Parent is valid as long as children_count > 0, which it is since
        // we're still alive (about to drop). The parent pointer is valid.
        unsafe {
            (*self.parent).remove_child();
        }
    }
}
