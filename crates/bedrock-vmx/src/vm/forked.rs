// SPDX-License-Identifier: GPL-2.0

//! ForkedVm - copy-on-write VM derived from a parent.

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
/// The EPT is cloned from the parent with R+X permissions, so writes fault
/// and trigger COW page allocation. Non-COW reads go through the parent's
/// `ParentVm` impl (recursively for nested forks). The parent must outlive
/// the fork; this is enforced by the parent's children_count.
#[repr(C)]
pub struct ForkedVm<V: VirtualMachineControlStructure, P: Page, I: InstructionCounter> {
    /// VM state. Boxed to reduce stack usage.
    pub state: VmStateBox<V, I>,

    /// Copy-on-write pages owned by this VM.
    pub cow_pages: CowPageMap<P>,

    /// Parent VM for reading non-COW pages.
    parent: *const dyn ParentVm,

    /// Number of child forks. Atomic because remove_child takes &self.
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
    /// Create a new ForkedVm from a parent VM, incrementing its children count.
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
        parent.add_child();

        Self::new_internal(
            parent,
            machine,
            allocator,
            exit_handler_rip,
            instruction_counter,
        )
    }

    /// Parallel-fork-safe variant of `new()` for a parent whose children_count
    /// was already incremented.
    ///
    /// Lets the caller bump children_count under a lock, drop the lock, then do
    /// the expensive work here. Concurrent calls for the same parent are fine
    /// since the parent cannot run while children_count > 0.
    ///
    /// # Safety
    ///
    /// Caller must have called `parent.add_child()` first, and must call
    /// `parent.remove_child()` if this returns an error.
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
        Self::new_internal(
            parent,
            machine,
            allocator,
            exit_handler_rip,
            instruction_counter,
        )
    }

    /// COW one page now so host `write_guest_memory` to it succeeds. No-op for
    /// GPA 0 or an already-COW'd page.
    fn pre_cow_page<A: CowAllocator<P>>(&mut self, page_gpa_raw: u64, allocator: &mut A) {
        if page_gpa_raw == 0 {
            return;
        }
        let page_gpa = GuestPhysAddr::new(page_gpa_raw & !0xFFF);

        if self.cow_pages.contains(page_gpa) {
            return;
        }

        let new_page = match allocator.allocate_cow_page() {
            Ok(page) => page,
            Err(_) => {
                log_err!(
                    "pre_cow_page: failed to allocate page for GPA {:#x}\n",
                    page_gpa.as_u64()
                );
                return;
            }
        };
        let new_page_virt = new_page.virtual_address().as_u64() as *mut u8;
        let new_page_phys = new_page.physical_address();

        let parent_page = match self.parent_read_page(page_gpa) {
            Some(ptr) => ptr,
            None => {
                log_err!(
                    "pre_cow_page: GPA {:#x} out of parent memory range\n",
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
            log_err!("pre_cow_page: failed to insert page into COW map\n");
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
                "pre_cow_page: failed to remap EPT for GPA {:#x}\n",
                page_gpa.as_u64()
            );
            return;
        }

        // SDM Vol 3C §30.4.3.4: single-context INVEPT after changing a leaf's
        // HPA. See the matching comment in handle_cow_fault.
        let _ = <<V::M as Machine>::V as Vmx>::invept_single_context(self.state.ept.eptp());

        log_debug!(
            "pre_cow_page: pre-COW'd page at GPA {:#x} -> HPA {:#x}\n",
            page_gpa.as_u64(),
            new_page_phys.as_u64()
        );
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
        let ept: EptPageTable<V::P> = parent
            .vm_state()
            .ept
            .clone_for_fork(allocator)
            .map_err(ForkedVmError::EptClone)?;

        let vmcs = V::new(machine).map_err(|_| ForkedVmError::VmcsAlloc)?;

        let state = VmState::new_for_fork::<A, I>(
            vmcs,
            ept,
            parent.vm_state(),
            machine,
            exit_handler_rip,
            instruction_counter,
        )
        .map_err(ForkedVmError::VmState)?;

        let parent_ptr: *const dyn ParentVm = parent as &dyn ParentVm;

        let mut forked_vm = Self {
            state: box_vm_state(state),
            cow_pages: CowPageMap::<P>::new(),
            parent: parent_ptr,
            children_count: AtomicUsize::new(0),
        };

        // Feedback buffers are COW'd lazily via handle_cow_fault, or eagerly by
        // cow_feedback_buffer_for_mapping when userspace maps them.

        // Pre-COW the I/O channel page: HYPERCALL_IO_GET_REQUEST writes it via
        // write_guest_memory, which fails on not-yet-COW'd pages.
        forked_vm.pre_cow_io_channel_page(allocator);

        // Pre-COW the PDIR DS page: `pdir_pre_vm_entry` rewinds `pebs_index`
        // through write_guest_memory, and PDIR's records must land rather than
        // fault on an R+X page.
        if let Some(pebs) = forked_vm.state.pebs_state.as_deref() {
            if pebs.mode == PreciseExitMode::Pdir {
                let gpa = pebs.ds_management_gpa;
                forked_vm.pre_cow_page(gpa, allocator);
            }
        }

        Ok(forked_vm)
    }

    pub fn cow_pages(&self) -> &CowPageMap<P> {
        &self.cow_pages
    }

    pub fn cow_pages_mut(&mut self) -> &mut CowPageMap<P> {
        &mut self.cow_pages
    }

    fn parent_memory_size(&self) -> usize {
        // SAFETY: Parent is valid as long as this ForkedVm exists (enforced by children_count)
        unsafe { (*self.parent).memory_size() }
    }

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

        if let Some(cow_page) = <CowPageMap<P>>::get(&self.cow_pages, page_gpa) {
            let cow_ptr = Page::virtual_address(cow_page).as_u64() as *const u8;
            let available_in_page = PAGE_SIZE - page_offset;

            if buf.len() <= available_in_page {
                // SAFETY: cow_ptr points to a valid COW page; page_offset + buf.len() <= PAGE_SIZE.
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        cow_ptr.add(page_offset),
                        buf.as_mut_ptr(),
                        buf.len(),
                    );
                }
            } else {
                // SAFETY: cow_ptr points to a valid COW page; page_offset + available_in_page == PAGE_SIZE.
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        cow_ptr.add(page_offset),
                        buf.as_mut_ptr(),
                        available_in_page,
                    );
                }
                self.read_guest_memory(
                    GuestPhysAddr::new(page_gpa.as_u64() + PAGE_SIZE as u64),
                    &mut buf[available_in_page..],
                )?;
            }
        } else {
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

        if let Some(cow_page) = self.cow_pages.get_mut(page_gpa) {
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
            // Not COW'd yet; writes should go through handle_cow_fault first.
            Err(MemoryError::PermissionDenied)
        }
    }

    fn handle_cow_fault<A: CowAllocator<Self::CowPage>>(
        &mut self,
        gpa: GuestPhysAddr,
        allocator: &mut A,
    ) -> Option<ExitHandlerResult> {
        let page_gpa = GuestPhysAddr::new(gpa.as_u64() & !0xFFF);

        if self.cow_pages.contains(page_gpa) {
            // EPT already remapped to RWX but the TLB held a stale R+X entry.
            // The EPT violation auto-invalidates it, so the retry succeeds.
            self.state.exit_stats.cow.stale_tlb_faults += 1;
            if self.state.exit_stats.cow.stale_tlb_faults == 1 {
                log_err!(
                    "COW: stale TLB EPT violation for already-COW'd page GPA={:#x}\n",
                    page_gpa.as_u64()
                );
            }
            return Some(ExitHandlerResult::Continue);
        }

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

        let new_page_virt = new_page.virtual_address().as_u64() as *mut u8;
        let new_page_phys = new_page.physical_address();

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

        if self.cow_pages.insert(page_gpa, new_page).is_err() {
            log_err!("COW: Failed to insert page into COW map\n");
            return None;
        }

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

        // SDM Vol 3C §30.4.3.4: single-context INVEPT after changing a leaf's
        // HPA. EPT-violation auto-invalidation only covers the faulting linear
        // address; combined mappings for other GVAs of this GPA (e.g. a
        // userspace mmap of a tmpfs file) would keep the old HPA.
        let _ = <<V::M as Machine>::V as Vmx>::invept_single_context(self.state.ept.eptp());

        log_debug!(
            "COW: Copied page at GPA {:#x} -> HPA {:#x}\n",
            page_gpa.as_u64(),
            new_page_phys.as_u64()
        );

        Some(ExitHandlerResult::Continue)
    }

    fn is_forked(&self) -> bool {
        true
    }

    #[allow(clippy::needless_range_loop)]
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
        self.pre_cow_page(self.state.io_channel.page_gpa, allocator);
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
                    // Hash only COW pages: the delta from the parent.
                    let mut hasher = Xxh64Hasher::new();

                    for (gpa, cow_page) in self.cow_pages.iter() {
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

        let cow_page_count = self.cow_pages.len() as u32;
        self.state
            .finalize_exit_memory_hash(memory_hash, cow_page_count);
    }
}

impl<V: VirtualMachineControlStructure, P: Page, I: InstructionCounter> ParentVm
    for ForkedVm<V, P, I>
{
    fn read_page(&self, gpa: GuestPhysAddr) -> Option<*const u8> {
        let page_gpa = GuestPhysAddr::new(gpa.as_u64() & !0xFFF);

        if let Some(page) = <CowPageMap<P>>::get(&self.cow_pages, page_gpa) {
            Some(Page::virtual_address(page).as_u64() as *const u8)
        } else {
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
        if let Err(_e) = self.state.vmcs.clear() {
            log_err!("Failed to clear VMCS during ForkedVm drop\n");
        }
        deallocate_vpid(self.state.vpid);
        // SAFETY: Parent outlives us: our children_count entry is still held.
        unsafe {
            (*self.parent).remove_child();
        }
    }
}
