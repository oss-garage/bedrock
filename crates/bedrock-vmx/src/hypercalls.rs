// SPDX-License-Identifier: GPL-2.0

//! Hypercall numbers for the bedrock hypervisor.
//!
//! Guest code invokes hypercalls via the VMCALL instruction with the
//! hypercall number in RAX.

/// Shutdown the VM cleanly.
pub const HYPERCALL_SHUTDOWN: u64 = 0;

/// Trigger a snapshot.
/// Exits to userspace and logs VM state if logging is enabled.
pub const HYPERCALL_SNAPSHOT: u64 = 1;

/// Register a feedback buffer for fuzzing.
///
/// Inputs:
/// - RBX: Guest virtual address of buffer
/// - RCX: Size of buffer in bytes
/// - RDX: Buffer index (0-15)
///
/// Outputs:
/// - RAX: 0 on success, -1 (0xFFFFFFFFFFFFFFFF) on failure
///
/// The buffer's GVA is translated to GPAs and stored in VmState
/// at the specified index for later mapping by host userspace.
/// Up to 16 feedback buffers can be registered per VM.
pub const HYPERCALL_REGISTER_FEEDBACK_BUFFER: u64 = 2;

/// Register the guest's 4KB shared I/O channel page.
///
/// Inputs:
/// - RBX: Guest virtual address of the shared page (must be 4KB-aligned).
///
/// Outputs:
/// - RAX: 0 on success, !0 (-1) on failure (unaligned or GVA translation failed).
///
/// The page is owned by a guest kernel module (`bedrock-io.ko`) and is the
/// rendezvous buffer for the deterministic I/O channel. Hypervisor → guest
/// communication is delivered as an external interrupt on IOAPIC pin
/// `IO_CHANNEL_IRQ`; the guest handler then issues
/// `HYPERCALL_IO_GET_REQUEST` to receive the request bytes the hypervisor
/// has written into this page, performs the action, writes the response
/// back into the same page, and issues `HYPERCALL_IO_PUT_RESPONSE` to hand
/// it back to the host.
///
/// Re-registration is allowed and overwrites the previous registration.
pub const HYPERCALL_IO_REGISTER_PAGE: u64 = 4;

/// Fetch the pending I/O request into the registered shared page.
///
/// Issued by the guest from its IRQ workqueue after the I/O channel IRQ
/// fires. The hypervisor writes the queued request bytes into the
/// previously-registered shared page (offset 0) and returns the request
/// length in RAX. RAX == 0 means there was no pending request (spurious or
/// already-consumed IRQ); RAX == !0 indicates an error (no page registered).
pub const HYPERCALL_IO_GET_REQUEST: u64 = 5;

/// Deliver the I/O response back to the host.
///
/// Inputs:
/// - RBX: Length in bytes of the response data written into the shared page
///   (capped at `PAGE_SIZE`).
///
/// Outputs:
/// - RAX: 0 on success, !0 on failure.
///
/// After this hypercall the hypervisor reads the response bytes out of the
/// shared page into VmState, clears the in-flight request, and exits to
/// userspace with `VmcallIoResponse` so the host driver can drain the
/// response and queue the next request.
pub const HYPERCALL_IO_PUT_RESPONSE: u64 = 6;

/// Signal that the guest has finished its boot/initialization and is ready
/// for the host to begin its workload (fuzzing, scheduling I/O actions, etc.).
///
/// Inputs: none.
/// Outputs: none — RAX is left untouched.
///
/// Surfaces to userspace as `ExitReason::VmcallReady` / `ExitKind::VmcallReady`
/// and, in the lab API, as `RunOutcome::Ready`. The hypervisor does not change
/// any internal state on this exit; it is purely a synchronization point.
pub const HYPERCALL_READY: u64 = 7;

/// Register a single 4KB page as the PEBS scratch page for precise VM exits.
///
/// The page must be:
/// - Writable in the guest's page tables (so PEBS writes don't take a guest #PF).
/// - Quiescent — the guest must agree not to read or write to it. Typical use:
///   `mmap` an anonymous page in userspace and `mlock` it; the kernel direct-map
///   alias of that page is then used by the hypervisor as both DS Management
///   Area and PEBS Buffer.
///
/// Inputs:
/// - RBX: Guest virtual address of the scratch page (must be 4KB-aligned).
///
/// Outputs:
/// - RAX: 0 on success, -1 on failure (translation failed, unaligned address,
///   capability missing on host CPU, or already registered).
///
/// On success, the hypervisor:
/// 1. Walks guest page tables to translate RBX to its guest physical address.
/// 2. Populates the DS Management Area at the start of that page (via the
///    host's EPT-mapped view).
/// 3. Remaps the page in EPT as R+E (no W). The next time the PEBS engine
///    attempts to write a record, an EPT violation fires and the precise-exit
///    handler runs.
/// 4. Stores `PebsState` in `VmState` so the APIC-timer precise-exit path
///    knows where to direct PEBS.
pub const HYPERCALL_REGISTER_PEBS_PAGE: u64 = 3;
