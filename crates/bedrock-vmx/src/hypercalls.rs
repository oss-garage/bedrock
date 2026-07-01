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
/// - RCX: Size of buffer in bytes (capped at 1MB / 256 pages)
/// - RDX: Guest virtual address of the identifier bytes
/// - RSI: Identifier length in bytes
///
/// Outputs:
/// - RAX: the assigned slot index on success, or one of the `FB_ERR_*`
///   sentinels (near `u64::MAX`) on failure.
///
/// The buffer's GVA is translated to GPAs and appended to a heap-growable
/// list in VmState; the returned slot index (its position in that list) is
/// used by host userspace to map it. The number of feedback buffers a VM may
/// register is unbounded — each registration appends a new slot.
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

/// Register the guest's 4KB shared paravirtual-console page.
///
/// Inputs:
/// - RBX: Guest virtual address of the console page (must be 4KB-aligned).
///
/// Outputs:
/// - RAX: 0 on success, !0 (-1) on failure (unaligned or GVA translation failed).
///
/// Mirrors `HYPERCALL_IO_REGISTER_PAGE`: the GVA is translated to a GPA once
/// and stored in `VmState`. The page is owned by the guest console module
/// (`bedrock-console.ko`), which registers both a `struct console` (kernel
/// printk) and a tty driver backing `/dev/console` (userspace output) and
/// copies each write buffer into this page before issuing
/// `HYPERCALL_SERIAL_WRITE`. The host only ever *reads* this page, so (unlike
/// the I/O channel) no pre-CoW is needed.
///
/// Re-registration is allowed and overwrites the previous registration.
pub const HYPERCALL_SERIAL_REGISTER_PAGE: u64 = 8;

/// Emit bytes from the registered console page to the serial output sink.
///
/// Inputs:
/// - RBX: Number of bytes at the start of the registered console page to emit
///   (clamped to `PAGE_SIZE`).
///
/// Outputs:
/// - RAX: 0 on success, !0 on failure (no page registered or guest memory
///   access failed).
///
/// The hypervisor copies those bytes and emits them as one `Serial` event
/// record (stamped with the line-start emulated TSC). This batches one whole
/// printk record into a single VM exit instead of one exit per byte through the
/// emulated 8250 UART.
pub const HYPERCALL_SERIAL_WRITE: u64 = 9;

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

/// Fetch the next chunk of a host-side file into the registered file-transfer
/// feedback buffer.
///
/// Inputs: none in registers — the request and the response are framed inside
/// the shared buffer the guest registered (via `HYPERCALL_REGISTER_FEEDBACK_BUFFER`
/// under the id `bedrock-file-xfer`). Before issuing the hypercall the guest
/// writes a request header into the start of that buffer:
/// - bytes `[0..8)`:   `u64` little-endian file offset to read from.
/// - bytes `[8..12)`:  `u32` little-endian length of the file name.
/// - bytes `[12..16)`: reserved (zero).
/// - bytes `[16..16+name_len)`: the file name (e.g. `images.tar`).
///
/// Outputs:
/// - RAX: 0. The actual result is delivered in the buffer (see below).
///
/// The hypervisor does not touch the buffer; it merely advances RIP and exits
/// to userspace with `ExitReason::VmcallFileFetch`. The host driver reads the
/// request out of the (host-mapped) buffer, reads up to `buffer_size - 16`
/// bytes of the named file starting at `offset`, and overwrites the buffer with
/// a response:
/// - bytes `[0..8)`: `i64` little-endian result — `>= 0` is the number of data
///   bytes that follow (0 means EOF), `-1` means the file is unknown/unreadable.
/// - bytes `[8..16)`: reserved (zero).
/// - bytes `[16..16+result)`: the file data chunk.
///
/// The guest reads the result word back out of the buffer after the hypercall
/// returns and loops, advancing `offset`, until it sees `0` (EOF). Because the
/// served bytes are a pure function of the (fixed) host file and the chunk
/// boundaries are fixed by the buffer size, the transfer is deterministic; it
/// runs entirely during the root VM's boot, before `HYPERCALL_READY`, so forked
/// VMs inherit the already-populated filesystem and never re-fetch.
pub const HYPERCALL_FILE_FETCH: u64 = 10;

/// Fetch fuzzer-controlled random bytes for the guest.
///
/// Issued by the patched guest `get_random_bytes_user()` — the single
/// chokepoint behind `/dev/urandom`, `/dev/random` and the `getrandom()`
/// syscall — once per (chunked) read instead of trapping RDRAND. It hands the
/// hypervisor the *size* of the request and the *PID* of the requesting
/// process, both of which surface to the fuzzer, which a bare RDRAND trap
/// cannot communicate.
///
/// Inputs:
/// - RBX: Guest virtual address of the destination buffer.
/// - RCX: Number of bytes requested (the hypervisor serves at most
///   `RANDOM_REPLY_MAX`; the guest loops for larger reads).
/// - RDX: PID (`current->tgid`) of the requesting process.
///
/// Outputs:
/// - RAX: number of bytes written into the buffer, or `!0` on failure
///   (GVA translation / guest-memory write failed).
///
/// Behaviour depends on the random device mode (configured together with
/// RDRAND via `SET_RDRAND_CONFIG`):
/// - **SeededRng**: the hypervisor fills the buffer from a deterministic in-VM
///   xorshift PRNG and resumes — no userspace round-trip.
/// - **ExitToUserspace**: the hypervisor records the request (buffer, length,
///   PID) and exits to userspace as `ExitReason::VmcallGetRandom`. Userspace
///   stages the reply bytes via `SET_RANDOM_BYTES` and re-runs; the handler then
///   writes them into the guest buffer and resumes. Mirrors the RDRAND
///   exit-to-userspace flow.
///
/// (Numbers 8/9 are the paravirtual console and 10 is `HYPERCALL_FILE_FETCH` on
/// this branch, so this is 11.)
pub const HYPERCALL_GET_RANDOM: u64 = 11;

/// Read the next chunk of a guest-side file from the feedback buffer into
/// a file on the host.
///
/// Inputs: none in registers - the request and the response are framed inside
/// the shared buffer the guest registered (via `HYPERCALL_REGISTER_FEEDBACK_BUFFER`
/// under the id `bedrock-file-store`). The terms request and response are a bit
/// backwards as the guest is not "requesting" anything. Before invoking the
/// hypercall, the guest writes the following into the start of the buffer:
/// - bytes `[0..4)`:   `u32` little-endian file name length.
/// - bytes `[4..8)`:   `u32` little-endian chunk length.
/// - bytes `[8..16)`:  reserved (zero).
/// - bytes `[16..16+name_len)`: the file name
/// - bytes `[16+name_len..16+name_len+chunk_len)`: file chunk
///
/// Outputs:
/// - RAX: 0. The actual result is delivered by the host in the buffer (see below).
///
/// The hypervisor does not touch the buffer; it advances RIP and exits to
/// userspace with `ExitReason::VmcallFileStore`. The host reads the request out of
/// the (host-mapped) buffer, reads the file name and creates a file with the same
/// name, then reads the chunk into the file. The host then responds via the buffer:
/// - bytes `[0..8)`: `i64` little-endian result - `> 0` is the number of bytes the
///   host read, `-1` means the host encountered an i/o error.
/// - bytes `[8..16)`: reserved (zero).
///
/// If the host read succeeded, the guest sends the next chunk. This loop happens
/// until the guest has no more chunks to send.
pub const HYPERCALL_FILE_STORE: u64 = 12;
