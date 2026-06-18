// SPDX-License-Identifier: GPL-2.0

//! VmState - Shared VM state for root and forked VMs.
//!
//! This module contains `VmState`, which holds all VM state except guest memory.
//! Both `RootVm` and `ForkedVm` use `VmState` to share common fields like VMCS,
//! registers, EPT, device state, and MSR state.

#[cfg(not(feature = "cargo"))]
use super::prelude::*;
#[cfg(feature = "cargo")]
use crate::prelude::*;

type DeviceStatesBox = HeapBox<DeviceStates>;
type ExitStatsBox = HeapBox<AllExitStats>;

/// Growable, unbounded collection of registered feedback buffers.
///
/// Stored as a heap vector of individually heap-boxed entries. The vector's
/// own contiguous backing store only ever holds small pointers (one per
/// buffer), so it stays tiny even with thousands of buffers; each ~2KB
/// `FeedbackBufferInfo` is a separate allocation. This lets the *number* of
/// registered buffers grow without bound and without ever requiring a large
/// physically-contiguous kernel allocation (the per-buffer size is still
/// capped at [`FEEDBACK_BUFFER_MAX_PAGES`]).
///
/// Registration is append-only within a VM's lifetime (there is no
/// unregister hypercall), so a buffer's slot index is its position in this
/// vector and is stable once assigned.
pub type FeedbackBuffers = HeapVec<HeapBox<FeedbackBufferInfo>>;

/// PEBS VM-entry MSR-load list entries, in fixed order. `pebs_pre_vm_entry`
/// writes the value field of each entry; the index field is set once at
/// VmState construction by `init_pebs_entry_msr_indexes`.
///
/// Entry 0 is `IA32_A_PMC0` so that armed iterations preserve the
/// instruction-counter's auto-reload semantics: while armed, the entry-load
/// list is repointed from the instruction counter's single-entry page to this
/// page, and entry 0's value is filled from the instruction counter's saved
/// value before each VM-entry. The VM-exit MSR-store list still points at the
/// instruction counter's page, so that page remains the single source of
/// truth for the counter value.
///
/// `IA32_PERF_GLOBAL_STATUS_RESET` clears any lingering overflow bits before
/// PEBS is re-enabled — without this the architecture flushes a buffered
/// record on every re-enable using stale state, which makes PEBS fire on
/// effectively every VM-entry instead of after the configured `delta`.
/// It must precede `IA32_PEBS_ENABLE` in the list.
///
/// Entry 1 and the last entry write `IA32_PERF_GLOBAL_CTRL`. The MSR-load
/// area runs *after* the VMCS-mediated `IA32_PERF_GLOBAL_CTRL` load (SDM
/// Vol 3C 28.3.2 and 28.4), so without this, when entries 2–4 reconfigure
/// `IA32_FIXED_CTR0` / `IA32_FIXED_CTR_CTRL` / `MSR_PEBS_DATA_CFG`, the
/// counter is already enabled — that "reconfiguring a running counter"
/// condition disqualifies PDist (SDM Vol 3B 21.9.6) and we want to play
/// it safe regardless. Wrapping the reconfig with explicit disable /
/// re-enable writes satisfies the rule.
///
/// The PEBS counter is `IA32_FIXED_CTR0`; the IC is on `IA32_PMC0`. Entry
/// 0 preserves the IC value across PEBS-armed iterations using the
/// full-width-write alias `IA32_A_PMC0` — writes via plain `IA32_PMC0`
/// truncate to 32 bits and sign-extend from bit 31, which garbles the
/// counter once it exceeds ~2.1 billion (SDM Vol 3B 21.2.8).
pub const PEBS_ENTRY_MSR_INDEXES: [u32; 9] = [
    msr::IA32_A_PMC0,
    msr::IA32_PERF_GLOBAL_CTRL,
    msr::IA32_FIXED_CTR0,
    msr::IA32_FIXED_CTR_CTRL,
    msr::MSR_PEBS_DATA_CFG,
    msr::IA32_DS_AREA,
    msr::IA32_PERF_GLOBAL_STATUS_RESET,
    msr::IA32_PEBS_ENABLE,
    msr::IA32_PERF_GLOBAL_CTRL,
];

/// Pre-populate the MSR-index fields of a VM-entry MSR-load list page. Each
/// entry is 16 bytes — u32 index, u32 reserved, u64 value (SDM Vol 3C
/// Table 26-16).
/// The value fields stay zero; they're filled by `pebs_pre_vm_entry`.
fn init_pebs_entry_msr_indexes(page_virt: u64) {
    let base = page_virt as *mut u32;
    for (i, &msr_index) in PEBS_ENTRY_MSR_INDEXES.iter().enumerate() {
        // SAFETY: page is freshly allocated, page-aligned, 4KB; we touch
        // bytes 0..(9 * 16) = 0..144, well within the page.
        unsafe {
            core::ptr::write(base.add(i * 4), msr_index);
        }
    }
}

/// Create an empty feedback-buffers vector. Starts with no allocation; it
/// grows on the heap as buffers are registered.
fn feedback_buffers_new() -> FeedbackBuffers {
    heap_vec_with_capacity(0).expect("Failed to allocate feedback buffers")
}

/// Clone the parent's feedback buffers into a fresh vector for a forked VM.
/// Each entry is deep-copied into its own heap allocation so the child's
/// buffers are independent of the parent's.
fn feedback_buffers_from(parent: &FeedbackBuffers) -> FeedbackBuffers {
    let mut v = heap_vec_with_capacity(parent.len()).expect("Failed to allocate feedback buffers");
    for fb in parent.iter() {
        // Copy heap-to-heap: materializing `**fb` (a ~2KB FeedbackBufferInfo)
        // on the stack here would blow the 8KB kernel stack on the deep
        // fork-creation call chain.
        let cloned = heap_box_copy_from(&**fb).expect("Failed to clone feedback buffer");
        heap_vec_push(&mut v, cloned).expect("Failed to clone feedback buffer");
    }
    v
}

/// Size of the I/O channel shared page (one 4KB page).
pub const IO_CHANNEL_BUF_SIZE: usize = 4096;

/// Heap-allocated 4KB buffer used for the I/O channel's pending request /
/// last-response slots. Vmalloc-backed because two 4KB arrays inline in
/// `VmState` plus the rest of the struct would blow the kernel's 8KB stack
/// budget during `VmState::new`.
pub type IoPageBufBox = VmallocBox<[u8; IO_CHANNEL_BUF_SIZE]>;

/// Allocate a zeroed I/O channel page buffer directly on the heap.
#[cfg(feature = "cargo")]
fn box_io_page_buf() -> IoPageBufBox {
    extern crate alloc;
    let v = alloc::vec![0u8; IO_CHANNEL_BUF_SIZE];
    let boxed_slice = v.into_boxed_slice();
    let ptr = alloc::boxed::Box::into_raw(boxed_slice) as *mut [u8; IO_CHANNEL_BUF_SIZE];
    // SAFETY: `boxed_slice` has exactly `IO_CHANNEL_BUF_SIZE` elements, so its
    // pointer can be reinterpreted as a pointer to a fixed-size array of the
    // same length.
    unsafe { alloc::boxed::Box::from_raw(ptr) }
}

#[cfg(not(feature = "cargo"))]
fn box_io_page_buf() -> IoPageBufBox {
    let mut boxed: kernel::alloc::KVBox<core::mem::MaybeUninit<[u8; IO_CHANNEL_BUF_SIZE]>> =
        kernel::alloc::KVBox::new_uninit(kernel::alloc::flags::GFP_KERNEL)
            .expect("Failed to allocate I/O channel page buffer");
    // SAFETY: page is freshly allocated and we zero-fill the entire region
    // before calling `assume_init`. After zeroing, every byte is initialized
    // to a valid `u8` (0), so the resulting `[u8; IO_CHANNEL_BUF_SIZE]` is
    // fully initialized.
    unsafe {
        let ptr = boxed.as_mut_ptr().cast::<u8>();
        core::ptr::write_bytes(ptr, 0, IO_CHANNEL_BUF_SIZE);
        boxed.assume_init()
    }
}

/// Heap-allocated early-boot serial line accumulator. Boxed for the same
/// reason as [`IoPageBufBox`]: `VmState` is built by value on the stack before
/// being moved into its `VmStateBox`, so keeping this buffer inline would add
/// its size (times the construction's temporary copies) to the kernel's 8KB
/// stack budget during `VmState::new`/`new_for_fork`. See `SERIAL_LINE_ACC_SIZE`.
pub type SerialLineBufBox = VmallocBox<[u8; SERIAL_LINE_ACC_SIZE]>;

/// Allocate a zeroed serial line accumulator directly on the heap.
#[cfg(feature = "cargo")]
fn box_serial_line_buf() -> SerialLineBufBox {
    extern crate alloc;
    let v = alloc::vec![0u8; SERIAL_LINE_ACC_SIZE];
    let boxed_slice = v.into_boxed_slice();
    let ptr = alloc::boxed::Box::into_raw(boxed_slice) as *mut [u8; SERIAL_LINE_ACC_SIZE];
    // SAFETY: `boxed_slice` has exactly `SERIAL_LINE_ACC_SIZE` elements, so its
    // pointer can be reinterpreted as a pointer to a fixed-size array of the
    // same length.
    unsafe { alloc::boxed::Box::from_raw(ptr) }
}

#[cfg(not(feature = "cargo"))]
fn box_serial_line_buf() -> SerialLineBufBox {
    let mut boxed: kernel::alloc::KVBox<core::mem::MaybeUninit<[u8; SERIAL_LINE_ACC_SIZE]>> =
        kernel::alloc::KVBox::new_uninit(kernel::alloc::flags::GFP_KERNEL)
            .expect("Failed to allocate serial line accumulator");
    // SAFETY: freshly allocated; we zero-fill the entire region before calling
    // `assume_init`, so every byte is initialized to a valid `u8` (0).
    unsafe {
        let ptr = boxed.as_mut_ptr().cast::<u8>();
        core::ptr::write_bytes(ptr, 0, SERIAL_LINE_ACC_SIZE);
        boxed.assume_init()
    }
}

/// Maximum number of I/O channel requests that can sit in the
/// hypervisor-side pending queue waiting for the in-flight slot to free
/// up. Higher than the depth users typically want today (a few bash
/// commands), low enough that the queue's heap footprint stays bounded
/// (worst case ~`PENDING_IO_QUEUE_CAP * IO_CHANNEL_BUF_SIZE` if every
/// request fills its buffer).
pub const PENDING_IO_QUEUE_CAP: usize = 256;

/// One pending I/O action waiting for the in-flight slot.
///
/// Data is stored tightly (just `data.len()` bytes), not as a fixed 4KB
/// box: callers typically send short shell commands and a fixed-size
/// allocation per pending entry would dominate the queue's heap
/// footprint at large queue depths.
pub struct PendingIoAction {
    /// Earliest emulated TSC at which this action should fire when
    /// promoted to the in-flight slot.
    pub target_tsc: u64,
    /// Serialised request bytes, exactly as the guest module will see
    /// them on its shared page.
    pub data: HeapVec<u8>,
}

/// Size of the paravirtual-console shared page (one 4KB page). A single
/// `HYPERCALL_SERIAL_WRITE` emits at most this many bytes; longer printk
/// records are split into multiple writes by the guest console driver.
///
/// Equal to `PAGE_SIZE` and to the capacity of `IoPageBufBox`, which the
/// overflow buffer reuses — so a clamped write always fits in the pending
/// buffer.
pub const SERIAL_CONSOLE_PAGE_SIZE: usize = PAGE_SIZE;

/// State for the deterministic paravirtual batch console.
///
/// The guest's `bedrock-console.ko` registers a 4KB shared page via
/// `HYPERCALL_SERIAL_REGISTER_PAGE`, then — from its `struct console` `.write`
/// callback — copies each fully-formatted printk record into that page and
/// issues `HYPERCALL_SERIAL_WRITE` with the byte count. The host copies those
/// bytes into `pending_buf` and emits them as one `Serial` event
/// (`event_emit_console`), turning one VM exit per console byte into one VM
/// exit per console line.
///
/// Like `IoChannelState`, this is excluded from the determinism state hash:
/// `page_gpa` is host bookkeeping and the pending bytes are host-side output
/// staging — none of it is guest-visible.
pub struct SerialConsoleState {
    /// Guest physical address of the registered console page. Zero means
    /// "not registered yet"; `HYPERCALL_SERIAL_WRITE` fails until set.
    pub page_gpa: u64,
    /// Staging buffer the host copies a `HYPERCALL_SERIAL_WRITE` record into
    /// before emitting it as a `Serial` event. Reuses `IoPageBufBox` purely as
    /// a page-sized heap buffer (kept off the 8KB kernel stack).
    pub pending_buf: IoPageBufBox,
}

impl Default for SerialConsoleState {
    fn default() -> Self {
        Self::new()
    }
}

impl SerialConsoleState {
    /// Create fresh console state with no registration and an empty pending
    /// buffer.
    pub fn new() -> Self {
        Self {
            page_gpa: 0,
            pending_buf: box_io_page_buf(),
        }
    }

    /// Clone state for a forked child VM.
    ///
    /// The page registration is inherited — the child snapshots from a parent
    /// where `bedrock-console.ko` has already registered its page, which lives
    /// in shared (CoW) guest memory reachable via the same GPA. Any pending
    /// overflow bytes are dropped: a fork point is a quiescent moment with no
    /// half-emitted console line in flight, and the parent's pending bytes (if
    /// any) belong to the parent's output stream.
    pub fn clone_for_fork(parent: &Self) -> Self {
        Self {
            page_gpa: parent.page_gpa,
            pending_buf: box_io_page_buf(),
        }
    }
}

/// State for the deterministic hypervisor↔guest I/O channel.
///
/// Lives on `VmState` and is updated by:
/// - `HYPERCALL_IO_REGISTER_PAGE` — sets `page_gpa`.
/// - The new `BEDROCK_VM_QUEUE_IO_ACTION` ioctl — fills `request_buf` and
///   `request_len`, leaves `request_delivered = false` so the run loop will
///   inject the IRQ on the next eligible VM-entry.
/// - `check_io_channel` in the injection path — sets `request_delivered` once
///   the IRR bit has been set, so the IRQ is not re-issued every iteration.
/// - `HYPERCALL_IO_GET_REQUEST` — copies `request_buf[..request_len]` into the
///   registered shared page; on success the request stays in-flight until the
///   guest delivers the response (so a guest that re-issues GET due to a retry
///   sees the same data).
/// - `HYPERCALL_IO_PUT_RESPONSE` — reads bytes out of the shared page into
///   `response_buf`, clears the in-flight request, and exits to userspace.
pub struct IoChannelState {
    /// Guest physical address of the registered shared page. Zero means
    /// "not registered yet" — the run loop must hold off IRQ injection
    /// until the guest module has registered its page.
    pub page_gpa: u64,
    /// Length of the in-flight request in `request_buf`. Zero means the
    /// in-flight slot is free; the next pending entry (if any) is
    /// promoted into it by `promote_next_pending_io`.
    pub request_len: usize,
    /// True once the IRQ has been delivered to the guest for the current
    /// in-flight request. Prevents the run loop from re-setting the IRR
    /// bit on every iteration while the guest is consuming the request.
    pub request_delivered: bool,
    /// Earliest emulated-TSC value at which the in-flight request may be
    /// delivered. Zero means "fire as soon as the guest is interruptible
    /// and the IOAPIC pin is unmasked" (no PEBS-precise arming).
    ///
    /// When non-zero, `arm_for_next_iteration` arms PEBS so the next
    /// precise exit lands at this target (taking the earlier of this and
    /// any pending APIC timer deadline), and `check_io_channel` defers
    /// setting the APIC IRR until `emulated_tsc >= request_target_tsc`.
    pub request_target_tsc: u64,
    /// Length of the response in `response_buf`, valid only after the
    /// `VmcallIoResponse` exit and until userspace drains it.
    pub response_len: usize,
    /// Pending request bytes for the in-flight slot. Copied into the
    /// shared page on `HYPERCALL_IO_GET_REQUEST`.
    pub request_buf: IoPageBufBox,
    /// Latest response bytes. Filled by `HYPERCALL_IO_PUT_RESPONSE` from the
    /// shared page, drained by userspace via the `BEDROCK_VM_DRAIN_IO_RESPONSE`
    /// ioctl.
    pub response_buf: IoPageBufBox,
    /// FIFO queue of pending requests waiting for the in-flight slot.
    /// Userspace queues by calling `BEDROCK_VM_QUEUE_IO_ACTION`; each
    /// `HYPERCALL_IO_GET_REQUEST` frees the slot and promotes the front
    /// of this queue. The guest module is free to spawn parallel workers
    /// per IRQ, so the hypervisor keeps firing IRQs as fast as the slot
    /// turns over without waiting for `HYPERCALL_IO_PUT_RESPONSE`.
    pub pending: HeapVec<PendingIoAction>,
}

impl Default for IoChannelState {
    fn default() -> Self {
        Self::new()
    }
}

impl IoChannelState {
    /// Create a fresh I/O channel state with empty buffers and no
    /// registration.
    pub fn new() -> Self {
        Self {
            page_gpa: 0,
            request_len: 0,
            request_delivered: false,
            request_target_tsc: 0,
            response_len: 0,
            request_buf: box_io_page_buf(),
            response_buf: box_io_page_buf(),
            pending: heap_vec_with_capacity(0).expect("Failed to allocate pending queue"),
        }
    }

    /// Clone state for a forked child VM.
    ///
    /// The page registration is preserved — the child snapshots from the
    /// parent's running state where `bedrock-io.ko` has already registered
    /// its page, and the page itself lives in shared (CoW) guest memory
    /// reachable via the same GPA. Transient request/response slots and
    /// any pending queue entries are reset because no I/O is in flight
    /// at the moment of fork.
    pub fn clone_for_fork(parent: &Self) -> Self {
        let _ = parent; // Only `page_gpa` is inherited; reset the rest.
        Self {
            page_gpa: parent.page_gpa,
            request_len: 0,
            request_delivered: false,
            request_target_tsc: 0,
            response_len: 0,
            request_buf: box_io_page_buf(),
            response_buf: box_io_page_buf(),
            pending: heap_vec_with_capacity(0).expect("Failed to allocate pending queue"),
        }
    }

    /// Promote the front of `pending` into the in-flight slot if and
    /// only if the slot is currently free (`request_len == 0`). Called
    /// at the end of `HYPERCALL_IO_GET_REQUEST` (to chase the next IRQ
    /// without waiting for `PUT_RESPONSE`) and from the QUEUE ioctl
    /// path (to fast-path the first request into the slot directly).
    pub fn promote_next_pending(&mut self) {
        if self.request_len != 0 {
            return;
        }
        // Pop the front. HeapVec doesn't expose VecDeque-style O(1)
        // pop_front, but at the queue depths we care about (single-digit
        // to low hundreds) the O(n) shift is negligible compared to the
        // per-request work.
        let next = match heap_vec_remove_front(&mut self.pending) {
            Some(n) => n,
            None => return,
        };
        let len = next.data.len().min(IO_CHANNEL_BUF_SIZE);
        self.request_buf[..len].copy_from_slice(&next.data[..len]);
        self.request_len = len;
        self.request_target_tsc = next.target_tsc;
        self.request_delivered = false;
        // A new in-flight request always starts a fresh response cycle.
        self.response_len = 0;
    }

    /// Append a new request to the pending queue. Does not promote;
    /// callers should invoke `promote_next_pending` afterwards (or rely
    /// on the next `GET_REQUEST` doing so).
    pub fn enqueue_pending(&mut self, action: PendingIoAction) -> EnqueueResult {
        if self.pending.len() >= PENDING_IO_QUEUE_CAP {
            return EnqueueResult::Full;
        }
        match heap_vec_push(&mut self.pending, action) {
            Ok(()) => EnqueueResult::Queued,
            Err(_) => EnqueueResult::OutOfMemory,
        }
    }
}

/// Outcome of `IoChannelState::enqueue_pending`. `Queued` is the happy
/// path; `Full` means the queue is at `PENDING_IO_QUEUE_CAP` (caller
/// should map to `-EBUSY`); `OutOfMemory` means the underlying push
/// failed to allocate (`-ENOMEM`). Distinguishing the two lets the
/// ioctl surface the right errno instead of silently dropping the
/// action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnqueueResult {
    Queued,
    Full,
    OutOfMemory,
}

/// Boxed VmState type alias - used by RootVm and ForkedVm to reduce stack usage.
pub type VmStateBox<V, I> = HeapBox<VmState<V, I>>;

/// Box a VmState for heap allocation.
pub fn box_vm_state<V: VirtualMachineControlStructure, I: InstructionCounter>(
    state: VmState<V, I>,
) -> VmStateBox<V, I> {
    heap_box(state)
}

const PAGE_SIZE: usize = 4096;

/// Maximum number of pages in a single feedback buffer (1MB = 256 pages).
///
/// This caps the size of an individual buffer. The *number* of feedback
/// buffers a guest may register is unbounded (see [`FeedbackBuffers`]).
pub const FEEDBACK_BUFFER_MAX_PAGES: usize = 256;

/// Size of one feedback-buffer slot in the mmap file-offset layout (1MB).
///
/// A single buffer is capped at this size ([`FEEDBACK_BUFFER_MAX_PAGES`]
/// pages), so feedback buffer `i` lives at file offset
/// `base + i * FEEDBACK_BUFFER_SLOT_SIZE`. Because the per-buffer size is
/// fixed, this fixed stride still works even though the *number* of buffers
/// is unbounded. Shared by the kernel module's mmap handlers and the
/// userspace mapper so the two never drift.
pub const FEEDBACK_BUFFER_SLOT_SIZE: u64 = FEEDBACK_BUFFER_MAX_PAGES as u64 * PAGE_SIZE as u64;

/// Fixed mmap file offset of the unified event buffer.
///
/// The feedback-buffer region is now unbounded (any number of 1MB slots), so
/// the event buffer can no longer sit "just past" a fixed-size region — it
/// lives at this sentinel offset instead. mmap file offsets are purely
/// virtual, so a large value costs nothing; it only has to sit above the
/// guest-memory and feedback-buffer regions for every realistic configuration
/// (64 TiB). Shared by the kernel module's mmap handlers and the userspace
/// mapper.
pub const EVENT_BUFFER_MMAP_OFFSET: u64 = 1 << 46;

/// Maximum length, in bytes, of a feedback-buffer identifier. Sized to fit a
/// SHA-256 hex digest with room for a colon-separated suffix.
pub const FEEDBACK_BUFFER_ID_MAX_LEN: usize = 128;

/// Information about a registered feedback buffer.
///
/// Guests register a feedback buffer (e.g., a coverage bitmap) via the
/// `HYPERCALL_REGISTER_FEEDBACK_BUFFER` hypercall so the host can read it
/// directly without copying.
///
/// Each buffer carries a byte-string identifier (e.g. a binary's
/// `--build-id`). IDs are *not* required to be unique: two registrations
/// with the same ID mean two instances of the same domain (typically two
/// processes running the same binary) and are expected to be merged at
/// read time by the host.
#[derive(Clone, Copy)]
pub struct FeedbackBufferInfo {
    /// Original guest virtual address.
    pub gva: u64,
    /// Size in bytes.
    pub size: u64,
    /// Number of pages.
    pub num_pages: usize,
    /// Page-aligned GPAs that make up the buffer.
    pub gpas: [u64; FEEDBACK_BUFFER_MAX_PAGES],
    /// Identifier bytes; only the first `id_len` are meaningful. Trailing
    /// bytes are zero so a slot can be plain-copied without leaking
    /// previous occupants.
    pub id: [u8; FEEDBACK_BUFFER_ID_MAX_LEN],
    /// Length of the identifier in bytes. Always `<= FEEDBACK_BUFFER_ID_MAX_LEN`.
    pub id_len: u32,
}

impl Default for FeedbackBufferInfo {
    fn default() -> Self {
        Self {
            gva: 0,
            size: 0,
            num_pages: 0,
            gpas: [0u64; FEEDBACK_BUFFER_MAX_PAGES],
            id: [0u8; FEEDBACK_BUFFER_ID_MAX_LEN],
            id_len: 0,
        }
    }
}

impl FeedbackBufferInfo {
    /// The identifier as a byte slice.
    pub fn id_bytes(&self) -> &[u8] {
        &self.id[..self.id_len as usize]
    }
}

/// Clear the intercept bit for an MSR in the MSR bitmap (enable passthrough).
///
/// Intel SDM Vol 3C, Section 26.6.9: MSR bitmap is 4KB with layout:
/// - Offset 0:    Read bitmap for low MSRs (0x00000000-0x00001FFF)
/// - Offset 1024: Read bitmap for high MSRs (0xC0000000-0xC0001FFF)
/// - Offset 2048: Write bitmap for low MSRs (0x00000000-0x00001FFF)
/// - Offset 3072: Write bitmap for high MSRs (0xC0000000-0xC0001FFF)
///
/// Each bit controls whether an MSR access causes a VM exit (1) or not (0).
///
/// # Safety
/// The bitmap pointer must point to a valid 4KB MSR bitmap page.
#[inline]
fn msr_bitmap_clear_intercept(bitmap: *mut u8, msr: u32) {
    let (read_base, write_base, index) = if msr < 0x2000 {
        // Low MSR range: 0x00000000-0x00001FFF
        (0usize, 2048usize, msr as usize)
    } else if (0xC000_0000..0xC000_2000).contains(&msr) {
        // High MSR range: 0xC0000000-0xC0001FFF
        (1024usize, 3072usize, (msr - 0xC000_0000) as usize)
    } else {
        // MSR outside bitmap range - always causes VM exit, nothing to do
        return;
    };

    let byte_offset = index / 8;
    let bit_mask = !(1u8 << (index % 8));

    // Safety: caller guarantees bitmap points to valid 4KB page
    unsafe {
        // Clear read intercept bit
        let read_ptr = bitmap.add(read_base + byte_offset);
        *read_ptr &= bit_mask;

        // Clear write intercept bit
        let write_ptr = bitmap.add(write_base + byte_offset);
        *write_ptr &= bit_mask;
    }
}

/// Default IA32_PAT value after reset.
/// PAT0=WB(6), PAT1=WT(4), PAT2=UC-(7), PAT3=UC(0),
/// PAT4=WB(6), PAT5=WT(4), PAT6=UC-(7), PAT7=UC(0)
pub const PAT_DEFAULT: u64 = 0x0007_0406_0007_0406;

/// Default TSC frequency (2995.2 MHz) for deterministic time emulation.
pub const DEFAULT_TSC_FREQUENCY: u64 = 2_995_200_000;

/// Logging mode for deterministic exit capture.
///
/// Controls when and how exits are captured:
/// - `Disabled`: No logging (default)
/// - `AllExits`: Log every deterministic exit (for debugging, higher overhead)
/// - `AtTsc`: Log once when TSC >= target, hash full memory (for binary search)
/// - `AtShutdown`: Log once at vmcall shutdown, hash full memory (for comparison)
/// - `Checkpoints`: Log state snapshots at configurable TSC intervals (for divergence window detection)
/// - `TscRange`: Log only exits within a TSC range (used with single-stepping)
#[repr(u32)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ExitTrigger {
    /// No logging.
    #[default]
    Disabled = 0,
    /// Log every deterministic exit (current behavior).
    AllExits = 1,
    /// Log once when TSC >= target_tsc, hash full memory.
    /// Used for binary search to find divergence point.
    AtTsc = 2,
    /// Log once at vmcall shutdown, hash full memory.
    /// Used for comparing final state across runs.
    AtShutdown = 3,
    /// Log checkpoints at configurable TSC intervals.
    /// Uses exit_target_tsc as the checkpoint interval.
    /// Each checkpoint includes registers and device state hashes.
    /// Memory hash is set to 0 to skip expensive full-memory hashing.
    Checkpoints = 4,
    /// Log only exits within a TSC range.
    /// Uses single_step_tsc_range field for bounds.
    /// Used with single-stepping for fine-grained debugging.
    TscRange = 5,
}

/// Synthetic exit reason for checkpoint entries.
/// This is not a hardware VMX exit reason - it identifies log entries
/// that are periodic state snapshots rather than actual VM exits.
pub const EXIT_REASON_CHECKPOINT: u32 = 0xFFFFFFFF;

/// Where a just-emitted `Exit` record's payload lives, so its deferred
/// `memory_hash` field can be patched after the guest's memory stabilizes.
#[derive(Clone, Copy)]
pub enum ExitLoc {
    /// Byte offset of the payload within the event buffer.
    Buffer(usize),
    /// The record was staged pending (buffer was full at emit); its payload is
    /// at offset 0 of `event_pending_buf`.
    Pending,
}

/// Per-exit-type performance statistics.
///
/// Tracks the count and total CPU cycles spent handling each exit type.
/// Cycles are measured using RDTSC.
#[repr(C)]
#[derive(Default, Clone, Copy, Debug)]
pub struct ExitStats {
    /// Number of exits of this type.
    pub count: u64,
    /// Total CPU cycles spent handling this exit type (via RDTSC).
    pub cycles: u64,
}

impl ExitStats {
    /// Record an exit with the given cycle count.
    #[inline]
    pub fn record(&mut self, cycles: u64) {
        self.count += 1;
        self.cycles += cycles;
    }

    /// Get the average cycles per exit, or 0 if no exits occurred.
    #[inline]
    pub fn avg_cycles(&self) -> u64 {
        self.cycles.checked_div(self.count).unwrap_or(0)
    }
}

/// Copy-on-write page allocation statistics.
///
/// Tracks COW fault patterns to analyze whether pre-allocating adjacent
/// pages would improve performance.
#[repr(C)]
#[derive(Default, Clone, Copy, Debug)]
pub struct CowStats {
    /// Total number of COW faults handled.
    pub total_faults: u64,
    /// Number of COW faults where an adjacent page (±1) was already COW'd.
    pub adjacent_1: u64,
    /// Number of COW faults where a page within ±2 pages was already COW'd.
    pub adjacent_2: u64,
    /// Number of COW faults where a page within ±4 pages was already COW'd.
    pub adjacent_4: u64,
    /// Number of COW faults where a page within ±8 pages was already COW'd.
    pub adjacent_8: u64,
    /// Number of EPT violations for pages that were already COW'd.
    /// This indicates stale EPT TLB entries (the EPT was already remapped to RWX
    /// but the TLB still had the old R+X entry).
    pub stale_tlb_faults: u64,
}

impl CowStats {
    /// Record a COW fault with adjacency information.
    ///
    /// `min_distance` is the minimum distance (in pages) to an already-COW'd page,
    /// or None if no pages have been COW'd yet.
    #[inline]
    pub fn record(&mut self, min_distance: Option<u64>) {
        self.total_faults += 1;
        if let Some(dist) = min_distance {
            if dist <= 1 {
                self.adjacent_1 += 1;
            }
            if dist <= 2 {
                self.adjacent_2 += 1;
            }
            if dist <= 4 {
                self.adjacent_4 += 1;
            }
            if dist <= 8 {
                self.adjacent_8 += 1;
            }
        }
    }
}

/// Collection of exit statistics for all exit types.
///
/// This structure tracks performance metrics for each type of VM exit,
/// allowing identification of which exits cause the most overhead.
#[repr(C)]
#[derive(Default, Clone, Copy, Debug)]
pub struct AllExitStats {
    /// CPUID instruction exits.
    pub cpuid: ExitStats,
    /// MSR read (RDMSR) exits.
    pub msr_read: ExitStats,
    /// MSR write (WRMSR) exits.
    pub msr_write: ExitStats,
    /// Control register access exits.
    pub cr_access: ExitStats,
    /// I/O instruction exits.
    pub io_instruction: ExitStats,
    /// EPT violation exits.
    pub ept_violation: ExitStats,
    /// External interrupt exits.
    pub external_interrupt: ExitStats,
    /// RDTSC instruction exits.
    pub rdtsc: ExitStats,
    /// RDTSCP instruction exits.
    pub rdtscp: ExitStats,
    /// RDPMC instruction exits.
    pub rdpmc: ExitStats,
    /// MWAIT instruction exits.
    pub mwait: ExitStats,
    /// VMCALL hypercall exits.
    pub vmcall: ExitStats,
    /// APIC access exits.
    pub apic_access: ExitStats,
    /// Monitor trap flag (MTF) exits.
    pub mtf: ExitStats,
    /// XSETBV instruction exits.
    pub xsetbv: ExitStats,
    /// RDRAND instruction exits.
    pub rdrand: ExitStats,
    /// RDSEED instruction exits.
    pub rdseed: ExitStats,
    /// Exception/NMI exits.
    pub exception_nmi: ExitStats,
    /// All other exit types combined.
    pub other: ExitStats,
    /// Total cycles in VM run loop (including guest time).
    pub total_run_cycles: u64,
    /// Total cycles in guest mode (actual VMX non-root execution).
    pub guest_cycles: u64,
    /// Cycles spent in run loop setup before VM entry (VMCS updates, GPR sync).
    pub vmentry_overhead_cycles: u64,
    /// Cycles spent after VM exit before exit handler (GPR sync, LFENCE, etc),
    /// excluding time in the IRQ window.
    pub vmexit_overhead_cycles: u64,
    /// Cycles spent in the IRQ window between VM exits (host interrupt servicing
    /// and perf counter read).
    pub irq_window_cycles: u64,
    /// Copy-on-write page allocation statistics.
    pub cow: CowStats,
    /// Count of non-deterministic MTF exits taken inside the PEBS margin
    /// window (the `PEBS_MARGIN` instructions between PEBS firing and the
    /// timer-deadline boundary). Bucketed separately from `mtf` because
    /// the count depends on PEBS skid and would otherwise diverge across
    /// runs in the determinism harness's exit-stats comparison.
    pub pebs_margin_steps: u64,
    /// `arm_precise_exit` returned `BelowMinDelta` — the requested target
    /// is within `PEBS_MIN_DELTA + PEBS_MARGIN` of the current count, so
    /// PEBS doesn't arm and MTF margin stepping is expected to land the
    /// boundary instead.
    pub pebs_arm_below_min_delta: u64,
    /// `arm_precise_exit` returned `AlreadyPast` — `target_tsc < current_tsc`.
    pub pebs_arm_already_past: u64,
    /// Iterations that VM-entered with `pebs.armed_action.is_some()` and
    /// returned without consuming the arming via a PEBS-induced exit. Each
    /// increment is one iter where PEBS was loaded but the counter didn't
    /// overflow before some other VM-exit happened.
    pub pebs_armed_iter_no_fire: u64,
    /// `check_apic_timer` fired the timer with `emulated_tsc > deadline`
    /// (strictly greater) — the precise PEBS+MTF boundary path was skipped
    /// and the timer is delivered late on the current deterministic exit.
    /// Diagnostic for silent PEBS misses.
    pub apic_timer_late_inject: u64,
}

impl AllExitStats {
    /// Record an exit of the given type with the specified cycle count.
    #[inline]
    pub fn record(&mut self, reason: ExitReason, cycles: u64) {
        match reason {
            ExitReason::Cpuid => self.cpuid.record(cycles),
            ExitReason::MsrRead => self.msr_read.record(cycles),
            ExitReason::MsrWrite => self.msr_write.record(cycles),
            ExitReason::CrAccess => self.cr_access.record(cycles),
            ExitReason::IoInstruction => self.io_instruction.record(cycles),
            ExitReason::EptViolation => self.ept_violation.record(cycles),
            ExitReason::ExternalInterrupt => self.external_interrupt.record(cycles),
            ExitReason::Rdtsc => self.rdtsc.record(cycles),
            ExitReason::Rdtscp => self.rdtscp.record(cycles),
            ExitReason::Rdpmc => self.rdpmc.record(cycles),
            ExitReason::Mwait => self.mwait.record(cycles),
            ExitReason::Vmcall | ExitReason::VmcallShutdown => self.vmcall.record(cycles),
            ExitReason::ApicAccess | ExitReason::ApicWrite => self.apic_access.record(cycles),
            ExitReason::MonitorTrapFlag => self.mtf.record(cycles),
            ExitReason::Xsetbv => self.xsetbv.record(cycles),
            ExitReason::Rdrand => self.rdrand.record(cycles),
            ExitReason::Rdseed => self.rdseed.record(cycles),
            ExitReason::ExceptionNmi => self.exception_nmi.record(cycles),
            _ => self.other.record(cycles),
        }
    }

    /// Get total exit count across all types.
    pub fn total_exit_count(&self) -> u64 {
        self.cpuid.count
            + self.msr_read.count
            + self.msr_write.count
            + self.cr_access.count
            + self.io_instruction.count
            + self.ept_violation.count
            + self.external_interrupt.count
            + self.rdtsc.count
            + self.rdtscp.count
            + self.rdpmc.count
            + self.mwait.count
            + self.vmcall.count
            + self.apic_access.count
            + self.mtf.count
            + self.xsetbv.count
            + self.rdrand.count
            + self.rdseed.count
            + self.exception_nmi.count
            + self.other.count
    }

    /// Get total exit handling cycles across all types.
    pub fn total_exit_cycles(&self) -> u64 {
        self.cpuid.cycles
            + self.msr_read.cycles
            + self.msr_write.cycles
            + self.cr_access.cycles
            + self.io_instruction.cycles
            + self.ept_violation.cycles
            + self.external_interrupt.cycles
            + self.rdtsc.cycles
            + self.rdtscp.cycles
            + self.rdpmc.cycles
            + self.mwait.cycles
            + self.vmcall.cycles
            + self.apic_access.cycles
            + self.mtf.cycles
            + self.xsetbv.cycles
            + self.rdrand.cycles
            + self.rdseed.cycles
            + self.exception_nmi.cycles
            + self.other.cycles
    }

    /// Reset all statistics to zero.
    pub fn reset(&mut self) {
        *self = Self::default();
    }
}

/// SYSCALL/SYSRET MSR state for guest emulation.
///
/// These MSRs configure the fast system call mechanism in 64-bit mode.
/// The guest needs to be able to read/write them for SYSCALL to work.
#[derive(Clone, Copy, Debug, Default)]
pub struct SyscallMsrs {
    /// IA32_STAR (0xC0000081) - SYSCALL segment selectors.
    pub star: Star,
    /// IA32_LSTAR (0xC0000082) - SYSCALL 64-bit entry point.
    pub lstar: Lstar,
    /// IA32_CSTAR (0xC0000083) - SYSCALL compatibility mode entry point.
    pub cstar: Cstar,
    /// IA32_FMASK (0xC0000084) - SYSCALL RFLAGS mask.
    pub fmask: Fmask,
}

impl SyscallMsrs {
    /// Capture SYSCALL MSRs from the current CPU.
    pub fn capture<M: MsrAccess>(msr_access: &M) -> Self {
        Self {
            star: Star::new(msr_access.read_msr(msr::IA32_STAR).unwrap_or(0)),
            lstar: Lstar::new(msr_access.read_msr(msr::IA32_LSTAR).unwrap_or(0)),
            cstar: Cstar::new(msr_access.read_msr(msr::IA32_CSTAR).unwrap_or(0)),
            fmask: Fmask::new(msr_access.read_msr(msr::IA32_FMASK).unwrap_or(0)),
        }
    }

    /// Load SYSCALL MSRs to hardware.
    ///
    /// This writes the MSR values to the CPU. Used to load guest MSR values
    /// before VM entry so SYSCALL/SYSRET work correctly in the guest.
    pub fn load<M: MsrAccess>(&self, msr_access: &M) {
        let _ = msr_access.write_msr(msr::IA32_STAR, self.star.bits());
        let _ = msr_access.write_msr(msr::IA32_LSTAR, self.lstar.bits());
        let _ = msr_access.write_msr(msr::IA32_CSTAR, self.cstar.bits());
        let _ = msr_access.write_msr(msr::IA32_FMASK, self.fmask.bits());
    }
}

/// Size of the early-boot serial line accumulator (the `OUT 0x3F8` byte path).
///
/// Before the paravirtual console module loads, `earlyprintk=serial` writes one
/// byte per `OUT 0x3F8`. To avoid a 32-byte event header per character, those
/// bytes are accumulated into this fixed buffer and emitted as one `Serial`
/// event per line (on `\n` or when the buffer fills). Boxed with the rest of
/// `VmState` — never on the 8 KB kernel stack.
pub const SERIAL_LINE_ACC_SIZE: usize = 256;

/// VM state that can be shared between RootVm and ForkedVm.
///
/// This struct contains all VM state except guest memory, which differs
/// between root and forked VMs (forked VMs use copy-on-write memory).
#[repr(C)]
pub struct VmState<V: VirtualMachineControlStructure, I: InstructionCounter> {
    /// The Virtual Machine Control Structure.
    pub vmcs: V,
    /// VMX context for guest/host register switching during VM entry/exit.
    /// Contains guest GPRs, host GPRs, and launch state.
    pub vmx_ctx: VmxContext,
    /// General-purpose register state (view for exit handler).
    /// Synced to/from vmx_ctx around VM entry/exit.
    pub gprs: GeneralPurposeRegisters,
    /// EPT page table for guest physical to host physical translation.
    /// Generic over the frame type V::P (the page type from VMCS).
    pub ept: EptPageTable<V::P>,
    /// MSR bitmap page (4KB, controls MSR access interception).
    pub msr_bitmap: V::P,
    /// VM-exit MSR-load list page (4KB). Pre-populated with a single entry —
    /// `IA32_PEBS_ENABLE = 0` — so the CPU atomically disables PEBS on VM-exit.
    /// This drops any PEBS record that would otherwise skid past VM-exit and
    /// fault while writing the host's now-stale `IA32_DS_AREA` mapping.
    /// The VMCS exit-load count stays at 0 until `register_pebs_page` arms it.
    pub pebs_exit_msr_load_page: V::P,
    /// VM-entry MSR-load list page (4KB). Updated by `pebs_pre_vm_entry` to
    /// hold the per-arming PEBS values; the CPU loads them atomically with
    /// VM-entry. Doing the writes via the load list (rather than WRMSR in
    /// host context) avoids a window where `IA32_DS_AREA` points at a guest
    /// VA in host mode — re-enabling `IA32_PEBS_ENABLE` in that window
    /// flushes any buffered PEBS record using the host's page tables and
    /// SMAP-faults on the user VA. Loaded only when the entry-load count is
    /// nonzero (set by `pebs_pre_vm_entry`, cleared by `pebs_post_vm_exit`).
    pub pebs_entry_msr_load_page: V::P,
    /// Early-boot serial line accumulator (the `OUT 0x3F8` byte path). Bytes are
    /// appended here and emitted as one `Serial` event per line, so early boot
    /// produces line-granular records like the paravirtual console — only the
    /// underlying exit cost differs (one VMX exit per byte vs. one VMCALL per
    /// line). See `SERIAL_LINE_ACC_SIZE`.
    pub serial_line_buf: SerialLineBufBox,
    /// Number of valid bytes in `serial_line_buf`.
    pub serial_line_len: usize,
    /// Emulated TSC captured at the first byte of the in-progress line. The
    /// emitted `Serial` event is stamped with this (not the flushing newline),
    /// matching the legacy per-line-start TSC semantics and the paravirt path.
    pub serial_line_tsc: u64,
    /// Host (raw RDTSC) captured at the first byte of the in-progress line.
    pub serial_line_real_tsc: u64,
    /// Guest XSAVE area page (4KB) for extended state (FPU/SSE/AVX) save/restore.
    pub guest_xsave_page: V::P,
    /// Host XSAVE area page (4KB) for extended state save/restore during VM transitions.
    pub host_xsave_page: V::P,
    /// XCR0 mask for XSAVE/XRSTOR operations.
    /// Set to xcr0::SSE_AVX (0x7) for SSE+AVX, 0 to disable XSAVE.
    pub xcr0_mask: u64,
    /// Last exit qualification (saved *after* the run loop prior to userspace exit).
    pub last_exit_qualification: u64,
    /// Last guest physical address (saved during VM exit for EPT violations).
    pub last_guest_physical_addr: u64,
    /// Grouped device states for emulation (APIC, serial, IOAPIC, RTC, MTRR, RDRAND).
    /// Boxed to reduce stack usage during VM creation.
    pub devices: DeviceStatesBox,
    /// Host state captured at VM initialization (for guest MSR emulation).
    pub host_state: HostState,
    /// Grouped guest MSR state (PAT, TSC_AUX, SYSCALL MSRs).
    pub msr_state: GuestMsrState,
    /// IA32_KERNEL_GS_BASE (0xC0000102) - kernel GS base for SWAPGS.
    pub kernel_gs_base: u64,
    /// Instruction counter for deterministic execution.
    pub instruction_counter: I,
    /// Last instruction count read after VM exit.
    pub last_instruction_count: u64,
    /// Emulated TSC value for deterministic time.
    /// Calculated as: last_instruction_count + tsc_offset
    pub emulated_tsc: u64,
    /// TSC offset added to instruction count for time-advancing idle exits.
    /// When HLT/MWAIT advances time to a timer deadline, this offset increases.
    pub tsc_offset: u64,
    /// Configured TSC frequency in Hz.
    pub tsc_frequency: u64,
    /// Logging mode for deterministic exit capture.
    pub exit_trigger: ExitTrigger,
    /// Target TSC value for AtTsc mode, or interval for Checkpoints mode.
    /// In AtTsc mode: log when emulated_tsc >= this value, then stop.
    /// In Checkpoints mode: interval between checkpoints.
    pub exit_target_tsc: u64,
    /// Universal logging start threshold (applies to all modes).
    /// No logging occurs until emulated_tsc >= this value.
    /// 0 means logging starts immediately (no threshold).
    pub exit_start_tsc: u64,
    /// Whether logging has been captured (for AtTsc/AtShutdown modes).
    /// Prevents logging more than once in single-point modes.
    pub exit_captured: bool,

    // --- Unified event stream (see `crate::events`). ---
    // `Exit` records (the `ExitRecord` body) are emitted into the event buffer
    // below, gated by `ExitTrigger` (above) as the trigger policy.
    /// Pointer to the event buffer (set by the kernel module after allocation).
    /// 1 MB, vmalloc'd by the kernel and mmap'd to userspace, drained linearly
    /// like the log/serial buffers. `None` until attached (and in cargo tests
    /// until `set_event_buffer` is called).
    pub event_buffer_ptr: Option<*mut u8>,
    /// Write cursor into the event buffer (the next free byte). Always a
    /// multiple of 8, so every `EventHeader` is naturally aligned.
    pub event_len: usize,
    /// Monotonic record sequence number. Never reset on drain, so userspace can
    /// detect gaps and order records globally across drains.
    pub event_seq: u64,
    /// Userspace include/exclude mask (set via ioctl). Filtering happens at emit
    /// time, so a disabled category costs a single bit test. Empty by default —
    /// the event stream is fully opt-in and adds zero overhead until enabled.
    pub event_categories: EventCategories,
    /// A single event staged because it did not fit in the remaining buffer.
    /// The caller exits to userspace to drain, and `event_clear()` re-appends
    /// this into the emptied buffer. `None` when no event is pending.
    pub event_pending: Option<EventKind>,
    /// Payload bytes of the pending event (page-sized heap buffer; reused as
    /// staging, kept off the 8 KB kernel stack).
    pub event_pending_buf: IoPageBufBox,
    /// Number of valid bytes in `event_pending_buf`.
    pub event_pending_len: usize,
    /// Header flags the pending event was emitted with (so the deterministic bit
    /// of a staged `Exit` survives the re-append in `event_clear`).
    pub event_pending_flags: u16,
    /// Emulated TSC the pending event was originally stamped with.
    pub event_pending_tsc: u64,
    /// Host (raw RDTSC) the pending event was originally stamped with.
    pub event_pending_real_tsc: u64,
    /// Where the most-recently-emitted `Exit` record's deferred `memory_hash`
    /// field lives, so `finalize_exit_memory_hash` can patch it after the guest
    /// memory stabilizes. `None` when no Exit record awaits finalization.
    pub pending_exit_loc: Option<ExitLoc>,
    /// When true, skip memory hashing in exit records (memory_hash stays 0).
    pub skip_memory_hash: bool,
    /// TSC range for single-stepping (start, end). None means disabled.
    pub single_step_tsc_range: Option<(u64, u64)>,
    /// Whether MTF is currently enabled in VMCS.
    pub mtf_enabled: bool,
    /// Stop VM when emulated_tsc reaches this value. None means disabled.
    pub stop_at_tsc: Option<u64>,
    /// Exit handler performance statistics.
    /// Boxed to reduce stack usage during VM creation.
    pub exit_stats: ExitStatsBox,
    /// Last checkpoint index written (for Checkpoints mode).
    /// Tracks which checkpoint interval we last logged.
    pub last_checkpoint_idx: u64,
    /// Whether the last VM exit was deterministic (i.e., emulated_tsc is up to date).
    /// Used to skip interrupt injection after non-deterministic exits (e.g., ExternalInterrupt)
    /// where the stale emulated_tsc could cause incorrect timer behavior.
    pub last_exit_deterministic: bool,
    /// Skid of the most recent PEBS-induced EPT-violation exit, in TSC ticks
    /// (= retired guest instructions). Computed as
    /// `current_tsc - armed_target_tsc` at handle_pebs_precise_exit time
    /// and consumed by `write_exit_record`. A non-zero value indicates the
    /// PEBS exit landed past the programmed PEBS firing point. With PDist this
    /// should usually be 0. Stale value outside the EPT_VIOLATION_PEBS log
    /// entry that captured it — the log writer resets it to 0 after recording.
    pub last_pebs_skid: i64,
    /// Guest INST_RETIRED gain between the most recent PEBS arming and the
    /// fire that produced `last_pebs_skid`. Subtracting the encoded
    /// PEBS-firing-point delta gives the actual hardware skid; comparing
    /// against `last_pebs_tsc_offset_delta` says whether emulated TSC
    /// advanced via guest instructions or via HLT/MWAIT clamps.
    pub last_pebs_inst_delta: i64,
    /// Tsc_offset gain between the most recent PEBS arming and fire. For a
    /// well-behaved PEBS exit this should be 0 — emulated_tsc only advances
    /// via HLT/MWAIT, and PEBS-induced EPT violations don't follow idle.
    pub last_pebs_tsc_offset_delta: i64,
    /// Run-loop iterations the firing arming persisted across. Reset to 0
    /// in `arm_precise_exit`'s Armed path. A non-zero value at fire time
    /// indicates the firing iter used a stale (multi-iter) arming.
    pub last_pebs_iters_since_arm: u32,
    /// PEBS firing target minus current TSC at the time of the most recent
    /// successful arming, in retired guest instructions. Useful for diagnosing
    /// skid outliers by correlating them against the programmed PDist distance.
    pub last_pebs_arm_delta: u64,
    /// Feedback buffers registered by the guest via hypercall (unbounded count).
    /// Used for efficient fuzzing feedback collection (e.g., coverage bitmap).
    /// Each registration is appended; the assigned slot index is returned to
    /// the guest in RAX. See [`FeedbackBuffers`] for the heap-growable layout.
    pub feedback_buffers: FeedbackBuffers,
    /// VPID (Virtual Processor Identifier) allocated for this VM.
    /// Used for TLB tagging. Returned to free list when VM is dropped.
    /// 0 means no VPID allocated (VPID feature disabled or cargo/test mode).
    pub vpid: u16,
    /// When true, intercept guest #PF exceptions via the exception bitmap.
    /// The #PF is logged and reinjected so the guest handles it normally.
    /// Used for determinism analysis to observe spurious page faults.
    pub intercept_pf: bool,
    /// Per-VM PEBS state for precise VM exits. None when the host CPU does not
    /// support EPT-friendly PEBS or when the feature has not been initialized
    /// for this VM. Boxed to avoid bloating the stack-resident `VmState`.
    /// See `crates/bedrock-vmx/src/exits/pebs.rs` and SDM Vol 3B Section 21.9.5.
    pub pebs_state: Option<HeapBox<PebsState>>,
    /// Whether the host CPU advertises the prerequisites for EPT-friendly
    /// PEBS — `IA32_PERF_CAPABILITIES.PEBS_BASELINE = 1` and `PEBS_FMT >= 4`.
    /// Cached at construction so exit handlers can gate the precise-exit
    /// hypercall without an extra MSR read (which would itself `#GP` on
    /// CPUs that don't implement `IA32_PERF_CAPABILITIES`).
    pub pebs_supported: bool,
    /// State for the deterministic hypervisor↔guest I/O channel.
    ///
    /// The guest's `bedrock-io.ko` registers a shared 4KB page via
    /// `HYPERCALL_IO_REGISTER_PAGE`, and the host queues actions via the
    /// `BEDROCK_VM_QUEUE_IO_ACTION` ioctl. Pending request bytes and the
    /// latest response are buffered here; the buffers themselves live on
    /// the heap so this field stays small (a handful of words plus two box
    /// pointers).
    pub io_channel: IoChannelState,
    /// State for the deterministic paravirtual batch console.
    ///
    /// The guest's `bedrock-console.ko` registers a shared 4KB page via
    /// `HYPERCALL_SERIAL_REGISTER_PAGE` and ships whole printk records through
    /// `HYPERCALL_SERIAL_WRITE`, which the host drains into the same serial
    /// sink the emulated 8250 uses. See `SerialConsoleState`.
    pub serial_console: SerialConsoleState,
    /// Logical CPU this VM most recently ran on, or `None` before the first
    /// run-loop entry. Used to detect cross-CPU migration between ioctls.
    ///
    /// VM entries/exits are not required to invalidate guest-physical mappings
    /// (Intel SDM Vol 3C §30.4.3.2), and EPT TLB entries are per-logical-processor —
    /// propagating EPT changes to other LPs is software's responsibility
    /// (§30.4.3.4). When the run thread migrates between ioctls, CoW
    /// remappings done on the intermediate CPU may leave this CPU's EPT TLB
    /// pointing at parent HPAs. The run-loop entry path issues
    /// `INVEPT single-context` whenever `last_cpu` differs from the current
    /// CPU to flush those potentially-stale entries.
    pub last_cpu: Option<u32>,
}

/// Error type for VmState creation.
#[derive(Debug)]
pub enum VmStateError<E> {
    /// EPT page table creation failed.
    EptCreation(E),
    /// MSR bitmap allocation failed.
    MsrBitmapAlloc,
    /// PEBS VM-exit MSR-load page allocation failed.
    PebsExitMsrLoadAlloc,
    /// XSAVE area page allocation failed.
    XsavePageAlloc,
    /// VMCS setup failed.
    VmcsSetup(VmcsSetupError),
    /// Guest state copy failed.
    GuestStateCopy,
    /// INVEPT failed during fork (EPT TLB invalidation).
    InveptFailed,
}

impl<V: VirtualMachineControlStructure, I: InstructionCounter> VmState<V, I> {
    /// Create a new VmState with the given VMCS, EPT, and machine.
    ///
    /// This allocates and initializes the MSR bitmap, serial buffer, and XSAVE pages,
    /// captures host state, and sets up the VMCS.
    ///
    /// # Arguments
    ///
    /// * `vmcs` - The VMCS, already allocated and initialized with revision ID
    /// * `ept` - The EPT page table, already set up with guest memory mappings
    /// * `machine` - Machine for allocating pages
    /// * `exit_handler_rip` - Address of the VM exit handler (HOST_RIP in VMCS)
    /// * `instruction_counter` - Instruction counter for deterministic execution
    /// * `tsc_frequency` - Configured TSC frequency in Hz
    #[inline(never)]
    pub fn new<A: FrameAllocator<Frame = V::P>>(
        vmcs: V,
        ept: EptPageTable<V::P>,
        machine: &V::M,
        exit_handler_rip: u64,
        instruction_counter: I,
        tsc_frequency: u64,
    ) -> Result<Self, VmStateError<A::Error>> {
        // Allocate and initialize the MSR bitmap page.
        // All bits set to 1 = intercept all MSR accesses.
        // Intel SDM Vol 3C, Section 26.6.9
        let msr_bitmap = machine
            .kernel()
            .alloc_zeroed_page()
            .ok_or(VmStateError::MsrBitmapAlloc)?;

        // Set all bits to 1 to intercept all MSR reads/writes
        let ptr = msr_bitmap.virtual_address().as_u64() as *mut u8;
        // SAFETY: ptr points to a freshly-allocated zeroed 4KB page; writing PAGE_SIZE bytes is within bounds.
        unsafe {
            core::ptr::write_bytes(ptr, 0xFF, PAGE_SIZE);
        }

        // Allocate the PEBS VM-exit MSR-load page and pre-populate one entry —
        // `IA32_PEBS_ENABLE = 0`. The CPU reads this list on every VM-exit
        // when `VmExitMsrLoadCount > 0`. We only set the count > 0 once a
        // PEBS scratch page has been registered, so this page is dormant for
        // VMs that never use precise exits.
        // Intel SDM Vol 3C Section 26.7.2 (VM-exit MSR areas), Table 26-16.
        let pebs_exit_msr_load_page = machine
            .kernel()
            .alloc_zeroed_page()
            .ok_or(VmStateError::PebsExitMsrLoadAlloc)?;
        // Layout per SDM Table 26-16: msr_index (u32), reserved (u32), value (u64).
        let entry_ptr = pebs_exit_msr_load_page.virtual_address().as_u64() as *mut u32;
        // SAFETY: page is freshly allocated, zero-initialized, page-aligned;
        // writing 16 bytes at offset 0 is within bounds.
        unsafe {
            core::ptr::write(entry_ptr, msr::IA32_PEBS_ENABLE);
            // Bytes 4..8 stay zero (reserved). Bytes 8..16 stay zero (value = 0).
        }

        // Allocate the VM-entry MSR-load page and pre-populate the MSR-index
        // fields for the PEBS entry-load list. The value fields stay zero
        // here; `pebs_pre_vm_entry` writes the actual per-arming values just
        // before VM-entry. Same entry format as the exit-load page above
        // (Table 26-16).
        let pebs_entry_msr_load_page = machine
            .kernel()
            .alloc_zeroed_page()
            .ok_or(VmStateError::PebsExitMsrLoadAlloc)?;
        init_pebs_entry_msr_indexes(pebs_entry_msr_load_page.virtual_address().as_u64());

        // Enable passthrough (no VM exit) for MSRs that have dedicated VMCS
        // guest state fields. Hardware automatically saves/restores these at
        // VM exit/entry.
        // Intel SDM Vol 3C, Section 26.6.9: MSR Bitmap layout:
        //   Offset 0:    Read bitmap for low MSRs (0x00000000-0x00001FFF)
        //   Offset 1024: Read bitmap for high MSRs (0xC0000000-0xC0001FFF)
        //   Offset 2048: Write bitmap for low MSRs (0x00000000-0x00001FFF)
        //   Offset 3072: Write bitmap for high MSRs (0xC0000000-0xC0001FFF)
        //
        // FS_BASE and GS_BASE have VMCS fields (GuestFsBase, GuestGsBase).
        msr_bitmap_clear_intercept(ptr, msr::IA32_FS_BASE); // FS_BASE
        msr_bitmap_clear_intercept(ptr, msr::IA32_GS_BASE); // GS_BASE

        // KERNEL_GS_BASE does NOT have a VMCS field - we save/restore manually.
        msr_bitmap_clear_intercept(ptr, msr::IA32_KERNEL_GS_BASE);
        // EFER has VMCS field (GuestIa32Efer) and VM-entry/exit controls for
        // automatic save/restore (SAVE_IA32_EFER, LOAD_IA32_EFER).
        msr_bitmap_clear_intercept(ptr, msr::IA32_EFER); // IA32_EFER

        // SYSCALL MSRs - passthrough for performance. Guest reads/writes go
        // directly to hardware. We save/restore around VM entry/exit.
        msr_bitmap_clear_intercept(ptr, msr::IA32_STAR);
        msr_bitmap_clear_intercept(ptr, msr::IA32_LSTAR);
        msr_bitmap_clear_intercept(ptr, msr::IA32_CSTAR);
        msr_bitmap_clear_intercept(ptr, msr::IA32_FMASK);

        // SYSENTER MSRs - passthrough. These have VMCS fields so VMX
        // automatically saves/restores them on VM entry/exit.
        msr_bitmap_clear_intercept(ptr, msr::IA32_SYSENTER_CS);
        msr_bitmap_clear_intercept(ptr, msr::IA32_SYSENTER_ESP);
        msr_bitmap_clear_intercept(ptr, msr::IA32_SYSENTER_EIP);

        // Allocate XSAVE area pages (4KB each, zeroed)
        let guest_xsave_page = machine
            .kernel()
            .alloc_zeroed_page()
            .ok_or(VmStateError::XsavePageAlloc)?;
        let host_xsave_page = machine
            .kernel()
            .alloc_zeroed_page()
            .ok_or(VmStateError::XsavePageAlloc)?;

        // Initialize guest XSAVE area with deterministic FPU state.
        // This ensures the guest always starts with the same FPU/SSE state,
        // making FXSAVE/XSAVE results deterministic.
        // SAFETY: guest_xsave_page is valid and 4KB aligned
        unsafe {
            let xsave_ptr = guest_xsave_page.virtual_address().as_u64() as *mut u8;

            // FCW (FPU Control Word) at offset 0 = 0x037F (default after FINIT)
            // This sets: all exceptions masked, round to nearest, 64-bit precision
            let fcw: u16 = 0x037F;
            core::ptr::copy_nonoverlapping(fcw.to_le_bytes().as_ptr(), xsave_ptr, 2);

            // MXCSR at offset 24 = 0x1F80 (default)
            // This sets: all exceptions masked, round to nearest, no denormals-are-zero
            let mxcsr: u32 = 0x1F80;
            core::ptr::copy_nonoverlapping(mxcsr.to_le_bytes().as_ptr(), xsave_ptr.add(24), 4);

            // XSTATE_BV at offset 512 = xcr0_mask (indicates which components are valid)
            // This tells XRSTOR which state components to restore from this area.
            let xstate_bv: u64 = xcr0::SSE_AVX;
            core::ptr::copy_nonoverlapping(xstate_bv.to_le_bytes().as_ptr(), xsave_ptr.add(512), 8);
        }

        let host_state = HostState::capture(
            machine.cr_access(),
            machine.msr_access(),
            machine.descriptor_table_access(),
            exit_handler_rip,
            // RSP for exit handler - set dynamically before VM entry
            0,
        );

        // Detect EPT-friendly PEBS support once at VM construction. Reading
        // `IA32_PERF_CAPABILITIES` is itself optional — on processors without
        // the architectural PMU, the MSR `#GP`s and `read_msr` returns `Err`,
        // which we treat as "not supported". Requires
        // `PEBS_BASELINE = 1` (bit 14) and `PEBS_FMT >= 4` (bits 11:8).
        // See SDM Vol 3B Section 21.8.
        let pebs_supported = machine
            .msr_access()
            .read_msr(msr::IA32_PERF_CAPABILITIES)
            .map(|v| (v >> 14) & 1 != 0 && ((v >> 8) & 0xF) >= 4)
            .unwrap_or(false);

        vmcs.setup(ept.eptp(), Some(msr_bitmap.physical_address()), &host_state)
            .map_err(VmStateError::VmcsSetup)?;

        // Read back the allocated VPID (0 if VPID is disabled)
        let vpid = vmcs.read16(VmcsField16::VirtualProcessorId).unwrap_or(0);

        // Invalidate EPT TLB entries for this EPT context.
        // This ensures no stale translations from previous VMs (which may have used
        // the same physical address for their EPT root) affect this VM.
        // With VPID enabled, TLB entries persist across VM exits, so stale EPT
        // translations could cause non-deterministic behavior.
        <V::M as Machine>::V::invept_single_context(ept.eptp())
            .map_err(|_| VmStateError::InveptFailed)?;

        Ok(Self {
            vmcs,
            vmx_ctx: VmxContext::new(),
            gprs: GeneralPurposeRegisters::default(),
            ept,
            msr_bitmap,
            pebs_exit_msr_load_page,
            pebs_entry_msr_load_page,
            serial_line_buf: box_serial_line_buf(),
            serial_line_len: 0,
            serial_line_tsc: 0,
            serial_line_real_tsc: 0,
            guest_xsave_page,
            host_xsave_page,
            // Enable XSAVE for SSE+AVX by default
            xcr0_mask: xcr0::SSE_AVX,
            last_exit_qualification: 0,
            last_guest_physical_addr: 0,
            devices: heap_box(DeviceStates::default()),
            host_state,
            msr_state: GuestMsrState::new(),
            kernel_gs_base: 0,
            instruction_counter,
            last_instruction_count: 0,
            emulated_tsc: 0,
            tsc_offset: 0,
            tsc_frequency,
            exit_trigger: ExitTrigger::Disabled,
            exit_target_tsc: 0,
            exit_start_tsc: 0,
            exit_captured: false,
            event_buffer_ptr: None,
            event_len: 0,
            event_seq: 0,
            event_categories: EventCategories::empty(),
            event_pending: None,
            event_pending_buf: box_io_page_buf(),
            event_pending_len: 0,
            event_pending_flags: 0,
            event_pending_tsc: 0,
            event_pending_real_tsc: 0,
            pending_exit_loc: None,
            skip_memory_hash: false,
            single_step_tsc_range: None,
            mtf_enabled: false,
            stop_at_tsc: None,
            exit_stats: heap_box(AllExitStats::default()),
            last_checkpoint_idx: 0,
            last_exit_deterministic: true,
            last_pebs_skid: 0,
            last_pebs_inst_delta: 0,
            last_pebs_tsc_offset_delta: 0,
            last_pebs_iters_since_arm: 0,
            last_pebs_arm_delta: 0,
            feedback_buffers: feedback_buffers_new(),
            vpid,
            intercept_pf: false,
            pebs_state: None,
            pebs_supported,
            io_channel: IoChannelState::new(),
            serial_console: SerialConsoleState::new(),
            last_cpu: None,
        })
    }

    // ========================================================================
    // Unified event stream (see `crate::events`).
    // ========================================================================

    /// Attach the kernel-allocated event buffer (1 MB, mmap'd to userspace).
    pub fn set_event_buffer(&mut self, ptr: *mut u8) {
        self.event_buffer_ptr = Some(ptr);
    }

    /// Detach the event buffer and reset the cursor (e.g. on disable).
    pub fn clear_event_buffer_ptr(&mut self) {
        self.event_buffer_ptr = None;
        self.event_len = 0;
        self.event_pending = None;
        self.event_pending_len = 0;
    }

    /// Number of valid bytes in the event buffer (`[0..event_len]`), which
    /// userspace drains after a RUN exit.
    pub fn event_buffer_len(&self) -> usize {
        self.event_len
    }

    /// True if an event was staged because the buffer filled. The exit
    /// dispatcher checks this after handling an exit and forces a drain
    /// round-trip to userspace.
    pub fn event_buffer_full(&self) -> bool {
        self.event_pending.is_some()
    }

    /// Returns the event buffer virtual address for mmap.
    pub fn event_buffer_ptr(&self) -> Option<*mut u8> {
        self.event_buffer_ptr
    }

    /// Set the userspace category include/exclude mask (from ioctl).
    pub fn set_event_categories(&mut self, categories: EventCategories) {
        self.event_categories = categories;
    }

    /// Current category mask.
    pub fn event_categories(&self) -> EventCategories {
        self.event_categories
    }

    /// True if `kind`'s category is enabled.
    pub fn event_category_enabled(&self, kind: EventKind) -> bool {
        self.event_categories.contains(kind.category())
    }

    /// Reset the event cursor after userspace drains the buffer, re-appending a
    /// single event that was staged because it did not fit before the drain.
    /// Called at the start of every RUN ioctl.
    pub fn event_clear(&mut self) {
        self.event_len = 0;
        if let Some(kind) = self.event_pending.take() {
            let len = self.event_pending_len;
            let flags = self.event_pending_flags;
            let tsc = self.event_pending_tsc;
            let real_tsc = self.event_pending_real_tsc;
            // `event_pending_buf` is a separate heap allocation, distinct from
            // the event buffer, so reading it via a raw pointer across the
            // `&mut self` call below does not alias the destination.
            let src = self.event_pending_buf.as_ptr();
            // SAFETY: `src` is valid for `len` bytes (set when the event was
            // staged); the now-empty buffer has room for it.
            unsafe {
                self.event_write(kind, flags, tsc, real_tsc, src, len, core::ptr::null(), 0);
            }
            // If this was the deferred `Exit` record, point finalize at its new
            // home so a still-pending memory_hash patch lands in the buffer.
            if kind == EventKind::Exit && matches!(self.pending_exit_loc, Some(ExitLoc::Pending)) {
                self.pending_exit_loc = Some(ExitLoc::Buffer(self.event_len_at_last_record()));
            }
            self.event_pending_len = 0;
        }
    }

    /// Byte offset of the payload of the most-recently-written record (used by
    /// `event_clear` to relocate a finalize target after re-appending it).
    fn event_len_at_last_record(&self) -> usize {
        // The last record's header sits at `event_len - (its total size)`; its
        // payload begins `EVENT_HEADER_SIZE` after that. Recompute from the
        // pending length (padded) since `event_write` just advanced the cursor.
        let total = EVENT_HEADER_SIZE + align_up(self.event_pending_len, 8);
        self.event_len - total + EVENT_HEADER_SIZE
    }

    /// Append one event stamped with the current emulated/host TSC.
    ///
    /// Returns `true` on success (or when filtered out — a disabled category is
    /// a single bit test), `false` if the buffer was full (the payload was
    /// staged as pending and the caller must advance RIP and exit to userspace
    /// to drain; `event_clear()` re-appends it).
    pub fn event_append(&mut self, kind: EventKind, payload: &[u8]) -> bool {
        // Early-out before reading the host TSC when the category is disabled
        // (the common case — the stream is opt-in). `event_write` re-checks.
        if !self.event_categories.contains(kind.category()) {
            return true;
        }
        let tsc = self.emulated_tsc;
        let real_tsc = rdtsc();
        // SAFETY: `payload` is a valid slice that never aliases the event buffer
        // (callers pass stack temporaries, stack-built POD, or separate heap
        // buffers).
        unsafe {
            self.event_write(
                kind,
                kind.default_flags(),
                tsc,
                real_tsc,
                payload.as_ptr(),
                payload.len(),
                core::ptr::null(),
                0,
            )
        }
    }

    /// Append one event stamped with an explicit TSC (e.g. a serial line's
    /// start time rather than the flushing newline's time).
    pub fn event_append_at(
        &mut self,
        kind: EventKind,
        payload: &[u8],
        tsc: u64,
        real_tsc: u64,
    ) -> bool {
        // SAFETY: as in `event_append`. `event_write` applies the category filter.
        unsafe {
            self.event_write(
                kind,
                kind.default_flags(),
                tsc,
                real_tsc,
                payload.as_ptr(),
                payload.len(),
                core::ptr::null(),
                0,
            )
        }
    }

    /// Low-level record writer. Writes an [`EventHeader`] followed by the payload
    /// — `head_len` bytes from `head_ptr` then `tail_len` bytes from `tail_ptr`,
    /// written contiguously — padded up to an 8-byte boundary.
    ///
    /// # Safety
    ///
    /// `head_ptr`/`tail_ptr` must be valid for `head_len`/`tail_len` reads and
    /// must point into memory distinct from the event buffer (they always do —
    /// payloads are stack temporaries, stack-built POD, or separate heap
    /// allocations, never the event buffer itself). `tail_ptr` may be null when
    /// `tail_len == 0` (the single-part case).
    #[allow(clippy::too_many_arguments)]
    unsafe fn event_write(
        &mut self,
        kind: EventKind,
        flags: u16,
        tsc: u64,
        real_tsc: u64,
        head_ptr: *const u8,
        head_len: usize,
        tail_ptr: *const u8,
        tail_len: usize,
    ) -> bool {
        // Filtered: one bit test, no work.
        if !self.event_categories.contains(kind.category()) {
            return true;
        }
        let base = match self.event_buffer_ptr {
            Some(p) => p,
            None => return true, // no buffer attached: drop silently
        };
        // The payload is `head` (a fixed struct or line) optionally followed by a
        // variable `tail` (e.g. an I/O-channel transaction's bytes). They are
        // written contiguously; `tail_len == 0` is the common single-part case.
        let len = head_len + tail_len;
        let need = EVENT_HEADER_SIZE + align_up(len, 8);
        if self.event_len + need > EVENT_BUFFER_SIZE {
            // Stage the payload as the single pending event and signal the
            // caller to drain. If one is already staged (the buffer filled
            // earlier this exit), drop this record rather than clobber it — the
            // staged one is re-appended after the drain; the dropped ones are
            // the bounded loss at the exact fill boundary.
            if self.event_pending.is_none() {
                let cap = IO_CHANNEL_BUF_SIZE;
                let head_copy = head_len.min(cap);
                let tail_copy = tail_len.min(cap - head_copy);
                let dst = self.event_pending_buf.as_mut_ptr().cast::<u8>();
                // SAFETY: `head_ptr`/`tail_ptr` are valid for `head_copy`/
                // `tail_copy` bytes; `dst` is a distinct page-sized heap buffer
                // with room for `head_copy + tail_copy <= cap` bytes written
                // contiguously. The tail copy is guarded because `tail_ptr` is
                // null for single-part callers (`tail_len == 0`).
                unsafe {
                    core::ptr::copy_nonoverlapping(head_ptr, dst, head_copy);
                    if tail_copy > 0 {
                        core::ptr::copy_nonoverlapping(tail_ptr, dst.add(head_copy), tail_copy);
                    }
                }
                self.event_pending = Some(kind);
                self.event_pending_len = head_copy + tail_copy;
                self.event_pending_flags = flags;
                self.event_pending_tsc = tsc;
                self.event_pending_real_tsc = real_tsc;
            }
            return false;
        }
        let header = EventHeader {
            seq: self.event_seq,
            tsc,
            real_tsc,
            kind: kind.as_u16(),
            flags,
            len: len as u32,
        };
        let padded = align_up(len, 8);
        // SAFETY: `event_len + need <= EVENT_BUFFER_SIZE` (checked above), so the
        // header, the `len` payload bytes, and the `padded - len` pad bytes all
        // fit in the buffer. `base` is page-aligned and `event_len` is a multiple
        // of 8, so the record start is 8-aligned (as `EventHeader` needs). Both
        // `head_ptr` (`head_len` bytes) and `tail_ptr` (`tail_len` bytes) are
        // valid and distinct from the event buffer.
        unsafe {
            let rec = base.add(self.event_len);
            core::ptr::write(rec.cast::<EventHeader>(), header);
            core::ptr::copy_nonoverlapping(head_ptr, rec.add(EVENT_HEADER_SIZE), head_len);
            // Guarded: `tail_ptr` is null for single-part callers (`tail_len == 0`).
            if tail_len > 0 {
                core::ptr::copy_nonoverlapping(
                    tail_ptr,
                    rec.add(EVENT_HEADER_SIZE + head_len),
                    tail_len,
                );
            }
            // Zero the 0..7 padding bytes so they never leak host memory / vary
            // run-to-run (the determinism comparison depends on this).
            core::ptr::write_bytes(rec.add(EVENT_HEADER_SIZE + len), 0, padded - len);
        }
        self.event_seq = self.event_seq.wrapping_add(1);
        self.event_len += need;
        true
    }

    /// Append one early-boot serial byte to the line accumulator and, on newline
    /// or when the fixed buffer fills, emit one `Serial` event stamped with the
    /// line-start TSC. No-op (and no accumulation) when the `Serial` category is
    /// disabled, so the byte path costs a single bit test then.
    ///
    /// Returns `false` if emitting the line filled the event buffer (the line
    /// was staged pending; the caller should advance RIP and exit to userspace).
    pub fn event_serial_byte(&mut self, byte: u8) -> bool {
        if !self.event_categories.contains(EventCategories::SERIAL) {
            return true;
        }
        if self.serial_line_len == 0 {
            // Stamp at the first byte of a fresh line.
            self.serial_line_tsc = self.emulated_tsc;
            self.serial_line_real_tsc = rdtsc();
        }
        if self.serial_line_len < SERIAL_LINE_ACC_SIZE {
            self.serial_line_buf[self.serial_line_len] = byte;
            self.serial_line_len += 1;
        }
        if byte == b'\n' || self.serial_line_len == SERIAL_LINE_ACC_SIZE {
            return self.event_flush_serial_line();
        }
        true
    }

    /// Emit the accumulated early-boot serial line (if any) as a `Serial` event,
    /// resetting the accumulator. Used as the newline/full flush, as cheap
    /// insurance before a `HYPERCALL_SERIAL_WRITE` line, and at shutdown so a
    /// final non-newline-terminated partial line is not lost.
    ///
    /// Returns `false` if the event buffer filled (line staged pending).
    pub fn event_flush_serial_line(&mut self) -> bool {
        if self.serial_line_len == 0 {
            return true;
        }
        let len = self.serial_line_len;
        let tsc = self.serial_line_tsc;
        let real_tsc = self.serial_line_real_tsc;
        // Copy into a small stack temporary so the payload does not alias `self`
        // (the accumulator is an inline field of `VmState`).
        let mut tmp = [0u8; SERIAL_LINE_ACC_SIZE];
        tmp[..len].copy_from_slice(&self.serial_line_buf[..len]);
        self.serial_line_len = 0;
        self.event_append_at(EventKind::Serial, &tmp[..len], tsc, real_tsc)
    }

    /// Emit the freshly-copied paravirtual-console record
    /// (`serial_console.pending_buf[0..len]`) as one `Serial` event. Returns
    /// `false` if the event buffer filled (the record was staged pending).
    pub fn event_emit_console(&mut self, len: usize) -> bool {
        if !self.event_categories.contains(EventCategories::SERIAL) {
            return true;
        }
        let tsc = self.emulated_tsc;
        let real_tsc = rdtsc();
        // `pending_buf` is a separate heap allocation, distinct from the event
        // buffer — holding its pointer across the `&mut self` call is sound.
        let src = self.serial_console.pending_buf.as_ptr();
        let len = len.min(SERIAL_CONSOLE_PAGE_SIZE);
        // SAFETY: `src` is valid for `len` <= SERIAL_CONSOLE_PAGE_SIZE bytes and
        // does not alias the event buffer.
        unsafe {
            self.event_write(
                EventKind::Serial,
                EventKind::Serial.default_flags(),
                tsc,
                real_tsc,
                src,
                len,
                core::ptr::null(),
                0,
            )
        }
    }

    /// Emit one `IoChannel` event: the fixed [`IoChannelPayload`] metadata
    /// followed by the transaction's actual bytes — the injected request command
    /// (e.g. an encoded bash command) for a `Request`, or the guest's reply for a
    /// `Response`. The bytes come straight from the channel buffers
    /// (`io_channel.{request,response}_buf`).
    ///
    /// Request bytes are a deterministic input, so a `Request` record keeps the
    /// deterministic flag; response bytes are host-derived (command output, a
    /// `call_usermodehelper` errno, …), so a `Response` record clears it.
    ///
    /// Returns `false` if the event buffer filled (record staged pending).
    pub fn event_emit_io_channel(&mut self, payload: &IoChannelPayload) -> bool {
        if !self.event_categories.contains(EventCategories::IO_CHANNEL) {
            return true;
        }
        let is_response = payload.phase == IoChannelPhase::Response as u8;
        let (data_ptr, data_len) = if is_response {
            (
                self.io_channel.response_buf.as_ptr(),
                self.io_channel.response_len,
            )
        } else {
            (
                self.io_channel.request_buf.as_ptr(),
                self.io_channel.request_len,
            )
        };
        let flags = if is_response {
            0
        } else {
            EVENT_FLAG_DETERMINISTIC
        };
        let tsc = self.emulated_tsc;
        let real_tsc = rdtsc();
        let data_len = data_len.min(IO_CHANNEL_BUF_SIZE);
        // SAFETY: `payload` is a caller-owned 24-byte struct; `data_ptr` points
        // into a distinct page-sized heap buffer (`io_channel.{request,response}_buf`),
        // valid for `data_len` bytes; neither aliases the event buffer.
        unsafe {
            self.event_write(
                EventKind::IoChannel,
                flags,
                tsc,
                real_tsc,
                payload.as_bytes().as_ptr(),
                core::mem::size_of::<IoChannelPayload>(),
                data_ptr,
                data_len,
            )
        }
    }

    /// Emit one `Exit` event carrying the full `ExitRecord` body, remembering
    /// where its `memory_hash` field landed so `finalize_exit_memory_hash` can
    /// patch it once guest memory has stabilized. The `deterministic` flag is
    /// reflected in the record header (so the stream's own determinism filter
    /// matches the per-exit determinism recorded in `ExitRecord.flags`).
    ///
    /// # Safety
    ///
    /// `payload_ptr` must point to a valid `ExitRecord` (`len` == `size_of::<ExitRecord>()`)
    /// that does not alias the event buffer (callers pass a stack-built entry).
    unsafe fn emit_exit_event(&mut self, payload_ptr: *const u8, len: usize, deterministic: bool) {
        self.pending_exit_loc = None;
        // Capture Exit records only when the event buffer is attached and the
        // EXIT category is enabled.
        if self.event_buffer_ptr.is_none() || !self.event_categories.contains(EventCategories::EXIT)
        {
            return;
        }
        let flags = if deterministic {
            EVENT_FLAG_DETERMINISTIC
        } else {
            0
        };
        let tsc = self.emulated_tsc;
        let real_tsc = rdtsc();
        let payload_off = self.event_len + EVENT_HEADER_SIZE;
        // SAFETY: forwards this function's contract — `payload_ptr` is valid for
        // `len` bytes and does not alias the event buffer.
        let fit = unsafe {
            self.event_write(
                EventKind::Exit,
                flags,
                tsc,
                real_tsc,
                payload_ptr,
                len,
                core::ptr::null(),
                0,
            )
        };
        self.pending_exit_loc = Some(if fit {
            ExitLoc::Buffer(payload_off)
        } else {
            ExitLoc::Pending
        });
    }

    /// Patch the `memory_hash` (and, for forked VMs, `cow_page_count`) field of
    /// the most-recently-emitted `Exit` event, which `emit_exit_event` left
    /// zeroed for deferred finalization. Called from the VM run loop after the
    /// guest's memory has stabilized. No-op if no Exit record is pending.
    pub fn finalize_exit_memory_hash(&mut self, memory_hash: u64, cow_page_count: u32) {
        let loc = match self.pending_exit_loc.take() {
            Some(l) => l,
            None => return,
        };
        let mh_off = core::mem::offset_of!(ExitRecord, memory_hash);
        let cc_off = core::mem::offset_of!(ExitRecord, cow_page_count);
        let payload_base: *mut u8 = match loc {
            ExitLoc::Buffer(payload_off) => match self.event_buffer_ptr {
                // SAFETY: `payload_off` is within the 1 MB buffer (the record
                // was written there).
                Some(base) => unsafe { base.add(payload_off) },
                None => return,
            },
            // The Exit record was staged pending (buffer was full at emit); its
            // payload lives at offset 0 of the staging buffer. Patch there so the
            // re-appended copy carries the hash.
            ExitLoc::Pending => self.event_pending_buf.as_mut_ptr().cast::<u8>(),
        };
        // SAFETY: `memory_hash`/`cow_page_count` lie fully within the 512-byte
        // payload; `payload_base` is 8-aligned (record start is 8-aligned and the
        // header is 32 bytes), so both field writes are aligned.
        unsafe {
            core::ptr::write(payload_base.add(mh_off).cast::<u64>(), memory_hash);
            core::ptr::write(payload_base.add(cc_off).cast::<u32>(), cow_page_count);
        }
    }

    /// Check if logging is enabled (any mode except Disabled).
    pub fn exit_capture_enabled(&self) -> bool {
        self.exit_trigger != ExitTrigger::Disabled
    }

    /// Enable deterministic logging (AllExits mode for backward compatibility).
    pub fn enable_exit_capture(&mut self) {
        self.exit_trigger = ExitTrigger::AllExits;
        self.exit_captured = false;
    }

    /// Disable deterministic logging.
    pub fn disable_exit_capture(&mut self) {
        self.exit_trigger = ExitTrigger::Disabled;
        self.exit_captured = false;
    }

    /// Set the logging mode and target TSC.
    ///
    /// # Arguments
    ///
    /// * `mode` - The logging mode to use
    /// * `target_tsc` - Target/threshold TSC value:
    ///   - AllExits: only log when emulated_tsc >= target_tsc
    ///   - AtTsc: log once when emulated_tsc >= target_tsc
    ///   - AtShutdown/Disabled: ignored
    pub fn set_exit_trigger(&mut self, mode: ExitTrigger, target_tsc: u64) {
        self.exit_trigger = mode;
        self.exit_target_tsc = target_tsc;
        self.exit_captured = false;
    }

    /// Get the current logging mode.
    pub fn exit_trigger(&self) -> ExitTrigger {
        self.exit_trigger
    }

    /// Set the universal logging start threshold.
    ///
    /// No logging will occur until emulated_tsc >= start_tsc.
    /// This applies to all logging modes.
    ///
    /// # Arguments
    ///
    /// * `start_tsc` - TSC threshold (0 = log from start)
    pub fn set_exit_start_tsc(&mut self, start_tsc: u64) {
        self.exit_start_tsc = start_tsc;
    }

    /// Enable or disable #PF interception.
    ///
    /// When enabled, guest #PF exceptions cause VM exits. The exit handler
    /// logs the fault and reinjects it so the guest handles it normally.
    /// Used for determinism analysis to observe spurious page faults.
    ///
    /// This only sets the flag. The exception bitmap is updated in
    /// `apply_intercept_pf()` after the VMCS is loaded.
    pub fn set_intercept_pf(&mut self, enable: bool) {
        self.intercept_pf = enable;
    }

    /// Apply the #PF interception flag to the VMCS exception bitmap.
    ///
    /// Must be called after `vmcs.load()` (VMPTRLD) so VMCS writes succeed.
    pub fn apply_intercept_pf(&self) {
        let bitmap = self.vmcs.read32(VmcsField32::ExceptionBitmap).unwrap_or(0);
        let new_bitmap = if self.intercept_pf {
            bitmap | (1 << 14)
        } else {
            bitmap & !(1 << 14)
        };
        let _ = self.vmcs.write32(VmcsField32::ExceptionBitmap, new_bitmap);
    }

    /// Write a log entry for a VM exit.
    ///
    /// This captures guest registers, hashes all device states, and writes an
    /// entry to the log buffer. Behavior depends on exit_trigger:
    ///
    /// - `Disabled`: Returns immediately (no logging)
    /// - `AllExits`: Logs all exits (deterministic and non-deterministic)
    /// - `AtTsc`: Logs once when TSC >= exit_target_tsc, then stops (deterministic only)
    /// - `AtShutdown`: Returns immediately (handled by capture_exit_at_shutdown)
    /// - `Checkpoints`: Deterministic only, at checkpoint intervals
    /// - `TscRange`: Deterministic only, within single_step_tsc_range
    ///
    /// All modes respect exit_start_tsc - no logging occurs until TSC >= exit_start_tsc.
    pub fn capture_exit(
        &mut self,
        exit_reason: ExitReason,
        exit_qualification: u64,
        deterministic: bool,
    ) {
        // Universal start threshold - applies to all modes
        if self.exit_start_tsc > 0 && self.emulated_tsc < self.exit_start_tsc {
            return;
        }

        match self.exit_trigger {
            ExitTrigger::Disabled => return,
            ExitTrigger::AtShutdown => return, // Handled by capture_exit_at_shutdown()
            ExitTrigger::Checkpoints => {
                // Non-deterministic exits are only useful in AllExits mode
                if !deterministic {
                    return;
                }
                let interval = self.exit_target_tsc;
                if interval == 0 {
                    return;
                }

                let checkpoint_idx = self.emulated_tsc / interval;
                if checkpoint_idx > self.last_checkpoint_idx {
                    self.last_checkpoint_idx = checkpoint_idx;
                } else {
                    return; // Not yet reached next checkpoint
                }
            }
            ExitTrigger::AtTsc => {
                // Non-deterministic exits are only useful in AllExits mode
                if !deterministic {
                    return;
                }
                // Log once when TSC reaches target
                if self.exit_captured || self.emulated_tsc < self.exit_target_tsc {
                    return;
                }
            }
            ExitTrigger::AllExits => {
                // Log all exits (both deterministic and non-deterministic)
            }
            ExitTrigger::TscRange => {
                // Log both deterministic and non-deterministic exits during
                // single-stepping — non-determ exits (EPT violations, external
                // interrupts) are essential for diagnosing divergences.
                // Only log if TSC is within the single-step range
                if let Some((start, end)) = self.single_step_tsc_range {
                    if self.emulated_tsc < start || self.emulated_tsc >= end {
                        return;
                    }
                } else {
                    return; // No range configured
                }
            }
        }

        let flags = if deterministic {
            EXIT_RECORD_FLAG_DETERMINISTIC
        } else {
            0
        };
        self.write_exit_record(exit_reason, exit_qualification, flags);

        // For AtTsc mode, mark as captured so we don't log again
        if self.exit_trigger == ExitTrigger::AtTsc {
            self.exit_captured = true;
        }
    }

    /// Write a log entry at vmcall shutdown (for AtShutdown mode).
    ///
    /// This is called from the vmcall shutdown handler to capture final state.
    /// Only logs if mode is AtShutdown and not already captured.
    /// Respects exit_start_tsc - no logging if TSC < exit_start_tsc.
    pub fn capture_exit_at_shutdown(&mut self) {
        if self.exit_trigger != ExitTrigger::AtShutdown || self.exit_captured {
            return;
        }

        // Universal start threshold
        if self.exit_start_tsc > 0 && self.emulated_tsc < self.exit_start_tsc {
            return;
        }

        // Use a synthetic exit reason for shutdown logging
        self.write_exit_record(
            ExitReason::VmcallShutdown,
            0,
            EXIT_RECORD_FLAG_DETERMINISTIC,
        );
        self.exit_captured = true;
    }

    /// Write a log entry for a snapshot hypercall.
    ///
    /// This is called from the vmcall snapshot handler to capture state on demand.
    /// If logging is disabled this is a no-op.
    pub fn capture_exit_at_snapshot(&mut self) {
        // Respect exit_start_tsc threshold
        if self.exit_start_tsc > 0 && self.emulated_tsc < self.exit_start_tsc {
            return;
        }

        // If logging disabled, do nothing
        if self.exit_trigger == ExitTrigger::Disabled {
            return;
        }

        self.write_exit_record(
            ExitReason::VmcallSnapshot,
            0,
            EXIT_RECORD_FLAG_DETERMINISTIC,
        );
    }

    /// Emit an `Exit` event capturing this VM exit.
    ///
    /// Builds the 512-byte `ExitRecord` body (guest registers, device-state
    /// hashes, diagnostics) and appends it as an `EventKind::Exit` record. The
    /// `memory_hash` is left zero for deferred finalization (see
    /// `finalize_exit_memory_hash`). No-op unless the event buffer is attached
    /// with the `EXIT` category enabled.
    fn write_exit_record(&mut self, exit_reason: ExitReason, exit_qualification: u64, flags: u32) {
        // Capture Exit records only when the buffer is attached and EXIT is enabled.
        if self.event_buffer_ptr.is_none() || !self.event_categories.contains(EventCategories::EXIT)
        {
            return;
        }

        // Read guest state from VMCS
        let rip = self
            .vmcs
            .read_natural(VmcsFieldNatural::GuestRip)
            .unwrap_or(0);
        let rflags = self
            .vmcs
            .read_natural(VmcsFieldNatural::GuestRflags)
            .unwrap_or(0);
        let fs_base = self
            .vmcs
            .read_natural(VmcsFieldNatural::GuestFsBase)
            .unwrap_or(0);
        let gs_base = self
            .vmcs
            .read_natural(VmcsFieldNatural::GuestGsBase)
            .unwrap_or(0);
        let cr3 = self
            .vmcs
            .read_natural(VmcsFieldNatural::GuestCr3)
            .unwrap_or(0);
        let cs_base = self
            .vmcs
            .read_natural(VmcsFieldNatural::GuestCsBase)
            .unwrap_or(0);
        let ds_base = self
            .vmcs
            .read_natural(VmcsFieldNatural::GuestDsBase)
            .unwrap_or(0);
        let es_base = self
            .vmcs
            .read_natural(VmcsFieldNatural::GuestEsBase)
            .unwrap_or(0);
        let ss_base = self
            .vmcs
            .read_natural(VmcsFieldNatural::GuestSsBase)
            .unwrap_or(0);
        let pending_dbg_exceptions = self
            .vmcs
            .read_natural(VmcsFieldNatural::GuestPendingDebugExceptions)
            .unwrap_or(0);
        let interruptibility_state = self
            .vmcs
            .read32(VmcsField32::GuestInterruptibilityState)
            .unwrap_or(0);

        // Compute device state hashes
        let apic_hash = self.devices.apic.state_hash();
        let serial_hash = self.devices.serial.state_hash();
        let ioapic_hash = self.devices.ioapic.state_hash();
        let rtc_hash = self.devices.rtc.state_hash();
        let mtrr_hash = self.devices.mtrr.state_hash();
        let rdrand_hash = self.devices.rdrand.state_hash();

        // Memory hash is computed later by finalize_exit_record() after this method returns.
        let memory_hash = 0;

        let entry = ExitRecord {
            tsc: self.emulated_tsc,
            exit_reason: exit_reason as u32,
            flags,
            exit_qualification,
            rax: self.gprs.rax,
            rcx: self.gprs.rcx,
            rdx: self.gprs.rdx,
            rbx: self.gprs.rbx,
            rsp: self.gprs.rsp,
            rbp: self.gprs.rbp,
            rsi: self.gprs.rsi,
            rdi: self.gprs.rdi,
            r8: self.gprs.r8,
            r9: self.gprs.r9,
            r10: self.gprs.r10,
            r11: self.gprs.r11,
            r12: self.gprs.r12,
            r13: self.gprs.r13,
            r14: self.gprs.r14,
            r15: self.gprs.r15,
            rip,
            rflags,
            apic_hash,
            serial_hash,
            ioapic_hash,
            rtc_hash,
            mtrr_hash,
            rdrand_hash,
            memory_hash,
            fs_base,
            gs_base,
            kernel_gs_base: self.kernel_gs_base,
            cr3,
            cs_base,
            ds_base,
            es_base,
            ss_base,
            pending_dbg_exceptions,
            interruptibility_state,
            cow_page_count: 0,
            pebs_skid: self.last_pebs_skid,
            pebs_inst_delta: self.last_pebs_inst_delta,
            pebs_tsc_offset_delta: self.last_pebs_tsc_offset_delta,
            pebs_iters_since_arm: self.last_pebs_iters_since_arm,
            pebs_arm_delta: self.last_pebs_arm_delta,
            last_instruction_count: self.last_instruction_count,
            apic_timer_deadline: self.devices.apic.timer_deadline,
            io_channel_target_tsc: self.io_channel.request_target_tsc,
            pebs_armed_target_tsc: self
                .pebs_state
                .as_deref()
                .map(|p| p.armed_target_tsc)
                .unwrap_or(0),
            vmx_state_flags: u64::from(self.mtf_enabled)
                | (u64::from(self.last_exit_deterministic) << 1),
            _padding: [0; 16],
        };
        // Consume the PEBS diagnostics: only the EPT_VIOLATION_PEBS log
        // entry that captured them should report non-zero values;
        // subsequent exits would otherwise show stale data until the next
        // PEBS exit.
        self.last_pebs_skid = 0;
        self.last_pebs_inst_delta = 0;
        self.last_pebs_tsc_offset_delta = 0;
        self.last_pebs_iters_since_arm = 0;
        self.last_pebs_arm_delta = 0;

        // Emit the entry as an `Exit` event. The record's header determinism bit
        // mirrors `ExitRecord.flags` (the payload keeps its own copy too).
        // `emit_exit_event` records where the `memory_hash` field landed so
        // `finalize_exit_memory_hash` can patch it after guest memory stabilizes.
        let deterministic = flags & EXIT_RECORD_FLAG_DETERMINISTIC != 0;
        // SAFETY: `entry` is a stack-local `ExitRecord` (512 bytes) that does not
        // alias the event buffer.
        unsafe {
            self.emit_exit_event(
                core::ptr::from_ref(&entry).cast::<u8>(),
                core::mem::size_of::<ExitRecord>(),
                deterministic,
            );
        }
    }

    /// Create a VmState for testing with minimal initialization.
    ///
    /// This is only available in tests and creates a VmState with:
    /// - Empty EPT
    /// - Mock/dummy pages for MSR bitmap, serial buffer, XSAVE areas
    /// - Default device and MSR states
    #[cfg(test)]
    pub fn new_mock<A: FrameAllocator<Frame = V::P>, K: Kernel<P = V::P>>(
        vmcs: V,
        allocator: &mut A,
        kernel: &K,
        instruction_counter: I,
    ) -> Result<Self, &'static str> {
        let ept: EptPageTable<V::P> =
            EptPageTable::new(allocator).map_err(|_| "EPT creation failed")?;

        let msr_bitmap = kernel
            .alloc_zeroed_page()
            .ok_or("MSR bitmap alloc failed")?;
        let guest_xsave_page = kernel
            .alloc_zeroed_page()
            .ok_or("Guest XSAVE alloc failed")?;
        let host_xsave_page = kernel
            .alloc_zeroed_page()
            .ok_or("Host XSAVE alloc failed")?;
        let pebs_exit_msr_load_page = kernel
            .alloc_zeroed_page()
            .ok_or("PEBS exit MSR load page alloc failed")?;
        let pebs_entry_msr_load_page = kernel
            .alloc_zeroed_page()
            .ok_or("PEBS entry MSR load page alloc failed")?;

        Ok(Self {
            vmcs,
            vmx_ctx: VmxContext::new(),
            gprs: GeneralPurposeRegisters::default(),
            ept,
            msr_bitmap,
            pebs_exit_msr_load_page,
            pebs_entry_msr_load_page,
            serial_line_buf: box_serial_line_buf(),
            serial_line_len: 0,
            serial_line_tsc: 0,
            serial_line_real_tsc: 0,
            guest_xsave_page,
            host_xsave_page,
            xcr0_mask: 0x7, // x87 + SSE + AVX
            last_exit_qualification: 0,
            last_guest_physical_addr: 0,
            devices: heap_box(DeviceStates::default()),
            host_state: HostState::default(),
            msr_state: GuestMsrState::new(),
            kernel_gs_base: 0,
            instruction_counter,
            last_instruction_count: 0,
            emulated_tsc: 0,
            tsc_offset: 0,
            tsc_frequency: DEFAULT_TSC_FREQUENCY,
            exit_trigger: ExitTrigger::Disabled,
            exit_target_tsc: 0,
            exit_start_tsc: 0,
            exit_captured: false,
            event_buffer_ptr: None,
            event_len: 0,
            event_seq: 0,
            event_categories: EventCategories::empty(),
            event_pending: None,
            event_pending_buf: box_io_page_buf(),
            event_pending_len: 0,
            event_pending_flags: 0,
            event_pending_tsc: 0,
            event_pending_real_tsc: 0,
            pending_exit_loc: None,
            skip_memory_hash: false,
            single_step_tsc_range: None,
            mtf_enabled: false,
            stop_at_tsc: None,
            exit_stats: heap_box(AllExitStats::default()),
            last_checkpoint_idx: 0,
            last_exit_deterministic: true,
            last_pebs_skid: 0,
            last_pebs_inst_delta: 0,
            last_pebs_tsc_offset_delta: 0,
            last_pebs_iters_since_arm: 0,
            last_pebs_arm_delta: 0,
            feedback_buffers: feedback_buffers_new(),
            vpid: 0, // Tests don't use VPID
            intercept_pf: false,
            pebs_state: None,
            pebs_supported: false,
            io_channel: IoChannelState::new(),
            serial_console: SerialConsoleState::new(),
            last_cpu: None,
        })
    }

    /// Create a new VmState for a forked VM by cloning state from a parent.
    ///
    /// This method uses a direct memcpy of the VMCS region for efficiency.
    /// Per Intel SDM, the VMCS data format is implementation-specific; this
    /// assumes the parent and child VMCS regions use the same VMCS revision and
    /// implementation format. After copying, fields that must differ (EPT
    /// pointer, MSR bitmap address, and related per-child state) are updated.
    ///
    /// # Arguments
    ///
    /// * `vmcs` - The VMCS for this forked VM (must have revision ID set)
    /// * `ept` - The EPT page table (already cloned from parent with R+X permissions)
    /// * `parent_state` - Parent VmState to clone state from
    /// * `machine` - Machine for allocating pages
    /// * `_exit_handler_rip` - Unused (host state is copied from parent VMCS)
    /// * `instruction_counter` - Instruction counter for this forked VM
    #[inline(never)]
    pub fn new_for_fork<A: FrameAllocator<Frame = V::P>, I2: InstructionCounter>(
        vmcs: V,
        ept: EptPageTable<V::P>,
        parent_state: &VmState<V, I2>,
        machine: &V::M,
        _exit_handler_rip: u64,
        instruction_counter: I,
    ) -> Result<Self, VmStateError<A::Error>>
    where
        V::M: Machine,
    {
        // Allocate and initialize the MSR bitmap page.
        let msr_bitmap = machine
            .kernel()
            .alloc_zeroed_page()
            .ok_or(VmStateError::MsrBitmapAlloc)?;

        // Copy MSR bitmap settings from parent
        let parent_bitmap_ptr = parent_state.msr_bitmap.virtual_address().as_u64() as *const u8;
        let bitmap_ptr = msr_bitmap.virtual_address().as_u64() as *mut u8;
        // SAFETY: Both pointers refer to valid PAGE_SIZE allocations and do not overlap.
        unsafe {
            core::ptr::copy_nonoverlapping(parent_bitmap_ptr, bitmap_ptr, PAGE_SIZE);
        }

        // Allocate the PEBS VM-exit MSR-load page. Each forked VM owns its
        // own page with the same `IA32_PEBS_ENABLE = 0` entry pre-populated.
        // If the parent had PEBS registered, the parent's VMCS referenced the
        // parent's exit-load page; the child's VMCS is a memcpy of that VMCS,
        // so the child's `VmExitMsrLoadAddr` initially points at parent
        // memory. The post-VMCS-copy block below repoints it at this child
        // page when `pebs_state` is being inherited.
        let pebs_exit_msr_load_page = machine
            .kernel()
            .alloc_zeroed_page()
            .ok_or(VmStateError::PebsExitMsrLoadAlloc)?;
        let entry_ptr = pebs_exit_msr_load_page.virtual_address().as_u64() as *mut u32;
        // SAFETY: page is freshly allocated and zero-initialized; writing 4 bytes at
        // offset 0 stays within the page.
        unsafe {
            core::ptr::write(entry_ptr, msr::IA32_PEBS_ENABLE);
        }
        let pebs_entry_msr_load_page = machine
            .kernel()
            .alloc_zeroed_page()
            .ok_or(VmStateError::PebsExitMsrLoadAlloc)?;
        init_pebs_entry_msr_indexes(pebs_entry_msr_load_page.virtual_address().as_u64());

        // Allocate XSAVE area pages (4KB each)
        let guest_xsave_page = machine
            .kernel()
            .alloc_zeroed_page()
            .ok_or(VmStateError::XsavePageAlloc)?;
        let host_xsave_page = machine
            .kernel()
            .alloc_zeroed_page()
            .ok_or(VmStateError::XsavePageAlloc)?;

        // Copy guest XSAVE state from parent
        let parent_xsave_ptr =
            parent_state.guest_xsave_page.virtual_address().as_u64() as *const u8;
        let guest_xsave_ptr = guest_xsave_page.virtual_address().as_u64() as *mut u8;
        // SAFETY: Both pointers refer to valid PAGE_SIZE allocations and do not overlap.
        unsafe {
            core::ptr::copy_nonoverlapping(parent_xsave_ptr, guest_xsave_ptr, PAGE_SIZE);
        }

        // VPID allocated for the forked VM (0 in cargo/test mode, real VPID in kernel mode)
        #[allow(unused_mut)] // mut needed in kernel mode but not cargo mode
        let mut allocated_vpid: u16 = 0;

        // In kernel mode, use direct memcpy of VMCS region for efficiency.
        // In cargo/test mode, skip VMCS copy since mock VMCSes use HashMaps.
        #[cfg(not(feature = "cargo"))]
        {
            // VMCLEAR parent to flush VMCS data to memory.
            // Intel SDM Vol 3C: VMCLEAR copies VMCS data from processor to memory
            // and sets launch state to "clear".
            parent_state
                .vmcs
                .clear()
                .map_err(|_| VmStateError::GuestStateCopy)?;

            // Note: We don't reset parent's vmx_ctx.launched here because:
            // 1. The parent shouldn't be run again while forked VMs are active
            // 2. If it is run, the caller is responsible for proper state management

            // Copy entire VMCS region from parent to child.
            // The VMCS data format is implementation-specific; the copy relies
            // on the parent and child VMCS regions having the same revision ID
            // and implementation format.
            // SAFETY: Both VMCS region pointers are valid PAGE_SIZE allocations.
            // Parent VMCS was cleared (flushed to memory) above, so the copy is coherent.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    parent_state.vmcs.vmcs_region_ptr(),
                    vmcs.vmcs_region_ptr(),
                    PAGE_SIZE,
                );
            }

            // Load child VMCS to update fields that must differ.
            // VMPTRLD validates revision ID but doesn't re-initialize data.
            vmcs.load().map_err(|_| VmStateError::GuestStateCopy)?;

            // Update fields that must differ or be reset for the child VM:
            // - EPT pointer: child has its own EPT for copy-on-write
            // - MSR bitmap address: child has its own MSR bitmap page
            // - Preemption timer: reset so parent's partially-counted value isn't inherited
            vmcs.write64(VmcsField64::EptPointer, ept.eptp())
                .map_err(|_| VmStateError::GuestStateCopy)?;
            vmcs.write64(
                VmcsField64::MsrBitmapAddr,
                msr_bitmap.physical_address().as_u64(),
            )
            .map_err(|_| VmStateError::GuestStateCopy)?;
            // Reset preemption timer so the child doesn't inherit a partially
            // counted-down value from the parent.
            vmcs.write32(VmcsField32::VmxPreemptionTimerValue, 0x100000)
                .map_err(|_| VmStateError::GuestStateCopy)?;

            // Repoint the VM-exit MSR-load list at the child's own page when
            // the parent had PEBS registered. `register_pebs_page` writes the
            // exit-load address once at registration time and never again, so
            // a memcpy of the parent VMCS leaves the child's exit-load
            // pointer dangling at parent memory. The page is dormant unless
            // count > 0, but the dangle is fragile — the parent could free
            // the page at teardown while the child still references it. The
            // entry-load fields are rewritten per-iteration in `prepare_vm_run`
            // and `pebs_pre/post_vm_*`, so they self-correct on first run; only
            // the exit-load fields need explicit repointing here.
            if parent_state.pebs_state.is_some() {
                vmcs.write64(
                    VmcsField64::VmExitMsrLoadAddr,
                    pebs_exit_msr_load_page.physical_address().as_u64(),
                )
                .map_err(|_| VmStateError::GuestStateCopy)?;
                vmcs.write32(VmcsField32::VmExitMsrLoadCount, 1)
                    .map_err(|_| VmStateError::GuestStateCopy)?;
            }

            // Allocate a new VPID for the forked VM.
            // The copied VMCS inherits the parent's VPID, which would cause TLB
            // sharing between parent and child. With VPID enabled, TLB entries are
            // tagged with VPID, so sharing would cause the forked VM to see stale
            // translations from the parent's execution.
            let current_exec2 = vmcs
                .read32(VmcsField32::SecondaryProcBasedVmExecControls)
                .unwrap_or(0);
            allocated_vpid = if current_exec2 & secondary_exec::ENABLE_VPID != 0 {
                let vpid = allocate_vpid();
                vmcs.write16(VmcsField16::VirtualProcessorId, vpid)
                    .map_err(|_| VmStateError::GuestStateCopy)?;

                // Flush all TLB entries for this VPID to ensure no stale entries
                // from any previous use of this VPID (e.g., if VPIDs wrap around).
                let _ = <V::M as Machine>::V::invvpid_single_context(vpid);

                log_info!("Forked VM allocated VPID={}\n", vpid);
                vpid
            } else {
                0
            };

            // Invalidate EPT TLB entries for the child's EPT context.
            // This ensures the forked VM doesn't see stale translations from
            // the parent. Without this, cached parent translations can let the
            // child read parent pages or miss expected CoW/write-protection
            // exits until an EPT violation happens to invalidate the entry.
            // We use single-context INVEPT (type 1) with the child's EPTP to
            // only invalidate this VM's entries without affecting other VMs.
            <V::M as Machine>::V::invept_single_context(ept.eptp())
                .map_err(|_| VmStateError::InveptFailed)?;

            // VMCLEAR child to set launch state to "clear" for VMLAUNCH.
            // Without this, VM entry would fail because the copied VMCS
            // has launch state "launched" from the parent.
            vmcs.clear().map_err(|_| VmStateError::GuestStateCopy)?;
        }

        log_info!(
            "Forked VM created parent_tsc={} (offset={}, instrs={})\n",
            parent_state.emulated_tsc,
            parent_state.tsc_offset,
            parent_state.last_instruction_count,
        );

        Ok(Self {
            vmcs,
            vmx_ctx: VmxContext::new(),
            gprs: parent_state.gprs, // Copy GPRs from parent
            ept,
            msr_bitmap,
            pebs_exit_msr_load_page,
            pebs_entry_msr_load_page,
            serial_line_buf: box_serial_line_buf(),
            serial_line_len: 0,
            serial_line_tsc: 0,
            serial_line_real_tsc: 0,
            guest_xsave_page,
            host_xsave_page,
            xcr0_mask: parent_state.xcr0_mask,
            last_exit_qualification: 0,
            last_guest_physical_addr: 0,
            devices: heap_box((*parent_state.devices).clone()),
            host_state: parent_state.host_state.clone(), // Copy host state from parent
            msr_state: parent_state.msr_state,           // Copy MSR state
            kernel_gs_base: parent_state.kernel_gs_base,
            instruction_counter,
            last_instruction_count: 0, // Child's counter starts from 0
            emulated_tsc: parent_state.emulated_tsc,
            tsc_offset: parent_state.emulated_tsc,
            tsc_frequency: parent_state.tsc_frequency,
            exit_trigger: ExitTrigger::Disabled, // Forked VMs start with logging disabled
            exit_target_tsc: 0,
            exit_start_tsc: 0,
            exit_captured: false,
            event_buffer_ptr: None,
            event_len: 0,
            event_seq: 0,
            event_categories: EventCategories::empty(),
            event_pending: None,
            event_pending_buf: box_io_page_buf(),
            event_pending_len: 0,
            event_pending_flags: 0,
            event_pending_tsc: 0,
            event_pending_real_tsc: 0,
            pending_exit_loc: None,
            skip_memory_hash: false,
            single_step_tsc_range: None,
            mtf_enabled: false,
            stop_at_tsc: None,
            exit_stats: heap_box(AllExitStats::default()), // Forked VMs start with fresh stats
            last_checkpoint_idx: 0, // Forked VMs start checkpoint tracking fresh
            last_exit_deterministic: true,
            last_pebs_skid: 0,
            last_pebs_inst_delta: 0,
            last_pebs_tsc_offset_delta: 0,
            last_pebs_iters_since_arm: 0,
            last_pebs_arm_delta: 0,
            feedback_buffers: feedback_buffers_from(&parent_state.feedback_buffers), // Deep-copy parent's feedback buffers
            vpid: allocated_vpid,
            intercept_pf: false,
            // Inherit PEBS registration from the parent — the forked guest is
            // at the parent's snapshot point and will never re-issue
            // `HYPERCALL_REGISTER_PEBS_PAGE`, so without this the child runs
            // forever with `pebs_state = None`, `pebs_pre_vm_entry` never
            // fires, and every timer falls through to the late-inject path.
            // `clone_for_fork` copies the registration constants and resets
            // all runtime fields so the child arms freshly. The PEBS scratch
            // page itself is shared with the parent through the EPT clone
            // (which preserves the parent's R+E leaf for the registered GPA).
            pebs_state: parent_state
                .pebs_state
                .as_deref()
                .map(|p| heap_box(p.clone_for_fork())),
            pebs_supported: parent_state.pebs_supported,
            io_channel: IoChannelState::clone_for_fork(&parent_state.io_channel),
            serial_console: SerialConsoleState::clone_for_fork(&parent_state.serial_console),
            last_cpu: None,
        })
    }
}

#[cfg(test)]
#[path = "vm_state_event_tests.rs"]
mod event_producer_tests;
