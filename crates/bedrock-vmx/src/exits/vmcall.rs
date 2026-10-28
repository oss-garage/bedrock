// SPDX-License-Identifier: GPL-2.0

//! VMCALL exit handler for hypercall dispatch.

use super::ept::{translate_gva_range_to_gpas, translate_gva_to_gpa};
use super::helpers::{advance_rip, emit_randomness_event, ExitHandlerResult};
use super::pebs::register_pebs_page;
use super::reasons::ExitReason;

#[cfg(not(feature = "cargo"))]
use super::super::prelude::*;
#[cfg(feature = "cargo")]
use crate::prelude::*;

/// Maximum feedback buffer size (1 MB = 256 pages).
const MAX_FEEDBACK_BUFFER_SIZE: u64 = FEEDBACK_BUFFER_MAX_PAGES as u64 * 4096;

/// RAX error codes for `HYPERCALL_REGISTER_FEEDBACK_BUFFER`, mirrored in
/// `guest/libvmcall.h` as `VMCALL_FB_ERR_*`. Success returns the slot index,
/// which can't realistically collide with these.
///
/// `_NOT_RESIDENT` means the page isn't faulted in: the hypervisor walks guest
/// page tables and can't fault pages in, so the caller must touch (and, for
/// the buffer, pin) the memory first.
pub const FB_ERR_BAD_SIZE: u64 = u64::MAX; // size 0 or > MAX_FEEDBACK_BUFFER_SIZE
pub const FB_ERR_BAD_ID_LEN: u64 = u64::MAX - 1; // id length 0 or > max
pub const FB_ERR_ID_NOT_RESIDENT: u64 = u64::MAX - 2; // id page not present
pub const FB_ERR_BUFFER_NOT_RESIDENT: u64 = u64::MAX - 3; // buffer page(s) not present
pub const FB_ERR_NO_SLOTS: u64 = u64::MAX - 4; // failed to allocate a new slot (ENOMEM)

/// Chunk size for staging I/O channel bytes through a stack buffer.
///
/// A slice of `VmState.io_channel` can't be passed to the guest memory
/// accessors directly (the borrows overlap), and a 4KB staging buffer would
/// blow the 8KB kernel stack budget, so copies go through 256-byte chunks.
const IO_COPY_CHUNK: usize = 256;

/// Copy `VmState.io_channel.request_buf` into guest memory at `gpa`, chunked
/// through `IO_COPY_CHUNK`.
fn copy_request_to_guest<C: VmContext>(
    ctx: &mut C,
    gpa: GuestPhysAddr,
    len: usize,
) -> Result<(), MemoryError> {
    let mut chunk = [0u8; IO_COPY_CHUNK];
    let mut offset = 0;
    while offset < len {
        let n = (len - offset).min(IO_COPY_CHUNK);
        chunk[..n].copy_from_slice(&ctx.state().io_channel.request_buf[offset..offset + n]);
        let dst = GuestPhysAddr::new(gpa.as_u64() + offset as u64);
        ctx.write_guest_memory(dst, &chunk[..n])?;
        offset += n;
    }
    Ok(())
}

/// Read `len` bytes (`<= dst.len()`) from guest memory at `gva` into `dst`,
/// page by page so the read may straddle a page boundary.
fn read_guest_id<C: VmContext>(ctx: &C, gva: u64, len: usize, dst: &mut [u8]) -> Result<(), ()> {
    debug_assert!(len <= dst.len());
    let mut offset = 0usize;
    while offset < len {
        let cur_gva = gva.wrapping_add(offset as u64);
        let page_off = (cur_gva & 0xFFF) as usize;
        let in_page = (4096 - page_off).min(len - offset);
        let gpa = translate_gva_to_gpa(ctx, cur_gva)?;
        ctx.read_guest_memory(gpa, &mut dst[offset..offset + in_page])
            .map_err(|_| ())?;
        offset += in_page;
    }
    Ok(())
}

/// Copy a slice out of guest memory into `VmState.io_channel.response_buf`.
/// Chunked for the same reason as `copy_request_to_guest`.
fn copy_response_from_guest<C: VmContext>(
    ctx: &mut C,
    gpa: GuestPhysAddr,
    len: usize,
) -> Result<(), MemoryError> {
    let mut chunk = [0u8; IO_COPY_CHUNK];
    let mut offset = 0;
    while offset < len {
        let n = (len - offset).min(IO_COPY_CHUNK);
        let src = GuestPhysAddr::new(gpa.as_u64() + offset as u64);
        ctx.read_guest_memory(src, &mut chunk[..n])?;
        ctx.state_mut().io_channel.response_buf[offset..offset + n].copy_from_slice(&chunk[..n]);
        offset += n;
    }
    Ok(())
}

/// Copy `len` (`<= SERIAL_CONSOLE_PAGE_SIZE`) bytes from the serial-console
/// page at `gpa` into `VmState.serial_console.pending_buf`. Chunked like
/// `copy_request_to_guest`.
fn copy_serial_console_from_guest<C: VmContext>(
    ctx: &mut C,
    gpa: GuestPhysAddr,
    len: usize,
) -> Result<(), MemoryError> {
    let mut chunk = [0u8; IO_COPY_CHUNK];
    let mut offset = 0;
    while offset < len {
        let n = (len - offset).min(IO_COPY_CHUNK);
        let src = GuestPhysAddr::new(gpa.as_u64() + offset as u64);
        ctx.read_guest_memory(src, &mut chunk[..n])?;
        ctx.state_mut().serial_console.pending_buf[offset..offset + n].copy_from_slice(&chunk[..n]);
        offset += n;
    }
    Ok(())
}

/// Outcome of a failed guest-memory write from a hypercall handler.
enum WriteGuest {
    /// COW page allocation failed; surface `PoolExhausted` and retry the VMCALL.
    Pool,
    /// GVA translation or the write itself failed.
    Fault,
}

/// COW every page in `[gva, gva+len)` on a forked VM so hypervisor-side writes
/// land in the fork's copy; such writes raise no EPT violation, so lazy COW
/// never fires. Done before any bytes are produced so a pool-exhaustion retry
/// never double-advances a PRNG or re-consumes input. No-op for root VMs.
fn ensure_guest_writable<C: VmContext, A: CowAllocator<C::CowPage>>(
    ctx: &mut C,
    allocator: &mut A,
    gva: u64,
    len: usize,
) -> Result<(), WriteGuest> {
    if !ctx.is_forked() {
        return Ok(());
    }
    let mut offset = 0usize;
    while offset < len {
        let cur_gva = gva.wrapping_add(offset as u64);
        let page_off = (cur_gva & 0xFFF) as usize;
        let in_page = (4096 - page_off).min(len - offset);
        let gpa = translate_gva_to_gpa(ctx, cur_gva).map_err(|()| WriteGuest::Fault)?;
        if ctx.handle_cow_fault(gpa, allocator).is_none() {
            return Err(WriteGuest::Pool);
        }
        offset += in_page;
    }
    Ok(())
}

/// Write `src` to guest memory at `gva`, page by page. The pages must already
/// be writable (see [`ensure_guest_writable`]).
fn write_guest_bytes<C: VmContext>(ctx: &mut C, gva: u64, src: &[u8]) -> Result<(), WriteGuest> {
    let mut offset = 0usize;
    while offset < src.len() {
        let cur_gva = gva.wrapping_add(offset as u64);
        let page_off = (cur_gva & 0xFFF) as usize;
        let in_page = (4096 - page_off).min(src.len() - offset);
        let gpa = translate_gva_to_gpa(ctx, cur_gva).map_err(|()| WriteGuest::Fault)?;
        ctx.write_guest_memory(gpa, &src[offset..offset + in_page])
            .map_err(|_| WriteGuest::Fault)?;
        offset += in_page;
    }
    Ok(())
}

/// Record a served `HYPERCALL_GET_RANDOM` on the randomness event stream
/// (`source = GetRandom`, requesting PID, then the bytes handed to the guest).
fn emit_get_random_event<C: VmContext>(ctx: &mut C, pid: u32, bytes: &[u8]) {
    let payload = RandomPayload {
        pid,
        source: RandomSource::GetRandom as u8,
        ..RandomPayload::default()
    };
    emit_randomness_event(ctx, &payload, bytes);
}

/// Handle VMCALL exit by dispatching based on hypercall number in RAX.
pub fn handle_vmcall<C: VmContext, A: CowAllocator<C::CowPage>>(
    ctx: &mut C,
    allocator: &mut A,
) -> ExitHandlerResult {
    let hypercall_nr = ctx.state().gprs.rax;

    match hypercall_nr {
        HYPERCALL_SHUTDOWN => {
            ctx.state_mut().capture_exit_at_shutdown();
            // Flush any final unterminated early-boot serial line.
            let _ = ctx.state_mut().event_flush_serial_line();

            if let Err(e) = advance_rip(ctx) {
                return ExitHandlerResult::Error(e);
            }
            ExitHandlerResult::ExitToUserspace(ExitReason::VmcallShutdown)
        }
        HYPERCALL_SNAPSHOT => {
            ctx.state_mut().capture_exit_at_snapshot();

            if let Err(e) = advance_rip(ctx) {
                return ExitHandlerResult::Error(e);
            }
            ExitHandlerResult::ExitToUserspace(ExitReason::VmcallSnapshot)
        }
        HYPERCALL_READY => {
            if let Err(e) = advance_rip(ctx) {
                return ExitHandlerResult::Error(e);
            }
            ExitHandlerResult::ExitToUserspace(ExitReason::VmcallReady)
        }
        HYPERCALL_REGISTER_FEEDBACK_BUFFER => {
            // ABI (registers):
            //   RBX = buffer GVA
            //   RCX = buffer size (bytes)
            //   RDX = id GVA (pointer to identifier bytes in guest memory)
            //   RSI = id length (1..=FEEDBACK_BUFFER_ID_MAX_LEN)
            //
            // Return (RAX): assigned slot index, or an `FB_ERR_*` code.
            //
            // IDs need not be unique: same-id registrations (e.g. two
            // processes of one binary) get separate slots and are merged by
            // the host at read time.
            let gva = ctx.state().gprs.rbx;
            let size = ctx.state().gprs.rcx;
            let id_gva = ctx.state().gprs.rdx;
            let id_len = ctx.state().gprs.rsi as usize;

            if size == 0 || size > MAX_FEEDBACK_BUFFER_SIZE {
                log_err!(
                    "HYPERCALL_REGISTER_FEEDBACK_BUFFER: invalid size {}\n",
                    size
                );
                ctx.state_mut().gprs.rax = FB_ERR_BAD_SIZE;
                if let Err(e) = advance_rip(ctx) {
                    return ExitHandlerResult::Error(e);
                }
                return ExitHandlerResult::Continue;
            }

            if id_len == 0 || id_len > FEEDBACK_BUFFER_ID_MAX_LEN {
                log_err!(
                    "HYPERCALL_REGISTER_FEEDBACK_BUFFER: invalid id length {} (max {})\n",
                    id_len,
                    FEEDBACK_BUFFER_ID_MAX_LEN
                );
                ctx.state_mut().gprs.rax = FB_ERR_BAD_ID_LEN;
                if let Err(e) = advance_rip(ctx) {
                    return ExitHandlerResult::Error(e);
                }
                return ExitHandlerResult::Continue;
            }

            let mut id_bytes = [0u8; FEEDBACK_BUFFER_ID_MAX_LEN];
            if let Err(()) = read_guest_id(ctx, id_gva, id_len, &mut id_bytes) {
                log_err!(
                    "HYPERCALL_REGISTER_FEEDBACK_BUFFER: id GVA translation failed id_gva={:#x} id_len={}\n",
                    id_gva,
                    id_len
                );
                ctx.state_mut().gprs.rax = FB_ERR_ID_NOT_RESIDENT;
                if let Err(e) = advance_rip(ctx) {
                    return ExitHandlerResult::Error(e);
                }
                return ExitHandlerResult::Continue;
            }

            let mut gpas = [0u64; FEEDBACK_BUFFER_MAX_PAGES];
            let num_pages = match translate_gva_range_to_gpas(ctx, gva, size, &mut gpas) {
                Ok(n) => n,
                Err(()) => {
                    log_err!(
                        "HYPERCALL_REGISTER_FEEDBACK_BUFFER: buffer GVA translation failed gva={:#x} size={}\n",
                        gva, size
                    );
                    ctx.state_mut().gprs.rax = FB_ERR_BUFFER_NOT_RESIDENT;
                    if let Err(e) = advance_rip(ctx) {
                        return ExitHandlerResult::Error(e);
                    }
                    return ExitHandlerResult::Continue;
                }
            };

            // Append-only; the slot index is the position in the vector. Only
            // GPAs are recorded: on a fork the pages are COW'd lazily through
            // the normal EPT write-fault path.
            let info = FeedbackBufferInfo {
                gva,
                size,
                num_pages,
                gpas,
                id: id_bytes,
                id_len: id_len as u32,
            };
            let buffer_idx = ctx.state().feedback_buffers.len();
            let pushed = match heap_box_try(info) {
                Ok(boxed) => heap_vec_push(&mut ctx.state_mut().feedback_buffers, boxed).is_ok(),
                Err(_) => false,
            };
            if !pushed {
                log_err!(
                    "HYPERCALL_REGISTER_FEEDBACK_BUFFER: failed to allocate slot {}\n",
                    buffer_idx
                );
                ctx.state_mut().gprs.rax = FB_ERR_NO_SLOTS;
                if let Err(e) = advance_rip(ctx) {
                    return ExitHandlerResult::Error(e);
                }
                return ExitHandlerResult::Continue;
            }

            log_info!(
                "HYPERCALL_REGISTER_FEEDBACK_BUFFER: registered slot={} gva={:#x} size={} pages={} id_len={}\n",
                buffer_idx,
                gva,
                size,
                num_pages,
                id_len
            );

            ctx.state_mut().gprs.rax = buffer_idx as u64;
            if let Err(e) = advance_rip(ctx) {
                return ExitHandlerResult::Error(e);
            }
            ExitHandlerResult::ExitToUserspace(ExitReason::VmcallFeedbackBuffer)
        }
        HYPERCALL_REGISTER_PEBS_PAGE => {
            let page_va = ctx.state().gprs.rbx;
            let result = register_pebs_page(ctx, allocator, page_va);
            ctx.state_mut().gprs.rax = result as u64;
            if let Err(e) = advance_rip(ctx) {
                return ExitHandlerResult::Error(e);
            }
            // Exit so userspace can record that precise exits are now usable.
            ExitHandlerResult::ExitToUserspace(ExitReason::VmcallPebsPage)
        }
        HYPERCALL_FILE_FETCH => {
            // The request (offset + name) and response live in the
            // `bedrock-file-xfer` feedback buffer and are handled entirely by
            // the host driver; the result is in the buffer's response header.
            ctx.state_mut().gprs.rax = 0;
            if let Err(e) = advance_rip(ctx) {
                return ExitHandlerResult::Error(e);
            }
            ExitHandlerResult::ExitToUserspace(ExitReason::VmcallFileFetch)
        }
        HYPERCALL_FILE_STORE => {
            // The chunk (name + data) and the host's reply live in the
            // `bedrock-file-store` feedback buffer.
            ctx.state_mut().gprs.rax = 0;
            if let Err(e) = advance_rip(ctx) {
                return ExitHandlerResult::Error(e);
            }
            ExitHandlerResult::ExitToUserspace(ExitReason::VmcallFileStore)
        }
        HYPERCALL_FUZZ_NEXT_INPUT => {
            // The guest harness wants the next fuzzer testcase. The host
            // driver writes the input into the (host-mapped) `fuzz-input`
            // feedback buffer before the next RUN. We only set RAX to 0,
            // advance RIP and exit to userspace. The result (input length,
            // or -1 for "no more inputs") is delivered in the buffer's
            // response header.
            ctx.state_mut().gprs.rax = 0;
            if let Err(e) = advance_rip(ctx) {
                return ExitHandlerResult::Error(e);
            }
            ExitHandlerResult::ExitToUserspace(ExitReason::VmcallFuzzNextInput)
        }
        HYPERCALL_IO_REGISTER_PAGE => {
            // RBX = 4KB-aligned GVA of the shared page. The GPA is recorded
            // since it is stable across CR3 changes (the module pins the page
            // in the kernel direct map).
            let page_va = ctx.state().gprs.rbx;
            let result: u64 = if page_va & 0xFFF != 0 {
                log_err!(
                    "HYPERCALL_IO_REGISTER_PAGE: page va {:#x} not 4KB aligned\n",
                    page_va
                );
                !0
            } else {
                match translate_gva_to_gpa(ctx, page_va) {
                    Ok(gpa) => {
                        let gpa = gpa.as_u64();
                        ctx.state_mut().io_channel.page_gpa = gpa;
                        // Keep `request_len`/`request_target_tsc`/`pending`
                        // (they belong to the host queue, so requests queued
                        // before the module loaded survive). Reset
                        // `request_delivered`/`response_len` so a previous
                        // module instance's unfinished IRQ is re-fired and
                        // stale response bytes dropped.
                        ctx.state_mut().io_channel.request_delivered = false;
                        ctx.state_mut().io_channel.response_len = 0;
                        // So GET_REQUEST's host-side writes hit the fork's copy.
                        ctx.pre_cow_io_channel_page(allocator);
                        log_info!(
                            "HYPERCALL_IO_REGISTER_PAGE: gva={:#x} gpa={:#x}\n",
                            page_va,
                            gpa
                        );
                        0
                    }
                    Err(()) => {
                        log_err!(
                            "HYPERCALL_IO_REGISTER_PAGE: GVA translation failed gva={:#x}\n",
                            page_va
                        );
                        !0
                    }
                }
            };
            ctx.state_mut().gprs.rax = result;
            if let Err(e) = advance_rip(ctx) {
                return ExitHandlerResult::Error(e);
            }
            // Notifies userspace the channel is live; it maps this to
            // `ExitKind::Continue`.
            ExitHandlerResult::ExitToUserspace(ExitReason::VmcallIoRegisterPage)
        }
        HYPERCALL_IO_GET_REQUEST => {
            // Copy the request into the shared page. RAX = byte count, 0 if
            // no request is pending (spurious IRQ), !0 on no page / fault.
            //
            // A successful copy consumes the in-flight slot and promotes the
            // next pending request, so the next IRQ can fire without waiting
            // for PUT_RESPONSE; this lets long-running guest commands overlap.
            let page_gpa = ctx.state().io_channel.page_gpa;
            let request_len = ctx.state().io_channel.request_len;
            let result: u64 = if page_gpa == 0 {
                log_err!("HYPERCALL_IO_GET_REQUEST: page not registered\n");
                !0
            } else if request_len == 0 {
                0
            } else {
                let gpa = GuestPhysAddr::new(page_gpa);
                match copy_request_to_guest(ctx, gpa, request_len) {
                    Ok(()) => {
                        let chan = &mut ctx.state_mut().io_channel;
                        chan.request_len = 0;
                        chan.request_delivered = false;
                        chan.request_target_tsc = 0;
                        chan.promote_next_pending();
                        request_len as u64
                    }
                    Err(e) => {
                        log_err!(
                            "HYPERCALL_IO_GET_REQUEST: write_guest_memory failed: {:?}\n",
                            e
                        );
                        !0
                    }
                }
            };
            ctx.state_mut().gprs.rax = result;
            if let Err(e) = advance_rip(ctx) {
                return ExitHandlerResult::Error(e);
            }
            ExitHandlerResult::Continue
        }
        HYPERCALL_IO_PUT_RESPONSE => {
            // RBX = response length (clamped to IO_CHANNEL_BUF_SIZE). The slot
            // was already consumed by GET_REQUEST; this only captures bytes.
            let response_len = (ctx.state().gprs.rbx as usize).min(IO_CHANNEL_BUF_SIZE);
            let page_gpa = ctx.state().io_channel.page_gpa;
            let result: u64 = if page_gpa == 0 {
                log_err!("HYPERCALL_IO_PUT_RESPONSE: page not registered\n");
                !0
            } else {
                let gpa = GuestPhysAddr::new(page_gpa);
                match copy_response_from_guest(ctx, gpa, response_len) {
                    Ok(()) => {
                        let chan = &mut ctx.state_mut().io_channel;
                        chan.response_len = response_len;
                        log_info!(
                            "HYPERCALL_IO_PUT_RESPONSE: captured {} bytes\n",
                            response_len
                        );
                        0
                    }
                    Err(e) => {
                        log_err!(
                            "HYPERCALL_IO_PUT_RESPONSE: read_guest_memory failed: {:?}\n",
                            e
                        );
                        !0
                    }
                }
            };
            ctx.state_mut().gprs.rax = result;
            if let Err(e) = advance_rip(ctx) {
                return ExitHandlerResult::Error(e);
            }
            // Record the response on the event stream. The bytes are
            // host-derived, so `event_emit_io_channel` clears the
            // deterministic flag.
            if result == 0 {
                let payload = IoChannelPayload {
                    phase: IoChannelPhase::Response as u8,
                    _pad: [0; 7],
                    target_tsc: 0,
                };
                let _ = ctx.state_mut().event_emit_io_channel(&payload);
            }
            ExitHandlerResult::ExitToUserspace(ExitReason::VmcallIoResponse)
        }
        HYPERCALL_SERIAL_REGISTER_PAGE => {
            // RBX = 4KB-aligned GVA of the console page; GPA recorded as in
            // HYPERCALL_IO_REGISTER_PAGE. The host only reads it, so no pre-CoW.
            let page_va = ctx.state().gprs.rbx;
            let result: u64 = if page_va & 0xFFF != 0 {
                log_err!(
                    "HYPERCALL_SERIAL_REGISTER_PAGE: page va {:#x} not 4KB aligned\n",
                    page_va
                );
                !0
            } else {
                match translate_gva_to_gpa(ctx, page_va) {
                    Ok(gpa) => {
                        let gpa = gpa.as_u64();
                        ctx.state_mut().serial_console.page_gpa = gpa;
                        log_info!(
                            "HYPERCALL_SERIAL_REGISTER_PAGE: gva={:#x} gpa={:#x}\n",
                            page_va,
                            gpa
                        );
                        0
                    }
                    Err(()) => {
                        log_err!(
                            "HYPERCALL_SERIAL_REGISTER_PAGE: GVA translation failed gva={:#x}\n",
                            page_va
                        );
                        !0
                    }
                }
            };
            ctx.state_mut().gprs.rax = result;
            if let Err(e) = advance_rip(ctx) {
                return ExitHandlerResult::Error(e);
            }
            ExitHandlerResult::Continue
        }
        HYPERCALL_SERIAL_WRITE => {
            // RBX = bytes at the start of the console page to emit (clamped),
            // emitted as one `Serial` event.
            let len = (ctx.state().gprs.rbx as usize).min(SERIAL_CONSOLE_PAGE_SIZE);
            let page_gpa = ctx.state().serial_console.page_gpa;
            let result: u64 = if page_gpa == 0 {
                log_err!("HYPERCALL_SERIAL_WRITE: page not registered\n");
                !0
            } else {
                let gpa = GuestPhysAddr::new(page_gpa);
                match copy_serial_console_from_guest(ctx, gpa, len) {
                    Ok(()) => 0,
                    Err(e) => {
                        log_err!(
                            "HYPERCALL_SERIAL_WRITE: read_guest_memory failed: {:?}\n",
                            e
                        );
                        !0
                    }
                }
            };
            ctx.state_mut().gprs.rax = result;
            if let Err(e) = advance_rip(ctx) {
                return ExitHandlerResult::Error(e);
            }
            if result == 0 {
                // Flush any partial early-boot line first so it never merges
                // with this record. A full event buffer is handled by the
                // dispatcher, so the returns are ignored.
                let _ = ctx.state_mut().event_flush_serial_line();
                let _ = ctx.state_mut().event_emit_console(len);
            }
            ExitHandlerResult::Continue
        }
        HYPERCALL_GET_RANDOM => {
            // ABI (registers):
            //   RBX = destination buffer GVA
            //   RCX = bytes requested
            //   RDX = PID (current->tgid) of the requesting process
            // Return (RAX): bytes written, or !0 on failure.
            //
            // Backs the guest's /dev/{u,}random and getrandom(). Uses the
            // RDRAND device's mode: SeededRng fills from the in-VM PRNG;
            // ExitToUserspace exits so the fuzzer can stage reply bytes, then
            // writes them on re-entry.
            let buf_gva = ctx.state().gprs.rbx;
            let req_len = ctx.state().gprs.rcx;
            let pid = ctx.state().gprs.rdx;
            let cap = (req_len as usize).min(RANDOM_REPLY_MAX);

            match ctx.state().devices.random.mode {
                RdrandMode::SeededRng => {
                    // Pre-COW the destination before advancing the PRNG so a
                    // pool-exhaustion retry re-produces identical bytes.
                    match ensure_guest_writable(ctx, allocator, buf_gva, cap) {
                        Ok(()) => {}
                        Err(WriteGuest::Pool) => {
                            return ExitHandlerResult::ExitToUserspace(ExitReason::PoolExhausted);
                        }
                        Err(WriteGuest::Fault) => {
                            ctx.state_mut().gprs.rax = !0u64;
                            if let Err(e) = advance_rip(ctx) {
                                return ExitHandlerResult::Error(e);
                            }
                            return ExitHandlerResult::Continue;
                        }
                    }
                    let mut tmp = [0u8; RANDOM_REPLY_MAX];
                    let mut off = 0;
                    while off < cap {
                        let v = ctx.state_mut().devices.random.next_seeded_u64();
                        let n = (cap - off).min(8);
                        tmp[off..off + n].copy_from_slice(&v.to_le_bytes()[..n]);
                        off += n;
                    }
                    let rax = match write_guest_bytes(ctx, buf_gva, &tmp[..cap]) {
                        Ok(()) => {
                            emit_get_random_event(ctx, pid as u32, &tmp[..cap]);
                            cap as u64
                        }
                        // Pages were just COW'd, so a fault here is unexpected.
                        Err(_) => !0u64,
                    };
                    ctx.state_mut().gprs.rax = rax;
                    if let Err(e) = advance_rip(ctx) {
                        return ExitHandlerResult::Error(e);
                    }
                    ExitHandlerResult::Continue
                }
                RdrandMode::ExitToUserspace => {
                    if ctx.state().devices.random.needs_get_random_exit() {
                        // First entry: don't advance RIP; the VMCALL re-executes
                        // once the reply bytes are staged.
                        ctx.state_mut()
                            .devices
                            .random
                            .begin_request(buf_gva, cap as u32, pid as u32);
                        return ExitHandlerResult::ExitToUserspace(ExitReason::VmcallGetRandom);
                    }
                    // Second entry: userspace staged the reply bytes.
                    let target_gva = ctx.state().devices.random.buf_gva;
                    let n = {
                        let r = &ctx.state().devices.random;
                        (r.reply_len as usize).min(r.req_len as usize)
                    };
                    match ensure_guest_writable(ctx, allocator, target_gva, n) {
                        Ok(()) => {}
                        Err(WriteGuest::Pool) => {
                            // Keep the staged reply and the in-flight request so
                            // the retried VMCALL completes the same write.
                            return ExitHandlerResult::ExitToUserspace(ExitReason::PoolExhausted);
                        }
                        Err(WriteGuest::Fault) => {
                            ctx.state_mut().devices.random.clear_request();
                            ctx.state_mut().gprs.rax = !0u64;
                            if let Err(e) = advance_rip(ctx) {
                                return ExitHandlerResult::Error(e);
                            }
                            return ExitHandlerResult::Continue;
                        }
                    }
                    let mut tmp = [0u8; RANDOM_REPLY_MAX];
                    let req_pid = ctx.state().devices.random.pid;
                    tmp[..n].copy_from_slice(&ctx.state().devices.random.reply[..n]);
                    let rax = match write_guest_bytes(ctx, target_gva, &tmp[..n]) {
                        Ok(()) => {
                            emit_get_random_event(ctx, req_pid, &tmp[..n]);
                            n as u64
                        }
                        Err(_) => !0u64,
                    };
                    ctx.state_mut().devices.random.clear_request();
                    ctx.state_mut().gprs.rax = rax;
                    if let Err(e) = advance_rip(ctx) {
                        return ExitHandlerResult::Error(e);
                    }
                    ExitHandlerResult::Continue
                }
            }
        }
        _ => ExitHandlerResult::ExitToUserspace(ExitReason::Vmcall),
    }
}
