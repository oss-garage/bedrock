// SPDX-License-Identifier: GPL-2.0

//! VMCALL exit handler for hypercall dispatch.

use super::ept::{translate_gva_range_to_gpas, translate_gva_to_gpa};
use super::helpers::{advance_rip, ExitHandlerResult};
use super::pebs::register_pebs_page;
use super::reasons::ExitReason;

#[cfg(not(feature = "cargo"))]
use super::super::prelude::*;
#[cfg(feature = "cargo")]
use crate::prelude::*;

/// Maximum feedback buffer size (1 MB = 256 pages).
const MAX_FEEDBACK_BUFFER_SIZE: u64 = FEEDBACK_BUFFER_MAX_PAGES as u64 * 4096;

/// Distinct RAX error codes for `HYPERCALL_REGISTER_FEEDBACK_BUFFER`, so guest
/// callers can tell *why* a registration was rejected instead of seeing one
/// opaque sentinel. Mirrored in `guest/libvmcall.h` as `VMCALL_FB_ERR_*`.
///
/// Success returns the assigned slot index (the buffer's position in the
/// unbounded feedback-buffer vector), which can't collide with these: a
/// realistic slot count is tiny next to `u64::MAX`. The
/// `_NOT_RESIDENT` codes mean the guest passed a pointer whose page isn't
/// faulted in — the hypervisor translates by walking the guest page tables and
/// can't fault a page in on the guest's behalf, so the caller must touch (and,
/// for the buffer, pin) the memory first.
pub const FB_ERR_BAD_SIZE: u64 = u64::MAX; // size 0 or > MAX_FEEDBACK_BUFFER_SIZE
pub const FB_ERR_BAD_ID_LEN: u64 = u64::MAX - 1; // id length 0 or > max
pub const FB_ERR_ID_NOT_RESIDENT: u64 = u64::MAX - 2; // id page not present
pub const FB_ERR_BUFFER_NOT_RESIDENT: u64 = u64::MAX - 3; // buffer page(s) not present
pub const FB_ERR_NO_SLOTS: u64 = u64::MAX - 4; // failed to allocate a new slot (ENOMEM)

/// Chunk size used to stage I/O channel bytes through a small stack buffer
/// when crossing the VmState ↔ guest-memory borrow boundary.
///
/// `read_guest_memory` borrows the `VmContext` immutably and
/// `write_guest_memory` borrows it mutably, so we can't hand out a `&[u8]`
/// directly out of `VmState.io_channel.{request,response}_buf` to either
/// call — the read-then-write would overlap the borrow. A page-sized stack
/// staging buffer (4KB) would also exceed the kernel's 8KB stack budget
/// once combined with the rest of the VMCALL frame, so we chunk: 256 bytes
/// is small enough to keep the stack frame quiet while still amortising the
/// per-call overhead of the guest memory accessors.
const IO_COPY_CHUNK: usize = 256;

/// Copy a slice from `VmState.io_channel.request_buf` into guest memory at
/// the given GPA. Chunks through `IO_COPY_CHUNK` to keep the stack frame
/// small and to break the (&VmState, &mut VmState) borrow conflict between
/// reading the source slice and calling `write_guest_memory`.
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

/// Read up to `len` bytes from guest memory at `gva` into `dst`. Walks the
/// range one page at a time so the read may straddle a page boundary.
/// `len` must be `<= dst.len()`.
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

/// Copy `len` bytes out of the registered serial-console page (at `gpa`) into
/// `VmState.serial_console.pending_buf`, from where the caller emits them as one
/// `Serial` event (`event_emit_console`). Chunked through a small stack buffer
/// for the same borrow/stack reasons as `copy_response_from_guest`. `len` must
/// be `<= SERIAL_CONSOLE_PAGE_SIZE`, which is the capacity of `pending_buf`.
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

/// Handle VMCALL exit by dispatching based on hypercall number in RAX.
pub fn handle_vmcall<C: VmContext, A: CowAllocator<C::CowPage>>(
    ctx: &mut C,
    allocator: &mut A,
) -> ExitHandlerResult {
    let hypercall_nr = ctx.state().gprs.rax;

    match hypercall_nr {
        HYPERCALL_SHUTDOWN => {
            // Log shutdown state if AtShutdown mode is enabled
            ctx.state_mut().capture_exit_at_shutdown();
            // Event stream: flush any final non-newline-terminated early-boot
            // line so it is not lost at shutdown (rare — the kernel
            // newline-terminates records). No-op if the accumulator is empty.
            let _ = ctx.state_mut().event_flush_serial_line();

            if let Err(e) = advance_rip(ctx) {
                return ExitHandlerResult::Error(e);
            }
            ExitHandlerResult::ExitToUserspace(ExitReason::VmcallShutdown)
        }
        HYPERCALL_SNAPSHOT => {
            // Log snapshot state (if logging is enabled)
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
            // Return (RAX):
            //   on success — slot index that was assigned (its position in the buffer list)
            //   on failure — u64::MAX
            //
            // IDs are not required to be unique: two registrations with the
            // same id represent two instances of the same domain (typically
            // two processes running the same binary) and are merged by the
            // host at read time. A fresh slot is allocated for each call.
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

            // Read the identifier bytes out of guest memory. May straddle a
            // page boundary; the loop walks one page at a time.
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

            // Registration is append-only and the buffer count is unbounded:
            // build the entry and push it onto the heap-growable vector. Its
            // assigned slot index is simply its position in the vector.
            // Duplicate ids are intentionally allowed.
            //
            // Only the buffer's GPAs are recorded here. For a forked VM the
            // pages are copied-on-write lazily through the normal EPT
            // write-fault path when the guest writes them; no copy is made at
            // registration.
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
            // Exit to userspace so it can sync any per-VM bookkeeping (e.g.,
            // record that precise exits are now usable for this VM).
            ExitHandlerResult::ExitToUserspace(ExitReason::VmcallPebsPage)
        }
        HYPERCALL_FILE_FETCH => {
            // The guest has framed a file-fetch request (offset + name) into
            // the start of the registered `bedrock-file-xfer` feedback buffer
            // and wants the next chunk. The hypervisor owns none of this: the
            // host driver reads the request out of the (host-mapped) buffer,
            // reads the file chunk, and overwrites the buffer with the response
            // before the next RUN. We only advance RIP and exit to userspace.
            // RAX is set to 0; the meaningful result (chunk length / EOF / error)
            // is delivered in the buffer's response header, not in a register.
            ctx.state_mut().gprs.rax = 0;
            if let Err(e) = advance_rip(ctx) {
                return ExitHandlerResult::Error(e);
            }
            ExitHandlerResult::ExitToUserspace(ExitReason::VmcallFileFetch)
        }
        HYPERCALL_IO_REGISTER_PAGE => {
            // RBX = guest virtual address of the shared 4KB page.
            // Must be 4KB-aligned; the GPA is what we record because the
            // guest's view of its own virtual address can drift across CR3
            // changes but the underlying GPA is stable (the module pins the
            // page in the kernel's direct map, which never migrates).
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
                        // The pending FIFO and the in-flight slot belong to
                        // the host's queue, not to a particular module
                        // instance — leave `request_len` /
                        // `request_target_tsc` / `pending` alone so a request
                        // queued before the guest first loaded the module
                        // (e.g. an `--io-action` on the CLI of a cold root
                        // VM) survives registration. We *do* reset
                        // `request_delivered` and `response_len`: if a
                        // previous module instance took the IRQ but didn't
                        // finish GET_REQUEST/PUT_RESPONSE, the new instance
                        // needs the IRQ re-fired and any stale response
                        // bytes dropped.
                        ctx.state_mut().io_channel.request_delivered = false;
                        ctx.state_mut().io_channel.response_len = 0;
                        // Pre-CoW the page so subsequent GET_REQUEST writes
                        // succeed when running under a forked VM. No-op for
                        // root VMs.
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
            // Userspace is notified that the channel is now live (so e.g.
            // queued I/O actions can start flowing) but doesn't need to do
            // anything synchronous — the exit reason is mapped to
            // `ExitKind::Continue` in the userspace dispatcher.
            ExitHandlerResult::ExitToUserspace(ExitReason::VmcallIoRegisterPage)
        }
        HYPERCALL_IO_GET_REQUEST => {
            // Guest's workqueue has woken up after the I/O channel IRQ and
            // is asking for the request bytes. Copy from VmState into the
            // registered shared page; return the byte count in RAX. 0 means
            // "spurious IRQ / no request pending" (the guest module should
            // treat that as a no-op). !0 means "no page registered yet" or
            // "guest memory access failed".
            //
            // After a successful copy, the in-flight slot is consumed:
            // request_len drops to 0, the slot's freshly free, and we
            // promote the next pending request from the queue so the
            // hypervisor can fire the next IRQ on the very next
            // `inject_pending_interrupt` (no waiting for the guest worker
            // to finish and call `HYPERCALL_IO_PUT_RESPONSE`). This is
            // what lets multiple long-running guest commands overlap.
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
            // RBX = response length in bytes (clamped to IO_CHANNEL_BUF_SIZE).
            // The in-flight slot was already consumed by GET_REQUEST and the
            // next pending request may already be promoted by the time a
            // worker calls PUT_RESPONSE — so this handler is purely about
            // capturing the response bytes and exiting to userspace.
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
            // Record the response delivery on the event stream: the metadata
            // followed by the actual response bytes (just copied into
            // `io_channel.response_buf`). Those bytes are host-derived, so the
            // record clears the deterministic flag (handled in
            // `event_emit_io_channel`). `status`/`exit_code` are 0 — the
            // hypervisor treats the response as opaque bytes — and `target_tsc`
            // is 0 on a response. The event buffer is drained by userspace on
            // this VmcallIoResponse exit; a pending record (if the buffer filled)
            // re-appends on the next RUN.
            if result == 0 {
                let payload = IoChannelPayload {
                    phase: IoChannelPhase::Response as u8,
                    _pad: [0; 7],
                    target_tsc: 0,
                };
                let _ = ctx.state_mut().event_emit_io_channel(&payload);
            }
            // Userspace drains the response via ioctl on this exit.
            ExitHandlerResult::ExitToUserspace(ExitReason::VmcallIoResponse)
        }
        HYPERCALL_SERIAL_REGISTER_PAGE => {
            // RBX = guest virtual address of the shared 4KB console page.
            // Mirror HYPERCALL_IO_REGISTER_PAGE: require 4KB alignment and
            // record the GPA (stable across guest CR3 changes — the module
            // pins the page in the kernel direct map). The host only ever
            // *reads* this page (in HYPERCALL_SERIAL_WRITE), so unlike the
            // I/O channel there is no host write that would need pre-CoW.
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
            // Purely host-internal registration — nothing for userspace to do.
            ExitHandlerResult::Continue
        }
        HYPERCALL_SERIAL_WRITE => {
            // RBX = number of bytes at the start of the registered console page
            // to emit (clamped to PAGE_SIZE). Copy them into the host pending
            // buffer and emit them as one `Serial` event. RIP is advanced
            // exactly once so the VMCALL is counted a single time (no
            // non-deterministic double-counting on resume).
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
                // Emit this console record as one Serial event. First flush any
                // residual early-boot line accumulator (cheap insurance — empty
                // by construction at a clean handover) so a partial byte-path
                // line never merges with a hypercall line. A full event buffer
                // is handled centrally by the dispatcher (`event_buffer_full` ->
                // drain), so the returns are ignored.
                let _ = ctx.state_mut().event_flush_serial_line();
                let _ = ctx.state_mut().event_emit_console(len);
            }
            ExitHandlerResult::Continue
        }
        _ => {
            // Unknown hypercall - exit to userspace with generic Vmcall reason
            ExitHandlerResult::ExitToUserspace(ExitReason::Vmcall)
        }
    }
}
