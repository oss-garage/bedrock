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

/// Handle VMCALL exit by dispatching based on hypercall number in RAX.
pub fn handle_vmcall<C: VmContext, A: CowAllocator<C::CowPage>>(
    ctx: &mut C,
    allocator: &mut A,
) -> ExitHandlerResult {
    let hypercall_nr = ctx.state().gprs.rax;

    match hypercall_nr {
        HYPERCALL_SHUTDOWN => {
            // Log shutdown state if AtShutdown mode is enabled
            ctx.state_mut().log_shutdown();

            if let Err(e) = advance_rip(ctx) {
                return ExitHandlerResult::Error(e);
            }
            ExitHandlerResult::ExitToUserspace(ExitReason::VmcallShutdown)
        }
        HYPERCALL_SNAPSHOT => {
            // Log snapshot state (if logging is enabled)
            ctx.state_mut().log_snapshot();

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
            // Read arguments: GVA in RBX, size in RCX, buffer index in RDX
            let gva = ctx.state().gprs.rbx;
            let size = ctx.state().gprs.rcx;
            let buffer_idx = ctx.state().gprs.rdx as usize;

            // Validate buffer index
            if buffer_idx >= MAX_FEEDBACK_BUFFERS {
                log_err!(
                    "HYPERCALL_REGISTER_FEEDBACK_BUFFER: invalid buffer index {} (max {})\n",
                    buffer_idx,
                    MAX_FEEDBACK_BUFFERS - 1
                );
                ctx.state_mut().gprs.rax = !0u64; // Return -1
                if let Err(e) = advance_rip(ctx) {
                    return ExitHandlerResult::Error(e);
                }
                return ExitHandlerResult::Continue;
            }

            // Validate size: must be > 0 and <= 1MB
            if size == 0 || size > MAX_FEEDBACK_BUFFER_SIZE {
                log_err!(
                    "HYPERCALL_REGISTER_FEEDBACK_BUFFER: invalid size {}\n",
                    size
                );
                ctx.state_mut().gprs.rax = !0u64; // Return -1
                if let Err(e) = advance_rip(ctx) {
                    return ExitHandlerResult::Error(e);
                }
                return ExitHandlerResult::Continue;
            }

            // Translate GVA range to GPAs
            let mut gpas = [0u64; FEEDBACK_BUFFER_MAX_PAGES];
            let num_pages = match translate_gva_range_to_gpas(ctx, gva, size, &mut gpas) {
                Ok(n) => n,
                Err(()) => {
                    log_err!(
                        "HYPERCALL_REGISTER_FEEDBACK_BUFFER: GVA translation failed gva={:#x} size={}\n",
                        gva, size
                    );
                    ctx.state_mut().gprs.rax = !0u64; // Return -1
                    if let Err(e) = advance_rip(ctx) {
                        return ExitHandlerResult::Error(e);
                    }
                    return ExitHandlerResult::Continue;
                }
            };

            // Store feedback buffer info in VmState at the specified index
            ctx.state_mut().feedback_buffers[buffer_idx] = Some(FeedbackBufferInfo {
                gva,
                size,
                num_pages,
                gpas,
            });

            // Pre-COW feedback buffer pages for stable userspace mapping.
            // This handles the case where the feedback buffer is registered after fork.
            ctx.pre_cow_feedback_buffer_at(buffer_idx, allocator);

            log_info!(
                "HYPERCALL_REGISTER_FEEDBACK_BUFFER: registered idx={} gva={:#x} size={} pages={}\n",
                buffer_idx,
                gva,
                size,
                num_pages
            );

            ctx.state_mut().gprs.rax = 0; // Return success
            if let Err(e) = advance_rip(ctx) {
                return ExitHandlerResult::Error(e);
            }
            // Exit to userspace so it can map the feedback buffer
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
            // Userspace drains the response via ioctl on this exit.
            ExitHandlerResult::ExitToUserspace(ExitReason::VmcallIoResponse)
        }
        _ => {
            // Unknown hypercall - exit to userspace with generic Vmcall reason
            ExitHandlerResult::ExitToUserspace(ExitReason::Vmcall)
        }
    }
}
