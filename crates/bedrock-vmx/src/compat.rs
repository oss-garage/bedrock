// SPDX-License-Identifier: GPL-2.0

//! Platform compatibility layer for allocation.
//!
//! Provides unified type aliases and helpers that abstract over the
//! different allocation APIs between cargo (userspace) and kernel builds.
//! All cfg gates for allocation are isolated here.

/// Error returned when heap allocation fails.
#[derive(Debug, Clone, Copy)]
pub struct AllocError;

#[cfg(feature = "cargo")]
mod cargo_impl {
    extern crate alloc;

    /// Heap-allocated box (standard allocator).
    pub type HeapBox<T> = alloc::boxed::Box<T>;

    /// Heap-allocated box using vmalloc (for large allocations).
    /// In cargo builds, this is the same as HeapBox.
    pub type VmallocBox<T> = alloc::boxed::Box<T>;

    /// Growable vector (standard allocator).
    pub type HeapVec<T> = alloc::vec::Vec<T>;

    /// Box a value on the heap.
    pub fn heap_box<T>(val: T) -> HeapBox<T> {
        alloc::boxed::Box::new(val)
    }

    /// Box a value on the heap, returning `Err(AllocError)` if allocation
    /// fails. In cargo builds the standard allocator aborts on OOM, so the
    /// `Result` is just for API parity with kernel builds.
    pub fn heap_box_try<T>(val: T) -> Result<HeapBox<T>, super::AllocError> {
        Ok(alloc::boxed::Box::new(val))
    }

    /// Box a heap copy of `*src` without ever materializing it on the stack.
    ///
    /// `heap_box_try(*src)` would copy the (potentially large) value into a
    /// stack temporary before moving it into the box; for kilobyte-sized POD
    /// like `FeedbackBufferInfo` that blows the 8KB kernel stack on deep call
    /// chains. This allocates uninitialized and copies heap-to-heap instead.
    pub fn heap_box_copy_from<T: Copy>(src: &T) -> Result<HeapBox<T>, super::AllocError> {
        use core::mem::MaybeUninit;
        let mut boxed: alloc::boxed::Box<MaybeUninit<T>> =
            alloc::boxed::Box::new(MaybeUninit::uninit());
        // SAFETY: `boxed` points to a freshly-allocated, aligned, T-sized slot;
        // `src` is a valid `&T`; the regions don't overlap. After the copy the
        // slot is fully initialized, so the cast to `Box<T>` is sound. `T: Copy`
        // means no `Drop`, so leaving `*src` in place creates no double-free.
        unsafe {
            core::ptr::copy_nonoverlapping(src, boxed.as_mut_ptr(), 1);
            Ok(alloc::boxed::Box::from_raw(
                alloc::boxed::Box::into_raw(boxed) as *mut T,
            ))
        }
    }

    /// Create a vector with pre-allocated capacity.
    pub fn heap_vec_with_capacity<T>(cap: usize) -> Result<HeapVec<T>, super::AllocError> {
        Ok(alloc::vec::Vec::with_capacity(cap))
    }

    /// Push a value onto a vector. Returns `Err(AllocError)` if growth
    /// fails — in cargo builds the standard allocator aborts on OOM, so
    /// the `Result` is just for API parity with kernel builds.
    pub fn heap_vec_push<T>(v: &mut HeapVec<T>, val: T) -> Result<(), super::AllocError> {
        v.push(val);
        Ok(())
    }

    /// Remove and return the front element of a vector, or `None` if
    /// empty. O(n) (shifts the rest down); used for FIFO queues whose
    /// depth is small enough that the shift cost is negligible relative
    /// to the per-element work.
    pub fn heap_vec_remove_front<T>(v: &mut HeapVec<T>) -> Option<T> {
        if v.is_empty() {
            None
        } else {
            Some(v.remove(0))
        }
    }
}

#[cfg(not(feature = "cargo"))]
mod kernel_impl {
    /// Heap-allocated box (kmalloc, GFP_KERNEL).
    pub type HeapBox<T> = kernel::alloc::KBox<T>;

    /// Heap-allocated box using kvmalloc (for large allocations).
    /// kvmalloc falls back to vmalloc when kmalloc fails for large contiguous
    /// allocations.
    pub type VmallocBox<T> = kernel::alloc::KVBox<T>;

    /// Growable vector (kmalloc, GFP_KERNEL).
    pub type HeapVec<T> = kernel::alloc::KVec<T>;

    /// Box a value on the heap.
    pub fn heap_box<T>(val: T) -> HeapBox<T> {
        kernel::alloc::KBox::new(val, kernel::alloc::flags::GFP_KERNEL)
            .expect("Failed to allocate HeapBox")
    }

    /// Box a value on the heap, returning `Err(AllocError)` on allocation
    /// failure instead of panicking. Use this on guest-controlled paths (e.g.
    /// unbounded feedback-buffer registration) where an out-of-memory
    /// condition must be reported to the guest rather than crashing the kernel.
    pub fn heap_box_try<T>(val: T) -> Result<HeapBox<T>, super::AllocError> {
        kernel::alloc::KBox::new(val, kernel::alloc::flags::GFP_KERNEL)
            .map_err(|_| super::AllocError)
    }

    /// Box a heap copy of `*src` without ever materializing it on the stack.
    ///
    /// `heap_box_try(*src)` would copy the (potentially large) value into a
    /// stack temporary before moving it into the box; for kilobyte-sized POD
    /// like `FeedbackBufferInfo` that blows the 8KB kernel stack on deep call
    /// chains. This allocates uninitialized and copies heap-to-heap instead.
    pub fn heap_box_copy_from<T: Copy>(src: &T) -> Result<HeapBox<T>, super::AllocError> {
        let mut boxed: kernel::alloc::KBox<core::mem::MaybeUninit<T>> =
            kernel::alloc::KBox::new_uninit(kernel::alloc::flags::GFP_KERNEL)
                .map_err(|_| super::AllocError)?;
        // SAFETY: `boxed` points to a freshly-allocated, aligned, T-sized slot;
        // `src` is a valid `&T`; the regions don't overlap. After the copy the
        // slot is fully initialized, so `assume_init` is sound. `T: Copy` means
        // no `Drop`, so leaving `*src` in place creates no double-free.
        unsafe {
            core::ptr::copy_nonoverlapping(src, boxed.as_mut_ptr(), 1);
            Ok(boxed.assume_init())
        }
    }

    /// Create a vector with pre-allocated capacity.
    pub fn heap_vec_with_capacity<T>(cap: usize) -> Result<HeapVec<T>, super::AllocError> {
        kernel::alloc::KVec::with_capacity(cap, kernel::alloc::flags::GFP_KERNEL)
            .map_err(|_| super::AllocError)
    }

    /// Push a value onto a vector. Returns `Err(AllocError)` on
    /// allocation failure; callers must propagate ENOMEM rather than
    /// silently dropping the value.
    pub fn heap_vec_push<T>(v: &mut HeapVec<T>, val: T) -> Result<(), super::AllocError> {
        v.push(val, kernel::alloc::flags::GFP_KERNEL)
            .map_err(|_| super::AllocError)
    }

    /// Remove and return the front element of a vector, or `None` if
    /// empty. Kernel `KVec::remove` returns `Result`; we collapse the
    /// `Err` (OOB) and empty cases together into `None`.
    pub fn heap_vec_remove_front<T>(v: &mut HeapVec<T>) -> Option<T> {
        v.remove(0).ok()
    }
}

#[cfg(feature = "cargo")]
pub use cargo_impl::*;
#[cfg(not(feature = "cargo"))]
pub use kernel_impl::*;
