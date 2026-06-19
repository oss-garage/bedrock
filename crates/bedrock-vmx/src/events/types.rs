// SPDX-License-Identifier: GPL-2.0

//! Wire format for the unified event stream.
//!
//! The event buffer is fundamentally an append-only `[u8]` with a write cursor
//! (`event_len`). The `repr(C)` types here are typed *lenses* over those bytes,
//! not a separate encoded representation — the struct layout **is** the byte
//! layout, so there is no serialize/decode step on the producer side.
//!
//! Each record is a TLV (type-length-value): a fixed [`EventHeader`] immediately
//! followed by `header.len` payload bytes, with the whole record padded up to an
//! 8-byte boundary so the next header is naturally aligned.
//!
//! ```text
//! offset O:            O + 32:                   O + 32 + len, padded to 8:
//! +------------------++------------------------++---------+
//! | EventHeader (32B) || payload = `len` bytes   || pad 0-7 |  <- next record
//! +------------------++------------------------++---------+
//! ```
//!
//! # `repr(C)` discipline
//!
//! `repr(C)` does the right thing **only if implicit padding is eliminated**,
//! because padding bytes are uninitialized — they would leak host memory to
//! userspace and, worse, differ run-to-run, breaking the determinism comparison
//! the feature exists for. The rules (mirroring `ExitRecord`):
//!
//! - Order fields large->small (`u64`s first) so no implicit padding is inserted.
//! - Name every remaining gap as an explicit `_pad: [u8; N]` that is zeroed.
//! - `const _: () = assert!(size_of::<T>() == EXPECTED)` on every payload to catch
//!   accidental padding at compile time.
//! - Pad each *record* to an 8-byte boundary (`align_up(len, 8)`).
//!
//! These types compile under both the kernel-module build and the `cargo` build.
//! The `zerocopy`/`serde` derives are `cfg`-gated to `cargo` so the kernel build
//! (Rust-for-Linux Kbuild, `core`/`alloc`/`kernel` only) never sees a crates.io
//! dependency.

/// Size of the event buffer (1 MB).
pub const EVENT_BUFFER_SIZE: usize = 1024 * 1024;

/// Number of 4 KB pages in the event buffer.
pub const EVENT_BUFFER_PAGES: usize = EVENT_BUFFER_SIZE / 4096;

/// Size of [`EventHeader`] in bytes.
pub const EVENT_HEADER_SIZE: usize = 32;

/// Per-record flag (`EventHeader.flags`): the record participates in run-vs-run
/// determinism comparison. Cleared on host-derived records (`Diagnostic`, and
/// any record carrying host-derived bytes).
pub const EVENT_FLAG_DETERMINISTIC: u16 = 1 << 0;

/// Round `n` up to the next multiple of `align` (which must be a power of two).
#[inline]
pub const fn align_up(n: usize, align: usize) -> usize {
    (n + align - 1) & !(align - 1)
}

/// Fixed prefix on every record. Generic time/order/filter fields live here;
/// everything kind-specific lives in the payload. 32 bytes, no implicit padding.
#[cfg_attr(
    feature = "cargo",
    derive(zerocopy::FromBytes, zerocopy::Immutable, zerocopy::KnownLayout)
)]
#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct EventHeader {
    /// Monotonic sequence number. Deterministic; breaks ties between records
    /// sharing a TSC and lets userspace detect a gap after a drain.
    pub seq: u64,
    /// Emulated TSC at emit time — the stream's primary, DETERMINISTIC time axis
    /// (advances at a fixed frequency from exit counts, not wall-clock time).
    pub tsc: u64,
    /// Host TSC (raw RDTSC) at emit time. NON-deterministic — for wall-clock and
    /// performance correlation only. Excluded from run-vs-run comparison; never
    /// order or key the stream on it. Kept last among the `u64`s so a comparator
    /// can simply ignore the trailing 8 bytes of the fixed header region.
    pub real_tsc: u64,
    /// [`EventKind`] as `u16`.
    pub kind: u16,
    /// Flags (see `EVENT_FLAG_*`).
    pub flags: u16,
    /// Payload length in bytes (excludes this header).
    pub len: u32,
}
const _: () = assert!(core::mem::size_of::<EventHeader>() == EVENT_HEADER_SIZE);

/// The kind of an event record. Stored in [`EventHeader::kind`] as a raw `u16`
/// (so an unknown value read from the buffer never becomes an invalid enum
/// discriminant — the reader matches on the `u16`).
#[repr(u16)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum EventKind {
    /// A full VM-exit snapshot. Payload = the `ExitRecord` body,
    /// sub-typed by `exit_reason`. Heavyweight; usually off except when
    /// debugging.
    Exit = 0,
    /// One guest console line (`HYPERCALL_SERIAL_WRITE`, or one accumulated
    /// early-boot line from `OUT 0x3F8`). Payload = raw bytes.
    Serial = 1,
    /// An interrupt injected into the guest. Payload = [`InjectPayload`]. Timer
    /// now; extensible to other emulated lines (serial THRE IRQ, etc.).
    Inject = 2,
    /// A controlled-randomness value served to the guest. Payload =
    /// [`RandomPayload`] (whose [`RandomSource`] says which channel: RDRAND,
    /// RDSEED, or the `HYPERCALL_GET_RANDOM` `/dev/urandom` / `getrandom()`
    /// chokepoint), optionally followed by the served byte buffer (GET_RANDOM
    /// only; RDRAND/RDSEED carry their value inline in the payload). Its own
    /// category so it can be captured on normal runs without enabling the
    /// firehose `Exit` capture — it is a determinism *input*.
    Randomness = 3,
    /// I/O channel transaction: request signaled + response delivered. Payload =
    /// [`IoChannelPayload`]. Its own category for the same reason as
    /// `Randomness`.
    IoChannel = 4,
    /// Reserved (not yet emitted): structured hypervisor diagnostics. Payload =
    /// `{ level: u8, msg: [u8] }`. Always non-deterministic.
    Diagnostic = 5,
}

impl EventKind {
    /// The category bit this kind belongs to.
    pub const fn category(self) -> EventCategories {
        match self {
            EventKind::Exit => EventCategories::EXIT,
            EventKind::Serial => EventCategories::SERIAL,
            EventKind::Inject => EventCategories::INJECT,
            EventKind::Randomness => EventCategories::RANDOMNESS,
            EventKind::IoChannel => EventCategories::IO_CHANNEL,
            EventKind::Diagnostic => EventCategories::DIAGNOSTIC,
        }
    }

    /// Default header flags for a freshly emitted record.
    pub const fn default_flags(self) -> u16 {
        match self {
            // Host-derived; never compared run-to-run.
            EventKind::Diagnostic => 0,
            _ => EVENT_FLAG_DETERMINISTIC,
        }
    }

    /// This kind as the raw `u16` stored in the header.
    pub const fn as_u16(self) -> u16 {
        self as u16
    }
}

/// Source of an injected interrupt.
#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum InjectSource {
    /// Emulated APIC timer.
    Timer = 0,
    // future: SerialThre = 1, ...
}

/// Payload for an [`EventKind::Inject`] record.
#[cfg_attr(
    feature = "cargo",
    derive(zerocopy::FromBytes, zerocopy::Immutable, zerocopy::KnownLayout)
)]
#[cfg_attr(feature = "cargo", derive(serde::Serialize))]
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct InjectPayload {
    /// Interrupt vector injected.
    pub vector: u8,
    /// [`InjectSource`] as `u8`.
    pub source: u8,
    /// Explicit padding (zeroed) so the struct has no implicit padding.
    #[cfg_attr(feature = "cargo", serde(skip))]
    pub _pad: [u8; 6],
    /// The deterministic TSC this injection was scheduled for (APIC
    /// `timer_deadline`). Pairing it with the header's actual `tsc` exposes
    /// scheduled-vs-delivered drift — the key signal for interrupt-timing
    /// divergence.
    pub target_tsc: u64,
}
const _: () = assert!(core::mem::size_of::<InjectPayload>() == 16);

impl InjectPayload {
    /// View this fixed-size, no-padding `repr(C)` POD as bytes for
    /// `event_append` (works in both builds; no `zerocopy` needed).
    pub fn as_bytes(&self) -> &[u8] {
        // SAFETY: `InjectPayload` is `repr(C)` with no padding (size-asserted).
        unsafe {
            core::slice::from_raw_parts(
                core::ptr::from_ref::<Self>(self).cast::<u8>(),
                core::mem::size_of::<Self>(),
            )
        }
    }
}

/// Which channel a controlled-randomness value was served on. All three are
/// determinism *inputs* recorded on the unified [`EventKind::Randomness`]
/// stream; the source lets a consumer tell them apart without separate event
/// kinds.
#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RandomSource {
    /// RDRAND instruction. Value carried inline in [`RandomPayload::value`].
    Rdrand = 0,
    /// RDSEED instruction. Value carried inline in [`RandomPayload::value`].
    Rdseed = 1,
    /// `HYPERCALL_GET_RANDOM` (the guest `/dev/urandom` / `getrandom()`
    /// chokepoint). The served bytes follow the [`RandomPayload`] header and the
    /// requesting process is in [`RandomPayload::pid`]; `value`/`width` are 0.
    GetRandom = 2,
}

impl RandomSource {
    /// Decode the `source` byte of a [`RandomPayload`]; unknown values fall back
    /// to [`Rdrand`](Self::Rdrand).
    pub fn from_u8(v: u8) -> Self {
        match v {
            x if x == Self::Rdseed as u8 => Self::Rdseed,
            x if x == Self::GetRandom as u8 => Self::GetRandom,
            _ => Self::Rdrand,
        }
    }
}

/// Payload for an [`EventKind::Randomness`] record.
#[cfg_attr(
    feature = "cargo",
    derive(zerocopy::FromBytes, zerocopy::Immutable, zerocopy::KnownLayout)
)]
#[cfg_attr(feature = "cargo", derive(serde::Serialize))]
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct RandomPayload {
    /// Value handed back to the guest for RDRAND/RDSEED. Unused (0) for
    /// `GetRandom`, whose served bytes follow the header instead.
    pub value: u64,
    /// Requesting process (`current->tgid`) for `GetRandom`. 0 for RDRAND/RDSEED
    /// (served at an instruction exit with no process context).
    pub pid: u32,
    /// [`RandomSource`] as `u8`.
    pub source: u8,
    /// Operand width in bytes (2/4/8: RDRAND r16/r32/r64). 0 for `GetRandom`.
    pub width: u8,
    /// Explicit padding (zeroed).
    #[cfg_attr(feature = "cargo", serde(skip))]
    pub _pad: [u8; 2],
}
const _: () = assert!(core::mem::size_of::<RandomPayload>() == 16);

impl RandomPayload {
    /// View this fixed-size, no-padding `repr(C)` POD as bytes for
    /// `event_append`.
    pub fn as_bytes(&self) -> &[u8] {
        // SAFETY: `RandomPayload` is `repr(C)` with no padding (size-asserted).
        unsafe {
            core::slice::from_raw_parts(
                core::ptr::from_ref::<Self>(self).cast::<u8>(),
                core::mem::size_of::<Self>(),
            )
        }
    }
}

/// Phase of an I/O channel transaction.
#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum IoChannelPhase {
    /// Host queued a request; IRQ signaled to the guest.
    Request = 0,
    /// Guest delivered its response (PUT_RESPONSE).
    Response = 1,
}

/// Fixed metadata prefix of an [`EventKind::IoChannel`] record.
///
/// The record's payload is this 16-byte struct followed by the transaction's
/// actual bytes (the request envelope, or the response header) — read the tail
/// as `payload[size_of::<IoChannelPayload>()..]`. The hypervisor treats the
/// channel bytes as opaque, so the per-transaction details (target, command,
/// status, exit code, …) are decoded from the tail by the userspace reader, not
/// carried here.
#[cfg_attr(
    feature = "cargo",
    derive(zerocopy::FromBytes, zerocopy::Immutable, zerocopy::KnownLayout)
)]
#[cfg_attr(feature = "cargo", derive(serde::Serialize))]
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct IoChannelPayload {
    /// [`IoChannelPhase`] as `u8`.
    pub phase: u8,
    /// Explicit padding (zeroed).
    #[cfg_attr(feature = "cargo", serde(skip))]
    pub _pad: [u8; 7],
    /// Request: scheduled `request_target_tsc` (0 on response).
    pub target_tsc: u64,
}
const _: () = assert!(core::mem::size_of::<IoChannelPayload>() == 16);

impl IoChannelPayload {
    /// View this fixed-size, no-padding `repr(C)` POD as bytes for
    /// `event_append`.
    pub fn as_bytes(&self) -> &[u8] {
        // SAFETY: `IoChannelPayload` is `repr(C)` with no padding (size-asserted).
        unsafe {
            core::slice::from_raw_parts(
                core::ptr::from_ref::<Self>(self).cast::<u8>(),
                core::mem::size_of::<Self>(),
            )
        }
    }
}

/// Userspace include/exclude mask (set via ioctl). Filtering happens at emit
/// time, so a disabled category costs a single bit test.
///
/// Hand-rolled following the `EXIT_RECORD_FLAG_*` convention — `bitflags`
/// is a crates.io dependency and unavailable in the kernel build.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, Default, Debug)]
pub struct EventCategories(pub u32);

impl EventCategories {
    /// Exit records.
    pub const EXIT: Self = Self(1 << 0);
    /// Serial records.
    pub const SERIAL: Self = Self(1 << 1);
    /// Injected-interrupt records.
    pub const INJECT: Self = Self(1 << 2);
    /// Controlled-randomness records.
    pub const RANDOMNESS: Self = Self(1 << 3);
    /// I/O channel records.
    pub const IO_CHANNEL: Self = Self(1 << 4);
    /// Diagnostic records.
    pub const DIAGNOSTIC: Self = Self(1 << 5);

    /// No categories enabled.
    pub const fn empty() -> Self {
        Self(0)
    }

    /// True if `self` contains every bit in `other`.
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// The union of two masks.
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

#[cfg(test)]
#[path = "types_tests.rs"]
mod tests;
