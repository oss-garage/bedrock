// SPDX-License-Identifier: GPL-2.0

//! Producer-side tests for the unified event stream: `event_append` framing,
//! category filtering, and the buffer-full pending / `event_clear` re-append
//! path. The userspace reader (`bedrock_vm::events`) is tested separately;
//! these tests parse the raw bytes by hand to confirm the producer emits
//! spec-compliant TLV records.

extern crate std;

use std::vec;
use std::vec::Vec;

use crate::events::{
    align_up, EventCategories, EventKind, InjectPayload, InjectSource, IoChannelPayload,
    IoChannelPhase, RandomPayload, RandomSource, EVENT_BUFFER_SIZE, EVENT_HEADER_SIZE,
};
use crate::tests::MockVmContext;
use crate::traits::VmContext;

/// A backing buffer kept alive for the duration of a test, attached to the VM.
struct EventBuf {
    buf: Vec<u8>,
}

impl EventBuf {
    fn new() -> Self {
        Self {
            buf: vec![0u8; EVENT_BUFFER_SIZE],
        }
    }

    fn attach(&mut self, ctx: &mut MockVmContext) {
        let ptr = self.buf.as_mut_ptr();
        ctx.state_mut().set_event_buffer(ptr);
    }

    fn bytes(&self, len: usize) -> &[u8] {
        &self.buf[..len]
    }
}

/// `repr(C)` POD -> bytes (test-only).
fn pod_bytes<T: Copy>(v: &T) -> &[u8] {
    // SAFETY: `T` is a `repr(C)` POD with no padding in these tests.
    unsafe { core::slice::from_raw_parts((v as *const T).cast::<u8>(), core::mem::size_of::<T>()) }
}

/// Decode a `u64`/`u32`/`u16` from a little-endian slice at `off`.
fn rd_u64(b: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(b[off..off + 8].try_into().unwrap())
}
fn rd_u32(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(b[off..off + 4].try_into().unwrap())
}
fn rd_u16(b: &[u8], off: usize) -> u16 {
    u16::from_le_bytes(b[off..off + 2].try_into().unwrap())
}

/// A parsed header (mirrors `EventHeader`).
struct Hdr {
    seq: u64,
    tsc: u64,
    real_tsc: u64,
    kind: u16,
    flags: u16,
    len: u32,
}

fn parse_header(b: &[u8], off: usize) -> Hdr {
    Hdr {
        seq: rd_u64(b, off),
        tsc: rd_u64(b, off + 8),
        real_tsc: rd_u64(b, off + 16),
        kind: rd_u16(b, off + 24),
        flags: rd_u16(b, off + 26),
        len: rd_u32(b, off + 28),
    }
}

#[test]
fn append_writes_framed_record() {
    let mut ctx = MockVmContext::new();
    let mut eb = EventBuf::new();
    eb.attach(&mut ctx);
    ctx.state_mut()
        .set_event_categories(EventCategories::SERIAL);
    ctx.set_emulated_tsc(0xABCD);

    assert!(ctx.state_mut().event_append(EventKind::Serial, b"hi\n"));

    let len = ctx.state().event_buffer_len();
    // 32-byte header + 3-byte payload padded to 8 = 40.
    assert_eq!(len, EVENT_HEADER_SIZE + align_up(3, 8));

    let bytes = eb.bytes(len);
    let h = parse_header(bytes, 0);
    assert_eq!(h.seq, 0);
    assert_eq!(h.tsc, 0xABCD);
    assert_eq!(h.kind, EventKind::Serial.as_u16());
    assert_eq!(h.flags, 1); // EVENT_FLAG_DETERMINISTIC
    assert_eq!(h.len, 3);
    assert_eq!(&bytes[EVENT_HEADER_SIZE..EVENT_HEADER_SIZE + 3], b"hi\n");
    // Padding bytes are zeroed.
    assert_eq!(
        &bytes[EVENT_HEADER_SIZE + 3..EVENT_HEADER_SIZE + 8],
        &[0u8; 5]
    );

    // Second append: seq advances, real_tsc/tsc captured fresh.
    ctx.set_emulated_tsc(0x1111);
    assert!(ctx.state_mut().event_append(EventKind::Serial, b"x"));
    let len2 = ctx.state().event_buffer_len();
    let bytes2 = eb.bytes(len2);
    let h2 = parse_header(bytes2, 40);
    assert_eq!(h2.seq, 1);
    assert_eq!(h2.tsc, 0x1111);
    assert_eq!(h2.len, 1);
}

#[test]
fn disabled_category_is_dropped() {
    let mut ctx = MockVmContext::new();
    let mut eb = EventBuf::new();
    eb.attach(&mut ctx);
    // Only SERIAL enabled.
    ctx.state_mut()
        .set_event_categories(EventCategories::SERIAL);

    // INJECT is filtered: returns true (success) but writes nothing.
    let inject = InjectPayload {
        vector: 0x20,
        source: InjectSource::Timer as u8,
        _pad: [0; 6],
        target_tsc: 42,
    };
    assert!(ctx
        .state_mut()
        .event_append(EventKind::Inject, pod_bytes(&inject)));
    assert_eq!(ctx.state().event_buffer_len(), 0);

    // SERIAL is kept.
    assert!(ctx.state_mut().event_append(EventKind::Serial, b"a"));
    assert!(ctx.state().event_buffer_len() > 0);
}

#[test]
fn no_buffer_attached_drops_silently() {
    let mut ctx = MockVmContext::new();
    ctx.state_mut()
        .set_event_categories(EventCategories::SERIAL);
    // No buffer attached -> append returns true (drop), no panic.
    assert!(ctx.state_mut().event_append(EventKind::Serial, b"hi"));
    assert_eq!(ctx.state().event_buffer_len(), 0);
}

#[test]
fn typed_payloads_roundtrip() {
    let mut ctx = MockVmContext::new();
    let mut eb = EventBuf::new();
    eb.attach(&mut ctx);
    ctx.state_mut().set_event_categories(
        EventCategories::INJECT
            .union(EventCategories::RANDOMNESS)
            .union(EventCategories::IO_CHANNEL),
    );

    let inject = InjectPayload {
        vector: 0xEC,
        source: InjectSource::Timer as u8,
        _pad: [0; 6],
        target_tsc: 700,
    };
    assert!(ctx
        .state_mut()
        .event_append(EventKind::Inject, pod_bytes(&inject)));

    let rand = RandomPayload {
        value: 0x0123_4567_89AB_CDEF,
        source: RandomSource::Rdrand as u8,
        width: 4,
        ..RandomPayload::default()
    };
    assert!(ctx
        .state_mut()
        .event_append(EventKind::Randomness, pod_bytes(&rand)));

    let io = IoChannelPayload {
        phase: IoChannelPhase::Request as u8,
        _pad: [0; 7],
        target_tsc: 900,
    };
    assert!(ctx
        .state_mut()
        .event_append(EventKind::IoChannel, pod_bytes(&io)));

    let total = ctx.state().event_buffer_len();
    let bytes = eb.bytes(total);

    // Record 0: Inject (16-byte payload) at offset 0.
    let h0 = parse_header(bytes, 0);
    assert_eq!(h0.kind, EventKind::Inject.as_u16());
    assert_eq!(h0.len, 16);
    assert_eq!(bytes[EVENT_HEADER_SIZE], 0xEC); // vector
    assert_eq!(rd_u64(bytes, EVENT_HEADER_SIZE + 8), 700); // target_tsc

    // Record 1: Randomness at offset 48 (32 + 16).
    let off1 = 48;
    let h1 = parse_header(bytes, off1);
    assert_eq!(h1.kind, EventKind::Randomness.as_u16());
    assert_eq!(h1.len, 16);
    assert_eq!(
        rd_u64(bytes, off1 + EVENT_HEADER_SIZE),
        0x0123_4567_89AB_CDEF
    );

    // Record 2: IoChannel (16-byte payload) at offset 96.
    let off2 = 96;
    let h2 = parse_header(bytes, off2);
    assert_eq!(h2.kind, EventKind::IoChannel.as_u16());
    assert_eq!(h2.len, 16);
    assert_eq!(
        bytes[off2 + EVENT_HEADER_SIZE],
        IoChannelPhase::Request as u8
    );
    assert_eq!(rd_u64(bytes, off2 + EVENT_HEADER_SIZE + 8), 900); // target_tsc
}

#[test]
fn buffer_full_stages_pending_then_event_clear_reappends() {
    let mut ctx = MockVmContext::new();
    let mut eb = EventBuf::new();
    eb.attach(&mut ctx);
    ctx.state_mut()
        .set_event_categories(EventCategories::SERIAL);

    // Fill the buffer with ~4 KB records until one does not fit.
    let payload = vec![0xABu8; 4000];
    let mut appended = 0u64;
    loop {
        if !ctx.state_mut().event_append(EventKind::Serial, &payload) {
            break;
        }
        appended += 1;
        assert!(
            appended < 1000,
            "buffer should fill well before 1000 records"
        );
    }

    // The overflowing record is staged as pending; the buffer holds `appended`
    // records and `event_seq` advanced exactly that many times (the pending
    // record has not consumed a seq yet).
    let len_before_clear = ctx.state().event_buffer_len();
    assert!(len_before_clear > 0);
    assert!(ctx.state().event_seq == appended);

    // Userspace drains, then event_clear re-appends the pending record into the
    // emptied buffer.
    ctx.state_mut().event_clear();
    let len_after = ctx.state().event_buffer_len();
    let one_record = EVENT_HEADER_SIZE + align_up(4000, 8);
    assert_eq!(len_after, one_record);

    let bytes = eb.bytes(len_after);
    let h = parse_header(bytes, 0);
    // The re-appended record keeps its original seq (== appended) and len.
    assert_eq!(h.seq, appended);
    assert_eq!(h.len, 4000);
    // seq has now advanced past it.
    assert_eq!(ctx.state().event_seq, appended + 1);
}

#[test]
fn serial_line_accumulator_emits_one_event_per_line() {
    let mut ctx = MockVmContext::new();
    let mut eb = EventBuf::new();
    eb.attach(&mut ctx);
    ctx.state_mut()
        .set_event_categories(EventCategories::SERIAL);
    ctx.set_emulated_tsc(0x5000);

    // Feed "ab\n" byte-by-byte: no event until the newline, then one event.
    assert!(ctx.state_mut().event_serial_byte(b'a'));
    assert_eq!(ctx.state().event_buffer_len(), 0);
    // Advance TSC mid-line; the emitted event must keep the line-START tsc.
    ctx.set_emulated_tsc(0x6000);
    assert!(ctx.state_mut().event_serial_byte(b'b'));
    assert_eq!(ctx.state().event_buffer_len(), 0);
    ctx.set_emulated_tsc(0x7000);
    assert!(ctx.state_mut().event_serial_byte(b'\n'));

    let len = ctx.state().event_buffer_len();
    assert_eq!(len, EVENT_HEADER_SIZE + align_up(3, 8));
    let bytes = eb.bytes(len);
    let h = parse_header(bytes, 0);
    assert_eq!(h.kind, EventKind::Serial.as_u16());
    assert_eq!(h.len, 3);
    assert_eq!(h.tsc, 0x5000); // line-start TSC, not the newline's 0x7000
    assert_eq!(&bytes[EVENT_HEADER_SIZE..EVENT_HEADER_SIZE + 3], b"ab\n");
    assert_eq!(h.real_tsc, 0); // rdtsc() is 0 in cargo builds
}

#[test]
fn serial_line_accumulator_disabled_is_noop() {
    let mut ctx = MockVmContext::new();
    let mut eb = EventBuf::new();
    eb.attach(&mut ctx);
    // SERIAL category disabled: accumulator does nothing.
    ctx.state_mut()
        .set_event_categories(EventCategories::empty());
    for &b in b"hello\n" {
        assert!(ctx.state_mut().event_serial_byte(b));
    }
    assert_eq!(ctx.state().event_buffer_len(), 0);
    assert_eq!(ctx.state().serial_line_len, 0);
}

#[test]
fn serial_line_flush_tail_on_shutdown() {
    let mut ctx = MockVmContext::new();
    let mut eb = EventBuf::new();
    eb.attach(&mut ctx);
    ctx.state_mut()
        .set_event_categories(EventCategories::SERIAL);

    // Partial line with no trailing newline.
    assert!(ctx.state_mut().event_serial_byte(b'p'));
    assert!(ctx.state_mut().event_serial_byte(b'q'));
    assert_eq!(ctx.state().event_buffer_len(), 0);

    // Explicit tail flush (what the shutdown path calls).
    assert!(ctx.state_mut().event_flush_serial_line());
    let len = ctx.state().event_buffer_len();
    let bytes = eb.bytes(len);
    let h = parse_header(bytes, 0);
    assert_eq!(h.len, 2);
    assert_eq!(&bytes[EVENT_HEADER_SIZE..EVENT_HEADER_SIZE + 2], b"pq");

    // A second flush is a no-op (accumulator already empty).
    assert!(ctx.state_mut().event_flush_serial_line());
    assert_eq!(ctx.state().event_buffer_len(), len);
}
