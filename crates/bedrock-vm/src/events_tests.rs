// SPDX-License-Identifier: GPL-2.0

//! Tests for the userspace event-stream reader (iterator + JSON).

use super::*;
use bedrock_vmx::events::{InjectSource, IoChannelPhase, RandomSource};

/// Reinterpret a `repr(C)` POD as bytes (test-only; mirrors what the producer
/// does via raw pointers in the kernel build).
fn pod_bytes<T: Copy>(v: &T) -> &[u8] {
    // SAFETY: `T` is a `repr(C)` POD with no padding in these tests.
    unsafe { std::slice::from_raw_parts((v as *const T).cast::<u8>(), std::mem::size_of::<T>()) }
}

/// Append one TLV record to `buf`, padding to an 8-byte boundary. Mirrors the
/// producer's framing so the reader can be tested against realistic bytes.
fn push_record(buf: &mut Vec<u8>, seq: u64, tsc: u64, real_tsc: u64, kind: u16, payload: &[u8]) {
    let flags = match kind {
        k if k == EventKind::Diagnostic.as_u16() => 0,
        _ => EVENT_FLAG_DETERMINISTIC,
    };
    let before = buf.len();
    buf.extend_from_slice(&seq.to_le_bytes());
    buf.extend_from_slice(&tsc.to_le_bytes());
    buf.extend_from_slice(&real_tsc.to_le_bytes());
    buf.extend_from_slice(&kind.to_le_bytes());
    buf.extend_from_slice(&flags.to_le_bytes());
    buf.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    assert_eq!(buf.len() - before, EVENT_HEADER_SIZE);
    buf.extend_from_slice(payload);
    while !buf.len().is_multiple_of(8) {
        buf.push(0);
    }
}

#[test]
fn empty_buffer_yields_no_records() {
    let buf: Vec<u8> = Vec::new();
    assert_eq!(EventStream::new(&buf).count(), 0);
}

#[test]
fn single_serial_record_roundtrips() {
    let mut buf = Vec::new();
    push_record(
        &mut buf,
        7,
        1234,
        99,
        EventKind::Serial.as_u16(),
        b"hello\n",
    );

    let recs: Vec<_> = EventStream::new(&buf).collect();
    assert_eq!(recs.len(), 1);
    let r = &recs[0];
    assert_eq!(r.seq(), 7);
    assert_eq!(r.tsc(), 1234);
    assert_eq!(r.real_tsc(), 99);
    assert_eq!(r.kind(), EventKind::Serial.as_u16());
    assert!(r.is_deterministic());
    match r.event() {
        Event::Serial(bytes) => assert_eq!(bytes, b"hello\n"),
        _ => panic!("expected Serial"),
    }
}

#[test]
fn padding_aligns_next_header() {
    let mut buf = Vec::new();
    // 13-byte serial payload -> record body padded to 16, so the second header
    // starts at an 8-aligned offset.
    push_record(
        &mut buf,
        1,
        10,
        0,
        EventKind::Serial.as_u16(),
        b"thirteen.byte",
    );
    push_record(&mut buf, 2, 20, 0, EventKind::Serial.as_u16(), b"x");

    let recs: Vec<_> = EventStream::new(&buf).collect();
    assert_eq!(recs.len(), 2);
    assert_eq!(recs[0].seq(), 1);
    assert_eq!(recs[1].seq(), 2);
    match recs[1].event() {
        Event::Serial(b) => assert_eq!(b, b"x"),
        _ => panic!("expected Serial"),
    }
}

#[test]
fn inject_random_iochannel_roundtrip() {
    let mut buf = Vec::new();

    let inject = InjectPayload {
        vector: 0x20,
        source: InjectSource::Timer as u8,
        _pad: [0; 6],
        target_tsc: 500_000,
    };
    push_record(
        &mut buf,
        1,
        500_001,
        0,
        EventKind::Inject.as_u16(),
        pod_bytes(&inject),
    );

    let rand = RandomPayload {
        value: 0xDEAD_BEEF_CAFE_F00D,
        source: RandomSource::Rdseed as u8,
        width: 8,
        ..RandomPayload::default()
    };
    push_record(
        &mut buf,
        2,
        500_010,
        0,
        EventKind::Randomness.as_u16(),
        pod_bytes(&rand),
    );

    let io = IoChannelPayload {
        phase: IoChannelPhase::Response as u8,
        _pad: [0; 7],
        target_tsc: 0,
    };
    // The IoChannel payload is the fixed struct followed by the transaction's
    // bytes (here, an opaque response body).
    let mut io_payload = pod_bytes(&io).to_vec();
    io_payload.extend_from_slice(b"hello from the guest");
    push_record(
        &mut buf,
        3,
        500_020,
        0,
        EventKind::IoChannel.as_u16(),
        &io_payload,
    );

    let recs: Vec<_> = EventStream::new(&buf).collect();
    assert_eq!(recs.len(), 3);

    match recs[0].event() {
        Event::Inject(p) => {
            assert_eq!(p.vector, 0x20);
            assert_eq!(p.source, InjectSource::Timer as u8);
            assert_eq!(p.target_tsc, 500_000);
        }
        _ => panic!("expected Inject"),
    }
    match recs[1].event() {
        Event::Randomness(p, bytes) => {
            assert_eq!(p.value, 0xDEAD_BEEF_CAFE_F00D);
            assert_eq!(p.source, RandomSource::Rdseed as u8);
            assert_eq!(p.width, 8);
            assert!(bytes.is_empty(), "RDRAND/RDSEED carry no trailing bytes");
        }
        _ => panic!("expected Randomness"),
    }
    match recs[2].event() {
        Event::IoChannel(p, data) => {
            assert_eq!(p.phase, IoChannelPhase::Response as u8);
            assert_eq!(data, b"hello from the guest");
        }
        _ => panic!("expected IoChannel"),
    }
}

#[test]
fn truncated_tail_stops_without_panic() {
    let mut buf = Vec::new();
    push_record(&mut buf, 1, 10, 0, EventKind::Serial.as_u16(), b"ok");
    buf.extend_from_slice(&[0u8; 10]); // partial header
    let recs: Vec<_> = EventStream::new(&buf).collect();
    assert_eq!(recs.len(), 1);
    assert_eq!(recs[0].seq(), 1);
}

#[test]
fn payload_overrun_stops() {
    let mut buf = Vec::new();
    let hdr = EventHeader {
        seq: 1,
        tsc: 1,
        real_tsc: 0,
        kind: EventKind::Serial.as_u16(),
        flags: EVENT_FLAG_DETERMINISTIC,
        len: 1000,
    };
    buf.extend_from_slice(pod_bytes(&hdr));
    buf.extend_from_slice(b"short");
    assert_eq!(EventStream::new(&buf).count(), 0);
}

#[test]
fn jsonl_output_renders_kinds() {
    let mut buf = Vec::new();
    push_record(
        &mut buf,
        1,
        100,
        7,
        EventKind::Serial.as_u16(),
        b"line one\n",
    );
    let rand = RandomPayload {
        value: 0x1234,
        source: RandomSource::Rdrand as u8,
        width: 4,
        ..RandomPayload::default()
    };
    push_record(
        &mut buf,
        2,
        200,
        0,
        EventKind::Randomness.as_u16(),
        pod_bytes(&rand),
    );

    // I/O channel request (bash on host): the metadata struct followed by the
    // bedrock-io.ko request envelope. The reader should decode it into
    // target/command/record_output rather than dumping the raw envelope bytes.
    let io = IoChannelPayload {
        phase: IoChannelPhase::Request as u8,
        _pad: [0; 7],
        target_tsc: 0,
    };
    let mut io_payload = pod_bytes(&io).to_vec();
    io_payload.extend_from_slice(&crate::io_channel::encode_request(None, "uname -a", true));
    push_record(
        &mut buf,
        3,
        300,
        0,
        EventKind::IoChannel.as_u16(),
        &io_payload,
    );

    let mut out = Vec::new();
    let n = write_jsonl(&mut out, &buf).unwrap();
    assert_eq!(n, 3);
    let text = String::from_utf8(out).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 3);

    assert!(lines[0].contains("\"kind\":\"serial\""));
    assert!(lines[0].contains("line one"));
    assert!(lines[0].contains("\"seq\":1"));
    assert!(lines[0].contains("\"deterministic\":true"));

    assert!(lines[1].contains("\"kind\":\"randomness\""));
    assert!(lines[1].contains("0x1234"));

    assert!(lines[2].contains("\"kind\":\"io_channel\""));
    assert!(lines[2].contains("\"phase\":\"request\""));
    assert!(lines[2].contains("\"target\":\"host\""));
    assert!(lines[2].contains("\"command\":\"uname -a\""));
    assert!(lines[2].contains("\"record_output\":true"));
}

#[test]
fn filtered_jsonl_keeps_only_category() {
    let mut buf = Vec::new();
    push_record(&mut buf, 1, 1, 0, EventKind::Serial.as_u16(), b"a");
    let rand = RandomPayload {
        value: 1,
        source: 0,
        width: 4,
        ..RandomPayload::default()
    };
    push_record(
        &mut buf,
        2,
        2,
        0,
        EventKind::Randomness.as_u16(),
        pod_bytes(&rand),
    );
    push_record(&mut buf, 3, 3, 0, EventKind::Serial.as_u16(), b"b");

    let mut out = Vec::new();
    let n = write_jsonl_filtered(&mut out, &buf, EventCategories::SERIAL).unwrap();
    assert_eq!(n, 2);
    let text = String::from_utf8(out).unwrap();
    assert_eq!(text.lines().count(), 2);
    assert!(text.contains("\"seq\":1"));
    assert!(text.contains("\"seq\":3"));
    assert!(!text.contains("randomness"));
}

#[test]
fn exit_record_json_round_trips() {
    // The CLI writes each `Exit` record's `ExitRecord` payload to the log JSONL,
    // and the determinism tooling reads it back. Validate the serde round-trip
    // and that padding is skipped.
    let mut entry = crate::ExitRecord::new();
    entry.tsc = 1234;
    entry.exit_reason = 30;
    entry.flags = crate::EXIT_RECORD_FLAG_DETERMINISTIC;
    entry.rax = 0xDEAD_BEEF;
    entry.memory_hash = 0xCAFE;
    entry.cow_page_count = 7;

    let json = serde_json::to_string(&entry).unwrap();
    // Padding is skipped; key fields are present.
    assert!(!json.contains("_padding"));
    assert!(json.contains("\"tsc\":1234"));
    assert!(json.contains("\"exit_reason\":30"));

    let back: crate::ExitRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(back.tsc, 1234);
    assert_eq!(back.exit_reason, 30);
    assert_eq!(back.rax, 0xDEAD_BEEF);
    assert_eq!(back.memory_hash, 0xCAFE);
    assert_eq!(back.cow_page_count, 7);
    assert!(back.is_deterministic());
}
