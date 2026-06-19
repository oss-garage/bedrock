// SPDX-License-Identifier: GPL-2.0

//! Tests for reconstructing an [`InputRecording`] from event-stream records.
//!
//! These exercise the pure decode path ([`InputRecording::record_event`]) with
//! hand-built event bytes, so they need no VM and run under `cargo test`.

use super::{InputRecording, InputSource, IoInput, RandomInput, RecordedInputSource};
use crate::bash::BashTarget;
use crate::time::VirtTime;
use bedrock_vm::events::{
    EventKind, IoChannelPayload, IoChannelPhase, RandomPayload, RandomSource,
    EVENT_FLAG_DETERMINISTIC, EVENT_HEADER_SIZE,
};
use bedrock_vm::io_channel::encode_request;
use bedrock_vm::EventStream;

const FREQ: u64 = 2_995_200_000;

/// Append one TLV record to `buf`, padding to an 8-byte boundary — mirrors the
/// kernel producer's framing (see `bedrock-vm/src/events_tests.rs`).
fn push_record(buf: &mut Vec<u8>, seq: u64, tsc: u64, kind: u16, payload: &[u8]) {
    let before = buf.len();
    buf.extend_from_slice(&seq.to_le_bytes());
    buf.extend_from_slice(&tsc.to_le_bytes());
    buf.extend_from_slice(&0u64.to_le_bytes()); // real_tsc — ignored on decode
    buf.extend_from_slice(&kind.to_le_bytes());
    buf.extend_from_slice(&EVENT_FLAG_DETERMINISTIC.to_le_bytes());
    buf.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    assert_eq!(buf.len() - before, EVENT_HEADER_SIZE);
    buf.extend_from_slice(payload);
    while !buf.len().is_multiple_of(8) {
        buf.push(0);
    }
}

fn random_record(buf: &mut Vec<u8>, seq: u64, tsc: u64, value: u64) {
    let p = RandomPayload {
        value,
        source: 0, // RDRAND
        width: 8,
        ..RandomPayload::default()
    };
    push_record(buf, seq, tsc, EventKind::Randomness.as_u16(), p.as_bytes());
}

/// A `HYPERCALL_GET_RANDOM` reply: same `EventKind::Randomness` record as
/// `random_record`, but `source = GetRandom` with the served bytes trailing the
/// header (and the requesting PID in the header).
fn get_random_record(buf: &mut Vec<u8>, seq: u64, tsc: u64, pid: u32, bytes: &[u8]) {
    let p = RandomPayload {
        pid,
        source: RandomSource::GetRandom as u8,
        ..RandomPayload::default()
    };
    let mut payload = p.as_bytes().to_vec();
    payload.extend_from_slice(bytes);
    push_record(buf, seq, tsc, EventKind::Randomness.as_u16(), &payload);
}

fn io_record(buf: &mut Vec<u8>, seq: u64, tsc: u64, phase: IoChannelPhase, envelope: &[u8]) {
    let meta = IoChannelPayload {
        phase: phase as u8,
        _pad: [0; 7],
        // Source-driven requests are queued fire-ASAP, so the wire `target_tsc`
        // is 0; the header `tsc` is what the recording uses for `at`.
        target_tsc: 0,
    };
    let mut payload = meta.as_bytes().to_vec();
    payload.extend_from_slice(envelope);
    push_record(buf, seq, tsc, EventKind::IoChannel.as_u16(), &payload);
}

/// Drive every record in `buf` through `record_event`, as `drain_events` does.
fn recording_from(buf: &[u8]) -> InputRecording {
    let mut rec = InputRecording::new();
    for record in EventStream::new(buf) {
        rec.record_event(&record, FREQ);
    }
    rec
}

#[test]
fn rdrand_events_become_random_inputs() {
    let mut buf = Vec::new();
    random_record(&mut buf, 0, 1_000, 0xDEAD_BEEF);
    random_record(&mut buf, 1, 2_000, 0x0BAD_F00D);

    let rec = recording_from(&buf);
    assert_eq!(rec.io_inputs().len(), 0);
    // RDRAND/RDSEED land in the one randomness stream, value stored as bytes.
    assert_eq!(
        rec.random_inputs(),
        &[
            RandomInput {
                at: VirtTime::from_instructions(1_000, FREQ),
                source: RandomSource::Rdrand,
                pid: 0,
                bytes: 0xDEAD_BEEF_u64.to_le_bytes().to_vec(),
            },
            RandomInput {
                at: VirtTime::from_instructions(2_000, FREQ),
                source: RandomSource::Rdrand,
                pid: 0,
                bytes: 0x0BAD_F00D_u64.to_le_bytes().to_vec(),
            },
        ]
    );

    // Replays as instruction values via next_rng_u64.
    let mut src = RecordedInputSource::new(rec);
    assert_eq!(src.next_rng_u64(), Some(0xDEAD_BEEF));
    assert_eq!(src.next_rng_u64(), Some(0x0BAD_F00D));
    assert_eq!(src.next_rng_u64(), None);
}

#[test]
fn get_random_events_become_random_inputs() {
    let mut buf = Vec::new();
    get_random_record(&mut buf, 0, 1_000, 42, &[1, 2, 3, 4]);
    get_random_record(&mut buf, 1, 2_000, 7, &[0xAA; 16]);

    let rec = recording_from(&buf);
    // GET_RANDOM lands in the same stream as RDRAND, tagged by source.
    assert_eq!(rec.io_inputs().len(), 0);
    assert_eq!(
        rec.random_inputs(),
        &[
            RandomInput {
                at: VirtTime::from_instructions(1_000, FREQ),
                source: RandomSource::GetRandom,
                pid: 42,
                bytes: vec![1, 2, 3, 4],
            },
            RandomInput {
                at: VirtTime::from_instructions(2_000, FREQ),
                source: RandomSource::GetRandom,
                pid: 7,
                bytes: vec![0xAA; 16],
            },
        ]
    );

    // Replays in order via next_random, zero-extending past the recording.
    let mut src = RecordedInputSource::new(rec);
    assert_eq!(src.next_random(4, 42), vec![1, 2, 3, 4]);
    assert_eq!(src.next_random(16, 7), vec![0xAA; 16]);
    assert_eq!(src.next_random(3, 0), vec![0, 0, 0]);
}

#[test]
fn rdrand_and_get_random_share_one_ordered_stream() {
    // RDRAND and GET_RANDOM events interleave into a single stream and replay
    // in capture order off one cursor — whichever method the consuming exit
    // calls.
    let mut buf = Vec::new();
    random_record(&mut buf, 0, 1_000, 0xAB); // RDRAND value
    get_random_record(&mut buf, 1, 2_000, 9, &[7, 7, 7, 7]); // GET_RANDOM bytes
    random_record(&mut buf, 2, 3_000, 0xCD); // RDRAND value

    let rec = recording_from(&buf);
    assert_eq!(rec.random_inputs().len(), 3);

    let mut src = RecordedInputSource::new(rec);
    assert_eq!(src.next_rng_u64(), Some(0xAB));
    assert_eq!(src.next_random(4, 9), vec![7, 7, 7, 7]);
    assert_eq!(src.next_rng_u64(), Some(0xCD));
    assert_eq!(src.next_rng_u64(), None);
}

#[test]
fn io_request_events_become_io_inputs() {
    let mut buf = Vec::new();
    io_record(
        &mut buf,
        0,
        3_000,
        IoChannelPhase::Request,
        &encode_request(None, "echo hi", true),
    );
    io_record(
        &mut buf,
        1,
        4_000,
        IoChannelPhase::Request,
        &encode_request(Some("bitcoind1"), "bitcoin-cli getinfo", false),
    );

    let rec = recording_from(&buf);
    assert_eq!(rec.random_inputs().len(), 0);
    assert_eq!(
        rec.io_inputs(),
        &[
            IoInput {
                at: VirtTime::from_instructions(3_000, FREQ),
                target: BashTarget::Host,
                command: "echo hi".to_string(),
                record_output: true,
            },
            IoInput {
                at: VirtTime::from_instructions(4_000, FREQ),
                target: BashTarget::container("bitcoind1"),
                command: "bitcoin-cli getinfo".to_string(),
                record_output: false,
            },
        ]
    );
}

#[test]
fn responses_and_other_kinds_are_ignored() {
    let mut buf = Vec::new();
    // An I/O channel *response* carries host-derived output, not an input.
    io_record(
        &mut buf,
        0,
        10,
        IoChannelPhase::Response,
        b"opaque response",
    );
    // A serial line is not an input either.
    push_record(&mut buf, 1, 20, EventKind::Serial.as_u16(), b"hello\n");
    // ...but a request between them still records.
    io_record(
        &mut buf,
        2,
        30,
        IoChannelPhase::Request,
        &encode_request(None, "true", false),
    );

    let rec = recording_from(&buf);
    assert_eq!(rec.random_inputs().len(), 0);
    assert_eq!(rec.io_inputs().len(), 1);
    assert_eq!(rec.io_inputs()[0].command, "true");
}

#[test]
fn recording_round_trips_through_replay_source() {
    let mut buf = Vec::new();
    random_record(&mut buf, 0, 1_000, 0x11);
    io_record(
        &mut buf,
        1,
        2_000,
        IoChannelPhase::Request,
        &encode_request(None, "first", false),
    );
    random_record(&mut buf, 2, 3_000, 0x22);
    io_record(
        &mut buf,
        3,
        4_000,
        IoChannelPhase::Request,
        &encode_request(None, "second", true),
    );

    let rec = recording_from(&buf);
    let mut source = RecordedInputSource::new(rec);

    // Randomness and I/O each replay in capture order, on independent cursors.
    assert_eq!(source.next_rng_u64(), Some(0x11));
    assert_eq!(source.next_rng_u64(), Some(0x22));
    assert_eq!(source.next_rng_u64(), None);

    let first = source.next_io_input().unwrap();
    assert_eq!(first.command, "first");
    assert!(!first.record_output);
    let second = source.next_io_input().unwrap();
    assert_eq!(second.command, "second");
    assert!(second.record_output);
    assert!(source.next_io_input().is_none());
}
