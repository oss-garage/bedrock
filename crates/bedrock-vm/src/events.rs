// SPDX-License-Identifier: GPL-2.0

//! Userspace reader for the unified event stream.
//!
//! The wire-format types are defined once in `bedrock-vmx` (`bedrock_vmx::events`)
//! and shared with the producer. This module adds the userspace-only reader: a
//! zero-copy TLV [`Iterator`] plus `serde` JSON output. It lives here (rather than
//! in `bedrock-vmx`) because the reader needs `std` and `serde_json`, while
//! `bedrock-vmx` is `#![no_std]`.
//!
//! TLV framing maps directly onto [`Iterator`], yielding borrowed, zero-copy
//! views and giving `.filter()`/`.map()`/`.take_while()` for free. The byte
//! stream is canonical, so only `Serialize` is provided; `Deserialize` is a
//! non-goal.

use std::borrow::Cow;
use std::io::{self, Write};
use std::mem::size_of;

use serde::Serialize;
use zerocopy::FromBytes;

use crate::ExitRecord;
pub use bedrock_vmx::events::{
    EventCategories, EventHeader, EventKind, InjectPayload, IoChannelPayload, IoChannelPhase,
    RandomPayload, RandomSource, EVENT_BUFFER_SIZE, EVENT_FLAG_DETERMINISTIC, EVENT_HEADER_SIZE,
};

/// A decoded view of one record's payload.
pub enum Event<'a> {
    /// Exit record (a [`ExitRecord`] snapshot, sub-typed by `exit_reason`).
    Exit(&'a ExitRecord),
    /// Raw console bytes.
    Serial(&'a [u8]),
    /// Injected interrupt.
    Inject(&'a InjectPayload),
    /// Controlled-randomness value: the fixed [`RandomPayload`] header plus, for
    /// `GetRandom`, the served byte buffer (empty for RDRAND/RDSEED, whose value
    /// is carried inline in the header). The payload's [`RandomSource`] says
    /// which channel served it.
    Randomness(&'a RandomPayload, &'a [u8]),
    /// I/O channel transaction: the fixed metadata plus the transaction's bytes
    /// (the injected request command, or the guest's response).
    IoChannel(&'a IoChannelPayload, &'a [u8]),
    /// A known-framed record of an unrecognized kind.
    Unknown {
        /// The raw `kind` field.
        kind: u16,
        /// The raw payload bytes.
        payload: &'a [u8],
    },
    /// The payload was too short for the kind's fixed struct.
    Malformed,
}

/// A borrowed view over one TLV record: its header plus its payload bytes.
#[derive(Clone, Copy, Debug)]
pub struct EventRecord<'a> {
    /// The fixed record header.
    pub header: &'a EventHeader,
    /// The `header.len` payload bytes immediately following the header.
    pub payload: &'a [u8],
}

impl<'a> EventRecord<'a> {
    /// Monotonic sequence number.
    pub fn seq(&self) -> u64 {
        self.header.seq
    }

    /// Emulated (deterministic) TSC at emit time.
    pub fn tsc(&self) -> u64 {
        self.header.tsc
    }

    /// Host (non-deterministic) TSC at emit time.
    pub fn real_tsc(&self) -> u64 {
        self.header.real_tsc
    }

    /// Raw `kind` field.
    pub fn kind(&self) -> u16 {
        self.header.kind
    }

    /// True if the record participates in run-vs-run comparison.
    pub fn is_deterministic(&self) -> bool {
        self.header.flags & EVENT_FLAG_DETERMINISTIC != 0
    }

    /// Decode the payload according to `kind`. Uses checked casts; returns
    /// [`Event::Malformed`] if the payload is shorter than the kind's struct.
    pub fn event(&self) -> Event<'a> {
        match self.header.kind {
            k if k == EventKind::Exit.as_u16() => match ExitRecord::ref_from_prefix(self.payload) {
                Ok((p, _)) => Event::Exit(p),
                Err(_) => Event::Malformed,
            },
            k if k == EventKind::Serial.as_u16() => Event::Serial(self.payload),
            k if k == EventKind::Inject.as_u16() => {
                match InjectPayload::ref_from_prefix(self.payload) {
                    Ok((p, _)) => Event::Inject(p),
                    Err(_) => Event::Malformed,
                }
            }
            k if k == EventKind::Randomness.as_u16() => {
                // `ref_from_prefix` splits the fixed header from any trailing
                // served bytes (GetRandom); the tail is empty for RDRAND/RDSEED.
                match RandomPayload::ref_from_prefix(self.payload) {
                    Ok((p, bytes)) => Event::Randomness(p, bytes),
                    Err(_) => Event::Malformed,
                }
            }
            k if k == EventKind::IoChannel.as_u16() => {
                match IoChannelPayload::ref_from_prefix(self.payload) {
                    // `ref_from_prefix` splits the 24-byte struct from the
                    // trailing transaction bytes.
                    Ok((p, data)) => Event::IoChannel(p, data),
                    Err(_) => Event::Malformed,
                }
            }
            kind => Event::Unknown {
                kind,
                payload: self.payload,
            },
        }
    }

    /// Build a serializable JSON view of this record.
    pub fn to_json(&self) -> EventJson<'a> {
        let body = match self.event() {
            Event::Exit(p) => EventBody::Exit(p),
            Event::Serial(bytes) => EventBody::Serial(String::from_utf8_lossy(bytes)),
            Event::Inject(p) => EventBody::Inject(p),
            Event::Randomness(p, bytes) => EventBody::Randomness {
                source: p.source,
                width: p.width,
                value: p.value,
                pid: p.pid,
                len: bytes.len(),
            },
            Event::IoChannel(p, data) => io_channel_body(p, data),
            Event::Unknown { kind, payload } => EventBody::Unknown {
                kind,
                len: payload.len(),
            },
            Event::Malformed => EventBody::Unknown {
                kind: self.header.kind,
                len: self.payload.len(),
            },
        };
        EventJson {
            seq: self.header.seq,
            tsc: self.header.tsc,
            real_tsc: self.header.real_tsc,
            deterministic: self.is_deterministic(),
            body,
        }
    }
}

/// Streaming iterator over a drained event buffer (`buf[0..event_len]`).
///
/// `next()` returns `None` on a truncated or overrunning tail rather than
/// panicking.
pub struct EventStream<'a> {
    buf: &'a [u8],
    off: usize,
}

impl<'a> EventStream<'a> {
    /// Wrap a drained buffer slice.
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, off: 0 }
    }
}

impl<'a> Iterator for EventStream<'a> {
    type Item = EventRecord<'a>;

    fn next(&mut self) -> Option<EventRecord<'a>> {
        let rest = self.buf.get(self.off..)?;
        // zerocopy 0.8: bounds-checked, alignment-checked prefix cast.
        let (header, after) = EventHeader::ref_from_prefix(rest).ok()?;
        let payload = after.get(..header.len as usize)?;
        self.off += size_of::<EventHeader>() + header.len as usize;
        // Records are padded up to an 8-byte boundary.
        self.off = (self.off + 7) & !7;
        Some(EventRecord { header, payload })
    }
}

// ============================================================================
// serde / JSONL output
// ============================================================================

/// Serialize a `u64` as a `0x…` hex string (for randomness values).
fn hex<S: serde::Serializer>(v: &u64, s: S) -> Result<S::Ok, S::Error> {
    s.collect_str(&format_args!("{:#x}", v))
}

/// Build an [`EventBody::IoChannel`] from a record: a request decodes into
/// `target`/`command`/`record_output`; a response decodes into
/// `status`/`exit_code`/`output_len`; anything else falls back to the
/// utf8-lossy bytes under `text`.
fn io_channel_body<'a>(meta: &'a IoChannelPayload, data: &'a [u8]) -> EventBody<'a> {
    use crate::io_channel::{self, IoTarget};
    let is_request = meta.phase == IoChannelPhase::Request as u8;

    let mut target = None;
    let mut command = None;
    let mut record_output = None;
    let mut status = None;
    let mut exit_code = None;
    let mut output_len = None;
    let mut text = None;

    if let Some(req) = io_channel::decode_request(data) {
        target = Some(match req.target {
            IoTarget::Host => Cow::Borrowed("host"),
            IoTarget::Container(name) => name,
        });
        command = Some(req.command);
        record_output = Some(req.record_output);
    } else if let Some(resp) = io_channel::decode_response(data) {
        status = Some(resp.status);
        exit_code = Some(resp.exit_code);
        output_len = Some(resp.output_len);
    } else if !data.is_empty() {
        text = Some(String::from_utf8_lossy(data));
    }

    EventBody::IoChannel {
        phase: if is_request { "request" } else { "response" },
        target_tsc: is_request.then_some(meta.target_tsc),
        target,
        command,
        record_output,
        status,
        exit_code,
        output_len,
        text,
    }
}

/// A serializable, human-friendly view of one record's body. Serializing a
/// *view* (rather than the raw wire struct) skips padding and renders values
/// nicely (hex for randomness, utf8-lossy string for serial).
///
/// Adjacent tagging (`tag`/`content`) is required because the `Serial` variant
/// is a string, not a map; internal tagging only works when every variant is a
/// map.
#[derive(Serialize)]
#[serde(tag = "kind", content = "data", rename_all = "snake_case")]
pub enum EventBody<'a> {
    /// Exit record body.
    Exit(&'a ExitRecord),
    /// Console text (utf8-lossy).
    Serial(Cow<'a, str>),
    /// Injected interrupt.
    Inject(&'a InjectPayload),
    /// Controlled-randomness value (value rendered as hex).
    Randomness {
        /// Source channel (0 = RDRAND, 1 = RDSEED, 2 = GET_RANDOM).
        source: u8,
        /// Operand width in bytes (RDRAND/RDSEED; 0 for GET_RANDOM).
        width: u8,
        /// Value handed to the guest, hex-encoded (RDRAND/RDSEED; 0 for
        /// GET_RANDOM, whose bytes are reported via `len`).
        #[serde(serialize_with = "hex")]
        value: u64,
        /// Requesting PID (GET_RANDOM; 0 for RDRAND/RDSEED).
        pid: u32,
        /// Number of served bytes trailing the header (GET_RANDOM; 0 for
        /// RDRAND/RDSEED). The bytes themselves are omitted to keep the log
        /// compact.
        len: usize,
    },
    /// I/O channel transaction. A request decodes into `target`/`command`/
    /// `record_output`; a response into `status`/`exit_code`/`output_len`; an
    /// unrecognized payload falls back to utf8-lossy `text`.
    IoChannel {
        /// `"request"` or `"response"`.
        phase: &'static str,
        /// Scheduled request target TSC (request only).
        #[serde(skip_serializing_if = "Option::is_none")]
        target_tsc: Option<u64>,
        /// Where the command runs: `"host"` or the container name (request).
        #[serde(skip_serializing_if = "Option::is_none")]
        target: Option<Cow<'a, str>>,
        /// The bash command (request).
        #[serde(skip_serializing_if = "Option::is_none")]
        command: Option<Cow<'a, str>>,
        /// Whether the command's output is captured into the output feedback
        /// buffer (request).
        #[serde(skip_serializing_if = "Option::is_none")]
        record_output: Option<bool>,
        /// Dispatch status (response).
        #[serde(skip_serializing_if = "Option::is_none")]
        status: Option<i32>,
        /// Command exit code (response).
        #[serde(skip_serializing_if = "Option::is_none")]
        exit_code: Option<i32>,
        /// Bytes written to the output feedback buffer (response).
        #[serde(skip_serializing_if = "Option::is_none")]
        output_len: Option<u32>,
        /// utf8-lossy bytes for an unrecognized payload.
        #[serde(skip_serializing_if = "Option::is_none")]
        text: Option<Cow<'a, str>>,
    },
    /// Unrecognized kind; raw payload length is reported.
    Unknown {
        /// The raw `kind` field.
        kind: u16,
        /// Number of payload bytes.
        len: usize,
    },
}

/// A flat JSON object for one record: the deterministic header fields plus the
/// flattened body.
#[derive(Serialize)]
pub struct EventJson<'a> {
    /// Monotonic sequence number.
    pub seq: u64,
    /// Emulated (deterministic) TSC.
    pub tsc: u64,
    /// Host (non-deterministic) TSC.
    pub real_tsc: u64,
    /// Whether the record participates in run-vs-run comparison.
    pub deterministic: bool,
    /// The kind-specific body.
    #[serde(flatten)]
    pub body: EventBody<'a>,
}

/// Write every record in a drained buffer as one JSON object per line (JSONL).
///
/// Returns the number of records written.
pub fn write_jsonl<W: Write>(writer: &mut W, drained: &[u8]) -> io::Result<usize> {
    let mut n = 0;
    for rec in EventStream::new(drained) {
        serde_json::to_writer(&mut *writer, &rec.to_json()).map_err(io::Error::other)?;
        writeln!(writer)?;
        n += 1;
    }
    Ok(n)
}

/// Write only the records whose kind is in `categories` as JSONL. Convenience
/// for splitting the stream into per-category files (e.g. deterministic vs not).
pub fn write_jsonl_filtered<W: Write>(
    writer: &mut W,
    drained: &[u8],
    categories: EventCategories,
) -> io::Result<usize> {
    let mut n = 0;
    for rec in EventStream::new(drained) {
        if !categories.contains(category_of(rec.header.kind)) {
            continue;
        }
        serde_json::to_writer(&mut *writer, &rec.to_json()).map_err(io::Error::other)?;
        writeln!(writer)?;
        n += 1;
    }
    Ok(n)
}

/// Map a raw `kind` to its category bit (empty for unknown kinds).
pub fn category_of(kind: u16) -> EventCategories {
    match kind {
        k if k == EventKind::Exit.as_u16() => EventCategories::EXIT,
        k if k == EventKind::Serial.as_u16() => EventCategories::SERIAL,
        k if k == EventKind::Inject.as_u16() => EventCategories::INJECT,
        k if k == EventKind::Randomness.as_u16() => EventCategories::RANDOMNESS,
        k if k == EventKind::IoChannel.as_u16() => EventCategories::IO_CHANNEL,
        k if k == EventKind::Diagnostic.as_u16() => EventCategories::DIAGNOSTIC,
        _ => EventCategories::empty(),
    }
}

#[cfg(test)]
#[path = "events_tests.rs"]
mod tests;
