// SPDX-License-Identifier: GPL-2.0

//! I/O channel wire protocol — the userspace half of the `bedrock-io.ko` ABI.
//!
//! The channel does exactly one thing: run a bash command, on the host or
//! inside a named container. The hypervisor treats the request/response bytes
//! as opaque; this module is the single userspace definition of their layout,
//! shared by the request encoder (the CLI and `bedrock-lab`) and by the
//! event-stream reader, which decodes a captured request/response to label
//! [`IoChannel`](crate::events::Event::IoChannel) events.
//!
//! The command's combined stdout+stderr always streams to the guest journal
//! (systemd-cat), regardless of recording. Recording is an *additional*
//! capture for the host: when the request sets the [`IO_FLAG_RECORD_OUTPUT`]
//! bit, the guest also writes that output into a dedicated **output feedback
//! buffer** ([`IO_OUTPUT_BUFFER_ID`], up to 1 MB) and reports how many bytes it
//! wrote in the response's `output_len`; the host reads them back via the
//! feedback-buffer mechanism. Recording is chosen per invocation, so cheap
//! fire-and-forget commands pay nothing.
//!
//! Keep these constants in sync with `bedrock-io.c`.

use std::borrow::Cow;

/// Request-side magic on the I/O channel shared page.
pub const IO_REQUEST_MAGIC: u32 = 0xB10C1010;
/// Response-side magic.
pub const IO_RESPONSE_MAGIC: u32 = 0x1010B10C;

/// Request flag: additionally capture the command's combined stdout+stderr
/// into the output feedback buffer ([`IO_OUTPUT_BUFFER_ID`]) — the output still
/// streams to the guest journal either way. The response's `output_len` then
/// says how many bytes are valid.
pub const IO_FLAG_RECORD_OUTPUT: u32 = 1 << 0;

/// Identifier the guest registers its single command-output feedback buffer
/// under (`HYPERCALL_REGISTER_FEEDBACK_BUFFER`). The host reads recorded output
/// from the buffer with this id.
pub const IO_OUTPUT_BUFFER_ID: &[u8] = b"bedrock-io-output";

/// Request header: `u32 magic | u32 flags | u32 payload_len`, followed by the
/// payload `container\0command\0` (an empty container means "run on the host").
pub const REQUEST_HEADER_LEN: usize = 12;
/// Response header: `u32 magic | u32 flags | i32 status | i32 exit_code | u32 output_len`.
pub const RESPONSE_HEADER_LEN: usize = 20;

/// Where a bash command runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IoTarget<'a> {
    /// On the guest host, outside any container.
    Host,
    /// Inside the named container (via `podman exec`).
    Container(Cow<'a, str>),
}

/// A decoded I/O channel request: run `command` on `target`, optionally
/// recording its output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IoRequest<'a> {
    /// Where the command runs.
    pub target: IoTarget<'a>,
    /// The bash command line.
    pub command: Cow<'a, str>,
    /// Whether the command's output is captured into the output feedback buffer.
    pub record_output: bool,
}

/// A decoded I/O channel response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IoResponse {
    /// Dispatch status (0 = the action ran; negative = an errno from the guest
    /// module before the command could run).
    pub status: i32,
    /// Raw `call_usermodehelper(UMH_WAIT_PROC)` return value reported by the
    /// guest, verbatim. For a command that ran this is a wait(2)-encoded status
    /// (`kernel_wait`) — the real exit code lives in bits 8-15, *not* a bare
    /// exit code — and a negative value is a guest-side errno. Use
    /// [`exit_code_from_wait_status`] to turn it into a conventional exit code.
    pub exit_code: i32,
    /// Bytes of output the guest wrote into the output feedback buffer (0 when
    /// the request did not set [`IO_FLAG_RECORD_OUTPUT`]).
    pub output_len: u32,
}

/// Encode a bash request: run `command` on the host (`container == None`) or
/// inside a container, optionally recording its output.
pub fn encode_request(container: Option<&str>, command: &str, record_output: bool) -> Vec<u8> {
    let container = container.unwrap_or("");
    let mut payload = Vec::with_capacity(container.len() + command.len() + 2);
    payload.extend_from_slice(container.as_bytes());
    payload.push(0);
    payload.extend_from_slice(command.as_bytes());
    payload.push(0);

    let flags = if record_output {
        IO_FLAG_RECORD_OUTPUT
    } else {
        0
    };
    let mut bytes = Vec::with_capacity(REQUEST_HEADER_LEN + payload.len());
    bytes.extend_from_slice(&IO_REQUEST_MAGIC.to_le_bytes());
    bytes.extend_from_slice(&flags.to_le_bytes());
    bytes.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&payload);
    bytes
}

/// Take the bytes up to the first NUL (utf8-lossy) and the remainder after it.
fn split_cstr(b: &[u8]) -> (Cow<'_, str>, &[u8]) {
    let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    let rest = b.get(end + 1..).unwrap_or(&[]);
    (String::from_utf8_lossy(&b[..end]), rest)
}

/// Decode a captured request. Returns `None` if `bytes` is not a well-formed
/// request (wrong magic or too short) — e.g. when it is actually a response.
/// The declared payload length is ignored: the NUL terminators delimit the
/// fields, so a request truncated at the event buffer-fill boundary still
/// decodes what survived.
pub fn decode_request(bytes: &[u8]) -> Option<IoRequest<'_>> {
    let magic = u32::from_le_bytes(bytes.get(0..4)?.try_into().ok()?);
    if magic != IO_REQUEST_MAGIC {
        return None;
    }
    let flags = u32::from_le_bytes(bytes.get(4..8)?.try_into().ok()?);
    let payload = bytes.get(REQUEST_HEADER_LEN..).unwrap_or(&[]);
    let (container, rest) = split_cstr(payload);
    let target = if container.is_empty() {
        IoTarget::Host
    } else {
        IoTarget::Container(container)
    };
    Some(IoRequest {
        target,
        command: split_cstr(rest).0,
        record_output: flags & IO_FLAG_RECORD_OUTPUT != 0,
    })
}

/// Decode a captured response header. Returns `None` if `bytes` is not a
/// well-formed response (wrong magic or too short).
pub fn decode_response(bytes: &[u8]) -> Option<IoResponse> {
    let magic = u32::from_le_bytes(bytes.get(0..4)?.try_into().ok()?);
    if magic != IO_RESPONSE_MAGIC {
        return None;
    }
    Some(IoResponse {
        status: i32::from_le_bytes(bytes.get(8..12)?.try_into().ok()?),
        exit_code: i32::from_le_bytes(bytes.get(12..16)?.try_into().ok()?),
        output_len: u32::from_le_bytes(bytes.get(16..20)?.try_into().ok()?),
    })
}

/// Interpret a raw `call_usermodehelper(UMH_WAIT_PROC)` return value (as
/// carried in [`IoResponse::exit_code`]) as a conventional process exit code.
///
/// When the command ran, the guest hands back the wait(2)-encoded status from
/// `kernel_wait`, where the exit code lives in bits 8-15 and a terminating
/// signal in bits 0-6 — so the raw value for `exit 7` is `7 << 8 == 1792`, not
/// `7`. This mirrors libc's `WEXITSTATUS` for a normal exit and the shell's
/// `128 + signo` convention when the process was killed by a signal. A negative
/// value is an errno from the guest module before the command could run and is
/// passed through unchanged.
pub fn exit_code_from_wait_status(raw: i32) -> i32 {
    if raw < 0 {
        raw
    } else if raw & 0x7f != 0 {
        // Terminated by a signal: report it the way a shell would.
        128 + (raw & 0x7f)
    } else {
        // Normal exit: WEXITSTATUS(raw).
        (raw >> 8) & 0xff
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_request_round_trips() {
        let bytes = encode_request(None, "uname -a", true);
        let req = decode_request(&bytes).unwrap();
        assert_eq!(req.target, IoTarget::Host);
        assert_eq!(req.command, "uname -a");
        assert!(req.record_output);
    }

    #[test]
    fn container_request_round_trips() {
        let bytes = encode_request(Some("bitcoind1"), "bitcoin-cli getinfo", false);
        let req = decode_request(&bytes).unwrap();
        assert_eq!(req.target, IoTarget::Container(Cow::Borrowed("bitcoind1")));
        assert_eq!(req.command, "bitcoin-cli getinfo");
        assert!(!req.record_output);
    }

    #[test]
    fn rejects_non_request() {
        assert_eq!(decode_request(b"not a request"), None);
        assert_eq!(decode_request(&[]), None);
        let mut resp = Vec::new();
        resp.extend_from_slice(&IO_RESPONSE_MAGIC.to_le_bytes());
        assert_eq!(decode_request(&resp), None);
    }

    #[test]
    fn response_decodes() {
        let mut b = Vec::new();
        b.extend_from_slice(&IO_RESPONSE_MAGIC.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes()); // flags
        b.extend_from_slice(&(-2i32).to_le_bytes()); // status
        b.extend_from_slice(&42i32.to_le_bytes()); // exit_code
        b.extend_from_slice(&1234u32.to_le_bytes()); // output_len
        assert_eq!(
            decode_response(&b),
            Some(IoResponse {
                status: -2,
                exit_code: 42,
                output_len: 1234,
            })
        );
        assert_eq!(decode_response(b"xxxx"), None);
    }

    #[test]
    fn exit_status_decodes_to_exit_code() {
        // Normal exit: the code sits in bits 8-15 (WEXITSTATUS).
        assert_eq!(exit_code_from_wait_status(0), 0);
        assert_eq!(exit_code_from_wait_status(7 << 8), 7);
        assert_eq!(exit_code_from_wait_status(255 << 8), 255);
        // Killed by a signal: shell-style 128 + signo.
        assert_eq!(exit_code_from_wait_status(9), 128 + 9); // SIGKILL
                                                            // Guest-side errno: passed through untouched.
        assert_eq!(exit_code_from_wait_status(-22), -22); // -EINVAL
    }
}
