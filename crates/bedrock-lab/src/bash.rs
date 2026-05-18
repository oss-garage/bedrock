// SPDX-License-Identifier: GPL-2.0

//! I/O channel actions: bash command injection and workload introspection.
//!
//! The hypervisor exposes a deterministic guest↔host I/O channel; in
//! combination with the in-guest `bedrock-io.ko` module it lets the lab
//! dispatch shell commands and query the guest's workload listing. This
//! module wraps the wire protocol so callers can think in terms of "run
//! this command" or "list workloads" rather than byte layouts.

/// Where a [`Branch::bash`](crate::Branch::bash) command runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BashTarget {
    /// Run on the guest host (outside any container).
    Host,
    /// Run inside the named container.
    Container(String),
}

impl BashTarget {
    /// Construct a [`BashTarget::Host`].
    pub fn host() -> Self {
        Self::Host
    }

    /// Construct a [`BashTarget::Container`] without typing `.into()`.
    pub fn container(name: impl Into<String>) -> Self {
        Self::Container(name.into())
    }
}

/// Result of a [`Branch::bash`](crate::Branch::bash) call.
///
/// Exec actions stream stdout/stderr into the guest journal via `systemd-cat`,
/// so the host-bound response carries only status and exit code — observe the
/// command's output through serial events on the [`EventSink`](crate::EventSink)
/// (the journal lines come out as `[<tag>] | …`), not through this struct.
#[derive(Debug, Clone)]
pub struct BashOutput {
    /// Action-level status from the guest module. `0` means the action was
    /// dispatched successfully; non-zero typically means the requested
    /// container/binary couldn't be found.
    pub status: i32,
    /// Exit code of the bash command itself.
    pub exit_code: i32,
}

impl BashOutput {
    /// Returns `true` iff the action dispatched and bash exited with 0.
    pub fn success(&self) -> bool {
        self.status == 0 && self.exit_code == 0
    }
}

/// One entry in a workload listing — a container and an executable "driver"
/// path inside it that can be invoked via `Branch::bash` with
/// `BashTarget::Container`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkloadDriver {
    pub container: String,
    pub driver: String,
}

// --- Wire protocol ---
//
// Mirrors the `bedrock-io.ko` ABI. Keep in sync with the kernel module's
// IO_REQUEST_MAGIC / IO_RESPONSE_MAGIC constants and action IDs.

pub(crate) const IO_REQUEST_MAGIC: u32 = 0xB10C1010;
pub(crate) const IO_RESPONSE_MAGIC: u32 = 0x1010B10C;

const ACTION_GET_WORKLOAD_DETAILS: u32 = 0;
const ACTION_EXEC_BASH: u32 = 1;
const ACTION_EXEC_HOST_BASH: u32 = 2;

const REQUEST_HEADER_LEN: usize = 12;
const RESPONSE_HEADER_LEN: usize = 20;

/// Encode a bash request targeting the host or a named container.
pub(crate) fn encode_bash_request(target: BashTarget, cmd: &str) -> Vec<u8> {
    let (action_id, payload_len) = match &target {
        BashTarget::Host => (ACTION_EXEC_HOST_BASH, cmd.len() + 1),
        BashTarget::Container(name) => (ACTION_EXEC_BASH, name.len() + 1 + cmd.len() + 1),
    };
    let mut bytes = Vec::with_capacity(REQUEST_HEADER_LEN + payload_len);
    bytes.extend_from_slice(&IO_REQUEST_MAGIC.to_le_bytes());
    bytes.extend_from_slice(&action_id.to_le_bytes());
    bytes.extend_from_slice(&(payload_len as u32).to_le_bytes());
    if let BashTarget::Container(name) = target {
        bytes.extend_from_slice(name.as_bytes());
        bytes.push(0);
    }
    bytes.extend_from_slice(cmd.as_bytes());
    bytes.push(0);
    bytes
}

/// Encode a workload-details request (empty payload).
pub(crate) fn encode_workload_details_request() -> Vec<u8> {
    let mut bytes = Vec::with_capacity(REQUEST_HEADER_LEN);
    bytes.extend_from_slice(&IO_REQUEST_MAGIC.to_le_bytes());
    bytes.extend_from_slice(&ACTION_GET_WORKLOAD_DETAILS.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes
}

/// Decoded I/O channel response, dispatched by action ID.
#[derive(Debug, Clone)]
pub enum ActionResponse {
    Bash(BashOutput),
    WorkloadDetails(Vec<WorkloadDriver>),
}

struct Envelope<'a> {
    action_id: u32,
    status: i32,
    exit_code: i32,
    data: &'a [u8],
}

fn decode_envelope(bytes: &[u8]) -> Result<Envelope<'_>, String> {
    if bytes.len() < RESPONSE_HEADER_LEN {
        return Err(format!("response too short: {} bytes", bytes.len()));
    }
    let magic = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    if magic != IO_RESPONSE_MAGIC {
        return Err(format!("bad response magic {:#x}", magic));
    }
    let action_id = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    let status = i32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
    let exit_code = i32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);
    let data_len = u32::from_le_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]) as usize;
    let data_end = RESPONSE_HEADER_LEN + data_len;
    if data_end > bytes.len() {
        return Err(format!(
            "response data overruns: {} > {}",
            data_end,
            bytes.len()
        ));
    }
    Ok(Envelope {
        action_id,
        status,
        exit_code,
        data: &bytes[RESPONSE_HEADER_LEN..data_end],
    })
}

fn parse_workload_listing(data: &[u8]) -> Vec<WorkloadDriver> {
    let text = String::from_utf8_lossy(data);
    let mut drivers = Vec::new();
    for line in text.lines() {
        if let Some((container, driver)) = line.split_once('\t') {
            if !driver.is_empty() {
                drivers.push(WorkloadDriver {
                    container: container.to_string(),
                    driver: driver.to_string(),
                });
            }
        }
    }
    drivers
}

/// Decode an I/O channel response, dispatching on the action ID to the
/// matching [`ActionResponse`] variant.
pub(crate) fn decode_response(bytes: &[u8]) -> Result<ActionResponse, String> {
    let env = decode_envelope(bytes)?;
    match env.action_id {
        ACTION_GET_WORKLOAD_DETAILS => Ok(ActionResponse::WorkloadDetails(parse_workload_listing(
            env.data,
        ))),
        ACTION_EXEC_BASH | ACTION_EXEC_HOST_BASH => Ok(ActionResponse::Bash(BashOutput {
            status: env.status,
            exit_code: env.exit_code,
        })),
        other => Err(format!("unknown action_id: {other}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_host_layout() {
        let bytes = encode_bash_request(BashTarget::Host, "echo hi");
        assert_eq!(&bytes[0..4], &IO_REQUEST_MAGIC.to_le_bytes());
        assert_eq!(&bytes[4..8], &ACTION_EXEC_HOST_BASH.to_le_bytes());
        // payload len = "echo hi\0" = 8
        assert_eq!(&bytes[8..12], &8u32.to_le_bytes());
        assert_eq!(&bytes[12..20], b"echo hi\0");
    }

    #[test]
    fn encode_container_layout() {
        let bytes = encode_bash_request(BashTarget::container("ctr"), "ls");
        assert_eq!(&bytes[4..8], &ACTION_EXEC_BASH.to_le_bytes());
        // "ctr\0ls\0" = 7
        assert_eq!(&bytes[8..12], &7u32.to_le_bytes());
        assert_eq!(&bytes[12..19], b"ctr\0ls\0");
    }

    #[test]
    fn encode_workload_details_layout() {
        let bytes = encode_workload_details_request();
        assert_eq!(bytes.len(), REQUEST_HEADER_LEN);
        assert_eq!(&bytes[0..4], &IO_REQUEST_MAGIC.to_le_bytes());
        assert_eq!(&bytes[4..8], &ACTION_GET_WORKLOAD_DETAILS.to_le_bytes());
        assert_eq!(&bytes[8..12], &0u32.to_le_bytes());
    }

    fn make_response(action_id: u32, status: i32, exit_code: i32, data: &[u8]) -> Vec<u8> {
        let mut resp = Vec::new();
        resp.extend_from_slice(&IO_RESPONSE_MAGIC.to_le_bytes());
        resp.extend_from_slice(&action_id.to_le_bytes());
        resp.extend_from_slice(&status.to_le_bytes());
        resp.extend_from_slice(&exit_code.to_le_bytes());
        resp.extend_from_slice(&(data.len() as u32).to_le_bytes());
        resp.extend_from_slice(data);
        resp
    }

    #[test]
    fn decode_bash_response_roundtrip() {
        let resp = make_response(ACTION_EXEC_HOST_BASH, 0, 42, b"");
        match decode_response(&resp).unwrap() {
            ActionResponse::Bash(out) => {
                assert_eq!(out.status, 0);
                assert_eq!(out.exit_code, 42);
            }
            other => panic!("expected Bash, got {other:?}"),
        }
    }

    #[test]
    fn decode_container_bash_response_uses_bash_variant() {
        let resp = make_response(ACTION_EXEC_BASH, 0, 0, b"");
        assert!(matches!(
            decode_response(&resp).unwrap(),
            ActionResponse::Bash(_)
        ));
    }

    #[test]
    fn decode_workload_details_parses_lines() {
        let body = "header1\t\nworker-1\t/drivers/a\nworker-2\t/drivers/b\nempty\t\n";
        let resp = make_response(ACTION_GET_WORKLOAD_DETAILS, 0, 0, body.as_bytes());
        match decode_response(&resp).unwrap() {
            ActionResponse::WorkloadDetails(drivers) => assert_eq!(
                drivers,
                vec![
                    WorkloadDriver {
                        container: "worker-1".into(),
                        driver: "/drivers/a".into()
                    },
                    WorkloadDriver {
                        container: "worker-2".into(),
                        driver: "/drivers/b".into()
                    },
                ]
            ),
            other => panic!("expected WorkloadDetails, got {other:?}"),
        }
    }

    #[test]
    fn decode_rejects_bad_magic() {
        let mut resp = make_response(0, 0, 0, b"");
        resp[0] = 0; // corrupt magic
        assert!(decode_response(&resp).is_err());
    }

    #[test]
    fn decode_rejects_unknown_action() {
        let resp = make_response(99, 0, 0, b"");
        assert!(decode_response(&resp).is_err());
    }
}
