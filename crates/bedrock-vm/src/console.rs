// SPDX-License-Identifier: GPL-2.0

//! Guest console log format — the host's view of one serial-console line.
//!
//! During the guest's runtime phase the console is a single stream of compact
//! journald JSON records, one per line: `{"SYSLOG_IDENTIFIER":…,"MESSAGE":…}`.
//! `journalctl -o json | jq -c '{SYSLOG_IDENTIFIER, MESSAGE}'` (see `guest/init`)
//! funnels container output, the `systemd-cat -t …` tags (assertions,
//! workload-monitor, …) and kernel printk (journald imports `/dev/kmsg`) all
//! through this one projection. Before that `journalctl` tail starts — the
//! early-boot window — the console instead carries raw kernel printk text.
//!
//! [`ConsoleLine::parse`] is the single host-side definition of how to read one
//! reassembled console line, shared by every consumer (the CLI's line printer,
//! `bedrock-lab`-driven tests' assertion reader). It classifies a line into a
//! [`Journal`](ConsoleLine::Journal) record or, when the line isn't one of those
//! JSON objects, [`Raw`](ConsoleLine::Raw) text.
//!
//! Keep the projected field names in sync with the `jq` filter in `guest/init`.

use serde::Deserialize;

/// One reassembled console line, classified by source format.
///
/// Obtain it from the bytes of a complete console line (the CLI reassembles its
/// own; `bedrock-lab` delivers them as
/// [`Event::SerialLine`](crate::events::Event::SerialLine)) via
/// [`ConsoleLine::parse`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConsoleLine {
    /// A journald record. `source` is `SYSLOG_IDENTIFIER` — the container name
    /// for container output, the `systemd-cat -t` tag for tagged host sources
    /// (`assertions`, `workload-monitor`, `init`, …), or `kernel` for kmsg
    /// records — and `message` is the `MESSAGE` payload.
    Journal { source: String, message: String },
    /// A line that is not a journald JSON record — early-boot kernel printk, or
    /// any line that fails to parse — kept verbatim.
    Raw(String),
}

impl ConsoleLine {
    /// Default source label for a record whose `SYSLOG_IDENTIFIER` is absent or
    /// null. journald tags kmsg records `kernel`, so a record that reaches us
    /// without an identifier is almost certainly one.
    const DEFAULT_SOURCE: &'static str = "kernel";

    /// Classify one complete console line.
    ///
    /// A line that parses as a JSON object carrying a `MESSAGE` field is a
    /// [`Journal`](ConsoleLine::Journal) record; everything else — raw printk, a
    /// not-yet-complete partial, unrelated JSON — is returned as
    /// [`Raw`](ConsoleLine::Raw) without modification.
    pub fn parse(line: &str) -> Self {
        match serde_json::from_str::<JournalRecord>(line.trim()) {
            Ok(rec) if rec.message.is_some() => ConsoleLine::Journal {
                source: rec
                    .syslog_identifier
                    .unwrap_or_else(|| Self::DEFAULT_SOURCE.to_string()),
                message: rec.message.map(|m| m.into_text()).unwrap_or_default(),
            },
            _ => ConsoleLine::Raw(line.to_string()),
        }
    }
}

/// The guest's runtime console projection: `{SYSLOG_IDENTIFIER, MESSAGE}`. `jq`
/// always emits both keys (even when their journal value is null), so a record
/// missing `MESSAGE` is not one of ours and parses back as [`ConsoleLine::Raw`].
#[derive(Deserialize)]
struct JournalRecord {
    #[serde(rename = "SYSLOG_IDENTIFIER")]
    syslog_identifier: Option<String>,
    #[serde(rename = "MESSAGE")]
    message: Option<JournalMessage>,
}

/// A journal `MESSAGE` value. journald renders it as a string normally, but as
/// an array of byte values when the message isn't a clean UTF-8 line (e.g. it
/// embeds a newline). Accept both.
#[derive(Deserialize)]
#[serde(untagged)]
enum JournalMessage {
    Text(String),
    Bytes(Vec<u8>),
}

impl JournalMessage {
    fn into_text(self) -> String {
        match self {
            JournalMessage::Text(s) => s,
            JournalMessage::Bytes(b) => String::from_utf8_lossy(&b).into_owned(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_tagged_record() {
        let line = r#"{"SYSLOG_IDENTIFIER":"assertions","MESSAGE":"{\"Always\":{}}"}"#;
        assert_eq!(
            ConsoleLine::parse(line),
            ConsoleLine::Journal {
                source: "assertions".to_string(),
                message: r#"{"Always":{}}"#.to_string(),
            }
        );
    }

    #[test]
    fn missing_identifier_defaults_to_kernel() {
        // jq emits the key even when the journal value is null.
        let line = r#"{"SYSLOG_IDENTIFIER":null,"MESSAGE":"oom-killer invoked"}"#;
        assert_eq!(
            ConsoleLine::parse(line),
            ConsoleLine::Journal {
                source: "kernel".to_string(),
                message: "oom-killer invoked".to_string(),
            }
        );
    }

    #[test]
    fn reassembles_a_byte_array_message() {
        // journald renders a multi-line MESSAGE as a byte array; "ab\ncd".
        let line = r#"{"SYSLOG_IDENTIFIER":"idle","MESSAGE":[97,98,10,99,100]}"#;
        assert_eq!(
            ConsoleLine::parse(line),
            ConsoleLine::Journal {
                source: "idle".to_string(),
                message: "ab\ncd".to_string(),
            }
        );
    }

    #[test]
    fn raw_kernel_printk_passes_through() {
        let line = "[    0.123456] Linux version 6.18.0";
        assert_eq!(ConsoleLine::parse(line), ConsoleLine::Raw(line.to_string()));
    }

    #[test]
    fn non_object_json_is_raw() {
        // A bare JSON scalar or array on the console isn't one of our records.
        assert_eq!(ConsoleLine::parse("42"), ConsoleLine::Raw("42".to_string()));
        let obj_without_message = r#"{"SYSLOG_IDENTIFIER":"x"}"#;
        assert_eq!(
            ConsoleLine::parse(obj_without_message),
            ConsoleLine::Raw(obj_without_message.to_string())
        );
    }
}
