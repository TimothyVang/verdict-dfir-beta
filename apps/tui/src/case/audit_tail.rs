//! Incremental tail of a running case's `audit.jsonl`.
//!
//! An append-only, hash-chained `audit.jsonl` is written line-by-line while a
//! run is in flight, and a reader may see a *partial* trailing line — the
//! writer can flush mid-record. This module re-implements the buffer-across-
//! appends behaviour the web dashboard solves in `apps/web/lib/audit-tail.ts`,
//! but in idiomatic Rust and at the byte level rather than the string level:
//! bytes are buffered until a `\n` terminates a line, so a multi-byte UTF-8
//! code point that straddles two appends is never decoded half-formed.
//!
//! # Read-only, presentation only
//!
//! The projection reads only the safe, structural fields of a record — its
//! `kind`, `seq`, `ts`, and the tool / tool-call-id / confidence / row-count
//! metadata. It never reads an evidence path, a tool `arguments` block, or a
//! Finding description, so the live stream cannot surface evidence content and
//! stays evidence-agnostic. Like the finalized viewer, it derives nothing that
//! could be mistaken for a Finding or a confidence change.

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use serde_json::Value;

/// One audit record projected for the live stream. Every field beyond `kind`
/// is optional — a record is rendered from whatever safe fields it carried.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuditRecord {
    /// Chain sequence number (`seq`), when present.
    pub seq: Option<i64>,
    /// The audit "kind" (`tool_call_start`, `finding_approved`, …). Defaults
    /// to `"unknown"` for a well-formed line that omits it.
    pub kind: String,
    /// ISO-8601Z timestamp, when present.
    pub ts: Option<String>,
    /// `payload.tool` — the tool name for tool-call records.
    pub tool: Option<String>,
    /// `payload.tool_call_id` — the citation id a Finding would reference.
    pub tool_call_id: Option<String>,
    /// `payload.confidence` — the tier on a Finding/verdict record.
    pub confidence: Option<String>,
    /// A compact, non-evidence metric line (e.g. `rows=4`), when derivable.
    pub metric: Option<String>,
}

impl AuditRecord {
    fn from_line(line: &[u8]) -> Option<Self> {
        let value: Value = serde_json::from_slice(line).ok()?;
        Some(Self::from_value(&value))
    }

    fn from_value(value: &Value) -> Self {
        let payload = value.get("payload");
        Self {
            seq: value.get("seq").and_then(Value::as_i64),
            kind: string_field(value, "kind").unwrap_or_else(|| "unknown".to_string()),
            ts: string_field(value, "ts"),
            tool: payload.and_then(|p| string_field(p, "tool")),
            tool_call_id: payload.and_then(|p| string_field(p, "tool_call_id")),
            confidence: payload.and_then(|p| string_field(p, "confidence")),
            metric: payload.and_then(metric_line),
        }
    }
}

/// The byte-level buffering core: feed it appended chunks, it yields the
/// records for every *complete* line and retains any partial trailing bytes
/// until a later append terminates them.
#[derive(Debug, Default)]
pub struct AuditTail {
    /// Bytes seen since the last newline — a partial line still in flight.
    partial: Vec<u8>,
}

impl AuditTail {
    /// A fresh tail with an empty partial-line buffer.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Append `chunk` and return a record for each newly completed line.
    ///
    /// Bytes past the last `\n` are held back as a partial line and folded
    /// into the next call, so a record split across two appends is parsed
    /// exactly once, when its terminating newline finally arrives.
    pub fn push(&mut self, chunk: &[u8]) -> Vec<AuditRecord> {
        self.partial.extend_from_slice(chunk);
        let Some(last_newline) = self.partial.iter().rposition(|&b| b == b'\n') else {
            // No complete line yet — keep buffering.
            return Vec::new();
        };
        // Split the buffer into the complete region (up to and including the
        // final newline) and the remaining partial line.
        let remainder = self.partial.split_off(last_newline + 1);
        let complete = std::mem::replace(&mut self.partial, remainder);
        complete
            .split(|&b| b == b'\n')
            .map(strip_cr)
            .filter(|line| !line.is_empty())
            .filter_map(AuditRecord::from_line)
            .collect()
    }

    /// Bytes currently held as an incomplete trailing line.
    #[must_use]
    pub const fn pending_len(&self) -> usize {
        self.partial.len()
    }

    /// Drop the partial-line buffer (used when the underlying file is
    /// truncated or rotated and the reader restarts from offset zero).
    pub fn reset(&mut self) {
        self.partial.clear();
    }
}

/// Follows a growing `audit.jsonl` from a byte offset.
///
/// Each [`poll`](FileFollower::poll) decodes the records newly appended since
/// the last call. A missing file is not an error — the follower simply yields
/// nothing until it appears.
#[derive(Debug)]
pub struct FileFollower {
    path: PathBuf,
    offset: u64,
    tail: AuditTail,
}

impl FileFollower {
    /// Follow `path`, starting from the beginning the first time it appears.
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            offset: 0,
            tail: AuditTail::new(),
        }
    }

    /// The path being followed.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Read whatever was appended since the last poll and return its records.
    ///
    /// # Errors
    /// Propagates an IO error other than "file not found" (a not-yet-created
    /// file is normal at the start of a run and yields an empty batch).
    pub fn poll(&mut self) -> io::Result<Vec<AuditRecord>> {
        let size = match std::fs::metadata(&self.path) {
            Ok(meta) => meta.len(),
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(err) => return Err(err),
        };
        if size < self.offset {
            // The file shrank — truncated or rotated. Restart from the top so
            // we never seek past EOF into stale bytes.
            self.offset = 0;
            self.tail.reset();
        }
        if size == self.offset {
            return Ok(Vec::new());
        }
        let mut file = File::open(&self.path)?;
        file.seek(SeekFrom::Start(self.offset))?;
        let mut buf = Vec::new();
        // Bound the read to the size we just stat'd so a concurrent append
        // does not desync the offset from what we actually consumed.
        let read = file.take(size - self.offset).read_to_end(&mut buf)?;
        self.offset += read as u64;
        Ok(self.tail.push(&buf))
    }
}

/// Strip a single trailing `\r` so CRLF-terminated lines decode cleanly.
const fn strip_cr(line: &[u8]) -> &[u8] {
    match line.split_last() {
        Some((b'\r', rest)) => rest,
        _ => line,
    }
}

fn string_field(value: &Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string)
}

/// Derive a compact, non-evidence metric from a payload — a count of rows or
/// records seen. Never surfaces a path, argument, or free-text field.
fn metric_line(payload: &Value) -> Option<String> {
    for key in ["row_count", "records_seen", "rows"] {
        if let Some(count) = payload.get(key).and_then(Value::as_u64) {
            return Some(format!("rows={count}"));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kinds(records: &[AuditRecord]) -> Vec<&str> {
        records.iter().map(|r| r.kind.as_str()).collect()
    }

    #[test]
    fn parses_a_single_complete_line() {
        let mut tail = AuditTail::new();
        let line = br#"{"seq":3,"kind":"tool_call_start","ts":"2026-06-12T16:29:32Z","payload":{"tool":"evtx_query","tool_call_id":"tc-001"}}
"#;
        let out = tail.push(line);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].kind, "tool_call_start");
        assert_eq!(out[0].seq, Some(3));
        assert_eq!(out[0].tool.as_deref(), Some("evtx_query"));
        assert_eq!(out[0].tool_call_id.as_deref(), Some("tc-001"));
        assert_eq!(tail.pending_len(), 0);
    }

    #[test]
    fn buffers_a_partial_line_until_its_newline_arrives() {
        let mut tail = AuditTail::new();
        // First append stops mid-record (writer flushed part of a line).
        let first = tail.push(br#"{"seq":1,"kind":"tool_ca"#);
        assert!(first.is_empty(), "no complete line yet");
        assert!(tail.pending_len() > 0, "partial line is buffered");

        // Second append completes the record and terminates it.
        let second = tail.push(b"ll_start\",\"payload\":{\"tool\":\"registry_query\"}}\n");
        assert_eq!(kinds(&second), vec!["tool_call_start"]);
        assert_eq!(second[0].tool.as_deref(), Some("registry_query"));
        assert_eq!(tail.pending_len(), 0);
    }

    #[test]
    fn a_newline_split_across_two_appends_yields_one_record() {
        let mut tail = AuditTail::new();
        // Whole record present but the terminating newline has not arrived.
        let none = tail.push(br#"{"seq":1,"kind":"agent_message"}"#);
        assert!(none.is_empty());
        // The newline is its own append (the classic partial-flush boundary).
        let one = tail.push(b"\n");
        assert_eq!(kinds(&one), vec!["agent_message"]);
    }

    #[test]
    fn splits_many_lines_in_one_append_and_keeps_the_trailing_partial() {
        let mut tail = AuditTail::new();
        let chunk = concat!(
            r#"{"seq":1,"kind":"case_open"}"#,
            "\n",
            r#"{"seq":2,"kind":"tool_call_start","payload":{"tool":"mft_timeline"}}"#,
            "\n",
            r#"{"seq":3,"kind":"tool_call_out"#, // trailing partial, no newline
        );
        let out = tail.push(chunk.as_bytes());
        assert_eq!(kinds(&out), vec!["case_open", "tool_call_start"]);
        assert!(tail.pending_len() > 0, "third record still buffering");

        let rest = tail.push(b"put\",\"payload\":{\"row_count\":4}}\n");
        assert_eq!(kinds(&rest), vec!["tool_call_output"]);
        assert_eq!(rest[0].metric.as_deref(), Some("rows=4"));
    }

    #[test]
    fn a_multibyte_utf8_char_split_across_appends_decodes_intact() {
        let mut tail = AuditTail::new();
        // The kind string carries a 4-byte code point (U+20BB7). Split it two
        // bytes in, so the first append ends mid-code-point — a naive
        // per-append UTF-8 decode would corrupt it. Byte buffering keeps the
        // line whole until the newline, so it decodes cleanly.
        let full = "{\"seq\":1,\"kind\":\"note-\u{20BB7}-x\"}".as_bytes();
        let char_start = "{\"seq\":1,\"kind\":\"note-".len();
        let split = char_start + 2; // inside the 4-byte sequence
        assert!(tail.push(&full[..split]).is_empty());
        let out = tail.push(&full[split..]);
        assert!(out.is_empty(), "still no newline");
        let done = tail.push(b"\n");
        assert_eq!(done.len(), 1);
        assert_eq!(done[0].kind, "note-\u{20BB7}-x");
    }

    #[test]
    fn skips_a_malformed_line_without_aborting_the_stream() {
        let mut tail = AuditTail::new();
        let chunk = concat!(
            r#"{"seq":1,"kind":"ok_before"}"#,
            "\n",
            "this is not json",
            "\n",
            r#"{"seq":3,"kind":"ok_after"}"#,
            "\n",
        );
        let out = tail.push(chunk.as_bytes());
        assert_eq!(kinds(&out), vec!["ok_before", "ok_after"]);
    }

    #[test]
    fn tolerates_crlf_line_endings_and_blank_lines() {
        let mut tail = AuditTail::new();
        let chunk = "{\"kind\":\"a\"}\r\n\r\n{\"kind\":\"b\"}\r\n";
        let out = tail.push(chunk.as_bytes());
        assert_eq!(kinds(&out), vec!["a", "b"]);
    }

    #[test]
    fn missing_confidence_and_metric_default_to_none() {
        let record =
            AuditRecord::from_line(br#"{"kind":"agent_message","payload":{}}"#).expect("parses");
        assert!(record.confidence.is_none());
        assert!(record.metric.is_none());
        assert!(record.tool.is_none());
    }

    #[test]
    fn projects_finding_confidence() {
        let record = AuditRecord::from_line(
            br#"{"seq":9,"kind":"finding_approved","payload":{"confidence":"CONFIRMED"}}"#,
        )
        .expect("parses");
        assert_eq!(record.confidence.as_deref(), Some("CONFIRMED"));
    }
}
