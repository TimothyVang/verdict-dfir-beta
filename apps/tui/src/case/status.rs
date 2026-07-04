//! The live liveness projection over a running case's `status.json`.
//!
//! While a local run is in flight the engine writes a best-effort
//! `<case_dir>/status.json` (see `find_evil_auto.py::_heartbeat`) carrying the
//! current stage and running counters. This module projects the handful of
//! fields the Live view renders, defaulting every one to "absent" — a missing
//! or half-written status file is a rendering state, never an error. It is
//! read-only: it displays what the run reported and derives no Finding.

use std::path::Path;

use serde_json::Value;

/// The status filename the engine's heartbeat writes.
pub const STATUS_FILE: &str = "status.json";

/// A snapshot of a run's advertised progress. Every field is optional.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RunStatus {
    pub case_id: Option<String>,
    pub stage: Option<String>,
    pub tool_calls: Option<u64>,
    pub findings_so_far: Option<u64>,
    pub updated_at: Option<String>,
}

impl RunStatus {
    /// Project a parsed `status.json` value.
    #[must_use]
    pub fn from_value(value: &Value) -> Self {
        Self {
            case_id: string_field(value, "case_id"),
            stage: string_field(value, "stage"),
            tool_calls: value.get("tool_calls").and_then(Value::as_u64),
            findings_so_far: value.get("findings_so_far").and_then(Value::as_u64),
            updated_at: string_field(value, "updated_at"),
        }
    }
}

/// Read and project `<case_dir>/status.json`, or `None` when it is absent or
/// unparseable (a run that has not written its first heartbeat yet, or a
/// mid-write torn read — both retried on the next tick).
#[must_use]
pub fn read_status(case_dir: &Path) -> Option<RunStatus> {
    let text = std::fs::read_to_string(case_dir.join(STATUS_FILE)).ok()?;
    let value: Value = serde_json::from_str(&text).ok()?;
    Some(RunStatus::from_value(&value))
}

fn string_field(value: &Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn projects_the_heartbeat_fields() {
        let value = json!({
            "case_id": "tui-123",
            "run_id": "r-1",
            "stage": "pool_a",
            "started_at": "2026-07-04T00:00:00Z",
            "updated_at": "2026-07-04T00:01:00Z",
            "tool_calls": 7,
            "findings_so_far": 2,
        });
        let status = RunStatus::from_value(&value);
        assert_eq!(status.stage.as_deref(), Some("pool_a"));
        assert_eq!(status.tool_calls, Some(7));
        assert_eq!(status.findings_so_far, Some(2));
        assert_eq!(status.case_id.as_deref(), Some("tui-123"));
    }

    #[test]
    fn absent_fields_default_to_none() {
        let status = RunStatus::from_value(&json!({}));
        assert!(status.stage.is_none());
        assert!(status.tool_calls.is_none());
        assert!(status.findings_so_far.is_none());
    }

    #[test]
    fn read_status_is_none_when_file_absent() {
        let tmp = tempfile::tempdir().expect("tempdir");
        assert!(read_status(tmp.path()).is_none());
    }

    #[test]
    fn read_status_projects_a_written_file() {
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            tmp.path().join(STATUS_FILE),
            r#"{"stage":"correlate","tool_calls":12,"findings_so_far":3}"#,
        )
        .expect("write status");
        let status = read_status(tmp.path()).expect("status present");
        assert_eq!(status.stage.as_deref(), Some("correlate"));
        assert_eq!(status.tool_calls, Some(12));
    }
}
