//! State for the Live monitor: a bounded ring of streamed audit records, the
//! latest `status.json` heartbeat, and the run phase.
//!
//! This is a small, pure value updated by the driver as it tails a case
//! directory — it performs no IO of its own, so it is unit-testable without a
//! terminal or a filesystem. It stores only what the run reported; it never
//! derives a Finding or changes a verdict.

use std::collections::{BTreeMap, VecDeque};
use std::path::{Path, PathBuf};

use crate::case::{AuditRecord, RunStatus};

/// How far a live run has progressed, from the viewer's vantage point.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// Spawned/attached but no audit record or status has appeared yet.
    Launching,
    /// Records are streaming in.
    Tailing,
    /// The run sealed a `verdict.json`; the finalized viewer can take over.
    Completed,
    /// The launcher exited without producing a `verdict.json`.
    Failed,
}

impl Phase {
    /// A short label for the header.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Launching => "LAUNCHING",
            Self::Tailing => "LIVE",
            Self::Completed => "COMPLETE",
            Self::Failed => "FAILED",
        }
    }
}

/// The most recent audit records shown in the stream. Older records scroll off
/// the top; the finalized `verdict.json` carries the full, sealed record.
const MAX_RECORDS: usize = 1000;

/// The live monitor state.
#[derive(Debug)]
pub struct LiveState {
    pub case_dir: PathBuf,
    pub display_name: String,
    pub phase: Phase,
    pub status: Option<RunStatus>,
    /// The tail of streamed records (bounded by [`MAX_RECORDS`]).
    pub records: VecDeque<AuditRecord>,
    /// Total records seen across the whole run (not just the retained tail).
    pub total_records: u64,
    /// Count of records per audit `kind`, for the header tally.
    pub kind_counts: BTreeMap<String, u64>,
    /// A launch/failure message to surface, if any.
    pub message: Option<String>,
}

impl LiveState {
    /// Build the initial state for a case directory being tailed.
    #[must_use]
    pub fn new(case_dir: impl Into<PathBuf>) -> Self {
        let case_dir = case_dir.into();
        let display_name = case_dir.file_name().map_or_else(
            || case_dir.to_string_lossy().into_owned(),
            |n| n.to_string_lossy().into_owned(),
        );
        Self {
            case_dir,
            display_name,
            phase: Phase::Launching,
            status: None,
            records: VecDeque::new(),
            total_records: 0,
            kind_counts: BTreeMap::new(),
            message: None,
        }
    }

    /// Fold a batch of newly tailed records into the state.
    pub fn ingest(&mut self, records: Vec<AuditRecord>) {
        if records.is_empty() {
            return;
        }
        if self.phase == Phase::Launching {
            self.phase = Phase::Tailing;
            // The "launching …" note is stale once records stream in.
            self.message = None;
        }
        for record in records {
            self.total_records += 1;
            *self.kind_counts.entry(record.kind.clone()).or_insert(0) += 1;
            self.records.push_back(record);
            if self.records.len() > MAX_RECORDS {
                self.records.pop_front();
            }
        }
    }

    /// Replace the current status snapshot (ignores a `None` refresh so a
    /// torn read never clears a previously good status).
    pub fn set_status(&mut self, status: Option<RunStatus>) {
        if let Some(status) = status {
            self.status = Some(status);
        }
    }

    /// Mark the run finished — its `verdict.json` is ready to load.
    pub const fn mark_completed(&mut self) {
        self.phase = Phase::Completed;
    }

    /// Mark the run failed with an operator-facing reason.
    pub fn mark_failed(&mut self, message: impl Into<String>) {
        self.phase = Phase::Failed;
        self.message = Some(message.into());
    }

    /// Set a transient status message (e.g. "waiting for the launcher").
    pub fn set_message(&mut self, message: impl Into<String>) {
        self.message = Some(message.into());
    }

    /// The count of records for one `kind`, or 0.
    #[must_use]
    pub fn count_of(&self, kind: &str) -> u64 {
        self.kind_counts.get(kind).copied().unwrap_or(0)
    }

    /// The most recent `n` records, oldest-first, for rendering.
    #[must_use]
    pub fn tail(&self, n: usize) -> Vec<&AuditRecord> {
        let start = self.records.len().saturating_sub(n);
        self.records.iter().skip(start).collect()
    }
}

/// True when a run's `verdict.json` exists — the completion signal that lets
/// the finalized viewer take over. A metadata check only; no evidence read.
#[must_use]
pub fn verdict_ready(case_dir: &Path) -> bool {
    case_dir.join(crate::case::loader::VERDICT_FILE).is_file()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(kind: &str) -> AuditRecord {
        AuditRecord {
            kind: kind.to_string(),
            ..AuditRecord::default()
        }
    }

    #[test]
    fn starts_in_launching_with_no_records() {
        let state = LiveState::new("/case/tui-1");
        assert_eq!(state.phase, Phase::Launching);
        assert_eq!(state.display_name, "tui-1");
        assert_eq!(state.total_records, 0);
    }

    #[test]
    fn first_batch_advances_to_tailing_and_counts_kinds() {
        let mut state = LiveState::new("/case/x");
        state.ingest(vec![
            record("case_open"),
            record("tool_call_start"),
            record("tool_call_start"),
        ]);
        assert_eq!(state.phase, Phase::Tailing);
        assert_eq!(state.total_records, 3);
        assert_eq!(state.count_of("tool_call_start"), 2);
        assert_eq!(state.count_of("case_open"), 1);
    }

    #[test]
    fn empty_ingest_is_a_noop() {
        let mut state = LiveState::new("/case/x");
        state.ingest(Vec::new());
        assert_eq!(state.phase, Phase::Launching);
        assert_eq!(state.total_records, 0);
    }

    #[test]
    fn ring_bounds_retained_records_but_not_the_total() {
        let mut state = LiveState::new("/case/x");
        let batch: Vec<AuditRecord> = (0..MAX_RECORDS + 50).map(|_| record("tick")).collect();
        state.ingest(batch);
        assert_eq!(state.records.len(), MAX_RECORDS);
        assert_eq!(state.total_records, (MAX_RECORDS + 50) as u64);
    }

    #[test]
    fn set_status_ignores_a_none_refresh() {
        let mut state = LiveState::new("/case/x");
        state.set_status(Some(RunStatus {
            stage: Some("pool_a".into()),
            ..RunStatus::default()
        }));
        state.set_status(None);
        assert_eq!(
            state.status.as_ref().and_then(|s| s.stage.as_deref()),
            Some("pool_a")
        );
    }

    #[test]
    fn tail_returns_the_most_recent_records() {
        let mut state = LiveState::new("/case/x");
        state.ingest(vec![record("a"), record("b"), record("c")]);
        let last_two = state.tail(2);
        assert_eq!(last_two.len(), 2);
        assert_eq!(last_two[0].kind, "b");
        assert_eq!(last_two[1].kind, "c");
    }
}
