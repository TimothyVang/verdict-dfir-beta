//! Golden-frame snapshot tests.
//!
//! Each test loads one of the committed sample-run case directories, renders
//! a frame with `ratatui`'s headless `TestBackend` (via
//! [`verdict_tui::ui::render_to_string`]), and compares the plain-text buffer
//! against a committed snapshot under `tests/snapshots/`.
//!
//! The two fixtures are chosen to exercise the two ends of the rendering:
//!   * `nitroba` — INDETERMINATE, all non-CONFIRMED, an embedded coverage
//!     manifest whose class list wraps in the header (the degrade path).
//!   * `attack-samples-evtx` — SUSPICIOUS with a CONFIRMED finding (tier
//!     colouring) and no coverage manifest ("not produced by this run").
//!
//! Regenerate after an intentional UI change with:
//!   `UPDATE_SNAPSHOTS=1 cargo test -p verdict-tui`

use std::path::{Path, PathBuf};

use verdict_tui::app::{App, View};
use verdict_tui::case::{AuditRecord, CaseBundle, Finding, RunStatus};
use verdict_tui::live::state::LiveState;
use verdict_tui::live::ui as live_ui;
use verdict_tui::ui;

const WIDTH: u16 = 100;
const HEIGHT: u16 = 40;

fn fixture_dir(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/sample-run")
        .join(name)
}

fn snapshot_path(file: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/snapshots")
        .join(file)
}

fn load_app(name: &str) -> App {
    let dir = fixture_dir(name);
    let case = CaseBundle::load(&dir).expect("fixture case directory must load");
    App::new(case)
}

/// Compare `actual` against the committed snapshot `file`, or rewrite it
/// when `UPDATE_SNAPSHOTS` is set.
fn check(file: &str, actual: &str) {
    let path = snapshot_path(file);
    if std::env::var_os("UPDATE_SNAPSHOTS").is_some() {
        let parent = path.parent().expect("snapshot path has a parent");
        std::fs::create_dir_all(parent).expect("create snapshot dir");
        std::fs::write(&path, actual).expect("write snapshot");
        return;
    }
    let expected = std::fs::read_to_string(&path).unwrap_or_else(|_| {
        panic!(
            "missing snapshot {}; regenerate with UPDATE_SNAPSHOTS=1",
            path.display()
        )
    });
    assert_eq!(actual, expected, "snapshot mismatch for {file}");
}

#[test]
fn nitroba_list_view() {
    let mut app = load_app("nitroba");
    let frame = ui::render_to_string(&mut app, WIDTH, HEIGHT);
    check("nitroba.list.txt", &frame);
}

#[test]
fn nitroba_detail_view() {
    let mut app = load_app("nitroba");
    app.view = View::Detail; // App::new selects the first finding
    let frame = ui::render_to_string(&mut app, WIDTH, HEIGHT);
    check("nitroba.detail.txt", &frame);
}

#[test]
fn attack_samples_list_view() {
    let mut app = load_app("attack-samples-evtx");
    let frame = ui::render_to_string(&mut app, WIDTH, HEIGHT);
    check("attack-samples-evtx.list.txt", &frame);
}

#[test]
fn attack_samples_detail_view_confirmed() {
    let mut app = load_app("attack-samples-evtx");
    // Index 0 is the CONFIRMED f-A-evtx-audit-log-cleared finding.
    app.view = View::Detail;
    let frame = ui::render_to_string(&mut app, WIDTH, HEIGHT);
    check("attack-samples-evtx.detail.txt", &frame);
}

/// The Live monitor renders a streaming case: a `status.json` heartbeat plus a
/// handful of audit records, mid-run. Built from a synthetic [`LiveState`] so
/// the frame is deterministic (no clock, no filesystem, no subprocess).
#[test]
fn live_tailing_view() {
    fn record(seq: i64, kind: &str, tool: Option<&str>, tcid: Option<&str>) -> AuditRecord {
        AuditRecord {
            seq: Some(seq),
            kind: kind.to_string(),
            ts: None,
            tool: tool.map(ToString::to_string),
            tool_call_id: tcid.map(ToString::to_string),
            confidence: None,
            metric: None,
        }
    }

    let mut state = LiveState::new("/cases/tmp/auto-runs/tui-fixture");
    state.set_status(Some(RunStatus {
        case_id: Some("tui-fixture".into()),
        stage: Some("pool_a".into()),
        tool_calls: Some(3),
        findings_so_far: Some(1),
        updated_at: Some("2026-07-04T00:01:00Z".into()),
    }));
    state.ingest(vec![
        record(1, "case_open", None, None),
        record(2, "tool_call_start", Some("evtx_query"), Some("tc-001")),
        record(3, "tool_call_output", None, Some("tc-001")),
        AuditRecord {
            seq: Some(4),
            kind: "finding_approved".into(),
            confidence: Some("CONFIRMED".into()),
            ..AuditRecord::default()
        },
    ]);

    let frame = live_ui::render_to_string(&state, WIDTH, HEIGHT);
    check("live-tailing.txt", &frame);
}

/// No committed fixture carries a replay SHA-256 mismatch, so exercise that
/// custody-drift path with a synthetic case bundle built directly.
#[test]
fn detail_marks_replay_sha_mismatch() {
    let finding = Finding {
        finding_id: Some("f-synthetic".into()),
        confidence: Some("CONFIRMED".into()),
        replay_expected_sha256: Some("aaaaaaaa".into()),
        replay_actual_sha256: Some("bbbbbbbb".into()),
        replay_matched: Some(false),
        ..Finding::default()
    };
    let case = CaseBundle {
        dir: PathBuf::from("/case/synthetic"),
        verdict_word: Some("SUSPICIOUS".into()),
        case_id: Some("c-synthetic".into()),
        findings: vec![finding],
        tally: None,
        artifact_classes: None,
        manifest_verify: None,
    };
    let mut app = App::new(case);
    app.view = View::Detail;
    let frame = ui::render_to_string(&mut app, WIDTH, HEIGHT);
    assert!(
        frame.contains("SHA-256 MISMATCH"),
        "detail pane must flag a replay SHA mismatch; got:\n{frame}"
    );
}

/// Absent optional siblings render as "not produced by this run" — never a
/// fabricated custody or coverage claim.
#[test]
fn absent_custody_and_coverage_render_not_produced() {
    let case = CaseBundle {
        dir: PathBuf::from("/case/bare"),
        verdict_word: Some("NO_EVIL".into()),
        case_id: None,
        findings: Vec::new(),
        tally: None,
        artifact_classes: None,
        manifest_verify: None,
    };
    let mut app = App::new(case);
    let frame = ui::render_to_string(&mut app, WIDTH, HEIGHT);
    assert!(frame.contains("manifest_verify.json not produced by this run"));
    assert!(frame.contains("coverage manifest not produced by this run"));
    assert!(frame.contains("no findings in this case"));
}
