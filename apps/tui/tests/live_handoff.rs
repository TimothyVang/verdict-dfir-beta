//! Integration test: the live-tail → finalized-viewer hand-off composes.
//!
//! This drives the same non-terminal sequence the interactive driver's
//! `live_loop` performs — poll the growing `audit.jsonl`, read `status.json`,
//! detect the sealed `verdict.json`, drain the final records, then load the
//! finalized [`CaseBundle`] — against a case directory that grows on disk.
//! The interactive draw/key-poll loop and the `notify` watcher are the only
//! pieces this does not exercise (they need a TTY); everything that decides
//! *what* the viewer shows and *when* it hands off is covered here.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

use verdict_tui::case::audit_tail::FileFollower;
use verdict_tui::case::{status, CaseBundle};
use verdict_tui::live::state::{verdict_ready, LiveState, Phase};

fn append(path: &Path, bytes: &[u8]) {
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .expect("open audit.jsonl");
    file.write_all(bytes).expect("append");
    file.flush().expect("flush");
}

/// One iteration of the driver's per-tick work (minus draw + key + notify).
fn tick(state: &mut LiveState, follower: &mut FileFollower) {
    state.ingest(follower.poll().expect("poll"));
    state.set_status(status::read_status(&state.case_dir));
}

#[test]
fn live_tail_composes_into_a_finalized_handoff() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let case_dir = tmp.path().join("tui-e2e");
    fs::create_dir_all(&case_dir).expect("mkdir case");
    let audit = case_dir.join("audit.jsonl");

    let mut state = LiveState::new(&case_dir);
    let mut follower = FileFollower::new(&audit);

    // Before anything is written: launching, no verdict.
    tick(&mut state, &mut follower);
    assert_eq!(state.phase, Phase::Launching);
    assert!(!verdict_ready(&case_dir));

    // First heartbeat + first records.
    fs::write(
        case_dir.join(status::STATUS_FILE),
        r#"{"stage":"pool_a","tool_calls":1,"findings_so_far":0}"#,
    )
    .expect("write status");
    append(
        &audit,
        b"{\"seq\":1,\"kind\":\"case_open\",\"payload\":{}}\n\
          {\"seq\":2,\"kind\":\"tool_call_start\",\"payload\":{\"tool\":\"evtx_query\",\"tool_call_id\":\"tc-001\"}}\n",
    );
    tick(&mut state, &mut follower);
    assert_eq!(state.phase, Phase::Tailing);
    assert_eq!(state.count_of("case_open"), 1);
    assert_eq!(
        state.status.as_ref().and_then(|s| s.stage.as_deref()),
        Some("pool_a")
    );

    // A record is flushed WITHOUT its newline — held back, not shown yet.
    append(
        &audit,
        br#"{"seq":3,"kind":"finding_approved","payload":{"confidenc"#,
    );
    tick(&mut state, &mut follower);
    assert_eq!(
        state.count_of("finding_approved"),
        0,
        "an unterminated record must not surface"
    );

    // The run seals: the terminating newline lands in the same burst as the
    // verdict.json write. The driver's completion path drains once more before
    // handing off, so the trailing record must not be lost.
    append(&audit, b"e\":\"CONFIRMED\"}}\n");
    fs::write(
        case_dir.join("verdict.json"),
        r#"{"verdict":"SUSPICIOUS","case_id":"tui-e2e",
            "findings":[{"finding_id":"f-1","confidence":"CONFIRMED",
            "description":"synthetic"}]}"#,
    )
    .expect("write verdict.json");

    // Completion, mirroring live_loop: verdict_ready → final drain → load.
    assert!(verdict_ready(&case_dir));
    state.ingest(follower.poll().expect("final drain"));
    assert_eq!(
        state.count_of("finding_approved"),
        1,
        "the record completed at seal time must be captured before hand-off"
    );

    let bundle = CaseBundle::load(&case_dir).expect("finalized case loads");
    assert_eq!(bundle.verdict_word.as_deref(), Some("SUSPICIOUS"));
    assert_eq!(bundle.findings.len(), 1);
    state.mark_completed();
    assert_eq!(state.phase, Phase::Completed);
}
