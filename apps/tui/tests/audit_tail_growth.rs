//! Integration test: follow a synthetic `audit.jsonl` that grows on disk the
//! way a live run writes it — appended a record (or a fraction of one) at a
//! time, with the terminating newline sometimes arriving on a later write.
//!
//! This exercises the tricky part of the live tail — buffering a partial
//! trailing line across appends — against a real file and byte offsets, not
//! just in-memory chunks. It needs no terminal, watcher, or forensic tool.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

use verdict_tui::case::audit_tail::FileFollower;
use verdict_tui::case::AuditRecord;

/// Append raw bytes to `path`, flushing so the follower sees exactly this much.
fn append(path: &Path, bytes: &[u8]) {
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .expect("open audit.jsonl for append");
    file.write_all(bytes).expect("append bytes");
    file.flush().expect("flush");
}

fn kinds(records: &[AuditRecord]) -> Vec<String> {
    records.iter().map(|r| r.kind.clone()).collect()
}

#[test]
fn follows_a_growing_audit_log_with_mid_record_flushes() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let audit = tmp.path().join("audit.jsonl");
    let mut follower = FileFollower::new(&audit);

    // 1. File does not exist yet — polling is a no-op, not an error.
    assert!(follower.poll().expect("poll absent").is_empty());

    // 2. First whole record lands.
    append(
        &audit,
        br#"{"seq":1,"kind":"case_open","payload":{}}
"#,
    );
    assert_eq!(kinds(&follower.poll().expect("poll 1")), vec!["case_open"]);

    // 3. A record is flushed WITHOUT its terminating newline — the follower
    //    must buffer it and yield nothing yet.
    append(
        &audit,
        br#"{"seq":2,"kind":"tool_call_start","payload":{"tool":"evtx_query","tool_call_id":"tc-001"}}"#,
    );
    assert!(
        follower.poll().expect("poll partial").is_empty(),
        "a record with no trailing newline must be held back"
    );

    // 4. The newline arrives on the next write, completing record 2, and the
    //    next record is appended whole in the same write.
    append(
        &audit,
        b"\n{\"seq\":3,\"kind\":\"tool_call_output\",\"payload\":{\"tool_call_id\":\"tc-001\",\"row_count\":4}}\n",
    );
    let batch = follower.poll().expect("poll completing");
    assert_eq!(kinds(&batch), vec!["tool_call_start", "tool_call_output"]);
    assert_eq!(batch[0].tool.as_deref(), Some("evtx_query"));
    assert_eq!(batch[1].metric.as_deref(), Some("rows=4"));

    // 5. Nothing new since the last poll.
    assert!(follower.poll().expect("poll idle").is_empty());

    // 6. A single record dribbled in three sub-record writes yields exactly
    //    one record, only once the final newline lands.
    append(&audit, br#"{"seq":4,"kind":"fin"#);
    assert!(follower.poll().expect("poll frag a").is_empty());
    append(&audit, br#"ding_approved","payload":{"confidence":"CONF"#);
    assert!(follower.poll().expect("poll frag b").is_empty());
    append(&audit, b"IRMED\"}}\n");
    let last = follower.poll().expect("poll frag c");
    assert_eq!(kinds(&last), vec!["finding_approved"]);
    assert_eq!(last[0].confidence.as_deref(), Some("CONFIRMED"));
}
