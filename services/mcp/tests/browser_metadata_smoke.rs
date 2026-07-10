//! Browser-artifact breadth contract for the existing `browser_history` tool.
//!
//! These fixtures deliberately contain secret values in columns that the tool
//! must never query or serialize. The public test surface is the same typed
//! tool interface used by MCP callers; no private parser helper is exercised.

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::path::{Path, PathBuf};

use findevil_mcp::{browser_history, BrowserHistoryInput, BrowserHistoryOutput};
use rusqlite::{params, Connection};
use serde_json::Value;

const COOKIE_VALUE_SECRET: &str = "COOKIE-PLAINTEXT-SECRET";
const COOKIE_ENCRYPTED_SECRET: &[u8] = b"COOKIE-ENCRYPTED-SECRET";
const AUTOFILL_VALUE_SECRET_1: &str = "AUTOFILL-VALUE-SECRET-ONE";
const AUTOFILL_VALUE_SECRET_2: &str = "AUTOFILL-VALUE-SECRET-TWO";
const PASSWORD_BLOB_SECRET: &[u8] = b"PASSWORD-BLOB-SECRET";
const FORM_DATA_SECRET: &[u8] = b"FORM-DATA-SECRET";
const PASSWORD_NOTE_SECRET: &[u8] = b"PASSWORD-NOTE-SECRET";

fn input(path: PathBuf, limit: Option<usize>) -> BrowserHistoryInput {
    BrowserHistoryInput {
        case_id: "browser-metadata-case".to_string(),
        history_path: path,
        limit,
    }
}

fn json(output: BrowserHistoryOutput) -> Value {
    serde_json::to_value(output).expect("serialize browser output")
}

fn rows(output: &Value) -> &[Value] {
    output["rows"].as_array().expect("rows array")
}

fn assert_row_keys(row: &Value, expected: &[&str]) {
    let actual = row
        .as_object()
        .expect("object row")
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    let expected = expected
        .iter()
        .map(|key| (*key).to_string())
        .collect::<BTreeSet<_>>();
    assert_eq!(actual, expected);
}

fn assert_no_sqlite_sidecars(path: &Path) {
    let file_name = path.file_name().expect("database file name");
    for suffix in ["-wal", "-journal", "-shm"] {
        let mut sidecar_name = OsString::from(file_name);
        sidecar_name.push(suffix);
        assert!(
            !path.with_file_name(sidecar_name).exists(),
            "read created SQLite sidecar {suffix}"
        );
    }
}

fn create_chromium_history(path: &Path) {
    let conn = Connection::open(path).expect("open History fixture");
    conn.execute_batch(
        "CREATE TABLE urls (
             id INTEGER PRIMARY KEY,
             url TEXT NOT NULL,
             title TEXT,
             visit_count INTEGER NOT NULL,
             last_visit_time INTEGER NOT NULL
         );
         CREATE TABLE visits (
             id INTEGER PRIMARY KEY,
             url INTEGER NOT NULL,
             visit_time INTEGER NOT NULL
         );
         CREATE TABLE downloads (
             id INTEGER PRIMARY KEY,
             current_path TEXT NOT NULL,
             target_path TEXT NOT NULL,
             start_time INTEGER NOT NULL,
             received_bytes INTEGER NOT NULL,
             total_bytes INTEGER NOT NULL,
             state INTEGER NOT NULL,
             danger_type INTEGER NOT NULL,
             interrupt_reason INTEGER NOT NULL,
             end_time INTEGER NOT NULL,
             opened INTEGER NOT NULL,
             referrer TEXT NOT NULL
         );
         CREATE TABLE downloads_url_chains (
             id INTEGER NOT NULL,
             chain_index INTEGER NOT NULL,
             url TEXT NOT NULL,
             PRIMARY KEY (id, chain_index)
         );",
    )
    .expect("create History schema");
    conn.execute(
        "INSERT INTO urls (id, url, title, visit_count, last_visit_time)
         VALUES (1, ?1, 'landing', 2, 13253932800000000)",
        ["https://download.example/landing"],
    )
    .expect("insert visit");
    conn.execute(
        "INSERT INTO downloads (
             id, current_path, target_path, start_time, received_bytes,
             total_bytes, state, danger_type, interrupt_reason, end_time,
             opened, referrer
         ) VALUES (
             7, 'C:\\Temp\\payload.exe.crdownload',
             'C:\\Users\\analyst\\Downloads\\payload.exe',
             13254019200000000, 4096, 4096, 1, 0, 0,
             13254019260000000, 1, 'https://download.example/landing'
         )",
        [],
    )
    .expect("insert download");
    conn.execute(
        "INSERT INTO downloads_url_chains (id, chain_index, url) VALUES (7, 0, ?1)",
        ["https://download.example/redirect"],
    )
    .expect("insert initial URL");
    conn.execute(
        "INSERT INTO downloads_url_chains (id, chain_index, url) VALUES (7, 1, ?1)",
        ["https://cdn.example/payload.exe"],
    )
    .expect("insert final URL");
}

#[test]
fn chromium_history_returns_visits_and_downloads_in_one_tagged_stream() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("History");
    create_chromium_history(&path);

    let output = json(browser_history(&input(path, None)).expect("parse History"));
    assert_eq!(output["schema_version"], 2);
    assert_eq!(output["browser_family"], "chrome");
    assert_eq!(output["artifact_kind"], "chromium_history");
    assert_eq!(output["rows_seen"], 2);
    assert_eq!(output["truncated"], false);

    let records = rows(&output);
    assert_eq!(records[0]["record_type"], "download");
    assert_eq!(
        records[0]["source_url"],
        "https://download.example/redirect"
    );
    assert_eq!(records[0]["final_url"], "https://cdn.example/payload.exe");
    assert_eq!(
        records[0]["target_path"],
        "C:\\Users\\analyst\\Downloads\\payload.exe"
    );
    assert_eq!(records[0]["start_time_iso"], "2021-01-02T00:00:00Z");
    assert_eq!(records[0]["end_time_iso"], "2021-01-02T00:01:00Z");
    assert_eq!(records[0]["total_bytes"], 4096);
    assert_eq!(records[0]["opened"], true);

    assert_eq!(records[1]["record_type"], "visit");
    assert_eq!(records[1]["url_id"], 1);
    assert_eq!(records[1]["url"], "https://download.example/landing");
    assert_eq!(records[1]["last_visit_time_iso"], "2021-01-01T00:00:00Z");
    assert_row_keys(
        &records[0],
        &[
            "record_type",
            "download_id",
            "source_url",
            "final_url",
            "current_path",
            "target_path",
            "referrer_url",
            "start_time_iso",
            "end_time_iso",
            "received_bytes",
            "total_bytes",
            "state",
            "danger_type",
            "interrupt_reason",
            "opened",
        ],
    );
    assert_row_keys(
        &records[1],
        &[
            "record_type",
            "url_id",
            "url",
            "title",
            "last_visit_time_iso",
            "visit_count",
        ],
    );
}

#[test]
fn limit_is_global_across_mixed_chromium_history_records() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("History");
    create_chromium_history(&path);

    let output = json(browser_history(&input(path, Some(1))).expect("parse History"));
    assert_eq!(output["rows_seen"], 1);
    assert_eq!(output["truncated"], true);
    assert_eq!(rows(&output).len(), 1);
    assert_eq!(rows(&output)[0]["record_type"], "download");
}

#[test]
fn mixed_history_limit_uses_native_microseconds_before_iso_truncation() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("History");
    create_chromium_history(&path);
    let conn = Connection::open(&path).expect("reopen History fixture");
    // Both serialize to the same whole ISO second. The visit is nevertheless
    // 800,000 microseconds newer and must win the one-row global limit.
    conn.execute("UPDATE urls SET last_visit_time = 13253932800900000", [])
        .expect("move visit within second");
    conn.execute("UPDATE downloads SET start_time = 13253932800100000", [])
        .expect("move download within second");
    drop(conn);

    let output = json(browser_history(&input(path, Some(1))).expect("parse History"));
    assert_eq!(rows(&output)[0]["record_type"], "visit");
}

#[test]
fn legacy_chromium_download_schema_keeps_visits_and_projects_downloads() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("History");
    let conn = Connection::open(&path).expect("open legacy History fixture");
    conn.execute_batch(
        "CREATE TABLE urls (
             id INTEGER PRIMARY KEY,
             url TEXT NOT NULL,
             title TEXT,
             visit_count INTEGER NOT NULL,
             last_visit_time INTEGER NOT NULL
         );
         CREATE TABLE visits (
             id INTEGER PRIMARY KEY,
             url INTEGER NOT NULL,
             visit_time INTEGER NOT NULL
         );
         CREATE TABLE downloads (
             id INTEGER PRIMARY KEY,
             full_path TEXT NOT NULL,
             url TEXT NOT NULL,
             start_time INTEGER NOT NULL,
             received_bytes INTEGER NOT NULL,
             total_bytes INTEGER NOT NULL,
             state INTEGER NOT NULL,
             end_time INTEGER NOT NULL,
             opened INTEGER NOT NULL
         );
         INSERT INTO urls VALUES (
             1, 'https://legacy.example/landing', 'legacy', 1,
             13253932800000000
         );
         INSERT INTO downloads VALUES (
             3, 'C:\\Users\\analyst\\Downloads\\legacy.zip',
             'https://legacy.example/legacy.zip', 1609545600,
             2048, 2048, 1, 1609545660, 1
         );",
    )
    .expect("create legacy History schema");
    drop(conn);

    let output = json(browser_history(&input(path, None)).expect("parse legacy History"));
    assert_eq!(output["rows_seen"], 2);
    assert_eq!(rows(&output)[0]["record_type"], "download");
    assert_eq!(
        rows(&output)[0]["source_url"],
        "https://legacy.example/legacy.zip"
    );
    assert_eq!(
        rows(&output)[0]["final_url"],
        "https://legacy.example/legacy.zip"
    );
    assert_eq!(rows(&output)[0]["start_time_iso"], "2021-01-02T00:00:00Z");
    assert_eq!(rows(&output)[0]["end_time_iso"], "2021-01-02T00:01:00Z");
    assert!(rows(&output)[0]["danger_type"].is_null());
    assert!(rows(&output)[0]["interrupt_reason"].is_null());
    assert_eq!(rows(&output)[1]["record_type"], "visit");
}

#[test]
fn caller_limit_above_safety_maximum_is_rejected() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("History");
    create_chromium_history(&path);

    let error = browser_history(&input(path, Some(10_001))).expect_err("reject huge limit");
    assert!(error.to_string().contains("maximum 10000"));
}

#[test]
fn chromium_cookies_returns_metadata_without_values() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("Cookies");
    let conn = Connection::open(&path).expect("open Cookies fixture");
    conn.execute_batch(
        "CREATE TABLE cookies (
             creation_utc INTEGER NOT NULL,
             host_key TEXT NOT NULL,
             top_frame_site_key TEXT NOT NULL,
             name TEXT NOT NULL,
             value TEXT NOT NULL,
             encrypted_value BLOB NOT NULL,
             path TEXT NOT NULL,
             expires_utc INTEGER NOT NULL,
             is_secure INTEGER NOT NULL,
             is_httponly INTEGER NOT NULL,
             last_access_utc INTEGER NOT NULL,
             has_expires INTEGER NOT NULL,
             is_persistent INTEGER NOT NULL,
             priority INTEGER NOT NULL,
             samesite INTEGER NOT NULL,
             source_scheme INTEGER NOT NULL,
             source_port INTEGER NOT NULL,
             last_update_utc INTEGER NOT NULL,
             source_type INTEGER NOT NULL,
             has_cross_site_ancestor INTEGER NOT NULL
         );",
    )
    .expect("create Cookies schema");
    conn.execute(
        "INSERT INTO cookies VALUES (
             13253932800000000, '.example.test', 'https://example.test',
             'session', ?1, ?2, '/', 13256611200000000, 1, 1,
             13254105600000000, 1, 1, 1, 1, 2, 443,
             13254192000000000, 1, 0
         )",
        params![COOKIE_VALUE_SECRET, COOKIE_ENCRYPTED_SECRET],
    )
    .expect("insert cookie");
    drop(conn);

    let parsed = browser_history(&input(path.clone(), None)).expect("parse Cookies");
    assert_no_sqlite_sidecars(&path);
    let serialized = serde_json::to_string(&parsed).expect("serialize Cookies");
    assert!(!serialized.contains(COOKIE_VALUE_SECRET));
    assert!(!serialized.contains("COOKIE-ENCRYPTED-SECRET"));
    assert!(!serialized.contains("encrypted_value"));

    let output = json(parsed);
    assert_eq!(output["artifact_kind"], "chromium_cookies");
    assert_eq!(rows(&output)[0]["record_type"], "cookie_metadata");
    assert_eq!(rows(&output)[0]["host"], ".example.test");
    assert_eq!(rows(&output)[0]["name"], "session");
    assert_eq!(
        rows(&output)[0]["last_access_time_iso"],
        "2021-01-03T00:00:00Z"
    );
    assert_eq!(rows(&output)[0]["is_secure"], true);
    assert_eq!(rows(&output)[0]["is_http_only"], true);
    assert_eq!(rows(&output)[0]["priority"], 1);
    assert_eq!(rows(&output)[0]["has_cross_site_ancestor"], false);
    assert_row_keys(
        &rows(&output)[0],
        &[
            "record_type",
            "host",
            "name",
            "path",
            "top_frame_site_key",
            "creation_time_iso",
            "expires_time_iso",
            "last_access_time_iso",
            "last_update_time_iso",
            "is_secure",
            "is_http_only",
            "has_expires",
            "is_persistent",
            "same_site",
            "source_scheme",
            "source_port",
            "source_type",
            "priority",
            "has_cross_site_ancestor",
        ],
    );
}

#[test]
fn legacy_chromium_cookie_flag_aliases_remain_parseable() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("Cookies");
    let conn = Connection::open(&path).expect("open legacy Cookies fixture");
    conn.execute_batch(
        "CREATE TABLE cookies (
             creation_utc INTEGER NOT NULL,
             host_key TEXT NOT NULL,
             name TEXT NOT NULL,
             value TEXT NOT NULL,
             path TEXT NOT NULL,
             expires_utc INTEGER NOT NULL,
             secure INTEGER NOT NULL,
             httponly INTEGER NOT NULL,
             last_access_utc INTEGER NOT NULL,
             persistent INTEGER NOT NULL
         );
         INSERT INTO cookies VALUES (
             13253932800000000, '.legacy-cookie.example', 'sid',
             'never-return-this-value', '/', 13256611200000000,
             1, 1, 13254105600000000, 1
         );",
    )
    .expect("create legacy Cookies schema");
    drop(conn);

    let output = json(browser_history(&input(path, None)).expect("parse legacy Cookies"));
    let row = &rows(&output)[0];
    assert_eq!(row["host"], ".legacy-cookie.example");
    assert_eq!(row["is_secure"], true);
    assert_eq!(row["is_http_only"], true);
    assert_eq!(row["is_persistent"], true);
    assert!(!serde_json::to_string(row)
        .expect("serialize row")
        .contains("never-return-this-value"));
}

fn create_cookie_tie_fixture(path: &Path, reverse: bool) {
    let conn = Connection::open(path).expect("open Cookies tie fixture");
    conn.execute_batch(
        "CREATE TABLE cookies (
             creation_utc INTEGER NOT NULL,
             host_key TEXT NOT NULL,
             top_frame_site_key TEXT NOT NULL,
             name TEXT NOT NULL,
             value TEXT NOT NULL,
             encrypted_value BLOB NOT NULL,
             path TEXT NOT NULL,
             expires_utc INTEGER NOT NULL,
             is_secure INTEGER NOT NULL,
             is_httponly INTEGER NOT NULL,
             last_access_utc INTEGER NOT NULL,
             has_expires INTEGER NOT NULL,
             is_persistent INTEGER NOT NULL,
             samesite INTEGER NOT NULL,
             source_scheme INTEGER NOT NULL,
             source_port INTEGER NOT NULL,
             last_update_utc INTEGER NOT NULL,
             source_type INTEGER NOT NULL
         );",
    )
    .expect("create Cookies tie schema");
    let records = if reverse {
        [("https://b.example", 8443), ("https://a.example", 443)]
    } else {
        [("https://a.example", 443), ("https://b.example", 8443)]
    };
    for (top_frame, port) in records {
        conn.execute(
            "INSERT INTO cookies VALUES (
                 13253932800000000, '.example.test', ?1, 'sid', '', X'', '/',
                 13256611200000000, 1, 1, 13254105600000000, 1, 1, 1, 2,
                 ?2, 13254192000000000, 1
             )",
            params![top_frame, port],
        )
        .expect("insert tied cookie");
    }
}

#[test]
fn cookie_order_is_independent_of_insertion_order_for_partitioned_rows() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let forward_path = tmp.path().join("Cookies-forward");
    let reverse_path = tmp.path().join("Cookies-reverse");
    create_cookie_tie_fixture(&forward_path, false);
    create_cookie_tie_fixture(&reverse_path, true);

    let forward = json(browser_history(&input(forward_path, None)).expect("parse forward"));
    let reverse = json(browser_history(&input(reverse_path, None)).expect("parse reverse"));

    assert_eq!(rows(&forward), rows(&reverse));
    assert_eq!(rows(&forward)[0]["top_frame_site_key"], "https://a.example");
}

#[test]
fn chromium_web_data_aggregates_autofill_without_values() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("Web Data");
    let conn = Connection::open(&path).expect("open Web Data fixture");
    conn.execute_batch(
        "CREATE TABLE autofill (
             name TEXT,
             value TEXT,
             value_lower TEXT,
             date_created INTEGER DEFAULT 0,
             date_last_used INTEGER DEFAULT 0,
             count INTEGER DEFAULT 1,
             PRIMARY KEY (name, value)
         );",
    )
    .expect("create Web Data schema");
    conn.execute(
        "INSERT INTO autofill VALUES ('email', ?1, 'secret-one', 1609459200, 1609545600, 2)",
        [AUTOFILL_VALUE_SECRET_1],
    )
    .expect("insert first autofill value");
    conn.execute(
        "INSERT INTO autofill VALUES ('email', ?1, 'secret-two', 1609372800, 1609632000, 3)",
        [AUTOFILL_VALUE_SECRET_2],
    )
    .expect("insert second autofill value");
    drop(conn);

    let parsed = browser_history(&input(path.clone(), None)).expect("parse Web Data");
    assert_no_sqlite_sidecars(&path);
    let serialized = serde_json::to_string(&parsed).expect("serialize Web Data");
    assert!(!serialized.contains(AUTOFILL_VALUE_SECRET_1));
    assert!(!serialized.contains(AUTOFILL_VALUE_SECRET_2));

    let output = json(parsed);
    assert_eq!(output["artifact_kind"], "chromium_web_data");
    let row = &rows(&output)[0];
    assert_eq!(row["record_type"], "autofill_metadata");
    assert_eq!(row["field_name"], "email");
    assert_eq!(row["stored_value_count"], 2);
    assert_eq!(row["use_count"], 5);
    assert_eq!(row["created_time_iso"], "2020-12-31T00:00:00Z");
    assert_eq!(row["last_used_time_iso"], "2021-01-03T00:00:00Z");
    assert_row_keys(
        row,
        &[
            "record_type",
            "field_name",
            "stored_value_count",
            "use_count",
            "created_time_iso",
            "last_used_time_iso",
        ],
    );
}

#[test]
fn chromium_web_data_accepts_null_autofill_dates() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("Web Data");
    let conn = Connection::open(&path).expect("open Web Data fixture");
    conn.execute_batch(
        "CREATE TABLE autofill (
             name TEXT,
             value TEXT,
             date_created INTEGER,
             date_last_used INTEGER,
             count INTEGER DEFAULT 1
         );
         INSERT INTO autofill VALUES ('email', 'never-return-me', NULL, NULL, 1);",
    )
    .expect("create nullable Web Data schema");
    drop(conn);

    let output = json(browser_history(&input(path, None)).expect("parse nullable dates"));
    assert_eq!(rows(&output)[0]["created_time_iso"], Value::Null);
    assert_eq!(rows(&output)[0]["last_used_time_iso"], Value::Null);
}

#[test]
fn chromium_login_data_returns_metadata_without_credential_secrets() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("Login Data");
    let conn = Connection::open(&path).expect("open Login Data fixture");
    conn.execute_batch(
        "CREATE TABLE logins (
             origin_url TEXT NOT NULL,
             action_url TEXT,
             username_element TEXT,
             username_value TEXT,
             password_element TEXT,
             password_value BLOB,
             submit_element TEXT,
             signon_realm TEXT NOT NULL,
             date_created INTEGER NOT NULL,
             blacklisted_by_user INTEGER NOT NULL,
             scheme INTEGER NOT NULL,
             password_type INTEGER,
             times_used INTEGER,
             form_data BLOB,
             display_name TEXT,
             icon_url TEXT,
             federation_url TEXT,
             id INTEGER PRIMARY KEY,
             date_last_used INTEGER,
             date_password_modified INTEGER
         );
         CREATE TABLE password_notes (
             id INTEGER PRIMARY KEY,
             parent_id INTEGER,
             key TEXT,
             value BLOB,
             date_created INTEGER,
             confidential INTEGER
         );",
    )
    .expect("create Login Data schema");
    conn.execute(
        "INSERT INTO logins VALUES (
             'https://portal.example/login', 'https://portal.example/session',
             'email', 'analyst@example.test', 'password', ?1, 'submit',
             'https://portal.example/', 13253932800000000, 0, 0, 0, 4,
             ?2, 'Example Portal', 'https://portal.example/icon.png', '', 9,
             13254105600000000, 13254192000000000
         )",
        params![PASSWORD_BLOB_SECRET, FORM_DATA_SECRET],
    )
    .expect("insert login");
    conn.execute(
        "INSERT INTO password_notes VALUES (1, 9, 'note', ?1, 13253932800000000, 1)",
        [PASSWORD_NOTE_SECRET],
    )
    .expect("insert password note");
    drop(conn);

    let parsed = browser_history(&input(path.clone(), None)).expect("parse Login Data");
    assert_no_sqlite_sidecars(&path);
    let serialized = serde_json::to_string(&parsed).expect("serialize Login Data");
    for secret in [
        "PASSWORD-BLOB-SECRET",
        "FORM-DATA-SECRET",
        "PASSWORD-NOTE-SECRET",
    ] {
        assert!(!serialized.contains(secret));
    }
    for forbidden_field in ["password_value", "form_data", "password_notes"] {
        assert!(!serialized.contains(forbidden_field));
    }

    let output = json(parsed);
    assert_eq!(output["artifact_kind"], "chromium_login_data");
    let row = &rows(&output)[0];
    assert_eq!(row["record_type"], "login_metadata");
    assert_eq!(row["login_id"], 9);
    assert_eq!(row["origin_url"], "https://portal.example/login");
    assert_eq!(row["username"], "analyst@example.test");
    assert_eq!(row["signon_realm"], "https://portal.example/");
    assert_eq!(row["times_used"], 4);
    assert_eq!(row["last_used_time_iso"], "2021-01-03T00:00:00Z");
    assert_row_keys(
        row,
        &[
            "record_type",
            "login_id",
            "origin_url",
            "action_url",
            "username_element",
            "username",
            "signon_realm",
            "created_time_iso",
            "last_used_time_iso",
            "password_modified_time_iso",
            "blacklisted_by_user",
            "scheme",
            "password_type",
            "times_used",
            "display_name",
            "icon_url",
            "federation_url",
        ],
    );
}

#[test]
fn login_order_falls_back_to_created_time_when_last_used_is_null() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("Login Data");
    let conn = Connection::open(&path).expect("open Login Data fixture");
    conn.execute_batch(
        "CREATE TABLE logins (
             origin_url TEXT NOT NULL,
             signon_realm TEXT NOT NULL,
             date_created INTEGER NOT NULL,
             blacklisted_by_user INTEGER NOT NULL,
             scheme INTEGER NOT NULL,
             id INTEGER PRIMARY KEY,
             date_last_used INTEGER
         );
         INSERT INTO logins VALUES (
             'https://new.example', 'https://new.example',
             13253932800900000, 0, 0, 1, NULL
         );
         INSERT INTO logins VALUES (
             'https://old.example', 'https://old.example',
             13253932800000000, 0, 0, 2, 13253932800100000
         );",
    )
    .expect("create login ordering fixture");
    drop(conn);

    let output = json(browser_history(&input(path, None)).expect("parse login ordering"));
    assert_eq!(rows(&output)[0]["origin_url"], "https://new.example");
}

#[test]
fn legacy_login_seconds_and_nullable_times_used_remain_metadata_not_errors() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("Login Data");
    let conn = Connection::open(&path).expect("open legacy Login Data fixture");
    conn.execute_batch(
        "CREATE TABLE logins (
             origin_url TEXT NOT NULL,
             signon_realm TEXT NOT NULL,
             date_created INTEGER NOT NULL,
             blacklisted_by_user INTEGER NOT NULL,
             scheme INTEGER NOT NULL,
             times_used INTEGER,
             id INTEGER PRIMARY KEY
         );
         INSERT INTO logins VALUES (
             'https://legacy-login.example', 'https://legacy-login.example',
             1609459200, 0, 0, NULL, 1
         );",
    )
    .expect("create legacy login fixture");
    drop(conn);

    let output = json(browser_history(&input(path, None)).expect("parse legacy login"));
    assert_eq!(rows(&output)[0]["created_time_iso"], "2021-01-01T00:00:00Z");
    assert_eq!(rows(&output)[0]["times_used"], 0);
}

#[test]
fn login_order_treats_zero_last_used_as_never_used() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("Login Data");
    let conn = Connection::open(&path).expect("open Login Data fixture");
    conn.execute_batch(
        "CREATE TABLE logins (
             origin_url TEXT NOT NULL,
             signon_realm TEXT NOT NULL,
             date_created INTEGER NOT NULL,
             blacklisted_by_user INTEGER NOT NULL,
             scheme INTEGER NOT NULL,
             id INTEGER PRIMARY KEY,
             date_last_used INTEGER NOT NULL DEFAULT 0
         );
         INSERT INTO logins VALUES (
             'https://new-never-used.example', 'https://new-never-used.example',
             13253932800900000, 0, 0, 1, 0
         );
         INSERT INTO logins VALUES (
             'https://old-used.example', 'https://old-used.example',
             13253932800000000, 0, 0, 2, 13253932800100000
         );",
    )
    .expect("create zero last-used ordering fixture");
    drop(conn);

    let output = json(browser_history(&input(path, Some(1))).expect("parse login ordering"));
    assert_eq!(
        rows(&output)[0]["origin_url"],
        "https://new-never-used.example"
    );
}
