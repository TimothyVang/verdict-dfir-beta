//! Browser schema/path edges kept separate from the metadata fixture matrix.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use findevil_mcp::{
    browser_history, path_looks_like_browser_history, BrowserArtifactRow, BrowserHistoryError,
    BrowserHistoryInput,
};
use rusqlite::Connection;

fn input(path: PathBuf) -> BrowserHistoryInput {
    BrowserHistoryInput {
        case_id: "browser-schema-edge-case".to_string(),
        history_path: path,
        limit: None,
    }
}

// Non-Apple Unix only: this proves the parser opens a non-UTF8 path without a
// lossy rewrite, which requires creating a file whose name holds a raw 0xff byte.
// Linux/BSD filesystems allow arbitrary byte sequences in names; macOS APFS/HFS+
// reject non-UTF8 filenames at creation, so the fixture cannot exist there.
#[cfg(all(unix, not(target_vendor = "apple")))]
#[test]
fn non_utf8_browser_database_path_is_opened_without_lossy_rewrite() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp
        .path()
        .join(OsString::from_vec(b"Cookies-\xff".to_vec()));
    let conn = Connection::open(&path).expect("open non-UTF8 Cookies fixture");
    conn.execute_batch(
        "CREATE TABLE cookies (
             creation_utc INTEGER NOT NULL,
             host_key TEXT NOT NULL,
             name TEXT NOT NULL,
             path TEXT NOT NULL,
             expires_utc INTEGER NOT NULL,
             is_secure INTEGER NOT NULL,
             is_httponly INTEGER NOT NULL,
             last_access_utc INTEGER NOT NULL
         );",
    )
    .expect("create non-UTF8 Cookies schema");
    drop(conn);

    let output = browser_history(&input(path)).expect("parse non-UTF8 path");
    assert_eq!(output.rows_seen, 0);
}

#[test]
fn path_predicate_matches_every_supported_browser_database_name() {
    for name in [
        "History",
        "places.sqlite",
        "Cookies",
        "Web Data",
        "Login Data",
    ] {
        assert!(
            path_looks_like_browser_history(Path::new(name)),
            "missing canonical browser database name: {name}"
        );
    }
}

#[test]
fn ambiguous_browser_schema_is_rejected_instead_of_guessing() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("ambiguous.sqlite");
    let conn = Connection::open(&path).expect("open ambiguous fixture");
    conn.execute_batch(
        "CREATE TABLE urls (id INTEGER);
         CREATE TABLE visits (id INTEGER);
         CREATE TABLE cookies (host_key TEXT);",
    )
    .expect("create ambiguous schema");
    drop(conn);

    let error = browser_history(&input(path)).expect_err("reject ambiguous schema");
    assert!(matches!(error, BrowserHistoryError::AmbiguousSchema(_)));
}

#[test]
fn fts_virtual_table_cannot_impersonate_a_browser_artifact_table() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("Cookies");
    let conn = Connection::open(&path).expect("open FTS fixture");
    conn.execute_batch(
        "CREATE VIRTUAL TABLE cookies USING fts5(
             creation_utc, host_key, name, path, expires_utc,
             is_secure, is_httponly, last_access_utc
         );
         CREATE TABLE pragma_table_list (
             schema TEXT, name TEXT, type TEXT
         );
         INSERT INTO pragma_table_list VALUES ('main', 'cookies', 'table');",
    )
    .expect("create FTS table and spoofed table-list relation");
    drop(conn);

    let error = browser_history(&input(path)).expect_err("reject virtual browser table");
    assert!(matches!(error, BrowserHistoryError::UnknownSchema(_)));
}

#[test]
fn amplified_schema_cardinality_is_rejected_before_artifact_queries() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("History");
    let conn = Connection::open(&path).expect("open amplified schema fixture");
    let mut schema = String::from(
        "CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT, title TEXT, \
         visit_count INTEGER, last_visit_time INTEGER); \
         CREATE TABLE visits (id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER);",
    );
    for index in 0..520 {
        write!(schema, "CREATE TABLE junk_{index} (value INTEGER);")
            .expect("append schema statement");
    }
    conn.execute_batch(&schema)
        .expect("create amplified schema");
    drop(conn);

    let error = browser_history(&input(path)).expect_err("reject amplified schema");
    assert!(matches!(error, BrowserHistoryError::ResourceLimit(_)));
    assert!(error.to_string().contains("schema"));
}

#[test]
fn recognized_table_missing_required_columns_is_rejected() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("Cookies");
    let conn = Connection::open(&path).expect("open incomplete fixture");
    conn.execute("CREATE TABLE cookies (host_key TEXT, name TEXT)", [])
        .expect("create incomplete schema");
    drop(conn);

    let error = browser_history(&input(path)).expect_err("reject incomplete schema");
    assert!(matches!(
        error,
        BrowserHistoryError::UnsupportedSchema {
            table: "cookies",
            ..
        }
    ));
}

#[test]
fn login_row_ids_distinguish_otherwise_identical_exposed_metadata() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("Login Data");
    let conn = Connection::open(&path).expect("open Login Data fixture");
    conn.execute_batch(
        "CREATE TABLE logins (
             origin_url TEXT NOT NULL,
             password_element TEXT,
             signon_realm TEXT NOT NULL,
             date_created INTEGER NOT NULL,
             blacklisted_by_user INTEGER NOT NULL,
             scheme INTEGER NOT NULL,
             id INTEGER PRIMARY KEY
         );
         INSERT INTO logins VALUES (
             'https://same.example', 'password-a', 'https://same.example',
             13253932800000000, 0, 0, 41
         );
         INSERT INTO logins VALUES (
             'https://same.example', 'password-b', 'https://same.example',
             13253932800000000, 0, 0, 42
         );",
    )
    .expect("create colliding login fixture");
    drop(conn);

    let output = browser_history(&input(path)).expect("parse Login Data");
    let ids = output
        .rows
        .iter()
        .map(|row| match row {
            BrowserArtifactRow::LoginMetadata(row) => row.login_id,
            _ => panic!("expected login metadata"),
        })
        .collect::<Vec<_>>();

    assert_eq!(ids, vec![41, 42]);
}

#[test]
fn autofill_zero_dates_do_not_mask_valid_group_timestamps() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("Web Data");
    let conn = Connection::open(&path).expect("open Web Data fixture");
    conn.execute_batch(
        "CREATE TABLE autofill (
             name TEXT, value TEXT, date_created INTEGER,
             date_last_used INTEGER, count INTEGER
         );
         INSERT INTO autofill VALUES ('email', 'unknown', 0, 0, 1);
         INSERT INTO autofill VALUES (
             'email', 'known', 1609459200, 1609545600, 1
         );",
    )
    .expect("create mixed-date autofill fixture");
    drop(conn);

    let output = browser_history(&input(path)).expect("parse Web Data");
    let BrowserArtifactRow::AutofillMetadata(row) = &output.rows[0] else {
        panic!("expected autofill metadata")
    };

    assert_eq!(
        row.created_time_iso.as_deref(),
        Some("2021-01-01T00:00:00Z")
    );
    assert_eq!(
        row.last_used_time_iso.as_deref(),
        Some("2021-01-02T00:00:00Z")
    );
}

fn create_tied_visit_fixture(path: &Path, firefox: bool, reverse: bool) {
    let conn = Connection::open(path).expect("open tied visit fixture");
    if firefox {
        conn.execute_batch(
            "CREATE TABLE moz_places (
                 id INTEGER PRIMARY KEY, url TEXT, title TEXT,
                 visit_count INTEGER, last_visit_date INTEGER
             );",
        )
        .expect("create Firefox schema");
    } else {
        conn.execute_batch(
            "CREATE TABLE urls (
                 id INTEGER PRIMARY KEY, url TEXT, title TEXT,
                 visit_count INTEGER, last_visit_time INTEGER
             );
             CREATE TABLE visits (id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER);",
        )
        .expect("create Chromium schema");
    }
    let table = if firefox { "moz_places" } else { "urls" };
    let time_column = if firefox {
        "last_visit_date"
    } else {
        "last_visit_time"
    };
    let timestamp = if firefox {
        1_609_459_200_000_000_i64
    } else {
        13_253_932_800_000_000_i64
    };
    let ids = if reverse {
        [2_i64, 1_i64]
    } else {
        [1_i64, 2_i64]
    };
    for id in ids {
        conn.execute(
            &format!(
                "INSERT INTO {table} (id, url, title, visit_count, {time_column}) \
                 VALUES (?1, 'https://tie.example', ?2, 1, ?3)"
            ),
            rusqlite::params![id, format!("title-{id}"), timestamp],
        )
        .expect("insert tied URL row");
    }
}

#[test]
fn tied_chromium_and_firefox_urls_have_total_stable_order() {
    let tmp = tempfile::tempdir().expect("tempdir");
    for (name, firefox) in [("History", false), ("places.sqlite", true)] {
        let forward_path = tmp.path().join(format!("forward-{name}"));
        let reverse_path = tmp.path().join(format!("reverse-{name}"));
        create_tied_visit_fixture(&forward_path, firefox, false);
        create_tied_visit_fixture(&reverse_path, firefox, true);

        let mut forward_input = input(forward_path);
        forward_input.limit = Some(1);
        let mut reverse_input = input(reverse_path);
        reverse_input.limit = Some(1);
        let forward = browser_history(&forward_input).expect("parse forward fixture");
        let reverse = browser_history(&reverse_input).expect("parse reverse fixture");
        let url_id = |row: &BrowserArtifactRow| match row {
            BrowserArtifactRow::Visit(row) => row.url_id,
            _ => panic!("expected visit row"),
        };

        assert_eq!(url_id(&forward.rows[0]), 1);
        assert_eq!(url_id(&reverse.rows[0]), 1);
    }
}
