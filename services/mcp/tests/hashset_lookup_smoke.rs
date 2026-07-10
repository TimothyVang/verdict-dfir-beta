//! Integration tests for `hashset_lookup`.
//!
//! Mirrors the `browser_history` smoke pattern: library-level error paths and
//! fixtures built on the fly (no checked-in binaries), plus an end-to-end
//! drive through the stdio server registry so schema advertisement, unknown-
//! field denial, and the `_meta` envelope are exercised on the real wire
//! shape. All hash values are synthetic test fixtures (evidence-agnostic).

use std::io::Cursor;
use std::sync::Mutex;

use findevil_mcp::server::run_stdio_server_with_streams;
use findevil_mcp::tools::{
    hashset_lookup, HashsetLookupError, HashsetLookupInput, LookupDisposition,
};
use rusqlite::Connection;
use serde_json::{json, Value};

/// Synthetic MD5-length hex (32 chars).
const MD5_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
/// Synthetic SHA-256-length hex (64 chars).
const SHA256_C: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

static ENV_LOCK: Mutex<()> = Mutex::new(());

fn sample_input(hashes: &[&str]) -> HashsetLookupInput {
    HashsetLookupInput {
        case_id: "test-case".to_string(),
        hashes: hashes.iter().map(ToString::to_string).collect(),
    }
}

struct RestoreEnv {
    name: &'static str,
    prior: Option<std::ffi::OsString>,
}

impl RestoreEnv {
    fn set(name: &'static str, value: impl AsRef<std::ffi::OsStr>) -> Self {
        let prior = std::env::var_os(name);
        std::env::set_var(name, value);
        Self { name, prior }
    }
}

impl Drop for RestoreEnv {
    fn drop(&mut self) {
        match self.prior.take() {
            Some(value) => std::env::set_var(self.name, value),
            None => std::env::remove_var(self.name),
        }
    }
}

/// Drive the real stdio server loop with one request line; return the
/// parsed JSON-RPC response.
fn drive(request: &Value) -> Value {
    drive_with_env(request, &[])
}

fn drive_with_env(request: &Value, env: &[(&'static str, std::ffi::OsString)]) -> Value {
    let _guard = ENV_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let case_id = request["params"]["arguments"]["case_id"]
        .as_str()
        .unwrap_or("smoke-case");
    let _binding = RestoreEnv::set(
        "FINDEVIL_BROWSER_CASE_BINDING",
        serde_json::to_string(&json!({"case_id": case_id, "artifacts": []})).unwrap(),
    );
    let _output_route = RestoreEnv::set("FINDEVIL_OUTPUT_ROUTE", "local_controller");
    let _restores = env
        .iter()
        .map(|(name, value)| RestoreEnv::set(name, value))
        .collect::<Vec<_>>();
    let line = format!("{request}\n");
    let mut output: Vec<u8> = Vec::new();
    run_stdio_server_with_streams(Cursor::new(line.into_bytes()), &mut output)
        .expect("server loop");
    serde_json::from_str(String::from_utf8(output).expect("utf-8").trim()).expect("json response")
}

#[test]
fn hashset_lookup_input_rejects_unknown_fields() {
    let body = r#"{"case_id":"c1","hashes":["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],"rogue_field":1}"#;
    let err = serde_json::from_str::<HashsetLookupInput>(body).unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("rogue_field") || msg.contains("unknown field"));
}

#[test]
fn hashset_lookup_rejects_invalid_hash() {
    let err = hashset_lookup(&sample_input(&["zz-not-hex"])).unwrap_err();
    assert!(matches!(
        err,
        HashsetLookupError::InvalidHash { index: 0, .. }
    ));
}

#[test]
fn hashset_lookup_text_fixture_end_to_end() {
    let _guard = ENV_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let tmp = tempfile::tempdir().expect("tempdir");
    let bad_dir = tmp.path().join("known_bad");
    std::fs::create_dir(&bad_dir).unwrap();
    let path = bad_dir.join("iocs.txt");
    std::fs::write(
        &path,
        format!("# comment\n{}\n", MD5_A.to_ascii_uppercase()),
    )
    .unwrap();

    let _root = RestoreEnv::set("FINDEVIL_HASHSET_DIR", tmp.path());
    let out = hashset_lookup(&sample_input(&[MD5_A, SHA256_C])).expect("lookup");
    assert_eq!(out.hashes_checked, 2);
    assert_eq!(out.results[0].hash, MD5_A);
    assert_eq!(out.results[0].disposition, LookupDisposition::KnownBad);
    assert_eq!(out.results[1].disposition, LookupDisposition::Unknown);
    assert_eq!(out.sets_loaded.len(), 1);
    assert!(out.sets_loaded[0].error.is_none());
}

#[test]
fn server_advertises_hashset_lookup_with_read_only_annotations() {
    let resp = drive(&json!({"jsonrpc":"2.0","id":1,"method":"tools/list"}));
    let tools = resp["result"]["tools"].as_array().expect("tools array");
    let tool = tools
        .iter()
        .find(|t| t["name"] == "hashset_lookup")
        .expect("hashset_lookup advertised");
    assert_eq!(tool["annotations"]["readOnlyHint"], true);
    assert_eq!(tool["annotations"]["destructiveHint"], false);
    assert_eq!(tool["annotations"]["idempotentHint"], true);
    assert_eq!(tool["annotations"]["openWorldHint"], false);
    assert!(tool["inputSchema"].is_object());
}

#[test]
fn server_tools_call_matches_sqlite_fixture() {
    // Generic-schema SQLite fixture, driven through the real registry.
    let tmp = tempfile::tempdir().expect("tempdir");
    let bad_dir = tmp.path().join("known_bad");
    std::fs::create_dir(&bad_dir).unwrap();
    let db_path = bad_dir.join("smoke-iocs.sqlite");
    let conn = Connection::open(&db_path).unwrap();
    conn.execute("CREATE TABLE hashes (hash TEXT)", []).unwrap();
    conn.execute("INSERT INTO hashes (hash) VALUES (?1)", [SHA256_C])
        .unwrap();
    drop(conn);

    let resp = drive_with_env(
        &json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "hashset_lookup",
                "arguments": {
                    "case_id": "smoke-case",
                    "hashes": [SHA256_C.to_ascii_uppercase(), MD5_A]
                }
            }
        }),
        &[(
            "FINDEVIL_HASHSET_DIR",
            tmp.path().as_os_str().to_os_string(),
        )],
    );

    assert!(
        resp.get("error").is_none(),
        "tools/call must succeed: {resp}"
    );
    let text = resp["result"]["content"][0]["text"]
        .as_str()
        .expect("text content");
    let payload: Value = serde_json::from_str(text).expect("payload json");
    assert_eq!(payload["case_id"], "smoke-case");
    assert_eq!(payload["hashes_checked"], 2);
    // Sorted by hash: "aaa…" (unknown) before "ccc…" (known_bad).
    assert_eq!(payload["results"][0]["hash"], MD5_A);
    assert_eq!(payload["results"][0]["disposition"], "unknown");
    assert_eq!(payload["results"][1]["hash"], SHA256_C);
    assert_eq!(payload["results"][1]["disposition"], "known_bad");
    assert_eq!(payload["results"][1]["matched_sets"][0], "smoke-iocs");
    assert_eq!(payload["sets_loaded"][0]["kind"], "sqlite_generic");
    assert_eq!(resp["result"]["_meta"]["tool"], "hashset_lookup");
    assert!(resp["result"]["_meta"]["output_sha256"].is_string());
}

#[test]
fn server_tools_call_denies_unknown_argument_fields() {
    let resp = drive(&json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {
            "name": "hashset_lookup",
            "arguments": {
                "case_id": "smoke-case",
                "hashes": [MD5_A],
                "rogue_field": "nope"
            }
        }
    }));
    assert_eq!(
        resp["error"]["code"], -32602,
        "unknown field must be denied"
    );
    let msg = resp["error"]["message"].as_str().expect("message");
    assert!(msg.contains("rogue_field") || msg.contains("unknown field"));
}

#[test]
fn server_tools_call_rejects_bad_hash_as_invalid_params() {
    let resp = drive(&json!({
        "jsonrpc": "2.0",
        "id": 4,
        "method": "tools/call",
        "params": {
            "name": "hashset_lookup",
            "arguments": {"case_id": "smoke-case", "hashes": ["nope"]}
        }
    }));
    assert_eq!(resp["error"]["code"], -32602);
}

#[test]
fn server_rejects_all_caller_supplied_hashset_paths() {
    for (id, path) in [
        (10, "/dev/zero"),
        (11, "/proc"),
        (12, "/tmp/outside-operator-hashsets.txt"),
    ] {
        let resp = drive(&json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "tools/call",
            "params": {
                "name": "hashset_lookup",
                "arguments": {
                    "case_id": "smoke-case",
                    "hashes": [MD5_A],
                    "hashset_paths": [{"path": path, "disposition": "known_bad"}]
                }
            }
        }));
        assert_eq!(resp["error"]["code"], -32602, "path={path}: {resp}");
    }
}

#[cfg(unix)]
#[test]
fn server_rejects_symlinks_inside_operator_hashset_root() {
    use std::os::unix::fs::symlink;

    let tmp = tempfile::tempdir().expect("tempdir");
    let bad_dir = tmp.path().join("known_bad");
    std::fs::create_dir(&bad_dir).unwrap();
    let outside = tmp.path().join("outside.txt");
    std::fs::write(&outside, format!("{MD5_A}\n")).unwrap();
    symlink(&outside, bad_dir.join("escape.txt")).unwrap();
    let resp = drive_with_env(
        &json!({
            "jsonrpc": "2.0",
            "id": 13,
            "method": "tools/call",
            "params": {
                "name": "hashset_lookup",
                "arguments": {"case_id": "smoke-case", "hashes": [MD5_A]}
            }
        }),
        &[(
            "FINDEVIL_HASHSET_DIR",
            tmp.path().as_os_str().to_os_string(),
        )],
    );
    assert_eq!(resp["error"]["code"], -32603, "{resp}");
    assert!(resp["error"]["message"]
        .as_str()
        .is_some_and(|message| message.contains("symlink")));
}

#[test]
fn server_aborts_a_text_set_with_a_line_over_the_configured_cap() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let bad_dir = tmp.path().join("known_bad");
    std::fs::create_dir(&bad_dir).unwrap();
    std::fs::write(bad_dir.join("huge-line.txt"), "a".repeat(4096)).unwrap();
    let resp = drive_with_env(
        &json!({
            "jsonrpc": "2.0",
            "id": 14,
            "method": "tools/call",
            "params": {
                "name": "hashset_lookup",
                "arguments": {"case_id": "smoke-case", "hashes": [MD5_A]}
            }
        }),
        &[
            (
                "FINDEVIL_HASHSET_DIR",
                tmp.path().as_os_str().to_os_string(),
            ),
            ("FINDEVIL_HASHSET_MAX_LINE_BYTES", "64".into()),
        ],
    );
    assert_eq!(resp["error"]["code"], -32603, "{resp}");
    assert!(resp["error"]["message"]
        .as_str()
        .is_some_and(|message| message.contains("line byte limit")));
}

#[test]
fn server_enforces_set_file_and_total_byte_caps() {
    for (id, files, env_name, env_value, expected) in [
        (
            20,
            vec![
                ("one.txt", format!("{MD5_A}\n")),
                ("two.txt", format!("{MD5_A}\n")),
            ],
            "FINDEVIL_HASHSET_MAX_SETS",
            "1",
            "set count limit",
        ),
        (
            21,
            vec![("one.txt", "a".repeat(256))],
            "FINDEVIL_HASHSET_MAX_FILE_BYTES",
            "64",
            "file byte limit",
        ),
        (
            22,
            vec![("one.txt", "a".repeat(40)), ("two.txt", "b".repeat(40))],
            "FINDEVIL_HASHSET_MAX_TOTAL_BYTES",
            "64",
            "total byte limit",
        ),
    ] {
        let tmp = tempfile::tempdir().expect("tempdir");
        let bad_dir = tmp.path().join("known_bad");
        std::fs::create_dir(&bad_dir).unwrap();
        for (name, body) in files {
            std::fs::write(bad_dir.join(name), body).unwrap();
        }
        let resp = drive_with_env(
            &json!({
                "jsonrpc": "2.0",
                "id": id,
                "method": "tools/call",
                "params": {
                    "name": "hashset_lookup",
                    "arguments": {"case_id": "smoke-case", "hashes": [MD5_A]}
                }
            }),
            &[
                (
                    "FINDEVIL_HASHSET_DIR",
                    tmp.path().as_os_str().to_os_string(),
                ),
                (env_name, env_value.into()),
            ],
        );
        assert_eq!(resp["error"]["code"], -32603, "{resp}");
        assert!(
            resp["error"]["message"]
                .as_str()
                .is_some_and(|message| message.contains(expected)),
            "expected {expected}: {resp}"
        );
    }
}

#[test]
fn server_enforces_sqlite_operation_and_field_caps() {
    for (id, env_name, env_value, expected) in [
        (
            30,
            "FINDEVIL_HASHSET_SQLITE_MAX_OPS",
            "1",
            "SQLite operation limit",
        ),
        (
            31,
            "FINDEVIL_HASHSET_SQLITE_MAX_FIELD_BYTES",
            "32",
            "SQLite field byte limit",
        ),
    ] {
        let tmp = tempfile::tempdir().expect("tempdir");
        let bad_dir = tmp.path().join("known_bad");
        std::fs::create_dir(&bad_dir).unwrap();
        let db_path = bad_dir.join("bounded.sqlite");
        let conn = Connection::open(&db_path).unwrap();
        conn.execute("CREATE TABLE hashes (hash TEXT)", []).unwrap();
        conn.execute("INSERT INTO hashes (hash) VALUES (?1)", [SHA256_C])
            .unwrap();
        drop(conn);
        let resp = drive_with_env(
            &json!({
                "jsonrpc": "2.0",
                "id": id,
                "method": "tools/call",
                "params": {
                    "name": "hashset_lookup",
                    "arguments": {"case_id": "smoke-case", "hashes": [SHA256_C]}
                }
            }),
            &[
                (
                    "FINDEVIL_HASHSET_DIR",
                    tmp.path().as_os_str().to_os_string(),
                ),
                (env_name, env_value.into()),
            ],
        );
        assert_eq!(resp["error"]["code"], -32603, "{resp}");
        assert!(
            resp["error"]["message"]
                .as_str()
                .is_some_and(|message| message.contains(expected)),
            "expected {expected}: {resp}"
        );
    }
}
