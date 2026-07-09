//! Integration tests for `bulk_extract`.
//!
//! These tests DO NOT require the `bulk_extractor` binary. They cover:
//!   * input validation (path errors, dash-leading image, serde),
//!   * the pure determinism helpers (argv builder incl. the `--` marker,
//!     feature-line parser, numeric-offset stable sort, staging-stem
//!     sanitizer, path scrubber, `case_id` validator),
//!   * the honest-degradation path, forced deterministically by pointing
//!     `$FINDEVIL_BULK_EXTRACTOR_BIN` at a nonexistent path (so the test
//!     asserts the degrade invariants even on a host WITH `bulk_extractor`
//!     installed),
//!   * the security-relevant negative paths (traversal `case_id`,
//!     `InvalidRegex`, missing keyword file) that must be rejected BEFORE
//!     any subprocess spawn.
//!
//! A real end-to-end run (and the free-space recall benchmark) needs BOTH
//! the `bulk_extractor` binary AND a carving fixture — neither is
//! committed here, so no recall delta is asserted.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, OnceLock};

use findevil_mcp::{
    build_bulk_args, bulk_extract, compare_offset, image_name_is_dash_leading, is_valid_case_id,
    parse_feature_line, sanitize_stem, scrub_absolute_paths, sort_features, BulkExtractError,
    BulkExtractInput, BulkFeature, BulkScanner,
};

// ---------------------------------------------------------------------------
// Env harness. FINDEVIL_HOME / FINDEVIL_BULK_EXTRACTOR_BIN /
// FINDEVIL_BULK_KEYWORD_FILE are process-global; serialize every test that
// touches them and restore the prior values on drop.
// ---------------------------------------------------------------------------

fn env_lock() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

const KEYS: [&str; 3] = [
    "FINDEVIL_HOME",
    "FINDEVIL_BULK_EXTRACTOR_BIN",
    "FINDEVIL_BULK_KEYWORD_FILE",
];

#[allow(clippy::used_underscore_binding)]
struct EnvGuard {
    prev: Vec<(&'static str, Option<String>)>,
    _lock: MutexGuard<'static, ()>,
}

#[allow(clippy::used_underscore_binding)]
impl EnvGuard {
    /// Acquire the lock, snapshot all managed keys, then set HOME + BIN and
    /// clear the keyword-file override so tests start from a known state.
    fn set(home: &Path, bin: &Path) -> Self {
        let _lock = env_lock();
        let prev = KEYS
            .iter()
            .map(|k| (*k, std::env::var(k).ok()))
            .collect::<Vec<_>>();
        std::env::set_var("FINDEVIL_HOME", home);
        std::env::set_var("FINDEVIL_BULK_EXTRACTOR_BIN", bin);
        std::env::remove_var("FINDEVIL_BULK_KEYWORD_FILE");
        Self { prev, _lock }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        for (key, prev) in &self.prev {
            match prev {
                Some(v) => std::env::set_var(key, v),
                None => std::env::remove_var(key),
            }
        }
    }
}

/// Create `<home>/cases/<case_id>` so `resolve_case_dir` succeeds.
fn make_case(home: &Path, case_id: &str) -> PathBuf {
    let dir = home.join("cases").join(case_id);
    std::fs::create_dir_all(&dir).expect("create case dir");
    dir
}

/// An existing file to use as a resolvable "binary" for pre-spawn-only
/// tests (the tool validates and returns before it ever spawns this).
fn stub_binary() -> PathBuf {
    std::env::current_exe().expect("test exe path")
}

fn sample_input(case_id: &str, image_path: PathBuf) -> BulkExtractInput {
    BulkExtractInput {
        case_id: case_id.to_string(),
        image_path,
        scanners: Vec::new(),
        find_regexes: Vec::new(),
        keyword_file: None,
        limit: None,
    }
}

fn write_image(dir: &Path, name: &str) -> PathBuf {
    let p = dir.join(name);
    std::fs::write(&p, b"\x00\x01\x02not a real image").unwrap();
    p
}

// --- input validation ------------------------------------------------------

#[test]
fn bulk_extract_errors_on_missing_image() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let input = sample_input("test-case", tmp.path().join("nope.dd"));
    let err = bulk_extract(&input).unwrap_err();
    assert!(matches!(err, BulkExtractError::NotFound(_)));
}

#[test]
fn bulk_extract_errors_when_image_path_is_a_directory() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let input = sample_input("test-case", tmp.path().to_path_buf());
    let err = bulk_extract(&input).unwrap_err();
    assert!(matches!(err, BulkExtractError::NotRegular(_)));
}

#[test]
fn bulk_extract_rejects_dash_leading_image_name() {
    // A `-`-leading filename could be read as a bulk_extractor flag; the
    // tool rejects it before resolving the binary (no env needed).
    let tmp = tempfile::tempdir().expect("tempdir");
    let image = write_image(tmp.path(), "-rf.dd");
    let input = sample_input("test-case", image);
    let err = bulk_extract(&input).unwrap_err();
    assert!(matches!(err, BulkExtractError::DashLeadingImageName(_)));
}

// --- security: destructive-path guards -------------------------------------

#[test]
fn bulk_extract_rejects_traversal_case_id() {
    // A traversal case_id must be rejected BEFORE resolve_case_dir joins it
    // (and before the caller's remove_dir_all / create_dir), so it can
    // never escape the case sandbox. Binary resolves (stub) so we reach the
    // case_id check; validation returns InvalidCaseId with no spawn.
    let tmp = tempfile::tempdir().expect("tempdir");
    let home = tmp.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    let image = write_image(tmp.path(), "image.dd");
    let _guard = EnvGuard::set(&home, &stub_binary());

    let input = sample_input("../../foo", image);
    let err = bulk_extract(&input).unwrap_err();
    assert!(matches!(err, BulkExtractError::InvalidCaseId(_)));
    // Nothing was created outside the sandbox.
    assert!(!home.join("cases").join("..").exists());
}

// --- honest degradation (forced) -------------------------------------------

#[test]
fn bulk_extract_degrades_when_binary_absent() {
    // FORCE the degrade path: point the binary at a definitely-nonexistent
    // path so resolve_binary returns None even on a host WITH bulk_extractor
    // installed. A real case dir is set up too. Assert the degrade-specific
    // invariants UNCONDITIONALLY.
    let tmp = tempfile::tempdir().expect("tempdir");
    let home = tmp.path().join("home");
    let case_id = "degrade-case";
    make_case(&home, case_id);
    let image = write_image(tmp.path(), "image.dd");
    let missing_bin = tmp.path().join("no-such-bulk_extractor-binary");
    let _guard = EnvGuard::set(&home, &missing_bin);

    let out = bulk_extract(&sample_input(case_id, image)).expect("degrade is Ok, not Err");
    assert!(!out.bulk_extractor_available);
    assert!(out.features.is_empty());
    assert!(out.staged_files.is_empty());
    assert_eq!(out.features_seen, 0);
    assert_eq!(out.engine_version, "");
    assert!(out.stderr_tail.is_empty());

    // The degrade output is serializable and DETERMINISTIC — the same bytes
    // the server's finalize_tool_output would fold into _meta.output_sha256
    // (verified live end-to-end separately; the wrapper itself is server
    // territory).
    let a = serde_json::to_string(&out).unwrap();
    let out2 = bulk_extract(&sample_input(case_id, tmp.path().join("image.dd"))).unwrap();
    let b = serde_json::to_string(&out2).unwrap();
    assert_eq!(
        a, b,
        "degrade output must be deterministic for custody replay"
    );
}

#[test]
fn bulk_extract_case_not_found_is_separate_from_degrade() {
    // Binary resolves (stub), case_id is valid, but the case dir does NOT
    // exist → CaseNotFound. This is a distinct branch from the degrade.
    let tmp = tempfile::tempdir().expect("tempdir");
    let home = tmp.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    let image = write_image(tmp.path(), "image.dd");
    let _guard = EnvGuard::set(&home, &stub_binary());

    let err = bulk_extract(&sample_input("no-such-case", image)).unwrap_err();
    assert!(matches!(err, BulkExtractError::CaseNotFound(_)));
}

// --- security: pre-spawn input rejection -----------------------------------

#[test]
fn bulk_extract_rejects_find_regex_with_control_char() {
    // A newline/NUL in a find regex would corrupt the generated -F file;
    // write_find_regexes rejects it BEFORE any spawn.
    let tmp = tempfile::tempdir().expect("tempdir");
    let home = tmp.path().join("home");
    let case_id = "regex-case";
    make_case(&home, case_id);
    let image = write_image(tmp.path(), "image.dd");
    let _guard = EnvGuard::set(&home, &stub_binary());

    let mut input = sample_input(case_id, image);
    input.find_regexes = vec!["ok".to_string(), "bad\nregex".to_string()];
    let err = bulk_extract(&input).unwrap_err();
    match err {
        BulkExtractError::InvalidRegex { index } => assert_eq!(index, 1),
        other => panic!("expected InvalidRegex, got {other:?}"),
    }
}

#[test]
fn bulk_extract_rejects_missing_keyword_file() {
    // A supplied keyword_file that does not exist is rejected before spawn.
    let tmp = tempfile::tempdir().expect("tempdir");
    let home = tmp.path().join("home");
    let case_id = "kw-case";
    make_case(&home, case_id);
    let image = write_image(tmp.path(), "image.dd");
    let _guard = EnvGuard::set(&home, &stub_binary());

    let mut input = sample_input(case_id, image);
    input.keyword_file = Some(tmp.path().join("no-such-keywords.txt"));
    let err = bulk_extract(&input).unwrap_err();
    assert!(matches!(err, BulkExtractError::KeywordFileNotFound(_)));
}

// --- determinism helpers ---------------------------------------------------

#[test]
fn build_bulk_args_forces_single_threaded_scan_with_end_of_options() {
    let args = build_bulk_args(
        Path::new("/case/out"),
        Path::new("/case/image.dd"),
        &[BulkScanner::Email, BulkScanner::Find],
        &[PathBuf::from("/case/kw.txt")],
    );
    // `-j 1` MUST lead so scan order (and thus output) is deterministic.
    assert_eq!(args[0], OsString::from("-j"));
    assert_eq!(args[1], OsString::from("1"));
    assert!(args.contains(&OsString::from("email")));
    assert!(args.contains(&OsString::from("find")));
    assert!(args.contains(&OsString::from("-F")));
    // End-of-options `--` immediately precedes the (final) image path.
    assert_eq!(args[args.len() - 2], OsString::from("--"));
    assert_eq!(args.last(), Some(&OsString::from("/case/image.dd")));
}

#[test]
fn image_name_dash_leading_is_detected() {
    assert!(image_name_is_dash_leading(Path::new("/case/-x.dd")));
    assert!(!image_name_is_dash_leading(Path::new("/case/image.dd")));
}

#[test]
fn case_id_validator_rejects_traversal() {
    assert!(is_valid_case_id("abc-123_DEF"));
    assert!(!is_valid_case_id("../../foo"));
    assert!(!is_valid_case_id("a/b"));
    assert!(!is_valid_case_id(""));
}

#[test]
fn scrub_absolute_paths_removes_host_prefixes() {
    let case = Path::new("/home/u/.findevil/cases/abc");
    let img = Path::new("/evidence/x.dd");
    let text = "wrote /home/u/.findevil/cases/abc/out/email.txt from /evidence/x.dd";
    let s = scrub_absolute_paths(text, &[case, img]);
    assert!(!s.contains("/home/u"));
    assert!(!s.contains("/evidence/x.dd"));
    assert!(s.contains("<redacted-path>"));
}

#[test]
fn parse_feature_line_extracts_offset_feature_context() {
    let row = parse_feature_line("email", "512\ta@b.test\tsome ctx").unwrap();
    assert_eq!(row.feature_type, "email");
    assert_eq!(row.offset, "512");
    assert_eq!(row.feature, "a@b.test");
    assert_eq!(row.context, "some ctx");
    assert!(parse_feature_line("email", "# BULK_EXTRACTOR-Version: 2.0.0").is_none());
    assert!(parse_feature_line("email", "").is_none());
}

#[test]
fn sort_features_orders_offsets_numerically() {
    let mk = |off: &str| BulkFeature {
        feature_type: "email".into(),
        offset: off.into(),
        feature: "x".into(),
        context: String::new(),
    };
    // Lexicographically "100" < "20" < "9"; numerically 9 < 20 < 100.
    let mut a = vec![mk("100"), mk("9"), mk("20")];
    sort_features(&mut a);
    assert_eq!(
        a.iter().map(|r| r.offset.as_str()).collect::<Vec<_>>(),
        vec!["9", "20", "100"]
    );
    // Sorting a shuffled copy yields the identical order (deterministic).
    let mut b = vec![mk("9"), mk("100"), mk("20")];
    sort_features(&mut b);
    assert_eq!(a, b);
}

#[test]
fn compare_offset_uses_leading_integer() {
    use std::cmp::Ordering;
    assert_eq!(compare_offset("9", "100"), Ordering::Less);
    assert_eq!(
        compare_offset("1234-GZIP-56", "1234-GZIP-78"),
        Ordering::Less
    );
}

#[test]
fn sanitize_stem_is_deterministic_and_filesystem_safe() {
    assert_eq!(
        sanitize_stem(Path::new("/e/disk image.dd")),
        "disk_image.dd"
    );
    assert_eq!(sanitize_stem(Path::new("/e/a;b|c.raw")), "a_b_c.raw");
}

// --- serde contract --------------------------------------------------------

#[test]
fn bulk_extract_input_roundtrips_through_serde() {
    let body = r#"{
        "case_id": "c1",
        "image_path": "/case/image.dd",
        "scanners": ["email", "httplogs", "find"],
        "find_regexes": ["intrusion", "exfil"],
        "keyword_file": "/opt/keywords.txt",
        "limit": 500
    }"#;
    let inp: BulkExtractInput = serde_json::from_str(body).unwrap();
    assert_eq!(inp.case_id, "c1");
    assert_eq!(inp.image_path, Path::new("/case/image.dd"));
    assert_eq!(inp.scanners.len(), 3);
    assert_eq!(inp.scanners[0], BulkScanner::Email);
    assert_eq!(inp.find_regexes, vec!["intrusion", "exfil"]);
    assert_eq!(
        inp.keyword_file.as_deref(),
        Some(Path::new("/opt/keywords.txt"))
    );
    assert_eq!(inp.limit, Some(500));
}

#[test]
fn bulk_extract_input_rejects_unknown_fields() {
    let body = r#"{
        "case_id": "c1",
        "image_path": "/x",
        "rogue_field": "nope"
    }"#;
    let err = serde_json::from_str::<BulkExtractInput>(body).unwrap_err();
    assert!(err.to_string().contains("rogue_field") || err.to_string().contains("unknown field"));
}

#[test]
fn bulk_extract_input_rejects_unknown_scanner() {
    let body = r#"{
        "case_id": "c1",
        "image_path": "/x",
        "scanners": ["definitely_not_a_scanner"]
    }"#;
    assert!(serde_json::from_str::<BulkExtractInput>(body).is_err());
}
