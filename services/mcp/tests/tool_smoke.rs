//! Integration tests for services/mcp tool modules.
//!
//! Spec #2 §12 AC scaffolding. Each test writes a synthetic
//! evidence file into a tempdir, overrides `FINDEVIL_HOME`, and
//! exercises one tool end-to-end — asserting the typed return
//! shape, on-disk side effects, and error paths the agent will
//! rely on.

use std::fs;
use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard, OnceLock};

use findevil_mcp::{
    case_open, disk_extract_artifacts, disk_mount, disk_unmount, CaseHandle, CaseOpenError,
    CaseOpenInput, DiskError, DiskExtractArtifactsInput, DiskMode, DiskMountInput,
    DiskUnmountInput,
};

/// Global lock that serializes env-var manipulation across every
/// test in this file. Cargo runs tests in parallel by default and
/// `std::env::set_var("FINDEVIL_HOME", …)` is a process-global
/// mutation — without this mutex, two tests racing to set their
/// own HOME value will stomp each other's tempdir override.
fn env_lock() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// RAII guard around `FINDEVIL_HOME` that (1) acquires the global
/// env-lock so parallel tests serialize, and (2) restores the prior
/// value on drop. Hold it for the entire body of a test.
///
/// The `_lock` field is only used for its `Drop` impl; clippy
/// correctly notices it's underscore-prefixed but structurally used
/// — the allow-list below acknowledges the pattern is intentional.
#[allow(clippy::used_underscore_binding)]
struct HomeGuard {
    prev: Option<String>,
    _lock: MutexGuard<'static, ()>,
}
#[allow(clippy::used_underscore_binding)]
impl HomeGuard {
    fn set(new: &std::path::Path) -> Self {
        let _lock = env_lock();
        let prev = std::env::var("FINDEVIL_HOME").ok();
        std::env::set_var("FINDEVIL_HOME", new);
        Self { prev, _lock }
    }
}
impl Drop for HomeGuard {
    fn drop(&mut self) {
        match &self.prev {
            Some(v) => std::env::set_var("FINDEVIL_HOME", v),
            None => std::env::remove_var("FINDEVIL_HOME"),
        }
    }
}

/// Points `disk_extract_artifacts` at fake `fls`/`icat` binaries that serve a
/// canned filesystem listing plus per-inode bytes, so the TSK direct-read
/// extraction path (`fls -r -p` enumerate → `icat` extract) is exercised
/// end-to-end without a real disk image. Real `fls`/`icat` reject a synthetic
/// image with "Cannot determine file system type", which is why mock-mode
/// directory fixtures no longer reach the extraction code.
///
/// Install only while a [`HomeGuard`] is held — that guard's env-lock
/// serializes these process-global overrides — and let this drop *before* the
/// `HomeGuard` so the overrides are restored while the lock is still held.
#[cfg(unix)]
struct FakeTsk {
    fls_prev: Option<String>,
    icat_prev: Option<String>,
}

#[cfg(unix)]
impl FakeTsk {
    fn install(dir: &std::path::Path, files: &[(&str, &str, &[u8])]) -> Self {
        use std::fmt::Write as _;
        let mut listing = String::new();
        let mut blobs: Vec<(&str, &[u8])> = Vec::new();
        for (inode, path, bytes) in files {
            // fls -p line shape: `r/r <inode>:\t<relative/path>`.
            writeln!(listing, "r/r {inode}:\t{path}").unwrap();
            blobs.push((inode, bytes));
        }
        Self::install_raw(dir, &listing, &blobs)
    }

    /// Like [`FakeTsk::install`], but takes pre-formed `fls -p` listing text so
    /// tests can exercise deleted (`*`) and `(realloc)` markers directly.
    /// `blobs` maps inode -> the bytes the fake `icat` serves for it.
    fn install_raw(dir: &std::path::Path, listing: &str, files: &[(&str, &[u8])]) -> Self {
        Self::install_raw_inner(dir, listing, files, None)
    }

    fn install_raw_with_arg_log(
        dir: &std::path::Path,
        listing: &str,
        files: &[(&str, &[u8])],
        arg_log: &std::path::Path,
    ) -> Self {
        Self::install_raw_inner(dir, listing, files, Some(arg_log))
    }

    fn install_raw_inner(
        dir: &std::path::Path,
        listing: &str,
        files: &[(&str, &[u8])],
        arg_log: Option<&std::path::Path>,
    ) -> Self {
        use std::os::unix::fs::PermissionsExt;
        let blobs = dir.join("blobs");
        fs::create_dir_all(&blobs).unwrap();
        for (inode, bytes) in files {
            fs::write(blobs.join(format!("{inode}.bin")), bytes).unwrap();
        }
        let fls_txt = dir.join("fls.txt");
        fs::write(&fls_txt, listing).unwrap();

        // fls ignores its args and prints the canned listing; icat extracts the
        // last argument (the inode) from `<image> <inode>` and streams that
        // blob, mirroring how `disk_extract_artifacts` invokes them.
        let fls = dir.join("fake_fls.sh");
        let fls_log = arg_log
            .map(|path| {
                format!(
                    "for a in \"$@\"; do printf 'fls\\t%s\\n' \"$a\" >> '{}'; done\n",
                    path.display()
                )
            })
            .unwrap_or_default();
        fs::write(
            &fls,
            format!("#!/bin/sh\n{fls_log}cat '{}'\n", fls_txt.display()),
        )
        .unwrap();
        let icat = dir.join("fake_icat.sh");
        let icat_log = arg_log
            .map(|path| format!("printf 'icat\\t%s\\n' \"$@\" >> '{}'\n", path.display()))
            .unwrap_or_default();
        fs::write(
            &icat,
            format!(
                "#!/bin/sh\n{icat_log}for a in \"$@\"; do last=\"$a\"; done\ncat '{}'/\"$last\".bin\n",
                blobs.display()
            ),
        )
        .unwrap();
        for script in [&fls, &icat] {
            let mut perm = fs::metadata(script).unwrap().permissions();
            perm.set_mode(0o755);
            fs::set_permissions(script, perm).unwrap();
        }

        let fls_prev = std::env::var("FINDEVIL_FLS_BIN").ok();
        let icat_prev = std::env::var("FINDEVIL_ICAT_BIN").ok();
        std::env::set_var("FINDEVIL_FLS_BIN", &fls);
        std::env::set_var("FINDEVIL_ICAT_BIN", &icat);
        Self {
            fls_prev,
            icat_prev,
        }
    }
}

#[cfg(unix)]
impl Drop for FakeTsk {
    fn drop(&mut self) {
        let restore = |key: &str, prev: &Option<String>| match prev {
            Some(v) => std::env::set_var(key, v),
            None => std::env::remove_var(key),
        };
        restore("FINDEVIL_FLS_BIN", &self.fls_prev);
        restore("FINDEVIL_ICAT_BIN", &self.icat_prev);
    }
}

fn write_evidence_image(dir: &std::path::Path, bytes: &[u8]) -> PathBuf {
    let p = dir.join("case.e01");
    fs::write(&p, bytes).expect("write fixture evidence");
    p
}

#[test]
fn case_open_registers_case_and_hashes_image() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let _home = HomeGuard::set(tmp.path());

    let image = write_evidence_image(tmp.path(), b"hello evidence world");

    let input = CaseOpenInput {
        image_path: image,
        expected_sha256: None,
        label: Some("integration-smoke".to_string()),
    };

    let handle: CaseHandle = case_open(&input).expect("case_open ok");

    // Shape assertions.
    assert_eq!(
        handle.image_size_bytes,
        b"hello evidence world".len() as u64
    );
    assert_eq!(handle.image_hash.len(), 64, "sha256 hex is 64 chars");
    assert!(handle
        .image_hash
        .chars()
        .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    assert!(handle.id.len() == 36, "uuid v4 canonical form");
    assert!(handle.case_dir.is_dir(), "case dir created");
    assert!(
        handle.case_dir.starts_with(tmp.path().join("cases")),
        "case dir under FINDEVIL_HOME/cases/"
    );
    assert_eq!(handle.db_path, handle.case_dir.join("evidence.ddb"));

    // Manifest persisted.
    let manifest = handle.case_dir.join("case.json");
    assert!(manifest.is_file(), "case.json written");
    let manifest_text = fs::read_to_string(&manifest).unwrap();
    assert!(
        manifest_text.contains(&handle.image_hash),
        "manifest embeds image_hash"
    );
    assert!(
        manifest_text.contains("integration-smoke"),
        "manifest preserves label"
    );
}

#[test]
fn case_open_persists_canonical_path_for_relative_input() {
    let home = tempfile::tempdir().expect("home tempdir");
    let _home = HomeGuard::set(home.path());
    let cwd = std::env::current_dir().expect("current dir");
    let evidence_dir = tempfile::Builder::new()
        .prefix(".case-open-relative-")
        .tempdir_in(&cwd)
        .expect("cwd tempdir");
    let absolute = write_evidence_image(evidence_dir.path(), b"relative evidence");
    let relative = absolute
        .strip_prefix(&cwd)
        .expect("fixture beneath cwd")
        .to_path_buf();

    let handle = case_open(&CaseOpenInput {
        image_path: relative,
        expected_sha256: None,
        label: None,
    })
    .expect("register relative image");
    let manifest: serde_json::Value = serde_json::from_slice(
        &fs::read(handle.case_dir.join("case.json")).expect("read case manifest"),
    )
    .expect("decode case manifest");

    // case_open persists the path via the product's `pathnorm::canonicalize`
    // (dunce), which drops the Windows `\\?\` verbatim prefix that std's
    // `canonicalize` keeps; compare against the same normalization. No-op on Unix.
    assert_eq!(
        manifest["image_path"],
        serde_json::json!(dunce::canonicalize(&absolute).unwrap())
    );
}

#[test]
fn case_open_rejects_mismatched_expected_hash() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let _home = HomeGuard::set(tmp.path());

    let image = write_evidence_image(tmp.path(), b"mismatched");
    let input = CaseOpenInput {
        image_path: image,
        expected_sha256: Some(
            "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
        ),
        label: None,
    };

    let err = case_open(&input).unwrap_err();
    match err {
        CaseOpenError::ImageHashMismatch { expected, actual } => {
            assert_eq!(expected, "0".repeat(64));
            assert_eq!(actual.len(), 64);
            assert_ne!(actual, expected);
        }
        other => panic!("expected ImageHashMismatch, got {other:?}"),
    }
}

#[test]
fn case_open_rejects_visible_split_ewf_segment_gap() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let _home = HomeGuard::set(tmp.path());

    let first = tmp.path().join("split.E01");
    let third = tmp.path().join("split.E03");
    fs::write(&first, b"first segment").unwrap();
    fs::write(&third, b"third segment").unwrap();

    let err = case_open(&CaseOpenInput {
        image_path: first,
        expected_sha256: None,
        label: None,
    })
    .expect_err("visible EWF segment gaps must not open as clean evidence");
    assert!(
        err.to_string().contains("missing split EWF segment"),
        "gap error should be explicit, got: {err}"
    );
}

#[test]
fn case_open_errors_on_missing_image() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let _home = HomeGuard::set(tmp.path());

    let input = CaseOpenInput {
        image_path: tmp.path().join("does-not-exist.e01"),
        expected_sha256: None,
        label: None,
    };

    let err = case_open(&input).unwrap_err();
    assert!(matches!(err, CaseOpenError::ImageNotFound(_)));
}

#[test]
fn case_open_rejects_an_oversized_utf8_label_before_touching_evidence() {
    let tmp = tempfile::tempdir().unwrap();
    let input = CaseOpenInput {
        image_path: tmp.path().join("missing.dd"),
        expected_sha256: None,
        // 65 four-byte scalar values: 260 UTF-8 bytes, despite only 65 chars.
        label: Some("🧪".repeat(65)),
    };

    let error = case_open(&input).expect_err("oversized label must fail before evidence I/O");
    assert!(
        error.to_string().contains("label") && error.to_string().contains("256"),
        "unexpected error: {error}"
    );
}

#[test]
fn case_open_errors_on_directory_not_file() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let _home = HomeGuard::set(tmp.path());

    let subdir = tmp.path().join("i-am-a-dir");
    fs::create_dir_all(&subdir).unwrap();

    let input = CaseOpenInput {
        image_path: subdir,
        expected_sha256: None,
        label: None,
    };

    let err = case_open(&input).unwrap_err();
    assert!(matches!(err, CaseOpenError::ImageNotRegular(_)));
}

/// The input doc promises "the tool does not follow symlinks" — prove it.
/// A symlink inside the evidence dir pointing at a file *outside* it must
/// be refused, otherwise a crafted evidence drop could pull arbitrary
/// host files (e.g. /etc/shadow) into the hashed chain of custody.
#[cfg(unix)]
#[test]
fn case_open_refuses_symlinked_evidence_path() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let _home = HomeGuard::set(tmp.path());

    // A real file outside the evidence drop zone...
    let outside = tempfile::tempdir().expect("outside tempdir");
    let target = outside.path().join("host-secret.bin");
    fs::write(&target, b"not-your-evidence").unwrap();

    // ...reached through a symlink placed where evidence would live.
    let link = tmp.path().join("evidence.dd");
    std::os::unix::fs::symlink(&target, &link).unwrap();

    let input = CaseOpenInput {
        image_path: link,
        expected_sha256: None,
        label: None,
    };

    let err = case_open(&input).unwrap_err();
    assert!(
        matches!(err, CaseOpenError::ImageNotRegular(_)),
        "symlinked evidence must be refused, got: {err:?}"
    );
}

#[test]
#[cfg(unix)]
fn case_open_refuses_hardlinked_evidence_path() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let _home = HomeGuard::set(tmp.path());
    let image = tmp.path().join("evidence.dd");
    let alias = tmp.path().join("alias.dd");
    fs::write(&image, b"hardlinked evidence").expect("write evidence");
    fs::hard_link(&image, &alias).expect("create hardlink alias");

    let error = case_open(&CaseOpenInput {
        image_path: image,
        expected_sha256: None,
        label: None,
    })
    .expect_err("multi-linked evidence must be refused");
    assert!(matches!(error, CaseOpenError::ImageNotRegular(_)));
}

#[test]
fn case_open_hashes_match_known_vector() {
    // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    let tmp = tempfile::tempdir().expect("tempdir");
    let _home = HomeGuard::set(tmp.path());
    let image = write_evidence_image(tmp.path(), b"");

    let handle = case_open(&CaseOpenInput {
        image_path: image,
        expected_sha256: Some(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
        ),
        label: None,
    })
    .expect("empty-file hash matches known vector");
    assert_eq!(
        handle.image_hash,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_eq!(handle.image_size_bytes, 0);
}

#[test]
fn case_open_two_calls_produce_distinct_case_ids() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let _home = HomeGuard::set(tmp.path());
    let image = write_evidence_image(tmp.path(), b"same-bytes");
    let input = CaseOpenInput {
        image_path: image,
        expected_sha256: None,
        label: None,
    };
    let h1 = case_open(&input).unwrap();
    let h2 = case_open(&input).unwrap();
    assert_ne!(h1.id, h2.id, "case_ids are per-call UUIDs");
    assert_eq!(h1.image_hash, h2.image_hash, "same bytes hash the same");
}

#[test]
fn disk_mount_reuses_the_active_mount_for_the_same_source() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let _home = HomeGuard::set(tmp.path());
    let image = write_evidence_image(tmp.path(), b"idempotent mock disk");
    let handle = case_open(&CaseOpenInput {
        image_path: image.clone(),
        expected_sha256: None,
        label: Some("mount-reuse".to_string()),
    })
    .expect("case_open");
    let input = DiskMountInput {
        case_id: handle.id.clone(),
        image_path: image,
        mount_point: None,
        mode: DiskMode::Mock,
    };

    let first = disk_mount(&input).expect("first mount");
    let second = disk_mount(&input).expect("same source should reuse");

    assert_eq!(second.mount_id, first.mount_id);
    assert_eq!(second.mount_point, first.mount_point);
    let ledger: serde_json::Value = serde_json::from_slice(
        &fs::read(handle.case_dir.join("session_resources.json")).expect("ledger"),
    )
    .expect("ledger JSON");
    let active_mounts = ledger["resources"]
        .as_array()
        .expect("resources")
        .iter()
        .filter(|resource| {
            resource["resource_type"] == "disk_mount" && resource["status"] == "mounted"
        })
        .count();
    assert_eq!(active_mounts, 1);
}

#[test]
fn disk_mount_enforces_the_combined_per_case_active_mount_cap() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let _home = HomeGuard::set(tmp.path());
    let image = write_evidence_image(tmp.path(), b"mount quota disk");
    let handle = case_open(&CaseOpenInput {
        image_path: image.clone(),
        expected_sha256: None,
        label: Some("mount-quota".to_string()),
    })
    .expect("case_open");
    let resources = (0..4)
        .map(|index| {
            serde_json::json!({
                "id": format!("vss-mount-{index}"),
                "resource_type": "vss_mount",
                "status": "mounted",
                "created_at": "2026-01-01T00:00:00Z",
                "updated_at": "2026-01-01T00:00:00Z",
                "image_path": tmp.path().join(format!("snapshot-{index}.dd")),
                "mount_point": handle.case_dir.join("mounts").join(format!("vss-{index}")),
                "fs_root": handle.case_dir.join("mounts").join(format!("vss-{index}")),
                "parent_id": null,
                "output_dir": null,
                "artifacts": [],
                "command": ["vshadowmount"],
                "note": "pre-existing active mount"
            })
        })
        .collect::<Vec<_>>();
    fs::write(
        handle.case_dir.join("session_resources.json"),
        serde_json::to_vec(&serde_json::json!({"resources": resources})).unwrap(),
    )
    .expect("seed ledger");

    let error = disk_mount(&DiskMountInput {
        case_id: handle.id,
        image_path: image,
        mount_point: None,
        mode: DiskMode::Mock,
    })
    .expect_err("a fifth active mount must be refused before allocation");

    assert!(
        error.to_string().contains("active mount") && error.to_string().contains('4'),
        "unexpected quota error: {error}"
    );
}

#[test]
#[cfg(unix)]
fn disk_mount_extract_unmount_uses_session_resource_ledger_in_mock_mode() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let _home = HomeGuard::set(tmp.path());
    let image = write_evidence_image(tmp.path(), b"fake disk image bytes");
    let handle = case_open(&CaseOpenInput {
        image_path: image.clone(),
        expected_sha256: None,
        label: Some("disk-ledger".to_string()),
    })
    .expect("case_open ok");

    let _tsk = FakeTsk::install(
        tmp.path(),
        &[
            ("100", "$MFT", b"mft bytes"),
            ("101", "Windows/Prefetch/CMD.EXE-12345678.pf", b"pf"),
            ("102", "Windows/System32/config/SOFTWARE", b"hive"),
        ],
    );

    let mounted = disk_mount(&DiskMountInput {
        case_id: handle.id.clone(),
        image_path: image,
        mount_point: None,
        mode: DiskMode::Mock,
    })
    .expect("mock mount succeeds");
    assert_eq!(mounted.status, "mounted");
    assert!(mounted.ledger_path.is_file());
    let mount_point = mounted.mount_point.clone();

    let extracted = disk_extract_artifacts(&DiskExtractArtifactsInput {
        case_id: handle.id.clone(),
        mount_id: mounted.mount_id.clone(),
        artifact_kinds: vec![],
        limit: 20,
        max_artifact_bytes: 1024,
        max_total_bytes: 4096,
        recover_deleted: true,
    })
    .expect("extract artifacts");
    let classes: Vec<&str> = extracted
        .artifacts
        .iter()
        .map(|a| a.artifact_class.as_str())
        .collect();
    assert!(classes.contains(&"mft"), "classes={classes:?}");
    assert!(classes.contains(&"prefetch"), "classes={classes:?}");
    assert!(classes.contains(&"registry"), "classes={classes:?}");
    assert_eq!(extracted.artifacts_skipped_oversize, 0);
    assert_eq!(extracted.max_artifact_bytes, 1024);
    assert_eq!(extracted.listing_entries_seen, 3);
    assert!(extracted.listing_stdout_bytes > 0);
    assert!(!extracted.listing_truncated);
    assert!(extracted.listing_limit_reason.is_none());
    for artifact in &extracted.artifacts {
        assert!(artifact.extracted_path.is_file());
        assert!(artifact.extracted_path.starts_with(&extracted.output_dir));
        assert_eq!(artifact.sha256.len(), 64);
    }

    let unmounted = disk_unmount(&DiskUnmountInput {
        case_id: handle.id,
        mount_id: mounted.mount_id,
        mode: DiskMode::Mock,
    })
    .expect("mock unmount succeeds");
    assert_eq!(unmounted.status, "unmounted");
    assert!(
        !mount_point.exists(),
        "successful unmount must remove its server-created leaf"
    );

    let ledger_text = fs::read_to_string(handle.case_dir.join("session_resources.json")).unwrap();
    assert!(ledger_text.contains("disk_mount"));
    assert!(ledger_text.contains("disk_extract_artifacts"));
    assert!(ledger_text.contains("unmounted"));
    let ledger: serde_json::Value = serde_json::from_str(&ledger_text).expect("ledger json");
    let ledger_hashes = ledger["resources"]
        .as_array()
        .expect("resources")
        .iter()
        .flat_map(|resource| resource["artifacts"].as_array().into_iter().flatten())
        .filter_map(|artifact| artifact["sha256"].as_str())
        .collect::<Vec<_>>();
    assert_eq!(ledger_hashes.len(), extracted.artifacts.len());
    assert!(ledger_hashes.iter().all(|sha256| sha256.len() == 64));
}

#[test]
#[cfg(unix)]
fn disk_extract_reports_mixed_live_icat_success_and_failure_as_truncated() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let _home = HomeGuard::set(tmp.path());
    let image = write_evidence_image(tmp.path(), b"fake disk image bytes");
    let handle = case_open(&CaseOpenInput {
        image_path: image.clone(),
        expected_sha256: None,
        label: Some("mixed-icat".to_string()),
    })
    .expect("case_open ok");
    let listing = "r/r 100:\tWindows/Prefetch/GOOD.EXE-11111111.pf\n\
                   r/r 200:\tWindows/Prefetch/FAILED.EXE-22222222.pf\n";
    // Inode 200 is deliberately absent: fake icat's `cat` exits nonzero.
    let _tsk = FakeTsk::install_raw(tmp.path(), listing, &[("100", b"good".as_slice())]);
    let mounted = disk_mount(&DiskMountInput {
        case_id: handle.id.clone(),
        image_path: image,
        mount_point: None,
        mode: DiskMode::Mock,
    })
    .expect("mock mount succeeds");

    let extracted = disk_extract_artifacts(&DiskExtractArtifactsInput {
        case_id: handle.id,
        mount_id: mounted.mount_id,
        artifact_kinds: vec![],
        limit: 20,
        max_artifact_bytes: 1024,
        max_total_bytes: 4096,
        recover_deleted: true,
    })
    .expect("mixed extraction completes with honest limitation");

    assert_eq!(extracted.artifacts.len(), 1);
    assert_eq!(extracted.artifacts_extraction_failed, 1);
    assert!(extracted.truncated);
    assert!(extracted
        .limit_reasons
        .iter()
        .any(|reason| reason == "artifact_extraction_failed"));
}

#[test]
fn disk_mount_rejects_different_same_hash_image_for_registered_case() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let _home = HomeGuard::set(tmp.path());
    let registered = tmp.path().join("registered.dd");
    let substitute = tmp.path().join("substitute.dd");
    fs::write(&registered, b"same bytes").expect("registered fixture");
    fs::write(&substitute, b"same bytes").expect("substitute fixture");
    let handle = case_open(&CaseOpenInput {
        image_path: registered,
        expected_sha256: None,
        label: None,
    })
    .expect("case_open ok");

    let err = disk_mount(&DiskMountInput {
        case_id: handle.id.clone(),
        image_path: substitute,
        mount_point: None,
        mode: DiskMode::Mock,
    })
    .expect_err("same bytes at a different path are not this Case's evidence");

    assert!(matches!(
        err,
        DiskError::IntegrityMismatch { ref case_id } if case_id == &handle.id
    ));
}

#[test]
fn disk_mount_rejects_evidence_mutated_after_case_open() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let _home = HomeGuard::set(tmp.path());
    let image = write_evidence_image(tmp.path(), b"registered bytes");
    let handle = case_open(&CaseOpenInput {
        image_path: image.clone(),
        expected_sha256: None,
        label: None,
    })
    .expect("case_open ok");
    fs::write(&image, b"mutated bytes").expect("mutate fixture after registration");

    let err = disk_mount(&DiskMountInput {
        case_id: handle.id.clone(),
        image_path: image,
        mount_point: None,
        mode: DiskMode::Mock,
    })
    .expect_err("post-registration evidence mutation must be refused");

    assert!(matches!(
        err,
        DiskError::IntegrityMismatch { ref case_id } if case_id == &handle.id
    ));
}

#[test]
fn disk_mount_rejects_mutated_split_ewf_segment() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let _home = HomeGuard::set(tmp.path());
    let first = tmp.path().join("case.E01");
    let second = tmp.path().join("case.E02");
    fs::write(&first, b"first segment").expect("first segment");
    fs::write(&second, b"second segment").expect("second segment");
    let handle = case_open(&CaseOpenInput {
        image_path: first.clone(),
        expected_sha256: None,
        label: None,
    })
    .expect("case_open split EWF");
    fs::write(&second, b"substituted second segment").expect("mutate segment");

    let err = disk_mount(&DiskMountInput {
        case_id: handle.id.clone(),
        image_path: first,
        mount_point: None,
        mode: DiskMode::Mock,
    })
    .expect_err("mutating any registered EWF segment must be refused");

    assert!(matches!(
        err,
        DiskError::IntegrityMismatch { ref case_id } if case_id == &handle.id
    ));
}

#[test]
#[cfg(unix)]
fn disk_extract_revalidates_evidence_after_mount() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let _home = HomeGuard::set(tmp.path());
    let image = write_evidence_image(tmp.path(), b"registered bytes");
    let handle = case_open(&CaseOpenInput {
        image_path: image.clone(),
        expected_sha256: None,
        label: None,
    })
    .expect("case_open ok");
    let _tsk = FakeTsk::install(
        tmp.path(),
        &[("100", "Windows/Prefetch/CMD.EXE-12345678.pf", b"pf")],
    );
    let mounted = disk_mount(&DiskMountInput {
        case_id: handle.id.clone(),
        image_path: image.clone(),
        mount_point: None,
        mode: DiskMode::Mock,
    })
    .expect("initial mount binds registered bytes");
    fs::write(&image, b"mutated after mount").expect("mutate after mount");

    let err = disk_extract_artifacts(&DiskExtractArtifactsInput {
        case_id: handle.id.clone(),
        mount_id: mounted.mount_id,
        artifact_kinds: vec![],
        limit: 20,
        max_artifact_bytes: 1024,
        max_total_bytes: 4096,
        recover_deleted: true,
    })
    .expect_err("extract must revalidate the case evidence binding");

    assert!(matches!(
        err,
        DiskError::IntegrityMismatch { ref case_id } if case_id == &handle.id
    ));
}

#[test]
#[cfg(unix)]
fn disk_extract_artifacts_passes_split_ewf_segments_to_tsk() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let _home = HomeGuard::set(tmp.path());
    let first = tmp.path().join("case.E01");
    let second = tmp.path().join("case.E02");
    fs::write(&first, b"first segment bytes").unwrap();
    fs::write(&second, b"second segment bytes").unwrap();
    // The tool canonicalizes the image path before handing it to TSK. On macOS
    // the tempdir lives under a `/var` -> `/private/var` symlink, so compare
    // against the canonicalized segment paths or the argv check below mismatches
    // `/private/var...` (what TSK sees) against `/var...`. No-op on Linux.
    let first = first.canonicalize().expect("canonicalize first segment");
    let second = second.canonicalize().expect("canonicalize second segment");

    let handle = case_open(&CaseOpenInput {
        image_path: first.clone(),
        expected_sha256: None,
        label: Some("split-ewf".to_string()),
    })
    .expect("case_open ok");

    let arg_log = tmp.path().join("tsk-args.log");
    let _tsk = FakeTsk::install_raw_with_arg_log(
        tmp.path(),
        "r/r 100:\tWindows/Prefetch/CMD.EXE-12345678.pf\n",
        &[("100", b"pf bytes".as_slice())],
        &arg_log,
    );

    let mounted = disk_mount(&DiskMountInput {
        case_id: handle.id.clone(),
        image_path: first.clone(),
        mount_point: None,
        mode: DiskMode::Mock,
    })
    .expect("mock mount succeeds");

    let extracted = disk_extract_artifacts(&DiskExtractArtifactsInput {
        case_id: handle.id,
        mount_id: mounted.mount_id,
        artifact_kinds: vec![],
        limit: 20,
        max_artifact_bytes: 1024,
        max_total_bytes: 4096,
        recover_deleted: true,
    })
    .expect("extract artifacts");
    assert_eq!(extracted.artifacts.len(), 1);

    let log = fs::read_to_string(arg_log).expect("read fake TSK argv log");
    let first_arg = first.to_string_lossy();
    let second_arg = second.to_string_lossy();
    assert!(
        log.lines().any(|line| line == format!("fls\t{first_arg}")),
        "fls argv omitted first segment: {log}"
    );
    assert!(
        log.lines().any(|line| line == format!("fls\t{second_arg}")),
        "fls argv omitted second segment: {log}"
    );
    assert!(
        log.lines().any(|line| line == format!("icat\t{first_arg}")),
        "icat argv omitted first segment: {log}"
    );
    assert!(
        log.lines()
            .any(|line| line == format!("icat\t{second_arg}")),
        "icat argv omitted second segment: {log}"
    );
}

#[test]
#[cfg(unix)]
fn disk_extract_artifacts_skips_oversized_yara_targets() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let _home = HomeGuard::set(tmp.path());
    let image = write_evidence_image(tmp.path(), b"fake disk image bytes");
    let handle = case_open(&CaseOpenInput {
        image_path: image.clone(),
        expected_sha256: None,
        label: Some("disk-oversize".to_string()),
    })
    .expect("case_open ok");

    let small = PathBuf::from("Users/Alice/AppData/Local/Temp/small.bin");
    let large = PathBuf::from("Users/Alice/AppData/Local/Temp/large.bin");
    let _tsk = FakeTsk::install(
        tmp.path(),
        &[
            ("200", small.to_str().unwrap(), b"small"),
            (
                "201",
                large.to_str().unwrap(),
                b"this file is too large for the smoke max",
            ),
        ],
    );

    let mounted = disk_mount(&DiskMountInput {
        case_id: handle.id.clone(),
        image_path: image,
        mount_point: None,
        mode: DiskMode::Mock,
    })
    .expect("mock mount succeeds");

    let extracted = disk_extract_artifacts(&DiskExtractArtifactsInput {
        case_id: handle.id,
        mount_id: mounted.mount_id,
        artifact_kinds: vec![],
        limit: 20,
        max_artifact_bytes: 8,
        max_total_bytes: 4096,
        recover_deleted: true,
    })
    .expect("extract artifacts");

    assert_eq!(extracted.artifacts_skipped_oversize, 1);
    assert!(
        extracted
            .artifacts
            .iter()
            .any(|artifact| artifact.source_path == small),
        "small YARA target should still be extracted"
    );
    assert!(
        extracted
            .artifacts
            .iter()
            .all(|artifact| artifact.source_path != large),
        "oversized YARA target should not be copied"
    );
}

#[test]
#[cfg(unix)]
fn disk_extract_artifacts_enforces_case_wide_aggregate_budget_across_calls() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let _home = HomeGuard::set(tmp.path());
    let image = write_evidence_image(tmp.path(), b"fake disk image bytes");
    let handle = case_open(&CaseOpenInput {
        image_path: image.clone(),
        expected_sha256: None,
        label: Some("disk-aggregate-limit".to_string()),
    })
    .expect("case_open ok");
    let _tsk = FakeTsk::install(
        tmp.path(),
        &[
            ("200", "Users/Alice/AppData/Local/Temp/one.bin", b"1111"),
            ("201", "Users/Alice/AppData/Local/Temp/two.bin", b"2222"),
        ],
    );
    let mounted = disk_mount(&DiskMountInput {
        case_id: handle.id.clone(),
        image_path: image,
        mount_point: None,
        mode: DiskMode::Mock,
    })
    .expect("mock mount succeeds");

    let first = disk_extract_artifacts(&DiskExtractArtifactsInput {
        case_id: handle.id.clone(),
        mount_id: mounted.mount_id.clone(),
        artifact_kinds: vec![],
        limit: 20,
        max_artifact_bytes: 16,
        max_total_bytes: 7,
        recover_deleted: true,
    })
    .expect("first bounded extract");
    assert_eq!(first.extracted_bytes, 4);
    assert_eq!(first.case_extracted_bytes_before, 0);
    assert_eq!(first.case_extracted_bytes_after, 4);
    assert_eq!(first.artifacts_skipped_total_limit, 1);
    assert!(first.truncated);
    assert!(first
        .limit_reasons
        .iter()
        .any(|reason| reason == "aggregate_bytes"));
    assert!(first
        .artifacts
        .iter()
        .all(|artifact| artifact.size_bytes <= first.max_total_bytes));
    assert!(first.artifacts.iter().all(|artifact| {
        artifact.sha256.len() == 64 && artifact.sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
    }));

    let second = disk_extract_artifacts(&DiskExtractArtifactsInput {
        case_id: handle.id,
        mount_id: mounted.mount_id,
        artifact_kinds: vec![],
        limit: 20,
        max_artifact_bytes: 16,
        max_total_bytes: 7,
        recover_deleted: true,
    })
    .expect("second bounded extract");
    assert_eq!(second.case_extracted_bytes_before, 4);
    assert_eq!(second.extracted_bytes, 0);
    assert_eq!(second.case_extracted_bytes_after, 4);
    assert!(second.artifacts.is_empty());
    assert!(second.artifacts_skipped_total_limit >= 1);
    assert!(second.truncated);
}

#[test]
#[cfg(unix)]
fn disk_extract_artifacts_accounts_for_orphaned_staging_after_a_crash() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let _home = HomeGuard::set(tmp.path());
    let image = write_evidence_image(tmp.path(), b"fake disk image bytes");
    let handle = case_open(&CaseOpenInput {
        image_path: image.clone(),
        expected_sha256: None,
        label: Some("disk-orphaned-staging".to_string()),
    })
    .expect("case_open ok");
    let _tsk = FakeTsk::install(
        tmp.path(),
        &[("200", "Users/Alice/AppData/Local/Temp/next.bin", b"next")],
    );
    let mounted = disk_mount(&DiskMountInput {
        case_id: handle.id.clone(),
        image_path: image,
        mount_point: None,
        mode: DiskMode::Mock,
    })
    .expect("mock mount succeeds");
    let orphan_dir = handle.case_dir.join("extracted/disk/orphaned-call");
    fs::create_dir_all(&orphan_dir).expect("orphan dir");
    fs::write(orphan_dir.join("partial.bin"), b"123456").expect("orphan partial");

    let extracted = disk_extract_artifacts(&DiskExtractArtifactsInput {
        case_id: handle.id,
        mount_id: mounted.mount_id,
        artifact_kinds: vec![],
        limit: 20,
        max_artifact_bytes: 16,
        max_total_bytes: 7,
        recover_deleted: true,
    })
    .expect("bounded extract after orphan");

    assert_eq!(extracted.case_extracted_bytes_before, 6);
    assert_eq!(extracted.extracted_bytes, 0);
    assert!(extracted.artifacts.is_empty());
    assert_eq!(extracted.artifacts_skipped_total_limit, 1);
    assert!(extracted.truncated);
}

#[test]
#[cfg(unix)]
fn disk_extract_artifacts_recovers_deleted_entries_and_skips_realloc() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let _home = HomeGuard::set(tmp.path());
    let image = write_evidence_image(tmp.path(), b"fake disk image bytes");
    let handle = case_open(&CaseOpenInput {
        image_path: image.clone(),
        expected_sha256: None,
        label: Some("disk-deleted-recovery".to_string()),
    })
    .expect("case_open ok");

    // One live prefetch, one recoverable deleted registry hive, one deleted
    // entry whose inode was reallocated (must be skipped — icat would return
    // the reusing live file's bytes), and one deleted entry whose content run
    // is gone (fake icat serves zero bytes -> failed recovery).
    let listing = "r/r 100:\tWindows/Prefetch/CMD.EXE-11111111.pf\n\
                   r/r * 200:\tWindows/System32/config/SOFTWARE\n\
                   -/r * 300(realloc):\tWindows/Prefetch/GONE.EXE-22222222.pf\n\
                   r/r * 400:\tWindows/System32/config/SAM\n";
    let _tsk = FakeTsk::install_raw(
        tmp.path(),
        listing,
        &[
            ("100", b"pf bytes".as_slice()),
            ("200", b"recovered hive bytes".as_slice()),
            ("400", b"".as_slice()),
        ],
    );

    let mounted = disk_mount(&DiskMountInput {
        case_id: handle.id.clone(),
        image_path: image,
        mount_point: None,
        mode: DiskMode::Mock,
    })
    .expect("mock mount succeeds");

    let extracted = disk_extract_artifacts(&DiskExtractArtifactsInput {
        case_id: handle.id.clone(),
        mount_id: mounted.mount_id.clone(),
        artifact_kinds: vec![],
        limit: 20,
        max_artifact_bytes: 1024,
        max_total_bytes: 4096,
        recover_deleted: true,
    })
    .expect("extract artifacts");

    assert_eq!(extracted.deleted_entries_seen, 3);
    assert_eq!(extracted.deleted_skipped_realloc, 1);
    assert_eq!(extracted.deleted_recovered, 1);
    assert_eq!(extracted.deleted_recovery_failed, 1);

    let recovered = extracted
        .artifacts
        .iter()
        .find(|artifact| artifact.recovered_deleted)
        .expect("one recovered-deleted artifact");
    assert_eq!(recovered.artifact_class, "registry");
    assert!(
        recovered
            .extracted_path
            .to_string_lossy()
            .contains("/registry/__deleted__/200/"),
        "recovered content must stage under __deleted__/<inode>: {:?}",
        recovered.extracted_path
    );
    assert_eq!(
        fs::read(&recovered.extracted_path).unwrap(),
        b"recovered hive bytes"
    );
    assert!(
        extracted
            .artifacts
            .iter()
            .all(|artifact| !artifact.source_path.to_string_lossy().contains("GONE")),
        "reallocated inode must never be extracted"
    );
    let live = extracted
        .artifacts
        .iter()
        .find(|artifact| artifact.artifact_class == "prefetch")
        .expect("live prefetch extracted");
    assert!(!live.recovered_deleted);

    // Opting out keeps the counters honest but recovers nothing.
    let opted_out = disk_extract_artifacts(&DiskExtractArtifactsInput {
        case_id: handle.id,
        mount_id: mounted.mount_id,
        artifact_kinds: vec![],
        limit: 20,
        max_artifact_bytes: 1024,
        max_total_bytes: 4096,
        recover_deleted: false,
    })
    .expect("extract artifacts without recovery");
    assert_eq!(opted_out.deleted_entries_seen, 3);
    assert_eq!(opted_out.deleted_skipped_realloc, 1);
    assert_eq!(opted_out.deleted_recovered, 0);
    assert_eq!(opted_out.deleted_recovery_failed, 0);
    assert!(opted_out.artifacts.iter().all(|a| !a.recovered_deleted));
}
