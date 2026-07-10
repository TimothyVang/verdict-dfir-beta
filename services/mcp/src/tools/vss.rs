//! `vss_list` / `vss_mount` — enumerate and mount Windows Volume Shadow Copies
//! from a disk image via libvshadow (`vshadowinfo` / `vshadowmount`).
//!
//! Volume Shadow Copy Service (VSS) snapshots hold *point-in-time* copies of a
//! volume. They are decisive for DFIR: a file an attacker deleted, a registry
//! hive value they changed, or a payload they wiped often still exists inside an
//! older shadow copy, and the delta between a snapshot and the live volume is a
//! direct anti-forensics / timeline signal. libvshadow reads the shadow store
//! from a raw/mounted volume: `vshadowinfo` lists the stores (creation time,
//! identifier), and `vshadowmount` exposes each snapshot as a `vssN` raw-volume
//! file under a FUSE mount that the normal disk tools then read unchanged.
//!
//! Both tools **degrade safely**: when libvshadow is not installed they return a
//! typed `*_available: false` result with empty data rather than erroring, so the
//! pipeline pivots (mirrors `ez_parse` / `plaso_parse`). Binary discovery is an
//! env override (`$FINDEVIL_VSHADOWINFO_BIN` / `$FINDEVIL_VSHADOWMOUNT_BIN`) then
//! PATH. Read-only: the shadow store and the exposed `vssN` files are never
//! modified.
//!
//! Evidence-agnostic: the `vshadowinfo` parser keys on libvshadow's stable field
//! labels, never on any host's identifiers, volume names, or timestamps.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::tools::disk::{
    admit_case_mount, create_case_mount_leaf, hash_bound_derived_artifact,
    register_vss_mount_resource, DiskError, MountKind, SessionResource,
};
use crate::tools::proc_runner::{run_with_timeout, timeout_from_env_clamped, RunError};

/// Cap on surfaced shadow stores so a pathological listing cannot bloat output.
const MAX_STORES: usize = 256;
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(600);
const HARD_TIMEOUT: Duration = Duration::from_secs(3_600);
const TIMEOUT_ENV: &str = "FINDEVIL_VSS_TIMEOUT_SECS";
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(60);

struct VssMountCleanup {
    mount_point: PathBuf,
    mount_attempted: bool,
    armed: bool,
}

impl VssMountCleanup {
    const fn new(mount_point: PathBuf) -> Self {
        Self {
            mount_point,
            mount_attempted: false,
            armed: true,
        }
    }

    const fn record_attempt(&mut self) {
        self.mount_attempted = true;
    }

    const fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for VssMountCleanup {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        if self.mount_attempted {
            cleanup_vss_mount(&self.mount_point);
        }
        let _ = std::fs::remove_dir(&self.mount_point);
    }
}

fn cleanup_vss_mount(mount_point: &Path) {
    let umount = std::env::var("FINDEVIL_UMOUNT_BIN").unwrap_or_else(|_| "umount".to_string());
    let mut cleanup = Command::new(umount);
    cleanup.arg(mount_point);
    let _ = run_with_timeout(cleanup, CLEANUP_TIMEOUT);
}

fn vshadowinfo_bin() -> String {
    std::env::var("FINDEVIL_VSHADOWINFO_BIN").unwrap_or_else(|_| "vshadowinfo".to_string())
}

fn vshadowmount_bin() -> String {
    std::env::var("FINDEVIL_VSHADOWMOUNT_BIN").unwrap_or_else(|_| "vshadowmount".to_string())
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VssListInput {
    /// Case ID from a prior `case_open` call. Audit correlation only.
    pub case_id: String,
    /// Path to a raw volume image or mounted volume device to enumerate shadow
    /// copies from.
    pub image_path: PathBuf,
}

/// One Volume Shadow Copy store as reported by `vshadowinfo`.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct ShadowStore {
    /// 1-based store number (`vssN` when mounted).
    pub store_number: u32,
    /// Store identifier GUID, as reported.
    pub identifier: Option<String>,
    /// Snapshot creation time, as reported (not UTC-normalized here).
    pub creation_time: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct VssListOutput {
    /// False when libvshadow is not installed (the pipeline pivots).
    pub vshadowinfo_available: bool,
    /// True if the image carries a VSS shadow store.
    pub has_shadow_store: bool,
    /// Number of shadow copies present (uncapped).
    pub store_count: usize,
    /// The shadow stores (sorted by number, capped).
    pub stores: Vec<ShadowStore>,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VssMountInput {
    /// Case ID from a prior `case_open` call.
    pub case_id: String,
    /// Path to the raw volume image or mounted volume device holding the shadow
    /// store.
    pub image_path: PathBuf,
    /// Reserved for wire compatibility. Product calls must omit this field;
    /// the server creates a fresh leaf under the current Case.
    #[serde(default)]
    pub mount_point: Option<PathBuf>,
}

#[derive(Clone, Debug, Serialize)]
pub struct VssMountOutput {
    /// False when libvshadow is not installed.
    pub vshadowmount_available: bool,
    /// Case-scoped mount id (also usable to locate the exposed snapshots).
    pub mount_id: String,
    /// Mount status: `mounted` or `unavailable`.
    pub status: String,
    /// The FUSE mount point holding the exposed `vssN` snapshot files.
    pub mount_point: PathBuf,
    /// Paths of the exposed per-snapshot raw-volume files (`vss1`, `vss2`, …),
    /// which the normal disk tools read unchanged.
    pub shadow_store_paths: Vec<PathBuf>,
    /// The exact command run (or the command that would run when available).
    pub command: Vec<String>,
}

#[derive(Debug, Error)]
pub enum VssError {
    #[error("image not found: {0}")]
    ImageNotFound(PathBuf),
    #[error("case not found or unusable: {0}")]
    Case(String),
    #[error("could not create mount point {path}: {source}")]
    MountPoint {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("caller-selected VSS mount points are forbidden: {0}")]
    UnsafeMountPoint(PathBuf),
    #[error("could not register VSS mount in the case session ledger: {0}")]
    Ledger(#[source] DiskError),
    #[error("VSS subprocess resource failure: {0}")]
    Subprocess(String),
}

/// Enumerate the Volume Shadow Copies in `image_path`. Degrades to
/// `vshadowinfo_available: false` when libvshadow is absent.
///
/// # Errors
/// * [`VssError::ImageNotFound`] — `image_path` missing.
pub fn vss_list(input: &VssListInput) -> Result<VssListOutput, VssError> {
    if !input.image_path.exists() {
        return Err(VssError::ImageNotFound(input.image_path.clone()));
    }
    let mut command = Command::new(vshadowinfo_bin());
    command.arg(&input.image_path);
    let output = match run_with_timeout(
        command,
        timeout_from_env_clamped(TIMEOUT_ENV, DEFAULT_TIMEOUT, HARD_TIMEOUT),
    ) {
        Ok(out) => out,
        Err(RunError::Spawn(ref error)) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(VssListOutput {
                vshadowinfo_available: false,
                has_shadow_store: false,
                store_count: 0,
                stores: Vec::new(),
            });
        }
        Err(error) => return Err(VssError::Subprocess(error.to_string())),
    };
    // vshadowinfo exits non-zero on a volume with no shadow store; that is a
    // valid "no snapshots" answer, not a tool failure.
    let text = String::from_utf8_lossy(&output.stdout);
    let stores = parse_vshadowinfo(&text);
    Ok(VssListOutput {
        vshadowinfo_available: true,
        has_shadow_store: !stores.is_empty(),
        store_count: stores.len(),
        stores: stores.into_iter().take(MAX_STORES).collect(),
    })
}

/// Parse `vshadowinfo` output into shadow stores. Pure over the text so it is
/// unit-tested without libvshadow. libvshadow prints a `Store: N` block per
/// snapshot with indented `Identifier:` and `Creation time:` labels.
fn parse_vshadowinfo(text: &str) -> Vec<ShadowStore> {
    let mut stores: Vec<ShadowStore> = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("Store:") {
            if let Ok(n) = rest.trim().parse::<u32>() {
                stores.push(ShadowStore {
                    store_number: n,
                    identifier: None,
                    creation_time: None,
                });
            }
        } else if let Some(rest) = trimmed.strip_prefix("Identifier") {
            if let Some(store) = stores.last_mut() {
                store.identifier = Some(clean_label_value(rest));
            }
        } else if let Some(rest) = trimmed.strip_prefix("Creation time") {
            if let Some(store) = stores.last_mut() {
                store.creation_time = Some(clean_label_value(rest));
            }
        }
    }
    stores.sort_by_key(|s| s.store_number);
    stores
}

/// Strip a libvshadow label's leading `:`/whitespace and trailing whitespace.
fn clean_label_value(rest: &str) -> String {
    rest.trim_start_matches([':', '\t', ' ']).trim().to_string()
}

/// Mount the shadow store's snapshots as `vssN` files under a case-scoped FUSE
/// mount. Degrades to `vshadowmount_available: false` when libvshadow is absent.
///
/// # Errors
/// * [`VssError::ImageNotFound`] — `image_path` missing.
/// * [`VssError::Case`] — the case directory is missing/unusable.
/// * [`VssError::MountPoint`] — the mount directory could not be created.
pub fn vss_mount(input: &VssMountInput) -> Result<VssMountOutput, VssError> {
    if !input.image_path.exists() {
        return Err(VssError::ImageNotFound(input.image_path.clone()));
    }
    if let Some(requested) = &input.mount_point {
        return Err(VssError::UnsafeMountPoint(requested.clone()));
    }
    let canonical_image = crate::pathnorm::canonicalize(&input.image_path)
        .map_err(|_| VssError::ImageNotFound(input.image_path.clone()))?;
    let admission = admit_case_mount(&input.case_id, MountKind::Vss, &canonical_image)
        .map_err(VssError::Ledger)?;
    if let Some(resource) = admission.existing() {
        return reused_vss_mount_output(resource);
    }
    let mount_id = format!("vss-mount-{}", Uuid::new_v4());
    let mount_point =
        create_case_mount_leaf(admission.case_dir(), &mount_id).map_err(VssError::Ledger)?;
    let mut cleanup = VssMountCleanup::new(mount_point.clone());

    let bin = vshadowmount_bin();
    let command = vec![
        bin.clone(),
        input.image_path.to_string_lossy().to_string(),
        mount_point.to_string_lossy().to_string(),
    ];

    let mut mount_command = Command::new(&bin);
    mount_command.arg(&input.image_path).arg(&mount_point);
    cleanup.record_attempt();
    let spawn = run_with_timeout(
        mount_command,
        timeout_from_env_clamped(TIMEOUT_ENV, DEFAULT_TIMEOUT, HARD_TIMEOUT),
    );
    let (vshadowmount_available, shadow_store_paths) = match spawn {
        Ok(out) if out.status.success() => (true, collect_vss_files(&mount_point)),
        Ok(_) => {
            return Ok(VssMountOutput {
                vshadowmount_available: true,
                mount_id,
                status: "unavailable".to_string(),
                mount_point,
                shadow_store_paths: Vec::new(),
                command,
            })
        }
        Err(RunError::Spawn(ref error)) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(VssMountOutput {
                vshadowmount_available: false,
                mount_id,
                status: "unavailable".to_string(),
                mount_point,
                shadow_store_paths: Vec::new(),
                command,
            })
        }
        Err(error) => return Err(VssError::Subprocess(error.to_string())),
    };
    let ledger_artifacts = shadow_store_paths
        .iter()
        .map(|path| {
            hash_bound_derived_artifact(&input.case_id, "vss_snapshot", &canonical_image, path)
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(VssError::Ledger)?;
    register_vss_mount_resource(
        &admission,
        &mount_id,
        &canonical_image,
        &mount_point,
        "mounted",
        &command,
        &ledger_artifacts,
    )
    .map_err(VssError::Ledger)?;
    cleanup.disarm();
    Ok(VssMountOutput {
        vshadowmount_available,
        mount_id,
        status: "mounted".to_string(),
        mount_point,
        shadow_store_paths,
        command,
    })
}

fn reused_vss_mount_output(resource: &SessionResource) -> Result<VssMountOutput, VssError> {
    let mount_point = resource
        .mount_point
        .clone()
        .ok_or_else(|| VssError::Ledger(DiskError::MountNotMounted(resource.id.clone())))?;
    Ok(VssMountOutput {
        vshadowmount_available: true,
        mount_id: resource.id.clone(),
        status: resource.status.clone(),
        mount_point,
        shadow_store_paths: resource
            .artifacts
            .iter()
            .map(|artifact| artifact.extracted_path.clone())
            .collect(),
        command: resource.command.clone(),
    })
}

/// The `vssN` snapshot files libvshadow exposes under the mount point, sorted.
fn collect_vss_files(mount_point: &Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(mount_point) else {
        return Vec::new();
    };
    let mut paths: Vec<PathBuf> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("vss"))
        })
        .collect();
    paths.sort();
    paths
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_multiple_shadow_stores_with_metadata() {
        let text = "\
vshadowinfo 20240506

Volume Shadow Snapshot information:
    Number of stores:\t2

Store: 1
    Identifier\t\t: 11111111-1111-1111-1111-111111111111
    Creation time\t\t: Mar 01, 2026 10:00:00
Store: 2
    Identifier\t\t: 22222222-2222-2222-2222-222222222222
    Creation time\t\t: Mar 05, 2026 12:30:00
";
        let stores = parse_vshadowinfo(text);
        assert_eq!(stores.len(), 2);
        assert_eq!(stores[0].store_number, 1);
        assert_eq!(
            stores[0].identifier.as_deref(),
            Some("11111111-1111-1111-1111-111111111111")
        );
        assert_eq!(stores[1].store_number, 2);
        assert!(stores[1]
            .creation_time
            .as_deref()
            .unwrap_or_default()
            .contains("Mar 05"));
    }

    #[test]
    fn no_shadow_store_yields_empty() {
        let text = "vshadowinfo 20240506\n\nNo Volume Shadow Snapshots found.\n";
        assert!(parse_vshadowinfo(text).is_empty());
    }

    #[test]
    fn stores_are_sorted_by_number() {
        let text = "Store: 3\nStore: 1\nStore: 2\n";
        let stores = parse_vshadowinfo(text);
        let nums: Vec<u32> = stores.iter().map(|s| s.store_number).collect();
        assert_eq!(nums, vec![1, 2, 3]);
    }

    #[test]
    fn clean_label_value_strips_colon_and_whitespace() {
        assert_eq!(clean_label_value("\t\t: value here"), "value here");
        assert_eq!(clean_label_value(": x"), "x");
    }

    #[test]
    #[cfg(unix)]
    fn repeated_vss_mount_reuses_one_active_resource_and_one_subprocess() {
        use std::os::unix::fs::PermissionsExt as _;

        let _env_guard = crate::env_lock();
        let tmp = tempfile::tempdir().expect("tempdir");
        let case_id = "vss-reuse-case";
        std::fs::create_dir_all(tmp.path().join("cases").join(case_id)).expect("case");
        let image = tmp.path().join("volume.dd");
        std::fs::write(&image, b"volume").expect("image");
        let calls = tmp.path().join("calls.log");
        let fake = tmp.path().join("vshadowmount");
        std::fs::write(
            &fake,
            format!(
                "#!/bin/sh\nprintf 'called\\n' >> '{}'\nprintf 'snapshot' > \"$2/vss1\"\n",
                calls.display()
            ),
        )
        .expect("fake binary");
        let mut permissions = std::fs::metadata(&fake).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&fake, permissions).unwrap();
        let previous_home = std::env::var_os("FINDEVIL_HOME");
        let previous_bin = std::env::var_os("FINDEVIL_VSHADOWMOUNT_BIN");
        std::env::set_var("FINDEVIL_HOME", tmp.path());
        std::env::set_var("FINDEVIL_VSHADOWMOUNT_BIN", &fake);

        let input = VssMountInput {
            case_id: case_id.to_string(),
            image_path: image,
            mount_point: None,
        };
        let first = vss_mount(&input).expect("first mount");
        let second = vss_mount(&input).expect("reused mount");

        match previous_home {
            Some(value) => std::env::set_var("FINDEVIL_HOME", value),
            None => std::env::remove_var("FINDEVIL_HOME"),
        }
        match previous_bin {
            Some(value) => std::env::set_var("FINDEVIL_VSHADOWMOUNT_BIN", value),
            None => std::env::remove_var("FINDEVIL_VSHADOWMOUNT_BIN"),
        }

        assert_eq!(second.mount_id, first.mount_id);
        assert_eq!(second.mount_point, first.mount_point);
        assert_eq!(std::fs::read_to_string(calls).unwrap().lines().count(), 1);
    }

    #[test]
    #[cfg(unix)]
    fn unavailable_vss_mount_removes_the_fresh_leaf_and_writes_no_resource() {
        use std::os::unix::fs::PermissionsExt as _;

        let _env_guard = crate::env_lock();
        let tmp = tempfile::tempdir().expect("tempdir");
        let case_id = "vss-unavailable-case";
        let case = tmp.path().join("cases").join(case_id);
        std::fs::create_dir_all(&case).expect("case");
        let image = tmp.path().join("volume.dd");
        std::fs::write(&image, b"volume").expect("image");
        let fake = tmp.path().join("vshadowmount-fail");
        std::fs::write(&fake, "#!/bin/sh\nexit 2\n").expect("fake binary");
        let cleanup_calls = tmp.path().join("cleanup-calls.log");
        let fake_umount = tmp.path().join("umount");
        std::fs::write(
            &fake_umount,
            format!(
                "#!/bin/sh\nprintf 'cleanup\\n' >> '{}'\n",
                cleanup_calls.display()
            ),
        )
        .expect("fake umount");
        let mut permissions = std::fs::metadata(&fake).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&fake, permissions).unwrap();
        let mut permissions = std::fs::metadata(&fake_umount).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&fake_umount, permissions).unwrap();
        let previous_home = std::env::var_os("FINDEVIL_HOME");
        let previous_bin = std::env::var_os("FINDEVIL_VSHADOWMOUNT_BIN");
        let previous_umount = std::env::var_os("FINDEVIL_UMOUNT_BIN");
        std::env::set_var("FINDEVIL_HOME", tmp.path());
        std::env::set_var("FINDEVIL_VSHADOWMOUNT_BIN", &fake);
        std::env::set_var("FINDEVIL_UMOUNT_BIN", &fake_umount);

        let output = vss_mount(&VssMountInput {
            case_id: case_id.to_string(),
            image_path: image,
            mount_point: None,
        })
        .expect("unavailable is a typed degrade");

        match previous_home {
            Some(value) => std::env::set_var("FINDEVIL_HOME", value),
            None => std::env::remove_var("FINDEVIL_HOME"),
        }
        match previous_bin {
            Some(value) => std::env::set_var("FINDEVIL_VSHADOWMOUNT_BIN", value),
            None => std::env::remove_var("FINDEVIL_VSHADOWMOUNT_BIN"),
        }
        match previous_umount {
            Some(value) => std::env::set_var("FINDEVIL_UMOUNT_BIN", value),
            None => std::env::remove_var("FINDEVIL_UMOUNT_BIN"),
        }

        assert_eq!(output.status, "unavailable");
        assert!(!output.mount_point.exists());
        assert!(!case.join("session_resources.json").exists());
        assert_eq!(
            std::fs::read_to_string(cleanup_calls)
                .expect("bounded cleanup subprocess ran")
                .lines()
                .count(),
            1
        );
    }
}
