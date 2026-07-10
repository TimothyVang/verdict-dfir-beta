//! Disk image mount/extract helpers.
//!
//! These tools intentionally expose a narrow typed surface rather than a
//! generic shell runner. Real mounting is best-effort on Unix/SIFT via fixed
//! tool invocations; tests and Windows use the explicit `mock` mode so normal
//! CI never needs FUSE, libewf, or administrator privileges.

use std::collections::{BTreeMap, VecDeque};
use std::fs;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{mpsc, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

use chrono::Utc;
use rusqlite::{Connection, ErrorCode};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

use super::ewf_segments::{is_first_ewf_segment, segment_paths_for_image};
use super::proc_runner::{
    kill_child_tree, quiesce_process_group, run_with_limits, run_with_limits_allow_background,
    spawn_isolated, CaptureLimits, ChildProcessGroup, RunError,
};

const LEDGER_NAME: &str = "session_resources.json";
const EXTRACTION_LOCK_DB: &str = ".disk-extract.lock.sqlite";
const STDERR_TAIL_BYTES: usize = 4096;
const HARD_MAX_ARTIFACTS: usize = 500;
const DEFAULT_MAX_ARTIFACT_BYTES: u64 = 512 * 1024 * 1024;
const HARD_MAX_ARTIFACT_BYTES: u64 = DEFAULT_MAX_ARTIFACT_BYTES;
const DEFAULT_MAX_TOTAL_BYTES: u64 = 8 * 1024 * 1024 * 1024;
const HARD_MAX_TOTAL_BYTES: u64 = DEFAULT_MAX_TOTAL_BYTES;
const HARD_MAX_ACCOUNTING_ENTRIES: usize = 100_000;
const HARD_MAX_ACTIVE_MOUNTS_PER_CASE: usize = 4;
const STREAM_BUFFER_BYTES: usize = 64 * 1024;
const FLS_STDOUT_MAX_BYTES: u64 = 256 * 1024 * 1024;
const FLS_STDERR_MAX_BYTES: u64 = 1024 * 1024;
const FLS_LINE_MAX_BYTES: u64 = 1024 * 1024;
const FLS_MAX_ENTRIES: usize = 1_000_000;
const FLS_READER_POLL_INTERVAL: Duration = Duration::from_millis(10);
const FLS_TIMEOUT_ENV: &str = "FINDEVIL_FLS_TIMEOUT_SECONDS";
const FLS_DEFAULT_TIMEOUT: Duration = Duration::from_secs(900);
const FLS_MAX_TIMEOUT: Duration = Duration::from_secs(1800);
const FLS_READER_SHUTDOWN_GRACE: Duration = Duration::from_millis(250);
const ICAT_TIMEOUT_ENV: &str = "FINDEVIL_ICAT_TIMEOUT_SECONDS";
const ICAT_DEFAULT_TIMEOUT: Duration = Duration::from_secs(300);
const ICAT_MAX_TIMEOUT: Duration = Duration::from_secs(900);
const ICAT_READER_SHUTDOWN_GRACE: Duration = Duration::from_millis(250);
const MMLS_TIMEOUT_ENV: &str = "FINDEVIL_MMLS_TIMEOUT_SECONDS";
const MMLS_DEFAULT_TIMEOUT: Duration = Duration::from_secs(60);
const MMLS_MAX_TIMEOUT: Duration = Duration::from_secs(300);
const MMLS_STDOUT_MAX_BYTES: u64 = 8 * 1024 * 1024;
const MMLS_STDERR_MAX_BYTES: u64 = 1024 * 1024;
const MMLS_READER_SHUTDOWN_GRACE: Duration = Duration::from_millis(250);
const MOCK_WALK_MAX_ENTRIES: usize = 100_000;
const MOCK_WALK_MAX_DEPTH: usize = 128;
const MOCK_WALK_MAX_METADATA_BYTES: u64 = 64 * 1024 * 1024;
const EVIDENCE_HASH_BUFFER_BYTES: usize = 1024 * 1024;
/// Command sentinel recorded for a mount that performs no FUSE/loop operation:
/// The Sleuth Kit reads the image directly, so `disk_extract_artifacts` (which
/// already reads off the recorded `image_path` via `fls`/`icat`) needs no live
/// mount. It is distinct from the `mock` sentinel so extraction still takes the
/// real-TSK path, and lets `disk_unmount` skip a teardown that never mounted
/// anything.
const DIRECT_TSK_COMMAND: &str = "direct-tsk";
const EWF_PROBE_TIMEOUT: Duration = Duration::from_secs(5);
const EWF_PROBE_CAPTURE_BYTES: usize = 64 * 1024;
const FIXED_COMMAND_TIMEOUT: Duration = Duration::from_secs(120);
const FIXED_COMMAND_STDOUT_BYTES: usize = 64 * 1024;
const FIXED_COMMAND_STDERR_BYTES: usize = 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct EffectiveExtractLimits {
    artifacts: usize,
    per_artifact_bytes: u64,
    total_bytes: u64,
    clamped: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct TskListLimits {
    stdout_bytes: u64,
    stderr_bytes: u64,
    line_bytes: u64,
    entries: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct MmlsProbeLimits {
    stdout_bytes: u64,
    stderr_bytes: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct MockWalkLimits {
    entries: usize,
    depth: usize,
    metadata_bytes: u64,
}

impl MockWalkLimits {
    const fn hard() -> Self {
        Self {
            entries: MOCK_WALK_MAX_ENTRIES,
            depth: MOCK_WALK_MAX_DEPTH,
            metadata_bytes: MOCK_WALK_MAX_METADATA_BYTES,
        }
    }
}

impl MmlsProbeLimits {
    const fn hard() -> Self {
        Self {
            stdout_bytes: MMLS_STDOUT_MAX_BYTES,
            stderr_bytes: MMLS_STDERR_MAX_BYTES,
        }
    }
}

impl TskListLimits {
    const fn hard() -> Self {
        Self {
            stdout_bytes: FLS_STDOUT_MAX_BYTES,
            stderr_bytes: FLS_STDERR_MAX_BYTES,
            line_bytes: FLS_LINE_MAX_BYTES,
            entries: FLS_MAX_ENTRIES,
        }
    }
}

fn bounded_timeout_from_raw(raw: Option<&str>, default: Duration, maximum: Duration) -> Duration {
    raw.and_then(|value| value.trim().parse::<u64>().ok())
        .filter(|seconds| *seconds > 0)
        .map_or(default, |seconds| {
            Duration::from_secs(seconds.min(maximum.as_secs()))
        })
}

fn fls_timeout_from_raw(raw: Option<&str>) -> Duration {
    bounded_timeout_from_raw(raw, FLS_DEFAULT_TIMEOUT, FLS_MAX_TIMEOUT)
}

fn fls_timeout() -> Duration {
    fls_timeout_from_raw(std::env::var(FLS_TIMEOUT_ENV).ok().as_deref())
}

fn icat_timeout_from_raw(raw: Option<&str>) -> Duration {
    bounded_timeout_from_raw(raw, ICAT_DEFAULT_TIMEOUT, ICAT_MAX_TIMEOUT)
}

fn icat_timeout() -> Duration {
    icat_timeout_from_raw(std::env::var(ICAT_TIMEOUT_ENV).ok().as_deref())
}

fn mmls_timeout_from_raw(raw: Option<&str>) -> Duration {
    bounded_timeout_from_raw(raw, MMLS_DEFAULT_TIMEOUT, MMLS_MAX_TIMEOUT)
}

fn mmls_timeout() -> Duration {
    mmls_timeout_from_raw(std::env::var(MMLS_TIMEOUT_ENV).ok().as_deref())
}

#[derive(Debug, PartialEq, Eq)]
struct TskListing {
    entries: Vec<FlsEntry>,
    entries_seen: usize,
    stdout_bytes: u64,
    stderr_bytes: u64,
    stderr_tail: String,
    truncated: bool,
    limit_reason: Option<String>,
    timeout: Duration,
}

impl TskListing {
    const fn mock(entries: Vec<FlsEntry>) -> Self {
        Self {
            entries_seen: entries.len(),
            entries,
            stdout_bytes: 0,
            stderr_bytes: 0,
            stderr_tail: String::new(),
            truncated: false,
            limit_reason: None,
            timeout: Duration::ZERO,
        }
    }
}

fn effective_extract_limits(
    requested_artifacts: usize,
    requested_per_artifact_bytes: u64,
    requested_total_bytes: u64,
) -> EffectiveExtractLimits {
    let artifacts = requested_artifacts.min(HARD_MAX_ARTIFACTS);
    let per_artifact_bytes = requested_per_artifact_bytes.min(HARD_MAX_ARTIFACT_BYTES);
    let total_bytes = requested_total_bytes.min(HARD_MAX_TOTAL_BYTES);
    EffectiveExtractLimits {
        artifacts,
        per_artifact_bytes,
        total_bytes,
        clamped: artifacts != requested_artifacts
            || per_artifact_bytes != requested_per_artifact_bytes
            || total_bytes != requested_total_bytes,
    }
}

struct ExtractionSource<'a> {
    image_paths: &'a [PathBuf],
    sector_offset: Option<u64>,
    output_dir: &'a Path,
    mock_root: Option<&'a Path>,
    via_walk: bool,
    icat_timeout: Duration,
}

fn extract_selected_artifacts(
    source: &ExtractionSource<'_>,
    selected: &[Candidate],
    limits: EffectiveExtractLimits,
    case_extracted_bytes_before: u64,
) -> Result<(Vec<ExtractedDiskArtifact>, ExtractStats), DiskError> {
    let mut artifacts = Vec::new();
    let mut stats = ExtractStats::default();
    for (index, candidate) in selected.iter().enumerate() {
        let remaining_total = limits
            .total_bytes
            .saturating_sub(case_extracted_bytes_before)
            .saturating_sub(stats.extracted_bytes);
        if remaining_total == 0 {
            stats.skipped_total_limit += selected.len().saturating_sub(index);
            stats.aggregate_limit_reached = true;
            break;
        }
        let aggregate_limit_reached = match (source.via_walk, source.mock_root) {
            (true, Some(root)) => mock_extract(
                root,
                candidate,
                source.output_dir,
                limits.per_artifact_bytes,
                remaining_total,
                &mut artifacts,
                &mut stats,
            )?,
            _ => tsk_extract(
                source.image_paths,
                source.sector_offset,
                candidate,
                source.output_dir,
                limits.per_artifact_bytes,
                remaining_total,
                source.icat_timeout,
                &mut artifacts,
                &mut stats,
            )?,
        };
        if aggregate_limit_reached {
            stats.skipped_total_limit += selected.len().saturating_sub(index + 1);
            stats.aggregate_limit_reached = true;
            break;
        }
    }
    Ok((artifacts, stats))
}

struct LimitSummary {
    truncated: bool,
    reasons: Vec<String>,
    case_extracted_bytes_after: u64,
}

#[derive(Debug)]
struct CaseExtractionLock {
    connection: Connection,
}

impl CaseExtractionLock {
    fn acquire(case_dir: &Path) -> Result<Self, DiskError> {
        let path = case_dir.join(EXTRACTION_LOCK_DB);
        let connection =
            Connection::open(&path).map_err(|err| extraction_lock_error(&path, &err))?;
        connection
            .busy_timeout(Duration::ZERO)
            .map_err(|err| extraction_lock_error(&path, &err))?;
        connection
            .execute_batch("BEGIN IMMEDIATE")
            .map_err(|err| extraction_lock_error(&path, &err))?;
        Ok(Self { connection })
    }
}

impl Drop for CaseExtractionLock {
    fn drop(&mut self) {
        let _ = self.connection.execute_batch("ROLLBACK");
    }
}

fn extraction_lock_error(path: &Path, err: &rusqlite::Error) -> DiskError {
    match err {
        rusqlite::Error::SqliteFailure(code, _)
            if matches!(
                code.code,
                ErrorCode::DatabaseBusy | ErrorCode::DatabaseLocked
            ) =>
        {
            DiskError::DiskSessionBusy(path.to_path_buf())
        }
        _ => DiskError::ExtractionLock {
            path: path.to_path_buf(),
            message: err.to_string(),
        },
    }
}

fn summarize_limits(
    artifacts_skipped_limit: usize,
    stats: &ExtractStats,
    case_extracted_bytes_before: u64,
) -> LimitSummary {
    let truncated = artifacts_skipped_limit > 0
        || stats.skipped_oversize > 0
        || stats.skipped_total_limit > 0
        || stats.extraction_failed > 0;
    let mut reasons = Vec::new();
    if artifacts_skipped_limit > 0 {
        reasons.push("artifact_count_limit".to_string());
    }
    if stats.skipped_oversize > 0 {
        reasons.push("per_artifact_bytes".to_string());
    }
    if stats.aggregate_limit_reached || stats.skipped_total_limit > 0 {
        reasons.push("aggregate_bytes".to_string());
    }
    if stats.extraction_failed > 0 {
        reasons.push("artifact_extraction_failed".to_string());
    }
    LimitSummary {
        truncated,
        reasons,
        case_extracted_bytes_after: case_extracted_bytes_before
            .saturating_add(stats.extracted_bytes),
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DiskMode {
    #[default]
    Auto,
    Mock,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MountKind {
    DiskAuto,
    DiskMock,
    Vss,
}

impl MountKind {
    const fn resource_type(self) -> &'static str {
        match self {
            Self::DiskAuto | Self::DiskMock => "disk_mount",
            Self::Vss => "vss_mount",
        }
    }

    fn matches_resource(self, resource: &SessionResource) -> bool {
        if resource.resource_type != self.resource_type() || resource.status != "mounted" {
            return false;
        }
        match self {
            Self::DiskAuto => resource.command.first().map(String::as_str) != Some("mock"),
            Self::DiskMock => resource.command.first().map(String::as_str) == Some("mock"),
            Self::Vss => true,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactKind {
    Mft,
    UsnJrnl,
    Prefetch,
    Registry,
    Evtx,
    YaraTarget,
    Amcache,
    Srum,
    Lnk,
    Jumplist,
    ScheduledTask,
    Recyclebin,
    RegTxlog,
    BrowserDb,
    LegacyEvt,
    IeHistory,
    Thumbnail,
    LinuxAccount,
    LinuxLog,
    LinuxShellHistory,
    LinuxSsh,
    LinuxCron,
    MacosUnifiedlog,
    MacosActivity,
    MacosLaunchd,
    MacosFsevents,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DiskMountInput {
    pub case_id: String,
    pub image_path: PathBuf,
    /// Reserved for wire compatibility. Product calls must omit this field;
    /// the server creates a fresh leaf under the current Case.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mount_point: Option<PathBuf>,
    #[serde(default)]
    pub mode: DiskMode,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DiskExtractArtifactsInput {
    pub case_id: String,
    pub mount_id: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub artifact_kinds: Vec<ArtifactKind>,
    #[serde(default = "default_limit")]
    pub limit: usize,
    #[serde(default = "default_max_artifact_bytes")]
    pub max_artifact_bytes: u64,
    /// Aggregate extracted-byte budget for this Case. The server clamps this
    /// to its hard ceiling and subtracts artifacts already committed to the
    /// case ledger, so repeated calls cannot multiply the per-file ceiling.
    #[serde(default = "default_max_total_bytes")]
    pub max_total_bytes: u64,
    /// Also recover deleted-but-metadata-intact files (unallocated dirents
    /// whose inode still resolves). Entries whose inode was reallocated to a
    /// live file are always skipped — extracting them would return the reusing
    /// file's bytes. Recovered files stage under `<class>/__deleted__/<inode>/`
    /// and never crowd allocated files out of the class budget.
    #[serde(default = "default_true")]
    pub recover_deleted: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DiskUnmountInput {
    pub case_id: String,
    pub mount_id: String,
    #[serde(default)]
    pub mode: DiskMode,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct DiskMountOutput {
    pub case_id: String,
    pub mount_id: String,
    pub status: String,
    pub image_path: PathBuf,
    pub mount_point: PathBuf,
    pub fs_root: PathBuf,
    pub ledger_path: PathBuf,
    pub command: Vec<String>,
    pub stderr_tail: String,
    pub note: String,
    /// Every filesystem partition enumerated from the image's `mmls` table (empty
    /// for a bare volume image with no table, in mock mode, or when mmls is
    /// unavailable). The tool mounts/extracts the primary (largest) volume; this
    /// list makes any additional volumes visible so multi-volume disks are not
    /// silently reduced to one. Defaults keep older ledgers deserializing.
    #[serde(default)]
    pub partitions: Vec<MmlsPartition>,
    /// Bounded partition enumeration failed after the read-only mount was
    /// established. The mount remains registered and usable, but partition
    /// coverage is explicitly limited rather than being reported as empty.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub partition_enumeration_error: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ExtractedDiskArtifact {
    pub artifact_class: String,
    pub source_path: PathBuf,
    pub extracted_path: PathBuf,
    pub size_bytes: u64,
    /// SHA-256 of the exact staged bytes. Downstream MCP reads authorize this
    /// path only when the current bytes still match this ledger binding.
    #[serde(default)]
    pub sha256: String,
    /// True when this artifact was recovered from a deleted (unallocated)
    /// directory entry rather than a live file. Default keeps pre-existing
    /// ledgers deserializing.
    #[serde(default)]
    pub recovered_deleted: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct DiskExtractArtifactsOutput {
    pub case_id: String,
    pub mount_id: String,
    pub extract_id: String,
    pub output_dir: PathBuf,
    pub artifacts: Vec<ExtractedDiskArtifact>,
    pub artifacts_seen: usize,
    /// Classified candidates seen before the count budget was applied.
    #[serde(default)]
    pub artifact_candidates_seen: usize,
    /// Bounded `fls` enumeration telemetry. Historical recorded outputs omit
    /// these additive fields and deserialize to their serde defaults.
    #[serde(default)]
    pub listing_entries_seen: usize,
    #[serde(default)]
    pub listing_stdout_bytes: u64,
    #[serde(default)]
    pub listing_stderr_bytes: u64,
    #[serde(default)]
    pub listing_stderr_tail: String,
    #[serde(default)]
    pub listing_truncated: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listing_limit_reason: Option<String>,
    #[serde(default)]
    pub listing_max_entries: usize,
    #[serde(default)]
    pub listing_max_stdout_bytes: u64,
    #[serde(default)]
    pub listing_max_stderr_bytes: u64,
    #[serde(default)]
    pub listing_max_line_bytes: u64,
    #[serde(default)]
    pub listing_timeout_seconds: u64,
    #[serde(default)]
    pub icat_timeout_seconds: u64,
    /// Candidates not selected because the effective artifact-count ceiling
    /// was reached.
    #[serde(default)]
    pub artifacts_skipped_limit: usize,
    pub artifacts_skipped_oversize: usize,
    /// Selected artifacts skipped when they could not fit inside the
    /// remaining case-wide extracted-byte budget.
    #[serde(default)]
    pub artifacts_skipped_total_limit: usize,
    /// Selected artifacts for which the extractor produced no usable output
    /// for a non-quota reason (for example, a nonzero `icat` exit).
    #[serde(default)]
    pub artifacts_extraction_failed: usize,
    /// Caller values are retained beside the effective server-side ceilings
    /// so a report cannot mistake a clamped request for full requested scope.
    #[serde(default)]
    pub requested_limit: usize,
    #[serde(default)]
    pub effective_limit: usize,
    #[serde(default)]
    pub requested_max_artifact_bytes: u64,
    pub max_artifact_bytes: u64,
    #[serde(default)]
    pub requested_max_total_bytes: u64,
    #[serde(default)]
    pub max_total_bytes: u64,
    #[serde(default)]
    pub extracted_bytes: u64,
    #[serde(default)]
    pub case_extracted_bytes_before: u64,
    #[serde(default)]
    pub case_extracted_bytes_after: u64,
    #[serde(default)]
    pub limits_clamped: bool,
    #[serde(default)]
    pub truncated: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub limit_reasons: Vec<String>,
    /// Deleted entries observed in the filesystem listing (including ones
    /// skipped as reallocated). Defaults keep pre-existing recorded outputs
    /// deserializing.
    #[serde(default)]
    pub deleted_entries_seen: usize,
    /// Deleted entries whose content was recovered and staged.
    #[serde(default)]
    pub deleted_recovered: usize,
    /// Deleted entries skipped because their inode was reused by a live file.
    #[serde(default)]
    pub deleted_skipped_realloc: usize,
    /// Deleted entries selected for recovery whose content was unreadable or
    /// empty.
    #[serde(default)]
    pub deleted_recovery_failed: usize,
    pub ledger_path: PathBuf,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct DiskUnmountOutput {
    pub case_id: String,
    pub mount_id: String,
    pub status: String,
    pub ledger_path: PathBuf,
    pub command: Vec<String>,
    pub stderr_tail: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct SessionResource {
    pub id: String,
    pub resource_type: String,
    pub status: String,
    pub created_at: String,
    pub updated_at: String,
    pub image_path: Option<PathBuf>,
    pub mount_point: Option<PathBuf>,
    pub fs_root: Option<PathBuf>,
    pub parent_id: Option<String>,
    pub output_dir: Option<PathBuf>,
    pub artifacts: Vec<ExtractedDiskArtifact>,
    pub command: Vec<String>,
    pub note: String,
    #[serde(default)]
    pub partitions: Vec<MmlsPartition>,
    #[serde(default)]
    pub partition_enumeration_error: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
struct SessionLedger {
    resources: Vec<SessionResource>,
}

/// Holds the per-case ledger lock from quota/reuse admission through either
/// mount registration or an idempotent response. This prevents parallel MCP
/// connections from both observing a free slot and allocating mounts at once.
pub(crate) struct CaseMountAdmission {
    case_id: String,
    case_dir: PathBuf,
    ledger_path: PathBuf,
    existing: Option<SessionResource>,
    _lock: CaseExtractionLock,
}

impl CaseMountAdmission {
    pub(crate) const fn case_id(&self) -> &str {
        self.case_id.as_str()
    }

    pub(crate) fn case_dir(&self) -> &Path {
        &self.case_dir
    }

    pub(crate) fn ledger_path(&self) -> &Path {
        &self.ledger_path
    }

    pub(crate) const fn existing(&self) -> Option<&SessionResource> {
        self.existing.as_ref()
    }
}

#[derive(Debug, Error)]
pub enum DiskError {
    #[error("case not found: {0}")]
    CaseNotFound(String),
    #[error("invalid case_id (must match [A-Za-z0-9_-]+, no path separators or '.'/'..'): {0}")]
    InvalidCaseId(String),
    #[error("evidence image not found: {0}")]
    ImageNotFound(PathBuf),
    #[error("mount resource not found: {0}")]
    MountNotFound(String),
    #[error("mount resource is not mounted: {0}")]
    MountNotMounted(String),
    #[error("disk evidence integrity mismatch for case {case_id}")]
    IntegrityMismatch { case_id: String },
    #[error("disk evidence authorization state is invalid for case {case_id}: {message}")]
    IntegrityState { case_id: String, message: String },
    #[error("cannot verify disk evidence integrity at {path}: {source}")]
    IntegrityRead {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error(
        "disk evidence integrity changed while mounting case {case_id}, and rollback failed: \
         {rollback_error}"
    )]
    MountIntegrityRollbackFailed {
        case_id: String,
        rollback_error: String,
    },
    #[error("another disk mount/extract/unmount update is already in progress for this Case: {0}")]
    DiskSessionBusy(PathBuf),
    #[error("cannot acquire disk extraction lock at {path}: {message}")]
    ExtractionLock { path: PathBuf, message: String },
    #[error("unsafe disk extraction staging root (must be a real directory): {0}")]
    UnsafeExtractionRoot(PathBuf),
    #[error("unsafe mount point (mount paths are fresh server-managed case leaves): {0}")]
    UnsafeMountPoint(PathBuf),
    #[error("mount root not found: {0}")]
    MountRootNotFound(PathBuf),
    #[error("case {case_id} already has the active mount limit of {limit}")]
    ActiveMountLimit { case_id: String, limit: usize },
    #[error("unsupported on this platform without mode=mock")]
    UnsupportedPlatform,
    #[error("subprocess failed ({status}): {stderr_tail}")]
    SubprocessFailed { status: String, stderr_tail: String },
    #[error(
        "fls {stream} {limit_kind} limit exceeded: limit={limit}, \
         observed_at_least={observed}; subprocess killed and partial listing refused"
    )]
    ListingLimitExceeded {
        stream: String,
        limit_kind: String,
        limit: u64,
        observed: u64,
    },
    #[error("cannot read bounded fls {stream}: {message}")]
    ListingRead { stream: String, message: String },
    #[error("bounded fls output reader thread terminated unexpectedly")]
    ListingReaderTerminated,
    #[error(
        "fls exceeded its hard wall-clock timeout of {timeout:?}; \
         subprocess tree killed and partial listing refused"
    )]
    ListingTimeout { timeout: Duration },
    #[error(
        "icat exceeded its hard per-artifact wall-clock timeout of {timeout:?}; \
         subprocess tree killed and partial output removed"
    )]
    IcatTimeout { timeout: Duration },
    #[error("bounded icat output reader thread terminated unexpectedly")]
    IcatReaderTerminated,
    #[error(
        "{operation} exceeded its hard wall-clock timeout of {timeout:?}; \
         subprocess tree killed and partial output refused"
    )]
    MmlsTimeout {
        operation: String,
        timeout: Duration,
    },
    #[error(
        "{operation} {stream} exceeded its {limit}-byte output limit \
         (observed at least {observed}); subprocess tree killed and partial output refused"
    )]
    MmlsOutputLimitExceeded {
        operation: String,
        stream: String,
        limit: u64,
        observed: u64,
    },
    #[error("cannot read bounded {operation} {stream}: {message}")]
    MmlsRead {
        operation: String,
        stream: String,
        message: String,
    },
    #[error("bounded {operation} output reader thread terminated unexpectedly")]
    MmlsReaderTerminated { operation: String },
    #[error(
        "mock evidence traversal {limit_kind} limit exceeded under {root}: \
         limit={limit}, observed={observed}; traversal stopped and coverage refused"
    )]
    MockTraversalLimitExceeded {
        root: PathBuf,
        limit_kind: String,
        limit: u64,
        observed: u64,
    },
    #[error(
        "mounted disk {failed_mount_id} could not be registered in {failed_ledger_path}: \
         {persistence_error}; rollback_attempted={rollback_attempted}; \
         rollback_error={rollback_error:?}"
    )]
    MountRegistrationFailed {
        failed_mount_id: String,
        failed_ledger_path: PathBuf,
        persistence_error: String,
        rollback_attempted: bool,
        rollback_error: Option<String>,
    },
    #[error("{0}")]
    EwfSegmentSet(String),
    #[error(
        "cannot read EWF image {image}: {bin} is unavailable and this Sleuth Kit build \
         reports no `ewf` image type (`mmls -i list`). Reading the segments directly would \
         silently yield zero artifacts instead of failing, so the disk lane is refused rather \
         than reporting a phantom clean disk. Install ewf-tools/libewf so {bin} resolves, or \
         run the DFIR container backend (`scripts/verdict --docker`)."
    )]
    EwfReaderUnavailable { image: PathBuf, bin: String },
    #[error("io error at {path}: {source}")]
    Io { path: PathBuf, source: io::Error },
    #[error("cannot serialize session resource ledger: {0}")]
    Serialize(#[from] serde_json::Error),
}

#[derive(Debug, Deserialize)]
struct DiskCaseManifest {
    id: String,
    image_path: PathBuf,
    image_hash: String,
    image_size_bytes: u64,
    #[serde(default)]
    image_segments: Vec<PathBuf>,
}

struct AuthorizedDiskImage {
    case_id: String,
    canonical_path: PathBuf,
    segment_paths: Vec<PathBuf>,
    expected_sha256: String,
    expected_size_bytes: u64,
}

fn integrity_mismatch(case_id: &str) -> DiskError {
    DiskError::IntegrityMismatch {
        case_id: case_id.to_string(),
    }
}

fn canonical_bound_file(case_id: &str, path: &Path) -> Result<PathBuf, DiskError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| DiskError::IntegrityRead {
        path: path.to_path_buf(),
        source,
    })?;
    #[cfg(unix)]
    let has_one_link = {
        use std::os::unix::fs::MetadataExt as _;
        metadata.nlink() == 1
    };
    #[cfg(not(unix))]
    let has_one_link = true;
    if !metadata.is_file() || metadata.file_type().is_symlink() || !has_one_link {
        return Err(integrity_mismatch(case_id));
    }
    crate::pathnorm::canonicalize(path).map_err(|source| DiskError::IntegrityRead {
        path: path.to_path_buf(),
        source,
    })
}

fn current_segment_paths(case_id: &str, first_path: &Path) -> Result<Vec<PathBuf>, DiskError> {
    segment_paths_for_image(first_path)
        .map_err(|_| integrity_mismatch(case_id))?
        .iter()
        .map(|path| canonical_bound_file(case_id, path))
        .collect()
}

fn sha256_bound_files(paths: &[PathBuf]) -> Result<String, DiskError> {
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; EVIDENCE_HASH_BUFFER_BYTES];
    for path in paths {
        let file = fs::File::open(path).map_err(|source| DiskError::IntegrityRead {
            path: path.clone(),
            source,
        })?;
        let mut reader = BufReader::with_capacity(EVIDENCE_HASH_BUFFER_BYTES, file);
        loop {
            let count = reader
                .read(&mut buffer)
                .map_err(|source| DiskError::IntegrityRead {
                    path: path.clone(),
                    source,
                })?;
            if count == 0 {
                break;
            }
            hasher.update(&buffer[..count]);
        }
    }
    Ok(hex::encode(hasher.finalize()))
}

fn verify_extracted_artifacts(
    case_id: &str,
    artifacts: &[ExtractedDiskArtifact],
) -> Result<(), DiskError> {
    for artifact in artifacts {
        if artifact.sha256.len() != 64
            || !artifact.sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(integrity_mismatch(case_id));
        }
        let canonical_path = canonical_bound_file(case_id, &artifact.extracted_path)?;
        let metadata =
            fs::symlink_metadata(&canonical_path).map_err(|source| DiskError::IntegrityRead {
                path: canonical_path.clone(),
                source,
            })?;
        if metadata.len() != artifact.size_bytes
            || !artifact
                .sha256
                .eq_ignore_ascii_case(&sha256_bound_files(&[canonical_path])?)
        {
            return Err(integrity_mismatch(case_id));
        }
    }
    Ok(())
}

fn verify_authorized_disk_image(binding: &AuthorizedDiskImage) -> Result<(), DiskError> {
    let current_segments = current_segment_paths(&binding.case_id, &binding.canonical_path)?;
    if current_segments != binding.segment_paths {
        return Err(integrity_mismatch(&binding.case_id));
    }
    let current_size = current_segments.iter().try_fold(0u64, |total, path| {
        let metadata = fs::symlink_metadata(path).map_err(|source| DiskError::IntegrityRead {
            path: path.clone(),
            source,
        })?;
        Ok::<u64, DiskError>(total.saturating_add(metadata.len()))
    })?;
    if current_size != binding.expected_size_bytes {
        return Err(integrity_mismatch(&binding.case_id));
    }
    let current_sha256 = sha256_bound_files(&current_segments)?;
    if !binding
        .expected_sha256
        .eq_ignore_ascii_case(&current_sha256)
    {
        return Err(integrity_mismatch(&binding.case_id));
    }
    Ok(())
}

fn authorize_disk_image(
    case_id: &str,
    requested_path: &Path,
) -> Result<AuthorizedDiskImage, DiskError> {
    let requested_metadata = fs::symlink_metadata(requested_path)
        .map_err(|_| DiskError::ImageNotFound(requested_path.to_path_buf()))?;
    if !requested_metadata.is_file() || requested_metadata.file_type().is_symlink() {
        return Err(DiskError::ImageNotFound(requested_path.to_path_buf()));
    }
    let requested_canonical =
        crate::pathnorm::canonicalize(requested_path).map_err(|source| DiskError::Io {
            path: requested_path.to_path_buf(),
            source,
        })?;
    let manifest_path = case_dir(case_id)?.join("case.json");
    let manifest_metadata =
        fs::symlink_metadata(&manifest_path).map_err(|source| DiskError::IntegrityRead {
            path: manifest_path.clone(),
            source,
        })?;
    if !manifest_metadata.is_file() || manifest_metadata.file_type().is_symlink() {
        return Err(DiskError::IntegrityState {
            case_id: case_id.to_string(),
            message: "case manifest is not a regular file".to_string(),
        });
    }
    let manifest_bytes = fs::read(&manifest_path).map_err(|source| DiskError::IntegrityRead {
        path: manifest_path.clone(),
        source,
    })?;
    let manifest: DiskCaseManifest =
        serde_json::from_slice(&manifest_bytes).map_err(|error| DiskError::IntegrityState {
            case_id: case_id.to_string(),
            message: format!("cannot decode case manifest: {error}"),
        })?;
    if manifest.id != case_id || manifest.image_hash.len() != 64 {
        return Err(DiskError::IntegrityState {
            case_id: case_id.to_string(),
            message: "case manifest identity or SHA-256 is invalid".to_string(),
        });
    }
    let registered_path = canonical_bound_file(case_id, &manifest.image_path)?;
    if requested_canonical != registered_path {
        return Err(integrity_mismatch(case_id));
    }
    let expected_segments = if manifest.image_segments.is_empty() {
        vec![registered_path.clone()]
    } else {
        manifest
            .image_segments
            .iter()
            .map(|path| canonical_bound_file(case_id, path))
            .collect::<Result<Vec<_>, _>>()?
    };
    let current_segments = current_segment_paths(case_id, &registered_path)?;
    if expected_segments != current_segments || expected_segments.first() != Some(&registered_path)
    {
        return Err(integrity_mismatch(case_id));
    }
    let binding = AuthorizedDiskImage {
        case_id: case_id.to_string(),
        canonical_path: registered_path,
        segment_paths: current_segments,
        expected_sha256: manifest.image_hash,
        expected_size_bytes: manifest.image_size_bytes,
    };
    verify_authorized_disk_image(&binding)?;
    Ok(binding)
}

struct MountedDiskRegistration {
    case_id: String,
    mount_id: String,
    status: String,
    image_path: PathBuf,
    mount_point: PathBuf,
    fs_root: PathBuf,
    ledger_path: PathBuf,
    command: Vec<String>,
    stderr_tail: String,
    note: String,
}

/// Best-effort rollback for a fresh mount leaf until its ownership is durably
/// transferred to the session ledger. The guard also runs during unwinding, so
/// a parser panic cannot silently strand an untracked device/FUSE mount.
struct UnregisteredMountCleanup {
    mount_point: PathBuf,
    fs_root: Option<PathBuf>,
    attempted: bool,
    virtual_mount: bool,
    armed: bool,
}

impl UnregisteredMountCleanup {
    const fn new(mount_point: PathBuf) -> Self {
        Self {
            mount_point,
            fs_root: None,
            attempted: false,
            virtual_mount: false,
            armed: true,
        }
    }

    const fn record_attempt(&mut self) {
        self.attempted = true;
    }

    fn record_virtual_mount(&mut self, fs_root: PathBuf) {
        self.attempted = true;
        self.virtual_mount = true;
        self.fs_root = Some(fs_root);
    }

    fn record_mount(&mut self, fs_root: PathBuf, command: &[String]) {
        self.attempted = true;
        self.virtual_mount = matches!(
            command.first().map(String::as_str),
            Some("mock" | DIRECT_TSK_COMMAND)
        );
        self.fs_root = Some(fs_root);
    }

    const fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for UnregisteredMountCleanup {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        if self.attempted && !self.virtual_mount {
            let inferred_root = self.fs_root.clone().or_else(|| {
                let fs_root = self.mount_point.join("fs");
                if directory_has_entries(&fs_root) {
                    return Some(fs_root);
                }
                let ewf_root = self.mount_point.join("ewf");
                if directory_has_entries(&ewf_root) {
                    return Some(ewf_root);
                }
                directory_has_entries(&self.mount_point).then(|| self.mount_point.clone())
            });
            if let Some(fs_root) = inferred_root {
                let _ = auto_unmount(&self.mount_point, &fs_root);
            }
        }
        let _ = fs::remove_dir(self.mount_point.join("fs"));
        let _ = fs::remove_dir(self.mount_point.join("ewf"));
        let _ = fs::remove_dir(&self.mount_point);
    }
}

fn directory_has_entries(path: &Path) -> bool {
    fs::read_dir(path)
        .ok()
        .and_then(|mut entries| entries.next())
        .is_some()
}

fn persist_mounted_disk(
    registration: MountedDiskRegistration,
    partition_result: Result<Vec<MmlsPartition>, DiskError>,
) -> Result<DiskMountOutput, DiskError> {
    persist_mounted_disk_with_rollback(registration, partition_result, rollback_unregistered_mount)
}

fn rollback_unregistered_mount(registration: &MountedDiskRegistration) -> Result<bool, DiskError> {
    let virtual_mount = matches!(
        registration.command.first().map(String::as_str),
        Some("mock" | DIRECT_TSK_COMMAND)
    );
    if virtual_mount {
        return Ok(false);
    }
    auto_unmount(&registration.mount_point, &registration.fs_root)?;
    Ok(true)
}

fn persist_mounted_disk_with_rollback(
    registration: MountedDiskRegistration,
    partition_result: Result<Vec<MmlsPartition>, DiskError>,
    rollback: impl FnOnce(&MountedDiskRegistration) -> Result<bool, DiskError>,
) -> Result<DiskMountOutput, DiskError> {
    let (partitions, partition_enumeration_error) = match partition_result {
        Ok(partitions) => (partitions, None),
        Err(err) => (Vec::new(), Some(err.to_string())),
    };
    let mut note = registration.note.clone();
    if let Some(error) = &partition_enumeration_error {
        note.push_str("; partition enumeration limited: ");
        note.push_str(error);
    }
    let now = now_iso();
    let resource = SessionResource {
        id: registration.mount_id.clone(),
        resource_type: "disk_mount".to_string(),
        status: registration.status.clone(),
        created_at: now.clone(),
        updated_at: now,
        image_path: Some(registration.image_path.clone()),
        mount_point: Some(registration.mount_point.clone()),
        fs_root: Some(registration.fs_root.clone()),
        parent_id: None,
        output_dir: None,
        artifacts: vec![],
        command: registration.command.clone(),
        note: note.clone(),
        partitions: partitions.clone(),
        partition_enumeration_error: partition_enumeration_error.clone(),
    };
    if let Err(err) = upsert_resource(&registration.ledger_path, resource) {
        let (rollback_attempted, rollback_error) = match rollback(&registration) {
            Ok(attempted) => (attempted, None),
            Err(rollback_err) => (true, Some(rollback_err.to_string())),
        };
        return Err(DiskError::MountRegistrationFailed {
            failed_mount_id: registration.mount_id,
            failed_ledger_path: registration.ledger_path,
            persistence_error: err.to_string(),
            rollback_attempted,
            rollback_error,
        });
    }

    Ok(DiskMountOutput {
        case_id: registration.case_id,
        mount_id: registration.mount_id,
        status: registration.status,
        image_path: registration.image_path,
        mount_point: registration.mount_point,
        fs_root: registration.fs_root,
        ledger_path: registration.ledger_path,
        command: registration.command,
        stderr_tail: registration.stderr_tail,
        note,
        partitions,
        partition_enumeration_error,
    })
}

pub fn disk_mount(input: &DiskMountInput) -> Result<DiskMountOutput, DiskError> {
    if let Some(requested) = &input.mount_point {
        return Err(DiskError::UnsafeMountPoint(requested.clone()));
    }
    let binding = authorize_disk_image(&input.case_id, &input.image_path)?;
    let mount_kind = match input.mode {
        DiskMode::Auto => MountKind::DiskAuto,
        DiskMode::Mock => MountKind::DiskMock,
    };
    let admission = admit_case_mount(&input.case_id, mount_kind, &binding.canonical_path)?;
    if let Some(resource) = admission.existing() {
        return reused_disk_mount_output(input, resource, admission.ledger_path());
    }
    let case_dir = admission.case_dir();
    let ledger_path = admission.ledger_path().to_path_buf();
    let mount_id = format!("disk-mount-{}", Uuid::new_v4());
    let mount_point = create_case_mount_leaf(case_dir, &mount_id)?;
    let mut cleanup = UnregisteredMountCleanup::new(mount_point.clone());
    let image_paths = binding.segment_paths.clone();

    let (status, fs_root, command, stderr_tail, note) = match input.mode {
        DiskMode::Mock => {
            cleanup.record_virtual_mount(mount_point.clone());
            (
                "mounted".to_string(),
                mount_point.clone(),
                vec!["mock".to_string(), "disk_mount".to_string()],
                String::new(),
                "mock mount registered; no privileged filesystem operation ran".to_string(),
            )
        }
        DiskMode::Auto => {
            cleanup.record_attempt();
            let result = auto_mount(&image_paths, &mount_point)?;
            cleanup.record_mount(result.1.clone(), &result.2);
            result
        }
    };
    let registration = MountedDiskRegistration {
        case_id: input.case_id.clone(),
        mount_id,
        status,
        image_path: binding.canonical_path.clone(),
        mount_point,
        fs_root,
        ledger_path,
        command,
        stderr_tail,
        note,
    };
    // Full partition table so multi-volume disks are visible. Enumeration is
    // best-effort after the read-only mount exists: every failure becomes an
    // explicit limitation in the output and ledger note, while the successful
    // mount is still registered and therefore can always be unmounted.
    // Prefer the ewfmount raw device when present: Debian/Ubuntu TSK has no
    // libewf, so mmls on the compressed .E01 is useless (and misleading).
    let partition_result = match input.mode {
        DiskMode::Mock => Ok(Vec::new()),
        DiskMode::Auto => {
            let ewf1 = registration.mount_point.join("ewf").join("ewf1");
            if ewf1.is_file() {
                enumerate_partitions(&[ewf1])
            } else {
                enumerate_partitions(&image_paths)
            }
        }
    };

    // Re-hash after every mount + partition read. If the registered source or
    // any split-EWF segment changed during those operations, tear down the
    // unregistered mount and refuse to bind its bytes to this Case.
    if let Err(integrity_error) = verify_authorized_disk_image(&binding) {
        return match rollback_unregistered_mount(&registration) {
            Ok(_) => Err(integrity_error),
            Err(rollback_error) => Err(DiskError::MountIntegrityRollbackFailed {
                case_id: input.case_id.clone(),
                rollback_error: rollback_error.to_string(),
            }),
        };
    }

    let output = persist_mounted_disk(registration, partition_result)?;
    cleanup.disarm();
    Ok(output)
}

fn reused_disk_mount_output(
    input: &DiskMountInput,
    resource: &SessionResource,
    ledger_path: &Path,
) -> Result<DiskMountOutput, DiskError> {
    let image_path = resource
        .image_path
        .clone()
        .ok_or_else(|| DiskError::MountNotMounted(resource.id.clone()))?;
    let mount_point = resource
        .mount_point
        .clone()
        .ok_or_else(|| DiskError::MountNotMounted(resource.id.clone()))?;
    let fs_root = resource
        .fs_root
        .clone()
        .ok_or_else(|| DiskError::MountNotMounted(resource.id.clone()))?;
    Ok(DiskMountOutput {
        case_id: input.case_id.clone(),
        mount_id: resource.id.clone(),
        status: resource.status.clone(),
        image_path,
        mount_point,
        fs_root,
        ledger_path: ledger_path.to_path_buf(),
        command: resource.command.clone(),
        stderr_tail: String::new(),
        note: format!("reused existing active mount; {}", resource.note),
        partitions: resource.partitions.clone(),
        partition_enumeration_error: resource.partition_enumeration_error.clone(),
    })
}

fn resolve_mounted_image(
    case_id: &str,
    ledger: &SessionLedger,
    mount_id: &str,
) -> Result<(SessionResource, PathBuf, Vec<PathBuf>), DiskError> {
    let mount = ledger
        .resources
        .iter()
        .find(|resource| resource.id == mount_id && resource.resource_type == "disk_mount")
        .cloned()
        .ok_or_else(|| DiskError::MountNotFound(mount_id.to_string()))?;
    if mount.status != "mounted" {
        return Err(DiskError::MountNotMounted(mount_id.to_string()));
    }
    let image_path = mount
        .image_path
        .clone()
        .ok_or_else(|| DiskError::MountNotMounted(mount_id.to_string()))?;
    if !image_path.is_file() {
        return Err(DiskError::ImageNotFound(image_path));
    }
    authorize_disk_image(case_id, &image_path)?;
    let image_paths = resolve_tsk_image_paths(&mount, &image_path)?;
    Ok((mount, image_path, image_paths))
}

fn list_extraction_entries(
    mount: &SessionResource,
    image_paths: &[PathBuf],
    sector_offset: Option<u64>,
) -> Result<(TskListing, bool, Option<PathBuf>), DiskError> {
    let mock_root = (mount.command.first().map(String::as_str) == Some("mock"))
        .then(|| mount.fs_root.clone())
        .flatten();
    let (listing, via_walk) = match tsk_list(image_paths, sector_offset) {
        Ok(listing) if !listing.entries.is_empty() => (listing, false),
        tsk_result => match &mock_root {
            Some(root) => (TskListing::mock(mock_list(root)?), true),
            None => (tsk_result?, false),
        },
    };
    Ok((listing, via_walk, mock_root))
}

struct DiskExtractionCompletion {
    extract_id: String,
    output_dir: PathBuf,
    artifacts: Vec<ExtractedDiskArtifact>,
    artifact_candidates_seen: usize,
    artifacts_skipped_limit: usize,
    stats: ExtractStats,
    limits: EffectiveExtractLimits,
    case_extracted_bytes_before: u64,
    limit_summary: LimitSummary,
    listing: TskListing,
    icat_timeout: Duration,
    deleted_entries_seen: usize,
    deleted_skipped_realloc: usize,
    ledger_path: PathBuf,
}

fn build_disk_extract_output(
    input: &DiskExtractArtifactsInput,
    completed: DiskExtractionCompletion,
) -> DiskExtractArtifactsOutput {
    let DiskExtractionCompletion {
        extract_id,
        output_dir,
        artifacts,
        artifact_candidates_seen,
        artifacts_skipped_limit,
        stats,
        limits,
        case_extracted_bytes_before,
        limit_summary,
        listing,
        icat_timeout,
        deleted_entries_seen,
        deleted_skipped_realloc,
        ledger_path,
    } = completed;
    DiskExtractArtifactsOutput {
        case_id: input.case_id.clone(),
        mount_id: input.mount_id.clone(),
        extract_id,
        output_dir,
        artifacts_seen: artifacts.len(),
        artifact_candidates_seen,
        listing_entries_seen: listing.entries_seen,
        listing_stdout_bytes: listing.stdout_bytes,
        listing_stderr_bytes: listing.stderr_bytes,
        listing_stderr_tail: listing.stderr_tail,
        listing_truncated: listing.truncated,
        listing_limit_reason: listing.limit_reason,
        listing_max_entries: FLS_MAX_ENTRIES,
        listing_max_stdout_bytes: FLS_STDOUT_MAX_BYTES,
        listing_max_stderr_bytes: FLS_STDERR_MAX_BYTES,
        listing_max_line_bytes: FLS_LINE_MAX_BYTES,
        listing_timeout_seconds: listing.timeout.as_secs(),
        icat_timeout_seconds: icat_timeout.as_secs(),
        artifacts_skipped_limit,
        artifacts_skipped_oversize: stats.skipped_oversize,
        artifacts_skipped_total_limit: stats.skipped_total_limit,
        artifacts_extraction_failed: stats.extraction_failed,
        requested_limit: input.limit,
        effective_limit: limits.artifacts,
        requested_max_artifact_bytes: input.max_artifact_bytes,
        max_artifact_bytes: limits.per_artifact_bytes,
        requested_max_total_bytes: input.max_total_bytes,
        max_total_bytes: limits.total_bytes,
        extracted_bytes: stats.extracted_bytes,
        case_extracted_bytes_before,
        case_extracted_bytes_after: limit_summary.case_extracted_bytes_after,
        limits_clamped: limits.clamped,
        truncated: limit_summary.truncated,
        limit_reasons: limit_summary.reasons,
        deleted_entries_seen,
        deleted_recovered: stats.deleted_recovered,
        deleted_skipped_realloc,
        deleted_recovery_failed: stats.deleted_recovery_failed,
        artifacts,
        ledger_path,
    }
}

pub fn disk_extract_artifacts(
    input: &DiskExtractArtifactsInput,
) -> Result<DiskExtractArtifactsOutput, DiskError> {
    let case_dir = case_dir(&input.case_id)?;
    // Cross-process SQLite write lock: multiple MCP clients can share one
    // FINDEVIL_HOME, so ledger read -> extract -> ledger write must be one
    // reservation critical section or each process could spend the same bytes.
    let _ledger_lock = CaseExtractionLock::acquire(&case_dir)?;
    let ledger_path = case_dir.join(LEDGER_NAME);
    let mut ledger = read_ledger(&ledger_path)?;
    let (mount, image_path, image_paths) =
        resolve_mounted_image(&input.case_id, &ledger, &input.mount_id)?;
    let case_extracted_bytes_before = case_extracted_bytes(&case_dir, &ledger)?;
    // Read artifacts with The Sleuth Kit (fls/icat). Prefer the ewfmount FUSE
    // raw device (`…/ewf/ewf1`) when disk_mount created one: Debian/Ubuntu TSK
    // is built without libewf, so fls on a compressed .E01 prints
    // "Possible encryption detected (High entropy)" and yields zero artifacts
    // (a silent false negative). The live FUSE device is a plain raw image.
    // When no ewf1 is present (raw .dd, or DirectTsk with a libewf-capable TSK),
    // fall back to the recorded original image path / segment set.
    let extract_id = format!("disk-extract-{}", Uuid::new_v4());
    let output_dir = case_dir.join("extracted").join("disk").join(&extract_id);

    // Sector offset from mmls on the TSK-facing image (ewf1 or raw). Empty
    // table → None → fls at offset 0 (volume-only acquisitions). ewf1 is
    // root-owned after sudo ewfmount, so the offset helper uses sudo there.
    let sector_offset = primary_partition_sector_offset(&image_paths)?;

    // Enumerate every file once and keep the wanted classes. Selection then
    // allocates the `limit` *fairly across classes* (round-robin) so a
    // voluminous class — hundreds of prefetch or evtx files — can't starve the
    // others, and within each class the highest-signal artifacts are drawn
    // first (for evtx, the canonical Windows logs ahead of the long
    // Microsoft-Windows-*/Operational tail). A single global priority sort
    // would otherwise let prefetch consume the whole budget and extract zero
    // event logs — the richest finding source on a disk.
    //
    // The Sleuth Kit reads the image directly (real images, and the faked
    // fls/icat in tests). A `mock` mount whose "image" is the synthetic
    // evidence the end-to-end smoke and Windows use is not a real filesystem,
    // so TSK can't enumerate it; that case falls back to walking the directory
    // tree disk_mount staged at fs_root. Auto mounts never fall back — a real
    // image TSK can't read is a genuine error to surface, not silently skip.
    let (mut listing, via_walk, mock_root) =
        list_extraction_entries(&mount, &image_paths, sector_offset)?;
    let (candidates, deleted_entries_seen, deleted_skipped_realloc) = build_candidates(
        std::mem::take(&mut listing.entries),
        &wanted_kinds(&input.artifact_kinds),
        input.recover_deleted,
    );
    let limits =
        effective_extract_limits(input.limit, input.max_artifact_bytes, input.max_total_bytes);
    let artifact_candidates_seen = candidates.len();
    let selected = select_artifacts(candidates, limits.artifacts);
    let artifacts_skipped_limit = artifact_candidates_seen.saturating_sub(selected.len());

    create_dir(&output_dir)?;
    let effective_icat_timeout = icat_timeout();
    let source = ExtractionSource {
        image_paths: &image_paths,
        sector_offset,
        output_dir: &output_dir,
        mock_root: mock_root.as_deref(),
        via_walk,
        icat_timeout: effective_icat_timeout,
    };
    let (artifacts, stats) =
        match extract_selected_artifacts(&source, &selected, limits, case_extracted_bytes_before) {
            Ok(result) => result,
            Err(err) => {
                let _ = fs::remove_dir_all(&output_dir);
                return Err(err);
            }
        };
    if let Err(err) = authorize_disk_image(&input.case_id, &image_path)
        .and_then(|_| verify_extracted_artifacts(&input.case_id, &artifacts))
    {
        let _ = fs::remove_dir_all(&output_dir);
        return Err(err);
    }
    let limit_summary =
        summarize_limits(artifacts_skipped_limit, &stats, case_extracted_bytes_before);

    let now = now_iso();
    ledger.resources.push(SessionResource {
        id: extract_id.clone(),
        resource_type: "disk_extract_artifacts".to_string(),
        status: "extracted".to_string(),
        created_at: now.clone(),
        updated_at: now,
        image_path: Some(image_path),
        mount_point: mount.mount_point,
        fs_root: mount.fs_root,
        parent_id: Some(input.mount_id.clone()),
        output_dir: Some(output_dir.clone()),
        artifacts: artifacts.clone(),
        command: vec!["fls".to_string(), "icat".to_string()],
        note: format!(
            "extracted disk artifacts directly from the image via The Sleuth Kit; bytes={} \
             case_bytes={}/{} truncated={}",
            stats.extracted_bytes,
            limit_summary.case_extracted_bytes_after,
            limits.total_bytes,
            limit_summary.truncated
        ),
        partitions: Vec::new(),
        partition_enumeration_error: None,
    });
    if let Err(err) = write_ledger(&ledger_path, &ledger) {
        let _ = fs::remove_dir_all(&output_dir);
        return Err(err);
    }

    Ok(build_disk_extract_output(
        input,
        DiskExtractionCompletion {
            extract_id,
            output_dir,
            artifacts,
            artifact_candidates_seen,
            artifacts_skipped_limit,
            stats,
            limits,
            case_extracted_bytes_before,
            limit_summary,
            listing,
            icat_timeout: effective_icat_timeout,
            deleted_entries_seen,
            deleted_skipped_realloc,
            ledger_path,
        },
    ))
}

pub fn disk_unmount(input: &DiskUnmountInput) -> Result<DiskUnmountOutput, DiskError> {
    let case_dir = case_dir(&input.case_id)?;
    let _ledger_lock = CaseExtractionLock::acquire(&case_dir)?;
    let ledger_path = case_dir.join(LEDGER_NAME);
    let mut ledger = read_ledger(&ledger_path)?;
    let idx = ledger
        .resources
        .iter()
        .position(|resource| {
            resource.id == input.mount_id
                && matches!(resource.resource_type.as_str(), "disk_mount" | "vss_mount")
        })
        .ok_or_else(|| DiskError::MountNotFound(input.mount_id.clone()))?;
    let mount_point = ledger.resources[idx]
        .mount_point
        .clone()
        .ok_or_else(|| DiskError::MountNotMounted(input.mount_id.clone()))?;
    // fs_root tells the teardown which layout this is: a nested EWF+NTFS mount
    // (fs_root == <mp>/fs), an EWF container only (fs_root == <mp>/ewf), or a
    // raw image mounted at the mount point. Default to the mount point for
    // older ledger rows that predate fs_root.
    let fs_root = ledger.resources[idx]
        .fs_root
        .clone()
        .unwrap_or_else(|| mount_point.clone());

    // A direct-TSK mount never ran a FUSE/loop mount, so there is nothing to
    // release: an `umount` would just fail on an unmounted path. Mark it
    // unmounted without a privileged teardown.
    let is_direct_tsk =
        ledger.resources[idx].command.first().map(String::as_str) == Some(DIRECT_TSK_COMMAND);
    let resource_was_mounted = ledger.resources[idx].status == "mounted";
    let canonical_mount = validate_case_mount_leaf(&case_dir, &mount_point)?;
    let (status, command, stderr_tail) = if !resource_was_mounted {
        (
            "unmounted".to_string(),
            vec!["no-op".to_string(), "disk_unmount".to_string()],
            String::new(),
        )
    } else if is_direct_tsk {
        (
            "unmounted".to_string(),
            vec![DIRECT_TSK_COMMAND.to_string(), "disk_unmount".to_string()],
            String::new(),
        )
    } else {
        let fs_root_metadata = fs::symlink_metadata(&fs_root).map_err(|source| DiskError::Io {
            path: fs_root.clone(),
            source,
        })?;
        if !fs_root_metadata.is_dir() || fs_root_metadata.file_type().is_symlink() {
            return Err(DiskError::UnsafeMountPoint(fs_root));
        }
        let canonical_fs_root =
            crate::pathnorm::canonicalize(&fs_root).map_err(|source| DiskError::Io {
                path: fs_root.clone(),
                source,
            })?;
        if !canonical_fs_root.starts_with(&canonical_mount) {
            return Err(DiskError::UnsafeMountPoint(canonical_fs_root));
        }
        match input.mode {
            DiskMode::Mock => (
                "unmounted".to_string(),
                vec!["mock".to_string(), "disk_unmount".to_string()],
                String::new(),
            ),
            DiskMode::Auto => auto_unmount(&canonical_mount, &canonical_fs_root)?,
        }
    };
    ledger.resources[idx].status.clone_from(&status);
    ledger.resources[idx].updated_at = now_iso();
    ledger.resources[idx].command.clone_from(&command);
    write_ledger(&ledger_path, &ledger)?;
    remove_empty_mount_leaf(&canonical_mount)?;

    Ok(DiskUnmountOutput {
        case_id: input.case_id.clone(),
        mount_id: input.mount_id.clone(),
        status,
        ledger_path,
        command,
        stderr_tail,
    })
}

fn remove_empty_mount_leaf(mount_point: &Path) -> Result<(), DiskError> {
    for path in [
        mount_point.join("fs"),
        mount_point.join("ewf"),
        mount_point.to_path_buf(),
    ] {
        match fs::remove_dir(&path) {
            Ok(()) => {}
            Err(source) if source.kind() == io::ErrorKind::NotFound => {}
            Err(source) => return Err(DiskError::Io { path, source }),
        }
    }
    Ok(())
}

pub(crate) fn register_vss_mount_resource(
    admission: &CaseMountAdmission,
    mount_id: &str,
    image_path: &Path,
    mount_point: &Path,
    status: &str,
    command: &[String],
    artifacts: &[ExtractedDiskArtifact],
) -> Result<PathBuf, DiskError> {
    if admission.existing().is_some() {
        return Err(DiskError::IntegrityState {
            case_id: admission.case_id().to_string(),
            message: "cannot register a new VSS resource over a reused admission".to_string(),
        });
    }
    let ledger_path = admission.ledger_path();
    let now = now_iso();
    upsert_resource(
        ledger_path,
        SessionResource {
            id: mount_id.to_string(),
            resource_type: "vss_mount".to_string(),
            status: status.to_string(),
            created_at: now.clone(),
            updated_at: now,
            image_path: Some(image_path.to_path_buf()),
            mount_point: Some(mount_point.to_path_buf()),
            fs_root: Some(mount_point.to_path_buf()),
            parent_id: None,
            output_dir: None,
            artifacts: artifacts.to_vec(),
            command: command.to_vec(),
            note: "read-only libvshadow mount; release with disk_unmount".to_string(),
            partitions: Vec::new(),
            partition_enumeration_error: None,
        },
    )?;
    Ok(ledger_path.to_path_buf())
}

pub(crate) fn hash_bound_derived_artifact(
    case_id: &str,
    artifact_class: &str,
    source_path: &Path,
    extracted_path: &Path,
) -> Result<ExtractedDiskArtifact, DiskError> {
    let canonical_path = canonical_bound_file(case_id, extracted_path)?;
    let size_bytes = fs::symlink_metadata(&canonical_path)
        .map_err(|source| DiskError::IntegrityRead {
            path: canonical_path.clone(),
            source,
        })?
        .len();
    Ok(ExtractedDiskArtifact {
        artifact_class: artifact_class.to_string(),
        source_path: source_path.to_path_buf(),
        extracted_path: canonical_path.clone(),
        size_bytes,
        sha256: sha256_bound_files(&[canonical_path])?,
        recovered_deleted: false,
    })
}

fn auto_mount(
    image_paths: &[PathBuf],
    mount_point: &Path,
) -> Result<(String, PathBuf, Vec<String>, String, String), DiskError> {
    if cfg!(windows) {
        return Err(DiskError::UnsupportedPlatform);
    }
    let image_path = image_paths
        .first()
        .ok_or_else(|| DiskError::ImageNotFound(PathBuf::from("<empty image set>")))?;
    if is_first_ewf_segment(image_path) {
        return auto_mount_ewf(image_paths, mount_point);
    }
    auto_mount_raw(image_path, mount_point)
}

fn auto_mount_ewf(
    image_paths: &[PathBuf],
    mount_point: &Path,
) -> Result<(String, PathBuf, Vec<String>, String, String), DiskError> {
    let bin = std::env::var("EWF_MOUNT_BIN").unwrap_or_else(|_| "ewfmount".to_string());
    // ewfmount (FUSE E01 -> raw) is NOT merely a convenience. Debian/Ubuntu build
    // The Sleuth Kit without libewf (`mmls -i list` offers raw/aff/afd/afm/afflib,
    // no `ewf`), so a "direct TSK read" of a .E01 parses the compressed container
    // as raw bytes: `fls` prints "Possible encryption detected (High entropy)",
    // exits 0, and extraction yields zero artifacts. That is a silent false
    // negative on real evidence, which is worse than a failed Case.
    //
    // So the fallback is only sound when THIS TSK actually advertises `ewf`.
    // Otherwise refuse. (The GIFT-PPA libewf/Plaso apt conflict that evicts
    // ewf-tools is exactly how a container reaches this state.)
    let image_path = image_paths
        .first()
        .ok_or_else(|| DiskError::ImageNotFound(PathBuf::from("<empty image set>")))?;
    match ewf_fallback_decision(ewfmount_available(&bin)?, tsk_supports_ewf()?) {
        EwfFallback::Mount => {}
        EwfFallback::DirectTsk => {
            return Ok(direct_tsk_mount(
                image_path,
                &format!("{bin} not found; this Sleuth Kit advertises `ewf`, reading directly"),
            ));
        }
        EwfFallback::Refuse => {
            return Err(DiskError::EwfReaderUnavailable {
                image: image_path.clone(),
                bin,
            });
        }
    }
    let ewf_dir = mount_point.join("ewf");
    create_dir(&ewf_dir)?;
    let mut args: Vec<String> = image_paths
        .iter()
        .map(|path| path.to_string_lossy().to_string())
        .collect();
    args.push(ewf_dir.to_string_lossy().to_string());
    // ewfmount must run as root: /etc/fuse.conf has no `user_allow_other`, so a
    // user-owned FUSE device is unreadable by the (root) loop/mount syscalls.
    let result = run_sudo_fixed_allow_background(&bin, &args)?;
    if !result.0 {
        // A PATH-present ewfmount can still be unreachable under sudo's
        // secure_path ("sudo: ewfmount: command not found"). Same rule as above:
        // fall through to a direct-TSK read only if this TSK can actually open
        // EWF, otherwise refuse rather than report a phantom clean disk.
        if is_missing_binary(&result.2) {
            let _ = fs::remove_dir(&ewf_dir);
            if tsk_supports_ewf()? {
                return Ok(direct_tsk_mount(image_path, &result.2));
            }
            return Err(DiskError::EwfReaderUnavailable {
                image: image_path.clone(),
                bin,
            });
        }
        return Err(DiskError::SubprocessFailed {
            status: result.1,
            stderr_tail: result.2,
        });
    }
    let ewf_cmd: Vec<String> = vec!["sudo".to_string(), "-n".to_string(), bin]
        .into_iter()
        .chain(args)
        .collect();
    let ewf_stderr = result.2;

    // ewfmount exposes the combined image as a single raw device named `ewf1`.
    // The NTFS volume inside still has to be loop-mounted before any files are
    // reachable. Use the kernel `ntfs3` driver (ntfs-3g refuses volumes whose
    // recorded size exceeds the image — common for acquired partitions) at
    // offset 0 for a bare volume image, or the first-partition offset for a full
    // disk. If it can't be mounted, fall back to custody-only on the container —
    // never worse than mounting nothing.
    let ewf_raw = ewf_dir.join("ewf1");
    let fs_dir = mount_point.join("fs");
    create_dir(&fs_dir)?;
    if let Ok((fs_cmd, fs_stderr)) = mount_ntfs_ro(&ewf_raw, &fs_dir) {
        let mut command = ewf_cmd;
        command.push("&&".to_string());
        command.extend(fs_cmd);
        Ok((
            "mounted".to_string(),
            fs_dir,
            command,
            fs_stderr,
            "mounted EWF container + NTFS filesystem read-only".to_string(),
        ))
    } else {
        let _ = fs::remove_dir(&fs_dir);
        Ok((
            "mounted".to_string(),
            ewf_dir,
            ewf_cmd,
            ewf_stderr,
            "mounted EWF container read-only; NTFS volume could not be mounted (custody-only)"
                .to_string(),
        ))
    }
}

/// Register a mount that performs no FUSE/loop operation. The returned tuple has
/// the same shape as a real EWF/raw mount, but `status = "mounted"`,
/// `fs_root = image_path` (the raw image itself), and the [`DIRECT_TSK_COMMAND`]
/// sentinel so `disk_extract_artifacts` reads directly with The Sleuth Kit and
/// `disk_unmount` skips a no-op teardown. Preserves the whole disk lane when
/// `ewfmount` is unavailable — the extracted bytes are identical (same
/// `fls`/`icat` off the same image + #147 largest-partition offset), so the
/// audit chain replays to the same `output_sha256`.
fn direct_tsk_mount(
    image_path: &Path,
    reason: &str,
) -> (String, PathBuf, Vec<String>, String, String) {
    (
        "mounted".to_string(),
        image_path.to_path_buf(),
        vec![DIRECT_TSK_COMMAND.to_string()],
        String::new(),
        format!("registered direct Sleuth Kit read of the image (no FUSE/loop mount): {reason}"),
    )
}

/// Whether `bin` (`ewfmount`) can be spawned at all. A failure to spawn
/// (`ErrorKind::NotFound`, i.e. the binary is not on PATH) means the direct-TSK
/// fallback must be used; any other outcome — it ran, or errored for another
/// reason — is treated as available. Probing with `-h` never mounts anything.
fn ewfmount_available(bin: &str) -> Result<bool, DiskError> {
    ewfmount_available_bounded(
        bin,
        EWF_PROBE_TIMEOUT,
        CaptureLimits {
            stdout_bytes: EWF_PROBE_CAPTURE_BYTES,
            stderr_bytes: EWF_PROBE_CAPTURE_BYTES,
        },
    )
}

fn ewfmount_available_bounded(
    bin: &str,
    timeout: Duration,
    limits: CaptureLimits,
) -> Result<bool, DiskError> {
    let mut command = Command::new(bin);
    command.arg("-h");
    match run_with_limits(command, timeout, limits) {
        Ok(_) => Ok(true),
        Err(RunError::Spawn(source)) if source.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(map_fixed_run_error(bin, error)),
    }
}

/// What to do with an EWF image, given whether `ewfmount` can run and whether
/// this Sleuth Kit build can open EWF itself. Pure so the policy is testable
/// without spawning either binary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EwfFallback {
    /// `ewfmount` is available: FUSE-expose the segments as a raw image.
    Mount,
    /// No `ewfmount`, but TSK advertises `ewf` — a direct read is sound.
    DirectTsk,
    /// No reader can open the image. Refusing beats a silent zero-artifact read.
    Refuse,
}

const fn ewf_fallback_decision(ewfmount_available: bool, tsk_supports_ewf: bool) -> EwfFallback {
    match (ewfmount_available, tsk_supports_ewf) {
        (true, _) => EwfFallback::Mount,
        (false, true) => EwfFallback::DirectTsk,
        (false, false) => EwfFallback::Refuse,
    }
}

/// Whether an `mmls -i list` listing advertises the `ewf` image type. Matches on
/// the leading type token only: `afflib (All AFFLIB image formats ...)` and any
/// description text mentioning EWF must not count as support.
fn mmls_list_supports_ewf(listing: &str) -> bool {
    listing.lines().any(|line| {
        // split_whitespace already skips leading whitespace.
        line.split_whitespace()
            .next()
            .is_some_and(|token| token.eq_ignore_ascii_case("ewf"))
    })
}

#[derive(Debug)]
struct MmlsProbeOutput {
    status: std::process::ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

enum MmlsProbeRead {
    Complete(Vec<u8>),
    LimitExceeded,
}

#[derive(Clone, Copy)]
enum MmlsStream {
    Stdout,
    Stderr,
}

impl MmlsStream {
    const fn name(self) -> &'static str {
        match self {
            Self::Stdout => "stdout",
            Self::Stderr => "stderr",
        }
    }

    const fn limit(self, limits: MmlsProbeLimits) -> u64 {
        match self {
            Self::Stdout => limits.stdout_bytes,
            Self::Stderr => limits.stderr_bytes,
        }
    }
}

struct MmlsReaderMessage {
    stream: MmlsStream,
    result: io::Result<MmlsProbeRead>,
}

impl MmlsReaderMessage {
    fn into_data(
        self,
        operation: &str,
        limits: MmlsProbeLimits,
    ) -> Result<(MmlsStream, Vec<u8>), DiskError> {
        match self.result {
            Ok(MmlsProbeRead::Complete(data)) => Ok((self.stream, data)),
            Ok(MmlsProbeRead::LimitExceeded) => {
                let limit = self.stream.limit(limits);
                Err(DiskError::MmlsOutputLimitExceeded {
                    operation: operation.to_string(),
                    stream: self.stream.name().to_string(),
                    limit,
                    observed: limit.saturating_add(1),
                })
            }
            Err(err) => Err(DiskError::MmlsRead {
                operation: operation.to_string(),
                stream: self.stream.name().to_string(),
                message: err.to_string(),
            }),
        }
    }
}

fn read_mmls_stream(mut reader: impl Read, limit: u64) -> io::Result<MmlsProbeRead> {
    let mut output = Vec::new();
    match copy_stream_bounded(&mut reader, &mut output, limit)? {
        BoundedCopyOutput::Complete(_) => Ok(MmlsProbeRead::Complete(output)),
        BoundedCopyOutput::LimitExceeded => Ok(MmlsProbeRead::LimitExceeded),
    }
}

fn join_mmls_readers_bounded(reader_threads: Vec<thread::JoinHandle<()>>) {
    let started = Instant::now();
    while reader_threads.iter().any(|thread| !thread.is_finished())
        && started.elapsed() < MMLS_READER_SHUTDOWN_GRACE
    {
        thread::sleep(FLS_READER_POLL_INTERVAL);
    }
    for thread in reader_threads {
        if thread.is_finished() {
            let _ = thread.join();
        }
    }
}

fn terminate_mmls_process(
    child: &mut std::process::Child,
    group: ChildProcessGroup,
    reader_threads: Vec<thread::JoinHandle<()>>,
) {
    kill_child_tree(child, group);
    let _ = child.wait();
    join_mmls_readers_bounded(reader_threads);
}

fn mmls_reader_terminated(operation: &str) -> DiskError {
    DiskError::MmlsReaderTerminated {
        operation: operation.to_string(),
    }
}

fn run_mmls_bounded(
    command: &mut Command,
    operation: &str,
    limits: MmlsProbeLimits,
    timeout: Duration,
) -> Result<MmlsProbeOutput, DiskError> {
    let program = PathBuf::from(command.get_program());
    let program_label = program.to_string_lossy().into_owned();
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let started = Instant::now();
    let (mut child, group) =
        spawn_isolated(command).map_err(|error| map_fixed_run_error(&program_label, error))?;
    let Some(stdout) = child.stdout.take() else {
        kill_child_tree(&mut child, group);
        let _ = child.wait();
        return Err(mmls_reader_terminated(operation));
    };
    let Some(stderr) = child.stderr.take() else {
        kill_child_tree(&mut child, group);
        let _ = child.wait();
        return Err(mmls_reader_terminated(operation));
    };

    let (sender, receiver) = mpsc::channel();
    let stdout_sender = sender.clone();
    let stdout_thread = thread::spawn(move || {
        let _ = stdout_sender.send(MmlsReaderMessage {
            stream: MmlsStream::Stdout,
            result: read_mmls_stream(stdout, limits.stdout_bytes),
        });
    });
    let stderr_thread = thread::spawn(move || {
        let _ = sender.send(MmlsReaderMessage {
            stream: MmlsStream::Stderr,
            result: read_mmls_stream(stderr, limits.stderr_bytes),
        });
    });
    let reader_threads = vec![stdout_thread, stderr_thread];
    let mut stdout_data = None;
    let mut stderr_data = None;
    let mut status = None;

    while status.is_none() || stdout_data.is_none() || stderr_data.is_none() {
        // The group token was captured from process_group(0)'s PID == PGID
        // invariant at spawn, so it remains usable after try_wait reaps a fast
        // leader and a closed-pipe descendant survives.
        if stdout_data.is_some() && stderr_data.is_some() && status.is_none() {
            status = match child.try_wait() {
                Ok(status) => status,
                Err(source) => {
                    terminate_mmls_process(&mut child, group, reader_threads);
                    return Err(DiskError::Io {
                        path: program,
                        source,
                    });
                }
            };
        }
        let elapsed = started.elapsed();
        if elapsed >= timeout {
            terminate_mmls_process(&mut child, group, reader_threads);
            return Err(DiskError::MmlsTimeout {
                operation: operation.to_string(),
                timeout,
            });
        }
        let poll_interval = FLS_READER_POLL_INTERVAL.min(timeout.saturating_sub(elapsed));
        if stdout_data.is_none() || stderr_data.is_none() {
            match receiver.recv_timeout(poll_interval) {
                Ok(message) => match message.into_data(operation, limits) {
                    Ok((MmlsStream::Stdout, data)) => stdout_data = Some(data),
                    Ok((MmlsStream::Stderr, data)) => stderr_data = Some(data),
                    Err(err) => {
                        terminate_mmls_process(&mut child, group, reader_threads);
                        return Err(err);
                    }
                },
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    terminate_mmls_process(&mut child, group, reader_threads);
                    return Err(mmls_reader_terminated(operation));
                }
            }
        } else {
            thread::sleep(poll_interval);
        }
    }
    for thread in reader_threads {
        thread
            .join()
            .map_err(|_| mmls_reader_terminated(operation))?;
    }
    quiesce_process_group(group).map_err(|error| map_fixed_run_error(&program_label, error))?;
    Ok(MmlsProbeOutput {
        status: status.ok_or_else(|| mmls_reader_terminated(operation))?,
        stdout: stdout_data.ok_or_else(|| mmls_reader_terminated(operation))?,
        stderr: stderr_data.ok_or_else(|| mmls_reader_terminated(operation))?,
    })
}

fn run_mmls(command: &mut Command, operation: &str) -> Result<MmlsProbeOutput, DiskError> {
    run_mmls_bounded(command, operation, MmlsProbeLimits::hard(), mmls_timeout())
}

/// Whether the local Sleuth Kit was built with libewf. Probed once per process:
/// `mmls -i list` is cheap, touches no evidence, and the answer cannot change
/// while the process runs. A missing `mmls` means no EWF support; bounded-runner
/// resource failures remain typed errors so the EWF decision cannot silently
/// downgrade after a hung or attacker-amplified probe.
fn tsk_supports_ewf() -> Result<bool, DiskError> {
    static SUPPORTS_EWF: OnceLock<bool> = OnceLock::new();
    if let Some(supports_ewf) = SUPPORTS_EWF.get() {
        return Ok(*supports_ewf);
    }
    let bin = std::env::var("FINDEVIL_MMLS_BIN").unwrap_or_else(|_| "mmls".to_string());
    let mut command = Command::new(&bin);
    command.args(["-i", "list"]);
    let output = match run_mmls(&mut command, "mmls EWF support probe") {
        Ok(output) => Some(output),
        Err(DiskError::Io { source, .. }) if source.kind() == io::ErrorKind::NotFound => None,
        Err(err) => return Err(err),
    };
    // TSK prints the type list to stderr on some builds, stdout on others.
    let supports_ewf = output.is_some_and(|output| {
        let mut listing = String::from_utf8_lossy(&output.stdout).into_owned();
        listing.push_str(&String::from_utf8_lossy(&output.stderr));
        mmls_list_supports_ewf(&listing)
    });
    let _ = SUPPORTS_EWF.set(supports_ewf);
    Ok(supports_ewf)
}

fn successful_mmls_stdout(
    command: &mut Command,
    operation: &str,
) -> Result<Option<String>, DiskError> {
    match run_mmls(command, operation) {
        Ok(output) if output.status.success() => {
            Ok(Some(String::from_utf8_lossy(&output.stdout).into_owned()))
        }
        Ok(_) => Ok(None),
        Err(DiskError::Io { source, .. }) if source.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err),
    }
}

/// Whether a subprocess `stderr` tail indicates the binary itself was missing
/// (as opposed to a genuine mount failure). Covers `sudo`'s
/// "sudo: ewfmount: command not found" and exec-wrapper "executable file not
/// found" phrasings.
fn is_missing_binary(stderr: &str) -> bool {
    let lower = stderr.to_ascii_lowercase();
    lower.contains("command not found") || lower.contains("executable file not found")
}

/// Loop-mount an NTFS volume read-only with the kernel `ntfs3` driver, under
/// sudo (the EWF device is root-owned). Tries offset 0 (bare volume image) then
/// the primary (largest) filesystem-partition offset from `mmls` (full disk
/// image).
fn mount_ntfs_ro(device: &Path, mount_point: &Path) -> Result<(Vec<String>, String), DiskError> {
    let mount_bin = std::env::var("FINDEVIL_MOUNT_BIN").unwrap_or_else(|_| "mount".to_string());
    let mut offsets = vec![0u64];
    if let Some(offset) = primary_partition_byte_offset_sudo(device)? {
        offsets.push(offset);
    }
    let mut last_status = String::new();
    let mut last_stderr = String::new();
    for offset in offsets {
        let opts = if offset == 0 {
            "ro,loop".to_string()
        } else {
            format!("ro,loop,offset={offset}")
        };
        let args = vec![
            "-t".to_string(),
            "ntfs3".to_string(),
            "-o".to_string(),
            opts,
            device.to_string_lossy().to_string(),
            mount_point.to_string_lossy().to_string(),
        ];
        let result = run_sudo_fixed(&mount_bin, &args)?;
        if result.0 {
            let command: Vec<String> = vec!["sudo".to_string(), "-n".to_string(), mount_bin]
                .into_iter()
                .chain(args)
                .collect();
            return Ok((command, result.2));
        }
        last_status = result.1;
        last_stderr = result.2;
    }
    Err(DiskError::SubprocessFailed {
        status: last_status,
        stderr_tail: last_stderr,
    })
}

/// `mmls` primary- (largest-) filesystem-partition byte offset, run under sudo
/// because the EWF device is root-owned. None when the image is a bare volume
/// (no table).
fn primary_partition_byte_offset_sudo(image_path: &Path) -> Result<Option<u64>, DiskError> {
    let bin = std::env::var("FINDEVIL_MMLS_BIN").unwrap_or_else(|_| "mmls".to_string());
    let mut command = Command::new("sudo");
    command.args(["-n", &bin]).arg(image_path);
    Ok(
        successful_mmls_stdout(&mut command, "sudo mmls primary-partition probe")?
            .and_then(|stdout| parse_mmls_primary_partition_offset(&stdout)),
    )
}

/// Enumerate every filesystem partition in the image for the mount output. Tries
/// a plain `mmls` first, then `sudo -n mmls` (the EWF device is root-owned),
/// mirroring the offset helpers. Returns an empty vec for a bare volume image,
/// when mmls is unavailable or exits nonzero. Timeout, output-limit, and read
/// failures propagate so limited enumeration cannot masquerade as a bare volume.
fn enumerate_partitions(image_paths: &[PathBuf]) -> Result<Vec<MmlsPartition>, DiskError> {
    let bin = std::env::var("FINDEVIL_MMLS_BIN").unwrap_or_else(|_| "mmls".to_string());
    let mut direct = Command::new(&bin);
    append_image_args(&mut direct, image_paths);
    let mut sudo = Command::new("sudo");
    sudo.args(["-n", &bin]);
    append_image_args(&mut sudo, image_paths);
    let text = match successful_mmls_stdout(&mut direct, "mmls partition enumeration")? {
        Some(stdout) => Some(stdout),
        None => successful_mmls_stdout(&mut sudo, "sudo mmls partition enumeration")?,
    };
    Ok(text
        .map(|stdout| parse_mmls_partitions(&stdout))
        .unwrap_or_default())
}

fn mount_bin_is_system_mount(bin: &str) -> bool {
    // FINDEVIL_MOUNT_BIN may be `/bin/mount` (DFIR image) not bare `mount`.
    let name = Path::new(bin)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(bin);
    name == "mount"
}

fn auto_mount_raw(
    image_path: &Path,
    mount_point: &Path,
) -> Result<(String, PathBuf, Vec<String>, String, String), DiskError> {
    let bin = std::env::var("FINDEVIL_MOUNT_BIN").unwrap_or_else(|_| "mount".to_string());
    let can_sudo_mount = mount_bin_is_system_mount(&bin);
    let args = vec![
        "-o".to_string(),
        "ro,loop".to_string(),
        image_path.to_string_lossy().to_string(),
        mount_point.to_string_lossy().to_string(),
    ];
    let result = run_fixed(&bin, &args)?;
    if result.0 {
        return Ok((
            "mounted".to_string(),
            mount_point.to_path_buf(),
            std::iter::once(bin).chain(args).collect(),
            result.2,
            "mounted raw image read-only with loop device".to_string(),
        ));
    }

    let direct_status = result.1;
    let direct_stderr = result.2;
    let image_paths = vec![image_path.to_path_buf()];
    if let Some(offset) = primary_partition_byte_offset(&image_paths)? {
        return auto_mount_raw_at_offset(
            &bin,
            image_path,
            mount_point,
            can_sudo_mount,
            &direct_status,
            &direct_stderr,
            offset,
        );
    }

    if can_sudo_mount {
        let sudo_result = run_sudo_fixed(&bin, &args)?;
        if sudo_result.0 {
            return Ok((
                "mounted".to_string(),
                mount_point.to_path_buf(),
                std::iter::once("sudo".to_string())
                    .chain(std::iter::once("-n".to_string()))
                    .chain(std::iter::once(bin))
                    .chain(args)
                    .collect(),
                sudo_result.2,
                "mounted raw image read-only with sudo loop device".to_string(),
            ));
        }
        let combined = format!(
            "direct mount failed ({direct_status}): {direct_stderr}\n\
             sudo mount failed: {}",
            sudo_result.2
        );
        if loop_mount_unavailable(&combined) {
            return Ok(direct_tsk_mount(
                image_path,
                &format!(
                    "loop mount unavailable ({}); reading raw image via Sleuth Kit",
                    summarize_loop_failure(&combined)
                ),
            ));
        }
        return Err(DiskError::SubprocessFailed {
            status: sudo_result.1,
            stderr_tail: combined,
        });
    }

    if loop_mount_unavailable(&direct_stderr) {
        return Ok(direct_tsk_mount(
            image_path,
            "loop mount unavailable; reading raw image via Sleuth Kit",
        ));
    }

    Err(DiskError::SubprocessFailed {
        status: direct_status,
        stderr_tail: direct_stderr,
    })
}

fn auto_mount_raw_at_offset(
    bin: &str,
    image_path: &Path,
    mount_point: &Path,
    can_sudo_mount: bool,
    direct_status: &str,
    direct_stderr: &str,
    offset: u64,
) -> Result<(String, PathBuf, Vec<String>, String, String), DiskError> {
    let offset_args = vec![
        "-o".to_string(),
        format!("ro,loop,offset={offset}"),
        image_path.to_string_lossy().to_string(),
        mount_point.to_string_lossy().to_string(),
    ];
    let offset_result = run_fixed(bin, &offset_args)?;
    if offset_result.0 {
        return Ok((
            "mounted".to_string(),
            mount_point.to_path_buf(),
            std::iter::once(bin.to_string())
                .chain(offset_args)
                .collect(),
            offset_result.2,
            format!("mounted primary filesystem partition read-only with loop offset {offset}"),
        ));
    }
    if can_sudo_mount {
        let sudo_result = run_sudo_fixed(bin, &offset_args)?;
        if sudo_result.0 {
            return Ok((
                "mounted".to_string(),
                mount_point.to_path_buf(),
                std::iter::once("sudo".to_string())
                    .chain(std::iter::once("-n".to_string()))
                    .chain(std::iter::once(bin.to_string()))
                    .chain(offset_args)
                    .collect(),
                sudo_result.2,
                format!(
                    "mounted primary filesystem partition read-only with sudo loop offset {offset}"
                ),
            ));
        }
        // DFIR containers often lack loop devices (losetup: No such device)
        // or deny loop-mount with EPERM even under sudo. Sleuth Kit can still
        // fls/icat a raw image + partition offset without a kernel mount —
        // register a direct-TSK mount so disk_extract_artifacts works.
        let combined = format!(
            "direct mount failed ({direct_status}): {direct_stderr}\n\
             offset mount failed: {}\n\
             sudo offset mount failed: {}",
            offset_result.2, sudo_result.2
        );
        if loop_mount_unavailable(&combined) {
            return Ok(direct_tsk_mount(
                image_path,
                &format!(
                    "loop mount unavailable ({}); reading raw image via Sleuth Kit",
                    summarize_loop_failure(&combined)
                ),
            ));
        }
    } else if loop_mount_unavailable(&format!("{direct_stderr}\n{}", offset_result.2)) {
        // Custom FINDEVIL_MOUNT_BIN that is not system mount: still fall back.
        return Ok(direct_tsk_mount(
            image_path,
            "loop mount unavailable; reading raw image via Sleuth Kit",
        ));
    }
    Err(DiskError::SubprocessFailed {
        status: offset_result.1,
        stderr_tail: format!(
            "direct mount failed ({direct_status}): {direct_stderr}\n\
             offset mount failed: {}",
            offset_result.2
        ),
    })
}

/// True when loop-device mount failed for environmental reasons (no loop nodes,
/// EPERM, Operation not permitted) rather than a corrupt image.
fn loop_mount_unavailable(stderr: &str) -> bool {
    let lower = stderr.to_ascii_lowercase();
    lower.contains("operation not permitted")
        || lower.contains("permission denied")
        || lower.contains("no such device")
        || lower.contains("failed to setup loop device")
        || lower.contains("cannot find an unused loop device")
        || lower.contains("not a block device")
}

fn summarize_loop_failure(stderr: &str) -> String {
    let lower = stderr.to_ascii_lowercase();
    if lower.contains("no such device") || lower.contains("unused loop device") {
        "no loop device".to_string()
    } else if lower.contains("operation not permitted") || lower.contains("permission denied") {
        "EPERM".to_string()
    } else {
        "loop unavailable".to_string()
    }
}

fn primary_partition_byte_offset(image_paths: &[PathBuf]) -> Result<Option<u64>, DiskError> {
    // Root-owned ewf1 (sudo ewfmount) is invisible to unprivileged mmls.
    if image_paths_need_sudo(image_paths) {
        return image_paths.first().map_or(Ok(None), |image_path| {
            primary_partition_byte_offset_sudo(image_path)
        });
    }
    let bin = std::env::var("FINDEVIL_MMLS_BIN").unwrap_or_else(|_| "mmls".to_string());
    let mut command = Command::new(&bin);
    append_image_args(&mut command, image_paths);
    Ok(
        successful_mmls_stdout(&mut command, "mmls primary-partition probe")?
            .and_then(|stdout| parse_mmls_primary_partition_offset(&stdout)),
    )
}

/// Byte offset of the **primary** filesystem partition — the largest-by-length
/// filesystem partition `mmls` reports, not merely the first one.
///
/// On a full Windows disk image the *first* filesystem partition is the small
/// "System Reserved" boot volume (a few hundred MB, ~a hundred files). The OS
/// volume that actually holds `Windows/System32/winevt/Logs`, the registry
/// hives, and user data is a separate, much larger partition further down the
/// table. Selecting the first partition therefore points `fls`/`icat` and the
/// loop mount at the boot stub and extracts almost nothing. Selecting by size
/// keys on a general disk-layout property (fully evidence-agnostic) and lands
/// on the OS/data volume instead. Returns `None` for a bare volume image (no
/// partition table), where TSK and the loop mount read at offset 0.
/// One filesystem partition enumerated from an `mmls` partition table. Byte and
/// sector offsets are derived from the reported start sector (512-byte sectors,
/// the mmls default the tool relies on elsewhere). Surfaced so a multi-volume
/// disk (e.g. a separate data volume, or a FAT/exFAT/ext partition beside the
/// primary NTFS OS volume) is visible rather than silently reduced to the single
/// largest volume — a precondition for honest per-filesystem coverage claims.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct MmlsPartition {
    /// mmls slot index (the leading `NNN:` column), e.g. 2 for `002:`.
    pub slot: u32,
    /// Start sector as reported by mmls.
    pub start_sector: u64,
    /// Length in sectors as reported by mmls.
    pub length_sectors: u64,
    /// Byte offset of the partition (`start_sector * 512`).
    pub byte_offset: u64,
    /// Free-text filesystem description from mmls (e.g. `NTFS / exFAT (0x07)`).
    pub description: String,
}

/// Enumerate **every** filesystem partition an `mmls` listing reports, in table
/// order. Metadata and unallocated rows are skipped; only rows whose description
/// matches a known filesystem ([`matches_filesystem_description`]) are kept. Pure
/// over the text so it is unit-tested without invoking mmls. Deterministic: the
/// order follows the mmls table, which is stable for a given image.
fn parse_mmls_partitions(output: &str) -> Vec<MmlsPartition> {
    let mut partitions = Vec::new();
    for line in output.lines() {
        let lower = line.to_ascii_lowercase();
        if lower.contains("meta")
            || lower.contains("unallocated")
            || !matches_filesystem_description(&lower)
        {
            continue;
        }
        // The leading `NNN:` slot index (before the CHS `000:000` column). Take
        // the first token, strip a trailing colon, parse as the slot number.
        let slot = line
            .split_whitespace()
            .next()
            .and_then(|tok| tok.strip_suffix(':'))
            .and_then(|n| n.parse::<u32>().ok());
        // The columns after the slot labels are Start, End, Length (decimal
        // sector counts), then the free-text description. Collect the decimal
        // fields in order; the index ("002:") and CHS-style slot ("000:000")
        // carry colons, so they never parse as all-digit.
        let mut nums = line
            .split_whitespace()
            .filter(|field| !field.is_empty() && field.chars().all(|c| c.is_ascii_digit()))
            .filter_map(|field| field.parse::<u64>().ok());
        let (Some(start), Some(_end), Some(length)) = (nums.next(), nums.next(), nums.next())
        else {
            continue;
        };
        let Some(byte_offset) = start.checked_mul(512) else {
            continue;
        };
        // Description is the trailing free text after the three decimal columns.
        let description = mmls_description(line);
        partitions.push(MmlsPartition {
            slot: slot.unwrap_or_default(),
            start_sector: start,
            length_sectors: length,
            byte_offset,
            description,
        });
    }
    partitions
}

/// The free-text filesystem description trailing an mmls row (everything after
/// the Start/End/Length decimal columns), trimmed. Empty if the shape is off.
fn mmls_description(line: &str) -> String {
    // Find the third all-decimal token (Length) and take the remainder.
    let mut seen_decimals = 0usize;
    let mut idx_after = None;
    for (i, tok) in line.split_whitespace().enumerate() {
        if !tok.is_empty() && tok.chars().all(|c| c.is_ascii_digit()) {
            seen_decimals += 1;
            if seen_decimals == 3 {
                idx_after = Some(i);
                break;
            }
        }
    }
    idx_after.map_or_else(String::new, |i| {
        line.split_whitespace()
            .skip(i + 1)
            .collect::<Vec<_>>()
            .join(" ")
    })
}

/// Byte offset of the **primary** filesystem partition — the largest-by-length
/// filesystem partition, reusing the full enumeration so selection and the
/// surfaced partition table can never disagree.
fn parse_mmls_primary_partition_offset(output: &str) -> Option<u64> {
    parse_mmls_partitions(output)
        .into_iter()
        .max_by_key(|p| p.length_sectors)
        .map(|p| p.byte_offset)
}

fn matches_filesystem_description(line: &str) -> bool {
    line.contains("ntfs")
        || line.contains("exfat")
        || line.contains("fat")
        || line.contains("linux")
        || line.contains("hfs")
        || line.contains("apfs")
}

/// Plan the teardown commands for a mount, newest layer first. Pure so the
/// ordering (the nested NTFS loop is released before the EWF container) is
/// unit-tested without touching real mounts. Both EWF and NTFS mounts are
/// root-owned (`sudo ewfmount` / `sudo mount`), so `umount` releases both —
/// `auto_unmount` retries each step under sudo.
fn unmount_steps(
    mount_point: &Path,
    fs_root: &Path,
    umount_bin: &str,
) -> Vec<(String, Vec<String>)> {
    let ewf_dir = mount_point.join("ewf");
    let fs_dir = mount_point.join("fs");
    if fs_root == fs_dir {
        // EWF container with a nested NTFS loop mount: drop the loop first, then
        // release the EWF container it sits on.
        vec![
            (
                umount_bin.to_string(),
                vec![fs_dir.to_string_lossy().to_string()],
            ),
            (
                umount_bin.to_string(),
                vec![ewf_dir.to_string_lossy().to_string()],
            ),
        ]
    } else if fs_root == ewf_dir {
        // EWF container only (filesystem could not be mounted).
        vec![(
            umount_bin.to_string(),
            vec![ewf_dir.to_string_lossy().to_string()],
        )]
    } else {
        // Raw image mounted directly at the mount point.
        vec![(
            umount_bin.to_string(),
            vec![mount_point.to_string_lossy().to_string()],
        )]
    }
}

fn auto_unmount(
    mount_point: &Path,
    fs_root: &Path,
) -> Result<(String, Vec<String>, String), DiskError> {
    if cfg!(windows) {
        return Err(DiskError::UnsupportedPlatform);
    }
    let umount_bin = std::env::var("FINDEVIL_UMOUNT_BIN").unwrap_or_else(|_| "umount".to_string());
    let steps = unmount_steps(mount_point, fs_root, &umount_bin);

    let mut commands: Vec<String> = Vec::new();
    let mut stderr_tail = String::new();
    for (idx, (bin, args)) in steps.iter().enumerate() {
        if idx > 0 {
            commands.push("&&".to_string());
        }
        let result = run_fixed(bin, args)?;
        if result.0 {
            commands.push(bin.clone());
            commands.extend(args.iter().cloned());
            stderr_tail = result.2;
            continue;
        }
        // Privileged mounts need sudo -n; harmless for fusermount on own mounts.
        let sudo_result = run_sudo_fixed(bin, args)?;
        if sudo_result.0 {
            commands.push("sudo".to_string());
            commands.push("-n".to_string());
            commands.push(bin.clone());
            commands.extend(args.iter().cloned());
            stderr_tail = sudo_result.2;
            continue;
        }
        return Err(DiskError::SubprocessFailed {
            status: sudo_result.1,
            stderr_tail: format!(
                "{bin} failed ({}): {}\nsudo {bin} failed: {}",
                result.1, result.2, sudo_result.2
            ),
        });
    }
    Ok(("unmounted".to_string(), commands, stderr_tail))
}

fn run_sudo_fixed(bin: &str, args: &[String]) -> Result<(bool, String, String), DiskError> {
    let mut sudo_args = vec!["-n".to_string(), bin.to_string()];
    sudo_args.extend(args.iter().cloned());
    run_fixed("sudo", &sudo_args)
}

fn run_sudo_fixed_allow_background(
    bin: &str,
    args: &[String],
) -> Result<(bool, String, String), DiskError> {
    let mut sudo_args = vec!["-n".to_string(), bin.to_string()];
    sudo_args.extend(args.iter().cloned());
    let mut command = Command::new("sudo");
    command.args(&sudo_args);
    let output = run_with_limits_allow_background(
        command,
        FIXED_COMMAND_TIMEOUT,
        CaptureLimits {
            stdout_bytes: FIXED_COMMAND_STDOUT_BYTES,
            stderr_bytes: FIXED_COMMAND_STDERR_BYTES,
        },
    )
    .map_err(|error| map_fixed_run_error("sudo", error))?;
    Ok((
        output.status.success(),
        output.status.to_string(),
        tail_utf8_lossy(&output.stderr),
    ))
}

fn run_fixed(bin: &str, args: &[String]) -> Result<(bool, String, String), DiskError> {
    run_fixed_bounded(
        bin,
        args,
        FIXED_COMMAND_TIMEOUT,
        CaptureLimits {
            stdout_bytes: FIXED_COMMAND_STDOUT_BYTES,
            stderr_bytes: FIXED_COMMAND_STDERR_BYTES,
        },
    )
}

fn run_fixed_bounded(
    bin: &str,
    args: &[String],
    timeout: Duration,
    limits: CaptureLimits,
) -> Result<(bool, String, String), DiskError> {
    let mut command = Command::new(bin);
    command.args(args);
    let output = run_with_limits(command, timeout, limits)
        .map_err(|error| map_fixed_run_error(bin, error))?;
    Ok((
        output.status.success(),
        output.status.to_string(),
        tail_utf8_lossy(&output.stderr),
    ))
}

fn map_fixed_run_error(bin: &str, error: RunError) -> DiskError {
    match error {
        RunError::Spawn(source) => DiskError::Io {
            path: PathBuf::from(bin),
            source,
        },
        other => DiskError::SubprocessFailed {
            status: "bounded runner aborted".to_string(),
            stderr_tail: tail_utf8_lossy(other.to_string().as_bytes()),
        },
    }
}

fn append_image_args(command: &mut Command, image_paths: &[PathBuf]) {
    for path in image_paths {
        command.arg(path);
    }
}

/// Sector offset of the primary (largest) filesystem partition for
/// `fls`/`icat -o`, or None for a bare volume image (TSK reads it at offset 0).
/// mmls reports the start
/// sector; the byte helper multiplies by 512, so divide it back to sectors.
fn primary_partition_sector_offset(image_paths: &[PathBuf]) -> Result<Option<u64>, DiskError> {
    Ok(primary_partition_byte_offset(image_paths)?.map(|bytes| bytes / 512))
}

/// Image path(s) for `fls`/`icat`/`mmls` after a mount.
///
/// When `disk_mount` ran `ewfmount`, the combined raw device is at
/// `<mount_point>/ewf/ewf1`. Prefer that single raw path so TSK without libewf
/// can still enumerate. The FUSE dir is root-owned (`sudo ewfmount`), so
/// `Path::is_file` from the unprivileged process often fails — trust the mount
/// ledger's command list rather than a permission-sensitive existence check.
/// Otherwise return the original image's segment set.
fn resolve_tsk_image_paths(
    mount: &SessionResource,
    original_image: &Path,
) -> Result<Vec<PathBuf>, DiskError> {
    if mount_used_ewfmount(&mount.command) {
        if let Some(mp) = mount.mount_point.as_ref() {
            return Ok(vec![mp.join("ewf").join("ewf1")]);
        }
    }
    if let Some(ewf1) = ewf1_device_path(mount.mount_point.as_deref(), mount.fs_root.as_deref()) {
        return Ok(vec![ewf1]);
    }
    segment_paths_for_image(original_image).map_err(|err| DiskError::EwfSegmentSet(err.to_string()))
}

/// Whether the mount ledger's recorded command invoked `ewfmount`.
fn mount_used_ewfmount(command: &[String]) -> bool {
    command.iter().any(|part| {
        Path::new(part)
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.eq_ignore_ascii_case("ewfmount"))
    })
}

/// True when fls/icat/mmls must run under `sudo -n` because the image is the
/// root-owned ewfmount FUSE device (`…/ewf1`).
fn image_paths_need_sudo(image_paths: &[PathBuf]) -> bool {
    image_paths.iter().any(|p| {
        p.file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.eq_ignore_ascii_case("ewf1"))
    })
}

/// Locate the ewfmount FUSE raw device if it is still mounted and visible.
///
/// Pure path selection + existence check; does not spawn ewfmount. May return
/// None for a live but root-only FUSE dir — callers that know ewfmount ran
/// should prefer [`resolve_tsk_image_paths`]'s ledger path.
fn ewf1_device_path(mount_point: Option<&Path>, fs_root: Option<&Path>) -> Option<PathBuf> {
    let mut candidates = Vec::with_capacity(3);
    if let Some(mp) = mount_point {
        candidates.push(mp.join("ewf").join("ewf1"));
    }
    if let Some(root) = fs_root {
        candidates.push(root.join("ewf1"));
        // fs_root might already be the ewf1 path itself.
        if root
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.eq_ignore_ascii_case("ewf1"))
        {
            candidates.push(root.to_path_buf());
        }
    }
    candidates.into_iter().find(|p| p.is_file())
}

/// One `fls -r -p` listing entry. `deleted` marks an unallocated directory
/// entry whose metadata address is still readable — recoverable via the same
/// `icat`-by-inode path as live files. `realloc` marks a deleted entry whose
/// inode has been reused by a live file; extracting it would return the
/// reusing file's content, so extraction must skip it.
#[derive(Clone, Debug, PartialEq, Eq)]
struct FlsEntry {
    inode: String,
    path: String,
    deleted: bool,
    realloc: bool,
}

/// One classified extraction candidate flowing from listing to selection.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Candidate {
    class: &'static str,
    inode: String,
    path: String,
    deleted: bool,
}

/// Enumerate every regular file in the image via `fls -r -p` — live files and
/// deleted-but-addressable entries alike. Reads the image directly (no mount).
/// Uses `sudo -n fls` when the image is the root-owned ewfmount `ewf1` device.
fn tsk_list(image_paths: &[PathBuf], sector_offset: Option<u64>) -> Result<TskListing, DiskError> {
    let bin = std::env::var("FINDEVIL_FLS_BIN").unwrap_or_else(|_| "fls".to_string());
    let mut command = if image_paths_need_sudo(image_paths) {
        let mut c = Command::new("sudo");
        c.args(["-n", &bin]);
        c
    } else {
        Command::new(&bin)
    };
    command.args(["-r", "-p"]);
    if let Some(offset) = sector_offset {
        command.arg("-o").arg(offset.to_string());
    }
    append_image_args(&mut command, image_paths);
    run_fls_command(&mut command, TskListLimits::hard(), fls_timeout())
}

#[derive(Debug)]
struct FlsStdoutData {
    entries: Vec<FlsEntry>,
    entries_seen: usize,
    bytes: u64,
}

#[derive(Debug)]
struct FlsStderrData {
    bytes: u64,
    tail: String,
}

#[derive(Debug)]
enum ListingReadFailure {
    Limit {
        stream: &'static str,
        limit_kind: &'static str,
        limit: u64,
        observed: u64,
    },
    Io {
        stream: &'static str,
        message: String,
    },
}

impl ListingReadFailure {
    fn into_disk_error(self) -> DiskError {
        match self {
            Self::Limit {
                stream,
                limit_kind,
                limit,
                observed,
            } => DiskError::ListingLimitExceeded {
                stream: stream.to_string(),
                limit_kind: limit_kind.to_string(),
                limit,
                observed,
            },
            Self::Io { stream, message } => DiskError::ListingRead {
                stream: stream.to_string(),
                message,
            },
        }
    }
}

enum ListingReaderMessage {
    Stdout(Result<FlsStdoutData, ListingReadFailure>),
    Stderr(Result<FlsStderrData, ListingReadFailure>),
}

fn read_fls_stdout(
    reader: impl Read,
    limits: TskListLimits,
) -> Result<FlsStdoutData, ListingReadFailure> {
    let mut reader = BufReader::new(reader);
    let mut entries = Vec::new();
    let mut entries_seen = 0usize;
    let mut bytes = 0u64;
    let mut line = Vec::new();
    loop {
        line.clear();
        let remaining_stdout = limits.stdout_bytes.saturating_sub(bytes);
        let read_limit = limits.line_bytes.min(remaining_stdout).saturating_add(1);
        let count = (&mut reader)
            .take(read_limit)
            .read_until(b'\n', &mut line)
            .map_err(|err| ListingReadFailure::Io {
                stream: "stdout",
                message: err.to_string(),
            })?;
        if count == 0 {
            break;
        }
        let count = u64::try_from(count).unwrap_or(u64::MAX);
        bytes = bytes.saturating_add(count);
        if bytes > limits.stdout_bytes {
            return Err(ListingReadFailure::Limit {
                stream: "stdout",
                limit_kind: "bytes",
                limit: limits.stdout_bytes,
                observed: bytes,
            });
        }
        if count > limits.line_bytes {
            return Err(ListingReadFailure::Limit {
                stream: "stdout",
                limit_kind: "line_bytes",
                limit: limits.line_bytes,
                observed: count,
            });
        }
        if let Some(entry) = parse_fls_line(&String::from_utf8_lossy(&line)) {
            entries_seen = entries_seen.saturating_add(1);
            if entries_seen > limits.entries {
                return Err(ListingReadFailure::Limit {
                    stream: "stdout",
                    limit_kind: "entries",
                    limit: u64::try_from(limits.entries).unwrap_or(u64::MAX),
                    observed: u64::try_from(entries_seen).unwrap_or(u64::MAX),
                });
            }
            entries.push(entry);
        }
    }
    Ok(FlsStdoutData {
        entries,
        entries_seen,
        bytes,
    })
}

fn append_stderr_tail(tail: &mut Vec<u8>, chunk: &[u8]) {
    if chunk.len() >= STDERR_TAIL_BYTES {
        tail.clear();
        tail.extend_from_slice(&chunk[chunk.len() - STDERR_TAIL_BYTES..]);
        return;
    }
    let overflow = tail
        .len()
        .saturating_add(chunk.len())
        .saturating_sub(STDERR_TAIL_BYTES);
    if overflow > 0 {
        tail.drain(..overflow);
    }
    tail.extend_from_slice(chunk);
}

fn read_fls_stderr(mut reader: impl Read, limit: u64) -> Result<FlsStderrData, ListingReadFailure> {
    let mut bytes = 0u64;
    let mut tail = Vec::with_capacity(STDERR_TAIL_BYTES);
    let mut buffer = vec![0u8; STREAM_BUFFER_BYTES];
    loop {
        let remaining = limit.saturating_sub(bytes);
        let read_cap = remaining
            .saturating_add(1)
            .min(u64::try_from(buffer.len()).unwrap_or(u64::MAX));
        let read_cap = usize::try_from(read_cap).unwrap_or(buffer.len());
        let count = reader
            .read(&mut buffer[..read_cap])
            .map_err(|err| ListingReadFailure::Io {
                stream: "stderr",
                message: err.to_string(),
            })?;
        if count == 0 {
            break;
        }
        let count_u64 = u64::try_from(count).unwrap_or(u64::MAX);
        bytes = bytes.saturating_add(count_u64);
        if bytes > limit {
            return Err(ListingReadFailure::Limit {
                stream: "stderr",
                limit_kind: "bytes",
                limit,
                observed: bytes,
            });
        }
        append_stderr_tail(&mut tail, &buffer[..count]);
    }
    Ok(FlsStderrData {
        bytes,
        tail: String::from_utf8_lossy(&tail).into_owned(),
    })
}

fn terminate_listing_process(
    child: &mut std::process::Child,
    group: ChildProcessGroup,
    reader_threads: Vec<thread::JoinHandle<()>>,
) {
    kill_child_tree(child, group);
    let _ = child.wait();
    let started = Instant::now();
    while reader_threads.iter().any(|thread| !thread.is_finished())
        && started.elapsed() < FLS_READER_SHUTDOWN_GRACE
    {
        thread::sleep(FLS_READER_POLL_INTERVAL);
    }
    for thread in reader_threads {
        if thread.is_finished() {
            let _ = thread.join();
        }
    }
}

fn finalize_fls_listing(
    stdout: FlsStdoutData,
    stderr: FlsStderrData,
    status: std::process::ExitStatus,
    timeout: Duration,
) -> Result<TskListing, DiskError> {
    if !status.success() {
        return Err(DiskError::SubprocessFailed {
            status: status.to_string(),
            stderr_tail: stderr.tail,
        });
    }
    Ok(TskListing {
        entries: stdout.entries,
        entries_seen: stdout.entries_seen,
        stdout_bytes: stdout.bytes,
        stderr_bytes: stderr.bytes,
        stderr_tail: stderr.tail,
        truncated: false,
        limit_reason: None,
        timeout,
    })
}

fn run_fls_command(
    command: &mut Command,
    limits: TskListLimits,
    timeout: Duration,
) -> Result<TskListing, DiskError> {
    let program = PathBuf::from(command.get_program());
    let program_label = program.to_string_lossy().into_owned();
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let started = Instant::now();
    let (mut child, group) =
        spawn_isolated(command).map_err(|error| map_fixed_run_error(&program_label, error))?;
    let Some(stdout) = child.stdout.take() else {
        kill_child_tree(&mut child, group);
        let _ = child.wait();
        return Err(DiskError::ListingReaderTerminated);
    };
    let Some(stderr) = child.stderr.take() else {
        kill_child_tree(&mut child, group);
        let _ = child.wait();
        return Err(DiskError::ListingReaderTerminated);
    };

    let (sender, receiver) = mpsc::channel();
    let stdout_sender = sender.clone();
    let stdout_thread = thread::spawn(move || {
        let _ = stdout_sender.send(ListingReaderMessage::Stdout(read_fls_stdout(
            stdout, limits,
        )));
    });
    let stderr_thread = thread::spawn(move || {
        let _ = sender.send(ListingReaderMessage::Stderr(read_fls_stderr(
            stderr,
            limits.stderr_bytes,
        )));
    });
    let reader_threads = vec![stdout_thread, stderr_thread];
    let mut stdout_data = None;
    let mut stderr_data = None;
    let mut status = None;

    while status.is_none() || stdout_data.is_none() || stderr_data.is_none() {
        // The group token is independent of the leader's /proc entry, so
        // try_wait may safely reap a fast leader before strict quiescence.
        if stdout_data.is_some() && stderr_data.is_some() && status.is_none() {
            status = match child.try_wait() {
                Ok(status) => status,
                Err(source) => {
                    terminate_listing_process(&mut child, group, reader_threads);
                    return Err(DiskError::Io {
                        path: program,
                        source,
                    });
                }
            };
        }
        let elapsed = started.elapsed();
        if elapsed >= timeout {
            terminate_listing_process(&mut child, group, reader_threads);
            return Err(DiskError::ListingTimeout { timeout });
        }
        let poll_interval = FLS_READER_POLL_INTERVAL.min(timeout.saturating_sub(elapsed));
        if stdout_data.is_none() || stderr_data.is_none() {
            match receiver.recv_timeout(poll_interval) {
                Ok(ListingReaderMessage::Stdout(Ok(data))) => stdout_data = Some(data),
                Ok(ListingReaderMessage::Stderr(Ok(data))) => stderr_data = Some(data),
                Ok(
                    ListingReaderMessage::Stdout(Err(err)) | ListingReaderMessage::Stderr(Err(err)),
                ) => {
                    terminate_listing_process(&mut child, group, reader_threads);
                    return Err(err.into_disk_error());
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    terminate_listing_process(&mut child, group, reader_threads);
                    return Err(DiskError::ListingReaderTerminated);
                }
            }
        } else {
            thread::sleep(poll_interval);
        }
    }
    for handle in reader_threads {
        handle
            .join()
            .map_err(|_| DiskError::ListingReaderTerminated)?;
    }
    let stdout = stdout_data.ok_or(DiskError::ListingReaderTerminated)?;
    let stderr = stderr_data.ok_or(DiskError::ListingReaderTerminated)?;
    let status = status.ok_or(DiskError::ListingReaderTerminated)?;
    quiesce_process_group(group).map_err(|error| map_fixed_run_error(&program_label, error))?;
    finalize_fls_listing(stdout, stderr, status, timeout)
}

/// Iteratively list regular files under a mock mount's `fs_root`, returning
/// entries shaped exactly like [`tsk_list`] so they flow through the same
/// classifier + fair-share selector. Entry, nesting-depth, and relative-path
/// metadata ceilings bound both the explicit directory stack and result Vec;
/// any ceiling breach refuses the partial listing so limited coverage can never
/// become a false clearance. The inode slot is a placeholder — mock extraction
/// copies by relative path, not inode — and a directory walk has no deleted-file
/// concept, so `deleted` is always false.
fn mock_list(fs_root: &Path) -> Result<Vec<FlsEntry>, DiskError> {
    mock_list_with_limits(fs_root, MockWalkLimits::hard())
}

fn mock_traversal_limit_error(
    root: &Path,
    limit_kind: &str,
    limit: u64,
    observed: u64,
) -> DiskError {
    DiskError::MockTraversalLimitExceeded {
        root: root.to_path_buf(),
        limit_kind: limit_kind.to_string(),
        limit,
        observed,
    }
}

fn mock_list_with_limits(root: &Path, limits: MockWalkLimits) -> Result<Vec<FlsEntry>, DiskError> {
    let mut out = Vec::new();
    let mut pending = vec![(root.to_path_buf(), 0usize)];
    let mut entries_seen = 0usize;
    let mut metadata_bytes = 0u64;
    while let Some((directory, depth)) = pending.pop() {
        for entry in fs::read_dir(&directory).map_err(|source| DiskError::Io {
            path: directory.clone(),
            source,
        })? {
            let entry = entry.map_err(|source| DiskError::Io {
                path: directory.clone(),
                source,
            })?;
            entries_seen = entries_seen.saturating_add(1);
            if entries_seen > limits.entries {
                return Err(mock_traversal_limit_error(
                    root,
                    "entries",
                    u64::try_from(limits.entries).unwrap_or(u64::MAX),
                    u64::try_from(entries_seen).unwrap_or(u64::MAX),
                ));
            }
            let entry_depth = depth.saturating_add(1);
            if entry_depth > limits.depth {
                return Err(mock_traversal_limit_error(
                    root,
                    "depth",
                    u64::try_from(limits.depth).unwrap_or(u64::MAX),
                    u64::try_from(entry_depth).unwrap_or(u64::MAX),
                ));
            }
            let path = entry.path();
            let Ok(relative) = path.strip_prefix(root) else {
                continue;
            };
            let relative = relative.to_string_lossy().replace('\\', "/");
            metadata_bytes =
                metadata_bytes.saturating_add(u64::try_from(relative.len()).unwrap_or(u64::MAX));
            if metadata_bytes > limits.metadata_bytes {
                return Err(mock_traversal_limit_error(
                    root,
                    "metadata_bytes",
                    limits.metadata_bytes,
                    metadata_bytes,
                ));
            }
            let file_type = entry.file_type().map_err(|source| DiskError::Io {
                path: path.clone(),
                source,
            })?;
            if file_type.is_dir() {
                pending.push((path, entry_depth));
            } else if file_type.is_file() {
                out.push(FlsEntry {
                    inode: "-".to_string(),
                    path: relative,
                    deleted: false,
                    realloc: false,
                });
            }
        }
    }
    Ok(out)
}

/// Copy a mock artifact from `fs_root`/`rel_path` to the output dir, mirroring
/// [`tsk_extract`]'s output record so the ledger and caller see identical
/// shapes whether the mount was mock or real.
fn mock_extract(
    fs_root: &Path,
    candidate: &Candidate,
    output_dir: &Path,
    max_artifact_bytes: u64,
    remaining_total_bytes: u64,
    out: &mut Vec<ExtractedDiskArtifact>,
    stats: &mut ExtractStats,
) -> Result<bool, DiskError> {
    let src = safe_join(fs_root, &candidate.path);
    let size = fs::metadata(&src)
        .map_err(|source| DiskError::Io {
            path: src.clone(),
            source,
        })?
        .len();
    let copy_cap = max_artifact_bytes.min(remaining_total_bytes);
    if size > copy_cap {
        if remaining_total_bytes < max_artifact_bytes {
            stats.skipped_total_limit += 1;
            return Ok(true);
        }
        stats.skipped_oversize += 1;
        return Ok(false);
    }
    let dest = safe_join(&output_dir.join(candidate.class), &candidate.path);
    if let Some(parent) = dest.parent() {
        create_dir(parent)?;
    }
    let mut source_file = fs::File::open(&src).map_err(|source| DiskError::Io {
        path: src.clone(),
        source,
    })?;
    let mut dest_file = fs::File::create(&dest).map_err(|source| DiskError::Io {
        path: dest.clone(),
        source,
    })?;
    let copy_outcome =
        copy_stream_bounded(&mut source_file, &mut dest_file, copy_cap).map_err(|source| {
            DiskError::Io {
                path: dest.clone(),
                source,
            }
        })?;
    drop(dest_file);
    let copied = match copy_outcome {
        BoundedCopyOutput::Complete(copied) => copied,
        BoundedCopyOutput::LimitExceeded => {
            let _ = fs::remove_file(&dest);
            if remaining_total_bytes < max_artifact_bytes {
                stats.skipped_total_limit += 1;
                return Ok(true);
            }
            stats.skipped_oversize += 1;
            return Ok(false);
        }
    };
    out.push(ExtractedDiskArtifact {
        artifact_class: candidate.class.to_string(),
        source_path: PathBuf::from(&candidate.path),
        sha256: sha256_bound_files(std::slice::from_ref(&dest))?,
        extracted_path: dest,
        size_bytes: copied,
        recovered_deleted: candidate.deleted,
    });
    stats.extracted_bytes = stats.extracted_bytes.saturating_add(copied);
    Ok(false)
}

/// Parse one `fls -p` line into an [`FlsEntry`]. Live files look like
/// `r/r 380861-128-4:\tWindows/System32/config/SYSTEM`; deleted entries carry
/// a `*` marker (`r/r * 999-128-1:\t...`) and often lose their name-type
/// (`-/r * 999:\t...`). Returns None for directories, non-files, and deleted
/// entries whose name-type is unknown while still allocated.
fn parse_fls_line(line: &str) -> Option<FlsEntry> {
    let (kind, rest) = line.split_once(char::is_whitespace)?;
    let mut rest = rest.trim_start();
    let deleted = rest.strip_prefix('*').is_some_and(|stripped| {
        rest = stripped.trim_start();
        true
    });
    // Deleted dirents frequently list as `-/r` (name-type lost, meta-type
    // still a regular file); accept that shape only for deleted entries so
    // live unknowns stay excluded.
    if !(kind.starts_with("r/r") || (deleted && kind.starts_with("-/r"))) {
        return None;
    }
    let (inode, path) = rest.split_once(':')?;
    let mut inode = inode.trim();
    // fls appends `(realloc)` when the deleted entry's inode was reused by a
    // live file — icat on it would return the *new* file's bytes.
    let realloc = inode.strip_suffix("(realloc)").is_some_and(|stripped| {
        inode = stripped.trim_end();
        true
    });
    let path = path.trim();
    if inode.is_empty() || path.is_empty() {
        return None;
    }
    // The inode is handed to `icat` argv and used as an output path component;
    // TSK prints only digits and dashes (`380861-128-4`), so reject anything
    // else a hostile listing line could smuggle in.
    if !inode.chars().all(|c| c.is_ascii_digit() || c == '-') {
        return None;
    }
    Some(FlsEntry {
        inode: inode.to_string(),
        path: path.to_string(),
        deleted,
        realloc,
    })
}

/// Extract order: forensically critical classes first, broad yara targets last,
/// so the `limit` never crowds out registry/MFT/prefetch.
fn class_priority(class: &str) -> u8 {
    match class {
        "mft" => 0,
        "registry" => 1,
        "prefetch" => 2,
        "usnjrnl" => 3,
        "evtx" => 4,
        // Decoded execution / persistence / anti-forensic inputs — high value,
        // drawn after the filesystem/registry/EVTX core but before the generic
        // yara content sweep.
        "amcache" => 5,
        // Includes device-install logs for sparse USBSTOR data and user-content
        // images that may carry EXIF GPS/software fingerprint leads.
        "srum" | "bits" | "wmi_repository" | "email" | "setupapi_log" | "image_exif" => 6,
        "lnk" => 7,
        "jumplist" => 8,
        "scheduled_task" => 9,
        "recyclebin" => 10,
        "reg_txlog" => 11,
        "browser_db" => 12,
        "legacy_evt" => 13,
        "ie_history" => 14,
        "thumbnail" => 15,
        // Linux + macOS auto-extracted classes.
        "linux_account" => 16,
        "linux_log" => 17,
        "linux_shell_history" => 18,
        "linux_ssh" => 19,
        "linux_cron" => 20,
        "macos_unifiedlog" => 21,
        "macos_activity" => 22,
        "macos_launchd" => 23,
        "macos_fsevents" => 24,
        // Generic content sweep is always last.
        "yara_target" => 50,
        _ => 99,
    }
}

/// Draw order *within* a class (lower = extracted first). Only evtx is
/// sub-ranked: a Windows disk carries hundreds of low-signal
/// `Microsoft-Windows-*/Operational` logs that sort alphabetically *ahead* of
/// `Security.evtx`/`System.evtx`, so without this the canonical logs that
/// Sigma/hayabusa rules actually fire on would be the ones crowded out of the
/// budget. Tier 0 = the core four (Security/System/Sysmon/PowerShell); tier 1 =
/// other named high-signal logs (Application, forwarded/rotated security,
/// task-scheduler, defender, winrm, wmi, terminal-services, applocker); tier 2
/// = the per-provider operational tail.
fn artifact_subrank(class: &str, rel_path: &str) -> u8 {
    if class != "evtx" {
        return 0;
    }
    let lower = rel_path.replace('\\', "/").to_ascii_lowercase();
    let name = lower.rsplit('/').next().unwrap_or("");
    if name == "security.evtx"
        || name == "system.evtx"
        || name.contains("sysmon")
        || name.contains("powershell")
    {
        0
    } else if name == "application.evtx"
        || name == "forwardedevents.evtx"
        || name.starts_with("archive-security")
        || name.contains("taskscheduler")
        || name.contains("windows defender")
        || name.contains("winrm")
        || name.contains("wmi-activity")
        || name.contains("terminalservices")
        || name.contains("applocker")
        || !name.starts_with("microsoft-windows-")
    {
        1
    } else {
        2
    }
}

/// Classify listing entries into wanted-class extraction candidates, dropping
/// reallocated deleted entries (extraction would return the reusing live
/// file's bytes) and — when recovery is opted out — deleted entries entirely.
/// Returns `(candidates, deleted_entries_seen, deleted_skipped_realloc)` so
/// the output counters stay honest even when nothing is recovered.
fn build_candidates(
    listed: Vec<FlsEntry>,
    wanted: &BTreeMap<&'static str, bool>,
    recover_deleted: bool,
) -> (Vec<Candidate>, usize, usize) {
    let deleted_entries_seen = listed.iter().filter(|entry| entry.deleted).count();
    let deleted_skipped_realloc = listed
        .iter()
        .filter(|entry| entry.deleted && entry.realloc)
        .count();
    let candidates = listed
        .into_iter()
        .filter(|entry| !entry.realloc && (recover_deleted || !entry.deleted))
        .filter_map(|entry| {
            let class = classify_artifact_path(&entry.path)?;
            wanted
                .get(class)
                .copied()
                .unwrap_or(false)
                .then_some(Candidate {
                    class,
                    inode: entry.inode,
                    path: entry.path,
                    deleted: entry.deleted,
                })
        })
        .collect();
    (candidates, deleted_entries_seen, deleted_skipped_realloc)
}

/// Choose up to `limit` artifacts to extract, allocating the budget *fairly
/// across classes* so no single voluminous class starves the rest. Classes are
/// visited in [`class_priority`] order and drawn round-robin: every class with
/// candidates gets a turn each pass, and a class that drains early hands its
/// unused budget to the others. Within a class, [`artifact_subrank`], then
/// allocated-before-deleted, then path order decides which artifacts win the
/// class's share — recovered-deleted entries never crowd out live ones. Pure
/// (no I/O) so the allocation is unit-testable.
fn select_artifacts(candidates: Vec<Candidate>, limit: usize) -> Vec<Candidate> {
    let mut buckets: BTreeMap<u8, Vec<Candidate>> = BTreeMap::new();
    for candidate in candidates {
        buckets
            .entry(class_priority(candidate.class))
            .or_default()
            .push(candidate);
    }
    let mut queues: Vec<VecDeque<Candidate>> = buckets
        .into_values()
        .map(|mut bucket| {
            bucket.sort_by(|a, b| {
                artifact_subrank(a.class, &a.path)
                    .cmp(&artifact_subrank(b.class, &b.path))
                    .then_with(|| a.deleted.cmp(&b.deleted))
                    .then_with(|| a.path.cmp(&b.path))
            });
            VecDeque::from(bucket)
        })
        .collect();

    let mut selected = Vec::new();
    while selected.len() < limit && queues.iter().any(|queue| !queue.is_empty()) {
        for queue in &mut queues {
            if selected.len() >= limit {
                break;
            }
            if let Some(item) = queue.pop_front() {
                selected.push(item);
            }
        }
    }
    selected
}

/// Per-extract counters shared by [`tsk_extract`] and [`mock_extract`].
#[derive(Debug, Default)]
struct ExtractStats {
    skipped_oversize: usize,
    skipped_total_limit: usize,
    extraction_failed: usize,
    extracted_bytes: u64,
    aggregate_limit_reached: bool,
    deleted_recovered: usize,
    deleted_recovery_failed: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BoundedCopyOutput {
    Complete(u64),
    LimitExceeded,
}

/// Copy at most `limit` bytes, then read exactly one additional byte to prove
/// whether the stream was truncated. The extra byte is never written. This is
/// deliberately stricter than `io::copy(reader.take(limit + 1), file)`, which
/// would let a host-backed staging file grow one byte beyond the ceiling before
/// the caller could notice and delete it.
fn copy_stream_bounded(
    reader: &mut impl Read,
    writer: &mut impl Write,
    limit: u64,
) -> io::Result<BoundedCopyOutput> {
    let mut written = 0u64;
    let mut buffer = vec![0u8; STREAM_BUFFER_BYTES];
    loop {
        let remaining = limit.saturating_sub(written);
        let capped_read = remaining
            .saturating_add(1)
            .min(u64::try_from(buffer.len()).unwrap_or(u64::MAX));
        let read_cap = usize::try_from(capped_read).unwrap_or(buffer.len());
        let count = reader.read(&mut buffer[..read_cap])?;
        if count == 0 {
            return Ok(BoundedCopyOutput::Complete(written));
        }
        if count as u64 > remaining {
            if remaining > 0 {
                let allowed = usize::try_from(remaining).unwrap_or(count);
                writer.write_all(&buffer[..allowed])?;
            }
            return Ok(BoundedCopyOutput::LimitExceeded);
        }
        writer.write_all(&buffer[..count])?;
        written = written.saturating_add(count as u64);
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum BoundedProcessOutput {
    Complete(u64),
    ProcessFailed(String),
    LimitExceeded,
}

/// Run a fixed-argv extractor with piped stdout and a hard destination-file
/// ceiling. On overflow the child is killed and reaped before the partial file
/// is removed; a wall-clock deadline covers both a silent child and a child
/// that closes stdout but keeps running. Every failure kills the isolated
/// process tree, reaps its leader, joins the output thread, and removes `dest`.
fn terminate_icat_process(
    child: &mut std::process::Child,
    group: ChildProcessGroup,
    reader_thread: thread::JoinHandle<()>,
    dest: &Path,
) {
    kill_child_tree(child, group);
    let _ = child.wait();
    let shutdown_started = Instant::now();
    while !reader_thread.is_finished() && shutdown_started.elapsed() < ICAT_READER_SHUTDOWN_GRACE {
        thread::sleep(FLS_READER_POLL_INTERVAL);
    }
    if reader_thread.is_finished() {
        let _ = reader_thread.join();
    }
    // On Unix an open file can still be unlinked if process-group cleanup had
    // to degrade and a detached reader remains blocked on an inherited pipe.
    // More importantly, cleanup itself is bounded and can never wedge the MCP.
    let _ = fs::remove_file(dest);
}

fn run_command_to_file_bounded(
    command: &mut Command,
    dest: &Path,
    limit: u64,
    timeout: Duration,
) -> Result<BoundedProcessOutput, DiskError> {
    let program = PathBuf::from(command.get_program());
    let program_label = program.to_string_lossy().into_owned();
    command.stdin(Stdio::null()).stdout(Stdio::piped());
    let started = Instant::now();
    let (mut child, group) =
        spawn_isolated(command).map_err(|error| map_fixed_run_error(&program_label, error))?;
    let Some(stdout) = child.stdout.take() else {
        kill_child_tree(&mut child, group);
        let _ = child.wait();
        return Err(DiskError::IcatReaderTerminated);
    };
    let file = match fs::File::create(dest) {
        Ok(file) => file,
        Err(source) => {
            kill_child_tree(&mut child, group);
            let _ = child.wait();
            return Err(DiskError::Io {
                path: dest.to_path_buf(),
                source,
            });
        }
    };
    let (sender, receiver) = mpsc::channel();
    let reader_thread = thread::spawn(move || {
        let mut stdout = stdout;
        let mut file = file;
        let _ = sender.send(copy_stream_bounded(&mut stdout, &mut file, limit));
    });
    let mut copy_result = None;
    let mut status = None;

    while status.is_none() || copy_result.is_none() {
        // The group token is captured before the leader can disappear from
        // /proc, so try_wait may reap it without weakening descendant cleanup.
        if copy_result.is_some() && status.is_none() {
            status = match child.try_wait() {
                Ok(status) => status,
                Err(source) => {
                    terminate_icat_process(&mut child, group, reader_thread, dest);
                    return Err(DiskError::Io {
                        path: program,
                        source,
                    });
                }
            };
        }
        let elapsed = started.elapsed();
        if elapsed >= timeout {
            terminate_icat_process(&mut child, group, reader_thread, dest);
            return Err(DiskError::IcatTimeout { timeout });
        }
        let poll_interval = FLS_READER_POLL_INTERVAL.min(timeout.saturating_sub(elapsed));
        if copy_result.is_none() {
            match receiver.recv_timeout(poll_interval) {
                Ok(Ok(BoundedCopyOutput::Complete(size))) => {
                    copy_result = Some(BoundedProcessOutput::Complete(size));
                }
                Ok(Ok(BoundedCopyOutput::LimitExceeded)) => {
                    terminate_icat_process(&mut child, group, reader_thread, dest);
                    return Ok(BoundedProcessOutput::LimitExceeded);
                }
                Ok(Err(source)) => {
                    terminate_icat_process(&mut child, group, reader_thread, dest);
                    return Err(DiskError::Io {
                        path: dest.to_path_buf(),
                        source,
                    });
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    terminate_icat_process(&mut child, group, reader_thread, dest);
                    return Err(DiskError::IcatReaderTerminated);
                }
            }
        } else {
            thread::sleep(poll_interval);
        }
    }
    reader_thread
        .join()
        .map_err(|_| DiskError::IcatReaderTerminated)?;
    let status = status.ok_or(DiskError::IcatReaderTerminated)?;
    let output = copy_result.ok_or(DiskError::IcatReaderTerminated)?;
    if let Err(error) = quiesce_process_group(group) {
        let _ = fs::remove_file(dest);
        return Err(map_fixed_run_error(&program_label, error));
    }
    if status.success() {
        Ok(output)
    } else {
        let _ = fs::remove_file(dest);
        Ok(BoundedProcessOutput::ProcessFailed(status.to_string()))
    }
}

/// `icat` one inode out of the image, streaming to disk (no in-memory
/// buffering) and enforcing the size cap. Live files land under
/// `output_dir/<class>/<rel_path>`; recovered-deleted entries under
/// `output_dir/<class>/__deleted__/<inode>/<rel_path>` so recovered content is
/// unmistakable in the ledger and report, and same-path collisions cannot
/// overwrite a live artifact. A failed `icat` (unreadable inode) is skipped,
/// not fatal; a zero-byte recovered-deleted file counts as a failed recovery.
#[allow(clippy::too_many_arguments)]
fn tsk_extract(
    image_paths: &[PathBuf],
    sector_offset: Option<u64>,
    candidate: &Candidate,
    output_dir: &Path,
    max_artifact_bytes: u64,
    remaining_total_bytes: u64,
    timeout: Duration,
    out: &mut Vec<ExtractedDiskArtifact>,
    stats: &mut ExtractStats,
) -> Result<bool, DiskError> {
    let class_dir = output_dir.join(candidate.class);
    let base = if candidate.deleted {
        safe_join(&class_dir.join("__deleted__"), &candidate.inode)
    } else {
        class_dir
    };
    let dest = safe_join(&base, &candidate.path);
    if let Some(parent) = dest.parent() {
        create_dir(parent)?;
    }
    let bin = std::env::var("FINDEVIL_ICAT_BIN").unwrap_or_else(|_| "icat".to_string());
    // Same root-owned ewf1 rule as fls: sudo ewfmount leaves ewf1 unreadable
    // without privileges.
    let mut command = if image_paths_need_sudo(image_paths) {
        let mut c = Command::new("sudo");
        c.args(["-n", &bin]);
        c
    } else {
        Command::new(&bin)
    };
    if let Some(offset) = sector_offset {
        command.arg("-o").arg(offset.to_string());
    }
    append_image_args(&mut command, image_paths);
    command.arg(&candidate.inode);
    let stream_cap = max_artifact_bytes.min(remaining_total_bytes);
    let size = match run_command_to_file_bounded(&mut command, &dest, stream_cap, timeout)? {
        BoundedProcessOutput::Complete(size) => size,
        BoundedProcessOutput::ProcessFailed(_status) => {
            stats.extraction_failed += 1;
            if candidate.deleted {
                stats.deleted_recovery_failed += 1;
            }
            return Ok(false);
        }
        BoundedProcessOutput::LimitExceeded => {
            if remaining_total_bytes < max_artifact_bytes {
                stats.skipped_total_limit += 1;
                return Ok(true);
            }
            stats.skipped_oversize += 1;
            return Ok(false);
        }
    };
    if candidate.deleted && size == 0 {
        // The dirent parsed but the content run is gone — nothing recovered.
        let _ = fs::remove_file(&dest);
        stats.extraction_failed += 1;
        stats.deleted_recovery_failed += 1;
        return Ok(false);
    }
    if candidate.deleted {
        stats.deleted_recovered += 1;
    }
    out.push(ExtractedDiskArtifact {
        artifact_class: candidate.class.to_string(),
        source_path: PathBuf::from(&candidate.path),
        sha256: sha256_bound_files(std::slice::from_ref(&dest))?,
        extracted_path: dest,
        size_bytes: size,
        recovered_deleted: candidate.deleted,
    });
    stats.extracted_bytes = stats.extracted_bytes.saturating_add(size);
    Ok(false)
}

/// Join an image-internal path under `base`, keeping only normal components so a
/// hostile image filename can't escape the output directory.
fn safe_join(base: &Path, rel: &str) -> PathBuf {
    let mut dest = base.to_path_buf();
    for part in rel.replace('\\', "/").split('/') {
        if part.is_empty() || part == "." || part == ".." {
            continue;
        }
        dest.push(part);
    }
    dest
}

/// Map a carved file path to a forensic class. Order matters: OS-specific
/// classes are tried before the generic Windows content sweep, so a macOS
/// `Library/...` path or a Linux `/var/log/...` path wins over the `users/`
/// catch-all. Split per-OS to keep each branch's complexity bounded.
fn classify_artifact_path(rel: &str) -> Option<&'static str> {
    let rel = rel.replace('\\', "/").to_ascii_lowercase();
    let name = rel.rsplit('/').next().unwrap_or(rel.as_str());
    classify_windows_specific(name, &rel)
        .or_else(|| classify_linux(name, &rel))
        .or_else(|| classify_macos(name, &rel))
        .or_else(|| classify_windows_generic(&rel))
}

/// Windows filesystem + registry + decoded execution/persistence/anti-forensic
/// inputs. These feed the typed downstream wrappers (`ez_parse`, `plaso_parse`).
fn classify_windows_specific(name: &str, rel: &str) -> Option<&'static str> {
    if name == "$mft" || name == "mft" {
        Some("mft")
    } else if name == "$j" || rel.contains("$usnjrnl") || has_extension(name, "usn") {
        Some("usnjrnl")
    } else if has_extension(name, "pf") {
        Some("prefetch")
    } else if name == "amcache.hve" {
        Some("amcache")
    } else if name == "srudb.dat" {
        Some("srum")
    } else if matches!(name, "qmgr0.dat" | "qmgr1.dat" | "qmgr.db")
        && (rel.contains("/network/downloader/") || rel.contains("microsoft/network/downloader"))
    {
        // BITS job queue state (T1197) under ProgramData\Microsoft\Network\Downloader.
        Some("bits")
    } else if name == "objects.data"
        && (rel.contains("/wbem/repository/") || rel.contains("wbem/repository"))
    {
        // WMI CIM repository — T1546.003 persistence pattern surface.
        Some("wmi_repository")
    } else if has_extension(name, "eml")
        || has_extension(name, "mbox")
        || (has_extension(name, "pst") || has_extension(name, "ost"))
    {
        // Standalone email / Outlook stores for email_parse / pst_parse.
        Some("email")
    } else if name == "setupapi.dev.log" || name == "setupapi.app.log" {
        // Device install history (USB insertion timestamps) under Windows\inf.
        Some("setupapi_log")
    } else if matches!(
        name,
        "software" | "system" | "sam" | "security" | "ntuser.dat" | "usrclass.dat"
    ) {
        Some("registry")
    } else if has_extension(name, "log1") || has_extension(name, "log2") {
        // NTFS registry transaction logs (dirty-hive replay), e.g. SYSTEM.LOG1.
        Some("reg_txlog")
    } else if has_extension(name, "evtx") {
        Some("evtx")
    } else if has_extension(name, "lnk") {
        Some("lnk")
    } else if name.ends_with(".automaticdestinations-ms")
        || name.ends_with(".customdestinations-ms")
    {
        Some("jumplist")
    } else if (name.starts_with("$i") && rel.contains("$recycle.bin"))
        || (name == "info2" && (rel.starts_with("recycler/") || rel.contains("/recycler/")))
    {
        Some("recyclebin")
    } else if has_extension(name, "evt") {
        Some("legacy_evt")
    } else if name == "index.dat"
        && (rel.contains("/history.ie5/") || rel.contains("/temporary internet files/"))
    {
        Some("ie_history")
    } else if name == "thumbs.db"
        || name.ends_with(".thumbcache")
        || ((name.starts_with("thumbcache_") || name.starts_with("iconcache_"))
            && has_extension(name, "db"))
    {
        // XP Thumbs.db plus the Vista+ Explorer caches (thumbcache_####.db /
        // iconcache_####.db); the bare `.thumbcache` extension is kept for
        // pre-existing fixtures.
        Some("thumbnail")
    } else if has_extension(name, "jpg")
        || has_extension(name, "jpeg")
        || has_extension(name, "tif")
        || has_extension(name, "tiff")
        || has_extension(name, "heic")
        || has_extension(name, "heif")
        || has_extension(name, "webp")
        || (has_extension(name, "png")
            && (rel.contains("/users/")
                || rel.contains("/documents and settings/")
                || rel.contains("/pictures/")
                || rel.contains("/desktop/")
                || rel.contains("/downloads/")
                || rel.contains("/my documents/")))
    {
        // User-content images for exif_parse (GPS/software). Broad PNG under
        // System32 is skipped — OS icons/resources are noise.
        Some("image_exif")
    } else if rel.contains("/system32/tasks/") || rel.starts_with("windows/system32/tasks/") {
        Some("scheduled_task")
    } else if matches!(
        name,
        "history" | "places.sqlite" | "web data" | "cookies" | "login data"
    ) {
        Some("browser_db")
    } else {
        None
    }
}

/// Linux host classes. `matches_filesystem_description` already accepts
/// linux/ext, so TSK reads these — this makes them auto-extract.
fn classify_linux(name: &str, rel: &str) -> Option<&'static str> {
    if (rel.starts_with("etc/") || rel.contains("/etc/"))
        && matches!(name, "passwd" | "shadow" | "group" | "sudoers")
    {
        Some("linux_account")
    } else if rel.starts_with("var/log/") || rel.contains("/var/log/") {
        Some("linux_log")
    } else if matches!(name, ".bash_history" | ".zsh_history" | ".python_history") {
        Some("linux_shell_history")
    } else if rel.contains("/.ssh/authorized_keys")
        || rel.contains("/.ssh/known_hosts")
        || rel.starts_with(".ssh/authorized_keys")
    {
        Some("linux_ssh")
    } else if rel.contains("var/spool/cron")
        || rel.starts_with("etc/cron")
        || rel.contains("/etc/cron")
    {
        Some("linux_cron")
    } else {
        None
    }
}

/// macOS host classes.
fn classify_macos(name: &str, rel: &str) -> Option<&'static str> {
    if has_extension(name, "tracev3") {
        Some("macos_unifiedlog")
    } else if matches!(name, "knowledgec.db" | "tcc.db")
        || name.starts_with("com.apple.launchservices.quarantineevents")
    {
        Some("macos_activity")
    } else if rel.contains("library/launchagents/") || rel.contains("library/launchdaemons/") {
        Some("macos_launchd")
    } else if rel.contains(".fseventsd/") {
        Some("macos_fsevents")
    } else {
        None
    }
}

/// Generic Windows content sweep — the yara catch-all. Kept last so specific
/// OS classes always win over the profile/`programdata` directory match.
/// `documents and settings/` is the pre-Vista (XP/2003) equivalent of
/// `users/`; without it the whole user-profile tree on an XP-era image is
/// invisible to the content sweep, so both live and recovered-deleted profile
/// files go unclassified.
fn classify_windows_generic(rel: &str) -> Option<&'static str> {
    // Expand beyond profile/ProgramData so drivers and drop-paths under
    // System32 are YARA-scannable (closes disk-yara-only-on-extract-targets gap
    // for the highest-value implant paths without whole-mount recursion).
    let name = rel.rsplit('/').next().unwrap_or(rel);
    if (has_extension(name, "sys") || has_extension(name, "dll") || has_extension(name, "exe"))
        && (rel.contains("/system32/drivers/")
            || rel.contains("/syswow64/")
            || rel.contains("/system32/")
            || rel.starts_with("windows/system32/")
            || rel.starts_with("windows/syswow64/"))
    {
        return Some("yara_target");
    }
    if rel.starts_with("users/")
        || rel.contains("/users/")
        || rel.starts_with("documents and settings/")
        || rel.contains("/documents and settings/")
        || rel.starts_with("programdata/")
        || rel.contains("/programdata/")
        || rel.starts_with("windows/temp/")
        || rel.contains("/windows/temp/")
        || rel.contains("/windows/system32/spool/")
        || rel.contains("/windows/system32/tasks/")
    {
        Some("yara_target")
    } else {
        None
    }
}

fn wanted_kinds(kinds: &[ArtifactKind]) -> BTreeMap<&'static str, bool> {
    let mut wanted = BTreeMap::new();
    let classes: Vec<&'static str> = if kinds.is_empty() {
        vec![
            "mft",
            "usnjrnl",
            "prefetch",
            "registry",
            "evtx",
            "yara_target",
            "amcache",
            "srum",
            "bits",
            "wmi_repository",
            "email",
            "setupapi_log",
            "image_exif",
            "lnk",
            "jumplist",
            "scheduled_task",
            "recyclebin",
            "reg_txlog",
            "browser_db",
            "legacy_evt",
            "ie_history",
            "thumbnail",
            "linux_account",
            "linux_log",
            "linux_shell_history",
            "linux_ssh",
            "linux_cron",
            "macos_unifiedlog",
            "macos_activity",
            "macos_launchd",
            "macos_fsevents",
        ]
    } else {
        kinds
            .iter()
            .map(|k| match k {
                ArtifactKind::Mft => "mft",
                ArtifactKind::UsnJrnl => "usnjrnl",
                ArtifactKind::Prefetch => "prefetch",
                ArtifactKind::Registry => "registry",
                ArtifactKind::Evtx => "evtx",
                ArtifactKind::YaraTarget => "yara_target",
                ArtifactKind::Amcache => "amcache",
                ArtifactKind::Srum => "srum",
                ArtifactKind::Lnk => "lnk",
                ArtifactKind::Jumplist => "jumplist",
                ArtifactKind::ScheduledTask => "scheduled_task",
                ArtifactKind::Recyclebin => "recyclebin",
                ArtifactKind::RegTxlog => "reg_txlog",
                ArtifactKind::BrowserDb => "browser_db",
                ArtifactKind::LegacyEvt => "legacy_evt",
                ArtifactKind::IeHistory => "ie_history",
                ArtifactKind::Thumbnail => "thumbnail",
                ArtifactKind::LinuxAccount => "linux_account",
                ArtifactKind::LinuxLog => "linux_log",
                ArtifactKind::LinuxShellHistory => "linux_shell_history",
                ArtifactKind::LinuxSsh => "linux_ssh",
                ArtifactKind::LinuxCron => "linux_cron",
                ArtifactKind::MacosUnifiedlog => "macos_unifiedlog",
                ArtifactKind::MacosActivity => "macos_activity",
                ArtifactKind::MacosLaunchd => "macos_launchd",
                ArtifactKind::MacosFsevents => "macos_fsevents",
            })
            .collect()
    };
    for class in classes {
        wanted.insert(class, true);
    }
    wanted
}

pub(crate) fn case_dir(case_id: &str) -> Result<PathBuf, DiskError> {
    if !super::case_id::is_valid_case_id(case_id) {
        return Err(DiskError::InvalidCaseId(case_id.to_string()));
    }
    let dir = findevil_home()?.join("cases").join(case_id);
    if dir.is_dir() {
        Ok(dir)
    } else {
        Err(DiskError::CaseNotFound(case_id.to_string()))
    }
}

pub(crate) fn create_case_mount_leaf(
    case_directory: &Path,
    mount_id: &str,
) -> Result<PathBuf, DiskError> {
    if mount_id.is_empty()
        || !mount_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(DiskError::UnsafeMountPoint(PathBuf::from(mount_id)));
    }
    let case_metadata = fs::symlink_metadata(case_directory).map_err(|source| DiskError::Io {
        path: case_directory.to_path_buf(),
        source,
    })?;
    if !case_metadata.is_dir() || case_metadata.file_type().is_symlink() {
        return Err(DiskError::UnsafeMountPoint(case_directory.to_path_buf()));
    }
    let canonical_case =
        crate::pathnorm::canonicalize(case_directory).map_err(|source| DiskError::Io {
            path: case_directory.to_path_buf(),
            source,
        })?;
    let mounts_root = case_directory.join("mounts");
    match fs::symlink_metadata(&mounts_root) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
        Ok(_) => return Err(DiskError::UnsafeMountPoint(mounts_root)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            fs::create_dir(&mounts_root).map_err(|source| DiskError::Io {
                path: mounts_root.clone(),
                source,
            })?;
        }
        Err(source) => {
            return Err(DiskError::Io {
                path: mounts_root,
                source,
            })
        }
    }
    let canonical_root =
        crate::pathnorm::canonicalize(&mounts_root).map_err(|source| DiskError::Io {
            path: mounts_root.clone(),
            source,
        })?;
    if canonical_root.parent() != Some(canonical_case.as_path()) {
        return Err(DiskError::UnsafeMountPoint(mounts_root));
    }
    let mount_point = canonical_root.join(mount_id);
    match fs::symlink_metadata(&mount_point) {
        Ok(_) => return Err(DiskError::UnsafeMountPoint(mount_point)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(source) => {
            return Err(DiskError::Io {
                path: mount_point,
                source,
            })
        }
    }
    fs::create_dir(&mount_point).map_err(|source| DiskError::Io {
        path: mount_point.clone(),
        source,
    })?;
    let canonical_mount =
        crate::pathnorm::canonicalize(&mount_point).map_err(|source| DiskError::Io {
            path: mount_point.clone(),
            source,
        })?;
    if canonical_mount.parent() != Some(canonical_root.as_path()) {
        return Err(DiskError::UnsafeMountPoint(mount_point));
    }
    Ok(canonical_mount)
}

fn validate_case_mount_leaf(
    case_directory: &Path,
    mount_point: &Path,
) -> Result<PathBuf, DiskError> {
    let mounts_root = case_directory.join("mounts");
    let root_metadata = fs::symlink_metadata(&mounts_root).map_err(|source| DiskError::Io {
        path: mounts_root.clone(),
        source,
    })?;
    let mount_metadata = fs::symlink_metadata(mount_point).map_err(|source| DiskError::Io {
        path: mount_point.to_path_buf(),
        source,
    })?;
    if !root_metadata.is_dir()
        || root_metadata.file_type().is_symlink()
        || !mount_metadata.is_dir()
        || mount_metadata.file_type().is_symlink()
    {
        return Err(DiskError::UnsafeMountPoint(mount_point.to_path_buf()));
    }
    let canonical_root =
        crate::pathnorm::canonicalize(&mounts_root).map_err(|source| DiskError::Io {
            path: mounts_root,
            source,
        })?;
    let canonical_mount =
        crate::pathnorm::canonicalize(mount_point).map_err(|source| DiskError::Io {
            path: mount_point.to_path_buf(),
            source,
        })?;
    if canonical_mount.parent() != Some(canonical_root.as_path()) {
        return Err(DiskError::UnsafeMountPoint(canonical_mount));
    }
    Ok(canonical_mount)
}

fn findevil_home() -> Result<PathBuf, DiskError> {
    if let Ok(v) = std::env::var("FINDEVIL_HOME") {
        if !v.is_empty() {
            return Ok(PathBuf::from(v));
        }
    }
    if let Ok(h) = std::env::var("HOME") {
        if !h.is_empty() {
            return Ok(PathBuf::from(h).join(".findevil"));
        }
    }
    if let Ok(p) = std::env::var("USERPROFILE") {
        if !p.is_empty() {
            return Ok(PathBuf::from(p).join(".findevil"));
        }
    }
    Err(DiskError::CaseNotFound("FINDEVIL_HOME".to_string()))
}

fn read_ledger(path: &Path) -> Result<SessionLedger, DiskError> {
    if !path.exists() {
        return Ok(SessionLedger::default());
    }
    let text = fs::read_to_string(path).map_err(|source| DiskError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    serde_json::from_str(&text).map_err(DiskError::Serialize)
}

pub(crate) fn admit_case_mount(
    case_id: &str,
    kind: MountKind,
    image_path: &Path,
) -> Result<CaseMountAdmission, DiskError> {
    let case_dir = case_dir(case_id)?;
    let lock = CaseExtractionLock::acquire(&case_dir)?;
    let ledger_path = case_dir.join(LEDGER_NAME);
    let ledger = read_ledger(&ledger_path)?;
    let canonical_image = canonical_bound_file(case_id, image_path)?;
    let existing = ledger
        .resources
        .iter()
        .find(|resource| {
            kind.matches_resource(resource)
                && resource.image_path.as_deref() == Some(canonical_image.as_path())
        })
        .cloned();
    if existing.is_none() {
        let active_mounts = ledger
            .resources
            .iter()
            .filter(|resource| {
                resource.status == "mounted"
                    && matches!(resource.resource_type.as_str(), "disk_mount" | "vss_mount")
            })
            .count();
        if active_mounts >= HARD_MAX_ACTIVE_MOUNTS_PER_CASE {
            return Err(DiskError::ActiveMountLimit {
                case_id: case_id.to_string(),
                limit: HARD_MAX_ACTIVE_MOUNTS_PER_CASE,
            });
        }
    }
    Ok(CaseMountAdmission {
        case_id: case_id.to_string(),
        case_dir,
        ledger_path,
        existing,
        _lock: lock,
    })
}

/// Bytes already committed by prior disk extraction resources in this Case.
/// This turns the aggregate ceiling into a per-Case budget rather than a
/// per-call budget that a caller could reset by requesting another extract ID.
fn ledger_extracted_bytes(ledger: &SessionLedger) -> u64 {
    ledger
        .resources
        .iter()
        .filter(|resource| resource.resource_type == "disk_extract_artifacts")
        .flat_map(|resource| resource.artifacts.iter())
        .fold(0u64, |total, artifact| {
            total.saturating_add(artifact.size_bytes)
        })
}

/// Account both committed ledger artifacts and regular files actually present
/// in the case extraction tree. The filesystem side catches bounded partials
/// left by an abrupt process/container death before the ledger commit. Symlink
/// trees are never followed, and an adversarially huge entry count consumes the
/// entire budget fail-closed rather than turning accounting itself into a `DoS`.
fn case_extracted_bytes(case_dir: &Path, ledger: &SessionLedger) -> Result<u64, DiskError> {
    let extraction_root = case_dir.join("extracted").join("disk");
    let ledger_bytes = ledger_extracted_bytes(ledger);
    if !extraction_root.exists() {
        return Ok(ledger_bytes);
    }
    let root_metadata = fs::symlink_metadata(&extraction_root).map_err(|source| DiskError::Io {
        path: extraction_root.clone(),
        source,
    })?;
    if !root_metadata.is_dir() || root_metadata.file_type().is_symlink() {
        return Err(DiskError::UnsafeExtractionRoot(extraction_root));
    }

    let mut total = 0u64;
    let mut entries_seen = 0usize;
    let mut pending = vec![extraction_root];
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(&directory).map_err(|source| DiskError::Io {
            path: directory.clone(),
            source,
        })? {
            let entry = entry.map_err(|source| DiskError::Io {
                path: directory.clone(),
                source,
            })?;
            entries_seen = entries_seen.saturating_add(1);
            if entries_seen > HARD_MAX_ACCOUNTING_ENTRIES {
                return Ok(HARD_MAX_TOTAL_BYTES.max(ledger_bytes));
            }
            let file_type = entry.file_type().map_err(|source| DiskError::Io {
                path: entry.path(),
                source,
            })?;
            if file_type.is_dir() {
                pending.push(entry.path());
            } else if file_type.is_file() {
                let size = entry.metadata().map_err(|source| DiskError::Io {
                    path: entry.path(),
                    source,
                })?;
                total = total.saturating_add(size.len());
                if total >= HARD_MAX_TOTAL_BYTES {
                    return Ok(total.max(ledger_bytes));
                }
            }
        }
    }
    Ok(total.max(ledger_bytes))
}

fn write_ledger(path: &Path, ledger: &SessionLedger) -> Result<(), DiskError> {
    let text = serde_json::to_string_pretty(ledger)?;
    fs::write(path, text).map_err(|source| DiskError::Io {
        path: path.to_path_buf(),
        source,
    })
}

fn upsert_resource(path: &Path, resource: SessionResource) -> Result<(), DiskError> {
    let mut ledger = read_ledger(path)?;
    ledger.resources.retain(|r| r.id != resource.id);
    ledger.resources.push(resource);
    write_ledger(path, &ledger)
}

fn create_dir(path: &Path) -> Result<(), DiskError> {
    fs::create_dir_all(path).map_err(|source| DiskError::Io {
        path: path.to_path_buf(),
        source,
    })
}

fn now_iso() -> String {
    Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

const fn default_limit() -> usize {
    HARD_MAX_ARTIFACTS
}

const fn default_max_artifact_bytes() -> u64 {
    DEFAULT_MAX_ARTIFACT_BYTES
}

const fn default_max_total_bytes() -> u64 {
    DEFAULT_MAX_TOTAL_BYTES
}

const fn default_true() -> bool {
    true
}

fn has_extension(name: &str, ext: &str) -> bool {
    Path::new(name)
        .extension()
        .is_some_and(|actual| actual.eq_ignore_ascii_case(ext))
}

fn tail_utf8_lossy(bytes: &[u8]) -> String {
    let start = bytes.len().saturating_sub(STDERR_TAIL_BYTES);
    String::from_utf8_lossy(&bytes[start..]).to_string()
}

#[cfg(test)]
mod tests {
    use super::{
        artifact_subrank, case_dir, class_priority, classify_artifact_path, copy_stream_bounded,
        direct_tsk_mount, effective_extract_limits, ewf1_device_path, ewf_fallback_decision,
        ewfmount_available, ewfmount_available_bounded, fls_timeout_from_raw,
        icat_timeout_from_raw, image_paths_need_sudo, is_missing_binary, mmls_list_supports_ewf,
        mmls_timeout_from_raw, mock_list, mock_list_with_limits, mount_used_ewfmount,
        parse_fls_line, parse_mmls_partitions, parse_mmls_primary_partition_offset,
        persist_mounted_disk, persist_mounted_disk_with_rollback, read_ledger,
        resolve_tsk_image_paths, run_command_to_file_bounded, run_fixed_bounded, run_fls_command,
        run_mmls_bounded, safe_join, select_artifacts, unmount_steps, wanted_kinds,
        BoundedCopyOutput, BoundedProcessOutput, Candidate, CaptureLimits, CaseExtractionLock,
        DiskError, DiskExtractArtifactsInput, EwfFallback, FlsEntry, MmlsProbeLimits,
        MockWalkLimits, MountedDiskRegistration, SessionResource, TskListLimits,
        DEFAULT_MAX_TOTAL_BYTES, DIRECT_TSK_COMMAND, FLS_DEFAULT_TIMEOUT, FLS_MAX_TIMEOUT,
        HARD_MAX_ARTIFACTS, HARD_MAX_ARTIFACT_BYTES, HARD_MAX_TOTAL_BYTES, ICAT_DEFAULT_TIMEOUT,
        ICAT_MAX_TIMEOUT, MMLS_DEFAULT_TIMEOUT, MMLS_MAX_TIMEOUT,
    };
    use std::cell::Cell;
    use std::fs;
    use std::io::Cursor;
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::thread;
    use std::time::{Duration, Instant};

    #[test]
    #[cfg(unix)]
    fn case_mount_leaf_rejects_existing_traversal_and_symlink_roots() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let case = tmp.path().join("case");
        fs::create_dir(&case).expect("case dir");
        let created = super::create_case_mount_leaf(&case, "fixed-mount").expect("fresh leaf");
        let canonical_root = crate::pathnorm::canonicalize(case.join("mounts")).unwrap();
        assert_eq!(created.parent(), Some(canonical_root.as_path()));
        assert!(matches!(
            super::create_case_mount_leaf(&case, "fixed-mount"),
            Err(DiskError::UnsafeMountPoint(_))
        ));
        assert!(matches!(
            super::create_case_mount_leaf(&case, "../escape"),
            Err(DiskError::UnsafeMountPoint(_))
        ));

        let second_case = tmp.path().join("case-with-link");
        let outside = tmp.path().join("outside");
        fs::create_dir(&second_case).expect("second case");
        fs::create_dir(&outside).expect("outside");
        std::os::unix::fs::symlink(&outside, second_case.join("mounts")).expect("symlink root");
        assert!(matches!(
            super::create_case_mount_leaf(&second_case, "mount"),
            Err(DiskError::UnsafeMountPoint(_))
        ));
    }

    #[test]
    fn vss_resource_is_ledgered_and_disk_unmount_closes_it() {
        let _env_guard = crate::env_lock();
        let tmp = tempfile::tempdir().expect("tempdir");
        let case_id = "vss-ledger-case";
        let case = tmp.path().join("cases").join(case_id);
        fs::create_dir_all(&case).expect("case dir");
        let previous_home = std::env::var_os("FINDEVIL_HOME");
        std::env::set_var("FINDEVIL_HOME", tmp.path());
        let mount_id = "vss-mount-test";
        let image = tmp.path().join("source.dd");
        fs::write(&image, b"source").expect("source");
        let admission =
            super::admit_case_mount(case_id, super::MountKind::Vss, &image).expect("VSS admission");
        let mount_point = super::create_case_mount_leaf(admission.case_dir(), mount_id)
            .expect("server mount leaf");
        super::register_vss_mount_resource(
            &admission,
            mount_id,
            &image,
            &mount_point,
            "unavailable",
            &["vshadowmount".to_string()],
            &[],
        )
        .expect("register VSS resource");
        drop(admission);
        let ledger_path = case.join(super::LEDGER_NAME);
        let ledger = read_ledger(&ledger_path).expect("read ledger");
        assert!(ledger
            .resources
            .iter()
            .any(|resource| { resource.id == mount_id && resource.resource_type == "vss_mount" }));

        let output = super::disk_unmount(&super::DiskUnmountInput {
            case_id: case_id.to_string(),
            mount_id: mount_id.to_string(),
            mode: super::DiskMode::Auto,
        })
        .expect("close unavailable VSS resource");
        assert_eq!(output.status, "unmounted");
        assert!(!mount_point.exists());
        let ledger = read_ledger(&ledger_path).expect("read updated ledger");
        assert_eq!(
            ledger
                .resources
                .iter()
                .find(|resource| resource.id == mount_id)
                .map(|resource| resource.status.as_str()),
            Some("unmounted")
        );

        match previous_home {
            Some(value) => std::env::set_var("FINDEVIL_HOME", value),
            None => std::env::remove_var("FINDEVIL_HOME"),
        }
    }

    #[test]
    fn extract_input_keeps_prior_json_requests_compatible() {
        let input: DiskExtractArtifactsInput = serde_json::from_value(serde_json::json!({
            "case_id": "case-1",
            "mount_id": "mount-1",
            "limit": 10,
            "max_artifact_bytes": 1024
        }))
        .expect("legacy request without max_total_bytes must deserialize");

        assert_eq!(input.max_total_bytes, DEFAULT_MAX_TOTAL_BYTES);
        assert!(input.recover_deleted);
    }

    #[test]
    fn extract_limits_clamp_untrusted_caller_values() {
        let limits = effective_extract_limits(usize::MAX, u64::MAX, u64::MAX);

        assert_eq!(limits.artifacts, HARD_MAX_ARTIFACTS);
        assert_eq!(limits.per_artifact_bytes, HARD_MAX_ARTIFACT_BYTES);
        assert_eq!(limits.total_bytes, HARD_MAX_TOTAL_BYTES);
        assert!(limits.clamped);
    }

    #[test]
    fn case_extraction_lock_prevents_concurrent_budget_reservations() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let first = CaseExtractionLock::acquire(tmp.path()).expect("first lock");

        let second = CaseExtractionLock::acquire(tmp.path());
        assert!(
            matches!(second, Err(DiskError::DiskSessionBusy(_))),
            "same-case concurrent extraction must fail closed: {second:?}"
        );

        drop(first);
        CaseExtractionLock::acquire(tmp.path()).expect("lock releases when owner drops");
    }

    #[test]
    fn post_mount_partition_failure_is_ledgered_as_a_limitation() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let image_path = tmp.path().join("evidence.dd");
        fs::write(&image_path, b"evidence").expect("fixture image");
        let ledger_path = tmp.path().join("session_resources.json");
        let mount_id = "disk-mount-test".to_string();
        let registration = MountedDiskRegistration {
            case_id: "case-test".to_string(),
            mount_id: mount_id.clone(),
            status: "mounted".to_string(),
            image_path,
            mount_point: tmp.path().join("mount"),
            fs_root: tmp.path().join("mount/fs"),
            ledger_path: ledger_path.clone(),
            command: vec!["mount".to_string()],
            stderr_tail: String::new(),
            note: "mounted read-only".to_string(),
        };
        let probe_error = DiskError::MmlsTimeout {
            operation: "mmls partition enumeration".to_string(),
            timeout: Duration::from_secs(1),
        };

        let output = persist_mounted_disk(registration, Err(probe_error))
            .expect("an already-mounted resource must still be registered");

        assert_eq!(output.status, "mounted");
        assert!(output.partitions.is_empty());
        assert!(
            output.partition_enumeration_error.is_some(),
            "bounded mmls failure must remain visible"
        );
        let ledger = read_ledger(&ledger_path).expect("read mount ledger");
        let resource = ledger
            .resources
            .iter()
            .find(|resource| resource.id == mount_id)
            .expect("successful mount must never be left untracked");
        assert_eq!(resource.status, "mounted");
        assert!(resource.note.contains("partition enumeration limited"));
    }

    #[test]
    fn ledger_persistence_failure_rolls_back_real_mount_and_returns_typed_error() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let ledger_path = tmp.path().join("ledger-is-a-directory");
        fs::create_dir(&ledger_path).expect("force ledger read/write failure");
        let mount_id = "disk-mount-rollback".to_string();
        let registration = MountedDiskRegistration {
            case_id: "case-test".to_string(),
            mount_id: mount_id.clone(),
            status: "mounted".to_string(),
            image_path: tmp.path().join("evidence.dd"),
            mount_point: tmp.path().join("mount"),
            fs_root: tmp.path().join("mount/fs"),
            ledger_path: ledger_path.clone(),
            command: vec!["mount".to_string(), "-o".to_string(), "ro".to_string()],
            stderr_tail: String::new(),
            note: "mounted read-only".to_string(),
        };
        let rollback_called = Cell::new(false);

        let err = persist_mounted_disk_with_rollback(registration, Ok(Vec::new()), |_| {
            rollback_called.set(true);
            Ok(true)
        })
        .expect_err("untracked real mount must be rolled back");

        assert!(rollback_called.get(), "rollback hook was not invoked");
        assert!(matches!(
            err,
            DiskError::MountRegistrationFailed {
                ref failed_mount_id,
                ref failed_ledger_path,
                rollback_attempted: true,
                rollback_error: None,
                ..
            } if failed_mount_id == &mount_id && failed_ledger_path == &ledger_path
        ));
    }

    #[test]
    fn bounded_copy_reads_only_limit_plus_one_and_never_writes_the_extra_byte() {
        let mut source = Cursor::new(b"0123456789".to_vec());
        let mut destination = Vec::new();

        let outcome =
            copy_stream_bounded(&mut source, &mut destination, 4).expect("bounded in-memory copy");

        assert_eq!(outcome, BoundedCopyOutput::LimitExceeded);
        assert_eq!(destination, b"0123");
        assert_eq!(
            source.position(),
            5,
            "overflow detection must consume only max+1 bytes"
        );
    }

    #[test]
    #[cfg(unix)]
    fn bounded_subprocess_never_leaves_a_file_larger_than_the_cap() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let dest = tmp.path().join("oversized.bin");
        let mut command = Command::new("sh");
        // The shell itself performs the writes, so killing it closes the pipe;
        // no grandchild can retain stdout and make the test hang.
        command.args(["-c", "while :; do printf 0123456789; done"]);

        let outcome = run_command_to_file_bounded(&mut command, &dest, 32, Duration::from_secs(2))
            .expect("bounded subprocess runner");

        assert_eq!(outcome, BoundedProcessOutput::LimitExceeded);
        assert!(
            !dest.exists(),
            "an over-limit icat destination must be removed immediately"
        );
    }

    #[test]
    #[cfg(unix)]
    fn bounded_subprocess_accepts_output_exactly_at_the_cap() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let dest = tmp.path().join("exact.bin");
        let mut command = Command::new("sh");
        command.args(["-c", "printf 12345678"]);

        let outcome = run_command_to_file_bounded(&mut command, &dest, 8, Duration::from_secs(2))
            .expect("bounded subprocess runner");

        assert_eq!(outcome, BoundedProcessOutput::Complete(8));
        assert_eq!(fs::read(&dest).expect("read bounded output"), b"12345678");
    }

    #[test]
    fn icat_timeout_override_defaults_and_clamps() {
        assert_eq!(icat_timeout_from_raw(None), ICAT_DEFAULT_TIMEOUT);
        assert_eq!(icat_timeout_from_raw(Some("")), ICAT_DEFAULT_TIMEOUT);
        assert_eq!(icat_timeout_from_raw(Some("0")), ICAT_DEFAULT_TIMEOUT);
        assert_eq!(icat_timeout_from_raw(Some("invalid")), ICAT_DEFAULT_TIMEOUT);
        assert_eq!(icat_timeout_from_raw(Some("1")), Duration::from_secs(1));
        assert_eq!(icat_timeout_from_raw(Some("999999")), ICAT_MAX_TIMEOUT);
    }

    #[test]
    #[cfg(unix)]
    fn icat_runner_times_out_silent_child_and_deletes_output() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let dest = tmp.path().join("silent.bin");
        let mut command = Command::new("sh");
        command.args(["-c", "while :; do :; done"]);
        let timeout = Duration::from_millis(50);
        let started = Instant::now();

        let err = run_command_to_file_bounded(&mut command, &dest, 1024, timeout)
            .expect_err("silent icat must time out");

        assert!(matches!(
            err,
            DiskError::IcatTimeout { timeout: actual } if actual == timeout
        ));
        assert!(!dest.exists(), "timeout must remove the destination");
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[test]
    #[cfg(unix)]
    fn icat_runner_times_out_after_stdout_closes_and_deletes_partial_output() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let dest = tmp.path().join("closed-stdout.bin");
        let mut command = Command::new("sh");
        command.args(["-c", "printf partial; exec 1>&-; while :; do :; done"]);
        let timeout = Duration::from_millis(50);

        let err = run_command_to_file_bounded(&mut command, &dest, 1024, timeout)
            .expect_err("closed-stdout icat must still time out");

        assert!(matches!(err, DiskError::IcatTimeout { .. }));
        assert!(
            !dest.exists(),
            "timeout must remove bytes written before stdout closed"
        );
    }

    #[test]
    #[cfg(unix)]
    fn icat_runner_times_out_when_exited_leader_leaves_stdout_open() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let dest = tmp.path().join("inherited-stdout.bin");
        let mut command = Command::new("sh");
        command.args(["-c", "sh -c 'while :; do :; done' & exit 0"]);
        let timeout = Duration::from_millis(50);
        let started = Instant::now();

        let err = run_command_to_file_bounded(&mut command, &dest, 1024, timeout)
            .expect_err("an inherited stdout pipe must not outlive the deadline");

        assert!(matches!(err, DiskError::IcatTimeout { .. }));
        assert!(!dest.exists(), "timeout must remove the destination");
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "timeout cleanup must remain bounded after the leader exits"
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn icat_runner_rejects_closed_pipe_success_descendant_and_removes_output() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let dest = tmp.path().join("mutated-after-success.bin");
        let mut command = Command::new("sh");
        command
            .env("FINDEVIL_TEST_DEST", &dest)
            .args([
                "-c",
                "printf safe; (exec >/dev/null 2>/dev/null; sleep 1; printf evil >> \"$FINDEVIL_TEST_DEST\") & exit 0",
            ]);

        run_command_to_file_bounded(&mut command, &dest, 1024, Duration::from_secs(2))
            .expect_err("closed-pipe descendant must invalidate icat success");
        assert!(
            !dest.exists(),
            "incomplete output must be removed immediately"
        );
        thread::sleep(Duration::from_millis(1_300));
        assert!(!dest.exists(), "delayed descendant recreated icat output");
    }

    fn tiny_mmls_probe_limits() -> MmlsProbeLimits {
        MmlsProbeLimits {
            stdout_bytes: 128,
            stderr_bytes: 128,
        }
    }

    #[test]
    fn mmls_timeout_override_defaults_and_clamps() {
        assert_eq!(mmls_timeout_from_raw(None), MMLS_DEFAULT_TIMEOUT);
        assert_eq!(mmls_timeout_from_raw(Some("")), MMLS_DEFAULT_TIMEOUT);
        assert_eq!(mmls_timeout_from_raw(Some("0")), MMLS_DEFAULT_TIMEOUT);
        assert_eq!(mmls_timeout_from_raw(Some("invalid")), MMLS_DEFAULT_TIMEOUT);
        assert_eq!(mmls_timeout_from_raw(Some("1")), Duration::from_secs(1));
        assert_eq!(mmls_timeout_from_raw(Some("999999")), MMLS_MAX_TIMEOUT);
    }

    #[test]
    #[cfg(unix)]
    fn mmls_probe_times_out_silent_child() {
        let mut command = Command::new("sh");
        command.args(["-c", "while :; do :; done"]);
        let timeout = Duration::from_millis(50);
        let started = Instant::now();

        let err = run_mmls_bounded(&mut command, "test mmls", tiny_mmls_probe_limits(), timeout)
            .expect_err("silent mmls must time out");

        assert!(matches!(
            err,
            DiskError::MmlsTimeout {
                ref operation,
                timeout: actual,
            } if operation == "test mmls" && actual == timeout
        ));
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "timeout cleanup must remain bounded"
        );
    }

    #[test]
    #[cfg(unix)]
    fn mmls_probe_kills_and_errors_on_stdout_overflow() {
        let mut command = Command::new("sh");
        command.args(["-c", "while :; do printf 0123456789; done"]);
        let mut limits = tiny_mmls_probe_limits();
        limits.stdout_bytes = 32;

        let err = run_mmls_bounded(&mut command, "test mmls", limits, Duration::from_secs(2))
            .expect_err("mmls stdout must be bounded");

        assert!(matches!(
            err,
            DiskError::MmlsOutputLimitExceeded {
                ref stream,
                limit: 32,
                observed: 33,
                ..
            } if stream == "stdout"
        ));
    }

    #[test]
    #[cfg(unix)]
    fn mmls_probe_kills_and_errors_on_stderr_overflow() {
        let mut command = Command::new("sh");
        command.args(["-c", "while :; do printf warning >&2; done"]);
        let mut limits = tiny_mmls_probe_limits();
        limits.stderr_bytes = 32;

        let err = run_mmls_bounded(&mut command, "test mmls", limits, Duration::from_secs(2))
            .expect_err("mmls stderr must be bounded");

        assert!(matches!(
            err,
            DiskError::MmlsOutputLimitExceeded {
                ref stream,
                limit: 32,
                observed: 33,
                ..
            } if stream == "stderr"
        ));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn mmls_probe_rejects_closed_pipe_success_descendant() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let sentinel = tmp.path().join("mmls-delayed");
        let mut command = Command::new("sh");
        command.env("FINDEVIL_TEST_SENTINEL", &sentinel).args([
            "-c",
            "(exec >/dev/null 2>/dev/null; sleep 1; touch \"$FINDEVIL_TEST_SENTINEL\") & exit 0",
        ]);

        run_mmls_bounded(
            &mut command,
            "test mmls",
            tiny_mmls_probe_limits(),
            Duration::from_secs(2),
        )
        .expect_err("closed-pipe descendant must invalidate mmls success");
        thread::sleep(Duration::from_millis(1_300));
        assert!(
            !sentinel.exists(),
            "mmls descendant survived success cleanup"
        );
    }

    fn tiny_listing_limits() -> TskListLimits {
        TskListLimits {
            stdout_bytes: 128,
            stderr_bytes: 128,
            line_bytes: 64,
            entries: 2,
        }
    }

    fn tiny_listing_timeout() -> Duration {
        Duration::from_secs(2)
    }

    #[test]
    fn fls_timeout_override_defaults_and_clamps() {
        assert_eq!(fls_timeout_from_raw(None), FLS_DEFAULT_TIMEOUT);
        assert_eq!(fls_timeout_from_raw(Some("")), FLS_DEFAULT_TIMEOUT);
        assert_eq!(fls_timeout_from_raw(Some("0")), FLS_DEFAULT_TIMEOUT);
        assert_eq!(fls_timeout_from_raw(Some("invalid")), FLS_DEFAULT_TIMEOUT);
        assert_eq!(fls_timeout_from_raw(Some("1")), Duration::from_secs(1));
        assert_eq!(fls_timeout_from_raw(Some("999999")), FLS_MAX_TIMEOUT);
    }

    #[test]
    #[cfg(unix)]
    fn fls_reader_kills_and_errors_on_stdout_byte_overflow() {
        let mut command = Command::new("sh");
        command.args([
            "-c",
            "while :; do printf 'not-an-entry-0123456789\\n'; done",
        ]);
        let mut limits = tiny_listing_limits();
        limits.stdout_bytes = 32;
        limits.entries = 100;

        let err = run_fls_command(&mut command, limits, tiny_listing_timeout())
            .expect_err("stdout must be bounded");

        assert!(matches!(
            err,
            DiskError::ListingLimitExceeded {
                ref stream,
                ref limit_kind,
                limit: 32,
                ..
            } if stream == "stdout" && limit_kind == "bytes"
        ));
    }

    #[test]
    #[cfg(unix)]
    fn fls_reader_kills_and_errors_on_entry_overflow() {
        let mut command = Command::new("sh");
        command.args(["-c", "printf 'r/r 1:\ta\\nr/r 2:\tb\\nr/r 3:\tc\\n'"]);

        let err = run_fls_command(&mut command, tiny_listing_limits(), tiny_listing_timeout())
            .expect_err("entries bounded");

        assert!(matches!(
            err,
            DiskError::ListingLimitExceeded {
                ref stream,
                ref limit_kind,
                limit: 2,
                observed: 3,
            } if stream == "stdout" && limit_kind == "entries"
        ));
    }

    #[test]
    #[cfg(unix)]
    fn fls_reader_kills_and_errors_on_single_line_overflow() {
        let mut command = Command::new("sh");
        command.args([
            "-c",
            "printf 'r/r 1:\tabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ'",
        ]);
        let mut limits = tiny_listing_limits();
        limits.line_bytes = 32;

        let err = run_fls_command(&mut command, limits, tiny_listing_timeout())
            .expect_err("line bytes bounded");

        assert!(matches!(
            err,
            DiskError::ListingLimitExceeded {
                ref stream,
                ref limit_kind,
                limit: 32,
                observed: 33,
            } if stream == "stdout" && limit_kind == "line_bytes"
        ));
    }

    #[test]
    #[cfg(unix)]
    fn fls_reader_kills_and_errors_on_stderr_overflow() {
        let mut command = Command::new("sh");
        command.args(["-c", "while :; do printf warning >&2; done"]);
        let mut limits = tiny_listing_limits();
        limits.stderr_bytes = 32;

        let err = run_fls_command(&mut command, limits, tiny_listing_timeout())
            .expect_err("stderr must be bounded");

        assert!(matches!(
            err,
            DiskError::ListingLimitExceeded {
                ref stream,
                ref limit_kind,
                limit: 32,
                ..
            } if stream == "stderr" && limit_kind == "bytes"
        ));
    }

    #[test]
    #[cfg(unix)]
    fn fls_reader_reports_bounded_success_metadata() {
        let mut command = Command::new("sh");
        command.args([
            "-c",
            "printf 'r/r 1:\ta\\nr/r 2:\tb\\n'; printf warning >&2",
        ]);

        let listing = run_fls_command(&mut command, tiny_listing_limits(), tiny_listing_timeout())
            .expect("bounded fls");

        assert_eq!(listing.entries.len(), 2);
        assert_eq!(listing.entries_seen, 2);
        assert_eq!(listing.stderr_tail, "warning");
        assert_eq!(listing.stderr_bytes, 7);
        assert!(listing.stdout_bytes > 0);
        assert!(!listing.truncated);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn fls_reader_rejects_closed_pipe_success_descendant() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let sentinel = tmp.path().join("fls-delayed");
        let mut command = Command::new("sh");
        command
            .env("FINDEVIL_TEST_SENTINEL", &sentinel)
            .args([
                "-c",
                "printf 'r/r 1:\tentry\n'; (exec >/dev/null 2>/dev/null; sleep 1; touch \"$FINDEVIL_TEST_SENTINEL\") & exit 0",
            ]);

        run_fls_command(&mut command, tiny_listing_limits(), Duration::from_secs(2))
            .expect_err("closed-pipe descendant must invalidate fls success");
        thread::sleep(Duration::from_millis(1_300));
        assert!(
            !sentinel.exists(),
            "fls descendant survived success cleanup"
        );
    }

    #[test]
    #[cfg(unix)]
    fn fls_reader_times_out_silent_child_and_reaps_it() {
        let mut command = Command::new("sh");
        command.args(["-c", "while :; do :; done"]);
        let timeout = Duration::from_millis(50);
        let started = Instant::now();

        let err = run_fls_command(&mut command, tiny_listing_limits(), timeout)
            .expect_err("silent fls must time out");

        assert!(matches!(
            err,
            DiskError::ListingTimeout { timeout: actual } if actual == timeout
        ));
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "timeout path did not return promptly"
        );
    }

    #[test]
    #[cfg(unix)]
    fn fls_reader_timeout_stays_bounded_when_exited_leader_leaves_pipes_open() {
        let mut command = Command::new("sh");
        command.args(["-c", "sh -c 'while :; do :; done' & exit 0"]);
        let timeout = Duration::from_millis(50);
        let started = Instant::now();

        let err = run_fls_command(&mut command, tiny_listing_limits(), timeout)
            .expect_err("inherited fls pipes must not outlive the deadline");

        assert!(matches!(err, DiskError::ListingTimeout { .. }));
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "timeout cleanup must not block joining inherited pipes"
        );
    }

    #[test]
    #[cfg(unix)]
    fn fls_reader_polls_child_after_both_pipes_close() {
        let mut command = Command::new("sh");
        command.args(["-c", "exec 1>&- 2>&-; sleep 0.05"]);
        let started = Instant::now();

        let listing = run_fls_command(&mut command, tiny_listing_limits(), Duration::from_secs(2))
            .expect("closed pipes must wait for the child without channel spinning");

        assert!(listing.entries.is_empty());
        assert!(started.elapsed() >= Duration::from_millis(40));
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn safe_join_strips_traversal_and_stays_under_base() {
        let base = Path::new("/cases/abc/extracted");
        // A `..`-laden relative path must not escape the base: every `..`,
        // `.`, and empty segment is dropped, so the result is always a
        // descendant of base. This is the only write-side path guard.
        for rel in [
            "../../etc/passwd",
            "..\\..\\windows\\system32\\config\\sam",
            "/abs/looking/path",
            "./a/../../../b",
            "../",
            "..",
        ] {
            let joined = safe_join(base, rel);
            assert!(joined.starts_with(base), "{rel:?} escaped base: {joined:?}");
            assert!(
                !joined.components().any(|c| c.as_os_str() == ".."),
                "{rel:?} left a .. component: {joined:?}"
            );
        }
    }

    #[test]
    fn safe_join_keeps_legitimate_nested_paths() {
        let base = Path::new("/cases/abc/extracted");
        let joined = safe_join(base, "registry/Windows/System32/config/SOFTWARE");
        assert_eq!(
            joined,
            Path::new("/cases/abc/extracted/registry/Windows/System32/config/SOFTWARE")
        );
    }

    #[test]
    fn mock_list_walks_tree_and_keeps_relative_paths() {
        // The mock disk-extract path (tests + Windows, no TSK) walks fs_root.
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path();
        std::fs::create_dir_all(root.join("Windows/Prefetch")).unwrap();
        std::fs::create_dir_all(root.join("Windows/System32/config")).unwrap();
        std::fs::write(root.join("$MFT"), b"mft").unwrap();
        std::fs::write(root.join("Windows/Prefetch/CMD.EXE-1.pf"), b"pf").unwrap();
        std::fs::write(root.join("Windows/System32/config/SOFTWARE"), b"hive").unwrap();

        let mut listed = mock_list(root).expect("walk");
        listed.sort_by(|a, b| a.path.cmp(&b.path));
        assert!(
            listed.iter().all(|entry| !entry.deleted && !entry.realloc),
            "a directory walk has no deleted-file concept"
        );
        let paths: Vec<&str> = listed.iter().map(|entry| entry.path.as_str()).collect();
        assert!(paths.contains(&"$MFT"), "{paths:?}");
        assert!(
            paths.contains(&"Windows/Prefetch/CMD.EXE-1.pf"),
            "{paths:?}"
        );
        assert!(
            paths.contains(&"Windows/System32/config/SOFTWARE"),
            "{paths:?}"
        );
        // Every listed entry classifies into a forensic class via the same
        // classifier the TSK path uses.
        let classes: std::collections::BTreeSet<_> = listed
            .iter()
            .filter_map(|entry| classify_artifact_path(&entry.path))
            .collect();
        assert!(classes.contains("mft"));
        assert!(classes.contains("prefetch"));
        assert!(classes.contains("registry"));
    }

    #[test]
    fn mock_list_refuses_wide_tree_past_entry_ceiling() {
        let dir = tempfile::tempdir().expect("tempdir");
        for index in 0..4 {
            fs::write(dir.path().join(format!("file-{index}")), b"x").expect("fixture file");
        }
        let limits = MockWalkLimits {
            entries: 3,
            depth: 8,
            metadata_bytes: 1024,
        };

        let err =
            mock_list_with_limits(dir.path(), limits).expect_err("wide tree must fail closed");

        assert!(matches!(
            err,
            DiskError::MockTraversalLimitExceeded {
                ref limit_kind,
                limit: 3,
                observed: 4,
                ..
            } if limit_kind == "entries"
        ));
    }

    #[test]
    fn mock_list_refuses_tree_past_depth_ceiling_without_recursion() {
        let dir = tempfile::tempdir().expect("tempdir");
        fs::create_dir_all(dir.path().join("one/two/three")).expect("deep fixture");
        let limits = MockWalkLimits {
            entries: 16,
            depth: 2,
            metadata_bytes: 1024,
        };

        let err =
            mock_list_with_limits(dir.path(), limits).expect_err("deep tree must fail closed");

        assert!(matches!(
            err,
            DiskError::MockTraversalLimitExceeded {
                ref limit_kind,
                limit: 2,
                observed: 3,
                ..
            } if limit_kind == "depth"
        ));
    }

    #[test]
    fn mock_list_refuses_path_metadata_past_byte_ceiling() {
        let dir = tempfile::tempdir().expect("tempdir");
        fs::write(dir.path().join("abcdefghij"), b"x").expect("fixture file");
        let limits = MockWalkLimits {
            entries: 16,
            depth: 8,
            metadata_bytes: 5,
        };

        let err =
            mock_list_with_limits(dir.path(), limits).expect_err("metadata bytes must fail closed");

        assert!(matches!(
            err,
            DiskError::MockTraversalLimitExceeded {
                ref limit_kind,
                limit: 5,
                observed: 10,
                ..
            } if limit_kind == "metadata_bytes"
        ));
    }

    #[test]
    fn classify_artifact_path_matches_thumbnail_caches() {
        assert_eq!(
            classify_artifact_path("Documents and Settings/Suspect User/My Documents/Thumbs.db"),
            Some("thumbnail")
        );
        assert_eq!(
            classify_artifact_path(
                "Users/bob/AppData/Local/Microsoft/Windows/Explorer/thumbcache_256.thumbcache"
            ),
            Some("thumbnail")
        );
        // Real Vista+ Explorer caches are thumbcache_####.db / iconcache_*.db —
        // the shapes that actually exist on disk.
        assert_eq!(
            classify_artifact_path(
                "Users/bob/AppData/Local/Microsoft/Windows/Explorer/thumbcache_1024.db"
            ),
            Some("thumbnail")
        );
        assert_eq!(
            classify_artifact_path(
                "Users/bob/AppData/Local/Microsoft/Windows/Explorer/iconcache_32.db"
            ),
            Some("thumbnail")
        );
    }

    #[test]
    fn parse_fls_line_extracts_inode_and_path_for_live_files() {
        assert_eq!(
            parse_fls_line("r/r 380861-128-4:\tWindows/System32/config/SYSTEM"),
            Some(FlsEntry {
                inode: "380861-128-4".to_string(),
                path: "Windows/System32/config/SYSTEM".to_string(),
                deleted: false,
                realloc: false,
            })
        );
    }

    #[test]
    fn parse_fls_line_skips_dirs_and_blanks() {
        assert_eq!(parse_fls_line("d/d 282867-144-5:\tUsers"), None);
        assert_eq!(parse_fls_line(""), None);
        // Live entries with unknown name-type stay excluded — only deleted
        // entries are allowed the `-/r` shape.
        assert_eq!(parse_fls_line("-/r 555-128-1:\tWindows/x.pf"), None);
    }

    #[test]
    fn parse_fls_line_keeps_deleted_entries_with_markers() {
        assert_eq!(
            parse_fls_line("r/r * 999-128-1:\tWindows/Prefetch/x.pf"),
            Some(FlsEntry {
                inode: "999-128-1".to_string(),
                path: "Windows/Prefetch/x.pf".to_string(),
                deleted: true,
                realloc: false,
            })
        );
        // Deleted entries that lost their name-type still parse.
        assert_eq!(
            parse_fls_line("-/r * 555-128-1:\tDocuments and Settings/user/evil.doc"),
            Some(FlsEntry {
                inode: "555-128-1".to_string(),
                path: "Documents and Settings/user/evil.doc".to_string(),
                deleted: true,
                realloc: false,
            })
        );
        // A reallocated inode is flagged so extraction can skip it — icat
        // would return the reusing live file's content.
        assert_eq!(
            parse_fls_line("r/r * 2036-128-3(realloc):\tWINDOWS/system32/mal.dll"),
            Some(FlsEntry {
                inode: "2036-128-3".to_string(),
                path: "WINDOWS/system32/mal.dll".to_string(),
                deleted: true,
                realloc: true,
            })
        );
    }

    #[test]
    fn parse_fls_line_rejects_non_tsk_inode_tokens() {
        // The inode is passed to icat argv and used as an output path
        // component; anything but digits/dashes is hostile-listing noise.
        assert_eq!(parse_fls_line("r/r ../escape:\tWindows/x.pf"), None);
        assert_eq!(parse_fls_line("r/r abc-def:\tWindows/x.pf"), None);
    }

    #[test]
    fn classify_artifact_path_matches_forensic_classes() {
        assert_eq!(
            classify_artifact_path("Windows/System32/config/SYSTEM"),
            Some("registry")
        );
        assert_eq!(
            classify_artifact_path("Windows/Prefetch/CMD.EXE-1234.pf"),
            Some("prefetch")
        );
        assert_eq!(classify_artifact_path("$MFT"), Some("mft"));
        assert_eq!(
            classify_artifact_path("Users/bob/NTUSER.DAT"),
            Some("registry")
        );
        assert_eq!(
            classify_artifact_path("Users/bob/Desktop/evil.txt"),
            Some("yara_target")
        );
        // XP/2003 profile path (the pre-Vista `Users/` equivalent) must also
        // reach the content sweep — live and recovered-deleted alike.
        assert_eq!(
            classify_artifact_path("Documents and Settings/analyst/Local Settings/Temp/x.exe"),
            Some("yara_target")
        );
        // System32 PE files are yara-targets so implant paths under drivers /
        // System32 are scanned when FIND_EVIL_DISK_YARA_RULES (or the bundled
        // ruleset) is available — not left invisible to disk YARA.
        assert_eq!(
            classify_artifact_path("Windows/System32/kernel32.dll"),
            Some("yara_target")
        );
        assert_eq!(
            classify_artifact_path("Windows/System32/drivers/evil.sys"),
            Some("yara_target")
        );
    }

    fn assert_classifications(cases: &[(&str, &str)]) {
        for &(path, expected) in cases {
            assert_eq!(
                classify_artifact_path(path),
                Some(expected),
                "unexpected classification for {path}"
            );
        }
    }

    #[test]
    fn classify_artifact_path_matches_extended_classes() {
        // Windows decoded-execution / persistence / anti-forensic inputs the
        // carve list must hand to downstream typed wrappers. A bare SYSTEM hive
        // remains registry rather than reg_txlog.
        assert_classifications(&[
            ("Windows/appcompat/Programs/Amcache.hve", "amcache"),
            ("Windows/System32/sru/SRUDB.dat", "srum"),
            ("ProgramData/Microsoft/Network/Downloader/qmgr0.dat", "bits"),
            (
                "Windows/System32/wbem/Repository/OBJECTS.DATA",
                "wmi_repository",
            ),
            ("Users/bob/Downloads/phish.eml", "email"),
            ("Users/bob/Documents/mail.pst", "email"),
            ("Windows/inf/setupapi.dev.log", "setupapi_log"),
            ("Users/bob/Pictures/vacation.jpg", "image_exif"),
            ("Users/bob/Desktop/shot.heic", "image_exif"),
            (
                "Users/bob/AppData/Roaming/Microsoft/Windows/Recent/evil.lnk",
                "lnk",
            ),
            ("RECYCLER/S-1-5-21-1000/INFO2", "recyclebin"),
            ("Windows/System32/config/SecEvent.Evt", "legacy_evt"),
            (
                "Documents and Settings/Suspect User/Local Settings/History/History.IE5/index.dat",
                "ie_history",
            ),
            (
                "Users/bob/AppData/Roaming/Microsoft/Windows/Recent/AutomaticDestinations/\
                 1b4dd67f29cb1962.automaticDestinations-ms",
                "jumplist",
            ),
            ("Windows/System32/Tasks/EvilPersist", "scheduled_task"),
            ("$Recycle.Bin/S-1-5-21-1004/$IABC123.txt", "recyclebin"),
            ("Windows/System32/config/SYSTEM.LOG1", "reg_txlog"),
            (
                "Users/bob/AppData/Local/Google/Chrome/User Data/Default/History",
                "browser_db",
            ),
            ("Windows/System32/config/SYSTEM", "registry"),
        ]);

        // System PNG resources must not steal extract budget as image_exif.
        assert_ne!(
            classify_artifact_path("Windows/System32/oobe/background.png"),
            Some("image_exif")
        );
    }

    #[test]
    fn classify_artifact_path_matches_linux_classes() {
        // Filesystem descriptions already accept linux/ext, so TSK reads and
        // auto-extracts these paths.
        assert_classifications(&[
            ("etc/passwd", "linux_account"),
            ("var/log/auth.log", "linux_log"),
            ("home/bob/.bash_history", "linux_shell_history"),
            ("home/bob/.ssh/authorized_keys", "linux_ssh"),
            ("var/spool/cron/crontabs/root", "linux_cron"),
        ]);
    }

    #[test]
    fn classify_artifact_path_matches_macos_classes() {
        assert_classifications(&[
            (
                "private/var/db/diagnostics/Persist/0000.tracev3",
                "macos_unifiedlog",
            ),
            (
                "Users/bob/Library/Application Support/Knowledge/knowledgeC.db",
                "macos_activity",
            ),
            ("Library/LaunchDaemons/com.evil.plist", "macos_launchd"),
            (".fseventsd/0000000000abcd12", "macos_fsevents"),
        ]);
    }

    #[test]
    fn wanted_kinds_default_includes_extended_classes() {
        // Default extraction (empty artifact_kinds) must carve the new classes,
        // or the downstream wrappers never receive disk-image input.
        let wanted = wanted_kinds(&[]);
        for class in [
            "mft",
            "registry",
            "amcache",
            "srum",
            "lnk",
            "jumplist",
            "scheduled_task",
            "recyclebin",
            "reg_txlog",
            "browser_db",
            "legacy_evt",
            "ie_history",
            "thumbnail",
            "linux_log",
            "macos_unifiedlog",
        ] {
            assert!(wanted.contains_key(class), "default set missing {class}");
        }
    }

    #[test]
    fn class_priority_orders_high_value_before_yara() {
        assert!(class_priority("mft") < class_priority("registry"));
        assert!(class_priority("registry") < class_priority("prefetch"));
        assert!(class_priority("prefetch") < class_priority("yara_target"));
    }

    #[test]
    fn loop_mount_unavailable_detects_eperm_and_missing_loop() {
        assert!(super::loop_mount_unavailable(
            "mount: /x: mount failed: Operation not permitted."
        ));
        assert!(super::loop_mount_unavailable(
            "losetup: cannot find an unused loop device: No such device"
        ));
        assert!(!super::loop_mount_unavailable(
            "mount: wrong fs type, bad option, bad superblock"
        ));
    }

    #[test]
    fn mount_bin_is_system_mount_accepts_path_forms() {
        assert!(super::mount_bin_is_system_mount("mount"));
        assert!(super::mount_bin_is_system_mount("/bin/mount"));
        assert!(super::mount_bin_is_system_mount("/usr/bin/mount"));
        assert!(!super::mount_bin_is_system_mount(
            "/home/sansforensics/sudo-mount"
        ));
    }

    #[test]
    fn artifact_subrank_surfaces_canonical_evtx_before_operational_tail() {
        let logs = "Windows/System32/winevt/Logs";
        // The core logs Sigma/hayabusa fire on hardest rank ahead of the long
        // Microsoft-Windows-*/Operational tail that sorts first alphabetically.
        assert!(
            artifact_subrank("evtx", &format!("{logs}/Security.evtx"))
                < artifact_subrank(
                    "evtx",
                    &format!("{logs}/Microsoft-Windows-Kernel-WHEA%4Operational.evtx")
                )
        );
        assert!(
            artifact_subrank("evtx", &format!("{logs}/System.evtx"))
                < artifact_subrank(
                    "evtx",
                    &format!("{logs}/Microsoft-Windows-Bits-Client%4Operational.evtx")
                )
        );
        // Sysmon / PowerShell match by substring regardless of provider prefix.
        assert_eq!(
            artifact_subrank(
                "evtx",
                &format!("{logs}/Microsoft-Windows-Sysmon%4Operational.evtx")
            ),
            0
        );
        // Non-evtx classes are never sub-ranked.
        assert_eq!(
            artifact_subrank("prefetch", "Windows/Prefetch/CMD.EXE-1.pf"),
            0
        );
    }

    #[test]
    fn select_artifacts_gives_every_class_a_fair_share() {
        // A budget far smaller than one voluminous class must still reach the
        // others: 400 prefetch + 600 operational evtx + 1 mft, limit 50 -> all
        // three classes represented (the old global-priority sort extracted
        // zero evtx), and the canonical Security.evtx wins evtx's share over
        // the operational tail.
        fn live(class: &'static str, inode: &str, path: String) -> Candidate {
            Candidate {
                class,
                inode: inode.to_string(),
                path,
                deleted: false,
            }
        }
        let mut candidates: Vec<Candidate> = Vec::new();
        for i in 0..400 {
            candidates.push(live("prefetch", &format!("{i}"), {
                format!("Windows/Prefetch/A{i:04}.pf")
            }));
        }
        for i in 0..600 {
            candidates.push(live(
                "evtx",
                &format!("e{i}"),
                format!(
                    "Windows/System32/winevt/Logs/Microsoft-Windows-Zzz{i:04}%4Operational.evtx"
                ),
            ));
        }
        candidates.push(live(
            "evtx",
            "sec",
            "Windows/System32/winevt/Logs/Security.evtx".to_string(),
        ));
        candidates.push(live("mft", "mft", "$MFT".to_string()));

        let selected = select_artifacts(candidates, 50);
        assert_eq!(selected.len(), 50);
        let classes: std::collections::HashSet<&str> = selected.iter().map(|c| c.class).collect();
        assert!(classes.contains("prefetch"), "prefetch starved");
        assert!(classes.contains("evtx"), "evtx starved (the original bug)");
        assert!(classes.contains("mft"), "mft missing");
        assert!(
            selected.iter().any(|c| c.path.ends_with("/Security.evtx")),
            "canonical Security.evtx must win evtx's fair share"
        );
    }

    #[test]
    fn select_artifacts_draws_allocated_before_deleted_within_a_class() {
        // With a class budget of 2, the two live prefetch files must win over
        // the alphabetically-earlier deleted one: recovered-deleted entries
        // never crowd allocated evidence out of the budget.
        let candidates = vec![
            Candidate {
                class: "prefetch",
                inode: "9".to_string(),
                path: "Windows/Prefetch/AAA-DELETED.pf".to_string(),
                deleted: true,
            },
            Candidate {
                class: "prefetch",
                inode: "1".to_string(),
                path: "Windows/Prefetch/LIVE1.pf".to_string(),
                deleted: false,
            },
            Candidate {
                class: "prefetch",
                inode: "2".to_string(),
                path: "Windows/Prefetch/LIVE2.pf".to_string(),
                deleted: false,
            },
        ];
        let selected = select_artifacts(candidates, 2);
        assert_eq!(selected.len(), 2);
        assert!(
            selected.iter().all(|c| !c.deleted),
            "deleted entry crowded out a live file: {selected:?}"
        );
    }

    #[test]
    fn select_artifacts_caps_at_limit_and_handles_empty() {
        assert!(select_artifacts(Vec::new(), 10).is_empty());
        let candidates = vec![
            Candidate {
                class: "mft",
                inode: "1".to_string(),
                path: "$MFT".to_string(),
                deleted: false,
            },
            Candidate {
                class: "prefetch",
                inode: "2".to_string(),
                path: "Windows/Prefetch/X.pf".to_string(),
                deleted: false,
            },
        ];
        assert_eq!(select_artifacts(candidates.clone(), 1).len(), 1);
        assert_eq!(select_artifacts(candidates, 5).len(), 2); // limit above supply
    }

    #[test]
    fn unmount_steps_ewf_plus_ntfs_releases_loop_then_container() {
        let mp = Path::new("/m");
        let fs_dir = mp.join("fs");
        let ewf_dir = mp.join("ewf");
        let steps = unmount_steps(mp, &fs_dir, "umount");
        assert_eq!(
            steps,
            vec![
                (
                    "umount".to_string(),
                    vec![fs_dir.to_string_lossy().to_string()]
                ),
                (
                    "umount".to_string(),
                    vec![ewf_dir.to_string_lossy().to_string()]
                ),
            ]
        );
    }

    #[test]
    fn unmount_steps_ewf_only_releases_container() {
        let mp = Path::new("/m");
        let ewf_dir = mp.join("ewf");
        let steps = unmount_steps(mp, &ewf_dir, "umount");
        assert_eq!(
            steps,
            vec![(
                "umount".to_string(),
                vec![ewf_dir.to_string_lossy().to_string()]
            )]
        );
    }

    #[test]
    fn unmount_steps_raw_umounts_the_mount_point() {
        let mp = Path::new("/m");
        let steps = unmount_steps(mp, mp, "umount");
        assert_eq!(
            steps,
            vec![("umount".to_string(), vec![mp.to_string_lossy().to_string()])]
        );
    }

    #[test]
    fn direct_tsk_mount_registers_a_mounted_read_off_the_image() {
        // The ewfmount-less fallback must register a resource disk_extract can
        // consume: status "mounted", fs_root == the image itself, and a sentinel
        // command that is neither "mock" (which would force the walk path) nor a
        // real mount command (which disk_unmount would try to tear down).
        let image = Path::new("/evidence/host-c-drive.E01");
        let (status, fs_root, command, stderr_tail, note) =
            direct_tsk_mount(image, "ewfmount gone");
        assert_eq!(status, "mounted");
        assert_eq!(fs_root, image);
        assert_eq!(command, vec![DIRECT_TSK_COMMAND.to_string()]);
        assert_ne!(command.first().map(String::as_str), Some("mock"));
        assert!(stderr_tail.is_empty());
        assert!(note.contains("no FUSE/loop mount"), "note was: {note}");
    }

    #[test]
    fn ewfmount_available_is_false_for_a_missing_binary() {
        // A binary that cannot be spawned (ENOENT) is the condition that forces
        // the fallback decision (direct-TSK only if this TSK can read EWF).
        assert!(
            !ewfmount_available("findevil-definitely-not-a-real-binary-zzz")
                .expect("missing probe is a normal unavailable result")
        );
    }

    #[test]
    #[cfg(unix)]
    fn ewfmount_probe_times_out_a_sleeping_binary() {
        use std::os::unix::fs::PermissionsExt as _;

        let temp = tempfile::tempdir().expect("tempdir");
        let binary = temp.path().join("sleeping-ewfmount");
        fs::write(&binary, "#!/bin/sh\nsleep 30\n").expect("write probe");
        let mut permissions = fs::metadata(&binary).expect("metadata").permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&binary, permissions).expect("chmod probe");
        let started = Instant::now();

        let error = ewfmount_available_bounded(
            binary.to_str().expect("utf8 path"),
            Duration::from_millis(50),
            CaptureLimits {
                stdout_bytes: 128,
                stderr_bytes: 128,
            },
        )
        .expect_err("sleeping probe must time out");

        assert!(error.to_string().contains("time budget"));
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[test]
    #[cfg(unix)]
    fn fixed_mount_command_times_out_a_sleeping_child() {
        let args = vec!["-c".to_string(), "sleep 30".to_string()];
        let started = Instant::now();
        let error = run_fixed_bounded(
            "sh",
            &args,
            Duration::from_millis(50),
            CaptureLimits {
                stdout_bytes: 128,
                stderr_bytes: 128,
            },
        )
        .expect_err("sleeping mount helper must time out");

        assert!(error.to_string().contains("time budget"));
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[test]
    #[cfg(unix)]
    fn fixed_mount_command_kills_infinite_stdout() {
        let args = vec![
            "-c".to_string(),
            "while :; do printf 0123456789; done".to_string(),
        ];
        let started = Instant::now();
        let error = run_fixed_bounded(
            "sh",
            &args,
            Duration::from_secs(2),
            CaptureLimits {
                stdout_bytes: 64,
                stderr_bytes: 128,
            },
        )
        .expect_err("unbounded mount stdout must be killed");

        assert!(error.to_string().contains("capture limit"));
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    // Real `mmls -i list` output from the DFIR container image. Debian/Ubuntu
    // build TSK without libewf, so `ewf` is absent and a direct read of a .E01
    // yields "Possible encryption detected (High entropy)" with exit 0 — a
    // silent false negative on real evidence.
    const MMLS_LIST_WITHOUT_EWF: &str = "Supported image format types:\n\
        \traw (Single or split raw file (dd))\n\
        \taff (Advanced Forensic Format)\n\
        \tafd (AFF Multiple File)\n\
        \tafm (AFF with external metadata)\n\
        \tafflib (All AFFLIB image formats (including beta ones))\n";

    const MMLS_LIST_WITH_EWF: &str = "Supported image format types:\n\
        \traw (Single or split raw file (dd))\n\
        \tewf (Expert Witness Format, EnCase)\n\
        \taff (Advanced Forensic Format)\n";

    #[test]
    fn mmls_listing_without_ewf_is_detected() {
        assert!(!mmls_list_supports_ewf(MMLS_LIST_WITHOUT_EWF));
    }

    #[test]
    fn mmls_listing_with_ewf_is_detected() {
        assert!(mmls_list_supports_ewf(MMLS_LIST_WITH_EWF));
    }

    #[test]
    fn mmls_listing_match_is_on_the_type_token_not_the_description() {
        // "afflib (All AFFLIB image formats ...)" must not match, and a
        // description mentioning EWF must not create a false positive.
        assert!(!mmls_list_supports_ewf(
            "\taff (Advanced Forensic Format, converts ewf)\n"
        ));
    }

    #[test]
    fn ewf_fallback_mounts_when_ewfmount_is_present() {
        assert_eq!(ewf_fallback_decision(true, false), EwfFallback::Mount);
        assert_eq!(ewf_fallback_decision(true, true), EwfFallback::Mount);
    }

    #[test]
    fn ewf_fallback_allows_direct_tsk_only_when_tsk_can_read_ewf() {
        assert_eq!(ewf_fallback_decision(false, true), EwfFallback::DirectTsk);
    }

    #[test]
    fn ewf_fallback_refuses_when_no_reader_can_open_the_image() {
        // The regression this guard exists for: without ewfmount, and with a TSK
        // that has no EWF support, a direct read reports "mounted" and extracts
        // zero artifacts. Refuse instead of reporting a phantom clean disk.
        assert_eq!(ewf_fallback_decision(false, false), EwfFallback::Refuse);
    }

    #[test]
    fn ewf_reader_unavailable_error_names_the_image_and_the_remedy() {
        let err = DiskError::EwfReaderUnavailable {
            image: PathBuf::from("/evidence/Laptop1Final.E01"),
            bin: "ewfmount".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("Laptop1Final.E01"), "message was: {msg}");
        assert!(msg.contains("ewfmount"), "message was: {msg}");
        // Must not be mistakable for "the disk is clean".
        assert!(
            msg.contains("zero artifacts") || msg.contains("silently"),
            "message must warn about the silent-false-negative: {msg}"
        );
    }

    #[test]
    fn is_missing_binary_matches_command_not_found_variants() {
        // The reported live failure was literally this line.
        assert!(is_missing_binary("sudo: ewfmount: command not found"));
        assert!(is_missing_binary("ewfmount: command not found"));
        assert!(is_missing_binary(
            "exec: \"ewfmount\": executable file not found in $PATH"
        ));
        // A genuine mount failure must NOT be mistaken for a missing binary —
        // that stays a surfaced error, not a silent fallback.
        assert!(!is_missing_binary(
            "ewfmount: unable to open file(s): permission denied"
        ));
        assert!(!is_missing_binary(""));
    }

    #[test]
    fn ewf1_device_path_prefers_mount_point_ewf_ewf1() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let mount_point = tmp.path().join("disk-mount-xyz");
        let ewf_dir = mount_point.join("ewf");
        fs::create_dir_all(&ewf_dir).expect("mkdir ewf");
        let ewf1 = ewf_dir.join("ewf1");
        fs::write(&ewf1, b"raw").expect("write ewf1");
        // fs_root also points at ewf dir (custody-only NTFS note path).
        let found = ewf1_device_path(Some(&mount_point), Some(&ewf_dir));
        assert_eq!(found.as_deref(), Some(ewf1.as_path()));
    }

    #[test]
    fn ewf1_device_path_none_when_fuse_not_present() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let mount_point = tmp.path().join("disk-mount-xyz");
        fs::create_dir_all(&mount_point).expect("mkdir");
        assert!(ewf1_device_path(Some(&mount_point), Some(&mount_point)).is_none());
    }

    fn test_mount_resource(
        mount_point: Option<PathBuf>,
        fs_root: Option<PathBuf>,
        command: Vec<String>,
    ) -> SessionResource {
        SessionResource {
            id: "disk-mount-test".to_string(),
            resource_type: "disk_mount".to_string(),
            status: "mounted".to_string(),
            created_at: "2026-01-01T00:00:00Z".to_string(),
            updated_at: "2026-01-01T00:00:00Z".to_string(),
            image_path: Some(PathBuf::from("/evidence/host.E01")),
            mount_point,
            fs_root,
            parent_id: None,
            output_dir: None,
            artifacts: vec![],
            command,
            note: String::new(),
            partitions: Vec::new(),
            partition_enumeration_error: None,
        }
    }

    #[test]
    fn mount_used_ewfmount_detects_sudo_prefixed_command() {
        assert!(mount_used_ewfmount(&[
            "sudo".into(),
            "-n".into(),
            "ewfmount".into(),
            "/evidence/x.E01".into(),
            "/tmp/ewf".into(),
        ]));
        assert!(mount_used_ewfmount(&["/usr/local/bin/ewfmount".into()]));
        assert!(!mount_used_ewfmount(&[
            DIRECT_TSK_COMMAND.into(),
            "mock".into()
        ]));
    }

    #[test]
    fn image_paths_need_sudo_only_for_ewf1() {
        assert!(image_paths_need_sudo(&[PathBuf::from(
            "/cases/x/mounts/m/ewf/ewf1"
        )]));
        assert!(!image_paths_need_sudo(&[PathBuf::from(
            "/evidence/host.dd"
        )]));
    }

    #[test]
    fn resolve_tsk_image_paths_uses_ewf1_from_ledger_even_without_visible_file() {
        // Regression: sudo ewfmount leaves ewf/ root-only, so Path::is_file
        // fails for the analyst process. Trust the command ledger and still
        // point fls/icat at ewf1 (they run under sudo).
        let tmp = tempfile::tempdir().expect("tempdir");
        let mount_point = tmp.path().join("disk-mount-xyz");
        // Deliberately do NOT create ewf1 — it is invisible to is_file().
        let original = tmp.path().join("host.E01");
        fs::write(&original, b"compressed-container").expect("write e01");
        let mount = test_mount_resource(
            Some(mount_point.clone()),
            Some(mount_point.join("ewf")),
            vec![
                "sudo".into(),
                "-n".into(),
                "ewfmount".into(),
                original.to_string_lossy().into(),
                mount_point.join("ewf").to_string_lossy().into(),
            ],
        );
        let paths = resolve_tsk_image_paths(&mount, &original).expect("resolve");
        assert_eq!(paths, vec![mount_point.join("ewf").join("ewf1")]);
    }

    #[test]
    fn resolve_tsk_image_paths_falls_back_to_original_when_no_ewfmount() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let original = tmp.path().join("host.dd");
        fs::write(&original, b"raw-dd").expect("write dd");
        let mount = test_mount_resource(None, None, vec![DIRECT_TSK_COMMAND.into()]);
        let paths = resolve_tsk_image_paths(&mount, &original).expect("resolve");
        assert_eq!(paths, vec![original]);
    }

    #[test]
    fn mmls_parser_returns_sole_filesystem_partition_offset() {
        let output = r"DOS Partition Table
Offset Sector: 0
Units are in 512-byte sectors

      Slot      Start        End          Length       Description
000:  Meta      0000000000   0000000000   0000000001   Primary Table (#0)
001:  -------   0000000000   0000000062   0000000063   Unallocated
002:  000:000   0000000063   0009510479   0009510417   NTFS / exFAT (0x07)
";

        assert_eq!(parse_mmls_primary_partition_offset(output), Some(63 * 512));
    }

    #[test]
    fn mmls_parser_ignores_metadata_and_unallocated_rows() {
        let output = r"      Slot      Start        End          Length       Description
000:  Meta      0000000000   0000000000   0000000001   Primary Table (#0)
001:  -------   0000000000   0000002047   0000002048   Unallocated
";

        assert_eq!(parse_mmls_primary_partition_offset(output), None);
    }

    /// Regression: on a full Windows disk image the first filesystem partition
    /// is the tiny "System Reserved" boot volume; the OS/C: volume that holds
    /// the event logs and registry is a separate, much larger partition. The
    /// parser must select the largest (offset 718848), not the first (2048) —
    /// selecting the first walked only ~166 files and extracted zero EVTX.
    #[test]
    fn mmls_parser_selects_largest_partition_not_the_system_reserved_stub() {
        let output = r"DOS Partition Table
Offset Sector: 0
Units are in 512-byte sectors

      Slot      Start        End          Length       Description
000:  Meta      0000000000   0000000000   0000000001   Primary Table (#0)
001:  -------   0000000000   0000002047   0000002048   Unallocated
002:  000:000   0000002048   0000718847   0000716800   NTFS / exFAT (0x07)
003:  000:001   0000718848   0023590911   0022872064   NTFS / exFAT (0x07)
004:  -------   0023590912   0023592959   0000002048   Unallocated
";

        assert_eq!(
            parse_mmls_primary_partition_offset(output),
            Some(718_848 * 512)
        );
    }

    /// The largest filesystem partition wins even when it is listed before the
    /// smaller ones, so ordering never masks the size comparison.
    #[test]
    fn mmls_parser_selects_largest_partition_regardless_of_order() {
        let output = r"      Slot      Start        End          Length       Description
000:  Meta      0000000000   0000000000   0000000001   Primary Table (#0)
002:  000:000   0000002048   0020000000   0019997953   NTFS / exFAT (0x07)
003:  000:001   0020002048   0020718847   0000716800   NTFS / exFAT (0x07)
";

        assert_eq!(
            parse_mmls_primary_partition_offset(output),
            Some(2048 * 512)
        );
    }

    #[test]
    fn mmls_enumerates_every_filesystem_partition_in_table_order() {
        // A full Windows disk: System Reserved stub + the large C: volume + a
        // separate FAT data volume. All three are filesystems; the Meta and
        // Unallocated rows must be excluded. Enumeration keeps every volume so a
        // multi-volume disk is not silently reduced to just the primary.
        let output = r"DOS Partition Table
Offset Sector: 0
Units are in 512-byte sectors

      Slot      Start        End          Length       Description
000:  Meta      0000000000   0000000000   0000000001   Primary Table (#0)
001:  -------   0000000000   0000002047   0000002048   Unallocated
002:  000:000   0000002048   0000718847   0000716800   NTFS / exFAT (0x07)
003:  000:001   0000718848   0023590911   0022872064   NTFS / exFAT (0x07)
004:  000:002   0023590912   0025590911   0002000000   FAT32 (0x0c)
";
        let parts = parse_mmls_partitions(output);
        assert_eq!(
            parts.len(),
            3,
            "three filesystem partitions, no meta/unalloc"
        );
        assert_eq!(parts[0].slot, 2);
        assert_eq!(parts[0].start_sector, 2048);
        assert_eq!(parts[0].byte_offset, 2048 * 512);
        assert_eq!(parts[1].slot, 3);
        assert_eq!(parts[1].length_sectors, 22_872_064);
        assert_eq!(parts[1].byte_offset, 718_848 * 512);
        assert_eq!(parts[2].slot, 4);
        assert!(parts[2].description.to_lowercase().contains("fat32"));
        // The primary selector agrees with the enumeration: largest = slot 3.
        assert_eq!(
            parse_mmls_primary_partition_offset(output),
            Some(718_848 * 512)
        );
    }

    #[test]
    fn mmls_enumeration_empty_for_bare_volume_no_table() {
        // A bare volume image (no partition table) yields no partitions; callers
        // fall back to reading at offset 0.
        let output = r"Cannot determine partition type
";
        assert!(parse_mmls_partitions(output).is_empty());
    }

    #[test]
    fn case_dir_rejects_traversal_case_id_before_join() {
        match case_dir("../../etc") {
            Err(DiskError::InvalidCaseId(id)) => assert_eq!(id, "../../etc"),
            other => panic!("expected InvalidCaseId, got {other:?}"),
        }
        match case_dir("a/b") {
            Err(DiskError::InvalidCaseId(_)) => {}
            other => panic!("expected InvalidCaseId for slash, got {other:?}"),
        }
        match case_dir("..") {
            Err(DiskError::InvalidCaseId(_)) => {}
            other => panic!("expected InvalidCaseId for .., got {other:?}"),
        }
    }
}
