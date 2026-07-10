//! Shared evidence authorization for the Rust MCP dispatch boundary.
//!
//! Every evidence-reading tool is mapped here to the argument fields that can
//! reach evidence bytes.  The dispatcher obtains a hash receipt before calling
//! a handler and verifies that receipt again before sealing any output.  This
//! keeps authorization independent of individual parser implementations.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::{BufReader, Read};
use std::path::{Component, Path, PathBuf};

use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::tools::ewf_segments::{is_first_ewf_segment, segment_paths_for_image};
use crate::tools::is_valid_case_id;

const LAUNCHER_BINDING_ENV: &str = "FINDEVIL_BROWSER_CASE_BINDING";
const CASE_OPEN_BINDING_ENV: &str = "FINDEVIL_CASE_OPEN_BINDING";
const MAX_LAUNCHER_BINDING_BYTES: usize = 512 * 1024;
const MAX_LAUNCHER_ARTIFACTS: usize = 500;
const MAX_DIRECTORY_FILES: usize = 500;
const MAX_DIRECTORY_ENTRIES: usize = 100_000;
const MAX_DIRECTORY_DEPTH: usize = 128;
const MAX_LEDGER_BYTES: u64 = 64 * 1024 * 1024;
const MAX_LEDGER_ARTIFACTS: usize = 100_000;
const HASH_BUFFER_BYTES: usize = 1024 * 1024;
const YARA_RULE_ENV_NAMES: [&str; 3] = [
    "FIND_EVIL_MEMORY_YARA_RULES",
    "FIND_EVIL_DISK_YARA_RULES",
    "FINDEVIL_YARA_RULES_ROOT",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ToolPolicy {
    /// `case_open` consumes a launcher-established source reservation.
    Registration,
    /// Reads only server-owned state whose evidence source is checked in-tool.
    StateOnly,
    /// Every listed JSON argument is an evidence path.
    Evidence(&'static [&'static str]),
    /// Operator configuration with no model-selected filesystem path.
    ConfigOnly,
}

#[derive(Debug, thiserror::Error)]
pub(super) enum AccessError {
    #[error("invalid evidence authorization input: {0}")]
    InvalidInput(String),
    #[error("evidence path {path} is not authorized for case {case_id}")]
    NotAuthorized { case_id: String, path: PathBuf },
    #[error("evidence integrity mismatch for case {case_id} at {path}")]
    IntegrityMismatch { case_id: String, path: PathBuf },
    #[error("evidence authorization state is invalid: {0}")]
    AuthorizationState(String),
    #[error("cannot read evidence authorization path {path}: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("evidence authorization resource limit exceeded: {0}")]
    ResourceLimit(String),
    #[error("case {0} is not active in this MCP session")]
    InactiveCase(String),
    #[error("case_open reservation has already been registered in this MCP session: {0}")]
    RegistrationConsumed(PathBuf),
    #[error(
        "parsed evidence egress is not authorized; set FINDEVIL_OUTPUT_ROUTE=local_controller \
         or local_dgx for a reviewed local route, or \
         FINDEVIL_ACKNOWLEDGE_PARSED_EVIDENCE_EGRESS=1 explicitly"
    )]
    PrivacyBoundary,
}

impl AccessError {
    pub(super) const fn is_client_error(&self) -> bool {
        matches!(
            self,
            Self::InvalidInput(_)
                | Self::NotAuthorized { .. }
                | Self::IntegrityMismatch { .. }
                | Self::ResourceLimit(_)
                | Self::InactiveCase(_)
                | Self::RegistrationConsumed(_)
                | Self::PrivacyBoundary
        )
    }
}

#[derive(Debug, Default)]
pub(super) struct EvidenceSession {
    active_case_ids: BTreeSet<String>,
    consumed_registration_paths: BTreeSet<PathBuf>,
    privacy_authorized: bool,
}

impl EvidenceSession {
    pub(super) fn from_launcher() -> Self {
        let mut session = Self {
            active_case_ids: BTreeSet::new(),
            consumed_registration_paths: BTreeSet::new(),
            privacy_authorized: privacy_route_authorized(),
        };
        if let Some(case_id) = launcher_case_id() {
            session.active_case_ids.insert(case_id);
        }
        session
    }

    #[cfg(test)]
    pub(super) fn trusted_test() -> Self {
        let mut session = Self::from_launcher();
        session.privacy_authorized = true;
        session
    }

    pub(super) fn activate_case(&mut self, case_id: &str) -> Result<(), AccessError> {
        if !is_valid_case_id(case_id) {
            return Err(AccessError::AuthorizationState(
                "case_open returned an invalid case id".to_string(),
            ));
        }
        self.active_case_ids.insert(case_id.to_string());
        Ok(())
    }

    fn require_active(&self, tool_name: &str, arguments: &Value) -> Result<(), AccessError> {
        if tool_policy(tool_name) == Some(ToolPolicy::Registration) {
            return Ok(());
        }
        let Some(case_id) = arguments.get("case_id").and_then(Value::as_str) else {
            return Ok(());
        };
        if self.active_case_ids.contains(case_id) {
            Ok(())
        } else {
            Err(AccessError::InactiveCase(case_id.to_string()))
        }
    }

    fn require_privacy_authorized(&self) -> Result<(), AccessError> {
        self.privacy_authorized
            .then_some(())
            .ok_or(AccessError::PrivacyBoundary)
    }

    fn require_registration_available(
        &self,
        tool_name: &str,
        arguments: &Value,
    ) -> Result<(), AccessError> {
        if tool_policy(tool_name) != Some(ToolPolicy::Registration) {
            return Ok(());
        }
        let requested = arguments
            .get("image_path")
            .and_then(Value::as_str)
            .ok_or_else(|| AccessError::InvalidInput("missing string image_path".to_string()))?;
        let canonical_path = canonical_regular_file(Path::new(requested))?;
        if self.consumed_registration_paths.contains(&canonical_path) {
            Err(AccessError::RegistrationConsumed(canonical_path))
        } else {
            Ok(())
        }
    }

    pub(super) fn consume_registration(
        &mut self,
        authorization: &ToolAuthorization,
    ) -> Result<(), AccessError> {
        let canonical_path = authorization.registration_path.as_ref().ok_or_else(|| {
            AccessError::AuthorizationState(
                "case_open authorization returned no registration path".to_string(),
            )
        })?;
        if self
            .consumed_registration_paths
            .insert(canonical_path.clone())
        {
            Ok(())
        } else {
            Err(AccessError::RegistrationConsumed(canonical_path.clone()))
        }
    }
}

fn privacy_route_authorized() -> bool {
    let route = std::env::var("FINDEVIL_OUTPUT_ROUTE").ok();
    let acknowledgment = std::env::var("FINDEVIL_ACKNOWLEDGE_PARSED_EVIDENCE_EGRESS").ok();
    privacy_route_values_authorized(route.as_deref(), acknowledgment.as_deref())
}

fn privacy_route_values_authorized(route: Option<&str>, acknowledgment: Option<&str>) -> bool {
    matches!(route, Some("local_controller" | "local_dgx")) || acknowledgment == Some("1")
}

fn launcher_case_id() -> Option<String> {
    let raw = std::env::var_os(LAUNCHER_BINDING_ENV)?;
    let bytes = raw.as_encoded_bytes();
    if bytes.len() > MAX_LAUNCHER_BINDING_BYTES {
        return None;
    }
    let binding: LauncherBinding = serde_json::from_slice(bytes).ok()?;
    is_valid_case_id(&binding.case_id).then_some(binding.case_id)
}

#[derive(Debug)]
struct HashReceipt {
    case_id: String,
    paths: Vec<PathBuf>,
    expected_sha256: String,
    expected_size_bytes: Option<u64>,
    identities: Vec<StableIdentity>,
    parent_identities: Vec<(PathBuf, StableIdentity)>,
}

impl HashReceipt {
    fn authorize(
        case_id: &str,
        paths: Vec<PathBuf>,
        expected_sha256: &str,
        expected_size_bytes: Option<u64>,
    ) -> Result<Self, AccessError> {
        let identities = paths
            .iter()
            .map(|path| stable_identity(path))
            .collect::<Result<Vec<_>, _>>()?;
        let parent_identities = capture_file_parent_identities(&paths)?;
        let receipt = Self {
            case_id: case_id.to_string(),
            paths,
            expected_sha256: normalize_sha256(expected_sha256).ok_or_else(|| {
                AccessError::AuthorizationState(format!(
                    "invalid SHA-256 binding for case {case_id}"
                ))
            })?,
            expected_size_bytes,
            identities,
            parent_identities,
        };
        receipt.verify()?;
        Ok(receipt)
    }

    fn verify(&self) -> Result<(), AccessError> {
        for (expected_path, expected_identity) in self.paths.iter().zip(&self.identities) {
            let current_path = canonical_regular_file(expected_path)?;
            if &current_path != expected_path
                || stable_identity(expected_path)? != *expected_identity
            {
                return Err(self.integrity_mismatch());
            }
        }
        if capture_file_parent_identities(&self.paths)? != self.parent_identities {
            return Err(self.integrity_mismatch());
        }
        if let Some(expected_size) = self.expected_size_bytes {
            let actual_size = self.paths.iter().try_fold(0_u64, |total, path| {
                let metadata = fs::symlink_metadata(path).map_err(|source| AccessError::Read {
                    path: path.clone(),
                    source,
                })?;
                Ok::<u64, AccessError>(total.saturating_add(metadata.len()))
            })?;
            if actual_size != expected_size {
                return Err(self.integrity_mismatch());
            }
        }
        let actual_sha256 = sha256_files(&self.paths)?;
        if actual_sha256 != self.expected_sha256 {
            return Err(self.integrity_mismatch());
        }
        Ok(())
    }

    fn integrity_mismatch(&self) -> AccessError {
        AccessError::IntegrityMismatch {
            case_id: self.case_id.clone(),
            path: self.paths.first().cloned().unwrap_or_default(),
        }
    }
}

#[derive(Debug)]
struct DirectoryReceipt {
    canonical_root: PathBuf,
    canonical_files: Vec<PathBuf>,
    directory_identities: Vec<(PathBuf, StableIdentity)>,
    parent_identity: Option<(PathBuf, StableIdentity)>,
}

#[derive(Debug)]
struct EwfInventoryReceipt {
    case_id: String,
    first_path: PathBuf,
    canonical_segments: Vec<PathBuf>,
}

impl EwfInventoryReceipt {
    fn verify(&self) -> Result<(), AccessError> {
        let current = canonical_ewf_segments(&self.case_id, &self.first_path)?;
        if current != self.canonical_segments {
            return Err(AccessError::IntegrityMismatch {
                case_id: self.case_id.clone(),
                path: self.first_path.clone(),
            });
        }
        Ok(())
    }
}

#[derive(Debug, Default)]
pub(super) struct ToolAuthorization {
    hashes: Vec<HashReceipt>,
    directories: Vec<DirectoryReceipt>,
    ewf_inventories: Vec<EwfInventoryReceipt>,
    registration_path: Option<PathBuf>,
}

impl ToolAuthorization {
    pub(super) fn verify_after(&self) -> Result<(), AccessError> {
        for directory in &self.directories {
            let current_root = canonical_directory(&directory.canonical_root)?;
            let current_files = enumerate_directory_files(&current_root)?;
            let current_identities = capture_directory_identities(&current_root)?;
            let current_parent_identity = directory_parent_identity(&current_root)?;
            if current_root != directory.canonical_root
                || current_files != directory.canonical_files
                || current_identities != directory.directory_identities
                || current_parent_identity != directory.parent_identity
            {
                return Err(AccessError::IntegrityMismatch {
                    case_id: self
                        .hashes
                        .first()
                        .map_or_else(String::new, |receipt| receipt.case_id.clone()),
                    path: directory.canonical_root.clone(),
                });
            }
        }
        for receipt in &self.hashes {
            receipt.verify()?;
        }
        for inventory in &self.ewf_inventories {
            inventory.verify()?;
        }
        Ok(())
    }
}

/// Exhaustive policy for the registry in [`super::build_registry`].  Keep this
/// match explicit: adding a tool without choosing a policy fails the registry
/// coverage test instead of silently creating an authorization gap.
pub(super) fn tool_policy(name: &str) -> Option<ToolPolicy> {
    let policy = match name {
        "case_open" => ToolPolicy::Registration,
        "disk_extract_artifacts" | "disk_unmount" => ToolPolicy::StateOnly,
        "hashset_lookup" => ToolPolicy::ConfigOnly,
        "disk_mount" | "bulk_extract" | "vss_list" | "vss_mount" | "mac_triage" => {
            ToolPolicy::Evidence(&["image_path"])
        }
        "evtx_query" | "sysmon_network_query" => ToolPolicy::Evidence(&["evtx_path"]),
        "prefetch_parse" => ToolPolicy::Evidence(&["prefetch_path"]),
        "mft_timeline" => ToolPolicy::Evidence(&["mft_path"]),
        "registry_query" => ToolPolicy::Evidence(&["hive_path"]),
        "yara_scan" => ToolPolicy::Evidence(&["target_path"]),
        "usnjrnl_query" => ToolPolicy::Evidence(&["usnjrnl_path"]),
        "hayabusa_scan" => ToolPolicy::Evidence(&["evtx_dir"]),
        "zeek_summary" => ToolPolicy::Evidence(&["zeek_path"]),
        "pcap_triage" | "suricata_eve" => ToolPolicy::Evidence(&["pcap_path"]),
        "vol_pslist" | "vol_malfind" | "vol_psscan" | "vol_psxview" | "vol_run" => {
            ToolPolicy::Evidence(&["memory_path"])
        }
        "ez_parse" | "plaso_parse" | "oe_dbx_parse" | "email_parse" | "exif_parse"
        | "setupapi_parse" | "bits_parse" | "srum_parse" | "pst_parse" | "wmi_persist_parse" => {
            ToolPolicy::Evidence(&["artifact_path"])
        }
        "thumbcache_parse" => ToolPolicy::Evidence(&["thumbcache_path"]),
        "cloud_audit" => ToolPolicy::Evidence(&["log_path"]),
        "journalctl_query" => ToolPolicy::Evidence(&["journal_path"]),
        "login_accounting" => ToolPolicy::Evidence(&["accounting_path"]),
        "ausearch" => ToolPolicy::Evidence(&["audit_log_path"]),
        "nfdump_query" => ToolPolicy::Evidence(&["flow_path"]),
        "indx_parse" => ToolPolicy::Evidence(&["indx_path"]),
        "browser_history" => ToolPolicy::Evidence(&["history_path"]),
        _ => return None,
    };
    Some(policy)
}

pub(super) fn authorize_tool_call(
    tool_name: &str,
    arguments: &mut Value,
) -> Result<ToolAuthorization, AccessError> {
    reject_product_mock_mode(tool_name, arguments)?;
    reject_caller_mount_point(tool_name, arguments)?;
    let policy = tool_policy(tool_name).ok_or_else(|| {
        AccessError::AuthorizationState(format!(
            "tool {tool_name} has no evidence authorization policy"
        ))
    })?;
    if policy == ToolPolicy::Registration {
        return authorize_case_open(arguments);
    }
    let ToolPolicy::Evidence(path_fields) = policy else {
        return Ok(ToolAuthorization::default());
    };

    let object = arguments.as_object_mut().ok_or_else(|| {
        AccessError::InvalidInput("tools/call arguments must be a JSON object".to_string())
    })?;
    let case_id = object
        .get("case_id")
        .and_then(Value::as_str)
        .ok_or_else(|| AccessError::InvalidInput("missing string case_id".to_string()))?
        .to_string();
    if !is_valid_case_id(&case_id) {
        return Err(AccessError::InvalidInput(format!(
            "invalid case_id: {case_id}"
        )));
    }
    let sources = AuthorizationSources::load(&case_id)?;
    let mut authorization = ToolAuthorization::default();
    for field in path_fields {
        let requested_path = object.get(*field).and_then(Value::as_str).ok_or_else(|| {
            AccessError::InvalidInput(format!("missing string evidence path field {field}"))
        })?;
        let authorized = sources.authorize_path(Path::new(requested_path))?;
        object.insert(
            (*field).to_string(),
            Value::String(authorized.canonical_path.to_string_lossy().into_owned()),
        );
        authorization.hashes.extend(authorized.hashes);
        if let Some(directory) = authorized.directory {
            authorization.directories.push(directory);
        }
        if let Some(inventory) = authorized.ewf_inventory {
            authorization.ewf_inventories.push(inventory);
        }
    }
    if tool_name == "yara_scan" {
        let authorized = authorize_yara_rules_path(&case_id, object)?;
        object.insert(
            "rules_path".to_string(),
            Value::String(authorized.canonical_path.to_string_lossy().into_owned()),
        );
        authorization.hashes.extend(authorized.hashes);
        if let Some(directory) = authorized.directory {
            authorization.directories.push(directory);
        }
    }
    if tool_name == "bulk_extract" {
        if let Some((canonical_path, receipt)) = authorize_bulk_keyword_file(&case_id, object)? {
            object.insert(
                "keyword_file".to_string(),
                Value::String(canonical_path.to_string_lossy().into_owned()),
            );
            authorization.hashes.push(receipt);
        }
    }
    if tool_name == "hayabusa_scan" {
        if let Some(authorized) = authorize_hayabusa_rule_set(&case_id, object)? {
            object.insert(
                "rule_set".to_string(),
                Value::String(authorized.canonical_path.to_string_lossy().into_owned()),
            );
            authorization.hashes.extend(authorized.hashes);
            if let Some(directory) = authorized.directory {
                authorization.directories.push(directory);
            }
        }
    }
    Ok(authorization)
}

fn authorize_hayabusa_rule_set(
    case_id: &str,
    arguments: &serde_json::Map<String, Value>,
) -> Result<Option<AuthorizedPath>, AccessError> {
    let Some(requested) = arguments.get("rule_set").filter(|value| !value.is_null()) else {
        return Ok(None);
    };
    let requested = requested.as_str().ok_or_else(|| {
        AccessError::InvalidInput("rule_set must be a string or null".to_string())
    })?;
    let mut approved = Vec::new();
    if let Some(value) =
        std::env::var_os("FINDEVIL_HAYABUSA_RULE_SET").filter(|value| !value.is_empty())
    {
        approved.push(PathBuf::from(value));
    }
    if let Some(value) = std::env::var_os("HAYABUSA_RULES_BASE").filter(|value| !value.is_empty()) {
        approved.push(PathBuf::from(value).join("rules"));
    }
    if approved.is_empty() {
        return Err(AccessError::NotAuthorized {
            case_id: case_id.to_string(),
            path: PathBuf::from(requested),
        });
    }
    let metadata = fs::symlink_metadata(requested).map_err(|source| AccessError::Read {
        path: PathBuf::from(requested),
        source,
    })?;
    let canonical_requested = if metadata.is_file() {
        canonical_regular_file(Path::new(requested))?
    } else if metadata.is_dir() {
        canonical_directory(Path::new(requested))?
    } else {
        return Err(AccessError::InvalidInput(
            "rule_set must be a regular file or directory".to_string(),
        ));
    };
    let mut canonical_approved = Vec::new();
    for path in approved {
        let metadata = fs::symlink_metadata(&path).map_err(|source| AccessError::Read {
            path: path.clone(),
            source,
        })?;
        if metadata.is_file() {
            canonical_approved.push(canonical_regular_file(&path)?);
        } else if metadata.is_dir() {
            canonical_approved.push(canonical_directory(&path)?);
        } else {
            return Err(AccessError::AuthorizationState(
                "approved Hayabusa rule path is not a regular file or directory".to_string(),
            ));
        }
    }
    if !canonical_approved.iter().any(|path| {
        canonical_requested == *path || (path.is_dir() && canonical_requested.starts_with(path))
    }) {
        return Err(AccessError::NotAuthorized {
            case_id: case_id.to_string(),
            path: canonical_requested,
        });
    }
    if metadata.is_file() {
        let sha256 = sha256_files(std::slice::from_ref(&canonical_requested))?;
        return Ok(Some(AuthorizedPath {
            canonical_path: canonical_requested.clone(),
            hashes: vec![HashReceipt::authorize(
                case_id,
                vec![canonical_requested],
                &sha256,
                None,
            )?],
            directory: None,
            ewf_inventory: None,
        }));
    }
    let canonical_files = enumerate_directory_files(&canonical_requested)?;
    if canonical_files.is_empty() {
        return Err(AccessError::InvalidInput(
            "approved Hayabusa rule directory is empty".to_string(),
        ));
    }
    let hashes = canonical_files
        .iter()
        .map(|path| {
            let sha256 = sha256_files(std::slice::from_ref(path))?;
            HashReceipt::authorize(case_id, vec![path.clone()], &sha256, None)
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Some(AuthorizedPath {
        canonical_path: canonical_requested.clone(),
        hashes,
        directory: Some(DirectoryReceipt {
            directory_identities: capture_directory_identities(&canonical_requested)?,
            parent_identity: directory_parent_identity(&canonical_requested)?,
            canonical_root: canonical_requested,
            canonical_files,
        }),
        ewf_inventory: None,
    }))
}

pub(super) fn authorize_session_tool_call(
    session: &EvidenceSession,
    tool_name: &str,
    arguments: &mut Value,
) -> Result<ToolAuthorization, AccessError> {
    session.require_privacy_authorized()?;
    session.require_active(tool_name, arguments)?;
    session.require_registration_available(tool_name, arguments)?;
    authorize_tool_call(tool_name, arguments)
}

fn authorize_bulk_keyword_file(
    case_id: &str,
    arguments: &serde_json::Map<String, Value>,
) -> Result<Option<(PathBuf, HashReceipt)>, AccessError> {
    let requested = arguments
        .get("keyword_file")
        .filter(|value| !value.is_null());
    let approved = std::env::var_os("FINDEVIL_BULK_KEYWORD_FILE").filter(|value| !value.is_empty());
    if requested.is_none() && approved.is_none() {
        return Ok(None);
    }
    let approved = approved.ok_or_else(|| AccessError::NotAuthorized {
        case_id: case_id.to_string(),
        path: requested
            .and_then(Value::as_str)
            .map_or_else(|| PathBuf::from("<keyword file>"), PathBuf::from),
    })?;
    let canonical_approved = canonical_regular_file(Path::new(&approved))?;
    let canonical_requested = if let Some(value) = requested {
        let path = value.as_str().ok_or_else(|| {
            AccessError::InvalidInput("keyword_file must be a string or null".to_string())
        })?;
        canonical_regular_file(Path::new(path))?
    } else {
        canonical_approved.clone()
    };
    if canonical_requested != canonical_approved {
        return Err(AccessError::NotAuthorized {
            case_id: case_id.to_string(),
            path: canonical_requested,
        });
    }
    let sha256 = sha256_files(std::slice::from_ref(&canonical_requested))?;
    let receipt =
        HashReceipt::authorize(case_id, vec![canonical_requested.clone()], &sha256, None)?;
    Ok(Some((canonical_requested, receipt)))
}

fn authorize_yara_rules_path(
    case_id: &str,
    arguments: &serde_json::Map<String, Value>,
) -> Result<AuthorizedPath, AccessError> {
    let requested = arguments
        .get("rules_path")
        .and_then(Value::as_str)
        .ok_or_else(|| AccessError::InvalidInput("missing string rules_path".to_string()))?;
    let approved = approved_yara_paths()?;
    if approved.is_empty() {
        return Err(AccessError::NotAuthorized {
            case_id: case_id.to_string(),
            path: PathBuf::from(requested),
        });
    }
    let metadata = fs::symlink_metadata(requested).map_err(|source| AccessError::Read {
        path: PathBuf::from(requested),
        source,
    })?;
    let canonical_path = if metadata.is_file() {
        let path = canonical_regular_file(Path::new(requested))?;
        if !is_yara_rule_file(&path) {
            return Err(AccessError::InvalidInput(
                "rules_path file must end in .yar, .yara, or .yarx".to_string(),
            ));
        }
        path
    } else if metadata.is_dir() {
        canonical_directory(Path::new(requested))?
    } else {
        return Err(AccessError::InvalidInput(
            "rules_path must be a regular file or directory".to_string(),
        ));
    };
    let allowed = approved.iter().any(|entry| match entry {
        ApprovedYaraPath::File(path) => canonical_path == *path,
        ApprovedYaraPath::Directory(path) => canonical_path.starts_with(path),
    });
    if !allowed {
        return Err(AccessError::NotAuthorized {
            case_id: case_id.to_string(),
            path: canonical_path,
        });
    }
    if metadata.is_file() {
        let sha256 = sha256_files(std::slice::from_ref(&canonical_path))?;
        return Ok(AuthorizedPath {
            canonical_path: canonical_path.clone(),
            hashes: vec![HashReceipt::authorize(
                case_id,
                vec![canonical_path],
                &sha256,
                None,
            )?],
            directory: None,
            ewf_inventory: None,
        });
    }
    let canonical_files = enumerate_directory_files(&canonical_path)?;
    let rule_files = canonical_files
        .iter()
        .filter(|path| is_yara_rule_file(path))
        .cloned()
        .collect::<Vec<_>>();
    if rule_files.is_empty() {
        return Err(AccessError::InvalidInput(
            "approved rules directory contains no YARA rule files".to_string(),
        ));
    }
    let hashes = rule_files
        .iter()
        .map(|path| {
            let sha256 = sha256_files(std::slice::from_ref(path))?;
            HashReceipt::authorize(case_id, vec![path.clone()], &sha256, None)
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(AuthorizedPath {
        canonical_path: canonical_path.clone(),
        hashes,
        directory: Some(DirectoryReceipt {
            directory_identities: capture_directory_identities(&canonical_path)?,
            parent_identity: directory_parent_identity(&canonical_path)?,
            canonical_root: canonical_path,
            // The handler enumerates all entries while selecting rule suffixes;
            // retain the whole inventory so a concurrent file swap is visible.
            canonical_files,
        }),
        ewf_inventory: None,
    })
}

enum ApprovedYaraPath {
    File(PathBuf),
    Directory(PathBuf),
}

fn approved_yara_paths() -> Result<Vec<ApprovedYaraPath>, AccessError> {
    let mut approved = Vec::new();
    for name in YARA_RULE_ENV_NAMES {
        let Some(raw) = std::env::var_os(name).filter(|value| !value.is_empty()) else {
            continue;
        };
        let path = PathBuf::from(raw);
        let metadata = fs::symlink_metadata(&path).map_err(|source| AccessError::Read {
            path: path.clone(),
            source,
        })?;
        if metadata.is_file() {
            approved.push(ApprovedYaraPath::File(canonical_regular_file(&path)?));
        } else if metadata.is_dir() {
            approved.push(ApprovedYaraPath::Directory(canonical_directory(&path)?));
        } else {
            return Err(AccessError::AuthorizationState(format!(
                "{name} is not a regular file or directory"
            )));
        }
    }
    Ok(approved)
}

fn is_yara_rule_file(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| {
            matches!(
                extension.to_ascii_lowercase().as_str(),
                "yar" | "yara" | "yarx"
            )
        })
}

fn authorize_case_open(arguments: &mut Value) -> Result<ToolAuthorization, AccessError> {
    let object = arguments.as_object_mut().ok_or_else(|| {
        AccessError::InvalidInput("tools/call arguments must be a JSON object".to_string())
    })?;
    let label = match object.get("label") {
        None | Some(Value::Null) => None,
        Some(Value::String(label)) => Some(label.as_str()),
        Some(_) => {
            return Err(AccessError::InvalidInput(
                "case_open label must be a string or null".to_string(),
            ))
        }
    };
    crate::tools::case_open::validate_case_label(label)
        .map_err(|error| AccessError::InvalidInput(error.to_string()))?;
    let bindings = load_case_open_bindings()?;
    if bindings.is_empty() {
        return Err(AccessError::NotAuthorized {
            case_id: "pre-registration".to_string(),
            path: PathBuf::from("<unreserved source>"),
        });
    }
    let requested_path = object
        .get("image_path")
        .and_then(Value::as_str)
        .ok_or_else(|| AccessError::InvalidInput("missing string image_path".to_string()))?;
    let expected_sha256 = object
        .get("expected_sha256")
        .and_then(Value::as_str)
        .and_then(normalize_sha256)
        .ok_or_else(|| {
            AccessError::InvalidInput(
                "case_open requires launcher-reserved expected_sha256".to_string(),
            )
        })?;
    let canonical_path = canonical_regular_file(Path::new(requested_path))?;
    let canonical_segments = canonical_ewf_segments("pre-registration", &canonical_path)?;
    let actual_sha256 = sha256_files(&canonical_segments)?;
    if actual_sha256 != expected_sha256 {
        return Err(AccessError::IntegrityMismatch {
            case_id: "pre-registration".to_string(),
            path: canonical_path,
        });
    }
    let hashes = canonical_segments
        .iter()
        .map(|path| {
            let sha256 = bindings
                .get(path)
                .ok_or_else(|| AccessError::NotAuthorized {
                    case_id: "pre-registration".to_string(),
                    path: path.clone(),
                })?;
            HashReceipt::authorize("pre-registration", vec![path.clone()], sha256, None)
        })
        .collect::<Result<Vec<_>, _>>()?;
    object.insert(
        "image_path".to_string(),
        Value::String(canonical_path.to_string_lossy().into_owned()),
    );
    object.insert(
        "expected_sha256".to_string(),
        Value::String(expected_sha256),
    );
    Ok(ToolAuthorization {
        hashes,
        directories: Vec::new(),
        ewf_inventories: is_first_ewf_segment(&canonical_path)
            .then(|| EwfInventoryReceipt {
                case_id: "pre-registration".to_string(),
                first_path: canonical_path.clone(),
                canonical_segments,
            })
            .into_iter()
            .collect(),
        registration_path: Some(canonical_path),
    })
}

fn reject_product_mock_mode(tool_name: &str, arguments: &Value) -> Result<(), AccessError> {
    if matches!(tool_name, "disk_mount" | "disk_unmount")
        && arguments.get("mode").and_then(Value::as_str) == Some("mock")
    {
        return Err(AccessError::InvalidInput(
            "disk mode=mock is test-only and is unavailable through the MCP server".to_string(),
        ));
    }
    Ok(())
}

fn reject_caller_mount_point(tool_name: &str, arguments: &Value) -> Result<(), AccessError> {
    if matches!(tool_name, "disk_mount" | "vss_mount")
        && arguments
            .get("mount_point")
            .is_some_and(|value| !value.is_null())
    {
        return Err(AccessError::InvalidInput(format!(
            "{tool_name} mount_point is server-managed and must be omitted"
        )));
    }
    Ok(())
}

struct AuthorizedPath {
    canonical_path: PathBuf,
    hashes: Vec<HashReceipt>,
    directory: Option<DirectoryReceipt>,
    ewf_inventory: Option<EwfInventoryReceipt>,
}

#[derive(Default)]
struct AuthorizationSources {
    case_id: String,
    registered: Option<RegisteredSource>,
    launcher: BTreeMap<PathBuf, String>,
    derived: BTreeMap<PathBuf, String>,
}

impl AuthorizationSources {
    fn load(case_id: &str) -> Result<Self, AccessError> {
        Ok(Self {
            case_id: case_id.to_string(),
            registered: load_registered_source(case_id)?,
            launcher: load_launcher_bindings(case_id)?,
            derived: load_derived_bindings(case_id)?,
        })
    }

    fn authorize_path(&self, requested_path: &Path) -> Result<AuthorizedPath, AccessError> {
        let metadata =
            fs::symlink_metadata(requested_path).map_err(|source| AccessError::Read {
                path: requested_path.to_path_buf(),
                source,
            })?;
        if metadata.file_type().is_symlink() {
            return Err(AccessError::InvalidInput(format!(
                "evidence paths may not be symlinks: {}",
                requested_path.display()
            )));
        }
        if metadata.is_file() {
            let canonical_path = canonical_regular_file(requested_path)?;
            let canonical_segments = canonical_ewf_segments(&self.case_id, &canonical_path)?;
            let hashes =
                if let Some(registered_paths) = self.registered_paths_for(&canonical_path)? {
                    if canonical_segments != registered_paths {
                        return Err(AccessError::IntegrityMismatch {
                            case_id: self.case_id.clone(),
                            path: canonical_path,
                        });
                    }
                    vec![self.authorize_file(&canonical_path)?]
                } else {
                    canonical_segments
                        .iter()
                        .map(|path| self.authorize_file(path))
                        .collect::<Result<Vec<_>, _>>()?
                };
            let ewf_inventory =
                is_first_ewf_segment(&canonical_path).then(|| EwfInventoryReceipt {
                    case_id: self.case_id.clone(),
                    first_path: canonical_path.clone(),
                    canonical_segments,
                });
            return Ok(AuthorizedPath {
                canonical_path,
                hashes,
                directory: None,
                ewf_inventory,
            });
        }
        if metadata.is_dir() {
            let canonical_path = canonical_directory(requested_path)?;
            let canonical_files = enumerate_directory_files(&canonical_path)?;
            if canonical_files.is_empty() {
                return Err(AccessError::NotAuthorized {
                    case_id: self.case_id.clone(),
                    path: canonical_path,
                });
            }
            let hashes = canonical_files
                .iter()
                .map(|path| self.authorize_file(path))
                .collect::<Result<Vec<_>, _>>()?;
            return Ok(AuthorizedPath {
                canonical_path: canonical_path.clone(),
                hashes,
                directory: Some(DirectoryReceipt {
                    directory_identities: capture_directory_identities(&canonical_path)?,
                    parent_identity: directory_parent_identity(&canonical_path)?,
                    canonical_root: canonical_path,
                    canonical_files,
                }),
                ewf_inventory: None,
            });
        }
        Err(AccessError::InvalidInput(format!(
            "evidence path is not a regular file or directory: {}",
            requested_path.display()
        )))
    }

    fn authorize_file(&self, canonical_path: &Path) -> Result<HashReceipt, AccessError> {
        if let Some(paths) = self.registered_paths_for(canonical_path)? {
            let source = self.registered.as_ref().ok_or_else(|| {
                AccessError::AuthorizationState("registered source disappeared".to_string())
            })?;
            return HashReceipt::authorize(
                &self.case_id,
                paths,
                &source.sha256,
                Some(source.size_bytes),
            );
        }
        if let Some(sha256) = self.launcher.get(canonical_path) {
            return HashReceipt::authorize(
                &self.case_id,
                vec![canonical_path.to_path_buf()],
                sha256,
                None,
            );
        }
        if let Some(sha256) = self.derived.get(canonical_path) {
            return HashReceipt::authorize(
                &self.case_id,
                vec![canonical_path.to_path_buf()],
                sha256,
                None,
            );
        }
        Err(AccessError::NotAuthorized {
            case_id: self.case_id.clone(),
            path: canonical_path.to_path_buf(),
        })
    }

    fn registered_paths_for(
        &self,
        canonical_path: &Path,
    ) -> Result<Option<Vec<PathBuf>>, AccessError> {
        let Some(source) = &self.registered else {
            return Ok(None);
        };
        let Some(first_path) = source.paths.first() else {
            return Err(AccessError::AuthorizationState(
                "registered source has an empty path inventory".to_string(),
            ));
        };
        // A derived binding is independently sufficient. If the original
        // source is offline, do not make a valid staged artifact unreadable.
        let Ok(canonical_first) = canonical_regular_file(first_path) else {
            return Ok(None);
        };
        if canonical_first != canonical_path {
            return Ok(None);
        }
        let paths = source
            .paths
            .iter()
            .map(|path| canonical_regular_file(path))
            .collect::<Result<Vec<_>, _>>()?;
        if paths.first() != Some(&canonical_first) {
            return Err(AccessError::AuthorizationState(
                "case manifest segment inventory does not start with image_path".to_string(),
            ));
        }
        Ok(Some(paths))
    }
}

struct RegisteredSource {
    paths: Vec<PathBuf>,
    sha256: String,
    size_bytes: u64,
}

#[derive(Deserialize)]
struct CaseManifest {
    id: String,
    image_path: PathBuf,
    image_hash: String,
    image_size_bytes: u64,
    #[serde(default)]
    image_segments: Vec<PathBuf>,
}

fn load_registered_source(case_id: &str) -> Result<Option<RegisteredSource>, AccessError> {
    let Some(home) = findevil_home() else {
        return Ok(None);
    };
    let manifest_path = home.join("cases").join(case_id).join("case.json");
    let metadata = match fs::symlink_metadata(&manifest_path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(source) => {
            return Err(AccessError::Read {
                path: manifest_path,
                source,
            })
        }
    };
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(AccessError::AuthorizationState(format!(
            "case manifest is not a regular file: {}",
            manifest_path.display()
        )));
    }
    let canonical_manifest = canonical_regular_file(&manifest_path)?;
    let manifest_bytes = fs::read(&canonical_manifest).map_err(|source| AccessError::Read {
        path: canonical_manifest,
        source,
    })?;
    let manifest: CaseManifest = serde_json::from_slice(&manifest_bytes).map_err(|error| {
        AccessError::AuthorizationState(format!("cannot decode case manifest: {error}"))
    })?;
    if manifest.id != case_id {
        return Err(AccessError::AuthorizationState(
            "case manifest id does not match its directory".to_string(),
        ));
    }
    let paths = if manifest.image_segments.is_empty() {
        vec![manifest.image_path]
    } else {
        manifest.image_segments
    };
    let source = RegisteredSource {
        paths,
        sha256: normalize_sha256(&manifest.image_hash).ok_or_else(|| {
            AccessError::AuthorizationState("case manifest SHA-256 is invalid".to_string())
        })?,
        size_bytes: manifest.image_size_bytes,
    };
    Ok(Some(source))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LauncherBinding {
    case_id: String,
    artifacts: Vec<LauncherArtifact>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LauncherArtifact {
    path: PathBuf,
    sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CaseOpenBinding {
    artifacts: Vec<LauncherArtifact>,
}

fn load_case_open_bindings() -> Result<BTreeMap<PathBuf, String>, AccessError> {
    let Some(raw) = std::env::var_os(CASE_OPEN_BINDING_ENV) else {
        return Ok(BTreeMap::new());
    };
    let bytes = raw.as_encoded_bytes();
    if bytes.len() > MAX_LAUNCHER_BINDING_BYTES {
        return Err(AccessError::ResourceLimit(format!(
            "{CASE_OPEN_BINDING_ENV} exceeds {MAX_LAUNCHER_BINDING_BYTES} bytes"
        )));
    }
    let binding: CaseOpenBinding = serde_json::from_slice(bytes).map_err(|error| {
        AccessError::AuthorizationState(format!("cannot decode {CASE_OPEN_BINDING_ENV}: {error}"))
    })?;
    if binding.artifacts.len() > MAX_LAUNCHER_ARTIFACTS {
        return Err(AccessError::ResourceLimit(format!(
            "{CASE_OPEN_BINDING_ENV} contains more than {MAX_LAUNCHER_ARTIFACTS} artifacts"
        )));
    }
    let mut paths = BTreeMap::new();
    for artifact in binding.artifacts {
        let sha256 = normalize_sha256(&artifact.sha256).ok_or_else(|| {
            AccessError::AuthorizationState(format!(
                "{CASE_OPEN_BINDING_ENV} contains an invalid SHA-256"
            ))
        })?;
        let canonical_path = canonical_regular_file(&artifact.path)?;
        insert_binding(&mut paths, canonical_path, sha256, CASE_OPEN_BINDING_ENV)?;
    }
    Ok(paths)
}

fn load_launcher_bindings(case_id: &str) -> Result<BTreeMap<PathBuf, String>, AccessError> {
    let Some(raw) = std::env::var_os(LAUNCHER_BINDING_ENV) else {
        return Ok(BTreeMap::new());
    };
    let bytes = raw.as_encoded_bytes();
    if bytes.len() > MAX_LAUNCHER_BINDING_BYTES {
        return Err(AccessError::ResourceLimit(format!(
            "{LAUNCHER_BINDING_ENV} exceeds {MAX_LAUNCHER_BINDING_BYTES} bytes"
        )));
    }
    let binding: LauncherBinding = serde_json::from_slice(bytes).map_err(|error| {
        AccessError::AuthorizationState(format!("cannot decode {LAUNCHER_BINDING_ENV}: {error}"))
    })?;
    if binding.artifacts.len() > MAX_LAUNCHER_ARTIFACTS {
        return Err(AccessError::ResourceLimit(format!(
            "{LAUNCHER_BINDING_ENV} contains more than {MAX_LAUNCHER_ARTIFACTS} artifacts"
        )));
    }
    if binding.case_id != case_id {
        return Ok(BTreeMap::new());
    }
    let mut paths = BTreeMap::new();
    for artifact in binding.artifacts {
        let sha256 = normalize_sha256(&artifact.sha256).ok_or_else(|| {
            AccessError::AuthorizationState(format!(
                "{LAUNCHER_BINDING_ENV} contains an invalid SHA-256"
            ))
        })?;
        let canonical_path = canonical_regular_file(&artifact.path)?;
        insert_binding(&mut paths, canonical_path, sha256, LAUNCHER_BINDING_ENV)?;
    }
    Ok(paths)
}

#[derive(Default, Deserialize)]
struct DerivedLedger {
    #[serde(default)]
    resources: Vec<DerivedResource>,
}

#[derive(Default, Deserialize)]
struct DerivedResource {
    #[serde(default)]
    artifacts: Vec<DerivedArtifact>,
}

#[derive(Deserialize)]
struct DerivedArtifact {
    extracted_path: PathBuf,
    #[serde(default)]
    sha256: String,
}

fn load_derived_bindings(case_id: &str) -> Result<BTreeMap<PathBuf, String>, AccessError> {
    let Some(home) = findevil_home() else {
        return Ok(BTreeMap::new());
    };
    let ledger_path = home
        .join("cases")
        .join(case_id)
        .join("session_resources.json");
    let metadata = match fs::symlink_metadata(&ledger_path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(BTreeMap::new()),
        Err(source) => {
            return Err(AccessError::Read {
                path: ledger_path,
                source,
            })
        }
    };
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(AccessError::AuthorizationState(format!(
            "derived-artifact ledger is not a regular file: {}",
            ledger_path.display()
        )));
    }
    if metadata.len() > MAX_LEDGER_BYTES {
        return Err(AccessError::ResourceLimit(format!(
            "derived-artifact ledger exceeds {MAX_LEDGER_BYTES} bytes"
        )));
    }
    let canonical_ledger = canonical_regular_file(&ledger_path)?;
    let bytes = fs::read(&canonical_ledger).map_err(|source| AccessError::Read {
        path: canonical_ledger,
        source,
    })?;
    let ledger: DerivedLedger = serde_json::from_slice(&bytes).map_err(|error| {
        AccessError::AuthorizationState(format!("cannot decode derived-artifact ledger: {error}"))
    })?;
    let artifact_count = ledger
        .resources
        .iter()
        .map(|resource| resource.artifacts.len())
        .sum::<usize>();
    if artifact_count > MAX_LEDGER_ARTIFACTS {
        return Err(AccessError::ResourceLimit(format!(
            "derived-artifact ledger contains more than {MAX_LEDGER_ARTIFACTS} artifacts"
        )));
    }
    let mut paths = BTreeMap::new();
    for artifact in ledger
        .resources
        .into_iter()
        .flat_map(|resource| resource.artifacts)
    {
        let Some(sha256) = normalize_sha256(&artifact.sha256) else {
            // Historical ledgers did not record hashes. They remain readable
            // state, but they cannot authorize an evidence read.
            continue;
        };
        let canonical_path = match canonical_regular_file(&artifact.extracted_path) {
            Ok(path) => path,
            Err(AccessError::Read { source, .. })
                if source.kind() == std::io::ErrorKind::NotFound =>
            {
                continue;
            }
            Err(error) => return Err(error),
        };
        insert_binding(
            &mut paths,
            canonical_path,
            sha256,
            "derived-artifact ledger",
        )?;
    }
    Ok(paths)
}

fn insert_binding(
    bindings: &mut BTreeMap<PathBuf, String>,
    path: PathBuf,
    sha256: String,
    source_name: &str,
) -> Result<(), AccessError> {
    if let Some(existing) = bindings.get(&path) {
        if existing != &sha256 {
            return Err(AccessError::AuthorizationState(format!(
                "{source_name} binds {} to conflicting SHA-256 values",
                path.display()
            )));
        }
        return Ok(());
    }
    bindings.insert(path, sha256);
    Ok(())
}

fn canonical_regular_file(path: &Path) -> Result<PathBuf, AccessError> {
    canonical_path_of_kind(path, true)
}

fn canonical_directory(path: &Path) -> Result<PathBuf, AccessError> {
    canonical_path_of_kind(path, false)
}

fn canonical_ewf_segments(case_id: &str, first_path: &Path) -> Result<Vec<PathBuf>, AccessError> {
    segment_paths_for_image(first_path)
        .map_err(|_| AccessError::IntegrityMismatch {
            case_id: case_id.to_string(),
            path: first_path.to_path_buf(),
        })?
        .iter()
        .map(|path| canonical_regular_file(path))
        .collect()
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct StableIdentity {
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(unix)]
    links: u64,
    // Non-Unix targets expose only the portable size here. The pre/post SHA-256
    // still detects content drift, but a hostile concurrent same-bytes ABA
    // replacement cannot be proven absent without Unix dev/inode/ctime data.
    size: u64,
    #[cfg(unix)]
    modified_seconds: i64,
    #[cfg(unix)]
    modified_nanoseconds: i64,
    #[cfg(unix)]
    changed_seconds: i64,
    #[cfg(unix)]
    changed_nanoseconds: i64,
}

fn stable_identity(path: &Path) -> Result<StableIdentity, AccessError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| AccessError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        Ok(StableIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
            links: metadata.nlink(),
            size: metadata.size(),
            modified_seconds: metadata.mtime(),
            modified_nanoseconds: metadata.mtime_nsec(),
            changed_seconds: metadata.ctime(),
            changed_nanoseconds: metadata.ctime_nsec(),
        })
    }
    #[cfg(not(unix))]
    {
        Ok(StableIdentity {
            size: metadata.len(),
        })
    }
}

fn directory_parent_identity(
    root: &Path,
) -> Result<Option<(PathBuf, StableIdentity)>, AccessError> {
    root.parent()
        .map(|parent| {
            let canonical_parent = canonical_directory(parent)?;
            let identity = stable_identity(&canonical_parent)?;
            Ok((canonical_parent, identity))
        })
        .transpose()
}

fn capture_file_parent_identities(
    paths: &[PathBuf],
) -> Result<Vec<(PathBuf, StableIdentity)>, AccessError> {
    let mut parents = BTreeMap::new();
    for path in paths {
        let parent = path.parent().ok_or_else(|| {
            AccessError::InvalidInput(format!(
                "evidence file has no parent directory: {}",
                path.display()
            ))
        })?;
        let canonical_parent = canonical_directory(parent)?;
        parents
            .entry(canonical_parent.clone())
            .or_insert(stable_identity(&canonical_parent)?);
    }
    Ok(parents.into_iter().collect())
}

fn capture_directory_identities(
    root: &Path,
) -> Result<Vec<(PathBuf, StableIdentity)>, AccessError> {
    let mut pending = vec![(root.to_path_buf(), 0_usize)];
    let mut directories = Vec::new();
    let mut entries_seen = 0_usize;
    while let Some((directory, depth)) = pending.pop() {
        if depth > MAX_DIRECTORY_DEPTH {
            return Err(AccessError::ResourceLimit(format!(
                "directory depth exceeds {MAX_DIRECTORY_DEPTH}: {}",
                root.display()
            )));
        }
        directories.push((directory.clone(), stable_identity(&directory)?));
        for entry in fs::read_dir(&directory).map_err(|source| AccessError::Read {
            path: directory.clone(),
            source,
        })? {
            let entry = entry.map_err(|source| AccessError::Read {
                path: directory.clone(),
                source,
            })?;
            entries_seen = entries_seen.saturating_add(1);
            if entries_seen > MAX_DIRECTORY_ENTRIES {
                return Err(AccessError::ResourceLimit(format!(
                    "directory contains more than {MAX_DIRECTORY_ENTRIES} entries: {}",
                    root.display()
                )));
            }
            let path = entry.path();
            let file_type = entry.file_type().map_err(|source| AccessError::Read {
                path: path.clone(),
                source,
            })?;
            if file_type.is_symlink() {
                return Err(AccessError::InvalidInput(format!(
                    "evidence directory contains a symlink: {}",
                    path.display()
                )));
            }
            if file_type.is_dir() {
                pending.push((canonical_directory(&path)?, depth + 1));
            }
        }
    }
    directories.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(directories)
}

fn canonical_path_of_kind(path: &Path, expect_file: bool) -> Result<PathBuf, AccessError> {
    reject_symlink_components(path)?;
    let metadata = fs::symlink_metadata(path).map_err(|source| AccessError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    #[cfg(unix)]
    let has_one_link = if expect_file {
        use std::os::unix::fs::MetadataExt as _;
        metadata.nlink() == 1
    } else {
        true
    };
    #[cfg(not(unix))]
    let has_one_link = true;
    let correct_kind = if expect_file {
        metadata.is_file() && has_one_link
    } else {
        metadata.is_dir()
    };
    if !correct_kind || metadata.file_type().is_symlink() {
        return Err(AccessError::InvalidInput(format!(
            "evidence path has the wrong file type: {}",
            path.display()
        )));
    }
    crate::pathnorm::canonicalize(path).map_err(|source| AccessError::Read {
        path: path.to_path_buf(),
        source,
    })
}

fn reject_symlink_components(path: &Path) -> Result<(), AccessError> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|source| AccessError::Read {
                path: path.to_path_buf(),
                source,
            })?
            .join(path)
    };
    let mut current = PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::Prefix(prefix) => current.push(prefix.as_os_str()),
            Component::RootDir => current.push(component.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                return Err(AccessError::InvalidInput(format!(
                    "evidence paths may not contain '..': {}",
                    path.display()
                )))
            }
            Component::Normal(part) => {
                current.push(part);
                let metadata =
                    fs::symlink_metadata(&current).map_err(|source| AccessError::Read {
                        path: current.clone(),
                        source,
                    })?;
                if metadata.file_type().is_symlink() {
                    return Err(AccessError::InvalidInput(format!(
                        "evidence paths may not traverse symlinks: {}",
                        path.display()
                    )));
                }
            }
        }
    }
    Ok(())
}

fn enumerate_directory_files(root: &Path) -> Result<Vec<PathBuf>, AccessError> {
    let mut pending = vec![(root.to_path_buf(), 0_usize)];
    let mut files = Vec::new();
    let mut entries_seen = 0_usize;
    while let Some((directory, depth)) = pending.pop() {
        if depth > MAX_DIRECTORY_DEPTH {
            return Err(AccessError::ResourceLimit(format!(
                "directory depth exceeds {MAX_DIRECTORY_DEPTH}: {}",
                root.display()
            )));
        }
        let entries = fs::read_dir(&directory).map_err(|source| AccessError::Read {
            path: directory.clone(),
            source,
        })?;
        for entry in entries {
            let entry = entry.map_err(|source| AccessError::Read {
                path: directory.clone(),
                source,
            })?;
            entries_seen = entries_seen.saturating_add(1);
            if entries_seen > MAX_DIRECTORY_ENTRIES {
                return Err(AccessError::ResourceLimit(format!(
                    "directory contains more than {MAX_DIRECTORY_ENTRIES} entries: {}",
                    root.display()
                )));
            }
            let path = entry.path();
            let file_type = entry.file_type().map_err(|source| AccessError::Read {
                path: path.clone(),
                source,
            })?;
            if file_type.is_symlink() {
                return Err(AccessError::InvalidInput(format!(
                    "evidence directory contains a symlink: {}",
                    path.display()
                )));
            }
            if file_type.is_dir() {
                pending.push((canonical_directory(&path)?, depth + 1));
            } else if file_type.is_file() {
                files.push(canonical_regular_file(&path)?);
                if files.len() > MAX_DIRECTORY_FILES {
                    return Err(AccessError::ResourceLimit(format!(
                        "directory contains more than {MAX_DIRECTORY_FILES} files: {}",
                        root.display()
                    )));
                }
            } else {
                return Err(AccessError::InvalidInput(format!(
                    "evidence directory contains a non-regular entry: {}",
                    path.display()
                )));
            }
        }
    }
    files.sort();
    Ok(files)
}

fn sha256_files(paths: &[PathBuf]) -> Result<String, AccessError> {
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; HASH_BUFFER_BYTES];
    for path in paths {
        let file = File::open(path).map_err(|source| AccessError::Read {
            path: path.clone(),
            source,
        })?;
        let mut reader = BufReader::with_capacity(HASH_BUFFER_BYTES, file);
        loop {
            let count = reader
                .read(&mut buffer)
                .map_err(|source| AccessError::Read {
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

fn normalize_sha256(value: &str) -> Option<String> {
    (value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .then(|| value.to_ascii_lowercase())
}

fn findevil_home() -> Option<PathBuf> {
    if let Some(value) = std::env::var_os("FINDEVIL_HOME").filter(|value| !value.is_empty()) {
        return Some(PathBuf::from(value));
    }
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .filter(|value| !value.is_empty())
        .map(|value| PathBuf::from(value).join(".findevil"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    struct RestoreEnv {
        key: &'static str,
        previous: Option<std::ffi::OsString>,
    }

    impl RestoreEnv {
        fn set(key: &'static str, value: impl AsRef<std::ffi::OsStr>) -> Self {
            let previous = std::env::var_os(key);
            std::env::set_var(key, value);
            Self { key, previous }
        }

        fn remove(key: &'static str) -> Self {
            let previous = std::env::var_os(key);
            std::env::remove_var(key);
            Self { key, previous }
        }
    }

    impl Drop for RestoreEnv {
        fn drop(&mut self) {
            if let Some(value) = &self.previous {
                std::env::set_var(self.key, value);
            } else {
                std::env::remove_var(self.key);
            }
        }
    }

    fn digest(path: &Path) -> String {
        sha256_files(&[path.to_path_buf()]).expect("fixture digest")
    }

    fn launcher_binding(case_id: &str, paths: &[&Path]) -> String {
        serde_json::to_string(&json!({
            "case_id": case_id,
            "artifacts": paths.iter().map(|path| json!({
                "path": path,
                "sha256": digest(path),
            })).collect::<Vec<_>>()
        }))
        .expect("serialize binding")
    }

    #[test]
    fn representative_evidence_tools_have_static_path_fields() {
        assert_eq!(
            tool_policy("evtx_query"),
            Some(ToolPolicy::Evidence(&["evtx_path"]))
        );
        assert_eq!(
            tool_policy("vol_pslist"),
            Some(ToolPolicy::Evidence(&["memory_path"]))
        );
        assert_eq!(tool_policy("hashset_lookup"), Some(ToolPolicy::ConfigOnly));
        assert_eq!(tool_policy("vel_collect"), None);
    }

    #[test]
    fn parsed_evidence_route_matrix_is_exact_and_unknown_routes_fail_closed() {
        for route in ["local_controller", "local_dgx"] {
            assert!(privacy_route_values_authorized(Some(route), None));
        }
        assert!(privacy_route_values_authorized(None, Some("1")));
        for route in ["local", "unknown", "LOCAL_CONTROLLER", ""] {
            assert!(!privacy_route_values_authorized(Some(route), None));
        }
        for acknowledgment in ["true", "yes", "0", ""] {
            assert!(!privacy_route_values_authorized(None, Some(acknowledgment)));
        }
        assert!(!privacy_route_values_authorized(None, None));
    }

    #[test]
    fn case_open_requires_an_exact_launcher_reservation() {
        let _env_guard = crate::env_lock();
        let tmp = crate::server::test_support::CanonicalTempDir::new();
        let evidence = tmp.path().join("source.dd");
        fs::write(&evidence, b"reserved source").expect("source");
        let expected = digest(&evidence);
        let _reservation = RestoreEnv::remove(CASE_OPEN_BINDING_ENV);
        let mut arbitrary = json!({
            "image_path": "/etc/passwd",
            "expected_sha256": "0".repeat(64),
        });
        assert!(matches!(
            authorize_tool_call("case_open", &mut arbitrary),
            Err(AccessError::NotAuthorized { .. })
        ));

        let reservation = serde_json::to_string(&json!({
            "artifacts": [{"path": evidence, "sha256": expected}],
        }))
        .expect("reservation");
        std::env::set_var(CASE_OPEN_BINDING_ENV, reservation);
        let mut args = json!({"image_path": evidence, "expected_sha256": expected});
        let authorization = authorize_tool_call("case_open", &mut args).expect("reserved source");
        authorization.verify_after().expect("stable source");

        let mut wrong_hash = json!({
            "image_path": evidence,
            "expected_sha256": "0".repeat(64),
        });
        assert!(matches!(
            authorize_tool_call("case_open", &mut wrong_hash),
            Err(AccessError::IntegrityMismatch { .. })
        ));
    }

    #[test]
    fn case_open_rejects_oversized_label_before_loading_evidence_bindings() {
        let _env_guard = crate::env_lock();
        let _binding = RestoreEnv::remove(CASE_OPEN_BINDING_ENV);
        let tmp = crate::server::test_support::CanonicalTempDir::new();
        let mut args = json!({
            "image_path": tmp.path().join("missing-evidence.dd"),
            "expected_sha256": "0".repeat(64),
            "label": "é".repeat(130),
        });

        assert!(matches!(
            authorize_tool_call("case_open", &mut args),
            Err(AccessError::InvalidInput(message))
                if message.contains("label") && message.contains("256")
        ));
    }

    #[test]
    fn launcher_binding_authorizes_evtx_and_memory_and_detects_mutation() {
        let _env_guard = crate::env_lock();
        let tmp = crate::server::test_support::CanonicalTempDir::new();
        let evtx = tmp.path().join("Security.evtx");
        let memory = tmp.path().join("memory.raw");
        fs::write(&evtx, b"evtx-a").expect("write evtx");
        fs::write(&memory, b"memory-a").expect("write memory");
        let binding = launcher_binding("inventory-case", &[&evtx, &memory]);
        let _binding = RestoreEnv::set(LAUNCHER_BINDING_ENV, binding);
        let _home = RestoreEnv::set("FINDEVIL_HOME", tmp.path().join("empty-home"));

        for (tool, field, path) in [
            ("evtx_query", "evtx_path", &evtx),
            ("vol_pslist", "memory_path", &memory),
        ] {
            let mut args = json!({"case_id": "inventory-case", field: path});
            let authorization = authorize_tool_call(tool, &mut args).expect("authorized");
            authorization.verify_after().expect("stable evidence");
        }

        let mut args = json!({"case_id": "inventory-case", "evtx_path": evtx});
        let authorization = authorize_tool_call("evtx_query", &mut args).expect("authorized");
        fs::write(&evtx, b"evtx-b").expect("mutate evtx");
        assert!(matches!(
            authorization.verify_after(),
            Err(AccessError::IntegrityMismatch { .. })
        ));
    }

    #[test]
    fn wrong_case_and_unbound_path_fail_closed() {
        let _env_guard = crate::env_lock();
        let tmp = crate::server::test_support::CanonicalTempDir::new();
        let bound = tmp.path().join("bound.evtx");
        let unbound = tmp.path().join("unbound.evtx");
        fs::write(&bound, b"bound").expect("write bound");
        fs::write(&unbound, b"unbound").expect("write unbound");
        let _binding = RestoreEnv::set(
            LAUNCHER_BINDING_ENV,
            launcher_binding("right-case", &[&bound]),
        );
        let _home = RestoreEnv::set("FINDEVIL_HOME", tmp.path().join("empty-home"));

        for args in [
            json!({"case_id": "wrong-case", "evtx_path": bound}),
            json!({"case_id": "right-case", "evtx_path": unbound}),
        ] {
            let mut args = args;
            assert!(matches!(
                authorize_tool_call("evtx_query", &mut args),
                Err(AccessError::NotAuthorized { .. })
            ));
        }
    }

    #[test]
    fn derived_ledger_requires_hash_and_rechecks_it_after_read() {
        let _env_guard = crate::env_lock();
        let tmp = crate::server::test_support::CanonicalTempDir::new();
        let home = tmp.path().join("home");
        let case_dir = home.join("cases").join("derived-case");
        fs::create_dir_all(&case_dir).expect("case dir");
        let artifact = case_dir.join("extracted").join("sample.pf");
        fs::create_dir_all(artifact.parent().expect("artifact parent")).expect("artifact dir");
        fs::write(&artifact, b"derived-a").expect("write artifact");
        fs::write(
            case_dir.join("session_resources.json"),
            serde_json::to_vec(&json!({
                "resources": [{
                    "artifacts": [{
                        "extracted_path": artifact,
                    }]
                }]
            }))
            .expect("ledger json"),
        )
        .expect("write ledger");
        let _home = RestoreEnv::set("FINDEVIL_HOME", &home);
        let _binding = RestoreEnv::remove(LAUNCHER_BINDING_ENV);

        let mut args = json!({"case_id": "derived-case", "prefetch_path": artifact});
        assert!(matches!(
            authorize_tool_call("prefetch_parse", &mut args),
            Err(AccessError::NotAuthorized { .. })
        ));
        fs::write(
            case_dir.join("session_resources.json"),
            serde_json::to_vec(&json!({
                "resources": [{
                    "artifacts": [{
                        "extracted_path": artifact,
                        "sha256": digest(&artifact),
                    }]
                }]
            }))
            .expect("hash-bound ledger json"),
        )
        .expect("write hash-bound ledger");
        let authorization =
            authorize_tool_call("prefetch_parse", &mut args).expect("ledger authorized");
        fs::write(&artifact, b"derived-b").expect("mutate artifact");
        assert!(matches!(
            authorization.verify_after(),
            Err(AccessError::IntegrityMismatch { .. })
        ));
    }

    #[test]
    fn hashset_config_is_exempt_but_yara_rules_are_operator_bound() {
        let _env_guard = crate::env_lock();
        let tmp = crate::server::test_support::CanonicalTempDir::new();
        let target = tmp.path().join("target.bin");
        fs::write(&target, b"target").expect("write target");
        let _binding = RestoreEnv::set(
            LAUNCHER_BINDING_ENV,
            launcher_binding("yara-case", &[&target]),
        );
        let _home = RestoreEnv::set("FINDEVIL_HOME", tmp.path().join("empty-home"));
        let approved_rules = tmp.path().join("operator-rules.yar");
        fs::write(&approved_rules, "rule approved { condition: true }").expect("rules");
        let _rules = RestoreEnv::set("FINDEVIL_YARA_RULES_ROOT", &approved_rules);
        let mut args = json!({
            "case_id": "yara-case",
            "target_path": target,
            "rules_path": approved_rules,
        });
        authorize_tool_call("yara_scan", &mut args).expect("operator-bound rules path");

        let mut hashset_args = json!({
            "case_id": "any-case",
            "hashes": ["0".repeat(64)],
        });
        authorize_tool_call("hashset_lookup", &mut hashset_args)
            .expect("hashset_lookup only reads operator configuration");
    }

    #[test]
    fn directory_requires_every_file_to_be_hash_bound() {
        let _env_guard = crate::env_lock();
        let tmp = crate::server::test_support::CanonicalTempDir::new();
        let directory = tmp.path().join("evtx");
        fs::create_dir(&directory).expect("directory");
        let first = directory.join("one.evtx");
        let second = directory.join("two.evtx");
        fs::write(&first, b"one").expect("first");
        fs::write(&second, b"two").expect("second");
        let _home = RestoreEnv::set("FINDEVIL_HOME", tmp.path().join("empty-home"));
        let _binding = RestoreEnv::set(
            LAUNCHER_BINDING_ENV,
            launcher_binding("directory-case", &[&first]),
        );
        let mut args = json!({"case_id": "directory-case", "evtx_dir": directory});
        assert!(matches!(
            authorize_tool_call("hayabusa_scan", &mut args),
            Err(AccessError::NotAuthorized { path, .. }) if path == crate::pathnorm::canonicalize(&second).unwrap()
        ));
    }

    #[test]
    fn launcher_binding_caps_size_inventory_and_conflicting_duplicates() {
        let _env_guard = crate::env_lock();
        let tmp = crate::server::test_support::CanonicalTempDir::new();
        let evidence = tmp.path().join("evidence.evtx");
        fs::write(&evidence, b"evidence").expect("evidence");
        let _home = RestoreEnv::set("FINDEVIL_HOME", tmp.path().join("empty-home"));

        {
            let _binding = RestoreEnv::set(
                LAUNCHER_BINDING_ENV,
                "x".repeat(MAX_LAUNCHER_BINDING_BYTES + 1),
            );
            let mut args = json!({"case_id": "case", "evtx_path": evidence});
            assert!(matches!(
                authorize_tool_call("evtx_query", &mut args),
                Err(AccessError::ResourceLimit(_))
            ));
        }

        {
            let artifacts = (0..=MAX_LAUNCHER_ARTIFACTS)
                .map(|_| json!({"path": evidence, "sha256": digest(&evidence)}))
                .collect::<Vec<_>>();
            let _binding = RestoreEnv::set(
                LAUNCHER_BINDING_ENV,
                serde_json::to_string(&json!({"case_id": "case", "artifacts": artifacts}))
                    .expect("inventory"),
            );
            let mut args = json!({"case_id": "case", "evtx_path": evidence});
            assert!(matches!(
                authorize_tool_call("evtx_query", &mut args),
                Err(AccessError::ResourceLimit(_))
            ));
        }

        let _binding = RestoreEnv::set(
            LAUNCHER_BINDING_ENV,
            serde_json::to_string(&json!({
                "case_id": "case",
                "artifacts": [
                    {"path": evidence, "sha256": digest(&evidence)},
                    {"path": evidence, "sha256": "0".repeat(64)},
                ]
            }))
            .expect("duplicates"),
        );
        let mut args = json!({"case_id": "case", "evtx_path": evidence});
        assert!(matches!(
            authorize_tool_call("evtx_query", &mut args),
            Err(AccessError::AuthorizationState(message)) if message.contains("conflicting")
        ));
    }

    #[test]
    fn product_server_rejects_disk_mock_without_an_opt_in() {
        let mut mount = json!({"case_id": "case", "image_path": "/tmp/a", "mode": "mock"});
        assert!(matches!(
            authorize_tool_call("disk_mount", &mut mount),
            Err(AccessError::InvalidInput(message)) if message.contains("test-only")
        ));
        let mut unmount = json!({"case_id": "case", "mount_id": "m", "mode": "mock"});
        assert!(matches!(
            authorize_tool_call("disk_unmount", &mut unmount),
            Err(AccessError::InvalidInput(message)) if message.contains("test-only")
        ));
    }

    #[test]
    #[cfg(unix)]
    fn product_server_rejects_every_caller_selected_mount_point_shape() {
        let tmp = crate::server::test_support::CanonicalTempDir::new();
        let existing = tmp.path().join("existing");
        let symlink = tmp.path().join("symlink");
        fs::create_dir(&existing).expect("existing dir");
        std::os::unix::fs::symlink(&existing, &symlink).expect("symlink");
        let repo = std::env::current_dir().expect("cwd");
        let candidate_paths = vec![
            PathBuf::from("/"),
            repo,
            tmp.path().to_path_buf(),
            PathBuf::from("../escape"),
            symlink,
            existing,
        ];

        for tool in ["disk_mount", "vss_mount"] {
            for mount_point in &candidate_paths {
                let mut args = json!({
                    "case_id": "mount-case",
                    "image_path": "/evidence/source.dd",
                    "mount_point": mount_point,
                });
                assert!(matches!(
                    authorize_tool_call(tool, &mut args),
                    Err(AccessError::InvalidInput(message))
                        if message.contains("server-managed")
                ));
            }
        }
    }

    #[test]
    #[cfg(unix)]
    fn launcher_binding_rejects_hardlinked_evidence() {
        let _env_guard = crate::env_lock();
        let tmp = crate::server::test_support::CanonicalTempDir::new();
        let evidence = tmp.path().join("memory.raw");
        let alias = tmp.path().join("memory-alias.raw");
        fs::write(&evidence, b"memory").expect("evidence");
        fs::hard_link(&evidence, &alias).expect("hardlink");
        let raw = serde_json::to_string(&json!({
            "case_id": "hardlink-case",
            "artifacts": [{"path": evidence, "sha256": digest(&evidence)}],
        }))
        .expect("binding");
        let _binding = RestoreEnv::set(LAUNCHER_BINDING_ENV, raw);
        let _home = RestoreEnv::set("FINDEVIL_HOME", tmp.path().join("empty-home"));
        let mut args = json!({"case_id": "hardlink-case", "memory_path": evidence});

        assert!(matches!(
            authorize_tool_call("vol_pslist", &mut args),
            Err(AccessError::InvalidInput(message)) if message.contains("wrong file type")
        ));
    }

    #[test]
    fn split_ewf_requires_and_rechecks_every_visible_segment() {
        let _env_guard = crate::env_lock();
        let tmp = crate::server::test_support::CanonicalTempDir::new();
        let first = tmp.path().join("host.E01");
        let second = tmp.path().join("host.E02");
        fs::write(&first, b"one").expect("first");
        fs::write(&second, b"two").expect("second");
        let _home = RestoreEnv::set("FINDEVIL_HOME", tmp.path().join("empty-home"));

        let mut args = json!({"case_id": "ewf-case", "image_path": first});
        {
            let _binding = RestoreEnv::set(
                LAUNCHER_BINDING_ENV,
                launcher_binding("ewf-case", &[&first]),
            );
            assert!(matches!(
                authorize_tool_call("bulk_extract", &mut args),
                Err(AccessError::NotAuthorized { path, .. }) if path == crate::pathnorm::canonicalize(&second).unwrap()
            ));
        }

        let _binding = RestoreEnv::set(
            LAUNCHER_BINDING_ENV,
            launcher_binding("ewf-case", &[&first, &second]),
        );
        let authorization =
            authorize_tool_call("bulk_extract", &mut args).expect("all segments bound");
        fs::write(&second, b"changed").expect("mutate second segment");
        assert!(matches!(
            authorization.verify_after(),
            Err(AccessError::IntegrityMismatch { path, .. }) if path == crate::pathnorm::canonicalize(&second).unwrap()
        ));
    }

    #[test]
    #[cfg(unix)]
    fn same_bytes_replacement_is_detected_by_file_identity() {
        let _env_guard = crate::env_lock();
        let tmp = crate::server::test_support::CanonicalTempDir::new();
        let evidence = tmp.path().join("Security.evtx");
        fs::write(&evidence, b"same bytes").expect("evidence");
        let _binding = RestoreEnv::set(
            LAUNCHER_BINDING_ENV,
            launcher_binding("aba-case", &[&evidence]),
        );
        let _home = RestoreEnv::set("FINDEVIL_HOME", tmp.path().join("empty-home"));
        let mut args = json!({"case_id": "aba-case", "evtx_path": evidence});
        let authorization = authorize_tool_call("evtx_query", &mut args).expect("authorized");
        let replacement = tmp.path().join("replacement");
        fs::write(&replacement, b"same bytes").expect("replacement");
        fs::rename(&replacement, &evidence).expect("same-path replacement");

        assert!(matches!(
            authorization.verify_after(),
            Err(AccessError::IntegrityMismatch { .. })
        ));
    }

    #[test]
    #[cfg(unix)]
    fn directory_add_remove_aba_is_detected_by_directory_identity() {
        let _env_guard = crate::env_lock();
        let tmp = crate::server::test_support::CanonicalTempDir::new();
        let directory = tmp.path().join("evtx");
        fs::create_dir(&directory).expect("directory");
        let evidence = directory.join("Security.evtx");
        fs::write(&evidence, b"event log").expect("evidence");
        let _binding = RestoreEnv::set(
            LAUNCHER_BINDING_ENV,
            launcher_binding("directory-aba", &[&evidence]),
        );
        let _home = RestoreEnv::set("FINDEVIL_HOME", tmp.path().join("empty-home"));
        let mut args = json!({"case_id": "directory-aba", "evtx_dir": directory});
        let authorization =
            authorize_tool_call("hayabusa_scan", &mut args).expect("authorized directory");
        std::thread::sleep(std::time::Duration::from_millis(5));
        let transient = directory.join("transient.evtx");
        fs::write(&transient, b"temporary").expect("transient");
        fs::remove_file(transient).expect("remove transient");

        assert!(matches!(
            authorization.verify_after(),
            Err(AccessError::IntegrityMismatch { .. })
        ));
    }
}
