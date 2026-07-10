//! Public wire types for the versioned `browser_history` artifact interface.

use std::path::PathBuf;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BrowserHistoryInput {
    /// Case ID from a prior `case_open` call or the deterministic engine's
    /// hash-bound directory inventory. The MCP boundary uses it to authorize
    /// the canonical database path before parsing.
    pub case_id: String,

    /// Path to an extracted browser `SQLite` database. The legacy field name is
    /// retained for MCP compatibility; supported files are Chrome/Edge
    /// `History`, Firefox `places.sqlite`, Chromium `Cookies`, `Web Data`, and
    /// `Login Data`.
    pub history_path: PathBuf,

    /// Hard cap on all rows returned by this call. Default and maximum 10000.
    /// For a Chromium `History` DB, visits and downloads share this global cap.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BrowserArtifactKind {
    ChromiumHistory,
    FirefoxHistory,
    ChromiumCookies,
    ChromiumWebData,
    ChromiumLoginData,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BrowserHistoryRow {
    /// Stable source identity (`urls.id` or `moz_places.id`).
    pub url_id: i64,
    pub url: String,
    pub title: Option<String>,
    pub last_visit_time_iso: Option<String>,
    pub visit_count: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BrowserDownloadRow {
    pub download_id: i64,
    pub source_url: Option<String>,
    pub final_url: Option<String>,
    pub current_path: String,
    pub target_path: String,
    pub referrer_url: Option<String>,
    pub start_time_iso: Option<String>,
    pub end_time_iso: Option<String>,
    pub received_bytes: i64,
    pub total_bytes: i64,
    pub state: i64,
    /// Chromium danger classification when that column exists. Legacy History
    /// schemas did not record it, so absence remains `null` rather than being
    /// synthesized as the semantically meaningful value `0`.
    pub danger_type: Option<i64>,
    /// Chromium interruption reason when recorded by the source schema.
    pub interrupt_reason: Option<i64>,
    pub opened: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BrowserCookieMetadataRow {
    pub host: String,
    pub name: String,
    pub path: String,
    pub top_frame_site_key: Option<String>,
    pub creation_time_iso: Option<String>,
    pub expires_time_iso: Option<String>,
    pub last_access_time_iso: Option<String>,
    pub last_update_time_iso: Option<String>,
    pub is_secure: bool,
    pub is_http_only: bool,
    pub has_expires: Option<bool>,
    pub is_persistent: Option<bool>,
    pub same_site: Option<i64>,
    pub source_scheme: Option<i64>,
    pub source_port: Option<i64>,
    pub source_type: Option<i64>,
    pub priority: Option<i64>,
    pub has_cross_site_ancestor: Option<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BrowserAutofillMetadataRow {
    pub field_name: String,
    pub stored_value_count: i64,
    pub use_count: i64,
    pub created_time_iso: Option<String>,
    pub last_used_time_iso: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BrowserLoginMetadataRow {
    /// Stable source-row identity (`id` when present, otherwise `SQLite` rowid).
    pub login_id: i64,
    pub origin_url: String,
    pub action_url: Option<String>,
    pub username_element: Option<String>,
    pub username: Option<String>,
    pub signon_realm: String,
    pub created_time_iso: Option<String>,
    pub last_used_time_iso: Option<String>,
    pub password_modified_time_iso: Option<String>,
    pub blacklisted_by_user: bool,
    pub scheme: i64,
    pub password_type: Option<i64>,
    pub times_used: i64,
    pub display_name: Option<String>,
    pub icon_url: Option<String>,
    pub federation_url: Option<String>,
}

/// A single stable stream keeps the interface small. The internally tagged
/// representation keeps visit fields at the row level and uses `record_type`
/// to distinguish the schema-version-2 artifact variants.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "record_type", rename_all = "snake_case")]
pub enum BrowserArtifactRow {
    Visit(BrowserHistoryRow),
    Download(BrowserDownloadRow),
    CookieMetadata(BrowserCookieMetadataRow),
    AutofillMetadata(BrowserAutofillMetadataRow),
    LoginMetadata(BrowserLoginMetadataRow),
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BrowserHistoryOutput {
    /// Wire contract version. Version 2 introduces tagged mixed artifact rows;
    /// version 1 was visit-only despite retaining the same tool/field names.
    pub schema_version: u32,
    /// `chrome` for Chromium-family databases, `firefox` for places.sqlite.
    pub browser_family: String,
    pub artifact_kind: BrowserArtifactKind,
    pub rows: Vec<BrowserArtifactRow>,
    /// Number of rows returned after the global limit is applied.
    pub rows_seen: usize,
    /// True when at least one additional matching row existed beyond `limit`.
    pub truncated: bool,
}

#[derive(Debug, Error)]
pub enum BrowserHistoryError {
    #[error("browser database row limit {requested} exceeds maximum {max}")]
    InvalidLimit { requested: usize, max: usize },

    #[error("browser database not found: {0}")]
    NotFound(PathBuf),

    #[error("browser database is not a regular file (symlinks are refused): {0}")]
    NotRegular(PathBuf),

    #[error("invalid browser case_id: {0}")]
    InvalidCaseId(String),

    #[error("browser database is not authorized for case {case_id}")]
    NotAuthorized { case_id: String },

    #[error("browser database integrity mismatch for case {case_id}")]
    IntegrityMismatch { case_id: String },

    #[error("cannot verify browser database integrity: {0}")]
    IntegrityRead(#[source] std::io::Error),

    #[error("browser case authorization state is invalid: {0}")]
    AuthorizationState(String),

    #[error("browser database size {size_bytes} bytes exceeds maximum {max_bytes} bytes")]
    DatabaseTooLarge { size_bytes: u64, max_bytes: u64 },

    #[error("browser database resource limit reached: {0}")]
    ResourceLimit(&'static str),

    #[error("cannot configure browser SQLite resource limits: {0}")]
    ResourceConfiguration(#[source] rusqlite::Error),

    #[error("browser output could not be encoded for budget accounting: {0}")]
    OutputEncoding(#[source] serde_json::Error),

    #[error("browser database unreadable {path}: {source}")]
    Unreadable {
        path: PathBuf,
        #[source]
        source: rusqlite::Error,
    },

    #[error("browser database parse failed for {path}: {source}")]
    ParseFailed {
        path: PathBuf,
        #[source]
        source: rusqlite::Error,
    },

    #[error("browser database {path} has unsupported {table} schema; missing: {missing}")]
    UnsupportedSchema {
        path: PathBuf,
        table: &'static str,
        missing: String,
    },

    #[error("{0} contains more than one recognized browser artifact schema")]
    AmbiguousSchema(PathBuf),

    #[error(
        "{0} is not a recognized browser database (expected Chromium history/downloads, cookies, autofill, logins, or Firefox moz_places)"
    )]
    UnknownSchema(PathBuf),
}
