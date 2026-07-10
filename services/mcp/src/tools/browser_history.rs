//! `browser_history` — read offline browser `SQLite` artifacts through one typed,
//! read-only interface.
//!
//! The historical tool name is kept for wire compatibility, but the module now
//! recognizes Chrome/Edge `History` (visits + downloads), Firefox
//! `places.sqlite`, Chromium `Cookies`, `Web Data`, and `Login Data`. Callers do
//! not select a mode: the schema is the source of truth. Rows use a tagged,
//! browser-agnostic shape so a single audit-chained call remains useful as
//! browser schemas grow.
//!
//! Privacy invariant: metadata queries use explicit positive projections. They
//! never select or represent cookie values, encrypted cookie values, autofill
//! values, password blobs, form data, or password notes. The DB is opened
//! read-only with `immutable=1`, so `SQLite` cannot create a WAL or journal beside
//! evidence.
//!
//! HONEST SCOPE: these records confirm what the browser database stored. A visit
//! is not execution; a download row is not proof the file ran; cookie/autofill/
//! login metadata is not proof of user intent or account compromise.

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::OnceLock;

use rusqlite::config::DbConfig;
use rusqlite::ffi::ErrorCode;
use rusqlite::limits::Limit;
use rusqlite::{Connection, OpenFlags};
use serde::Serialize;

mod history_readers;
mod metadata_readers;
mod types;
use history_readers::{read_chromium_history, read_firefox};
use metadata_readers::{read_autofill, read_cookies, read_logins};
pub use types::{
    BrowserArtifactKind, BrowserArtifactRow, BrowserAutofillMetadataRow, BrowserCookieMetadataRow,
    BrowserDownloadRow, BrowserHistoryError, BrowserHistoryInput, BrowserHistoryOutput,
    BrowserHistoryRow, BrowserLoginMetadataRow,
};

/// WebKit/Chromium epoch (1601-01-01) to Unix epoch (1970-01-01), in seconds.
const WEBKIT_UNIX_OFFSET_SECS: i64 = 11_644_473_600;
const MAX_PLAUSIBLE_UNIX_SECONDS: i64 = 10_000_000_000;
const DEFAULT_LIMIT: usize = 10_000;
const MAX_LIMIT: usize = 10_000;
const DEFAULT_MAX_DATABASE_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const DEFAULT_MAX_FIELD_BYTES: u64 = 1024 * 1024;
const DEFAULT_MAX_SQLITE_OPS: u64 = 50_000_000;
// The Python JSON-RPC readers reject any frame above 64 MiB. The typed payload
// is serialized once into MCP's text field and then JSON-escaped again in the
// outer response, which can nearly double hostile quote/backslash-heavy data.
// Keep the inner payload at 24 MiB so the envelope and metadata retain a hard
// safety margin. Operator configuration may lower this limit, never raise it.
const MAX_BROWSER_OUTPUT_BYTES: u64 = 24 * 1024 * 1024;
const DEFAULT_MAX_OUTPUT_BYTES: u64 = MAX_BROWSER_OUTPUT_BYTES;
const DEFAULT_MAX_SQLITE_HEAP_BYTES: u64 = 128 * 1024 * 1024;
const MIN_MAX_SQLITE_HEAP_BYTES: u64 = 16 * 1024 * 1024;
const MAX_MAX_SQLITE_HEAP_BYTES: u64 = 1024 * 1024 * 1024;
const DEFAULT_MAX_SCHEMA_ENTRIES: u64 = 512;
const MAX_MAX_SCHEMA_ENTRIES: u64 = 4096;
const MAX_PROGRESS_INTERVAL: u64 = 10_000;
static SQLITE_HEAP_LIMIT: OnceLock<Result<u64, String>> = OnceLock::new();

#[derive(Clone, Copy)]
struct BrowserResourceLimits {
    database_bytes: u64,
    field_bytes: u64,
    sqlite_ops: u64,
    output_bytes: u64,
    sqlite_heap_bytes: u64,
    schema_entries: u64,
}

impl BrowserResourceLimits {
    fn from_env() -> Self {
        Self {
            database_bytes: env_u64("FINDEVIL_BROWSER_DB_MAX_BYTES", DEFAULT_MAX_DATABASE_BYTES),
            field_bytes: env_u64("FINDEVIL_BROWSER_FIELD_MAX_BYTES", DEFAULT_MAX_FIELD_BYTES)
                .min(i32::MAX as u64),
            sqlite_ops: env_u64("FINDEVIL_BROWSER_SQLITE_MAX_OPS", DEFAULT_MAX_SQLITE_OPS),
            output_bytes: bounded_browser_output_bytes(env_u64(
                "FINDEVIL_BROWSER_OUTPUT_MAX_BYTES",
                DEFAULT_MAX_OUTPUT_BYTES,
            )),
            sqlite_heap_bytes: env_u64(
                "FINDEVIL_BROWSER_SQLITE_HEAP_MAX_BYTES",
                DEFAULT_MAX_SQLITE_HEAP_BYTES,
            )
            .clamp(MIN_MAX_SQLITE_HEAP_BYTES, MAX_MAX_SQLITE_HEAP_BYTES),
            schema_entries: env_u64(
                "FINDEVIL_BROWSER_SCHEMA_MAX_ENTRIES",
                DEFAULT_MAX_SCHEMA_ENTRIES,
            )
            .min(MAX_MAX_SCHEMA_ENTRIES),
        }
    }
}

const fn bounded_browser_output_bytes(configured: u64) -> u64 {
    if configured < MAX_BROWSER_OUTPUT_BYTES {
        configured
    } else {
        MAX_BROWSER_OUTPUT_BYTES
    }
}

struct OutputBudget {
    used_bytes: u64,
    max_bytes: u64,
}

impl OutputBudget {
    const fn new(max_bytes: u64) -> Self {
        Self {
            used_bytes: 0,
            max_bytes,
        }
    }

    fn charge<T: Serialize>(&mut self, value: &T) -> Result<(), BrowserHistoryError> {
        // Charge the representation that will actually cross the MCP boundary.
        // Neutralization markers can be larger than attacker-controlled chat
        // tokens (for example `[INST]` -> `[neutralized:inst_open]`), so charging
        // raw rows would let a database amplify beyond the advertised ceiling
        // after parsing. Per-row sanitization keeps peak expansion bounded before
        // the row is retained in the aggregate output.
        let raw_value = serde_json::to_value(value).map_err(BrowserHistoryError::OutputEncoding)?;
        let (sanitized_value, _) = crate::sanitize::sanitize_value(&raw_value);
        let row_bytes = serde_json::to_vec(&sanitized_value)
            .map_err(BrowserHistoryError::OutputEncoding)?
            .len() as u64;
        self.used_bytes = self.used_bytes.saturating_add(row_bytes);
        if self.used_bytes > self.max_bytes {
            Err(BrowserHistoryError::ResourceLimit(
                "cumulative serialized output budget exceeded",
            ))
        } else {
            Ok(())
        }
    }
}

pub(crate) fn browser_history_output_max_bytes() -> u64 {
    BrowserResourceLimits::from_env().output_bytes
}

pub(crate) fn validate_browser_history_limit(
    input: &BrowserHistoryInput,
) -> Result<(), BrowserHistoryError> {
    let limit = input.limit.unwrap_or(DEFAULT_LIMIT);
    if limit > MAX_LIMIT {
        return Err(BrowserHistoryError::InvalidLimit {
            requested: limit,
            max: MAX_LIMIT,
        });
    }
    Ok(())
}

/// Cheap pre-flight based on canonical browser DB names. Generic `.sqlite`
/// files remain accepted; schema detection is still the source of truth.
#[must_use]
pub fn path_looks_like_browser_history(path: &Path) -> bool {
    if path
        .extension()
        .is_some_and(|extension| extension.eq_ignore_ascii_case("sqlite"))
    {
        return true;
    }
    let Some(name) = path.file_name().and_then(|value| value.to_str()) else {
        return false;
    };
    matches!(
        name.to_ascii_lowercase().as_str(),
        "history" | "archived history" | "places.sqlite" | "cookies" | "web data" | "login data"
    )
}

/// Read one extracted browser database without modifying it.
///
/// # Errors
/// Returns a typed error when the file is missing/unreadable, its schema is
/// unknown or ambiguous, required metadata columns are absent, or a projected
/// query cannot be decoded.
pub fn browser_history(
    input: &BrowserHistoryInput,
) -> Result<BrowserHistoryOutput, BrowserHistoryError> {
    validate_browser_history_limit(input)?;
    let limit = input.limit.unwrap_or(DEFAULT_LIMIT);
    let query_limit = limit.saturating_add(1);
    let path = &input.history_path;
    preflight_browser_file(path)?;
    let resource_limits = BrowserResourceLimits::from_env();
    install_global_sqlite_heap_limit(resource_limits.sqlite_heap_bytes)?;
    let uri = sqlite_immutable_uri(path);
    let conn = Connection::open_with_flags(
        uri,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI,
    )
    .map_err(|source| BrowserHistoryError::Unreadable {
        path: path.clone(),
        source,
    })?;
    conn.set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)
        .and_then(|_| conn.set_db_config(DbConfig::SQLITE_DBCONFIG_TRUSTED_SCHEMA, false))
        .and_then(|_| conn.set_db_config(DbConfig::SQLITE_DBCONFIG_ENABLE_TRIGGER, false))
        .and_then(|_| conn.set_db_config(DbConfig::SQLITE_DBCONFIG_ENABLE_VIEW, false))
        .map_err(BrowserHistoryError::ResourceConfiguration)?;
    conn.execute_batch(
        "PRAGMA query_only=ON; \
         PRAGMA trusted_schema=OFF; \
         PRAGMA cell_size_check=ON; \
         PRAGMA mmap_size=0;",
    )
    .map_err(|source| BrowserHistoryError::Unreadable {
        path: path.clone(),
        source,
    })?;
    install_sqlite_limits(&conn, resource_limits)?;
    let mut output_budget = OutputBudget::new(resource_limits.output_bytes);

    let detected = detect_artifact(&conn, path, resource_limits.schema_entries)?;
    let mut rows = match detected {
        DetectedArtifact::ChromiumHistory => {
            read_chromium_history(&conn, path, query_limit, &mut output_budget)?
        }
        DetectedArtifact::FirefoxHistory => {
            read_firefox(&conn, path, query_limit, &mut output_budget)?
                .into_iter()
                .map(BrowserArtifactRow::Visit)
                .collect()
        }
        DetectedArtifact::ChromiumCookies => {
            { read_cookies(&conn, path, query_limit, &mut output_budget)? }
                .into_iter()
                .map(BrowserArtifactRow::CookieMetadata)
                .collect()
        }
        DetectedArtifact::ChromiumWebData => {
            { read_autofill(&conn, path, query_limit, &mut output_budget)? }
                .into_iter()
                .map(BrowserArtifactRow::AutofillMetadata)
                .collect()
        }
        DetectedArtifact::ChromiumLoginData => {
            { read_logins(&conn, path, query_limit, &mut output_budget)? }
                .into_iter()
                .map(BrowserArtifactRow::LoginMetadata)
                .collect()
        }
    };
    let truncated = rows.len() > limit;
    rows.truncate(limit);

    Ok(BrowserHistoryOutput {
        schema_version: 2,
        browser_family: detected.browser_family().to_string(),
        artifact_kind: detected.artifact_kind(),
        rows_seen: rows.len(),
        rows,
        truncated,
    })
}

pub(super) fn preflight_browser_file(
    path: &Path,
) -> Result<std::fs::Metadata, BrowserHistoryError> {
    let metadata =
        std::fs::symlink_metadata(path).map_err(|_| BrowserHistoryError::NotFound(path.into()))?;
    if !metadata.is_file() {
        return Err(BrowserHistoryError::NotRegular(path.into()));
    }
    enforce_database_size(metadata.len(), BrowserResourceLimits::from_env())?;
    Ok(metadata)
}

const fn enforce_database_size(
    size_bytes: u64,
    limits: BrowserResourceLimits,
) -> Result<(), BrowserHistoryError> {
    if size_bytes > limits.database_bytes {
        Err(BrowserHistoryError::DatabaseTooLarge {
            size_bytes,
            max_bytes: limits.database_bytes,
        })
    } else {
        Ok(())
    }
}

fn install_sqlite_limits(
    conn: &Connection,
    limits: BrowserResourceLimits,
) -> Result<(), BrowserHistoryError> {
    let max_field_bytes = i32::try_from(limits.field_bytes).unwrap_or(i32::MAX);
    conn.set_limit(Limit::SQLITE_LIMIT_LENGTH, max_field_bytes)
        .map_err(BrowserHistoryError::ResourceConfiguration)?;
    for (limit, value) in [
        (Limit::SQLITE_LIMIT_SQL_LENGTH, 100_000),
        (Limit::SQLITE_LIMIT_COLUMN, 100),
        (Limit::SQLITE_LIMIT_EXPR_DEPTH, 10),
        (Limit::SQLITE_LIMIT_COMPOUND_SELECT, 3),
        (Limit::SQLITE_LIMIT_VDBE_OP, 25_000),
        (Limit::SQLITE_LIMIT_FUNCTION_ARG, 8),
        (Limit::SQLITE_LIMIT_ATTACHED, 0),
        (Limit::SQLITE_LIMIT_LIKE_PATTERN_LENGTH, 64),
        (Limit::SQLITE_LIMIT_VARIABLE_NUMBER, 16),
        (Limit::SQLITE_LIMIT_TRIGGER_DEPTH, 10),
        (Limit::SQLITE_LIMIT_WORKER_THREADS, 0),
    ] {
        conn.set_limit(limit, value)
            .map_err(BrowserHistoryError::ResourceConfiguration)?;
    }

    let interval = limits.sqlite_ops.clamp(1, MAX_PROGRESS_INTERVAL);
    let allowed_callbacks = limits.sqlite_ops.div_ceil(interval).max(1);
    let mut callbacks = 0_u64;
    conn.progress_handler(
        i32::try_from(interval).unwrap_or(i32::MAX),
        Some(move || {
            callbacks = callbacks.saturating_add(1);
            callbacks >= allowed_callbacks
        }),
    )
    .map_err(BrowserHistoryError::ResourceConfiguration)?;
    Ok(())
}

fn install_global_sqlite_heap_limit(max_bytes: u64) -> Result<(), BrowserHistoryError> {
    let configured = SQLITE_HEAP_LIMIT.get_or_init(|| {
        let requested = i64::try_from(max_bytes).map_err(|error| error.to_string())?;
        // A bootstrap in-memory connection lets us use SQLite's safe PRAGMA
        // wrapper before the hostile on-disk database is opened. The hard heap
        // ceiling is process-global, so it applies to every later connection.
        let bootstrap = Connection::open_in_memory().map_err(|error| error.to_string())?;
        bootstrap
            .pragma_update(None, "hard_heap_limit", requested)
            .map_err(|error| error.to_string())?;
        let current: i64 = bootstrap
            .query_row("PRAGMA hard_heap_limit", [], |row| row.get(0))
            .map_err(|error| error.to_string())?;
        let current = u64::try_from(current).map_err(|error| error.to_string())?;
        if current == 0 || current > max_bytes {
            return Err("SQLite did not install the requested hard heap limit".to_string());
        }
        Ok(current)
    });
    configured
        .as_ref()
        .map(|_| ())
        .map_err(|_| BrowserHistoryError::ResourceLimit("SQLite hard heap limit unavailable"))
}

fn has_table(conn: &Connection, name: &str) -> Result<bool, rusqlite::Error> {
    // Detection already bounded schema cardinality. Downstream readers still
    // need a few optional-table checks; repeat the unspoofable PRAGMA statement
    // instead of its attacker-shadowable table-valued alias.
    let mut statement = conn.prepare("PRAGMA main.table_list")?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        let schema = row.get::<_, String>(0)?;
        let table_name = row.get::<_, String>(1)?;
        let table_type = row.get::<_, String>(2)?;
        if schema == "main" && table_name == name && table_type == "table" {
            return Ok(true);
        }
    }
    Ok(false)
}

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(default)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum DetectedArtifact {
    ChromiumHistory,
    FirefoxHistory,
    ChromiumCookies,
    ChromiumWebData,
    ChromiumLoginData,
}

impl DetectedArtifact {
    const fn browser_family(self) -> &'static str {
        match self {
            Self::FirefoxHistory => "firefox",
            Self::ChromiumHistory
            | Self::ChromiumCookies
            | Self::ChromiumWebData
            | Self::ChromiumLoginData => "chrome",
        }
    }

    const fn artifact_kind(self) -> BrowserArtifactKind {
        match self {
            Self::ChromiumHistory => BrowserArtifactKind::ChromiumHistory,
            Self::FirefoxHistory => BrowserArtifactKind::FirefoxHistory,
            Self::ChromiumCookies => BrowserArtifactKind::ChromiumCookies,
            Self::ChromiumWebData => BrowserArtifactKind::ChromiumWebData,
            Self::ChromiumLoginData => BrowserArtifactKind::ChromiumLoginData,
        }
    }
}

fn detect_artifact(
    conn: &Connection,
    path: &Path,
    max_schema_entries: u64,
) -> Result<DetectedArtifact, BrowserHistoryError> {
    let tables = ordinary_tables(conn, path, max_schema_entries)?;
    let mut matches = BTreeSet::new();
    if (tables.contains("urls") && tables.contains("visits")) || tables.contains("downloads") {
        matches.insert(DetectedArtifact::ChromiumHistory);
    }
    if tables.contains("moz_places") {
        matches.insert(DetectedArtifact::FirefoxHistory);
    }
    if tables.contains("cookies") {
        matches.insert(DetectedArtifact::ChromiumCookies);
    }
    if tables.contains("autofill") {
        matches.insert(DetectedArtifact::ChromiumWebData);
    }
    if tables.contains("logins") {
        matches.insert(DetectedArtifact::ChromiumLoginData);
    }
    match matches.len() {
        0 => Err(BrowserHistoryError::UnknownSchema(path.to_path_buf())),
        1 => Ok(*matches.first().expect("one detected artifact")),
        _ => Err(BrowserHistoryError::AmbiguousSchema(path.to_path_buf())),
    }
}

fn ordinary_tables(
    conn: &Connection,
    path: &Path,
    max_schema_entries: u64,
) -> Result<BTreeSet<String>, BrowserHistoryError> {
    // `sqlite_master.type='table'` also matches virtual FTS5 tables. Forensic
    // databases are attacker-controlled and SQLite FTS has had crafted-index
    // memory-safety CVEs, while every supported browser target is an ordinary
    // table. `pragma_table_list` distinguishes ordinary, virtual, and shadow
    // tables, so reject the latter two before preparing any artifact query.
    // Use the PRAGMA statement itself: its table-valued SQL alias can be
    // shadowed by an attacker-created ordinary table named
    // `pragma_table_list`.
    let map_err = |source| parse_error(path, source);
    let mut statement = conn.prepare("PRAGMA main.table_list").map_err(map_err)?;
    let mut rows = statement.query([]).map_err(map_err)?;
    let mut seen = 0_u64;
    let mut tables = BTreeSet::new();
    while let Some(row) = rows.next().map_err(map_err)? {
        seen = seen.saturating_add(1);
        if seen > max_schema_entries {
            return Err(BrowserHistoryError::ResourceLimit(
                "SQLite schema entry budget exceeded",
            ));
        }
        let schema = row.get::<_, String>(0).map_err(map_err)?;
        let table_name = row.get::<_, String>(1).map_err(map_err)?;
        let table_type = row.get::<_, String>(2).map_err(map_err)?;
        if schema == "main" && table_type == "table" {
            tables.insert(table_name);
        }
    }
    Ok(tables)
}

fn table_columns(
    conn: &Connection,
    path: &Path,
    table: &'static str,
) -> Result<BTreeSet<String>, BrowserHistoryError> {
    let sql = match table {
        "downloads" => "SELECT name FROM pragma_table_info('downloads')",
        "downloads_url_chains" => "SELECT name FROM pragma_table_info('downloads_url_chains')",
        "cookies" => "SELECT name FROM pragma_table_info('cookies')",
        "autofill" => "SELECT name FROM pragma_table_info('autofill')",
        "logins" => "SELECT name FROM pragma_table_info('logins')",
        _ => unreachable!("table name is an internal allow-list"),
    };
    let map_err = |source| parse_error(path, source);
    let mut stmt = conn.prepare(sql).map_err(map_err)?;
    let columns = stmt
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(map_err)?
        .collect::<Result<BTreeSet<_>, _>>()
        .map_err(map_err)?;
    Ok(columns)
}

fn require_columns(
    columns: &BTreeSet<String>,
    path: &Path,
    table: &'static str,
    required: &[&str],
) -> Result<(), BrowserHistoryError> {
    let missing = required
        .iter()
        .copied()
        .filter(|name| !columns.contains(*name))
        .collect::<Vec<_>>();
    if missing.is_empty() {
        Ok(())
    } else {
        Err(BrowserHistoryError::UnsupportedSchema {
            path: path.to_path_buf(),
            table,
            missing: missing.join(", "),
        })
    }
}

fn collect_budgeted<T, F>(
    rows: rusqlite::MappedRows<'_, F>,
    path: &Path,
    output_budget: &mut OutputBudget,
) -> Result<Vec<T>, BrowserHistoryError>
where
    T: Serialize,
    F: FnMut(&rusqlite::Row<'_>) -> rusqlite::Result<T>,
{
    let mut output = Vec::new();
    for row in rows {
        let row = row.map_err(|source| parse_error(path, source))?;
        output_budget.charge(&row)?;
        output.push(row);
    }
    Ok(output)
}

fn first_present<'a>(columns: &BTreeSet<String>, names: &'a [&'a str]) -> Option<&'a str> {
    names.iter().copied().find(|name| columns.contains(*name))
}

fn optional_column<'a>(columns: &BTreeSet<String>, name: &'a str, fallback: &'a str) -> &'a str {
    if columns.contains(name) {
        name
    } else {
        fallback
    }
}

fn unsupported(path: &Path, table: &'static str, missing: &str) -> BrowserHistoryError {
    BrowserHistoryError::UnsupportedSchema {
        path: path.to_path_buf(),
        table,
        missing: missing.to_string(),
    }
}

fn parse_error(path: &Path, source: rusqlite::Error) -> BrowserHistoryError {
    match source.sqlite_error_code() {
        Some(ErrorCode::OperationInterrupted) => {
            return BrowserHistoryError::ResourceLimit("SQLite operation budget exceeded");
        }
        Some(ErrorCode::TooBig) => {
            return BrowserHistoryError::ResourceLimit("SQLite field length limit exceeded");
        }
        Some(ErrorCode::OutOfMemory) => {
            return BrowserHistoryError::ResourceLimit("SQLite hard heap limit exceeded");
        }
        _ => {}
    }
    BrowserHistoryError::ParseFailed {
        path: path.to_path_buf(),
        source,
    }
}

fn sqlite_immutable_uri(path: &Path) -> String {
    let path_bytes = path.as_os_str().as_encoded_bytes();
    let mut encoded = String::with_capacity(path_bytes.len() + 32);
    for &byte in path_bytes {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b':' | b'-' | b'_' | b'.' | b'~') {
            encoded.push(char::from(byte));
        } else {
            use std::fmt::Write as _;
            let _ = write!(encoded, "%{byte:02X}");
        }
    }
    format!("file:{encoded}?mode=ro&immutable=1")
}

fn empty_to_none(value: Option<String>) -> Option<String> {
    value.filter(|item| !item.is_empty())
}

fn limit_as_i64(limit: usize) -> i64 {
    i64::try_from(limit).unwrap_or(i64::MAX)
}

fn webkit_micros_to_iso(webkit_micros: i64) -> Option<String> {
    if webkit_micros <= 0 {
        return None;
    }
    let unix_micros = webkit_micros.checked_sub(WEBKIT_UNIX_OFFSET_SECS * 1_000_000)?;
    unix_micros_to_iso(unix_micros)
}

fn unix_micros_to_iso(unix_micros: i64) -> Option<String> {
    if unix_micros <= 0 {
        return None;
    }
    let secs = unix_micros.div_euclid(1_000_000);
    let nanos = u32::try_from(unix_micros.rem_euclid(1_000_000) * 1_000).ok()?;
    chrono::DateTime::from_timestamp(secs, nanos)
        .map(|timestamp| timestamp.format("%Y-%m-%dT%H:%M:%SZ").to_string())
}

fn unix_seconds_to_iso(unix_seconds: i64) -> Option<String> {
    if unix_seconds <= 0 {
        return None;
    }
    chrono::DateTime::from_timestamp(unix_seconds, 0)
        .map(|timestamp| timestamp.format("%Y-%m-%dT%H:%M:%SZ").to_string())
}

const fn unix_seconds_to_webkit_micros(unix_seconds: i64) -> i64 {
    unix_seconds
        .saturating_add(WEBKIT_UNIX_OFFSET_SECS)
        .saturating_mul(1_000_000)
}

fn chromium_login_time_to_iso(value: i64) -> Option<String> {
    if value > 0 && value < MAX_PLAUSIBLE_UNIX_SECONDS {
        unix_seconds_to_iso(value)
    } else {
        webkit_micros_to_iso(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn webkit_epoch_converts_to_known_instant() {
        let unix_epoch_in_webkit = WEBKIT_UNIX_OFFSET_SECS * 1_000_000;
        assert_eq!(
            webkit_micros_to_iso(unix_epoch_in_webkit + 1_000_000),
            Some("1970-01-01T00:00:01Z".to_string())
        );
    }

    #[test]
    fn firefox_unix_micros_converts() {
        assert_eq!(
            unix_micros_to_iso(1_609_459_200 * 1_000_000),
            Some("2021-01-01T00:00:00Z".to_string())
        );
    }

    #[test]
    fn unix_seconds_convert_for_autofill() {
        assert_eq!(
            unix_seconds_to_iso(1_609_459_200),
            Some("2021-01-01T00:00:00Z".to_string())
        );
    }

    #[test]
    fn zero_and_pre_unix_timestamps_are_none() {
        assert_eq!(webkit_micros_to_iso(0), None);
        assert_eq!(unix_micros_to_iso(0), None);
        assert_eq!(unix_seconds_to_iso(0), None);
        assert_eq!(webkit_micros_to_iso(1), None);
    }

    #[test]
    fn immutable_uri_percent_encodes_query_delimiters() {
        let uri = sqlite_immutable_uri(Path::new("/tmp/a b?#/History"));
        assert_eq!(uri, "file:/tmp/a%20b%3F%23/History?mode=ro&immutable=1");
    }

    #[test]
    fn path_predicate_matches_supported_names() {
        for name in [
            "History",
            "Archived History",
            "places.sqlite",
            "Cookies",
            "Web Data",
            "Login Data",
            "x.sqlite",
        ] {
            assert!(path_looks_like_browser_history(Path::new(name)));
        }
        assert!(!path_looks_like_browser_history(Path::new("evil.evtx")));
        assert!(!path_looks_like_browser_history(Path::new("SOFTWARE")));
    }

    #[test]
    fn database_size_ceiling_is_loud() {
        let limits = BrowserResourceLimits {
            database_bytes: 7,
            field_bytes: DEFAULT_MAX_FIELD_BYTES,
            sqlite_ops: DEFAULT_MAX_SQLITE_OPS,
            output_bytes: DEFAULT_MAX_OUTPUT_BYTES,
            sqlite_heap_bytes: DEFAULT_MAX_SQLITE_HEAP_BYTES,
            schema_entries: DEFAULT_MAX_SCHEMA_ENTRIES,
        };
        let error = enforce_database_size(8, limits).expect_err("reject oversized database");
        assert!(matches!(
            error,
            BrowserHistoryError::DatabaseTooLarge {
                size_bytes: 8,
                max_bytes: 7
            }
        ));
    }

    #[test]
    fn sqlite_operation_budget_interrupts_expensive_work() {
        let conn = Connection::open_in_memory().expect("open SQLite fixture");
        install_sqlite_limits(
            &conn,
            BrowserResourceLimits {
                database_bytes: DEFAULT_MAX_DATABASE_BYTES,
                field_bytes: DEFAULT_MAX_FIELD_BYTES,
                sqlite_ops: 1,
                output_bytes: DEFAULT_MAX_OUTPUT_BYTES,
                sqlite_heap_bytes: DEFAULT_MAX_SQLITE_HEAP_BYTES,
                schema_entries: DEFAULT_MAX_SCHEMA_ENTRIES,
            },
        )
        .expect("install operation budget");
        let error = conn
            .query_row("SELECT 1", [], |row| row.get::<_, i64>(0))
            .expect_err("operation budget must interrupt query");
        assert_eq!(
            error.sqlite_error_code(),
            Some(ErrorCode::OperationInterrupted)
        );
    }

    #[test]
    fn sqlite_field_length_limit_rejects_oversized_values() {
        let conn = Connection::open_in_memory().expect("open SQLite fixture");
        conn.execute("CREATE TABLE values_table (value TEXT)", [])
            .expect("create fixture table");
        conn.execute("INSERT INTO values_table VALUES (?1)", ["x".repeat(1024)])
            .expect("insert oversized fixture value before limiting reads");
        install_sqlite_limits(
            &conn,
            BrowserResourceLimits {
                database_bytes: DEFAULT_MAX_DATABASE_BYTES,
                field_bytes: 128,
                sqlite_ops: DEFAULT_MAX_SQLITE_OPS,
                output_bytes: DEFAULT_MAX_OUTPUT_BYTES,
                sqlite_heap_bytes: DEFAULT_MAX_SQLITE_HEAP_BYTES,
                schema_entries: DEFAULT_MAX_SCHEMA_ENTRIES,
            },
        )
        .expect("install field budget");
        let error = conn
            .query_row("SELECT value FROM values_table", [], |row| {
                row.get::<_, String>(0)
            })
            .expect_err("field limit must reject oversized value");
        assert_eq!(error.sqlite_error_code(), Some(ErrorCode::TooBig));
    }

    #[test]
    fn sqlite_heap_exhaustion_is_a_typed_resource_limit() {
        let sqlite_error = rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_NOMEM),
            None,
        );
        let error = parse_error(Path::new("History"), sqlite_error);

        assert!(matches!(
            error,
            BrowserHistoryError::ResourceLimit("SQLite hard heap limit exceeded")
        ));
    }

    #[test]
    fn cumulative_output_budget_rejects_many_individually_small_rows() {
        let row = BrowserHistoryRow {
            url_id: 1,
            url: "x".repeat(64),
            title: Some("y".repeat(64)),
            last_visit_time_iso: None,
            visit_count: 1,
        };
        let single_size = serde_json::to_vec(&row).unwrap().len() as u64;
        let mut budget = OutputBudget::new(single_size * 3);
        for _ in 0..3 {
            budget.charge(&row).expect("row remains under total budget");
        }
        assert!(matches!(
            budget.charge(&row),
            Err(BrowserHistoryError::ResourceLimit(
                "cumulative serialized output budget exceeded"
            ))
        ));
    }

    #[test]
    fn configured_output_budget_reserves_json_rpc_envelope_space() {
        assert_eq!(
            bounded_browser_output_bytes(u64::MAX),
            MAX_BROWSER_OUTPUT_BYTES
        );
        assert_eq!(bounded_browser_output_bytes(1024), 1024);
        assert_eq!(DEFAULT_MAX_OUTPUT_BYTES, MAX_BROWSER_OUTPUT_BYTES);
    }

    #[test]
    fn output_budget_charges_sanitizer_expansion_before_rows_accumulate() {
        let row = serde_json::json!({"title": "[INST]".repeat(8)});
        let raw_size = serde_json::to_vec(&row).unwrap().len() as u64;
        let (sanitized, _) = crate::sanitize::sanitize_value(&row);
        let sanitized_size = serde_json::to_vec(&sanitized).unwrap().len() as u64;
        assert!(sanitized_size > raw_size);

        let mut budget = OutputBudget::new(raw_size);
        assert!(matches!(
            budget.charge(&row),
            Err(BrowserHistoryError::ResourceLimit(
                "cumulative serialized output budget exceeded"
            ))
        ));
    }

    #[test]
    fn bundled_sqlite_includes_hostile_fts_database_fixes() {
        // SQLite 3.50.3 fixes CVE-2025-7709's corrupt-FTS-index path. Forensic
        // inputs are attacker-controlled database files, so the usual "trusted
        // DB" caveat does not apply to this parser.
        assert!(
            rusqlite::version_number() >= 3_050_003,
            "bundled SQLite {} is below the hostile-FTS safety floor 3.50.3",
            rusqlite::version()
        );
    }
}
