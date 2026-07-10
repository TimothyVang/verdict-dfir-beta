//! Privacy-preserving metadata readers for Chromium profile databases.

use std::path::Path;

use rusqlite::Connection;

use super::{
    chromium_login_time_to_iso, collect_budgeted, empty_to_none, first_present, limit_as_i64,
    optional_column, parse_error, require_columns, table_columns, unix_seconds_to_iso, unsupported,
    webkit_micros_to_iso, BrowserAutofillMetadataRow, BrowserCookieMetadataRow,
    BrowserHistoryError, BrowserLoginMetadataRow, OutputBudget, MAX_PLAUSIBLE_UNIX_SECONDS,
    WEBKIT_UNIX_OFFSET_SECS,
};

pub(super) fn read_cookies(
    conn: &Connection,
    path: &Path,
    limit: usize,
    output_budget: &mut OutputBudget,
) -> Result<Vec<BrowserCookieMetadataRow>, BrowserHistoryError> {
    let columns = table_columns(conn, path, "cookies")?;
    require_columns(
        &columns,
        path,
        "cookies",
        &[
            "creation_utc",
            "host_key",
            "name",
            "path",
            "expires_utc",
            "last_access_utc",
        ],
    )?;
    let is_secure = first_present(&columns, &["is_secure", "secure"])
        .ok_or_else(|| unsupported(path, "cookies", "is_secure/secure"))?;
    let is_http_only = first_present(&columns, &["is_httponly", "httponly"])
        .ok_or_else(|| unsupported(path, "cookies", "is_httponly/httponly"))?;
    let top_frame = optional_column(&columns, "top_frame_site_key", "NULL");
    let last_update = optional_column(&columns, "last_update_utc", "NULL");
    let has_expires = optional_column(&columns, "has_expires", "NULL");
    let is_persistent = first_present(&columns, &["is_persistent", "persistent"]).unwrap_or("NULL");
    let same_site = optional_column(&columns, "samesite", "NULL");
    let source_scheme = optional_column(&columns, "source_scheme", "NULL");
    let source_port = optional_column(&columns, "source_port", "NULL");
    let source_type = optional_column(&columns, "source_type", "NULL");
    let priority = optional_column(&columns, "priority", "NULL");
    let has_cross_site_ancestor = optional_column(&columns, "has_cross_site_ancestor", "NULL");
    // Positive metadata projection only. Value-bearing columns are deliberately
    // absent from the SQL string and from BrowserCookieMetadataRow.
    let sql = format!(
        "SELECT host_key, name, path, creation_utc, expires_utc,
                last_access_utc, {is_secure}, {is_http_only}, {top_frame},
                {last_update}, {has_expires}, {is_persistent}, {same_site},
                {source_scheme}, {source_port}, {source_type}, {priority},
                {has_cross_site_ancestor}
         FROM cookies
         ORDER BY last_access_utc DESC, creation_utc DESC,
                  host_key ASC, name ASC, path ASC, {top_frame} ASC,
                  {source_scheme} ASC, {source_port} ASC, {source_type} ASC,
                  {has_cross_site_ancestor} ASC, {priority} ASC,
                  expires_utc ASC, {is_secure} ASC, {is_http_only} ASC,
                  {has_expires} ASC, {is_persistent} ASC, {same_site} ASC,
                  {last_update} ASC
         LIMIT ?1"
    );
    let map_err = |source| parse_error(path, source);
    let mut stmt = conn.prepare(&sql).map_err(map_err)?;
    let rows = stmt
        .query_map([limit_as_i64(limit)], |row| {
            let has_expires: Option<i64> = row.get(10)?;
            let is_persistent: Option<i64> = row.get(11)?;
            Ok(BrowserCookieMetadataRow {
                host: row.get(0)?,
                name: row.get(1)?,
                path: row.get(2)?,
                creation_time_iso: webkit_micros_to_iso(row.get(3)?),
                expires_time_iso: webkit_micros_to_iso(row.get(4)?),
                last_access_time_iso: webkit_micros_to_iso(row.get(5)?),
                is_secure: row.get::<_, i64>(6)? != 0,
                is_http_only: row.get::<_, i64>(7)? != 0,
                top_frame_site_key: empty_to_none(row.get(8)?),
                last_update_time_iso: row.get::<_, Option<i64>>(9)?.and_then(webkit_micros_to_iso),
                has_expires: has_expires.map(|value| value != 0),
                is_persistent: is_persistent.map(|value| value != 0),
                same_site: row.get(12)?,
                source_scheme: row.get(13)?,
                source_port: row.get(14)?,
                source_type: row.get(15)?,
                priority: row.get(16)?,
                has_cross_site_ancestor: row.get::<_, Option<i64>>(17)?.map(|value| value != 0),
            })
        })
        .map_err(map_err)?;
    collect_budgeted(rows, path, output_budget)
}

pub(super) fn read_autofill(
    conn: &Connection,
    path: &Path,
    limit: usize,
    output_budget: &mut OutputBudget,
) -> Result<Vec<BrowserAutofillMetadataRow>, BrowserHistoryError> {
    let columns = table_columns(conn, path, "autofill")?;
    require_columns(
        &columns,
        path,
        "autofill",
        &["name", "date_created", "date_last_used", "count"],
    )?;
    // Aggregate by field name so no value-bearing column is selected, even as
    // an ordering key. Counts preserve useful forensic metadata.
    let map_err = |source| parse_error(path, source);
    let mut stmt = conn
        .prepare(
            "SELECT name, COUNT(*), COALESCE(SUM(count), 0),
                    MIN(NULLIF(date_created, 0)),
                    MAX(NULLIF(date_last_used, 0))
             FROM autofill
             GROUP BY name
             ORDER BY MAX(NULLIF(date_last_used, 0)) DESC, name ASC
             LIMIT ?1",
        )
        .map_err(map_err)?;
    let rows = stmt
        .query_map([limit_as_i64(limit)], |row| {
            Ok(BrowserAutofillMetadataRow {
                field_name: row.get(0)?,
                stored_value_count: row.get(1)?,
                use_count: row.get(2)?,
                created_time_iso: row.get::<_, Option<i64>>(3)?.and_then(unix_seconds_to_iso),
                last_used_time_iso: row.get::<_, Option<i64>>(4)?.and_then(unix_seconds_to_iso),
            })
        })
        .map_err(map_err)?;
    collect_budgeted(rows, path, output_budget)
}

pub(super) fn read_logins(
    conn: &Connection,
    path: &Path,
    limit: usize,
    output_budget: &mut OutputBudget,
) -> Result<Vec<BrowserLoginMetadataRow>, BrowserHistoryError> {
    let columns = table_columns(conn, path, "logins")?;
    require_columns(
        &columns,
        path,
        "logins",
        &[
            "origin_url",
            "signon_realm",
            "date_created",
            "blacklisted_by_user",
            "scheme",
        ],
    )?;
    let action_url = optional_column(&columns, "action_url", "NULL");
    let username_element = optional_column(&columns, "username_element", "NULL");
    let username = optional_column(&columns, "username_value", "NULL");
    let last_used = optional_column(&columns, "date_last_used", "NULL");
    let modified = optional_column(&columns, "date_password_modified", "NULL");
    let password_type = optional_column(&columns, "password_type", "NULL");
    let times_used = if columns.contains("times_used") {
        "COALESCE(times_used, 0)"
    } else {
        "0"
    };
    let display_name = optional_column(&columns, "display_name", "NULL");
    let icon_url = optional_column(&columns, "icon_url", "NULL");
    let federation_url = optional_column(&columns, "federation_url", "NULL");
    let id = optional_column(&columns, "id", "rowid");
    let effective_activity = if columns.contains("date_last_used") {
        "COALESCE(NULLIF(date_last_used, 0), date_created)"
    } else {
        "date_created"
    };
    let normalized_activity = format!(
        "CASE WHEN {effective_activity} > 0 AND \
                   {effective_activity} < {MAX_PLAUSIBLE_UNIX_SECONDS} \
              THEN ({effective_activity} + {WEBKIT_UNIX_OFFSET_SECS}) * 1000000 \
              ELSE {effective_activity} END"
    );
    // Credential payload columns are intentionally not projected. Usernames are
    // account metadata and remain useful for host/account correlation.
    let sql = format!(
        "SELECT origin_url, {action_url}, {username_element}, {username},
                signon_realm, date_created, {last_used}, {modified},
                blacklisted_by_user, scheme, {password_type}, {times_used},
                {display_name}, {icon_url}, {federation_url}, {id}
         FROM logins
         ORDER BY {normalized_activity} DESC,
                  date_created DESC, {id} ASC
         LIMIT ?1"
    );
    let map_err = |source| parse_error(path, source);
    let mut stmt = conn.prepare(&sql).map_err(map_err)?;
    let rows = stmt
        .query_map([limit_as_i64(limit)], |row| {
            Ok(BrowserLoginMetadataRow {
                login_id: row.get(15)?,
                origin_url: row.get(0)?,
                action_url: empty_to_none(row.get(1)?),
                username_element: empty_to_none(row.get(2)?),
                username: empty_to_none(row.get(3)?),
                signon_realm: row.get(4)?,
                created_time_iso: chromium_login_time_to_iso(row.get(5)?),
                last_used_time_iso: row
                    .get::<_, Option<i64>>(6)?
                    .and_then(chromium_login_time_to_iso),
                password_modified_time_iso: row
                    .get::<_, Option<i64>>(7)?
                    .and_then(chromium_login_time_to_iso),
                blacklisted_by_user: row.get::<_, i64>(8)? != 0,
                scheme: row.get(9)?,
                password_type: row.get(10)?,
                times_used: row.get(11)?,
                display_name: empty_to_none(row.get(12)?),
                icon_url: empty_to_none(row.get(13)?),
                federation_url: empty_to_none(row.get(14)?),
            })
        })
        .map_err(map_err)?;
    collect_budgeted(rows, path, output_budget)
}
