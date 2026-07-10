//! Visit and download readers for Chromium and Firefox history databases.

use std::cmp::Ordering;
use std::path::Path;

use rusqlite::Connection;
use serde::Serialize;

use super::{
    collect_budgeted, empty_to_none, first_present, has_table, limit_as_i64, optional_column,
    parse_error, require_columns, table_columns, unix_micros_to_iso, unix_seconds_to_iso,
    unix_seconds_to_webkit_micros, unsupported, webkit_micros_to_iso, BrowserArtifactRow,
    BrowserDownloadRow, BrowserHistoryError, BrowserHistoryRow, OutputBudget,
};

impl BrowserArtifactRow {
    fn chromium_history_tie_cmp(&self, other: &Self) -> Ordering {
        match (self, other) {
            (Self::Download(left), Self::Download(right)) => {
                right.download_id.cmp(&left.download_id)
            }
            (Self::Visit(left), Self::Visit(right)) => left
                .url
                .cmp(&right.url)
                .then_with(|| left.url_id.cmp(&right.url_id)),
            (Self::Download(_), Self::Visit(_)) => Ordering::Less,
            (Self::Visit(_), Self::Download(_)) => Ordering::Greater,
            _ => unreachable!("only Chromium History rows share the mixed stream"),
        }
    }
}

pub(super) fn read_chromium_history(
    conn: &Connection,
    path: &Path,
    limit: usize,
    output_budget: &mut OutputBudget,
) -> Result<Vec<BrowserArtifactRow>, BrowserHistoryError> {
    let mut rows = Vec::with_capacity(limit.min(256));
    if has_table(conn, "urls").map_err(|source| parse_error(path, source))?
        && has_table(conn, "visits").map_err(|source| parse_error(path, source))?
    {
        rows.extend(read_chrome_visits(conn, path, limit, output_budget)?);
    }
    if has_table(conn, "downloads").map_err(|source| parse_error(path, source))? {
        rows.extend(read_downloads(conn, path, limit, output_budget)?);
    }
    rows.sort_by(|left, right| {
        right
            .webkit_micros
            .cmp(&left.webkit_micros)
            .then_with(|| left.row.chromium_history_tie_cmp(&right.row))
    });
    rows.truncate(limit);
    Ok(rows.into_iter().map(|row| row.row).collect())
}

#[derive(Serialize)]
struct ChromiumTimedRow {
    webkit_micros: i64,
    row: BrowserArtifactRow,
}

fn read_chrome_visits(
    conn: &Connection,
    path: &Path,
    limit: usize,
    output_budget: &mut OutputBudget,
) -> Result<Vec<ChromiumTimedRow>, BrowserHistoryError> {
    let map_err = |source| parse_error(path, source);
    let mut stmt = conn
        .prepare(
            "SELECT id, url, title, visit_count, last_visit_time
             FROM urls
             ORDER BY last_visit_time DESC, url ASC, id ASC
             LIMIT ?1",
        )
        .map_err(map_err)?;
    let rows = stmt
        .query_map([limit_as_i64(limit)], |row| {
            let webkit_micros: i64 = row.get(4)?;
            Ok(ChromiumTimedRow {
                webkit_micros,
                row: BrowserArtifactRow::Visit(BrowserHistoryRow {
                    url_id: row.get(0)?,
                    url: row.get(1)?,
                    title: row.get(2)?,
                    visit_count: row.get(3)?,
                    last_visit_time_iso: webkit_micros_to_iso(webkit_micros),
                }),
            })
        })
        .map_err(map_err)?;
    collect_budgeted(rows, path, output_budget)
}

struct DownloadProjection {
    legacy_schema: bool,
    current_path: &'static str,
    target_path: &'static str,
    referrer: &'static str,
    source_url: &'static str,
    final_url: &'static str,
    danger_type: &'static str,
    interrupt_reason: &'static str,
}

fn download_projection(
    conn: &Connection,
    path: &Path,
) -> Result<DownloadProjection, BrowserHistoryError> {
    let columns = table_columns(conn, path, "downloads")?;
    let legacy_schema = columns.contains("full_path")
        && columns.contains("url")
        && !columns.contains("current_path")
        && !columns.contains("target_path");
    require_columns(
        &columns,
        path,
        "downloads",
        &[
            "id",
            "start_time",
            "received_bytes",
            "total_bytes",
            "state",
            "end_time",
            "opened",
        ],
    )?;
    if legacy_schema {
        require_columns(&columns, path, "downloads", &["full_path", "url"])?;
    } else {
        require_columns(
            &columns,
            path,
            "downloads",
            &["danger_type", "interrupt_reason"],
        )?;
    }
    let current_path = first_present(&columns, &["current_path", "full_path", "target_path"])
        .ok_or_else(|| unsupported(path, "downloads", "current_path/full_path/target_path"))?;
    let target_path = first_present(&columns, &["target_path", "full_path", "current_path"])
        .ok_or_else(|| unsupported(path, "downloads", "target_path/full_path/current_path"))?;
    let referrer = optional_column(&columns, "referrer", "NULL");
    let has_url_chains =
        has_table(conn, "downloads_url_chains").map_err(|source| parse_error(path, source))?;
    let (source_url, final_url) = if has_url_chains {
        let chain_columns = table_columns(conn, path, "downloads_url_chains")?;
        require_columns(
            &chain_columns,
            path,
            "downloads_url_chains",
            &["id", "chain_index", "url"],
        )?;
        (
            "(SELECT url FROM downloads_url_chains c WHERE c.id=d.id ORDER BY chain_index ASC LIMIT 1)",
            "(SELECT url FROM downloads_url_chains c WHERE c.id=d.id ORDER BY chain_index DESC LIMIT 1)",
        )
    } else if legacy_schema {
        ("d.url", "d.url")
    } else {
        ("NULL", "NULL")
    };
    Ok(DownloadProjection {
        legacy_schema,
        current_path,
        target_path,
        referrer,
        source_url,
        final_url,
        danger_type: if legacy_schema {
            "NULL"
        } else {
            "d.danger_type"
        },
        interrupt_reason: if legacy_schema {
            "NULL"
        } else {
            "d.interrupt_reason"
        },
    })
}

fn read_downloads(
    conn: &Connection,
    path: &Path,
    limit: usize,
    output_budget: &mut OutputBudget,
) -> Result<Vec<ChromiumTimedRow>, BrowserHistoryError> {
    let projection = download_projection(conn, path)?;
    let DownloadProjection {
        legacy_schema,
        current_path,
        target_path,
        referrer,
        source_url,
        final_url,
        danger_type,
        interrupt_reason,
    } = projection;
    let sql = format!(
        "SELECT d.id, d.{current_path}, d.{target_path}, d.start_time,
                d.received_bytes, d.total_bytes, d.state, {danger_type},
                {interrupt_reason}, d.end_time, d.opened, {source_url},
                {final_url}, {referrer}
         FROM downloads d
         ORDER BY d.start_time DESC, d.id DESC
         LIMIT ?1"
    );
    let map_err = |source| parse_error(path, source);
    let mut stmt = conn.prepare(&sql).map_err(map_err)?;
    let rows = stmt
        .query_map([limit_as_i64(limit)], |row| {
            let start_time: i64 = row.get(3)?;
            let end_time: i64 = row.get(9)?;
            Ok(ChromiumTimedRow {
                webkit_micros: if legacy_schema {
                    unix_seconds_to_webkit_micros(start_time)
                } else {
                    start_time
                },
                row: BrowserArtifactRow::Download(BrowserDownloadRow {
                    download_id: row.get(0)?,
                    current_path: row.get(1)?,
                    target_path: row.get(2)?,
                    start_time_iso: if legacy_schema {
                        unix_seconds_to_iso(start_time)
                    } else {
                        webkit_micros_to_iso(start_time)
                    },
                    received_bytes: row.get(4)?,
                    total_bytes: row.get(5)?,
                    state: row.get(6)?,
                    danger_type: row.get::<_, Option<i64>>(7)?,
                    interrupt_reason: row.get::<_, Option<i64>>(8)?,
                    end_time_iso: if legacy_schema {
                        unix_seconds_to_iso(end_time)
                    } else {
                        webkit_micros_to_iso(end_time)
                    },
                    opened: row.get::<_, i64>(10)? != 0,
                    source_url: empty_to_none(row.get(11)?),
                    final_url: empty_to_none(row.get(12)?),
                    referrer_url: empty_to_none(row.get(13)?),
                }),
            })
        })
        .map_err(map_err)?;
    collect_budgeted(rows, path, output_budget)
}

pub(super) fn read_firefox(
    conn: &Connection,
    path: &Path,
    limit: usize,
    output_budget: &mut OutputBudget,
) -> Result<Vec<BrowserHistoryRow>, BrowserHistoryError> {
    let map_err = |source| parse_error(path, source);
    let mut stmt = conn
        .prepare(
            "SELECT id, url, title, visit_count, last_visit_date
             FROM moz_places
             ORDER BY last_visit_date DESC, url ASC, id ASC
             LIMIT ?1",
        )
        .map_err(map_err)?;
    let rows = stmt
        .query_map([limit_as_i64(limit)], |row| {
            let unix_micros: Option<i64> = row.get(4)?;
            Ok(BrowserHistoryRow {
                url_id: row.get(0)?,
                url: row.get(1)?,
                title: row.get(2)?,
                visit_count: row.get(3)?,
                last_visit_time_iso: unix_micros.and_then(unix_micros_to_iso),
            })
        })
        .map_err(map_err)?;
    collect_budgeted(rows, path, output_budget)
}
