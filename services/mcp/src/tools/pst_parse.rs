//! `pst_parse` — read an Outlook personal-folders (`.pst`) / offline-store
//! (`.ost`) mail file and return each message's RFC822 envelope.
//!
//! Why this exists: a Windows host's mail almost always lives in a PST, and no
//! other product tool reads one — plaso has no PST parser, `oe_dbx_parse` only
//! reads the legacy Outlook Express `.dbx` format, and `browser_history` is
//! SQLite-only. Without this verb the entire mail store is invisible to the
//! pipeline, so header-level spoofing tells (a `Reply-To` that diverges from
//! `From`) and attachment egress cannot be seen at all.
//!
//! The PST on-disk format is a paged B-tree over an encrypted node database
//! ([MS-PST]); decoding it by hand is exactly the kind of work where a subtle
//! misparse would put WRONG content behind a Finding. So this tool does not
//! implement it — it shells out to a maintained libpst / libpff reader
//! (`readpst` or `pffexport`), both of which export one RFC822 header block per
//! message, and parses those. Binary discovery is `$PST_READER_BIN`, then
//! `readpst`, then `pffexport` on PATH; a host without either degrades to a
//! typed [`PstParseError::BinaryNotFound`] rather than a crash — the same
//! contract as `vol_*`, `mac_triage`, and `plaso_parse`.
//!
//! Output is header-level and deliberately conservative: envelope headers
//! (`From` / `Reply-To` / `To` / `Subject` / `Date`) plus attachment names and
//! media types. It does not claim to reconstruct bodies or recover deleted
//! items. Messages are deduped and sorted, and the per-run export directory
//! never appears in the payload, so a `verify_finding` replay of a cited call
//! reproduces the same bytes.
//!
//! Nothing here is image-specific: any PST from any host parses the same way.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// `!BDN` — the signature every PST/OST carries at offset 0 ([MS-PST] HEADER).
const PST_MAGIC: [u8; 4] = *b"!BDN";

/// Default cap on surfaced messages. A real mailbox is thousands of messages;
/// the envelope rows are small, but the cap keeps one response bounded.
const DEFAULT_LIMIT: usize = 2_000;
/// Hard ceiling regardless of the requested `limit`.
const MAX_LIMIT: usize = 20_000;
/// Largest exported message file read. Bodies can be huge; the envelope lives
/// in the first few KB, and MIME part headers shortly after.
const MAX_EXPORT_FILE_BYTES: u64 = 4 * 1024 * 1024;
/// Directory-recursion depth cap for the export tree.
const MAX_EXPORT_DEPTH: usize = 12;
/// Cap on files visited while walking one export tree.
const MAX_EXPORT_FILES: usize = 200_000;
/// Longest header value kept (RFC 5322 line-length ceiling).
const MAX_HEADER_LEN: usize = 998;
/// Cap on attachments surfaced per message.
const MAX_ATTACHMENTS: usize = 32;
/// Cap on recipients surfaced per message.
const MAX_RECIPIENTS: usize = 32;

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PstParseInput {
    /// Case ID from a prior `case_open` call. Audit correlation only.
    pub case_id: String,
    /// Path to one Outlook `.pst` / `.ost` mail store.
    pub artifact_path: PathBuf,
    /// Hard cap on surfaced messages. Default 2000, ceiling 20000.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
}

/// One attachment carried by a message.
#[derive(Clone, Debug, Serialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct PstAttachment {
    /// Filename as recorded in the message (or the exported file's name).
    pub name: String,
    /// Lowercased extension, e.g. `xls`. Empty when the name has none.
    pub extension: String,
    /// MIME media type from the part's `Content-Type`, when the export
    /// carried one. Empty otherwise.
    pub content_type: String,
}

/// One message's RFC822 envelope.
#[derive(Clone, Debug, Serialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct PstMessage {
    /// `Subject` header, unfolded.
    pub subject: String,
    /// Display name from `From`, e.g. `Alison Smith`. Empty for a bare address.
    pub from_display: String,
    /// Address from `From`, e.g. `president@m57.biz`.
    pub from_address: String,
    /// Display name from `Reply-To`. Empty when absent.
    pub reply_to_display: String,
    /// Address from `Reply-To`. Empty when the message carries no `Reply-To`.
    /// A value here that differs from `from_address` is the classic
    /// reply-address spoofing tell.
    pub reply_to_address: String,
    /// Addresses from `To` (capped).
    pub to: Vec<String>,
    /// `Date` header verbatim (RFC822 form; not normalized).
    pub date: String,
    /// Attachments (capped, sorted).
    pub attachments: Vec<PstAttachment>,
}

/// What the first bytes of the artifact say it is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StoreClass {
    /// True when the file carries the `!BDN` PST/OST signature.
    pub is_pst: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct PstParseOutput {
    /// True if the artifact carries the PST/OST signature.
    pub is_pst: bool,
    /// Reader that produced the messages: `readpst`, `pffexport`, or `none`
    /// (non-PST input — no subprocess ran).
    pub backend: String,
    /// Messages parsed out of the export, before the `limit` cap.
    pub message_count: usize,
    /// True when `message_count` exceeded the cap and `messages` is a prefix.
    pub messages_truncated: bool,
    /// Total attachments across the surfaced messages.
    pub attachment_count: usize,
    /// Deduped, sorted message envelopes (capped).
    pub messages: Vec<PstMessage>,
}

#[derive(Debug, Error)]
pub enum PstParseError {
    #[error("artifact not found: {0}")]
    ArtifactNotFound(PathBuf),
    #[error("could not read artifact {path}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error(
        "no PST reader found: install libpst (readpst) or libpff (pffexport), \
         or set $PST_READER_BIN to one of them"
    )]
    BinaryNotFound,
    #[error("PST reader {binary} failed ({status}): {stderr_tail}")]
    SubprocessFailed {
        binary: String,
        status: String,
        stderr_tail: String,
    },
}

/// Which external reader was resolved, and where.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Reader {
    /// libpst — `readpst -e -D -o <dir> <pst>` writes one `.eml` per message.
    ReadPst(PathBuf),
    /// libpff — `pffexport -q -f text -t <dir> <pst>` writes one item
    /// directory per message carrying `InternetHeaders.txt` + `Attachments/`.
    PffExport(PathBuf),
}

impl Reader {
    const fn name(&self) -> &'static str {
        match self {
            Self::ReadPst(_) => "readpst",
            Self::PffExport(_) => "pffexport",
        }
    }

    const fn binary(&self) -> &PathBuf {
        match self {
            Self::ReadPst(p) | Self::PffExport(p) => p,
        }
    }

    fn args(&self, pst: &Path, out_dir: &Path) -> Vec<std::ffi::OsString> {
        let mut args: Vec<std::ffi::OsString> = Vec::new();
        match self {
            Self::ReadPst(_) => {
                // -e: one .eml per message (RFC822, so the same parser reads
                // both backends). -D: include deleted items. -q: quiet.
                args.push("-e".into());
                args.push("-D".into());
                args.push("-q".into());
                args.push("-o".into());
                args.push(out_dir.into());
            }
            Self::PffExport(_) => {
                args.push("-q".into());
                args.push("-f".into());
                args.push("text".into());
                args.push("-t".into());
                args.push(out_dir.join("export").into());
            }
        }
        args.push(pst.into());
        args
    }
}

/// Parse one Outlook mail store's message envelopes.
///
/// # Errors
/// * [`PstParseError::ArtifactNotFound`] — `artifact_path` missing.
/// * [`PstParseError::Read`] — IO error reading the artifact.
/// * [`PstParseError::BinaryNotFound`] — neither `readpst` nor `pffexport`
///   is installed and `$PST_READER_BIN` is unset or not a file.
/// * [`PstParseError::SubprocessFailed`] — the reader returned non-zero.
pub fn pst_parse(input: &PstParseInput) -> Result<PstParseOutput, PstParseError> {
    if !input.artifact_path.exists() {
        return Err(PstParseError::ArtifactNotFound(input.artifact_path.clone()));
    }
    let limit = input.limit.unwrap_or(DEFAULT_LIMIT).min(MAX_LIMIT);

    if !classify_path(&input.artifact_path)?.is_pst {
        // Not a PST — a truthful falsy shape, no subprocess. Mirrors
        // `oe_dbx_parse`'s `is_oe_dbx=false` contract.
        return Ok(build_output(false, "none", Vec::new(), limit));
    }

    let reader = resolve_reader()?;
    let out_dir = std::env::temp_dir().join(format!(
        "findevil-pst-{}-{}",
        std::process::id(),
        nanosecond_tag()
    ));
    std::fs::create_dir_all(&out_dir).map_err(|source| PstParseError::Read {
        path: out_dir.clone(),
        source,
    })?;

    let result = run_reader(&reader, &input.artifact_path, &out_dir)
        .map(|()| collect_export_messages(&out_dir, limit.saturating_add(1)));
    let _ = std::fs::remove_dir_all(&out_dir);

    Ok(build_output(true, reader.name(), result?, limit))
}

/// The first bytes of `path`, classified. Reads only the signature.
fn classify_path(path: &Path) -> Result<StoreClass, PstParseError> {
    use std::io::Read;
    let mut file = std::fs::File::open(path).map_err(|source| PstParseError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    let mut head = [0u8; PST_MAGIC.len()];
    match file.read_exact(&mut head) {
        Ok(()) => Ok(classify_store(&head)),
        // Shorter than the signature — cannot be a PST, and not an error.
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => Ok(StoreClass { is_pst: false }),
        Err(source) => Err(PstParseError::Read {
            path: path.to_path_buf(),
            source,
        }),
    }
}

/// Pure signature check — unit-tested without IO.
fn classify_store(data: &[u8]) -> StoreClass {
    StoreClass {
        is_pst: data.len() >= PST_MAGIC.len() && data[..PST_MAGIC.len()] == PST_MAGIC,
    }
}

fn build_output(
    is_pst: bool,
    backend: &str,
    mut messages: Vec<PstMessage>,
    limit: usize,
) -> PstParseOutput {
    let message_count = messages.len();
    let messages_truncated = message_count > limit;
    messages.truncate(limit);
    let attachment_count = messages.iter().map(|m| m.attachments.len()).sum();
    PstParseOutput {
        is_pst,
        backend: backend.to_string(),
        message_count,
        messages_truncated,
        attachment_count,
        messages,
    }
}

// ---------------------------------------------------------------------------
// External reader
// ---------------------------------------------------------------------------

/// `$PST_READER_BIN` first (its file name selects the backend), then `readpst`,
/// then `pffexport` on PATH.
fn resolve_reader() -> Result<Reader, PstParseError> {
    if let Some(path) = std::env::var_os("PST_READER_BIN").map(PathBuf::from) {
        if path.is_file() {
            return Ok(reader_for_name(&path));
        }
    }
    if let Some(path_var) = std::env::var_os("PATH") {
        for name in ["readpst", "pffexport"] {
            for dir in std::env::split_paths(&path_var) {
                let candidate = dir.join(name);
                if candidate.is_file() {
                    return Ok(reader_for_name(&candidate));
                }
            }
        }
    }
    Err(PstParseError::BinaryNotFound)
}

/// libpff when the binary is named `pffexport*`, libpst otherwise.
fn reader_for_name(path: &Path) -> Reader {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    if name.starts_with("pffexport") {
        Reader::PffExport(path.to_path_buf())
    } else {
        Reader::ReadPst(path.to_path_buf())
    }
}

/// Run the reader with a fixed argv (no shell, per the no-`execute_shell`
/// invariant) and let it populate `out_dir`.
fn run_reader(reader: &Reader, pst: &Path, out_dir: &Path) -> Result<(), PstParseError> {
    let mut command = Command::new(reader.binary());
    command.args(reader.args(pst, out_dir));
    let output = command.output().map_err(|source| {
        if source.kind() == std::io::ErrorKind::NotFound {
            PstParseError::BinaryNotFound
        } else {
            PstParseError::Read {
                path: reader.binary().clone(),
                source,
            }
        }
    })?;
    if output.status.success() {
        return Ok(());
    }
    Err(PstParseError::SubprocessFailed {
        binary: reader.name().to_string(),
        status: output.status.to_string(),
        stderr_tail: tail_lossy(&output.stderr),
    })
}

fn tail_lossy(bytes: &[u8]) -> String {
    const TAIL: usize = 2048;
    let start = bytes.len().saturating_sub(TAIL);
    String::from_utf8_lossy(&bytes[start..]).to_string()
}

fn nanosecond_tag() -> u128 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos())
}

// ---------------------------------------------------------------------------
// Export-tree reader (shared by both backends)
// ---------------------------------------------------------------------------

/// Walk an export tree and return every message envelope it holds, deduped and
/// sorted (hence deterministic across runs and machines).
///
/// Both backends are covered by one walk: libpst `-e` writes `<n>.eml` files,
/// libpff writes a per-item directory holding `InternetHeaders.txt` plus an
/// `Attachments/` directory. Both header files are RFC822, so one parser reads
/// both.
fn collect_export_messages(dir: &Path, limit: usize) -> Vec<PstMessage> {
    let mut files = Vec::new();
    walk_export(dir, 0, &mut files);
    files.sort();

    let mut seen: BTreeSet<PstMessage> = BTreeSet::new();
    for file in files {
        if seen.len() >= limit {
            break;
        }
        let Some(text) = read_capped(&file) else {
            continue;
        };
        let Some(mut message) = parse_message_headers(&text) else {
            continue;
        };
        merge_attachments(&mut message, sibling_attachments(&file));
        seen.insert(message);
    }
    seen.into_iter().take(limit).collect()
}

/// Files a mail export puts an RFC822 header block in. libpst `-e` writes
/// `<n>.eml`; libpff writes `InternetHeaders.txt` per item directory.
fn is_message_file(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower == "internetheaders.txt"
        || Path::new(&lower)
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("eml"))
}

fn walk_export(dir: &Path, depth: usize, out: &mut Vec<PathBuf>) {
    if depth > MAX_EXPORT_DEPTH || out.len() >= MAX_EXPORT_FILES {
        return;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        if out.len() >= MAX_EXPORT_FILES {
            return;
        }
        let path = entry.path();
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if file_type.is_dir() {
            walk_export(&path, depth + 1, out);
        } else if file_type.is_file()
            && path
                .file_name()
                .is_some_and(|n| is_message_file(&n.to_string_lossy()))
        {
            out.push(path);
        }
    }
}

fn read_capped(path: &Path) -> Option<String> {
    use std::io::Read;
    let file = std::fs::File::open(path).ok()?;
    let mut buf = Vec::new();
    file.take(MAX_EXPORT_FILE_BYTES)
        .read_to_end(&mut buf)
        .ok()?;
    Some(String::from_utf8_lossy(&buf).into_owned())
}

/// libpff writes a message's attachments as real files under a sibling
/// `Attachments/` directory; libpst inlines them as MIME parts. Reading the
/// directory covers the libpff layout.
fn sibling_attachments(message_file: &Path) -> Vec<PstAttachment> {
    let Some(dir) = message_file.parent().map(|p| p.join("Attachments")) else {
        return Vec::new();
    };
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut out: Vec<PstAttachment> = entries
        .flatten()
        .filter(|e| e.file_type().is_ok_and(|t| t.is_file()))
        .map(|e| {
            let name = e.file_name().to_string_lossy().into_owned();
            let extension = extension_of(&name);
            PstAttachment {
                name,
                extension,
                content_type: String::new(),
            }
        })
        .collect();
    out.sort();
    out.truncate(MAX_ATTACHMENTS);
    out
}

fn merge_attachments(message: &mut PstMessage, extra: Vec<PstAttachment>) {
    if extra.is_empty() {
        return;
    }
    let mut all: BTreeSet<PstAttachment> = message.attachments.drain(..).collect();
    let known: BTreeSet<String> = all.iter().map(|a| a.name.clone()).collect();
    for attachment in extra {
        if !known.contains(&attachment.name) {
            all.insert(attachment);
        }
    }
    message.attachments = all.into_iter().take(MAX_ATTACHMENTS).collect();
}

// ---------------------------------------------------------------------------
// RFC822 header parsing
// ---------------------------------------------------------------------------

/// Parse one exported message into an envelope, or `None` when the text carries
/// no addressed mail headers (so a stray export file is skipped, not surfaced
/// as an empty message).
fn parse_message_headers(raw: &str) -> Option<PstMessage> {
    let lines = unfold(raw);
    let header_end = lines
        .iter()
        .position(|l| l.trim().is_empty())
        .unwrap_or(lines.len());

    let mut envelope: BTreeMap<String, String> = BTreeMap::new();
    for line in &lines[..header_end] {
        if let Some((field, value)) = split_header(line) {
            // First occurrence wins — a later duplicate cannot rewrite the
            // envelope the recipient actually saw.
            envelope.entry(field).or_insert(value);
        }
    }

    let (from_display, from_address) =
        split_mailbox(envelope.get("from").map_or("", String::as_str));
    let (reply_to_display, reply_to_address) =
        split_mailbox(envelope.get("reply-to").map_or("", String::as_str));
    let to = address_list(envelope.get("to").map_or("", String::as_str));
    if from_address.is_empty() && to.is_empty() {
        return None;
    }

    Some(PstMessage {
        subject: clamp(envelope.get("subject").map_or("", String::as_str)),
        from_display,
        from_address,
        reply_to_display,
        reply_to_address,
        to,
        date: clamp(envelope.get("date").map_or("", String::as_str)),
        attachments: mime_attachments(&lines),
    })
}

/// RFC822 unfolding: a line starting with space/tab continues the previous one.
fn unfold(raw: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for line in raw.split('\n') {
        let line = line.strip_suffix('\r').unwrap_or(line);
        if line.starts_with([' ', '\t']) {
            if let Some(last) = out.last_mut() {
                if !last.trim().is_empty() {
                    last.push(' ');
                    last.push_str(line.trim());
                    continue;
                }
            }
        }
        out.push(line.to_string());
    }
    out
}

/// `Field: value` → `(lowercased field, trimmed value)`.
fn split_header(line: &str) -> Option<(String, String)> {
    let (field, value) = line.split_once(':')?;
    if field.is_empty() || !field.bytes().all(|b| b.is_ascii_graphic() && b != b':') {
        return None;
    }
    Some((field.to_ascii_lowercase(), value.trim().to_string()))
}

/// Split `"Display Name" <addr@host>` into its two halves. A bare address
/// yields an empty display name.
fn split_mailbox(value: &str) -> (String, String) {
    let value = value.trim();
    if let (Some(open), Some(close)) = (value.find('<'), value.rfind('>')) {
        if open < close {
            let display = value[..open].trim().trim_matches('"').trim().to_string();
            let address = value[open + 1..close].trim().to_string();
            return (clamp(&display), clamp(&address));
        }
    }
    if value.contains('@') {
        return (String::new(), clamp(value.trim_matches('"').trim()));
    }
    (clamp(value.trim_matches('"').trim()), String::new())
}

/// Addresses from a comma-separated recipient header.
fn address_list(value: &str) -> Vec<String> {
    let mut out: Vec<String> = value
        .split(',')
        .filter_map(|part| {
            let (_, address) = split_mailbox(part);
            (!address.is_empty()).then_some(address)
        })
        .collect();
    out.sort();
    out.dedup();
    out.truncate(MAX_RECIPIENTS);
    out
}

/// Attachment names/types from MIME part headers anywhere in the message.
/// Only parts carrying a `name=` / `filename=` parameter count, so the
/// top-level `multipart/mixed` container is never mistaken for an attachment.
fn mime_attachments(lines: &[String]) -> Vec<PstAttachment> {
    let mut by_name: BTreeMap<String, String> = BTreeMap::new();
    for line in lines {
        let Some((field, value)) = split_header(line) else {
            continue;
        };
        match field.as_str() {
            "content-type" => {
                if let Some(name) = param(&value, "name") {
                    let media = value
                        .split(';')
                        .next()
                        .unwrap_or_default()
                        .trim()
                        .to_ascii_lowercase();
                    by_name.insert(name, clamp(&media));
                }
            }
            "content-disposition" => {
                if let Some(name) = param(&value, "filename") {
                    by_name.entry(name).or_default();
                }
            }
            _ => {}
        }
    }
    by_name
        .into_iter()
        .take(MAX_ATTACHMENTS)
        .map(|(name, content_type)| PstAttachment {
            extension: extension_of(&name),
            name,
            content_type,
        })
        .collect()
}

/// `key=value` / `key="value"` out of a header's parameter list. Matches the
/// whole parameter name so `filename` never satisfies a lookup for `name`.
fn param(value: &str, key: &str) -> Option<String> {
    for part in value.split(';').skip(1) {
        let (raw_key, raw_value) = part.split_once('=')?;
        if raw_key.trim().to_ascii_lowercase() == key {
            let cleaned = raw_value.trim().trim_matches('"').trim();
            if !cleaned.is_empty() {
                return Some(clamp(cleaned));
            }
        }
    }
    None
}

fn extension_of(name: &str) -> String {
    name.rsplit_once('.')
        .map(|(_, ext)| ext.to_ascii_lowercase())
        .filter(|ext| !ext.is_empty() && ext.len() <= 16)
        .unwrap_or_default()
}

/// Bound one header value so a hostile store cannot bloat the payload.
fn clamp(value: &str) -> String {
    value.chars().take(MAX_HEADER_LEN).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_pst_bytes_report_is_pst_false() {
        let out = classify_store(b"not a pst at all");
        assert!(!out.is_pst);
    }

    #[test]
    fn pst_magic_is_recognised() {
        let mut data = b"!BDN".to_vec();
        data.extend_from_slice(&[0u8; 32]);
        assert!(classify_store(&data).is_pst);
    }

    #[test]
    fn message_headers_are_parsed_into_an_envelope() {
        let raw = concat!(
            "Return-Path: <outsider@example.net>\r\n",
            "Date: Tue, 15 Jul 2008 09:12:44 -0700\r\n",
            "From: \"Alison Smith\" <president@m57.biz>\r\n",
            "Reply-To: alison.smith@example.net\r\n",
            "To: jean@m57.biz\r\n",
            "Subject: urgent request\r\n",
            "\r\n",
            "body text\r\n",
        );
        let msg = parse_message_headers(raw).expect("message");
        assert_eq!(msg.subject, "urgent request");
        assert_eq!(msg.from_display, "Alison Smith");
        assert_eq!(msg.from_address, "president@m57.biz");
        assert_eq!(msg.reply_to_address, "alison.smith@example.net");
        assert_eq!(msg.to, vec!["jean@m57.biz".to_string()]);
        assert_eq!(msg.date, "Tue, 15 Jul 2008 09:12:44 -0700");
    }

    #[test]
    fn folded_header_continuation_lines_are_unfolded() {
        let raw = "Subject: a very long\r\n\tsubject line\r\nFrom: a@b.com\r\n\r\nbody\r\n";
        let msg = parse_message_headers(raw).expect("message");
        assert_eq!(msg.subject, "a very long subject line");
    }

    #[test]
    fn attachment_name_and_type_come_from_mime_parts() {
        let raw = concat!(
            "From: jean@m57.biz\r\n",
            "To: outsider@example.net\r\n",
            "Subject: as requested\r\n",
            "Content-Type: multipart/mixed; boundary=\"XYZ\"\r\n",
            "\r\n",
            "--XYZ\r\n",
            "Content-Type: text/plain\r\n\r\nhere you go\r\n",
            "--XYZ\r\n",
            "Content-Type: application/vnd.ms-excel; name=\"m57biz.xls\"\r\n",
            "Content-Disposition: attachment; filename=\"m57biz.xls\"\r\n",
            "\r\n",
            "--XYZ--\r\n",
        );
        let msg = parse_message_headers(raw).expect("message");
        assert_eq!(msg.attachments.len(), 1);
        assert_eq!(msg.attachments[0].name, "m57biz.xls");
        assert_eq!(msg.attachments[0].extension, "xls");
        assert_eq!(msg.attachments[0].content_type, "application/vnd.ms-excel");
    }

    #[test]
    fn a_header_block_with_no_addresses_is_not_a_message() {
        assert!(parse_message_headers("just some prose\r\nwith no headers\r\n").is_none());
    }

    #[test]
    fn mailbox_splits_display_name_from_address() {
        assert_eq!(
            split_mailbox("\"Alison Smith\" <president@m57.biz>"),
            ("Alison Smith".to_string(), "president@m57.biz".to_string())
        );
        assert_eq!(
            split_mailbox("bare@example.com"),
            (String::new(), "bare@example.com".to_string())
        );
    }

    #[test]
    fn export_tree_is_walked_and_output_is_sorted_and_deduped() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join("Inbox")).unwrap();
        std::fs::create_dir_all(root.join("Sent Items")).unwrap();
        std::fs::write(
            root.join("Inbox/0001.eml"),
            "From: b@x.com\r\nTo: jean@m57.biz\r\nSubject: bbb\r\n\r\nx\r\n",
        )
        .unwrap();
        std::fs::write(
            root.join("Inbox/0002.eml"),
            "From: a@x.com\r\nTo: jean@m57.biz\r\nSubject: aaa\r\n\r\nx\r\n",
        )
        .unwrap();
        // duplicate of 0002 in another folder — deduped
        std::fs::write(
            root.join("Sent Items/InternetHeaders.txt"),
            "From: a@x.com\r\nTo: jean@m57.biz\r\nSubject: aaa\r\n\r\n",
        )
        .unwrap();

        let msgs = collect_export_messages(root, 100);
        assert_eq!(msgs.len(), 2, "{msgs:?}");
        assert_eq!(msgs[0].subject, "aaa");
        assert_eq!(msgs[1].subject, "bbb");
        assert_eq!(collect_export_messages(root, 100), msgs); // determinism
    }

    #[test]
    fn sibling_attachments_directory_is_read_for_pffexport_layout() {
        let dir = tempfile::tempdir().unwrap();
        let item = dir.path().join("Message00001");
        std::fs::create_dir_all(item.join("Attachments")).unwrap();
        std::fs::write(
            item.join("InternetHeaders.txt"),
            "From: jean@m57.biz\r\nTo: outsider@example.net\r\nSubject: as requested\r\n\r\n",
        )
        .unwrap();
        std::fs::write(item.join("Attachments/m57biz.xls"), b"fake").unwrap();

        let msgs = collect_export_messages(dir.path(), 100);
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].attachments.len(), 1);
        assert_eq!(msgs[0].attachments[0].name, "m57biz.xls");
        assert_eq!(msgs[0].attachments[0].extension, "xls");
    }

    #[test]
    fn output_never_carries_the_export_directory_path() {
        // verify_finding replays the cited tool against the Rust server; a
        // per-run temp path in the payload would change the output hash.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("0001.eml"),
            "From: a@x.com\r\nTo: b@y.com\r\nSubject: s\r\n\r\nx\r\n",
        )
        .unwrap();
        let out = build_output(
            true,
            "readpst",
            collect_export_messages(dir.path(), 100),
            100,
        );
        let json = serde_json::to_string(&out).unwrap();
        let needle = dir.path().to_string_lossy().to_string();
        assert!(!json.contains(&needle), "export path leaked: {json}");
    }

    #[test]
    fn missing_artifact_is_a_typed_error() {
        let input = PstParseInput {
            case_id: "c".into(),
            artifact_path: std::path::PathBuf::from("/nonexistent/none.pst"),
            limit: None,
        };
        assert!(matches!(
            pst_parse(&input),
            Err(PstParseError::ArtifactNotFound(_))
        ));
    }

    #[test]
    fn missing_reader_binary_is_a_typed_error_not_a_crash() {
        // A real PST with no libpst/libpff on PATH must degrade to a typed
        // BinaryNotFound, exactly like vol_* / mac_triage / plaso_parse.
        let dir = tempfile::tempdir().unwrap();
        let pst = dir.path().join("outlook.pst");
        let mut data = b"!BDN".to_vec();
        data.extend_from_slice(&[0u8; 512]);
        std::fs::write(&pst, &data).unwrap();

        let empty = dir.path().join("empty-bin-dir");
        std::fs::create_dir_all(&empty).unwrap();
        let err = with_env(&empty, || {
            pst_parse(&PstParseInput {
                case_id: "c".into(),
                artifact_path: pst.clone(),
                limit: None,
            })
        });
        assert!(matches!(err, Err(PstParseError::BinaryNotFound)), "{err:?}");
    }

    #[test]
    fn non_pst_artifact_returns_falsy_output_without_running_a_binary() {
        let dir = tempfile::tempdir().unwrap();
        let dbx = dir.path().join("Inbox.dbx");
        std::fs::write(&dbx, b"\xcf\xad\x12\xfe not a pst").unwrap();
        let empty = dir.path().join("empty-bin-dir");
        std::fs::create_dir_all(&empty).unwrap();

        let out = with_env(&empty, || {
            pst_parse(&PstParseInput {
                case_id: "c".into(),
                artifact_path: dbx.clone(),
                limit: None,
            })
        })
        .expect("non-PST input is not an error");
        assert!(!out.is_pst);
        assert_eq!(out.backend, "none");
        assert!(out.messages.is_empty());
    }

    /// Run `f` with PATH and `$PST_READER_BIN` pointing at an empty directory
    /// so binary discovery provably fails. Serialized: env is process-global.
    fn with_env<T>(empty_dir: &std::path::Path, f: impl FnOnce() -> T) -> T {
        use std::sync::{Mutex, OnceLock};
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        let _guard = LOCK.get_or_init(|| Mutex::new(())).lock().unwrap();
        let prev_path = std::env::var_os("PATH");
        let prev_bin = std::env::var_os("PST_READER_BIN");
        std::env::set_var("PATH", empty_dir);
        std::env::set_var("PST_READER_BIN", empty_dir.join("no-such-binary"));
        let out = f();
        match prev_path {
            Some(v) => std::env::set_var("PATH", v),
            None => std::env::remove_var("PATH"),
        }
        match prev_bin {
            Some(v) => std::env::set_var("PST_READER_BIN", v),
            None => std::env::remove_var("PST_READER_BIN"),
        }
        out
    }
}
