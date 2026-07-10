//! `mft_timeline` — extract timeline events from an NTFS Master File Table.
//!
//! Spec #2 §6 + `agent-config/MEMORY.md`. The MFT is the canonical "did
//! this file ever exist?" artifact for NTFS. Combined with Prefetch
//! (`prefetch_parse`) it satisfies the SOUL.md ≥2 artifact-class rule
//! for execution claims: MFT confirms the binary was on disk; Prefetch
//! confirms it ran.
//!
//! **DFIR caveat (per MEMORY.md):** `$SI` (`$STANDARD_INFORMATION`)
//! timestamps are trivially stompable via the `SetFileTime` API.
//! `$FN` (`$FILE_NAME`) timestamps are only updated on the rare path of
//! file rename/move and are tamper-evident. Our output exposes BOTH so
//! the agent can detect timestomping by comparing them. A binary whose
//! `$SI.modified` is older than its `$FN.modified` is a strong
//! tampering signal.
//!
//! Backed by `mft = "=0.7.0"` (omerbenamram, MIT, 100% safe Rust). Parses
//! every entry (allocated and unallocated). The tool exposes the most
//! agent-relevant fields: the four MAC times for both $SI and $FN, the
//! parent reference, the file name, the resolved full path, allocation
//! and directory flags, and the logical size.

use std::collections::HashSet;
use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};

use mft::attribute::x10::StandardInfoAttr;
use mft::attribute::x30::{FileNameAttr, FileNamespace};
use mft::attribute::{FileAttributeFlags, MftAttributeContent, MftAttributeType};
use mft::entry::EntryFlags;
use mft::{MftParser, Timestamp};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

const DEFAULT_LIMIT: usize = 10_000;
const MAX_OUTPUT_ROWS: usize = 100_000;
const MAX_MFT_RECORDS_SCANNED: u64 = 5_000_000;
const MAX_MFT_SCAN_BYTES: u64 = 5 * 1024 * 1024 * 1024;
const MAX_ATTRIBUTES_PER_RECORD: usize = 1024;
const MAX_PATH_DEPTH: usize = 256;
const MFT_ENTRY_HEADER_BYTES: usize = 42;
const MFT_ATTRIBUTE_COMMON_HEADER_BYTES: usize = 16;
const MFT_ATTRIBUTE_RESIDENT_HEADER_BYTES: usize = 24;
const MFT_ATTRIBUTE_NONRESIDENT_HEADER_BYTES: usize = 64;
const MIN_MFT_ENTRY_BYTES: u32 = 42;
const MAX_MFT_ENTRY_BYTES: u32 = 1024 * 1024;
const FILE_SIGNATURE: &[u8; 4] = b"FILE";
const BAAD_SIGNATURE: &[u8; 4] = b"BAAD";
const ZERO_SIGNATURE: &[u8; 4] = b"\0\0\0\0";

struct ValidatedMft {
    parser: MftParser<BufReader<File>>,
    header_reader: BufReader<File>,
    entry_count: u64,
    entry_size: u32,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MftInput {
    /// Case ID from a prior `case_open` call. Accepted for audit-log
    /// correlation; not consumed by the parser.
    pub case_id: String,

    /// Absolute or relative path to the `$MFT` file (or a Velociraptor /
    /// `MFTECmd` export of it).
    pub mft_path: PathBuf,

    /// Optional inclusive lower bound on `$SI.modified`. UTC ISO-8601
    /// (e.g. `2026-04-25T00:00:00Z`). Entries older than this are
    /// dropped. Use to focus the timeline around an incident window.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since_iso: Option<String>,

    /// Optional inclusive upper bound on `$SI.modified`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until_iso: Option<String>,

    /// Optional row cap. Default `10_000`. Returned `row_count` reports
    /// how many matched the filter; `records_seen` reports total entries
    /// scanned including those filtered out.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct MftEntryRow {
    /// MFT record number (entry index).
    pub record_number: u64,

    /// Parent directory's MFT record number (from `$FN`). None when no
    /// `$FN` attribute was found (rare; usually only on system entries).
    pub parent_record_number: Option<u64>,

    /// File or directory name from `$FN`. Empty string when absent.
    pub name: String,

    /// Full path resolved by walking parent references. May be None if
    /// any ancestor entry is unallocated or unparseable.
    pub full_path: Option<String>,

    /// True if the `$FN` attribute has the `FILE_ATTRIBUTE_DIRECTORY`
    /// flag set.
    pub is_directory: bool,

    /// True if the entry's `EntryFlags::ALLOCATED` bit is set. False
    /// entries are deleted/freed; their attributes may still parse but
    /// the data they reference can be reused.
    pub is_allocated: bool,

    /// Logical size from `$FN.logical_size`. 0 for directories or when
    /// `$FN` is absent.
    pub logical_size: u64,

    // ---- $STANDARD_INFORMATION timestamps (stompable, per MEMORY.md) ----
    pub si_created_iso: Option<String>,
    pub si_modified_iso: Option<String>,
    pub si_accessed_iso: Option<String>,
    pub si_mft_modified_iso: Option<String>,

    // ---- $FILE_NAME timestamps (tamper-evident reference) ----
    pub fn_created_iso: Option<String>,
    pub fn_modified_iso: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct MftOutput {
    pub entries: Vec<MftEntryRow>,

    /// Per-record parse failures swallowed during the scan (e.g. broken
    /// fixup arrays). The walk does not abort on a single bad entry;
    /// counts are reported so the caller can sanity-check completeness.
    pub parse_errors: usize,

    /// Total entries the parser saw before any filter.
    pub records_seen: usize,

    /// Length of `entries` after filter + limit.
    pub row_count: usize,
}

#[derive(Debug, Error)]
pub enum MftError {
    #[error("MFT file not found: {0}")]
    MftNotFound(PathBuf),

    #[error("MFT file unreadable {path}: {source}")]
    MftUnreadable {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// Boxed because `mft::err::Error` is large enough to push our
    /// `Result<_, MftError>` over clippy's `result_large_err` threshold.
    #[error("MFT parser failed to open {path}: {source}")]
    MftOpen {
        path: PathBuf,
        #[source]
        source: Box<mft::err::Error>,
    },

    #[error("invalid MFT structure {path}: {reason}")]
    MftMalformed { path: PathBuf, reason: String },

    #[error("invalid time filter {value:?}: {reason}")]
    InvalidTimeFilter { value: String, reason: String },

    #[error("invalid MFT row limit {value}; expected 1..={max}")]
    InvalidLimit { value: usize, max: usize },

    #[error("MFT resource limit exceeded for {path}: {reason}")]
    ResourceLimit { path: PathBuf, reason: String },
}

/// Cheap pre-flight: file path looks like an MFT export.
///
/// Used by the Python agent to pick which MCP tool to dispatch. Common
/// names: `$MFT`, `MFT`, `mft.bin`, `<host>.mft`. We treat anything
/// ending in `mft` (case-insensitive) or starting with `$MFT` as a
/// candidate; the actual parser is the source of truth.
#[must_use]
pub fn path_looks_like_mft(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|s| s.to_str()) else {
        return false;
    };
    let lower = name.to_ascii_lowercase();
    if lower.starts_with("$mft") || lower == "mft" {
        return true;
    }
    path.extension()
        .is_some_and(|e| e.eq_ignore_ascii_case("mft"))
}

/// Parse an `$MFT` file and produce a timeline.
///
/// The walk uses a prevalidated entry count and indexed reads rather than
/// the dependency's iterator. That keeps hostile record sizing out of an
/// internal division, bounds per-record allocation, and releases the parser
/// borrow before resolving each retained entry's full path.
///
/// # Errors
/// * [`MftError::MftNotFound`] — the file does not exist.
/// * [`MftError::MftUnreadable`] — exists but cannot be read.
/// * [`MftError::MftOpen`] — file is not a valid `$MFT` (wrong magic).
/// * [`MftError::MftMalformed`] — the first record has an impossible header.
/// * [`MftError::InvalidTimeFilter`] — `since_iso` or `until_iso` is
///   not a parseable RFC 3339 / ISO-8601 string.
/// * [`MftError::InvalidLimit`] — the requested output cap is unsafe.
/// * [`MftError::ResourceLimit`] — the declared record count exceeds the
///   bounded in-process scan budget.
pub fn mft_timeline(input: &MftInput) -> Result<MftOutput, MftError> {
    let path = &input.mft_path;
    if !path.is_file() {
        return Err(MftError::MftNotFound(path.clone()));
    }

    let limit = input.limit.unwrap_or(DEFAULT_LIMIT);
    if !(1..=MAX_OUTPUT_ROWS).contains(&limit) {
        return Err(MftError::InvalidLimit {
            value: limit,
            max: MAX_OUTPUT_ROWS,
        });
    }
    let since = parse_optional_iso(input.since_iso.as_deref())?;
    let until = parse_optional_iso(input.until_iso.as_deref())?;

    let ValidatedMft {
        mut parser,
        mut header_reader,
        entry_count,
        entry_size,
    } = open_validated_parser(path)?;

    let mut entries: Vec<MftEntryRow> = Vec::new();
    let mut parse_errors: usize = 0;
    let mut records_seen: usize = 0;

    // Index explicitly rather than calling `MftParser::iter_entries`: mft
    // 0.7 derives that iterator's count by dividing by the first record's
    // declared size, and a zero-filled hostile input otherwise triggers
    // division by zero inside the dependency. Explicit indexing also avoids
    // retaining a full second copy of a large MFT in memory.
    for entry_number in 0..entry_count {
        records_seen = records_seen.saturating_add(1);
        let entry_result = validate_record_header(&mut header_reader, entry_number, entry_size)
            .and_then(|()| get_entry_contained(&mut parser, entry_number));
        let Ok(entry) = entry_result else {
            parse_errors = parse_errors.saturating_add(1);
            continue;
        };
        if validate_attribute_chain(&entry).is_err() {
            parse_errors = parse_errors.saturating_add(1);
            continue;
        }

        // Extract the most agent-relevant attributes.
        let (x10, x30) = extract_attrs(&entry);

        // Apply time filter against $SI.modified (the field analysts
        // typically narrow on; stompability of $SI is the agent's
        // problem to flag, not the timeline tool's to hide).
        if let Some(ref si) = x10 {
            if let Some(lo) = since {
                if si.modified < lo {
                    continue;
                }
            }
            if let Some(hi) = until {
                if si.modified > hi {
                    continue;
                }
            }
        }

        let full_path = x30.as_ref().and_then(|name| {
            resolve_full_path_contained(
                &mut parser,
                &mut header_reader,
                &entry,
                name,
                entry_count,
                entry_size,
            )
        });

        entries.push(MftEntryRow {
            record_number: entry.header.record_number,
            parent_record_number: x30.as_ref().map(|f| f.parent.entry),
            name: x30.as_ref().map(|f| f.name.clone()).unwrap_or_default(),
            full_path,
            is_directory: x30.as_ref().is_some_and(|f| {
                f.flags
                    .contains(FileAttributeFlags::FILE_ATTRIBUTE_DIRECTORY)
            }),
            is_allocated: entry.header.flags.contains(EntryFlags::ALLOCATED),
            logical_size: x30.as_ref().map_or(0, |f| f.logical_size),
            si_created_iso: x10.as_ref().map(|s| iso(&s.created)),
            si_modified_iso: x10.as_ref().map(|s| iso(&s.modified)),
            si_accessed_iso: x10.as_ref().map(|s| iso(&s.accessed)),
            si_mft_modified_iso: x10.as_ref().map(|s| iso(&s.mft_modified)),
            fn_created_iso: x30.as_ref().map(|f| iso(&f.created)),
            fn_modified_iso: x30.as_ref().map(|f| iso(&f.modified)),
        });

        if entries.len() >= limit {
            break;
        }
    }

    let row_count = entries.len();
    Ok(MftOutput {
        entries,
        parse_errors,
        records_seen,
        row_count,
    })
}

fn get_entry_contained(
    parser: &mut MftParser<BufReader<File>>,
    entry_number: u64,
) -> Result<mft::MftEntry, mft::err::Error> {
    catch_unwind(AssertUnwindSafe(|| parser.get_entry(entry_number))).unwrap_or_else(|_| {
        Err(mft::err::Error::Any {
            detail: format!("mft parser panicked while decoding record {entry_number}"),
        })
    })
}

fn resolve_full_path_contained(
    parser: &mut MftParser<BufReader<File>>,
    header_reader: &mut BufReader<File>,
    entry: &mft::MftEntry,
    name: &FileNameAttr,
    entry_count: u64,
    entry_size: u32,
) -> Option<String> {
    let mut visited = HashSet::from([entry.header.record_number]);
    let mut components = vec![name.name.clone()];
    let mut parent_id = name.parent.entry;

    for _ in 0..MAX_PATH_DEPTH {
        if parent_id == 5 {
            components.reverse();
            return Some(
                components
                    .into_iter()
                    .collect::<PathBuf>()
                    .to_string_lossy()
                    .into_owned(),
            );
        }
        if parent_id == 0 {
            components.push("[Orphaned]".to_string());
            components.reverse();
            return Some(
                components
                    .into_iter()
                    .collect::<PathBuf>()
                    .to_string_lossy()
                    .into_owned(),
            );
        }
        if parent_id >= entry_count || !visited.insert(parent_id) {
            return None;
        }

        validate_record_header(header_reader, parent_id, entry_size).ok()?;
        let parent = get_entry_contained(parser, parent_id).ok()?;
        validate_attribute_chain(&parent).ok()?;
        if !parent.is_dir() {
            return None;
        }
        let parent_name = parent.find_best_name_attribute()?;
        components.push(parent_name.name);
        parent_id = parent_name.parent.entry;
    }
    None
}

fn validate_attribute_chain(entry: &mft::MftEntry) -> Result<(), mft::err::Error> {
    let used_size = usize::try_from(entry.header.used_entry_size).map_err(|_| {
        attribute_error(
            entry.header.record_number,
            "used entry size does not fit usize",
        )
    })?;
    let mut offset = usize::from(entry.header.first_attribute_record_offset);
    if used_size > entry.data.len() || offset < MFT_ENTRY_HEADER_BYTES || offset > used_size {
        return Err(attribute_error(
            entry.header.record_number,
            "attribute bounds fall outside the used entry bytes",
        ));
    }

    for _ in 0..MAX_ATTRIBUTES_PER_RECORD {
        let Some(next) = validate_attribute_record(entry, offset, used_size)? else {
            return Ok(());
        };
        offset = next;
    }

    Err(attribute_error(
        entry.header.record_number,
        "attribute count exceeds the per-record safety cap",
    ))
}

fn validate_attribute_record(
    entry: &mft::MftEntry,
    offset: usize,
    used_size: usize,
) -> Result<Option<usize>, mft::err::Error> {
    let entry_number = entry.header.record_number;
    let type_end = offset
        .checked_add(4)
        .ok_or_else(|| attribute_error(entry_number, "attribute offset overflow"))?;
    if type_end > used_size {
        return Err(attribute_error(
            entry_number,
            "attribute chain has no in-bounds terminator",
        ));
    }
    let type_code = read_u32(&entry.data, offset);
    if type_code == u32::MAX {
        return Ok(None);
    }

    let common_end = offset
        .checked_add(MFT_ATTRIBUTE_COMMON_HEADER_BYTES)
        .ok_or_else(|| attribute_error(entry_number, "attribute header overflow"))?;
    if common_end > used_size {
        return Err(attribute_error(
            entry_number,
            "truncated attribute common header",
        ));
    }
    let record_length = read_u32(&entry.data, offset + 4) as usize;
    let form_code = entry.data[offset + 8];
    let minimum_length = attribute_minimum_length(entry, offset, used_size, form_code)?;
    let next = offset
        .checked_add(record_length)
        .ok_or_else(|| attribute_error(entry_number, "attribute length overflow"))?;
    if record_length < minimum_length || !record_length.is_multiple_of(8) || next > used_size {
        return Err(attribute_error(
            entry_number,
            "attribute length is zero, unaligned, undersized, or out of bounds",
        ));
    }

    validate_attribute_name(entry, offset, record_length, minimum_length)?;
    validate_attribute_payload(
        entry,
        offset,
        record_length,
        minimum_length,
        form_code,
        type_code,
    )?;
    Ok(Some(next))
}

fn attribute_minimum_length(
    entry: &mft::MftEntry,
    offset: usize,
    used_size: usize,
    form_code: u8,
) -> Result<usize, mft::err::Error> {
    let entry_number = entry.header.record_number;
    match form_code {
        0 => Ok(MFT_ATTRIBUTE_RESIDENT_HEADER_BYTES),
        1 => {
            let header_end = offset
                .checked_add(MFT_ATTRIBUTE_NONRESIDENT_HEADER_BYTES)
                .ok_or_else(|| {
                    attribute_error(entry_number, "non-resident attribute header overflow")
                })?;
            if header_end > used_size {
                return Err(attribute_error(
                    entry_number,
                    "truncated non-resident attribute header",
                ));
            }
            let compressed = read_u16(&entry.data, offset + 34) > 0;
            Ok(MFT_ATTRIBUTE_NONRESIDENT_HEADER_BYTES + usize::from(compressed) * 8)
        }
        _ => Err(attribute_error(
            entry_number,
            "attribute has an invalid resident form code",
        )),
    }
}

fn validate_attribute_name(
    entry: &mft::MftEntry,
    offset: usize,
    record_length: usize,
    minimum_length: usize,
) -> Result<(), mft::err::Error> {
    let name_size = usize::from(entry.data[offset + 9]);
    if name_size == 0 {
        return Ok(());
    }
    let name_offset = usize::from(read_u16(&entry.data, offset + 10));
    let name_end = name_offset
        .checked_add(name_size.saturating_mul(2))
        .ok_or_else(|| attribute_error(entry.header.record_number, "attribute name overflow"))?;
    if name_offset < minimum_length || name_end > record_length {
        return Err(attribute_error(
            entry.header.record_number,
            "attribute name falls outside its record",
        ));
    }
    Ok(())
}

fn validate_attribute_payload(
    entry: &mft::MftEntry,
    offset: usize,
    record_length: usize,
    minimum_length: usize,
    form_code: u8,
    type_code: u32,
) -> Result<(), mft::err::Error> {
    let entry_number = entry.header.record_number;
    let (data_offset, data_size) = if form_code == 0 {
        (
            usize::from(read_u16(&entry.data, offset + 20)),
            read_u32(&entry.data, offset + 16) as usize,
        )
    } else {
        (usize::from(read_u16(&entry.data, offset + 32)), 0)
    };
    let data_end = data_offset
        .checked_add(data_size)
        .ok_or_else(|| attribute_error(entry_number, "attribute data size overflow"))?;
    if data_offset < minimum_length || data_end > record_length {
        return Err(attribute_error(
            entry_number,
            "attribute payload falls outside its record",
        ));
    }
    validate_relevant_resident_payload(entry, offset, form_code, type_code, data_offset, data_size)
}

fn validate_relevant_resident_payload(
    entry: &mft::MftEntry,
    offset: usize,
    form_code: u8,
    type_code: u32,
    data_offset: usize,
    data_size: usize,
) -> Result<(), mft::err::Error> {
    if !matches!(type_code, 0x10 | 0x30) {
        return Ok(());
    }
    let entry_number = entry.header.record_number;
    if form_code != 0 || entry.data[offset + 9] != 0 || data_offset != 24 {
        return Err(attribute_error(
            entry_number,
            "$STANDARD_INFORMATION/$FILE_NAME must be unnamed resident data at offset 24",
        ));
    }
    if type_code == 0x10 && data_size < 72 {
        return Err(attribute_error(
            entry_number,
            "$STANDARD_INFORMATION is shorter than the parser's 72-byte payload",
        ));
    }
    if type_code == 0x30 {
        if data_size < 66 {
            return Err(attribute_error(
                entry_number,
                "$FILE_NAME is shorter than its fixed payload",
            ));
        }
        let embedded_name_size = usize::from(entry.data[offset + data_offset + 64]);
        let required_size = 66_usize
            .checked_add(embedded_name_size.saturating_mul(2))
            .ok_or_else(|| attribute_error(entry_number, "$FILE_NAME size overflow"))?;
        if required_size > data_size {
            return Err(attribute_error(
                entry_number,
                "$FILE_NAME name bytes exceed the declared resident payload",
            ));
        }
    }
    Ok(())
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(
        bytes[offset..offset + 2]
            .try_into()
            .expect("two-byte slice has a fixed length"),
    )
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(
        bytes[offset..offset + 4]
            .try_into()
            .expect("four-byte slice has a fixed length"),
    )
}

fn attribute_error(entry_number: u64, detail: &str) -> mft::err::Error {
    mft::err::Error::Any {
        detail: format!("record {entry_number}: {detail}"),
    }
}

fn open_validated_parser(path: &Path) -> Result<ValidatedMft, MftError> {
    let mut file = File::open(path).map_err(|source| MftError::MftUnreadable {
        path: path.to_path_buf(),
        source,
    })?;
    let file_size = file
        .metadata()
        .map_err(|source| MftError::MftUnreadable {
            path: path.to_path_buf(),
            source,
        })?
        .len();

    if file_size < MFT_ENTRY_HEADER_BYTES as u64 {
        return Err(malformed(
            path,
            format!(
                "file is {file_size} bytes; at least {MFT_ENTRY_HEADER_BYTES} bytes are required"
            ),
        ));
    }

    let mut header = [0_u8; MFT_ENTRY_HEADER_BYTES];
    file.read_exact(&mut header)
        .map_err(|source| MftError::MftUnreadable {
            path: path.to_path_buf(),
            source,
        })?;

    let signature: [u8; 4] = header[..4]
        .try_into()
        .expect("four-byte slice has a fixed length");
    if signature == *ZERO_SIGNATURE {
        return Err(malformed(
            path,
            "the first MFT record is zero-filled and has no entry size".to_string(),
        ));
    }
    if signature != *FILE_SIGNATURE && signature != *BAAD_SIGNATURE {
        return Err(MftError::MftOpen {
            path: path.to_path_buf(),
            source: Box::new(mft::err::Error::InvalidEntrySignature {
                bad_sig: signature.to_vec(),
            }),
        });
    }

    let used_entry_size = u32::from_le_bytes(
        header[24..28]
            .try_into()
            .expect("four-byte slice has a fixed length"),
    );
    let total_entry_size = u32::from_le_bytes(
        header[28..32]
            .try_into()
            .expect("four-byte slice has a fixed length"),
    );
    if !(MIN_MFT_ENTRY_BYTES..=MAX_MFT_ENTRY_BYTES).contains(&total_entry_size) {
        return Err(malformed(
            path,
            format!(
                "declared entry size {total_entry_size} is outside the supported {MFT_ENTRY_HEADER_BYTES}..={MAX_MFT_ENTRY_BYTES} byte range"
            ),
        ));
    }
    if u64::from(total_entry_size) > file_size {
        return Err(malformed(
            path,
            format!("declared entry size {total_entry_size} exceeds the {file_size}-byte file"),
        ));
    }
    if used_entry_size > total_entry_size {
        return Err(malformed(
            path,
            format!(
                "used entry size {used_entry_size} exceeds allocated entry size {total_entry_size}"
            ),
        ));
    }

    if signature == *FILE_SIGNATURE {
        validate_fixup_header(path, &header, total_entry_size)?;
    }

    let entry_count = validate_scan_record_count(path, file_size, total_entry_size)?;
    file.rewind().map_err(|source| MftError::MftUnreadable {
        path: path.to_path_buf(),
        source,
    })?;
    let header_reader = BufReader::with_capacity(4096, file);
    let parser_file = File::open(path).map_err(|source| MftError::MftUnreadable {
        path: path.to_path_buf(),
        source,
    })?;
    let parser =
        MftParser::from_read_seek(BufReader::with_capacity(4096, parser_file), Some(file_size))
            .map_err(|source| MftError::MftOpen {
                path: path.to_path_buf(),
                source: Box::new(source),
            })?;

    Ok(ValidatedMft {
        parser,
        header_reader,
        entry_count,
        entry_size: total_entry_size,
    })
}

fn validate_scan_record_count(
    path: &Path,
    file_size: u64,
    entry_size: u32,
) -> Result<u64, MftError> {
    let entry_count = file_size / u64::from(entry_size);
    if entry_count > MAX_MFT_RECORDS_SCANNED {
        return Err(MftError::ResourceLimit {
            path: path.to_path_buf(),
            reason: format!(
                "declared {entry_count} records exceeds the {MAX_MFT_RECORDS_SCANNED}-record scan cap"
            ),
        });
    }
    let scan_bytes = entry_count
        .checked_mul(u64::from(entry_size))
        .ok_or_else(|| MftError::ResourceLimit {
            path: path.to_path_buf(),
            reason: "declared scan-byte budget overflowed".to_string(),
        })?;
    if scan_bytes > MAX_MFT_SCAN_BYTES {
        return Err(MftError::ResourceLimit {
            path: path.to_path_buf(),
            reason: format!(
                "declared {scan_bytes} scan bytes exceeds the {MAX_MFT_SCAN_BYTES}-byte scan cap"
            ),
        });
    }
    Ok(entry_count)
}

fn validate_record_header(
    reader: &mut BufReader<File>,
    entry_number: u64,
    expected_entry_size: u32,
) -> Result<(), mft::err::Error> {
    let offset = entry_number
        .checked_mul(u64::from(expected_entry_size))
        .ok_or_else(|| mft::err::Error::Any {
            detail: format!("record {entry_number} offset overflow"),
        })?;
    reader.seek(SeekFrom::Start(offset))?;
    let mut header = [0_u8; MFT_ENTRY_HEADER_BYTES];
    reader.read_exact(&mut header)?;

    let signature: [u8; 4] = header[..4]
        .try_into()
        .expect("four-byte slice has a fixed length");
    if signature == *ZERO_SIGNATURE || signature == *BAAD_SIGNATURE {
        return Ok(());
    }
    if signature != *FILE_SIGNATURE {
        return Err(mft::err::Error::InvalidEntrySignature {
            bad_sig: signature.to_vec(),
        });
    }

    let used_entry_size = u32::from_le_bytes(
        header[24..28]
            .try_into()
            .expect("four-byte slice has a fixed length"),
    );
    let total_entry_size = u32::from_le_bytes(
        header[28..32]
            .try_into()
            .expect("four-byte slice has a fixed length"),
    );
    if total_entry_size != expected_entry_size || used_entry_size > total_entry_size {
        return Err(mft::err::Error::Any {
            detail: format!(
                "record {entry_number} declares invalid used/allocated sizes {used_entry_size}/{total_entry_size}; expected allocation {expected_entry_size}"
            ),
        });
    }
    validate_fixup_fields(&header, total_entry_size).map_err(|detail| mft::err::Error::Any {
        detail: format!("record {entry_number}: {detail}"),
    })
}

fn validate_fixup_header(
    path: &Path,
    header: &[u8; MFT_ENTRY_HEADER_BYTES],
    total_entry_size: u32,
) -> Result<(), MftError> {
    validate_fixup_fields(header, total_entry_size).map_err(|reason| malformed(path, reason))
}

fn validate_fixup_fields(
    header: &[u8; MFT_ENTRY_HEADER_BYTES],
    total_entry_size: u32,
) -> Result<(), String> {
    let usa_offset = u16::from_le_bytes(
        header[4..6]
            .try_into()
            .expect("two-byte slice has a fixed length"),
    );
    let usa_size = u16::from_le_bytes(
        header[6..8]
            .try_into()
            .expect("two-byte slice has a fixed length"),
    );
    if usa_size == 0 {
        return Err("FILE record has an empty update-sequence array".to_string());
    }

    let fixup_end = u32::from(usa_offset) + u32::from(usa_size) * 2;
    let covered_bytes = u32::from(usa_size - 1) * 512;
    if fixup_end > total_entry_size || covered_bytes > total_entry_size {
        return Err(format!(
            "update-sequence array (offset {usa_offset}, count {usa_size}) exceeds the {total_entry_size}-byte entry"
        ));
    }

    Ok(())
}

fn malformed(path: &Path, reason: String) -> MftError {
    MftError::MftMalformed {
        path: path.to_path_buf(),
        reason,
    }
}

/// Best-effort attribute extraction. Prefers the Win32 namespace `$FN`
/// when multiple are present (DOS 8.3 names are typically duplicates).
fn extract_attrs(entry: &mft::MftEntry) -> (Option<StandardInfoAttr>, Option<FileNameAttr>) {
    let mut x10: Option<StandardInfoAttr> = None;
    let mut x30: Option<FileNameAttr> = None;
    for attr_result in entry.iter_attributes_matching(Some(vec![
        MftAttributeType::StandardInformation,
        MftAttributeType::FileName,
    ])) {
        let Ok(attr) = attr_result else {
            continue;
        };
        match attr.data {
            MftAttributeContent::AttrX10(s) => {
                if x10.is_none() {
                    x10 = Some(s);
                }
            }
            MftAttributeContent::AttrX30(f) => {
                let prefer = matches!(
                    f.namespace,
                    FileNamespace::Win32 | FileNamespace::Win32AndDos
                );
                if x30.is_none() || prefer {
                    x30 = Some(f);
                }
            }
            _ => {}
        }
    }
    (x10, x30)
}

fn iso(dt: &Timestamp) -> String {
    dt.strftime("%Y-%m-%dT%H:%M:%SZ").to_string()
}

fn parse_optional_iso(value: Option<&str>) -> Result<Option<Timestamp>, MftError> {
    value.map_or(Ok(None), |s| {
        s.parse::<Timestamp>()
            .map(Some)
            .map_err(|err| MftError::InvalidTimeFilter {
                value: s.to_string(),
                reason: err.to_string(),
            })
    })
}
