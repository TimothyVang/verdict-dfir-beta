//! `setupapi_parse` — USB / removable-storage install events from setupapi logs.
//!
//! Windows `setupapi.dev.log` and `setupapi.app.log` (under `Windows\inf`) record
//! `PnP` device installs with section headers and start timestamps. USBSTOR
//! registry keys can be empty or sparse on some images while setupapi still
//! holds insertion history — a useful secondary source for removable-media
//! leads.
//!
//! This tool is deliberately conservative: it only surfaces section headers that
//! mention USB mass-storage / USB VID paths / WPDBUSENUM, plus optional section-
//! start timestamps. It never invents serials, never claims data transfer, and
//! sorts/dedupes so `verify_finding` replay is deterministic. Cap events so a
//! multi-MB noisy log cannot bloat the audit chain.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Refuse pathological multi-GB paths; real setupapi logs are far smaller.
const MAX_FILE_BYTES: u64 = 32 * 1024 * 1024;
/// Hard cap on scanned text (header/metadata lives early; tail is noise).
const MAX_READ_BYTES: usize = 2 * 1024 * 1024;
/// Default / hard cap on returned USB events.
const DEFAULT_LIMIT: usize = 40;
const MAX_LIMIT: usize = 200;

const USB_TELLS: &[&str] = &["usbstor", "usb\\vid_", "usb\\root_hub", "swd\\wpdbusen"];

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SetupapiParseInput {
    /// Case ID from a prior `case_open` call. Audit correlation only.
    pub case_id: String,
    /// Path to `setupapi.dev.log` or `setupapi.app.log`.
    pub artifact_path: PathBuf,
    /// Maximum USB events returned (post-dedupe). Defaults to 40.
    #[serde(default = "default_limit")]
    pub limit: usize,
}

const fn default_limit() -> usize {
    DEFAULT_LIMIT
}

#[derive(Clone, Debug, Serialize)]
pub struct SetupapiUsbEvent {
    /// Section header text identifying the device install.
    pub device: String,
    /// Section start time if present, rewritten toward ISO-like UTC form.
    pub install_time_iso: Option<String>,
    /// First matching content line under the section (truncated).
    pub sample_line: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct SetupapiParseOutput {
    pub case_id: String,
    pub artifact_path: PathBuf,
    /// USB / removable-storage install events, sorted by device then time.
    pub events: Vec<SetupapiUsbEvent>,
    /// Uncapped count of unique USB section headers seen before the limit.
    pub events_seen: usize,
    /// Bytes of log text considered.
    pub bytes_read: usize,
}

#[derive(Debug, Error)]
pub enum SetupapiParseError {
    #[error("artifact not found: {0}")]
    ArtifactNotFound(String),
    #[error("not a regular file: {0}")]
    NotRegular(String),
    #[error("file too large ({0} bytes); refuse to load")]
    TooLarge(u64),
    #[error("read error: {0}")]
    Read(String),
}

/// True when the path basename is a known setupapi device log.
#[must_use]
pub fn path_looks_like_setupapi(path: &Path) -> bool {
    let name = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    name == "setupapi.dev.log" || name == "setupapi.app.log"
}

/// Parse a setupapi log for USB device-install section events.
pub fn setupapi_parse(
    input: &SetupapiParseInput,
) -> Result<SetupapiParseOutput, SetupapiParseError> {
    let path = &input.artifact_path;
    let meta = fs::metadata(path)
        .map_err(|_| SetupapiParseError::ArtifactNotFound(path.display().to_string()))?;
    if !meta.is_file() {
        return Err(SetupapiParseError::NotRegular(path.display().to_string()));
    }
    if meta.len() > MAX_FILE_BYTES {
        return Err(SetupapiParseError::TooLarge(meta.len()));
    }

    let raw = fs::read(path).map_err(|e| SetupapiParseError::Read(e.to_string()))?;
    let take = raw.len().min(MAX_READ_BYTES);
    let text = String::from_utf8_lossy(&raw[..take]);

    let limit = input.limit.clamp(1, MAX_LIMIT);
    let (events, seen) = parse_usb_events(&text, limit);

    Ok(SetupapiParseOutput {
        case_id: input.case_id.clone(),
        artifact_path: path.clone(),
        events,
        events_seen: seen,
        bytes_read: take,
    })
}

fn parse_usb_events(text: &str, limit: usize) -> (Vec<SetupapiUsbEvent>, usize) {
    let mut current_header: Option<String> = None;
    let mut current_ts: Option<String> = None;
    let mut seen_keys: BTreeSet<String> = BTreeSet::new();
    let mut events: Vec<SetupapiUsbEvent> = Vec::new();
    let mut events_seen: usize = 0;

    for raw_line in text.lines() {
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(header) = parse_section_header(line) {
            current_header = Some(header);
            current_ts = None;
            continue;
        }
        if let Some(ts) = parse_section_start(line) {
            current_ts = Some(ts);
            continue;
        }
        let Some(header) = current_header.as_ref() else {
            continue;
        };
        let blob = format!("{header} {line}").to_ascii_lowercase();
        if !USB_TELLS.iter().any(|t| blob.contains(t)) {
            continue;
        }
        let key = header.to_ascii_lowercase();
        if !seen_keys.insert(key) {
            continue;
        }
        events_seen += 1;
        if events.len() < limit {
            events.push(SetupapiUsbEvent {
                device: header.chars().take(300).collect(),
                install_time_iso: current_ts.clone(),
                sample_line: line.chars().take(200).collect(),
            });
        }
    }

    events.sort_by(|a, b| {
        a.device
            .cmp(&b.device)
            .then_with(|| a.install_time_iso.cmp(&b.install_time_iso))
    });

    (events, events_seen)
}

/// `>>>  [Device Install ...]`
fn parse_section_header(line: &str) -> Option<String> {
    let trimmed = line.trim_start();
    if !trimmed.starts_with(">>>") {
        return None;
    }
    let rest = trimmed.trim_start_matches('>').trim_start();
    let start = rest.find('[')?;
    let end = rest.find(']')?;
    if end <= start + 1 {
        return None;
    }
    Some(rest[start + 1..end].trim().to_string())
}

/// `>>>  Section start 2004/08/26 12:00:00.000` → `2004-08-26T12:00:00Z`
fn parse_section_start(line: &str) -> Option<String> {
    let lower = line.to_ascii_lowercase();
    let idx = lower.find("section start")?;
    let after = line[idx + "section start".len()..].trim();
    // YYYY/MM/DD HH:MM:SS...
    let mut parts = after.split_whitespace();
    let date = parts.next()?;
    let time = parts.next()?.split('.').next()?;
    if date.len() != 10 || !date.contains('/') {
        return None;
    }
    Some(format!("{}T{}Z", date.replace('/', "-"), time))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn sample_log() -> String {
        r"
>>>  [Device Install (Hardware initiated) - USBSTOR\Disk&Ven_X&Prod_Y\SERIAL123]
>>>  Section start 2004/08/26 12:00:00.000
     inf:      Opened PNF: 'C:\WINDOWS\inf\usbstor.inf'
>>>  [Device Install - USB\VID_0781&PID_5151\...]
>>>  Section start 2004/08/26 12:01:00.000
     sto:      Device is USB mass storage
>>>  [Device Install - PCI\VEN_8086]
>>>  Section start 2004/08/26 12:02:00.000
     inf:      not a usb row
"
        .to_string()
    }

    #[test]
    fn parse_extracts_usb_sections_only() {
        let (events, seen) = parse_usb_events(&sample_log(), 40);
        assert_eq!(seen, 2);
        assert_eq!(events.len(), 2);
        assert!(events.iter().any(|e| e.device.contains("USBSTOR")));
        assert!(events.iter().any(|e| e.device.contains("VID_0781")));
        assert!(events.iter().all(|e| e
            .install_time_iso
            .as_deref()
            .is_some_and(|t| t.ends_with('Z'))));
        assert!(!events.iter().any(|e| e.device.contains("PCI")));
    }

    #[test]
    fn setupapi_parse_reads_file() {
        let mut f = NamedTempFile::new().unwrap();
        write!(f, "{}", sample_log()).unwrap();
        let input = SetupapiParseInput {
            case_id: "case-test".into(),
            artifact_path: f.path().to_path_buf(),
            limit: 10,
        };
        let out = setupapi_parse(&input).unwrap();
        assert_eq!(out.events_seen, 2);
        assert_eq!(out.events.len(), 2);
        assert!(path_looks_like_setupapi(Path::new(
            "Windows/inf/setupapi.dev.log"
        )));
        assert!(!path_looks_like_setupapi(Path::new(
            "Windows/inf/other.log"
        )));
    }

    #[test]
    fn missing_file_is_not_found() {
        let input = SetupapiParseInput {
            case_id: "case-test".into(),
            artifact_path: PathBuf::from("/no/such/setupapi.dev.log"),
            limit: 10,
        };
        let err = setupapi_parse(&input).unwrap_err();
        assert!(matches!(err, SetupapiParseError::ArtifactNotFound(_)));
    }
}
