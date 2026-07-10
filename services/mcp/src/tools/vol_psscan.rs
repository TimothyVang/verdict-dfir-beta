//! `vol_psscan` — subprocess wrapper for Volatility 3's `windows.psscan`.
//!
//! Companion to `vol_pslist`. Where pslist walks the kernel's
//! `PsActiveProcessHead` linked list, **psscan scans the entire
//! memory image for `_EPROCESS` signatures**. The two are deliberately
//! redundant:
//!
//! * pslist is faster and produces clean output but is FOOLED by DKOM
//!   (Direct Kernel Object Manipulation) rootkits that unlink malicious
//!   processes from the active list.
//! * psscan is slower but catches orphaned `_EPROCESS` blocks that
//!   were unlinked from the active list but still exist in pool memory.
//!
//! **Divergence between the two outputs is itself the forensic
//! finding** — see `docs/false-positives.md`. A pslist=0 + psscan>0
//! result is the textbook MITRE ATT&CK T1014 (Rootkit) signature.
//!
//! Volatility invocation: `<vol> --offline -f <memory> -r json -q windows.psscan`.
//! Output schema is identical to pslist for shared fields.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::tools::proc_runner::{run_with_timeout, timeout_from_env_clamped, RunError};

const DEFAULT_LIMIT: usize = 10_000;
const TIMEOUT_ENV: &str = "FINDEVIL_VOL_TIMEOUT_SECS";
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(1800);
const HARD_TIMEOUT: Duration = Duration::from_secs(7200);

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VolPsscanInput {
    /// Case ID from a prior `case_open` call.
    pub case_id: String,

    /// Path to the memory image (`.mem`, `.raw`, `.dmp`, `.vmem`, `.img`).
    pub memory_path: PathBuf,

    /// Optional PID filter.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pid_filter: Option<Vec<u32>>,

    /// Hard cap on rows emitted. Default `10_000`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct VolPsscanProcess {
    /// Process ID.
    pub pid: u32,

    /// Parent process ID.
    pub ppid: u32,

    /// Process image name (e.g. `explorer.exe`, `lsass.exe`).
    pub image_name: String,

    /// Process creation time as UTC ISO-8601Z, when known.
    pub create_time_iso: Option<String>,

    /// Process exit time as UTC ISO-8601Z; `None` for live processes.
    pub exit_time_iso: Option<String>,

    /// Thread count.
    pub threads: u32,

    /// `_EPROCESS` virtual offset where psscan recovered this object.
    /// Diagnostic — useful for cross-referencing with manual analysis.
    pub offset_v: Option<u64>,

    /// Session ID.
    pub session_id: u32,

    /// True for 32-bit processes running under `WoW64`.
    pub wow64: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct VolPsscanOutput {
    pub processes: Vec<VolPsscanProcess>,

    /// Total processes Volatility's psscan recovered before our filter / limit.
    pub processes_seen: usize,

    /// Stderr tail (capped at 4096 bytes).
    pub stderr_tail: String,
}

#[derive(Debug, Error)]
pub enum VolPsscanError {
    #[error("memory image not found: {0}")]
    MemoryNotFound(PathBuf),

    #[error("memory image is not a regular file: {0}")]
    MemoryNotRegular(PathBuf),

    #[error(
        "volatility binary not on PATH (set $VOLATILITY_BIN to override). \
         Install: `pip install volatility3` or use the SIFT VM bundle."
    )]
    BinaryNotFound,

    #[error("volatility exited {exit_code}: {stderr}")]
    SubprocessFailed { exit_code: i32, stderr: String },

    #[error("volatility exceeded its {seconds} s time budget and was killed")]
    Timeout { seconds: u64 },

    #[error("volatility {stream} exceeded its {limit} byte capture limit and was killed")]
    OutputLimit { stream: String, limit: usize },

    #[error("could not parse volatility JSON output: {0}")]
    OutputParse(String),
}

/// Run Volatility's `windows.psscan` against a memory image.
///
/// # Errors
/// * [`VolPsscanError::MemoryNotFound`] / [`VolPsscanError::MemoryNotRegular`]
///   — filesystem path missing or not a file.
/// * [`VolPsscanError::BinaryNotFound`] — Volatility not on PATH and
///   `$VOLATILITY_BIN` unset.
/// * [`VolPsscanError::SubprocessFailed`] — Volatility returned non-zero.
/// * [`VolPsscanError::OutputParse`] — JSON output was malformed.
pub fn vol_psscan(input: &VolPsscanInput) -> Result<VolPsscanOutput, VolPsscanError> {
    if !input.memory_path.exists() {
        return Err(VolPsscanError::MemoryNotFound(input.memory_path.clone()));
    }
    if !input.memory_path.is_file() {
        return Err(VolPsscanError::MemoryNotRegular(input.memory_path.clone()));
    }

    let binary = resolve_binary()?;
    let limit = input.limit.unwrap_or(DEFAULT_LIMIT);

    let mut cmd = Command::new(&binary);
    cmd.args(crate::tools::vol_run::build_vol_args(
        &input.memory_path,
        "windows.psscan",
        None,
    ));

    let proc = run_with_timeout(
        cmd,
        timeout_from_env_clamped(TIMEOUT_ENV, DEFAULT_TIMEOUT, HARD_TIMEOUT),
    )
    .map_err(map_run_error)?;

    let stderr_tail = truncate_to(String::from_utf8_lossy(&proc.stderr).into_owned(), 4096);

    if !proc.status.success() {
        return Err(VolPsscanError::SubprocessFailed {
            exit_code: proc.status.code().unwrap_or(-1),
            stderr: stderr_tail,
        });
    }

    let stdout = String::from_utf8_lossy(&proc.stdout);
    parse_processes(
        stdout.as_ref(),
        input.pid_filter.as_deref(),
        limit,
        stderr_tail,
    )
}

fn map_run_error(error: RunError) -> VolPsscanError {
    match error {
        RunError::Spawn(error) if error.kind() == std::io::ErrorKind::NotFound => {
            VolPsscanError::BinaryNotFound
        }
        RunError::Timeout(duration) => VolPsscanError::Timeout {
            seconds: duration.as_secs(),
        },
        RunError::OutputLimit { stream, limit } => VolPsscanError::OutputLimit {
            stream: stream.to_string(),
            limit,
        },
        RunError::OutputQuota(error) => VolPsscanError::SubprocessFailed {
            exit_code: -1,
            stderr: error.to_string(),
        },
        RunError::Spawn(error) => VolPsscanError::SubprocessFailed {
            exit_code: -1,
            stderr: format!("spawn failed: {error}"),
        },
        RunError::Io(error) => VolPsscanError::SubprocessFailed {
            exit_code: -1,
            stderr: format!("io error: {error}"),
        },
        RunError::PipeStillOpen { streams } => VolPsscanError::SubprocessFailed {
            exit_code: -1,
            stderr: format!("inherited subprocess pipes remained open: {streams:?}"),
        },
        RunError::ChildTreeStillRunning => VolPsscanError::SubprocessFailed {
            exit_code: -1,
            stderr: "subprocess descendants remained alive after leader exit".to_string(),
        },
        RunError::ReaderPanicked => VolPsscanError::SubprocessFailed {
            exit_code: -1,
            stderr: "volatility output reader thread panicked".to_string(),
        },
    }
}

fn resolve_binary() -> Result<PathBuf, VolPsscanError> {
    if let Ok(env_path) = std::env::var("VOLATILITY_BIN") {
        let p = PathBuf::from(env_path);
        if p.is_file() {
            return Ok(p);
        }
    }
    if let Ok(path_var) = std::env::var("PATH") {
        let candidates: &[&str] = if cfg!(windows) {
            &["vol.exe", "volatility3.exe", "volatility.exe", "vol.py"]
        } else {
            &["vol", "volatility3", "volatility", "vol.py"]
        };
        for dir in std::env::split_paths(&path_var) {
            for name in candidates {
                let candidate = dir.join(name);
                if candidate.is_file() {
                    return Ok(candidate);
                }
            }
        }
    }
    Err(VolPsscanError::BinaryNotFound)
}

fn parse_processes(
    stdout: &str,
    pid_filter: Option<&[u32]>,
    limit: usize,
    stderr_tail: String,
) -> Result<VolPsscanOutput, VolPsscanError> {
    let trimmed = stdout.trim();
    if trimmed.is_empty() {
        return Ok(VolPsscanOutput {
            processes: Vec::new(),
            processes_seen: 0,
            stderr_tail,
        });
    }
    let raw: Vec<serde_json::Value> =
        serde_json::from_str(trimmed).map_err(|e| VolPsscanError::OutputParse(e.to_string()))?;

    let processes_seen = raw.len();
    let mut out = Vec::with_capacity(processes_seen.min(limit));
    for value in raw {
        let proc = json_value_to_process(&value);
        if let Some(filter) = pid_filter {
            if !filter.contains(&proc.pid) {
                continue;
            }
        }
        out.push(proc);
        if out.len() >= limit {
            break;
        }
    }

    Ok(VolPsscanOutput {
        processes: out,
        processes_seen,
        stderr_tail,
    })
}

/// Tolerant projection of one Volatility psscan row into our typed shape.
fn json_value_to_process(v: &serde_json::Value) -> VolPsscanProcess {
    let map = v.as_object().cloned().unwrap_or_default();
    let pick_u32 = |keys: &[&str]| -> u32 {
        for k in keys {
            if let Some(val) = map.get(*k) {
                if let Some(n) = val.as_u64() {
                    return u32::try_from(n).unwrap_or(0);
                }
                if let Some(s) = val.as_str() {
                    if let Ok(n) = s.parse::<u32>() {
                        return n;
                    }
                }
            }
        }
        0
    };
    let pick_str = |keys: &[&str]| -> Option<String> {
        for k in keys {
            if let Some(val) = map.get(*k) {
                if let Some(s) = val.as_str() {
                    if !s.is_empty() && s != "N/A" && s != "-" {
                        return Some(s.to_string());
                    }
                }
            }
        }
        None
    };
    let pick_u64 = |keys: &[&str]| -> Option<u64> {
        for k in keys {
            if let Some(val) = map.get(*k) {
                if let Some(n) = val.as_u64() {
                    return Some(n);
                }
                if let Some(s) = val.as_str() {
                    if let Some(stripped) = s.strip_prefix("0x") {
                        if let Ok(n) = u64::from_str_radix(stripped, 16) {
                            return Some(n);
                        }
                    }
                }
            }
        }
        None
    };

    VolPsscanProcess {
        pid: pick_u32(&["PID", "pid"]),
        ppid: pick_u32(&["PPID", "ppid"]),
        image_name: pick_str(&["ImageFileName", "ImageName", "image_name"]).unwrap_or_default(),
        create_time_iso: pick_str(&["CreateTime", "create_time"]),
        exit_time_iso: pick_str(&["ExitTime", "exit_time"]),
        threads: pick_u32(&["Threads", "threads"]),
        offset_v: pick_u64(&["Offset(V)", "offset_v", "Offset"]),
        session_id: pick_u32(&["SessionId", "session_id"]),
        wow64: map
            .get("Wow64")
            .or_else(|| map.get("wow64"))
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false),
    }
}

/// Cheap pre-flight: file path looks like a memory image.
#[must_use]
pub fn path_looks_like_memory(path: &Path) -> bool {
    path.extension().is_some_and(|e| {
        e.eq_ignore_ascii_case("mem")
            || e.eq_ignore_ascii_case("raw")
            || e.eq_ignore_ascii_case("dmp")
            || e.eq_ignore_ascii_case("vmem")
            || e.eq_ignore_ascii_case("lime")
            || e.eq_ignore_ascii_case("aff4")
            || e.eq_ignore_ascii_case("img")
    })
}

fn truncate_to(mut s: String, max: usize) -> String {
    if s.len() > max {
        let mut boundary = max;
        while boundary > 0 && !s.is_char_boundary(boundary) {
            boundary -= 1;
        }
        s.truncate(boundary);
        s.push_str("…[truncated]");
    }
    s
}
