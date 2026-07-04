//! Drive mode: launch `scripts/verdict` and hand back the case directory it
//! will write into, so the caller can live-tail the run.
//!
//! # A pure launcher, not an engine
//!
//! This module is the *only* place in the crate that spawns a subprocess, and
//! it spawns exactly one program — the repo's own `scripts/verdict` launcher
//! ([`VERDICT_LAUNCHER`]). It re-implements none of the investigation: it does
//! not open evidence, drive an MCP tool, parse an artifact, or emit a Finding.
//! It forwards the operator-supplied evidence path to the launcher as an
//! opaque argument (the launcher, engine, and typed MCP tools do the
//! forensics) and then only ever *reads* the case directory the launcher
//! creates. The evidence path is never opened here — it is passed through
//! untouched.
//!
//! Because the case id is pinned up front, the case directory is known before
//! the run starts, so the tail can attach immediately — the same trick the
//! launcher uses to open the dashboard "LIVE" before `case_open`.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

/// The one and only program this crate ever spawns, relative to the repo root.
///
/// The read-only smoke (`scripts/tui-smoke.py`) keys on this constant to prove
/// the subprocess surface is the launcher and nothing else.
pub const VERDICT_LAUNCHER: &str = "scripts/verdict";

/// Where `scripts/verdict` writes a case directory, relative to the repo root.
pub const CASE_ROOT_REL: &str = "tmp/auto-runs";

/// A pinned, launcher-safe case id, unique per launch.
///
/// The basename satisfies the launcher's `safe_case_id` rule (alnum-led, then
/// `[alnum_.+-]`) and is made unique with wall-clock millis plus the pid.
#[must_use]
pub fn drive_case_id() -> String {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    format!("tui-{millis}-{pid}", pid = std::process::id())
}

/// The case directory `scripts/verdict --case-id <case_id>` will create.
#[must_use]
pub fn expected_case_dir(repo_root: &Path, case_id: &str) -> PathBuf {
    repo_root.join(CASE_ROOT_REL).join(case_id)
}

/// A launched drive run: the child process plus the case directory it writes.
#[derive(Debug)]
pub struct DriveHandle {
    child: Child,
    case_dir: PathBuf,
    case_id: String,
}

impl DriveHandle {
    /// The case directory the run writes into (the tail target).
    #[must_use]
    pub fn case_dir(&self) -> &Path {
        &self.case_dir
    }

    /// The pinned case id.
    #[must_use]
    pub fn case_id(&self) -> &str {
        &self.case_id
    }

    /// Poll the launcher without blocking. `Ok(Some(status))` once it exits.
    ///
    /// # Errors
    /// Propagates a failure to reap the child process.
    pub fn try_wait(&mut self) -> std::io::Result<Option<ExitStatus>> {
        self.child.try_wait()
    }
}

/// Spawn `scripts/verdict <evidence> --case-id <case_id>` from `repo_root` and
/// return a handle to the run.
///
/// The child's stdout/stderr are discarded — the run's own `audit.jsonl` and
/// `status.json`, which the caller tails, are the live surface; the launcher's
/// console log would otherwise clobber the alternate screen. The child is left
/// to run to completion if the viewer exits: a real investigation seals a
/// signed manifest of its own accord, and the launcher owns its custody/exit
/// handling, so the viewer never kills it mid-run.
///
/// # Errors
/// Returns an IO error if the launcher script is missing or cannot be spawned.
pub fn spawn_drive(
    repo_root: &Path,
    evidence: &Path,
    case_id: &str,
) -> std::io::Result<DriveHandle> {
    let program = repo_root.join(VERDICT_LAUNCHER);
    let child = Command::new(&program)
        .arg(evidence)
        .arg("--case-id")
        .arg(case_id)
        .arg("--no-dashboard")
        .current_dir(repo_root)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    Ok(DriveHandle {
        child,
        case_dir: expected_case_dir(repo_root, case_id),
        case_id: case_id.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn case_id_is_launcher_safe() {
        let id = drive_case_id();
        assert!(id.starts_with("tui-"));
        // safe_case_id: alnum-led, then [alnum _ . + -].
        let mut chars = id.chars();
        let first = chars.next().expect("non-empty");
        assert!(first.is_ascii_alphanumeric() || first == '_');
        assert!(id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '+' | '-')));
    }

    #[test]
    fn expected_case_dir_is_under_the_case_root() {
        let dir = expected_case_dir(Path::new("/repo"), "tui-1-2");
        assert_eq!(dir, PathBuf::from("/repo/tmp/auto-runs/tui-1-2"));
    }

    #[test]
    fn launcher_constant_is_the_verdict_script() {
        assert_eq!(VERDICT_LAUNCHER, "scripts/verdict");
    }
}
