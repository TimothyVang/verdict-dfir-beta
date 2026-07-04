//! Discover case directories under the allow-listed roots.
//!
//! Mirrors the dashboard's `apps/web/lib/audit-tail.ts` behaviour (repo
//! marker + allow-listed roots + newest-first) so the two surfaces agree
//! on where cases live, without porting the TypeScript. The TUI keys on
//! `verdict.json` (the file it renders) rather than the dashboard's
//! `audit.jsonl`. Discovery reads directory entries and file mtimes only;
//! it never opens evidence.

use std::path::{Path, PathBuf};
use std::time::SystemTime;

use crate::case::loader::VERDICT_FILE;

/// Files that jointly mark the VERDICT repo root, matching
/// `apps/web/lib/repo-root.ts`.
const REPO_MARKERS: [&str; 3] = [
    "scripts/doctor.sh",
    "apps/web/package.json",
    "pnpm-workspace.yaml",
];

/// Default allow-listed case roots, relative to the repo root. Mirrors the
/// dashboard's set plus `docs/sample-run` (the committed fixtures the TUI
/// ships with).
const DEFAULT_ALLOWED_ROOTS: [&str; 5] = [
    "goldens",
    "tmp/auto-runs",
    "tmp/smoke",
    "test-forensics",
    "docs/sample-run",
];

/// Env var (path-delimiter-separated) that appends extra allow-listed
/// roots without a code change. Shared with the dashboard.
const EXTRA_ROOTS_ENV: &str = "FINDEVIL_DASHBOARD_EXTRA_ROOTS";

/// Env var that pins the repo root explicitly (else it is discovered by
/// walking up from the current directory).
const REPO_ROOT_ENV: &str = "FINDEVIL_REPO_ROOT";

/// A discovered case directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaseEntry {
    pub path: PathBuf,
    pub name: String,
    pub mtime: SystemTime,
}

/// Resolve the repo root: `FINDEVIL_REPO_ROOT` when set and valid, else by
/// walking up from `start` until every [`REPO_MARKERS`] entry is present.
#[must_use]
pub fn repo_root(start: &Path) -> Option<PathBuf> {
    if let Some(pinned) = std::env::var_os(REPO_ROOT_ENV) {
        let dir = PathBuf::from(pinned);
        if has_repo_markers(&dir) {
            return Some(dir);
        }
    }
    let mut dir = start.to_path_buf();
    loop {
        if has_repo_markers(&dir) {
            return Some(dir);
        }
        if !dir.pop() {
            return None;
        }
    }
}

fn has_repo_markers(dir: &Path) -> bool {
    REPO_MARKERS.iter().all(|marker| dir.join(marker).exists())
}

/// Resolve the ordered list of allow-listed case roots (absolute).
#[must_use]
pub fn allowed_roots(repo_root: &Path) -> Vec<PathBuf> {
    let mut roots: Vec<PathBuf> = DEFAULT_ALLOWED_ROOTS
        .iter()
        .map(|rel| repo_root.join(rel))
        .collect();
    if let Some(extra) = std::env::var_os(EXTRA_ROOTS_ENV) {
        for entry in std::env::split_paths(&extra) {
            if entry.as_os_str().is_empty() {
                continue;
            }
            roots.push(if entry.is_absolute() {
                entry
            } else {
                repo_root.join(entry)
            });
        }
    }
    roots
}

/// List case directories (immediate children of the allow-listed roots
/// that contain a `verdict.json`), newest-first by that file's mtime.
#[must_use]
pub fn list_cases(repo_root: &Path) -> Vec<CaseEntry> {
    let mut out: Vec<CaseEntry> = Vec::new();
    let mut seen: Vec<PathBuf> = Vec::new();
    for root in allowed_roots(repo_root) {
        let Ok(entries) = std::fs::read_dir(&root) else {
            continue;
        };
        for entry in entries.flatten() {
            let dir = entry.path();
            if !dir.is_dir() || seen.contains(&dir) {
                continue;
            }
            let verdict = dir.join(VERDICT_FILE);
            let Ok(meta) = std::fs::metadata(&verdict) else {
                continue;
            };
            let mtime = meta.modified().unwrap_or(SystemTime::UNIX_EPOCH);
            let name = dir
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            seen.push(dir.clone());
            out.push(CaseEntry {
                path: dir,
                name,
                mtime,
            });
        }
    }
    out.sort_by(|a, b| b.mtime.cmp(&a.mtime));
    out
}

/// The newest case directory under the allow-listed roots, if any.
#[must_use]
pub fn newest_case(repo_root: &Path) -> Option<PathBuf> {
    list_cases(repo_root).into_iter().next().map(|c| c.path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::thread::sleep;
    use std::time::Duration;

    fn write_case(root: &Path, rel: &str, name: &str) -> PathBuf {
        let dir = root.join(rel).join(name);
        fs::create_dir_all(&dir).expect("mkdir case");
        fs::write(dir.join(VERDICT_FILE), "{}").expect("write verdict.json");
        dir
    }

    #[test]
    fn allowed_roots_include_defaults() {
        let repo = Path::new("/repo");
        let roots = allowed_roots(repo);
        assert!(roots.contains(&repo.join("goldens")));
        assert!(roots.contains(&repo.join("tmp/auto-runs")));
        assert!(roots.contains(&repo.join("docs/sample-run")));
    }

    #[test]
    fn lists_cases_newest_first_and_skips_non_cases() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let repo = tmp.path();
        let older = write_case(repo, "goldens", "old-case");
        sleep(Duration::from_millis(10));
        let newer = write_case(repo, "tmp/auto-runs", "new-case");
        // A directory without verdict.json must be ignored.
        fs::create_dir_all(repo.join("goldens/not-a-case")).expect("mkdir");

        let cases = list_cases(repo);
        let names: Vec<&str> = cases.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(names, vec!["new-case", "old-case"]);
        assert_eq!(newest_case(repo), Some(newer));
        assert!(cases.iter().any(|c| c.path == older));
    }

    #[test]
    fn newest_case_is_none_when_no_cases() {
        let tmp = tempfile::tempdir().expect("tempdir");
        assert!(newest_case(tmp.path()).is_none());
    }

    #[test]
    fn repo_root_walks_up_to_markers() {
        // Skip if the outer environment pins the repo root (the pin would
        // shadow the walk-up under test).
        if std::env::var_os(REPO_ROOT_ENV).is_some() {
            return;
        }
        let tmp = tempfile::tempdir().expect("tempdir");
        let repo = tmp.path();
        fs::create_dir_all(repo.join("scripts")).expect("mkdir scripts");
        fs::create_dir_all(repo.join("apps/web")).expect("mkdir apps/web");
        fs::write(repo.join("scripts/doctor.sh"), "#!/bin/sh\n").expect("marker");
        fs::write(repo.join("apps/web/package.json"), "{}").expect("marker");
        fs::write(repo.join("pnpm-workspace.yaml"), "packages: []\n").expect("marker");
        let nested = repo.join("apps/web/deep/nested");
        fs::create_dir_all(&nested).expect("mkdir nested");

        let found = repo_root(&nested).expect("repo root found");
        assert_eq!(
            found.canonicalize().expect("canon"),
            repo.canonicalize().expect("canon")
        );
    }
}
