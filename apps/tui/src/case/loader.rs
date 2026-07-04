//! Load a finished case directory into an in-memory [`CaseBundle`].
//!
//! Only `verdict.json` is required; `coverage_manifest.json`,
//! `run.manifest.json` and `manifest_verify.json` are each independently
//! optional and render as "not produced by this run" when missing. The
//! loader reads exactly those four files inside the case directory and
//! nothing else — it never resolves or opens `verdict.evidence_path`, so
//! the viewer cannot touch evidence by construction.

use std::fs;
use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::case::model::{self, ArtifactClass, ConfidenceTally, Finding, ManifestVerify};

/// The four case-directory files the viewer reads. Evidence paths are
/// deliberately excluded.
pub const VERDICT_FILE: &str = "verdict.json";
pub const COVERAGE_FILE: &str = "coverage_manifest.json";
pub const RUN_MANIFEST_FILE: &str = "run.manifest.json";
pub const MANIFEST_VERIFY_FILE: &str = "manifest_verify.json";

/// Failure to load the required `verdict.json`. The optional siblings
/// never produce an error — their absence is a rendering state.
#[derive(Debug, thiserror::Error)]
pub enum LoadError {
    #[error("no verdict.json in case directory: {0}")]
    VerdictMissing(PathBuf),
    #[error("failed to read {path}: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse {path}: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
}

/// A loaded case, pre-projected into the shapes the UI renders. Holds the
/// projected data plus the case directory; the raw `verdict.json` `Value`
/// is retained for accessors the UI does not pre-compute.
#[derive(Debug, Clone)]
pub struct CaseBundle {
    pub dir: PathBuf,
    pub verdict_word: Option<String>,
    pub case_id: Option<String>,
    pub findings: Vec<Finding>,
    pub tally: Option<ConfidenceTally>,
    /// `None` when neither a sibling coverage manifest nor an embedded
    /// block was found. `Some(empty)` when a manifest existed but listed
    /// no classes.
    pub artifact_classes: Option<Vec<ArtifactClass>>,
    /// `None` when `manifest_verify.json` was absent.
    pub manifest_verify: Option<ManifestVerify>,
}

impl CaseBundle {
    /// Load the case directory at `dir`. Errors only when `verdict.json`
    /// is missing or unparseable.
    ///
    /// # Errors
    /// Returns [`LoadError`] when the required `verdict.json` cannot be
    /// read or parsed.
    pub fn load(dir: &Path) -> Result<Self, LoadError> {
        let verdict_path = dir.join(VERDICT_FILE);
        if !verdict_path.is_file() {
            return Err(LoadError::VerdictMissing(dir.to_path_buf()));
        }
        let verdict = read_json_required(&verdict_path)?;

        let coverage_value = read_json_optional(&dir.join(COVERAGE_FILE))
            .or_else(|| verdict.get("coverage_manifest").cloned());
        let artifact_classes = coverage_value.as_ref().map(model::artifact_classes);

        let manifest_verify = read_json_optional(&dir.join(MANIFEST_VERIFY_FILE))
            .as_ref()
            .map(model::manifest_verify);

        Ok(Self {
            dir: dir.to_path_buf(),
            verdict_word: model::verdict_word(&verdict),
            case_id: model::case_id(&verdict),
            findings: model::findings(&verdict),
            tally: model::confidence_tally(&verdict),
            artifact_classes,
            manifest_verify,
        })
    }

    /// The case directory's basename, used as the display title.
    #[must_use]
    pub fn display_name(&self) -> String {
        self.dir.file_name().map_or_else(
            || self.dir.to_string_lossy().into_owned(),
            |name| name.to_string_lossy().into_owned(),
        )
    }
}

/// Read a required JSON file, mapping IO/parse failures to [`LoadError`].
fn read_json_required(path: &Path) -> Result<Value, LoadError> {
    let text = fs::read_to_string(path).map_err(|source| LoadError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    serde_json::from_str(&text).map_err(|source| LoadError::Parse {
        path: path.to_path_buf(),
        source,
    })
}

/// Read an optional JSON file. A missing or malformed file yields `None`
/// rather than an error — the caller renders "not produced by this run".
fn read_json_optional(path: &Path) -> Option<Value> {
    let text = fs::read_to_string(path).ok()?;
    serde_json::from_str(&text).ok()
}
