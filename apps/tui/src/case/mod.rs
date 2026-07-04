//! Case-directory loading and the typed model projected over the loose
//! `verdict.json` `Value`.

pub mod loader;
pub mod model;

pub use loader::{CaseBundle, LoadError};
pub use model::{ArtifactClass, ConfidenceTally, Finding, ManifestVerify};
