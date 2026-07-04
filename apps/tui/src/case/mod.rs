//! Case-directory loading and the typed model projected over the loose
//! `verdict.json` `Value`.
//!
//! The finalized-viewer surface ([`loader`] + [`model`]) reads the JSON a
//! completed run sealed. The Phase 2 live surface ([`audit_tail`], [`status`],
//! [`runner`]) follows a run that is still in flight — an incremental
//! `audit.jsonl` tail and `status.json` heartbeat, plus the pure launcher that
//! starts a run. Every module here is read-only: it renders or launches, it
//! never opens evidence or emits a Finding.

pub mod audit_tail;
pub mod loader;
pub mod model;
pub mod runner;
pub mod status;

pub use audit_tail::{AuditRecord, AuditTail, FileFollower};
pub use loader::{CaseBundle, LoadError};
pub use model::{ArtifactClass, ConfidenceTally, Finding, ManifestVerify};
pub use runner::DriveHandle;
pub use status::RunStatus;
