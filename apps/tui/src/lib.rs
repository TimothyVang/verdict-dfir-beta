//! `verdict-tui` — a read-only terminal viewer for a finished VERDICT case
//! directory.
//!
//! # Read-only by construction
//!
//! The viewer reads only the JSON a completed run wrote into a case
//! directory (`verdict.json` plus optional custody/coverage siblings). It
//! is **not** an MCP client: it never opens evidence, never resolves
//! `evidence_path`, never calls a forensic tool, and never emits or
//! upgrades a Finding. It is presentation only — it renders the scoped
//! verdict, Findings, and custody state the run already committed to.
//!
//! The crate exposes a library face so the snapshot tests can build the
//! [`case`] model and render frames headlessly, without a TTY.

// doc_markdown fires on the many DFIR identifiers that read fine as prose
// (verdict.json, tool_call_id, SHA-256, evidence_path); allow it crate-wide
// rather than backticking every mention.
#![allow(clippy::doc_markdown)]

pub mod app;
pub mod case;
pub mod cli;
pub mod discovery;
pub mod keymap;
pub mod runtime;
pub mod ui;

use std::error::Error;
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::app::{App, View};
use crate::case::CaseBundle;
use crate::cli::Args;

/// Run the viewer for a parsed invocation.
///
/// `--help` / `--version` / `--print` write to `out` and return; the
/// interactive path drives the real terminal. `cwd` is the directory used
/// to discover the repo root when no explicit case directory is given.
///
/// # Errors
/// Returns an error when no case directory can be resolved, when the
/// required `verdict.json` cannot be loaded, or on a terminal/IO failure.
pub fn run(args: &Args, cwd: &Path, out: &mut impl Write) -> Result<(), Box<dyn Error>> {
    if args.help {
        write!(out, "{}", cli::help_text())?;
        return Ok(());
    }
    if args.version {
        writeln!(out, "{}", cli::version_text())?;
        return Ok(());
    }

    let dir = resolve_case_dir(args, cwd)?;
    let case = CaseBundle::load(&dir)?;
    let mut app = App::new(case);
    if args.detail && app.finding_count() > 0 {
        app.view = View::Detail;
    }

    if args.print {
        let frame = ui::render_to_string(&mut app, args.width, args.height);
        write!(out, "{frame}")?;
        return Ok(());
    }

    runtime::run(&mut app)?;
    Ok(())
}

/// Resolve which case directory to open: the explicit argument, else the
/// newest case discovered under the allow-listed roots.
fn resolve_case_dir(args: &Args, cwd: &Path) -> Result<PathBuf, Box<dyn Error>> {
    if let Some(dir) = &args.case_dir {
        return Ok(dir.clone());
    }
    let repo = discovery::repo_root(cwd)
        .ok_or("could not locate the VERDICT repo root; pass a CASE_DIR explicitly")?;
    discovery::newest_case(&repo).ok_or_else(|| {
        "no case directory found under the allow-listed roots; pass a CASE_DIR explicitly".into()
    })
}
