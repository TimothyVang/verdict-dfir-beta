//! The interactive live loop: launch or attach to a run, tail its case
//! directory, and hand off to the finalized viewer when it seals.
//!
//! This is a TTY-touching module (like [`crate::runtime`]), so its logic is
//! exercised by manual/best-effort runs rather than snapshot tests; the tested
//! pieces are the incremental tail ([`crate::case::audit_tail`]), the state
//! reducer ([`crate::live::state`]), and the pure render
//! ([`crate::live::ui`]).
//!
//! # Correctness does not depend on `notify`
//!
//! The loop re-reads the growing `audit.jsonl` and `status.json` on a fixed
//! tick, so a record is never dropped even if the filesystem watcher misses or
//! debounces an event. `notify` is attached once the case directory exists and
//! its events are drained as a "something changed" hint — a latency aid layered
//! on top of the robust poll, never the source of truth.

use std::io;
use std::path::Path;
use std::sync::mpsc::{channel, Receiver};
use std::time::Duration;

use notify::{RecommendedWatcher, RecursiveMode, Watcher};
use ratatui::crossterm::event::{self, Event, KeyEventKind};

use crate::app::App;
use crate::case::runner::{self, DriveHandle};
use crate::case::{audit_tail::FileFollower, status, AuditRecord, CaseBundle};
use crate::keymap::{action_for, Action};
use crate::live::state::{self, LiveState};
use crate::live::ui;
use crate::runtime;

/// The audit filename inside a case directory.
const AUDIT_FILE: &str = "audit.jsonl";

/// Poll cadence: bounds append latency and refreshes status/completion.
const TICK: Duration = Duration::from_millis(120);

/// Launch `scripts/verdict <evidence>` from `repo_root`, then live-tail the
/// case directory it creates, handing off to the finalized viewer on seal.
///
/// # Errors
/// Propagates a launcher-spawn or terminal error.
pub fn drive(evidence: &Path, repo_root: &Path) -> io::Result<()> {
    // Ensure the case ROOT exists so the tail and the launcher agree on it.
    // The case directory itself is left for the launcher to create — it
    // refuses a pre-existing one.
    let _ = std::fs::create_dir_all(repo_root.join(runner::CASE_ROOT_REL));

    let case_id = runner::drive_case_id();
    let handle = runner::spawn_drive(repo_root, evidence, &case_id)?;
    let mut live = LiveState::new(handle.case_dir());
    live.set_message("launching scripts/verdict");
    run_session(&mut live, Some(handle))
}

/// Attach to an already-running (or finished) case directory and live-tail it.
///
/// # Errors
/// Propagates a terminal error.
pub fn follow(case_dir: &Path) -> io::Result<()> {
    let mut live = LiveState::new(case_dir);
    run_session(&mut live, None)
}

/// Own one terminal session for the whole lifecycle: the live tail, then the
/// finalized viewer if the run sealed. Restores the terminal unconditionally.
fn run_session(live: &mut LiveState, child: Option<DriveHandle>) -> io::Result<()> {
    let mut terminal = runtime::init()?;
    let result = (|| -> io::Result<()> {
        if let Some(bundle) = live_loop(&mut terminal, live, child)? {
            let mut app = App::new(bundle);
            runtime::event_loop(&mut terminal, &mut app)?;
        }
        Ok(())
    })();
    let restore = runtime::restore(&mut terminal);
    result.and(restore)
}

/// The live tail loop. Returns the loaded [`CaseBundle`] when the run seals
/// (hand off to the finalized viewer), or `None` when the operator quits.
fn live_loop(
    terminal: &mut runtime::Tui,
    live: &mut LiveState,
    mut child: Option<DriveHandle>,
) -> io::Result<Option<CaseBundle>> {
    let mut tailer = LiveTailer::new(live.case_dir.join(AUDIT_FILE), live.case_dir.clone());
    // `settled` freezes the run-polling once the launcher failed: the FAILED
    // frame stays up until the operator quits, so they see why.
    let mut settled = false;

    loop {
        terminal.draw(|frame| ui::render(frame, live))?;

        // Key events, with the tick doubling as the idle timeout.
        if event::poll(TICK)? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press && action_for(key) == Action::Quit {
                    return Ok(None);
                }
            }
        }

        if settled {
            continue;
        }

        // Robust poll (correctness): attach the watcher once the dir exists,
        // drain its change hints, then re-read the tail and status regardless.
        tailer.attach(live);
        tailer.drain_hints();
        live.ingest(tailer.poll());
        live.set_status(status::read_status(&live.case_dir));

        // Completion: the sealed verdict.json is the hand-off signal. A
        // half-written file fails to load — keep polling until it is whole.
        if state::verdict_ready(&live.case_dir) {
            live.ingest(tailer.poll());
            if let Ok(bundle) = CaseBundle::load(&live.case_dir) {
                live.mark_completed();
                return Ok(Some(bundle));
            }
        }

        // Failure: the launcher exited without sealing a verdict.
        if let Some(handle) = child.as_mut() {
            if let Ok(Some(exit)) = handle.try_wait() {
                if !state::verdict_ready(&live.case_dir) {
                    live.mark_failed(format!(
                        "launcher exited ({exit}) without sealing verdict.json \
                         — run scripts/verdict directly for its log"
                    ));
                    settled = true;
                }
                child = None;
            }
        }
    }
}

/// Couples the poll-based [`FileFollower`] with an optional `notify` watcher.
/// The follower is the source of truth; the watcher only signals "poll now".
struct LiveTailer {
    follower: FileFollower,
    watch_dir: std::path::PathBuf,
    watcher: Option<RecommendedWatcher>,
    hints: Option<Receiver<()>>,
}

impl LiveTailer {
    fn new(audit_path: std::path::PathBuf, watch_dir: std::path::PathBuf) -> Self {
        Self {
            follower: FileFollower::new(audit_path),
            watch_dir,
            watcher: None,
            hints: None,
        }
    }

    /// Attach the watcher to the case directory once it exists. Best-effort:
    /// on any failure the loop keeps working from the poll alone.
    fn attach(&mut self, live: &mut LiveState) {
        if self.watcher.is_some() || !self.watch_dir.is_dir() {
            return;
        }
        let (tx, rx) = channel();
        let handler = move |result: notify::Result<notify::Event>| {
            if result.is_ok() {
                // Best-effort: a full/closed channel just means the loop is
                // already polling; the tick still covers correctness.
                let _ = tx.send(());
            }
        };
        if let Ok(mut watcher) = notify::recommended_watcher(handler) {
            if watcher
                .watch(&self.watch_dir, RecursiveMode::NonRecursive)
                .is_ok()
            {
                self.watcher = Some(watcher);
                self.hints = Some(rx);
                if live.message.as_deref() == Some("launching scripts/verdict") {
                    live.set_message("tailing the case directory");
                }
            }
        }
    }

    /// Drain any pending change hints (non-blocking). The return value is
    /// advisory — the caller polls the follower unconditionally either way.
    fn drain_hints(&self) {
        if let Some(rx) = &self.hints {
            while rx.try_recv().is_ok() {}
        }
    }

    /// Read newly appended records. A transient IO error yields an empty
    /// batch and is retried on the next tick.
    fn poll(&mut self) -> Vec<AuditRecord> {
        self.follower.poll().unwrap_or_default()
    }
}
