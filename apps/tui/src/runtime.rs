//! The interactive terminal loop.
//!
//! Sets up raw mode + the alternate screen, then draws and reads key
//! events until the user quits, restoring the terminal on the way out
//! (even on error). This is the one module that touches a real TTY, so it
//! is exercised by manual/smoke runs rather than snapshot tests; the pure
//! render path in [`crate::ui`] carries the tested logic.
//!
//! The terminal lifecycle is exposed as [`init`] / [`restore`] /
//! [`event_loop`] so the Phase 2 live driver can reuse one terminal session
//! across the live tail and the finalized-viewer hand-off — no flicker from a
//! second alternate-screen enter.

use std::io::{self, Stdout};

use ratatui::backend::CrosstermBackend;
use ratatui::crossterm::event::{self, Event, KeyEventKind};
use ratatui::crossterm::execute;
use ratatui::crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::Terminal;

use crate::app::App;
use crate::keymap::action_for;
use crate::ui;

/// The concrete terminal type the crate drives (crossterm over stdout).
pub type Tui = Terminal<CrosstermBackend<Stdout>>;

/// Run the interactive finalized viewer to completion, restoring the
/// terminal before returning.
///
/// # Errors
/// Propagates terminal setup, draw, or event-read errors.
pub fn run(app: &mut App) -> io::Result<()> {
    let mut terminal = init()?;
    let result = event_loop(&mut terminal, app);
    // Restore unconditionally so a mid-loop error does not leave the
    // terminal in raw mode / the alternate screen.
    let restore_result = restore(&mut terminal);
    result.and(restore_result)
}

/// Drive the finalized-viewer draw/read loop on an already-initialized
/// terminal until the user quits.
///
/// # Errors
/// Propagates draw or event-read errors.
pub fn event_loop(terminal: &mut Tui, app: &mut App) -> io::Result<()> {
    loop {
        terminal.draw(|frame| ui::render(frame, app))?;
        if let Event::Key(key) = event::read()? {
            if key.kind == KeyEventKind::Press {
                app.apply(action_for(key));
            }
        }
        if app.should_quit {
            return Ok(());
        }
    }
}

/// Enter raw mode + the alternate screen and build the terminal.
///
/// # Errors
/// Propagates a terminal setup failure.
pub fn init() -> io::Result<Tui> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    Terminal::new(CrosstermBackend::new(stdout))
}

/// Leave the alternate screen, disable raw mode, and restore the cursor.
///
/// # Errors
/// Propagates a terminal restore failure.
pub fn restore(terminal: &mut Tui) -> io::Result<()> {
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()
}
