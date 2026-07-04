//! Frame composition: header pane on top, the list or detail pane in the
//! body, a key-hint footer, and the optional help overlay.
//!
//! [`render_to_string`] draws one frame into a headless
//! [`TestBackend`](ratatui::backend::TestBackend) and returns its text —
//! the shared path used by the `--print` mode and the snapshot tests.

pub mod finding_detail;
pub mod findings_list;
pub mod help;
pub mod theme;
pub mod verdict_header;

use ratatui::backend::TestBackend;
use ratatui::buffer::Buffer;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::Span;
use ratatui::widgets::Paragraph;
use ratatui::{Frame, Terminal};

use crate::app::{App, View};

const FOOTER_HINT: &str = "q quit  |  Up/Down or j/k move  |  Enter open  |  Esc back  |  ? help";

/// Draw the whole viewer for the current [`App`] state into `frame`.
pub fn render(frame: &mut Frame<'_>, app: &mut App) {
    let area = frame.area();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(verdict_header::height()),
            Constraint::Min(1),
            Constraint::Length(1),
        ])
        .split(area);

    verdict_header::render(frame, chunks[0], &app.case);
    render_body(frame, chunks[1], app);
    render_footer(frame, chunks[2]);

    if app.show_help {
        help::render(frame, area);
    }
}

fn render_body(frame: &mut Frame<'_>, area: Rect, app: &mut App) {
    match app.view {
        View::List => {
            findings_list::render(frame, area, &app.case.findings, &mut app.list_state);
        }
        View::Detail => {
            let finding = app
                .list_state
                .selected()
                .and_then(|i| app.case.findings.get(i));
            finding_detail::render(frame, area, finding, app.detail_scroll);
        }
    }
}

fn render_footer(frame: &mut Frame<'_>, area: Rect) {
    let footer = Paragraph::new(Span::styled(
        FOOTER_HINT,
        Style::default().add_modifier(Modifier::DIM),
    ));
    frame.render_widget(footer, area);
}

/// Render one frame of `app` at `width`×`height` into a headless backend
/// and return the buffer as plain text (trailing spaces trimmed per row).
///
/// The `TestBackend` render path is infallible, so this returns the text
/// directly rather than a `Result`.
#[must_use]
pub fn render_to_string(app: &mut App, width: u16, height: u16) -> String {
    let backend = TestBackend::new(width, height);
    let mut terminal =
        Terminal::new(backend).expect("TestBackend terminal construction is infallible");
    terminal
        .draw(|frame| render(frame, app))
        .expect("TestBackend draw is infallible");
    buffer_to_string(terminal.backend().buffer())
}

/// Flatten a rendered [`Buffer`] to text: one line per row, trailing
/// whitespace trimmed, rows joined by `\n`.
#[must_use]
pub fn buffer_to_string(buffer: &Buffer) -> String {
    let area = buffer.area;
    let mut out = String::new();
    for y in 0..area.height {
        let mut line = String::new();
        for x in 0..area.width {
            if let Some(cell) = buffer.cell((x, y)) {
                line.push_str(cell.symbol());
            }
        }
        out.push_str(line.trim_end());
        out.push('\n');
    }
    out
}
