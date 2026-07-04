//! The help overlay — a centred popup listing the key bindings and the
//! viewer's read-only doctrine.

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph};
use ratatui::Frame;

/// Render the help popup centred over the whole frame.
pub fn render(frame: &mut Frame<'_>, area: Rect) {
    let popup = centered_rect(60, 60, area);
    frame.render_widget(Clear, popup);
    let block = Block::default().borders(Borders::ALL).title(" Help ");
    frame.render_widget(Paragraph::new(lines()).block(block), popup);
}

fn lines() -> Vec<Line<'static>> {
    vec![
        binding("q / Ctrl-C", "quit"),
        binding("Up / k", "move up (list) or scroll up (detail)"),
        binding("Down / j", "move down (list) or scroll down (detail)"),
        binding("Enter / l", "open the selected Finding"),
        binding("Esc / h", "back to the list (or close this help)"),
        binding("?", "toggle this help"),
        Line::from(""),
        Line::from(Span::styled(
            "Read-only viewer.",
            Style::default().add_modifier(Modifier::BOLD),
        )),
        Line::from(Span::raw(
            "Renders a finished case directory only. It never opens",
        )),
        Line::from(Span::raw("evidence, calls a tool, or emits a Finding.")),
    ]
}

fn binding(keys: &str, description: &str) -> Line<'static> {
    Line::from(vec![
        Span::styled(
            format!("  {keys:<12}"),
            Style::default().add_modifier(Modifier::BOLD),
        ),
        Span::raw(description.to_string()),
    ])
}

/// A rectangle `percent_x` × `percent_y` of `area`, centred.
fn centered_rect(percent_x: u16, percent_y: u16, area: Rect) -> Rect {
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(area);
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(vertical[1])[1]
}
