//! The scrollable Findings list pane.
//!
//! One row per Finding: id, confidence tier (coloured), MITRE technique,
//! and a one-line description. Selection is driven by the shared
//! [`ListState`]. Presentation only — the list reflects the Findings the
//! case already recorded and re-orders nothing.

use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState};
use ratatui::Frame;

use crate::case::Finding;
use crate::ui::theme;

/// Render the Findings list into `area`, honouring the selection/scroll
/// carried by `state`.
pub fn render(frame: &mut Frame<'_>, area: Rect, findings: &[Finding], state: &mut ListState) {
    let title = format!(" Findings ({}) ", findings.len());
    let block = Block::default().borders(Borders::ALL).title(title);

    if findings.is_empty() {
        let empty = List::new(vec![ListItem::new(Line::from(Span::raw(
            "no findings in this case",
        )))])
        .block(block);
        frame.render_widget(empty, area);
        return;
    }

    let items: Vec<ListItem<'_>> = findings.iter().map(row).collect();
    let list = List::new(items)
        .block(block)
        .highlight_symbol("> ")
        .highlight_style(Style::default().add_modifier(Modifier::REVERSED));
    frame.render_stateful_widget(list, area, state);
}

fn row(finding: &Finding) -> ListItem<'static> {
    let confidence = finding
        .confidence
        .clone()
        .unwrap_or_else(|| "?".to_string());
    let id = finding
        .finding_id
        .clone()
        .unwrap_or_else(|| "?".to_string());
    let mitre = finding
        .mitre_technique
        .clone()
        .unwrap_or_else(|| "-".to_string());
    let description = finding
        .description
        .clone()
        .unwrap_or_else(|| "(no description)".to_string());

    let line = Line::from(vec![
        Span::styled(
            format!("{confidence:<12}"),
            Style::default().fg(theme::confidence_color(&confidence)),
        ),
        Span::styled(
            format!("{mitre:<12}"),
            Style::default().add_modifier(Modifier::DIM),
        ),
        Span::raw(format!("{id}  ")),
        Span::raw(one_line(&description)),
    ]);
    ListItem::new(line)
}

/// Collapse a possibly multi-line description to a single line for the row.
fn one_line(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}
