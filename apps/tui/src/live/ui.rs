//! Render the Live monitor: a header with the run phase, `status.json` stage
//! and counters, and a kind tally, over a stream of the most recent audit
//! records.
//!
//! Presentation only, exactly like the finalized viewer: it shows the records
//! and counters the run reported, colours them for scanability, and never
//! derives a Finding or a verdict. Colour is styling, not a claim.

use ratatui::backend::TestBackend;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph};
use ratatui::{Frame, Terminal};

use crate::case::AuditRecord;
use crate::live::state::{LiveState, Phase};
use crate::ui::{buffer_to_string, theme};

const ABSENT: &str = "absent";

/// Audit kinds surfaced in the header tally, in stream order.
const TALLY_KINDS: [&str; 4] = [
    "tool_call_start",
    "tool_call_output",
    "finding_approved",
    "course_correction",
];

const FOOTER_HINT: &str =
    "q quit  |  live tail — auto-follows the run  |  hands off to the viewer on verdict.json";

/// Draw the whole Live monitor for `state` into `frame`.
pub fn render(frame: &mut Frame<'_>, state: &LiveState) {
    let area = frame.area();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(header_height()),
            Constraint::Min(1),
            Constraint::Length(1),
        ])
        .split(area);

    render_header(frame, chunks[0], state);
    render_stream(frame, chunks[1], state);
    render_footer(frame, chunks[2]);
}

/// The header's fixed row budget (three content rows plus two border rows).
#[must_use]
pub const fn header_height() -> u16 {
    5
}

fn render_header(frame: &mut Frame<'_>, area: Rect, state: &LiveState) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" VERDICT — live run monitor ");
    let paragraph = Paragraph::new(header_lines(state)).block(block);
    frame.render_widget(paragraph, area);
}

fn header_lines(state: &LiveState) -> Vec<Line<'static>> {
    vec![phase_line(state), stage_line(state), stream_line(state)]
}

fn phase_line(state: &LiveState) -> Line<'static> {
    let mut spans = vec![
        Span::raw("Case    "),
        Span::styled(
            state.display_name.clone(),
            Style::default().add_modifier(Modifier::BOLD),
        ),
        Span::raw("    "),
        Span::styled(
            state.phase.label().to_string(),
            Style::default()
                .fg(phase_color(state.phase))
                .add_modifier(Modifier::BOLD),
        ),
    ];
    if let Some(message) = &state.message {
        spans.push(Span::raw(format!("  ({message})")));
    }
    Line::from(spans)
}

fn stage_line(state: &LiveState) -> Line<'static> {
    let snapshot = state.status.as_ref();
    let stage_text = snapshot
        .and_then(|s| s.stage.clone())
        .unwrap_or_else(|| ABSENT.to_string());
    let tools = snapshot
        .and_then(|s| s.tool_calls)
        .map_or_else(|| ABSENT.to_string(), |n| n.to_string());
    let findings = snapshot
        .and_then(|s| s.findings_so_far)
        .map_or_else(|| ABSENT.to_string(), |n| n.to_string());
    let updated = snapshot
        .and_then(|s| s.updated_at.clone())
        .unwrap_or_else(|| ABSENT.to_string());
    Line::from(vec![
        Span::raw("Stage   "),
        Span::styled(stage_text, Style::default().add_modifier(Modifier::BOLD)),
        Span::raw(format!(
            "    tool_calls {tools}    findings_so_far {findings}    updated {updated}"
        )),
    ])
}

fn stream_line(state: &LiveState) -> Line<'static> {
    let mut spans = vec![Span::raw(format!(
        "Stream  {} records    ",
        state.total_records
    ))];
    let mut first = true;
    for kind in TALLY_KINDS {
        let count = state.count_of(kind);
        if count == 0 {
            continue;
        }
        if !first {
            spans.push(Span::raw("  ·  "));
        }
        first = false;
        spans.push(Span::styled(
            format!("{kind} {count}"),
            Style::default().fg(theme::audit_kind_color(kind)),
        ));
    }
    Line::from(spans)
}

fn render_stream(frame: &mut Frame<'_>, area: Rect, state: &LiveState) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(format!(" Audit stream ({} records) ", state.total_records));

    if state.records.is_empty() {
        let waiting = List::new(vec![ListItem::new(Line::from(Span::styled(
            "waiting for the first audit record ...",
            Style::default().add_modifier(Modifier::DIM),
        )))])
        .block(block);
        frame.render_widget(waiting, area);
        return;
    }

    // Auto-follow: show the most recent records that fit the body height
    // (two rows are borders). No scroll state — the tail is always in view.
    let visible = area.height.saturating_sub(2) as usize;
    let items: Vec<ListItem<'_>> = state.tail(visible).into_iter().map(record_row).collect();
    frame.render_widget(List::new(items).block(block), area);
}

fn record_row(record: &AuditRecord) -> ListItem<'static> {
    let seq = record
        .seq
        .map_or_else(|| "   -".to_string(), |n| format!("{n:>4}"));
    let mut spans = vec![
        Span::styled(seq, Style::default().add_modifier(Modifier::DIM)),
        Span::raw("  "),
        Span::styled(
            format!("{:<18}", record.kind),
            Style::default().fg(theme::audit_kind_color(&record.kind)),
        ),
    ];
    if let Some(tool) = &record.tool {
        spans.push(Span::raw(format!("{tool:<16}")));
    }
    if let Some(tcid) = &record.tool_call_id {
        spans.push(Span::raw(format!("{tcid}  ")));
    }
    if let Some(confidence) = &record.confidence {
        spans.push(Span::styled(
            format!("{confidence}  "),
            Style::default().fg(theme::confidence_color(confidence)),
        ));
    }
    if let Some(metric) = &record.metric {
        spans.push(Span::styled(
            metric.clone(),
            Style::default().add_modifier(Modifier::DIM),
        ));
    }
    ListItem::new(Line::from(spans))
}

fn render_footer(frame: &mut Frame<'_>, area: Rect) {
    let footer = Paragraph::new(Span::styled(
        FOOTER_HINT,
        Style::default().add_modifier(Modifier::DIM),
    ));
    frame.render_widget(footer, area);
}

const fn phase_color(phase: Phase) -> ratatui::style::Color {
    use ratatui::style::Color;
    match phase {
        Phase::Launching => Color::Yellow,
        Phase::Tailing => Color::Cyan,
        Phase::Completed => Color::Green,
        Phase::Failed => Color::Red,
    }
}

/// Render one Live frame at `width`×`height` into a headless backend and
/// return the buffer as plain text — the shared path for the snapshot test.
#[must_use]
pub fn render_to_string(state: &LiveState, width: u16, height: u16) -> String {
    let backend = TestBackend::new(width, height);
    let mut terminal =
        Terminal::new(backend).expect("TestBackend terminal construction is infallible");
    terminal
        .draw(|frame| render(frame, state))
        .expect("TestBackend draw is infallible");
    buffer_to_string(terminal.backend().buffer())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::case::RunStatus;

    fn record(kind: &str, tool: Option<&str>, tcid: Option<&str>) -> AuditRecord {
        AuditRecord {
            seq: Some(1),
            kind: kind.to_string(),
            tool: tool.map(ToString::to_string),
            tool_call_id: tcid.map(ToString::to_string),
            ..AuditRecord::default()
        }
    }

    #[test]
    fn waiting_state_renders_the_placeholder() {
        let state = LiveState::new("/case/tui-1");
        let frame = render_to_string(&state, 90, 20);
        assert!(frame.contains("LAUNCHING"));
        assert!(frame.contains("waiting for the first audit record"));
    }

    #[test]
    fn tailing_state_renders_records_and_stage() {
        let mut state = LiveState::new("/case/tui-1");
        state.set_status(Some(RunStatus {
            stage: Some("pool_a".into()),
            tool_calls: Some(3),
            findings_so_far: Some(1),
            ..RunStatus::default()
        }));
        state.ingest(vec![
            record("tool_call_start", Some("evtx_query"), Some("tc-001")),
            record("tool_call_output", None, Some("tc-001")),
        ]);
        let frame = render_to_string(&state, 90, 20);
        assert!(frame.contains("LIVE"));
        assert!(frame.contains("pool_a"));
        assert!(frame.contains("evtx_query"));
        assert!(frame.contains("tc-001"));
    }
}
