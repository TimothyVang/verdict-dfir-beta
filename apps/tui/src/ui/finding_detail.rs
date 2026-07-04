//! The Finding detail pane — the custody strip.
//!
//! Renders, in order: `tool_call_id` → replay expected-vs-actual SHA-256
//! (a real mismatch is highlighted red) → asserted values →
//! counter-hypothesis → `derived_from`. Everything shown is a value the
//! case already recorded; absent fields render as "absent", never a
//! fabricated value.

use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};
use ratatui::Frame;

use crate::case::Finding;
use crate::ui::theme;

const ABSENT: &str = "absent";

/// Render the detail pane for `finding` into `area`, scrolled by `scroll`
/// rows.
pub fn render(frame: &mut Frame<'_>, area: Rect, finding: Option<&Finding>, scroll: u16) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Finding detail — custody strip ");
    let lines = finding.map_or_else(
        || vec![Line::from(Span::raw("no finding selected"))],
        detail_lines,
    );
    let paragraph = Paragraph::new(lines)
        .block(block)
        .wrap(Wrap { trim: true })
        .scroll((scroll, 0));
    frame.render_widget(paragraph, area);
}

fn detail_lines(finding: &Finding) -> Vec<Line<'static>> {
    let mut lines = Vec::new();

    let confidence = finding
        .confidence
        .clone()
        .unwrap_or_else(|| "?".to_string());
    lines.push(Line::from(vec![
        Span::raw("Finding   "),
        Span::styled(
            finding.finding_id.clone().unwrap_or_else(|| ABSENT.into()),
            Style::default().add_modifier(Modifier::BOLD),
        ),
    ]));
    lines.push(Line::from(vec![
        Span::raw("Tier      "),
        Span::styled(
            confidence.clone(),
            Style::default().fg(theme::confidence_color(&confidence)),
        ),
        Span::raw("    MITRE "),
        Span::raw(
            finding
                .mitre_technique
                .clone()
                .unwrap_or_else(|| "-".into()),
        ),
    ]));
    lines.push(Line::from(Span::raw(
        finding
            .description
            .clone()
            .unwrap_or_else(|| "(no description)".into()),
    )));

    lines.push(Line::from(""));
    lines.push(section("Custody"));
    lines.push(field("tool_call_id", finding.tool_call_id.as_deref()));
    lines.push(field(
        "replay expected sha256",
        finding.replay_expected_sha256.as_deref(),
    ));
    lines.push(replay_actual_line(finding));
    if finding.replay_mismatch() {
        lines.push(Line::from(Span::styled(
            "  !! SHA-256 MISMATCH — replay does not reproduce the recorded output",
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        )));
    }
    lines.push(field(
        "replay matched",
        Some(matched_text(finding.replay_matched)),
    ));

    lines.push(Line::from(""));
    lines.push(section("Asserted values"));
    if finding.asserted_values.is_empty() {
        lines.push(indented(ABSENT));
    } else {
        for value in &finding.asserted_values {
            lines.push(indented(value));
        }
    }

    lines.push(Line::from(""));
    lines.push(section("Counter-hypothesis"));
    lines.push(indented(
        finding.counter_hypothesis.as_deref().unwrap_or(ABSENT),
    ));

    lines.push(Line::from(""));
    lines.push(section("Derived from"));
    if finding.derived_from.is_empty() {
        lines.push(indented(ABSENT));
    } else {
        lines.push(indented(&finding.derived_from.join(", ")));
    }

    lines
}

fn replay_actual_line(finding: &Finding) -> Line<'static> {
    let color = theme::replay_color(
        finding.replay_expected_sha256.as_deref(),
        finding.replay_actual_sha256.as_deref(),
    );
    Line::from(vec![
        Span::raw("  replay actual sha256   "),
        Span::styled(
            finding
                .replay_actual_sha256
                .clone()
                .unwrap_or_else(|| ABSENT.into()),
            Style::default().fg(color),
        ),
    ])
}

fn section(title: &str) -> Line<'static> {
    Line::from(Span::styled(
        title.to_string(),
        Style::default().add_modifier(Modifier::BOLD | Modifier::UNDERLINED),
    ))
}

fn field(label: &str, value: Option<&str>) -> Line<'static> {
    Line::from(vec![
        Span::raw(format!("  {label}   ")),
        Span::raw(value.unwrap_or(ABSENT).to_string()),
    ])
}

fn indented(text: &str) -> Line<'static> {
    Line::from(Span::raw(format!("  {text}")))
}

const fn matched_text(matched: Option<bool>) -> &'static str {
    match matched {
        Some(true) => "yes",
        Some(false) => "no",
        None => "?",
    }
}
