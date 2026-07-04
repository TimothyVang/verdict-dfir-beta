//! The Verdict header pane: the scoped verdict word, the confidence
//! tally, the offline custody light, and coverage.
//!
//! Presentation only. It renders the verdict word and counts the case
//! already committed to — it never re-derives a verdict, upgrades a
//! confidence tier, or turns absent coverage into a clean bill of health.
//! Absent optional data renders as "not produced by this run".

use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};
use ratatui::Frame;

use crate::case::{CaseBundle, ManifestVerify};
use crate::ui::theme;

const ABSENT: &str = "absent";
const NOT_PRODUCED: &str = "not produced by this run";

/// Render the header into `area`.
pub fn render(frame: &mut Frame<'_>, area: Rect, case: &CaseBundle) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" VERDICT — read-only case viewer ");
    let paragraph = Paragraph::new(lines(case))
        .block(block)
        .wrap(Wrap { trim: true });
    frame.render_widget(paragraph, area);
}

/// The header's fixed row budget (including the two border rows).
#[must_use]
pub const fn height() -> u16 {
    9
}

fn lines(case: &CaseBundle) -> Vec<Line<'static>> {
    vec![
        case_line(case),
        verdict_line(case),
        tally_line(case),
        custody_line(case.manifest_verify.as_ref()),
        coverage_line(case),
    ]
}

fn case_line(case: &CaseBundle) -> Line<'static> {
    Line::from(vec![
        Span::raw("Case    "),
        Span::styled(
            case.display_name(),
            Style::default().add_modifier(Modifier::BOLD),
        ),
        Span::raw("    case_id "),
        Span::raw(case.case_id.clone().unwrap_or_else(|| ABSENT.to_string())),
    ])
}

fn verdict_line(case: &CaseBundle) -> Line<'static> {
    let word = case
        .verdict_word
        .clone()
        .unwrap_or_else(|| ABSENT.to_string());
    let color = theme::verdict_color(&word);
    Line::from(vec![
        Span::raw("Verdict "),
        Span::styled(
            word,
            Style::default().fg(color).add_modifier(Modifier::BOLD),
        ),
        Span::raw(format!("    Findings {}", case.findings.len())),
    ])
}

fn tally_line(case: &CaseBundle) -> Line<'static> {
    let Some(tally) = case.tally.as_ref() else {
        return Line::from(vec![Span::raw("Tally   "), Span::raw(NOT_PRODUCED)]);
    };
    let mut spans = vec![Span::raw("Tally   ")];
    for (index, (tier, count)) in tally.counts.iter().enumerate() {
        if index > 0 {
            spans.push(Span::raw("  ·  "));
        }
        spans.push(Span::styled(
            format!("{tier} {count}"),
            Style::default().fg(theme::confidence_color(tier)),
        ));
    }
    Line::from(spans)
}

fn custody_line(verify: Option<&ManifestVerify>) -> Line<'static> {
    let Some(verify) = verify else {
        return Line::from(vec![
            Span::raw("Custody "),
            Span::raw(format!("manifest_verify.json {NOT_PRODUCED}")),
        ]);
    };
    let overall = verify.overall;
    let signature = verify
        .signature_kind
        .clone()
        .unwrap_or_else(|| ABSENT.to_string());
    Line::from(vec![
        Span::raw("Custody "),
        Span::styled(
            format!("overall {}", tri_state(overall)),
            Style::default().fg(theme::bool_light_color(overall)),
        ),
        Span::raw(format!(
            "    signature {signature}  present {}  verified {}",
            tri_state(verify.signature_present),
            tri_state(verify.signature_verified),
        )),
    ])
}

fn coverage_line(case: &CaseBundle) -> Line<'static> {
    let Some(classes) = case.artifact_classes.as_ref() else {
        return Line::from(vec![
            Span::raw("Cover   "),
            Span::raw(format!("coverage manifest {NOT_PRODUCED}")),
        ]);
    };
    if classes.is_empty() {
        return Line::from(vec![
            Span::raw("Cover   "),
            Span::raw("no artifact classes recorded"),
        ]);
    }
    let mut spans = vec![Span::raw("Cover   ")];
    for (index, class) in classes.iter().enumerate() {
        if index > 0 {
            spans.push(Span::raw("  ·  "));
        }
        let name = class.name.clone().unwrap_or_else(|| "?".to_string());
        let status = class.status.clone().unwrap_or_else(|| "?".to_string());
        spans.push(Span::raw(format!("{name}=")));
        spans.push(Span::styled(
            status.clone(),
            Style::default().fg(theme::coverage_status_color(&status)),
        ));
    }
    Line::from(spans)
}

/// Render a tri-state boolean as `yes` / `no` / `?`.
const fn tri_state(value: Option<bool>) -> &'static str {
    match value {
        Some(true) => "yes",
        Some(false) => "no",
        None => "?",
    }
}
