//! Colour selection for the viewer.
//!
//! These are pure functions (input value → [`Color`]) so they can be
//! unit-tested directly, including the custody-mismatch red that no
//! committed fixture triggers. Colour is presentation only: it never
//! changes a confidence tier or a verdict word, it only styles what the
//! case already asserts.

use ratatui::style::Color;

/// Colour for a confidence tier label. Unknown tiers fall back to a
/// neutral colour rather than implying a severity.
#[must_use]
pub fn confidence_color(tier: &str) -> Color {
    match tier {
        "CONFIRMED" => Color::Red,
        "INFERRED" => Color::Yellow,
        "HYPOTHESIS" => Color::Cyan,
        _ => Color::Gray,
    }
}

/// Colour for the top-level verdict word.
#[must_use]
pub fn verdict_color(word: &str) -> Color {
    match word {
        "SUSPICIOUS" => Color::Red,
        "INDETERMINATE" => Color::Yellow,
        "NO_EVIL" => Color::Green,
        _ => Color::Gray,
    }
}

/// Colour for a tri-state boolean light: green true, red false, gray
/// unknown/absent.
#[must_use]
pub const fn bool_light_color(value: Option<bool>) -> Color {
    match value {
        Some(true) => Color::Green,
        Some(false) => Color::Red,
        None => Color::Gray,
    }
}

/// Colour for a replay SHA-256 pair: red on a real mismatch, green when
/// both are present and equal, gray when either is absent.
#[must_use]
pub fn replay_color(expected: Option<&str>, actual: Option<&str>) -> Color {
    match (expected, actual) {
        (Some(expected), Some(actual)) => {
            if expected == actual {
                Color::Green
            } else {
                Color::Red
            }
        }
        _ => Color::Gray,
    }
}

/// Categorical colour for a live audit record's `kind`.
///
/// Informational, not a severity: it groups the stream (tool activity,
/// findings/verdict, recovery, failure) so the eye can scan it. It never
/// re-ranks a Finding or a verdict — the record's own confidence tier is
/// coloured separately by [`confidence_color`].
#[must_use]
pub fn audit_kind_color(kind: &str) -> Color {
    match kind {
        "tool_call_start" | "tool_call_output" | "replay" | "verifier_action" => Color::Cyan,
        "finding_approved" | "finding_rejected" | "verdict_packet" | "verdict_artifact" => {
            Color::Blue
        }
        "course_correction" | "verdict_revision" => Color::Yellow,
        "heartbeat_failure" | "heartbeat_terminated" | "fault_injection" => Color::Red,
        _ => Color::Gray,
    }
}

/// Colour for a coverage artifact-class status.
#[must_use]
pub fn coverage_status_color(status: &str) -> Color {
    match status {
        "parsed" => Color::Green,
        "attempted_no_rows" | "attempted" => Color::Yellow,
        "failed" | "unsupported" => Color::Red,
        _ => Color::Gray,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn confidence_tiers_are_distinctly_coloured() {
        assert_eq!(confidence_color("CONFIRMED"), Color::Red);
        assert_eq!(confidence_color("INFERRED"), Color::Yellow);
        assert_eq!(confidence_color("HYPOTHESIS"), Color::Cyan);
        assert_eq!(confidence_color("UNKNOWN"), Color::Gray);
    }

    #[test]
    fn verdict_words_map_to_expected_colours() {
        assert_eq!(verdict_color("SUSPICIOUS"), Color::Red);
        assert_eq!(verdict_color("INDETERMINATE"), Color::Yellow);
        assert_eq!(verdict_color("NO_EVIL"), Color::Green);
    }

    #[test]
    fn replay_mismatch_is_red_and_match_is_green() {
        assert_eq!(replay_color(Some("a"), Some("b")), Color::Red);
        assert_eq!(replay_color(Some("a"), Some("a")), Color::Green);
        assert_eq!(replay_color(Some("a"), None), Color::Gray);
        assert_eq!(replay_color(None, None), Color::Gray);
    }

    #[test]
    fn bool_light_is_tri_state() {
        assert_eq!(bool_light_color(Some(true)), Color::Green);
        assert_eq!(bool_light_color(Some(false)), Color::Red);
        assert_eq!(bool_light_color(None), Color::Gray);
    }
}
