//! Typed, forgiving accessors over the loose `serde_json::Value` case
//! bundle.
//!
//! `verdict.json` has ~30 top-level keys and no top-level
//! `schema_version`, so the loader keeps the raw `Value` and this module
//! projects the handful of fields v1 renders. Every accessor defaults to
//! "absent"/`None`/empty rather than erroring: a missing or oddly-shaped
//! field is a rendering concern ("not produced by this run"), never a
//! crash. The projection is read-only and derives nothing that could be
//! mistaken for a Finding or a confidence upgrade.

use serde_json::Value;

/// The confidence tiers VERDICT emits, in descending strength. The header
/// tally renders them in this fixed order regardless of map iteration
/// order in the source JSON.
pub const CONFIDENCE_TIERS: [&str; 3] = ["CONFIRMED", "INFERRED", "HYPOTHESIS"];

/// One Finding projected for display. Every field is optional/empty when
/// the source omits it; nothing here is fabricated.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Finding {
    pub finding_id: Option<String>,
    pub confidence: Option<String>,
    pub mitre_technique: Option<String>,
    pub description: Option<String>,
    pub tool_call_id: Option<String>,
    pub replay_expected_sha256: Option<String>,
    pub replay_actual_sha256: Option<String>,
    pub replay_matched: Option<bool>,
    /// Human-rendered lines for each asserted value (path/expected/match).
    pub asserted_values: Vec<String>,
    pub counter_hypothesis: Option<String>,
    /// Upstream `tool_call_id`s this Finding was derived from.
    pub derived_from: Vec<String>,
}

impl Finding {
    /// True when both replay SHA-256 fields are present and differ — the
    /// custody mismatch the detail pane highlights in red. Absent fields
    /// are never treated as a mismatch (unknown is not failure).
    #[must_use]
    pub fn replay_mismatch(&self) -> bool {
        match (
            self.replay_expected_sha256.as_deref(),
            self.replay_actual_sha256.as_deref(),
        ) {
            (Some(expected), Some(actual)) => expected != actual,
            _ => false,
        }
    }

    fn from_value(value: &Value) -> Self {
        Self {
            finding_id: string_field(value, "finding_id"),
            confidence: string_field(value, "confidence"),
            mitre_technique: string_field(value, "mitre_technique"),
            description: string_field(value, "description"),
            tool_call_id: string_field(value, "tool_call_id"),
            replay_expected_sha256: string_field(value, "replay_expected_sha256"),
            replay_actual_sha256: string_field(value, "replay_actual_sha256"),
            replay_matched: value.get("replay_matched").and_then(Value::as_bool),
            asserted_values: asserted_value_lines(value.get("asserted_values")),
            counter_hypothesis: scalar_or_json(value.get("counter_hypothesis")),
            derived_from: string_array(value.get("derived_from")),
        }
    }
}

/// One coverage artifact class projected for display.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ArtifactClass {
    pub name: Option<String>,
    pub status: Option<String>,
}

impl ArtifactClass {
    fn from_value(value: &Value) -> Self {
        Self {
            name: string_field(value, "artifact_class").or_else(|| string_field(value, "name")),
            status: string_field(value, "status").or_else(|| string_field(value, "state")),
        }
    }
}

/// Count of Findings per confidence tier, from `findings_summary.by_confidence`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConfidenceTally {
    /// Ordered `(tier, count)` pairs — known tiers first (see
    /// [`CONFIDENCE_TIERS`]), then any others the source carried.
    pub counts: Vec<(String, u64)>,
}

impl ConfidenceTally {
    /// Total Findings across all tiers.
    #[must_use]
    pub fn total(&self) -> u64 {
        self.counts.iter().map(|(_, n)| *n).sum()
    }

    fn from_value(value: Option<&Value>) -> Option<Self> {
        let object = value?.as_object()?;
        let mut counts: Vec<(String, u64)> = Vec::new();
        for tier in CONFIDENCE_TIERS {
            if let Some(count) = object.get(tier).and_then(Value::as_u64) {
                counts.push((tier.to_string(), count));
            }
        }
        for (key, val) in object {
            if CONFIDENCE_TIERS.contains(&key.as_str()) {
                continue;
            }
            if let Some(count) = val.as_u64() {
                counts.push((key.clone(), count));
            }
        }
        Some(Self { counts })
    }
}

/// The offline custody-verification summary (`manifest_verify.json`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ManifestVerify {
    pub overall: Option<bool>,
    pub signature_present: Option<bool>,
    pub signature_verified: Option<bool>,
    pub signature_kind: Option<String>,
}

impl ManifestVerify {
    fn from_value(value: &Value) -> Self {
        Self {
            overall: value.get("overall").and_then(Value::as_bool),
            signature_present: value.get("signature_present").and_then(Value::as_bool),
            signature_verified: value.get("signature_verified").and_then(Value::as_bool),
            signature_kind: string_field(value, "signature_kind"),
        }
    }
}

/// Read the top-level verdict word (`SUSPICIOUS` / `INDETERMINATE` /
/// `NO_EVIL` / …). Presentation only; this never re-derives or upgrades it.
#[must_use]
pub fn verdict_word(verdict: &Value) -> Option<String> {
    string_field(verdict, "verdict")
}

/// The case identifier, if present.
#[must_use]
pub fn case_id(verdict: &Value) -> Option<String> {
    string_field(verdict, "case_id")
}

/// Project every Finding in `verdict.findings[]`, preserving source order.
#[must_use]
pub fn findings(verdict: &Value) -> Vec<Finding> {
    verdict
        .get("findings")
        .and_then(Value::as_array)
        .map(|arr| arr.iter().map(Finding::from_value).collect())
        .unwrap_or_default()
}

/// The confidence tally from `findings_summary.by_confidence`.
#[must_use]
pub fn confidence_tally(verdict: &Value) -> Option<ConfidenceTally> {
    let by_confidence = verdict
        .get("findings_summary")
        .and_then(|summary| summary.get("by_confidence"));
    ConfidenceTally::from_value(by_confidence)
}

/// Project the coverage artifact classes from a coverage-manifest `Value`
/// (either a sibling `coverage_manifest.json` or the block embedded in
/// `verdict.json`).
#[must_use]
pub fn artifact_classes(coverage_manifest: &Value) -> Vec<ArtifactClass> {
    coverage_manifest
        .get("artifact_classes")
        .and_then(Value::as_array)
        .map(|arr| arr.iter().map(ArtifactClass::from_value).collect())
        .unwrap_or_default()
}

/// Project the manifest-verify summary from a `manifest_verify.json` `Value`.
#[must_use]
pub fn manifest_verify(value: &Value) -> ManifestVerify {
    ManifestVerify::from_value(value)
}

fn string_field(value: &Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string)
}

fn string_array(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(Value::as_str)
                .map(ToString::to_string)
                .collect()
        })
        .unwrap_or_default()
}

/// Render a scalar (string/number/bool) as-is, or fall back to compact
/// JSON for a structured value. `None`/JSON-null both yield `None`.
fn scalar_or_json(value: Option<&Value>) -> Option<String> {
    match value {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) => {
            let trimmed = s.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            }
        }
        Some(other) => Some(other.to_string()),
    }
}

/// Turn `asserted_values` (an array of `{path, expected, match, …}`
/// objects, or scalars) into one human line per element.
fn asserted_value_lines(value: Option<&Value>) -> Vec<String> {
    let Some(items) = value.and_then(Value::as_array) else {
        return Vec::new();
    };
    items.iter().map(render_asserted_value).collect()
}

fn render_asserted_value(item: &Value) -> String {
    let Some(object) = item.as_object() else {
        return item.to_string();
    };
    let path = object.get("path").and_then(Value::as_str);
    let expected = object.get("expected").map(compact_scalar);
    let match_kind = object.get("match").and_then(Value::as_str);
    match (path, expected) {
        (Some(path), Some(expected)) => match_kind.map_or_else(
            || format!("{path} = {expected}"),
            |kind| format!("{path} = {expected} ({kind})"),
        ),
        _ => item.to_string(),
    }
}

fn compact_scalar(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn projects_core_finding_fields() {
        let value = json!({
            "finding_id": "f-1",
            "confidence": "CONFIRMED",
            "mitre_technique": "T1070.001",
            "description": "  log clearing  ",
            "tool_call_id": "tc-002",
            "replay_expected_sha256": "aaa",
            "replay_actual_sha256": "aaa",
            "replay_matched": true,
            "derived_from": ["tc-001", "tc-002"],
        });
        let finding = Finding::from_value(&value);
        assert_eq!(finding.finding_id.as_deref(), Some("f-1"));
        assert_eq!(finding.confidence.as_deref(), Some("CONFIRMED"));
        assert_eq!(finding.description.as_deref(), Some("log clearing"));
        assert_eq!(finding.replay_matched, Some(true));
        assert_eq!(finding.derived_from, vec!["tc-001", "tc-002"]);
        assert!(!finding.replay_mismatch());
    }

    #[test]
    fn absent_fields_default_to_none() {
        let finding = Finding::from_value(&json!({}));
        assert!(finding.finding_id.is_none());
        assert!(finding.confidence.is_none());
        assert!(finding.asserted_values.is_empty());
        assert!(finding.derived_from.is_empty());
        assert!(!finding.replay_mismatch());
    }

    #[test]
    fn detects_replay_mismatch_only_when_both_present_and_differ() {
        let mut finding = Finding {
            replay_expected_sha256: Some("aaa".into()),
            replay_actual_sha256: Some("bbb".into()),
            ..Finding::default()
        };
        assert!(finding.replay_mismatch());
        finding.replay_actual_sha256 = Some("aaa".into());
        assert!(!finding.replay_mismatch());
        finding.replay_actual_sha256 = None;
        assert!(!finding.replay_mismatch());
    }

    #[test]
    fn renders_asserted_value_objects_as_lines() {
        let value = json!({
            "asserted_values": [
                {"path": "run_count", "expected": "2", "match": "int"},
                {"path": "name", "expected": "x"},
                "loose-scalar",
            ]
        });
        let finding = Finding::from_value(&value);
        assert_eq!(finding.asserted_values[0], "run_count = 2 (int)");
        assert_eq!(finding.asserted_values[1], "name = x");
        assert_eq!(finding.asserted_values[2], "\"loose-scalar\"");
    }

    #[test]
    fn tally_orders_known_tiers_first() {
        let verdict = json!({
            "findings_summary": {
                "by_confidence": {"HYPOTHESIS": 2, "CONFIRMED": 1, "INFERRED": 7}
            }
        });
        let tally = confidence_tally(&verdict).expect("tally present");
        let order: Vec<&str> = tally.counts.iter().map(|(t, _)| t.as_str()).collect();
        assert_eq!(order, vec!["CONFIRMED", "INFERRED", "HYPOTHESIS"]);
        assert_eq!(tally.total(), 10);
    }

    #[test]
    fn counter_hypothesis_null_becomes_none() {
        let finding = Finding::from_value(&json!({"counter_hypothesis": null}));
        assert!(finding.counter_hypothesis.is_none());
        let finding = Finding::from_value(&json!({"counter_hypothesis": "could be benign"}));
        assert_eq!(
            finding.counter_hypothesis.as_deref(),
            Some("could be benign")
        );
    }

    #[test]
    fn artifact_classes_project_name_and_status() {
        let manifest = json!({
            "artifact_classes": [
                {"artifact_class": "network", "status": "parsed"},
                {"artifact_class": "evtx", "status": "not_supplied"},
            ]
        });
        let classes = artifact_classes(&manifest);
        assert_eq!(classes[0].name.as_deref(), Some("network"));
        assert_eq!(classes[0].status.as_deref(), Some("parsed"));
        assert_eq!(classes[1].status.as_deref(), Some("not_supplied"));
    }
}
