"""A run that produced nothing must not score as a pass.

The 2026-07-28 golden aggregate reported 4/7 passing — but two of those four
(``synthetic-benign``, ``synthetic-decoy``) passed with ``run_finding_n == 0``,
and three of the four ended ``INDETERMINATE``. Three separate scorer behaviours
combined to hand out those free passes:

  1. an empty golden (``expected_n == 0``) scored recall 100 unconditionally, so a
     run that errored out before producing anything looked perfectly recalled;
  2. ``_verdict_consistent`` accepted ``INDETERMINATE`` against ANY golden verdict,
     and ``INDETERMINATE`` is exactly what a tool failure produces; and
  3. precision/F1/hallucination reported ``100`` / ``0.0`` off a zero denominator,
     so a run with nothing scored read as perfectly precise.

Plus a latent crash: a golden with ``min_recall_percent: null`` (``sans-starter``)
hit ``int(None)``.

These tests pin all four. They are deliberately shaped like the real failures.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from findevil_agent import accuracy

_REPO_ROOT = Path(__file__).resolve().parents[3]
_GOLDENS = _REPO_ROOT / "goldens"

_BENIGN_GOLDEN = _GOLDENS / "synthetic-benign" / "expected-findings.json"
_DECOY_GOLDEN = _GOLDENS / "synthetic-decoy" / "expected-findings.json"
_NITROBA_GOLDEN = _GOLDENS / "nitroba" / "expected-findings.json"
_ALIHADI_GOLDEN = _GOLDENS / "alihadi-09-encrypt" / "expected-findings.json"
_SANS_GOLDEN = _GOLDENS / "sans-starter" / "expected-findings.json"

# A tool call as ``find_evil_auto`` records it. Every failure site tags
# ``extra["error"]`` before ``_record_tool``, so a failed tool is an ``error`` key
# on the tool_calls entry (see scripts/find_evil_auto.py::_record_tool).
_OK_TOOL = {"tool_call_id": "tc-1", "tool": "case_open"}
_FAILED_TOOL = {
    "tool_call_id": "tc-2",
    "tool": "disk_extract_artifacts",
    "error": "subprocess failed: Cannot determine file system type",
}


def _write_case(
    case_dir: Path,
    case_id: str,
    verdict: str,
    findings: list[dict[str, Any]],
    *,
    tool_calls: list[dict[str, Any]] | None = None,
    heartbeat: dict[str, Any] | None = None,
) -> Path:
    case_dir.mkdir(parents=True, exist_ok=True)
    doc: dict[str, Any] = {
        "case_id": case_id,
        "verdict": verdict,
        "findings": findings,
        "tool_calls": [_OK_TOOL] if tool_calls is None else tool_calls,
    }
    if heartbeat is not None:
        doc["heartbeat"] = heartbeat
    (case_dir / "verdict.json").write_text(json.dumps(doc), encoding="utf-8")
    return case_dir


def _echo_golden_findings(golden_path: Path) -> list[dict[str, Any]]:
    """Run findings that restate every golden claim verbatim — full recall by construction."""
    golden = json.loads(golden_path.read_text(encoding="utf-8"))
    return [
        {
            "finding_id": f"r-{i:03d}",
            "description": exp.get("description"),
            "artifact_path": exp.get("artifact_hint"),
        }
        for i, exp in enumerate(golden.get("findings") or [], start=1)
    ]


class TestEmptyGoldenIsNotAFreePass:
    """``expected_n == 0`` means "nothing to find", not "nothing went wrong"."""

    def test_indeterminate_run_does_not_pass_the_benign_golden(self, tmp_path: Path) -> None:
        # The exact shape of the 2026-07-28 synthetic-benign "pass": zero findings,
        # verdict INDETERMINATE. The golden wants NO_EVIL.
        case = _write_case(tmp_path / "benign", "synthetic-benign", "INDETERMINATE", [])
        result = accuracy.score(case, _BENIGN_GOLDEN)
        assert result["run_finding_n"] == 0
        assert result["recall_percent"] != 100
        assert result["pass"] is False

    def test_errored_run_does_not_pass_the_decoy_golden(self, tmp_path: Path) -> None:
        # Right verdict word, zero findings — but a tool blew up, so the run never
        # actually established the negative.
        case = _write_case(
            tmp_path / "decoy",
            "synthetic-decoy",
            "NO_EVIL",
            [],
            tool_calls=[_OK_TOOL, _FAILED_TOOL],
        )
        result = accuracy.score(case, _DECOY_GOLDEN)
        assert result["run_completed"] is False
        assert result["recall_percent"] != 100
        assert result["pass"] is False

    def test_heartbeat_terminated_partial_run_does_not_pass(self, tmp_path: Path) -> None:
        case = _write_case(
            tmp_path / "benign",
            "synthetic-benign",
            "NO_EVIL",
            [],
            heartbeat={"terminated_partial": True},
        )
        result = accuracy.score(case, _BENIGN_GOLDEN)
        assert result["run_completed"] is False
        assert result["pass"] is False

    def test_clean_true_negative_run_still_passes(self, tmp_path: Path) -> None:
        # The whole point of a true-negative golden: a run that completed, called
        # the case NO_EVIL and correctly found nothing is a real PASS. Zero-expected
        # must not become an automatic fail.
        case = _write_case(tmp_path / "benign", "synthetic-benign", "NO_EVIL", [])
        result = accuracy.score(case, _BENIGN_GOLDEN)
        assert result["run_completed"] is True
        assert result["recall_percent"] == 100
        assert result["pass"] is True


class TestIndeterminateIsNotAVerdictMatch:
    """``INDETERMINATE`` is what a tool failure produces — it cannot mean "correct"."""

    def test_indeterminate_run_fails_a_confirmed_evil_golden(self, tmp_path: Path) -> None:
        # Nitroba's shape: full recall, but the run never committed to a call while
        # the key says CONFIRMED_EVIL.
        case = _write_case(
            tmp_path / "nitroba",
            "nitroba",
            "INDETERMINATE",
            _echo_golden_findings(_NITROBA_GOLDEN),
        )
        result = accuracy.score(case, _NITROBA_GOLDEN)
        assert result["recall_percent"] == 100, "fixture must isolate the verdict check"
        assert result["verdict_match"] is False
        assert result["pass"] is False

    def test_indeterminate_run_matches_an_indeterminate_golden(self, tmp_path: Path) -> None:
        # The false-positive control (alihadi-09) is authored to EXPECT uncertainty.
        # A neutral run against a neutral key is the right answer, not a free pass.
        case = _write_case(
            tmp_path / "alihadi",
            "alihadi-09-encrypt",
            "INDETERMINATE",
            _echo_golden_findings(_ALIHADI_GOLDEN),
        )
        result = accuracy.score(case, _ALIHADI_GOLDEN)
        assert result["verdict_match"] is True
        assert result["pass"] is True

    def test_definite_run_still_fails_an_indeterminate_golden(self, tmp_path: Path) -> None:
        # Unchanged behaviour, pinned so the fix does not loosen the FP control:
        # escalating to CONFIRMED_EVIL on a key authored INDETERMINATE is wrong.
        case = _write_case(
            tmp_path / "alihadi",
            "alihadi-09-encrypt",
            "CONFIRMED_EVIL",
            _echo_golden_findings(_ALIHADI_GOLDEN),
        )
        result = accuracy.score(case, _ALIHADI_GOLDEN)
        assert result["verdict_match"] is False
        assert result["pass"] is False


class TestUnscoredPrecisionIsNotReportedAsPerfect:
    """A zero-denominator metric is *not measured*, and must not print as 100%."""

    def test_zero_finding_run_reports_precision_as_not_measured(self, tmp_path: Path) -> None:
        nist = _GOLDENS / "nist-hacking-case" / "expected-findings.json"
        case = _write_case(tmp_path / "nist", "nist-hacking-case", "INDETERMINATE", [])
        result = accuracy.score(case, nist)
        assert result["run_finding_n"] == 0
        assert result["precision_percent"] is None
        assert result["hallucination_rate"] is None
        assert result["f1"] is None

    def test_scored_run_still_reports_real_numbers(self, tmp_path: Path) -> None:
        case = _write_case(
            tmp_path / "nitroba",
            "nitroba",
            "CONFIRMED_EVIL",
            _echo_golden_findings(_NITROBA_GOLDEN),
        )
        result = accuracy.score(case, _NITROBA_GOLDEN)
        assert result["precision_percent"] == 100
        assert result["hallucination_rate"] == 0.0


class TestNullMinRecallFailsLoudly:
    """``sans-starter`` carries ``min_recall_percent: null`` — a stub, not a threshold."""

    def test_null_min_recall_raises_an_error_naming_the_golden(self, tmp_path: Path) -> None:
        case = _write_case(tmp_path / "sans", "sans-starter", "UNKNOWN", [])
        with pytest.raises(ValueError, match="sans-starter"):
            accuracy.score(case, _SANS_GOLDEN)
