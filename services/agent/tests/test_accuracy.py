"""Tests for the pure accuracy-scoring core in ``findevil_agent.accuracy``.

This is the single source of truth that both ``scripts/score-recall.py`` and the
``accuracy_compare`` MCP shim import. The matching / precision / verdict-consistency
logic itself is already pinned by ``test_score_recall_precision.py`` (which loads it
through the script). These tests pin the *extracted module's* public surface and the
new ``negative_coverage`` block — the negative-assertion coverage a maintainer reads
to know the run avoided every planted-bait claim it was supposed to avoid.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from findevil_agent import accuracy

_REPO_ROOT = Path(__file__).resolve().parents[3]
_NIST_GOLDEN = _REPO_ROOT / "goldens" / "nist-hacking-case" / "expected-findings.json"


def _write_verdict(case_dir: Path, verdict: str, findings: list[dict[str, object]]) -> Path:
    case_dir.mkdir(parents=True, exist_ok=True)
    doc = {"case_id": "nist-hacking-case", "verdict": verdict, "findings": findings}
    (case_dir / "verdict.json").write_text(json.dumps(doc), encoding="utf-8")
    return case_dir


def _ready_golden_copy(tmp_path: Path, source: Path) -> Path:
    """Make an explicitly scoreable copy for tests of scoring math."""

    data = json.loads(source.read_text(encoding="utf-8"))
    data["scoring_status"] = "ready"
    data.pop("not_ready_reason", None)
    destination = tmp_path / f"{source.parent.name}-ready.json"
    destination.write_text(json.dumps(data), encoding="utf-8")
    return destination


# Seven of the 14 SCHARDT ground-truth claims, worded with the distinctive tokens
# of each golden finding so token-overlap matching is unambiguous. 7/14 = 50%,
# below the golden's 71% min_recall — so this is a deliberate recall-MISS fixture.
_SEVEN_OF_FOURTEEN = [
    {
        "finding_id": "r-001",
        "description": "Dual-boot XP install linked-list recent searches hacking tools",
    },
    {
        "finding_id": "r-002",
        "description": "USB device insertion history external drive connected staging",
    },
    {
        "finding_id": "r-003",
        "description": "Recovered deleted email discussing the intrusion plan",
    },
    {
        "finding_id": "r-004",
        "description": "Hacking tool artifacts Program Files downloaded applications",
    },
    {
        "finding_id": "r-005",
        "description": "Prefetch evidence hacking tool execution",
    },
    {
        "finding_id": "r-006",
        "description": "Internet history indicating downloads illicit content",
    },
    {
        "finding_id": "r-007",
        "description": "Shellbag entries navigation removable media holding staged files",
    },
]


class TestScoreCore:
    def test_seven_of_fourteen_schardt_recall(self, tmp_path: Path) -> None:
        case_dir = _write_verdict(tmp_path / "case", "CONFIRMED_EVIL", _SEVEN_OF_FOURTEEN)
        result = accuracy.score(case_dir, _NIST_GOLDEN)
        assert result["expected_n"] == 14
        assert result["recalled_n"] == 7
        assert result["recall_percent"] == 50
        assert result["min_recall_percent"] == 71
        # verdict polarity agrees (EVIL/EVIL) ...
        assert result["verdict_match"] is True
        # ... but 50% < 71% min_recall, so the run does NOT pass.
        assert result["pass"] is False

    def test_score_reports_precision_and_f1_keys(self, tmp_path: Path) -> None:
        case_dir = _write_verdict(tmp_path / "case", "CONFIRMED_EVIL", _SEVEN_OF_FOURTEEN)
        result = accuracy.score(case_dir, _NIST_GOLDEN)
        for key in (
            "precision_percent",
            "f1",
            "hallucination_rate",
            "negative_coverage",
        ):
            assert key in result, f"missing {key}"

    def test_not_ready_golden_cannot_produce_a_score(self, tmp_path: Path) -> None:
        golden = _REPO_ROOT / "goldens" / "synthetic-decoy" / "expected-findings.json"
        case_dir = _write_verdict(tmp_path / "decoy", "NO_EVIL", [])

        with pytest.raises(
            ValueError,
            match=r"scoring_status=not_ready.*not scoreable",
        ):
            accuracy.score(case_dir, golden)


class TestNegativeCoverage:
    def test_clean_decoy_run_has_full_negative_coverage(self, tmp_path: Path) -> None:
        # A run that surfaces ZERO findings against the planted-DECOY golden
        # correctly avoids every known_negative / denylisted name.
        golden = _ready_golden_copy(
            tmp_path,
            _REPO_ROOT / "goldens" / "synthetic-decoy" / "expected-findings.json",
        )
        case_dir = _write_verdict(tmp_path / "decoy", "NO_EVIL", [])
        result = accuracy.score(case_dir, golden)
        neg = result["negative_coverage"]
        # 4 known_negatives in the decoy golden, all avoided.
        assert neg["known_negative_total"] == 4
        assert neg["known_negative_violations"] == 0
        assert neg["denylist_terms_asserted"] == 0
        assert neg["clean"] is True
        assert neg["coverage_percent"] == 100

    def test_asserting_denylisted_name_drops_negative_coverage(self, tmp_path: Path) -> None:
        golden = _ready_golden_copy(
            tmp_path,
            _REPO_ROOT / "goldens" / "synthetic-decoy" / "expected-findings.json",
        )
        # A hallucinated finding that asserts a denylisted malware name on the
        # benign decoy: planted-bait false positive.
        findings = [
            {
                "finding_id": "fp-1",
                "description": ("mimikatz credential dumping observed against lsass on this host"),
            }
        ]
        case_dir = _write_verdict(tmp_path / "decoy", "SUSPICIOUS", findings)
        result = accuracy.score(case_dir, golden)
        neg = result["negative_coverage"]
        assert neg["denylist_terms_asserted"] >= 1
        assert neg["clean"] is False
        assert neg["coverage_percent"] < 100
        # planted bait always fails the run.
        assert result["pass"] is False


class TestScriptStillImportsCore:
    def test_score_recall_script_delegates_to_core(self, tmp_path: Path) -> None:
        # The hyphenated maintainer script must keep working by loading the
        # extracted core from the SAME source file — single source of truth, no
        # logic fork. (It loads accuracy.py by path, not via `import
        # findevil_agent.accuracy`, to stay stdlib-only / bare-python3 runnable;
        # so we assert same-source-file, then identical output.)
        import importlib.util

        script = _REPO_ROOT / "scripts" / "score-recall.py"
        spec = importlib.util.spec_from_file_location("score_recall_core", script)
        assert spec and spec.loader
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)

        # Same source file backs both the script and the package import.
        assert Path(mod._ACC_PATH).resolve() == Path(accuracy.__file__).resolve()

        # And both produce byte-identical results on the same fixture.
        case_dir = _write_verdict(tmp_path / "case", "CONFIRMED_EVIL", _SEVEN_OF_FOURTEEN)
        assert mod.score(case_dir, _NIST_GOLDEN) == accuracy.score(case_dir, _NIST_GOLDEN)
