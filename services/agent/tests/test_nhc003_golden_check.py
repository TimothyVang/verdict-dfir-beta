from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[3]
_SCRIPT = _REPO_ROOT / "scripts" / "nhc003-golden-check"


def _run_check(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(_SCRIPT), *args],
        cwd=_REPO_ROOT,
        text=True,
        capture_output=True,
        check=False,
    )


def test_no_case_dir_is_unmeasured_and_prints_no_recall_number() -> None:
    result = _run_check()

    assert result.returncode == 0
    assert "score_recall: not run" in result.stdout
    assert "STATUS=UNMEASURED" in result.stdout
    assert "  recall:" not in result.stdout
    assert "STATUS=SCORED" not in result.stdout


def test_stale_recall_score_without_verdict_is_not_scored(tmp_path: Path) -> None:
    case_dir = tmp_path / "not-a-case"
    case_dir.mkdir()
    (case_dir / "recall-score.json").write_text(
        json.dumps({"recalled_n": 14, "expected_n": 14, "recall_percent": 100}),
        encoding="utf-8",
    )

    result = _run_check(str(case_dir))

    assert result.returncode == 0
    assert "score_recall: not run" in result.stdout
    assert "STATUS=UNMEASURED" in result.stdout
    assert "100%" not in result.stdout
    assert "STATUS=SCORED" not in result.stdout


def test_real_case_dir_runs_score_recall_before_status_scored(tmp_path: Path) -> None:
    case_dir = tmp_path / "case"
    case_dir.mkdir()
    (case_dir / "verdict.json").write_text(
        json.dumps(
            {
                "case_id": "nist-hacking-case",
                "verdict": "INDETERMINATE",
                "findings": [],
            }
        ),
        encoding="utf-8",
    )

    result = _run_check(str(case_dir))

    assert result.returncode == 0
    assert "score_recall: ran" in result.stdout
    assert "  recall: 0/14 = 0%" in result.stdout
    assert (
        "  nhc-003: MISSED - Recovered deleted email discussing the intrusion plan" in result.stdout
    )
    assert "STATUS=SCORED" in result.stdout
    assert (case_dir / "recall-score.json").is_file()
