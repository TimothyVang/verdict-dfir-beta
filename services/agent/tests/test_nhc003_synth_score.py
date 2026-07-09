from __future__ import annotations

import subprocess
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[3]
_SCRIPT = _REPO_ROOT / "scripts" / "nhc003-synth-score"


def test_synth_score_matches_nhc003_mechanism() -> None:
    result = subprocess.run(
        [sys.executable, str(_SCRIPT)],
        cwd=_REPO_ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + "\n" + result.stderr
    assert "STATUS=MATCHED" in result.stdout
    assert "nhc-003" in result.stdout or "recall" in result.stdout.lower()
    # Honesty: must not claim SCHARDT
    assert "SCHARDT" in result.stdout and "ABSENT" in result.stdout
