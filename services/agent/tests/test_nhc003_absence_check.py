from __future__ import annotations

import subprocess
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[3]
_SCRIPT = _REPO_ROOT / "scripts" / "nhc003-absence-check"


def _run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(_SCRIPT), *args],
        cwd=_REPO_ROOT,
        text=True,
        capture_output=True,
        check=False,
    )


def test_no_inputs_is_unmeasured() -> None:
    result = _run()
    assert result.returncode == 0
    assert "STATUS=UNMEASURED" in result.stdout
    assert "recall" not in result.stdout.lower() or "not a golden" in result.stdout


def test_email_without_intrusion_plan_is_absent(tmp_path: Path) -> None:
    email = tmp_path / "email.txt"
    email.write_text(
        "# Feature-Recorder: email\n"
        "100\talice@example.net\tSubject: lunch plans\n"
        "200\tbob@example.net\tWelcome to Outlook Express 6\n",
        encoding="utf-8",
    )
    result = _run("--email-txt", str(email))
    assert result.returncode == 0
    assert "STATUS=ABSENT" in result.stdout
    assert "email_colocated_intrusion_plan_emailish: 0" in result.stdout
    assert "%" not in result.stdout  # no fake recall


def test_colocated_intrusion_plan_email_is_present(tmp_path: Path) -> None:
    email = tmp_path / "email.txt"
    email.write_text(
        "12345\tintruder@example.net\tSubject: intrusion plan for the network\n",
        encoding="utf-8",
    )
    result = _run("--email-txt", str(email))
    assert result.returncode == 0
    assert "STATUS=PRESENT" in result.stdout
    assert "email_colocated_intrusion_plan_emailish: 1" in result.stdout
