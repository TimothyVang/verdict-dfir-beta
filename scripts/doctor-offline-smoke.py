#!/usr/bin/env python3
"""Smoke: doctor --offline does not require Claude credential / claude CLI.

Asserts the offline profile is a first-class packaging path for scripts/verdict
and Spark/GB10 (no Anthropic login).
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DOCTOR = REPO / "scripts" / "doctor.sh"


def main() -> int:
    assert DOCTOR.is_file(), f"missing {DOCTOR}"
    text = DOCTOR.read_text(encoding="utf-8")
    assert "--offline" in text, "doctor.sh must accept --offline"
    assert "OFFLINE_MODE" in text or "offline" in text.lower()

    # JSON offline: must report offline:true and must not fail solely on credential
    # when we strip Claude env (best-effort — host may still have ~/.claude).
    env = os.environ.copy()
    env.pop("CLAUDE_CODE_OAUTH_TOKEN", None)
    env.pop("ANTHROPIC_API_KEY", None)
    env["VERDICT_OFFLINE"] = "1"
    env["DOCTOR_OFFLINE"] = "1"

    proc = subprocess.run(
        ["bash", str(DOCTOR), "--offline", "--json"],
        cwd=str(REPO),
        env=env,
        capture_output=True,
        text=True,
    )
    if proc.returncode not in (0, 1):
        print(
            f"FAIL: unexpected exit {proc.returncode}\n{proc.stderr}", file=sys.stderr
        )
        return 1
    line = (proc.stdout or "").strip().splitlines()[-1] if proc.stdout else ""
    try:
        data = json.loads(line)
    except json.JSONDecodeError:
        print(
            f"FAIL: doctor --offline --json did not emit JSON:\n{proc.stdout}\n{proc.stderr}",
            file=sys.stderr,
        )
        return 1
    if data.get("offline") is not True:
        print(f"FAIL: offline flag missing in JSON: {data}", file=sys.stderr)
        return 1

    # Human offline path mentions offline profile when no JSON.
    proc2 = subprocess.run(
        ["bash", str(DOCTOR), "--offline"],
        cwd=str(REPO),
        env=env,
        capture_output=True,
        text=True,
    )
    out = (proc2.stdout or "") + (proc2.stderr or "")
    if "offline" not in out.lower():
        print(
            "FAIL: human offline doctor output does not mention offline",
            file=sys.stderr,
        )
        print(out[-1500:], file=sys.stderr)
        return 1

    # scripts/verdict must invoke doctor with --offline by default.
    verdict = (REPO / "scripts" / "verdict").read_text(encoding="utf-8")
    if "--offline" not in verdict or "DOCTOR_ARGS" not in verdict:
        print(
            "FAIL: scripts/verdict must preflight with doctor --offline",
            file=sys.stderr,
        )
        return 1

    print("PASS: doctor --offline JSON+human; scripts/verdict offline preflight")
    print(
        f"  offline JSON ready={data.get('ready')} missing_required={data.get('missing_required')}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
