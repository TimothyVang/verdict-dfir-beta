"""scripts/verdict --fleet: one command for a multi-host case folder.

Offline and fast: --dry-run prints the stage plan without running anything.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import uuid
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[3]
_VERDICT = _REPO / "scripts" / "verdict"


def _run(args: list[str], cwd: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["bash", str(_VERDICT), *args],
        cwd=str(_REPO),
        capture_output=True,
        text=True,
        timeout=60,
    )


def _case_root(tmp_path: Path) -> Path:
    root = tmp_path / "big-case"
    (root / "hosts" / "h1").mkdir(parents=True)
    (root / "hosts" / "h1" / "h1-memory.img").write_bytes(b"\x00" * 16)
    return root


class TestFleetMode:
    def test_multi_host_folder_auto_enters_fleet_mode(self, tmp_path: Path) -> None:
        root = _case_root(tmp_path)
        proc = _run([str(root), "--dry-run", "--no-dashboard", "--skip-build"], tmp_path)
        out = proc.stdout + proc.stderr
        assert proc.returncode == 0, out
        # All three stages are named in the plan.
        assert "run-whole-case-local" in out
        assert "fleet_correlate" in out
        assert "render_fleet_report" in out

    def test_explicit_fleet_flag(self, tmp_path: Path) -> None:
        root = _case_root(tmp_path)
        proc = _run([str(root), "--fleet", "--dry-run", "--no-dashboard"], tmp_path)
        out = proc.stdout + proc.stderr
        assert proc.returncode == 0, out
        assert "run-whole-case-local" in out

    def test_single_file_evidence_does_not_enter_fleet_mode(self, tmp_path: Path) -> None:
        evidence = tmp_path / "memory.img"
        evidence.write_bytes(b"\x00" * 16)
        proc = _run([str(evidence), "--dry-run", "--no-dashboard", "--skip-build"], tmp_path)
        out = proc.stdout + proc.stderr
        assert proc.returncode == 0, out
        assert "run-whole-case-local" not in out
        assert "find_evil_auto" in out  # the normal single-case engine plan

    @pytest.mark.parametrize("extra_args", [[], ["--fleet"]], ids=["auto", "explicit"])
    def test_agent_mode_rejects_fleet_before_deterministic_run(
        self, tmp_path: Path, extra_args: list[str]
    ) -> None:
        root = _case_root(tmp_path)
        proc = _run(
            [str(root), "--agent", *extra_args, "--dry-run", "--no-dashboard"],
            tmp_path,
        )
        out = proc.stdout + proc.stderr
        assert proc.returncode != 0, out
        assert "--agent supports a single EVTX file only" in out
        assert "run-whole-case-local" not in out


def test_agent_launcher_rejects_successful_engine_with_failed_manifest(
    tmp_path: Path,
) -> None:
    evidence = tmp_path / "sample.evtx"
    evidence.write_bytes(b"evtx")
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    fake_uv = fake_bin / "uv"
    fake_uv.write_text(
        """#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" != "run" ]]; then
  exec "${REAL_UV}" "$@"
fi
summary=""
while [[ $# -gt 0 ]]; do
  if [[ "$1" == "--run-summary" ]]; then
    summary="$2"
    break
  fi
  shift
done
mkdir -p "$(dirname "${summary}")"
printf '%s\n' '{"result":{"verdict":"NO_EVIL","manifest_verify_overall":false}}' >"${summary}"
printf '%s\n' '{"verdict":"NO_EVIL"}' >"$(dirname "$(dirname "${summary}")")/verdict.json"
printf '%s\n' 'DONE — verdict: NO_EVIL'
""",
        encoding="utf-8",
    )
    fake_uv.chmod(0o755)
    case_id = f"test-native-manifest-{uuid.uuid4().hex}"
    case_dir = _REPO / "tmp" / "auto-runs" / case_id
    env = os.environ.copy()
    env.update(
        {
            "PATH": f"{fake_bin}:{env['PATH']}",
            "REAL_UV": shutil.which("uv") or "uv",
            "FINDEVIL_SKIP_GROUNDING": "1",
        }
    )

    try:
        proc = subprocess.run(
            [
                "bash",
                str(_VERDICT),
                str(evidence),
                "--agent",
                "--skip-build",
                "--no-dashboard",
                "--case-id",
                case_id,
            ],
            cwd=str(_REPO),
            capture_output=True,
            text=True,
            timeout=120,
            env=env,
        )
    finally:
        shutil.rmtree(case_dir, ignore_errors=True)

    out = proc.stdout + proc.stderr
    assert proc.returncode != 0, out
    assert "manifest verification failed" in out.lower()
