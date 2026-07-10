#!/usr/bin/env python3
"""launcher-smoke -assert the operator-facing launcher scripts stay
sane.

This locks the audit findings from 2026-04-26's prose-vs-code sweep so
that future contributors can't silently re-introduce drift:

* The Claude Code CLI binary is ``claude``, not ``claude-code`` (commit
  c167aec found ``scripts/find-evil`` had been exec'ing a non-existent
  binary; cc4e93e caught the same in ``scripts/find-evil-sift`` since
  the previous grep filter missed extension-less scripts).
* The CLI doesn't take a positional path arg per ``claude --help`` —
  the trailing ``.`` was wrong in either form.
* Every shell launcher in scripts/ should be ``bash -n`` clean.

Scope: scripts/find-evil, scripts/find-evil-auto, scripts/find-evil-sift
plus every ``*.sh`` in scripts/. Extension-less files are explicitly
included because the find-evil family deliberately drops ``.sh``.

Wall-clock: usually sub-second, dominated by bash startup. Native
Windows Git Bash startup can be slower under load, so the per-file
syntax timeout is configurable with
``FINDEVIL_LAUNCHER_SMOKE_BASH_TIMEOUT_SECONDS``. Wired into
docker/l1-compose.yml after the policy smokes as an L1 smoke.
"""

from __future__ import annotations

import os
import re
import shlex
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO / "scripts"

# Shebangs that mark a file as a shell script we should audit.
# Extension-less files (the find-evil family deliberately drops .sh
# to read like CLI tools) get auto-discovered via this check so a
# new launcher dropped under scripts/ is gated next CI run without
# anyone having to update an explicit list.
SHELL_SHEBANGS: tuple[bytes, ...] = (
    b"#!/usr/bin/env bash",
    b"#!/bin/bash",
    b"#!/usr/bin/env sh",
    b"#!/bin/sh",
)

# CLI binary the launchers should resolve to.
CANONICAL_CLAUDE_BINARY = "claude"

# Things that look like the wrong binary. ``claude-code`` is the legacy
# name; never the right exec target. The list is deliberately narrow —
# false positives here will block real CI builds.
BAD_BINARY_PATTERNS = [
    # Match `command -v claude-code`, `exec claude-code`, or bare
    # `claude-code` invocations. Allow "claude-code" inside filenames
    # (claude-code-mode.md), URL paths (claude-code/install), inside
    # comments referencing legacy names, and inside the user-facing
    # error message that explains "Install: ...".
    re.compile(r"^\s*(?:exec\s+)?claude-code\b(?!\.md|/install)", re.MULTILINE),
    re.compile(r"^(?!\s*#).*?\bcommand\s+-v\s+claude-code\b", re.MULTILINE),
]

# `claude` does not take a positional path arg (per `claude --help`).
# `claude .` would treat `.` as a prompt. Catch that shape.
BAD_INVOCATION_PATTERNS = [
    re.compile(r"^\s*(?:exec\s+)?claude\s+\.\s*(?:$|#|\")", re.MULTILINE),
]

OK = "[OK  ]"
FAIL = "[FAIL]"
DEFAULT_BASH_TIMEOUT_SECONDS = 30
WINDOWS_BASH_TIMEOUT_SECONDS = 90
MAX_BASH_TIMEOUT_SECONDS = 300


def _has_shell_shebang(p: Path) -> bool:
    """True if p starts with one of SHELL_SHEBANGS. Reads only the
    first ~80 bytes to keep this cheap."""
    try:
        with p.open("rb") as f:
            first = f.read(80)
    except OSError:
        return False
    return any(first.startswith(s) for s in SHELL_SHEBANGS)


def _list_launchers() -> list[Path]:
    """Every launcher we need to syntax-check + audit.

    Discovery is two-pronged so a new launcher dropped under
    scripts/ is auto-gated:
      1. *.sh glob - any shell script with the conventional suffix.
      2. extension-less files in scripts/ that have a shell shebang
         (the find-evil family drops .sh to read like CLI tools).
    """
    out: set[Path] = set(SCRIPTS_DIR.glob("*.sh"))
    for p in SCRIPTS_DIR.iterdir():
        if not p.is_file():
            continue
        if "." in p.name:
            continue  # Skip *.py, *.css, etc; only extension-less.
        if _has_shell_shebang(p):
            out.add(p)
    return sorted(out)


def _bash_syntax_check(p: Path) -> tuple[bool, str]:
    """Run ``bash -n <p>``; True on exit 0."""
    attempts = 2
    timeout_seconds = _bash_timeout_seconds()
    for attempt in range(1, attempts + 1):
        try:
            r = subprocess.run(
                ["bash", "-n", _path_for_bash(p)],
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
                cwd=REPO,
            )
        except subprocess.TimeoutExpired:
            if attempt == attempts:
                return (
                    False,
                    f"bash -n timed out after {timeout_seconds}s x {attempts} attempts",
                )
            continue
        if r.returncode == 0:
            return True, ""
        return False, (r.stderr or r.stdout).strip()
    return False, "bash -n did not complete"


def _bash_timeout_seconds() -> int:
    raw = os.environ.get("FINDEVIL_LAUNCHER_SMOKE_BASH_TIMEOUT_SECONDS", "")
    if not raw.strip():
        return _default_bash_timeout_seconds()
    try:
        parsed = int(raw)
    except ValueError:
        return _default_bash_timeout_seconds()
    return max(1, min(parsed, MAX_BASH_TIMEOUT_SECONDS))


def _default_bash_timeout_seconds() -> int:
    if sys.platform == "win32":
        return WINDOWS_BASH_TIMEOUT_SECONDS
    return DEFAULT_BASH_TIMEOUT_SECONDS


def _path_for_bash(p: Path) -> str:
    try:
        return p.relative_to(REPO).as_posix()
    except ValueError:
        pass
    if sys.platform != "win32" or not p.drive:
        return str(p)
    drive = p.drive.rstrip(":").lower()
    rest = p.as_posix()[2:]
    candidates = [f"/mnt/{drive}{rest}", f"/{drive}{rest}"]
    for candidate in candidates:
        probe = subprocess.run(
            ["bash", "-lc", f"test -e {shlex.quote(candidate)}"],
            capture_output=True,
            timeout=5,
        )
        if probe.returncode == 0:
            return candidate
    return candidates[0]


def _scan_for_bad_binary(p: Path) -> list[str]:
    """Return list of bad-binary findings (line + reason) in p."""
    text = p.read_text(encoding="utf-8")
    findings = []
    for pat in BAD_BINARY_PATTERNS:
        for m in pat.finditer(text):
            line_no = text[: m.start()].count("\n") + 1
            line = text.splitlines()[line_no - 1].strip()
            findings.append(
                f"line {line_no}: {line!r} -`claude-code` is not a real "
                f"binary; the Claude Code CLI is `{CANONICAL_CLAUDE_BINARY}` "
                f"(installed via https://docs.anthropic.com/en/docs/claude-code/install)"
            )
    return findings


def _scan_for_bad_invocation(p: Path) -> list[str]:
    """Return list of bad-invocation findings in p."""
    text = p.read_text(encoding="utf-8")
    findings = []
    for pat in BAD_INVOCATION_PATTERNS:
        for m in pat.finditer(text):
            line_no = text[: m.start()].count("\n") + 1
            line = text.splitlines()[line_no - 1].strip()
            findings.append(
                f"line {line_no}: {line!r} -`claude` doesn't take a "
                f"positional path arg per `claude --help`; the trailing "
                f"`.` is parsed as a prompt. Use bare `claude` (script "
                f"should already cd to the right directory)."
            )
    return findings


def _check_find_evil_egress_ack() -> tuple[bool, str]:
    """The interactive wrapper must require and privately export consent."""
    with tempfile.TemporaryDirectory(prefix="verdict-launcher-smoke-") as raw_temp:
        temp = Path(raw_temp)
        fake_claude = temp / "claude"
        fake_claude.write_text(
            "#!/bin/sh\n"
            "printf 'ACK=%s\\n' \"${FINDEVIL_ACKNOWLEDGE_PARSED_EVIDENCE_EGRESS-}\"\n"
            "printf 'ARGS=%s\\n' \"$*\"\n",
            encoding="utf-8",
        )
        fake_claude.chmod(0o755)
        env = {
            **os.environ,
            "PATH": f"{temp}{os.pathsep}{os.environ.get('PATH', os.defpath)}",
        }
        denied = subprocess.run(
            ["bash", str(SCRIPTS_DIR / "find-evil")],
            cwd=REPO,
            env=env,
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        if denied.returncode == 0 or "acknowledge-evidence-egress" not in denied.stderr:
            return (
                False,
                "interactive wrapper did not fail closed without explicit consent",
            )
        allowed = subprocess.run(
            [
                "bash",
                str(SCRIPTS_DIR / "find-evil"),
                "--acknowledge-evidence-egress",
                "--resume",
            ],
            cwd=REPO,
            env=env,
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        if allowed.returncode != 0:
            return False, f"acknowledged wrapper failed: {allowed.stderr.strip()}"
        if "ACK=1" not in allowed.stdout or "ARGS=--resume" not in allowed.stdout:
            return (
                False,
                "consent was not privately exported or was forwarded as a Claude arg",
            )
    return True, ""


def _check_sift_egress_ack_contract() -> tuple[bool, str]:
    text = (SCRIPTS_DIR / "find-evil-sift").read_text(encoding="utf-8")
    required = (
        "--acknowledge-evidence-egress",
        "FINDEVIL_ACKNOWLEDGE_PARSED_EVIDENCE_EGRESS=1",
    )
    missing = [value for value in required if value not in text]
    if missing:
        return False, f"SIFT interactive launcher lacks consent gate: {missing}"
    return True, ""


def _check_post_verdict_egress_contract() -> tuple[bool, str]:
    text = (SCRIPTS_DIR / "verdict").read_text(encoding="utf-8")
    required = (
        "--acknowledge-post-verdict-egress",
        "POST_VERDICT_EGRESS_ACK=0",
        'if [[ "${POST_VERDICT_EGRESS_ACK}" == "1"',
    )
    missing = [value for value in required if value not in text]
    if missing:
        return False, f"post-verdict automation is not explicit opt-in: {missing}"
    return True, ""


def main() -> int:
    print("=" * 60)
    print("Find Evil! - launcher-smoke")
    print("=" * 60)

    launchers = _list_launchers()
    if not launchers:
        print(f"{FAIL} no launchers found in {SCRIPTS_DIR}")
        return 1

    failed = 0
    for p in launchers:
        rel = p.relative_to(REPO)

        # 1. Bash syntax.
        ok, err = _bash_syntax_check(p)
        if not ok:
            print(f"{FAIL} {rel} - bash -n failed: {err}")
            failed += 1
            continue
        print(f"{OK} {rel} - bash -n clean")

        # 2. No claude-code remnants.
        bad_bin = _scan_for_bad_binary(p)
        for finding in bad_bin:
            print(f"{FAIL} {rel} {finding}")
            failed += 1
        if not bad_bin:
            print(f"{OK} {rel} - no `claude-code` invocations")

        # 3. No `claude .` (positional arg) invocations.
        bad_inv = _scan_for_bad_invocation(p)
        for finding in bad_inv:
            print(f"{FAIL} {rel} {finding}")
            failed += 1
        if not bad_inv:
            print(f"{OK} {rel} - no `claude .` (positional arg) invocations")

    egress_ok, egress_error = _check_find_evil_egress_ack()
    if egress_ok:
        print(
            f"{OK} scripts/find-evil - parsed-evidence egress requires explicit consent"
        )
    else:
        print(f"{FAIL} scripts/find-evil - {egress_error}")
        failed += 1
    sift_egress_ok, sift_egress_error = _check_sift_egress_ack_contract()
    if sift_egress_ok:
        print(f"{OK} scripts/find-evil-sift - parsed-evidence egress requires consent")
    else:
        print(f"{FAIL} scripts/find-evil-sift - {sift_egress_error}")
        failed += 1
    post_egress_ok, post_egress_error = _check_post_verdict_egress_contract()
    if post_egress_ok:
        print(f"{OK} scripts/verdict - post-verdict network workflows require consent")
    else:
        print(f"{FAIL} scripts/verdict - {post_egress_error}")
        failed += 1

    print()
    print("=" * 60)
    if failed:
        print(f"FAIL - {failed} assertion(s) failed across {len(launchers)} launchers.")
        print("To fix: see scripts/find-evil and scripts/find-evil-sift for")
        print("the canonical pattern (cd to repo, command -v claude check,")
        print("exec claude with no positional args).")
        return 1
    total_assertions = len(launchers) * 3 + 3
    print(
        f"OK - all {total_assertions} launcher assertions pass "
        f"({len(launchers)} launchers x 3 static checks + 3 consent checks)."
    )
    print("=" * 60)
    return 0


if __name__ == "__main__":
    sys.exit(main())
