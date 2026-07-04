#!/usr/bin/env python3
"""tui-smoke - build verdict-tui and drive it non-interactively.

The VERDICT TUI (apps/tui, the `verdict-tui` binary) is a read-only case
viewer and live monitor: it renders a case directory's JSON and, in drive
mode, launches the repo's own `scripts/verdict` launcher and tails the run.
By construction it never opens evidence itself, never calls an MCP/forensic
tool, and never emits a Finding. This smoke locks that contract without a
terminal:

  1. Build the crate (`cargo build -p verdict-tui --locked`). If the build
     cannot run (no cargo) or fails offline but a binary already exists,
     fall back to the existing binary; otherwise fail.
  2. Static doctrine check over apps/tui/src: the source must not read the
     evidence-path field, or pull a network client crate - the structural
     guarantee behind "read-only by construction".
  3. Launcher isolation: the ONLY subprocess the crate spawns is
     `scripts/verdict`, spawned solely from case/runner.rs. No other source
     file may call `Command::new`; runner.rs must spawn exactly once, pin the
     program to the `scripts/verdict` launcher constant, and open no shell or
     forensic-tool escape hatch.
  4. Run `verdict-tui --print` (headless TestBackend render to stdout)
     against the committed sample-run fixtures AND with no argument
     (newest-case discovery). Assert exit 0, non-empty output, the VERDICT
     header, and no Rust panic on stderr. Also assert `--print --drive` is
     rejected (the live path never runs headless) without spawning anything.
  5. Assert the run wrote nothing under `evidence/`.

Evidence-agnostic: the fixtures are discovered under docs/sample-run and
the checks key on structural markers ("VERDICT", the scoped verdict word),
never a specific image's values.

Wall-clock: ~1s once the debug binary exists (incremental build is a
no-op). Wired into scripts/run-all-smokes.sh beside the other Rust smokes.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SRC = REPO / "apps" / "tui" / "src"
SAMPLE_RUN = REPO / "docs" / "sample-run"
EVIDENCE = REPO / "evidence"

# Fixtures the viewer must render cleanly (both committed under docs/sample-run).
FIXTURES = ("nitroba", "attack-samples-evtx")

# Scoped verdict vocabulary - at least one must appear in a rendered header.
VERDICT_WORDS = ("SUSPICIOUS", "INDETERMINATE", "NO_EVIL")

# Patterns that would break "read-only by construction" if they appeared in
# the TUI source. Each maps to why it is forbidden. `evidence_path` is
# matched in its JSON-key form ("evidence_path") so a real read of the field
# trips it while prose in doc comments that merely names it does not.
#
# `Command::new` is NOT here: Phase 2 drive mode must spawn the scripts/verdict
# launcher. That single, pinned spawn is enforced structurally by
# check_launcher_isolation() below instead of blanket-banned here.
FORBIDDEN_SOURCE = {
    '"evidence_path"': "the viewer must never read/resolve the evidence path field",
    "reqwest": "the viewer must never make a network/MCP call",
    "TcpStream": "the viewer must never open a network connection",
}

# The one module allowed to spawn a subprocess, and the launcher it must pin.
LAUNCHER_MODULE = SRC / "case" / "runner.rs"
LAUNCHER_MARKER = 'VERDICT_LAUNCHER: &str = "scripts/verdict"'

# Shell / raw-exec escape hatches that must never appear in the launcher: the
# only program it may start is the scripts/verdict launcher, never a shell or a
# forensic tool. Quoted forms avoid matching flag substrings like --no-dashboard.
LAUNCHER_ESCAPES = (
    '"/bin/sh"',
    '"/bin/bash"',
    '"sh"',
    '"bash"',
    '"-c"',
    "execute_shell",
    "shell_exec",
)


def fail(message: str) -> None:
    print(f"  FAIL: {message}")
    raise SystemExit(1)


def binary_path() -> Path | None:
    """Return an existing verdict-tui binary under the target dir, if any."""
    import os

    target = Path(os.environ.get("CARGO_TARGET_DIR", REPO / "target"))
    for profile in ("debug", "release"):
        for name in ("verdict-tui", "verdict-tui.exe"):
            candidate = target / profile / name
            if candidate.is_file():
                return candidate
    return None


def build() -> Path:
    """Build the crate; fall back to an existing binary if the build can't run."""
    print("  building verdict-tui (cargo build -p verdict-tui --locked) ...")
    try:
        result = subprocess.run(
            ["cargo", "build", "-p", "verdict-tui", "--locked"],
            cwd=REPO,
            capture_output=True,
            text=True,
            timeout=600,
        )
    except FileNotFoundError:
        existing = binary_path()
        if existing:
            print("  cargo not found; using existing binary")
            return existing
        fail("cargo not found and no prebuilt verdict-tui binary")
    except subprocess.TimeoutExpired:
        fail("cargo build timed out")

    if result.returncode != 0:
        existing = binary_path()
        if existing:
            print("  build failed (offline?); using existing binary")
            return existing
        fail(f"cargo build failed:\n{result.stderr[-2000:]}")

    built = binary_path()
    if not built:
        fail("build reported success but no binary was found")
    return built


def check_source_doctrine() -> None:
    """The source must not reference evidence, subprocesses, or network I/O."""
    hits: list[str] = []
    for path in SRC.rglob("*.rs"):
        text = path.read_text(encoding="utf-8", errors="replace")
        for needle, reason in FORBIDDEN_SOURCE.items():
            if needle in text:
                rel = path.relative_to(REPO)
                hits.append(f"{rel}: contains '{needle}' - {reason}")
    if hits:
        fail("read-only-by-construction violation in source:\n    " + "\n    ".join(hits))
    print(f"  source doctrine OK ({len(FORBIDDEN_SOURCE)} forbidden patterns absent)")


def check_launcher_isolation() -> None:
    """The only subprocess is scripts/verdict, spawned solely from runner.rs."""
    if not LAUNCHER_MODULE.is_file():
        fail(f"expected the launcher module at {LAUNCHER_MODULE.relative_to(REPO)}")

    # 1. `Command::new` may appear ONLY in the launcher module.
    offenders: list[str] = []
    for path in SRC.rglob("*.rs"):
        if path == LAUNCHER_MODULE:
            continue
        count = path.read_text(encoding="utf-8", errors="replace").count("Command::new")
        if count:
            offenders.append(
                f"{path.relative_to(REPO)}: {count} Command::new "
                "(only case/runner.rs may spawn a subprocess)"
            )
    if offenders:
        fail("subprocess spawn outside the launcher module:\n    " + "\n    ".join(offenders))

    runner = LAUNCHER_MODULE.read_text(encoding="utf-8", errors="replace")

    # 2. Exactly one spawn.
    spawns = runner.count("Command::new(")
    if spawns != 1:
        fail(f"launcher must spawn exactly one subprocess; runner.rs has {spawns} Command::new(")

    # 3. That spawn is pinned to the scripts/verdict launcher constant.
    if LAUNCHER_MARKER not in runner:
        fail(f"launcher must pin the program via `{LAUNCHER_MARKER}`")

    # 4. No shell / raw-exec escape hatch.
    hits = [needle for needle in LAUNCHER_ESCAPES if needle in runner]
    if hits:
        fail(f"launcher must not open a shell/raw-exec escape hatch: {sorted(hits)}")

    print("  launcher isolation OK (one scripts/verdict spawn in case/runner.rs, no shell escape)")


def snapshot_tree(root: Path) -> set[tuple[str, int]]:
    """Set of (relpath, size) for every file under root (empty if absent)."""
    if not root.exists():
        return set()
    out: set[tuple[str, int]] = set()
    for path in root.rglob("*"):
        if path.is_file():
            out.add((str(path.relative_to(root)), path.stat().st_size))
    return out


def run_print(binary: Path, args: list[str], label: str) -> str:
    result = subprocess.run(
        [str(binary), "--print", *args],
        cwd=REPO,
        capture_output=True,
        text=True,
        timeout=60,
    )
    stderr = result.stderr or ""
    if "panicked" in stderr or "RUST_BACKTRACE" in stderr:
        fail(f"{label}: viewer panicked:\n{stderr[-1500:]}")
    if result.returncode != 0:
        fail(f"{label}: exit {result.returncode}\n{stderr[-1500:]}")
    if not result.stdout.strip():
        fail(f"{label}: empty render")
    if "VERDICT" not in result.stdout:
        fail(f"{label}: rendered frame is missing the VERDICT header")
    print(f"  {label}: rendered OK (exit 0, no panic)")
    return result.stdout


def check_drive_print_rejected(binary: Path) -> None:
    """`--print --drive` must be refused (live path never runs headless)."""
    result = subprocess.run(
        [str(binary), "--print", "--drive", "/nonexistent/evidence"],
        cwd=REPO,
        capture_output=True,
        text=True,
        timeout=60,
    )
    stderr = result.stderr or ""
    if "panicked" in stderr:
        fail(f"--print --drive panicked:\n{stderr[-1500:]}")
    if result.returncode == 0:
        fail("--print --drive was accepted; the live path must not run headless")
    print("  --print --drive rejected (no subprocess, no headless drive)")


def main() -> int:
    print("tui-smoke: verdict-tui read-only viewer")

    if not SAMPLE_RUN.is_dir():
        fail(f"missing fixtures dir {SAMPLE_RUN}")

    binary = build()
    check_source_doctrine()
    check_launcher_isolation()

    before = snapshot_tree(EVIDENCE)

    # 1. Each committed fixture renders cleanly.
    for name in FIXTURES:
        fixture = SAMPLE_RUN / name
        if not (fixture / "verdict.json").is_file():
            fail(f"fixture {fixture} has no verdict.json")
        out = run_print(binary, [str(fixture)], f"fixture:{name}")
        if not any(word in out for word in VERDICT_WORDS):
            fail(f"fixture:{name}: no scoped verdict word in header")

    # 2. Detail pane render (exercises the custody strip path).
    run_print(binary, ["--detail", str(SAMPLE_RUN / FIXTURES[0])], "detail-pane")

    # 3. No-argument newest-case discovery under the allow-listed roots.
    run_print(binary, [], "newest-case-discovery")

    # 4. The interactive drive path refuses to run headless (and spawns nothing).
    check_drive_print_rejected(binary)

    # 5. The viewer wrote nothing under evidence/.
    after = snapshot_tree(EVIDENCE)
    if after != before:
        added = after - before
        fail(f"viewer wrote under evidence/: {sorted(p for p, _ in added)}")
    print("  evidence/ untouched")

    print("OK: verdict-tui builds, renders headlessly, and stays read-only")
    return 0


if __name__ == "__main__":
    sys.exit(main())
