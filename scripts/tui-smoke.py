#!/usr/bin/env python3
"""tui-smoke - build verdict-tui and drive it non-interactively.

The VERDICT TUI (apps/tui, the `verdict-tui` binary) is a read-only case
viewer: it renders a finished case directory's JSON and, by construction,
never opens evidence, never calls an MCP/forensic tool, and never emits a
Finding. This smoke locks that contract without a terminal:

  1. Build the crate (`cargo build -p verdict-tui --locked`). If the build
     cannot run (no cargo) or fails offline but a binary already exists,
     fall back to the existing binary; otherwise fail.
  2. Static doctrine check over apps/tui/src: the source must not reference
     `evidence_path`, spawn a subprocess (`Command::new`), or pull a network
     client crate - the structural guarantee behind "read-only by
     construction".
  3. Run `verdict-tui --print` (headless TestBackend render to stdout)
     against the committed sample-run fixtures AND with no argument
     (newest-case discovery). Assert exit 0, non-empty output, the VERDICT
     header, and no Rust panic on stderr.
  4. Assert the run wrote nothing under `evidence/`.

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
FORBIDDEN_SOURCE = {
    '"evidence_path"': "the viewer must never read/resolve the evidence path field",
    "Command::new": "the viewer must never spawn a subprocess / forensic tool",
    "reqwest": "the viewer must never make a network/MCP call",
    "TcpStream": "the viewer must never open a network connection",
}


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


def main() -> int:
    print("tui-smoke: verdict-tui read-only viewer")

    if not SAMPLE_RUN.is_dir():
        fail(f"missing fixtures dir {SAMPLE_RUN}")

    binary = build()
    check_source_doctrine()

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

    # 4. The viewer wrote nothing under evidence/.
    after = snapshot_tree(EVIDENCE)
    if after != before:
        added = after - before
        fail(f"viewer wrote under evidence/: {sorted(p for p, _ in added)}")
    print("  evidence/ untouched")

    print("OK: verdict-tui builds, renders headlessly, and stays read-only")
    return 0


if __name__ == "__main__":
    sys.exit(main())
