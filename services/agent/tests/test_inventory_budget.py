"""Tests for the evidence-inventory budget report.

``build_local_evidence_inventory`` stops walking at ``limit`` and sets
``truncated: true``. That says the walk stopped; it does not say what it did not
look at. Downstream -- notably a coverage ledger claiming what was inspected --
that reads as coverage over the whole tree: 500 of 500 is indistinguishable from
500 of 40,000 unless the denominator travels with the result.

So the inventory now carries ``discovered`` (candidates the walk saw) and
``over_budget`` (candidates it never examined) alongside ``truncated``.

- B1: under budget, discovered == inspected and over_budget is 0.
- B2: over budget, the three reconcile: inspected + over_budget == discovered.
- B3: truncated stays true when the budget binds, and the counts say by how much
      -- a boolean alone was the gap.
- B4: adding the counts does not destabilise inventory_sha256 run-to-run, which
      is what offline re-verification reproduces.
"""

from __future__ import annotations

import sys
from pathlib import Path

_SCRIPTS = Path(__file__).resolve().parents[3] / "scripts"
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import find_evil_auto as fea  # noqa: E402


def _tree(tmp_path: Path, count: int) -> Path:
    root = tmp_path / "evidence"
    root.mkdir()
    for i in range(count):
        (root / f"f{i:03d}.txt").write_text(f"artifact {i}")
    return root


def test_b1_under_budget_reports_a_full_denominator(tmp_path: Path) -> None:
    root = _tree(tmp_path, 12)
    inv = fea.build_local_evidence_inventory(root, limit=500)
    assert inv["discovered"] == 12
    assert inv["summary"]["inspected"] == 12
    assert inv["over_budget"] == 0
    assert inv["truncated"] is False


def test_b2_over_budget_counts_reconcile(tmp_path: Path) -> None:
    root = _tree(tmp_path, 30)
    inv = fea.build_local_evidence_inventory(root, limit=10)
    assert inv["summary"]["inspected"] + inv["over_budget"] == inv["discovered"], (
        "every discovered candidate must be either inspected or counted as "
        "over budget; anything else is an object that vanished silently"
    )


def test_b3_truncation_says_by_how_much(tmp_path: Path) -> None:
    root = _tree(tmp_path, 30)
    inv = fea.build_local_evidence_inventory(root, limit=10)
    assert inv["truncated"] is True
    assert inv["over_budget"] > 0, "truncated without a count is the original gap"
    assert inv["summary"]["over_budget"] == inv["over_budget"]


def test_b4_the_counts_do_not_destabilise_the_custody_digest(tmp_path: Path) -> None:
    root = _tree(tmp_path, 8)
    first = fea.build_local_evidence_inventory(root, limit=500)
    second = fea.build_local_evidence_inventory(root, limit=500)
    assert first["inventory_sha256"] == second["inventory_sha256"], (
        "offline re-verification reproduces this digest; the budget counts are "
        "derived from the same walk and must not make it vary run-to-run"
    )
