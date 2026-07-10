"""Same-host disk+memory fusion drives the shipped Investigation method.

Proves `_fuse_disk_memory_execution` upgrades Prefetch leads when the same
executable name appears in memory timeline events — without reimplementing
fusion rules outside the engine.
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock

_SCRIPTS = Path(__file__).resolve().parents[3] / "scripts"
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import find_evil_auto as fea  # noqa: E402


class TestDiskMemoryFusion:
    def _inv(self) -> fea.Investigation:
        inv = fea.Investigation("pair", unattended=True, with_report=False)
        inv.handle = {"id": "case-fusion"}
        return inv

    def test_no_inputs_is_silent(self) -> None:
        inv = self._inv()
        inv._fuse_disk_memory_execution(MagicMock())
        assert inv.findings_pool_a == []
        assert inv.findings_pool_b == []

    def test_matching_name_emits_corroboration_upgrade(self) -> None:
        inv = self._inv()
        # Prefetch-side lead recorded as the engine does in real runs.
        pf_finding = {
            "case_id": "case-fusion",
            "finding_id": "f-B-prefetch-evil",
            "tool_call_id": "tc-pf-1",
            "description": "Prefetch evil.exe run_count=3",
            "confidence": "INFERRED",
            "pool_origin": "B",
        }
        inv._prefetch_exec_findings.append(("evil.exe", pf_finding))
        inv.findings_pool_b.append(pf_finding)
        inv.tool_calls.append({"tool": "vol_pslist", "tool_call_id": "tc-mem-1"})
        inv.timeline_events.append(
            {
                "artifact_class": "memory",
                "description": "process start: evil.exe pid=4242",
                "tool_call_id": "tc-mem-1",
            }
        )
        inv._fuse_disk_memory_execution(MagicMock())
        # Fusion either upgrades the existing finding or appends a fusion lead.
        blobs = " ".join(
            f.get("description", "") + " " + str(f.get("confidence"))
            for f in inv.findings_pool_a + inv.findings_pool_b
        ).lower()
        assert (
            "fusion" in blobs
            or "corroborat" in blobs
            or any(
                f.get("confidence") == "CONFIRMED"
                for f in inv.findings_pool_a + inv.findings_pool_b
            )
        ), blobs[:500]
