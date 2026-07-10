"""Whole-mount recursive disk YARA opt-in control path.

Drives the shipped env helpers and Investigation wiring in find_evil_auto —
not a reimplementation of yara_scan. recursive=true is the typed MCP path
already exercised by services/mcp yara_scan_smoke; this file asserts the
engine gate (default off, env on, timeout/limit bounds, skip when no rules
or no fs_root).
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock

_SCRIPTS = Path(__file__).resolve().parents[3] / "scripts"
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import find_evil_auto as fea  # noqa: E402


class TestWholeMountEnvHelpers:
    def test_default_off(self) -> None:
        assert fea.disk_yara_whole_mount_enabled({}) is False
        assert fea.disk_yara_whole_mount_enabled({"FIND_EVIL_DISK_YARA_WHOLE_MOUNT": ""}) is False

    def test_enabled_truthy_tokens(self) -> None:
        for token in ("1", "true", "YES", "on"):
            assert fea.disk_yara_whole_mount_enabled({"FIND_EVIL_DISK_YARA_WHOLE_MOUNT": token})

    def test_timeout_bounds(self) -> None:
        assert fea.disk_yara_whole_mount_timeout_s({}) == 1800.0
        assert (
            fea.disk_yara_whole_mount_timeout_s({"FIND_EVIL_DISK_YARA_WHOLE_MOUNT_TIMEOUT": "30"})
            == 60.0
        )  # floor
        assert (
            fea.disk_yara_whole_mount_timeout_s(
                {"FIND_EVIL_DISK_YARA_WHOLE_MOUNT_TIMEOUT": "99999"}
            )
            == 14400.0
        )  # ceiling
        assert (
            fea.disk_yara_whole_mount_timeout_s(
                {"FIND_EVIL_DISK_YARA_WHOLE_MOUNT_TIMEOUT": "not-a-number"}
            )
            == 1800.0
        )

    def test_limit_bounds(self) -> None:
        assert fea.disk_yara_whole_mount_limit({}) == 500
        assert fea.disk_yara_whole_mount_limit({"FIND_EVIL_DISK_YARA_WHOLE_MOUNT_LIMIT": "0"}) == 1
        assert (
            fea.disk_yara_whole_mount_limit({"FIND_EVIL_DISK_YARA_WHOLE_MOUNT_LIMIT": "99999"})
            == 5000
        )


class TestWholeMountEngineGate:
    def _inv(self) -> fea.Investigation:
        inv = fea.Investigation("disk.img", unattended=True, with_report=False)
        inv.handle = {"id": "case-yara-wm"}
        inv.audit_path = "/tmp/case-yara-wm/audit.jsonl"
        return inv

    def test_disabled_is_noop(self, monkeypatch) -> None:
        inv = self._inv()
        monkeypatch.setattr(fea, "disk_yara_whole_mount_enabled", lambda: False)
        rust = MagicMock()
        py = MagicMock()
        inv._run_disk_yara_whole_mount(rust, py, disk_case_id="case-yara-wm", fs_root="/mnt/case")
        rust.call_tool.assert_not_called()

    def test_enabled_without_rules_records_limitation(self, monkeypatch) -> None:
        inv = self._inv()
        monkeypatch.setattr(fea, "disk_yara_whole_mount_enabled", lambda: True)
        monkeypatch.setattr(fea, "DISK_YARA_RULES", None)
        rust = MagicMock()
        py = MagicMock()
        inv._run_disk_yara_whole_mount(rust, py, disk_case_id="case-yara-wm", fs_root="/mnt/case")
        rust.call_tool.assert_not_called()
        assert any(
            "WHOLE_MOUNT" in lim or "whole-mount" in lim.lower() or "YARA rules" in lim
            for lim in inv.analysis_limitations
        )

    def test_enabled_without_fs_root_records_limitation(self, monkeypatch) -> None:
        inv = self._inv()
        monkeypatch.setattr(fea, "disk_yara_whole_mount_enabled", lambda: True)
        monkeypatch.setattr(fea, "DISK_YARA_RULES", "/rules/disk-triage.yar")
        rust = MagicMock()
        py = MagicMock()
        inv._run_disk_yara_whole_mount(rust, py, disk_case_id="case-yara-wm", fs_root=None)
        rust.call_tool.assert_not_called()
        assert any("fs_root" in lim for lim in inv.analysis_limitations)

    def test_enabled_calls_yara_scan_recursive(self, monkeypatch) -> None:
        inv = self._inv()
        monkeypatch.setattr(fea, "disk_yara_whole_mount_enabled", lambda: True)
        monkeypatch.setattr(fea, "DISK_YARA_RULES", "/rules/disk-triage.yar")
        monkeypatch.setattr(fea, "disk_yara_whole_mount_timeout_s", lambda: 120.0)
        monkeypatch.setattr(fea, "disk_yara_whole_mount_limit", lambda: 42)
        rust = MagicMock()
        rust.call_tool.return_value = {
            "matches": [
                {
                    "file_path": "/mnt/case/Windows/evil.dll",
                    "rule_name": "demo_rule",
                }
            ],
            "files_scanned": 17,
            "rules_compiled": 3,
            "scan_errors": 0,
        }
        py = MagicMock()
        # _record_tool needs lighter stubs
        inv._record_tool = MagicMock(return_value="tc-wm-1")  # type: ignore[method-assign]
        inv._output_hash = MagicMock(return_value="deadbeef")  # type: ignore[method-assign]
        inv._run_disk_yara_whole_mount(rust, py, disk_case_id="case-yara-wm", fs_root="/mnt/case")
        rust.call_tool.assert_called_once()
        name, args = rust.call_tool.call_args[0][0], rust.call_tool.call_args[0][1]
        assert name == "yara_scan"
        assert args["recursive"] is True
        assert args["target_path"] == "/mnt/case"
        assert args["rules_path"] == "/rules/disk-triage.yar"
        assert args["limit"] == 42
        assert len(inv.findings_pool_b) == 1
        assert inv.findings_pool_b[0]["tool_call_id"] == "tc-wm-1"
        assert inv.findings_pool_b[0]["confidence"] == "HYPOTHESIS"
        assert (
            "whole-mount" in inv.findings_pool_b[0]["description"].lower()
            or "recursive" in inv.findings_pool_b[0]["description"].lower()
        )
