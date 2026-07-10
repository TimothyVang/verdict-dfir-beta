"""Disk parser limit telemetry must remain loud in engine coverage."""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock

_SCRIPTS = Path(__file__).resolve().parents[3] / "scripts"
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import find_evil_auto as fea  # noqa: E402


def test_disk_mount_and_extract_limits_reach_audit_and_analysis() -> None:
    inv = fea.Investigation("disk.img", unattended=True, with_report=False)
    inv.handle = {"id": "case-disk-limits"}
    inv.audit_path = "/tmp/case-disk-limits/audit.jsonl"
    inv._record_tool = MagicMock(return_value="tc-limit")  # type: ignore[method-assign]
    inv._audit = MagicMock()  # type: ignore[method-assign]
    inv.investigate_extracted_disk_artifacts = MagicMock()  # type: ignore[method-assign]
    inv.investigate_oe_dbx_stores = MagicMock()  # type: ignore[method-assign]
    inv._run_disk_yara_whole_mount = MagicMock()  # type: ignore[method-assign]

    responses = {
        "disk_mount": {
            "status": "mounted",
            "mount_id": "mount-1",
            "fs_root": "/mnt/case",
            "partitions": [
                {
                    "slot": 2,
                    "start_sector": 2048,
                    "length_sectors": 1_000_000,
                    "byte_offset": 1_048_576,
                    "description": "NTFS / exFAT (0x07)",
                },
                {
                    "slot": 3,
                    "start_sector": 1_002_048,
                    "length_sectors": 250_000,
                    "byte_offset": 513_048_576,
                    "description": "Linux (0x83)",
                },
            ],
            "partition_enumeration_error": "mmls timed out after 60 seconds",
        },
        "vss_list": {
            "vshadowinfo_available": True,
            "has_shadow_store": False,
            "store_count": 0,
        },
        "disk_extract_artifacts": {
            "artifacts": [
                {
                    "artifact_class": "prefetch",
                    "extracted_path": "/derived/CMD.EXE.pf",
                    "size_bytes": 42,
                }
            ],
            "artifact_candidates_seen": 11,
            "artifacts_skipped_limit": 7,
            "artifacts_skipped_oversize": 0,
            "artifacts_skipped_total_limit": 3,
            "artifacts_extraction_failed": 2,
            "truncated": True,
            "limit_reasons": [
                "artifact_count_limit",
                "aggregate_bytes",
                "artifact_extraction_failed",
            ],
            "requested_limit": 500,
            "effective_limit": 500,
            "limits_clamped": False,
        },
        "disk_unmount": {"status": "unmounted"},
    }
    rust = MagicMock()
    rust.call_tool.side_effect = lambda name, *_args, **_kwargs: responses[name]
    py = MagicMock()

    inv.investigate_disk(rust, py)

    recorded = {
        call.args[1]: call.args[3]
        for call in inv._record_tool.call_args_list
        if len(call.args) >= 4
    }
    assert recorded["disk_mount"]["partition_enumeration_error"].startswith("mmls")
    assert recorded["disk_mount"]["partition_count"] == 2
    assert recorded["disk_mount"]["partitions"][1]["slot"] == 3
    assert recorded["disk_extract_artifacts"]["truncated"] is True
    assert recorded["disk_extract_artifacts"]["limit_reasons"] == [
        "artifact_count_limit",
        "aggregate_bytes",
        "artifact_extraction_failed",
    ]
    assert recorded["disk_extract_artifacts"]["artifacts_skipped_limit"] == 7
    assert recorded["disk_extract_artifacts"]["artifacts_skipped_total_limit"] == 3
    assert recorded["disk_extract_artifacts"]["artifacts_extraction_failed"] == 2

    limitations = "\n".join(inv.analysis_limitations)
    assert "partition enumeration" in limitations.lower()
    assert "mmls timed out" in limitations
    assert "2 filesystem partitions" in limitations
    assert "primary partition" in limitations
    assert "artifact_count_limit" in limitations
    assert "aggregate_bytes" in limitations
    assert "artifact_extraction_failed" in limitations
    assert "7" in limitations and "3" in limitations and "2" in limitations

    audited_messages = [
        call.args[2]["content"]
        for call in inv._audit.call_args_list
        if len(call.args) >= 3
        and call.args[1] == "agent_message"
        and isinstance(call.args[2], dict)
    ]
    assert any("partition enumeration" in message.lower() for message in audited_messages)
    assert any("2 filesystem partitions" in message for message in audited_messages)
    assert any("artifact_count_limit" in message for message in audited_messages)
