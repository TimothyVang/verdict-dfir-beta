from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from findevil_agent.crypto.audit_log import AuditLog

from findevil_agent_mcp.tools.manifest_finalize import (
    ManifestWorkflowError,
    validate_manifest_workflow,
)


def _qa_payload() -> dict[str, object]:
    report = {"status": "PASS", "checks": []}
    digest = hashlib.sha256(
        json.dumps(report, separators=(",", ":"), sort_keys=True).encode()
    ).hexdigest()
    return {
        "status": "PASS",
        "report_qa": report,
        "report_qa_sha256": digest,
    }


def test_manifest_workflow_requires_audited_report_qa(tmp_path: Path) -> None:
    log = AuditLog(tmp_path / "audit.jsonl")
    log.append("agent_message", {"content": "started"})

    with pytest.raises(ManifestWorkflowError, match="report_qa"):
        validate_manifest_workflow(log)


@pytest.mark.parametrize("missing", ["verifier", "handoff"])
def test_manifest_workflow_requires_verified_handoff_per_finding(
    tmp_path: Path, missing: str
) -> None:
    log = AuditLog(tmp_path / "audit.jsonl")
    log.append("tool_call_output", {"tool_call_id": "tc-1", "output_hash": "a" * 64})
    if missing != "verifier":
        log.append(
            "verifier_action",
            {
                "finding_id": "f-1",
                "action": "approved",
                "replay_matched": True,
                "replay_artifact": {"entailment": {"passed": True}},
            },
        )
    if missing != "handoff":
        log.append(
            "acp_handoff",
            {
                "correlation_id": "f-1",
                "from_role": "verifier",
                "to_role": "judge",
                "payload": {"finding_id": "f-1", "action": "approved"},
            },
        )
    log.append(
        "finding_approved",
        {"finding_id": "f-1", "tool_call_id": "tc-1"},
    )
    log.append("report_qa", _qa_payload())

    with pytest.raises(ManifestWorkflowError, match=missing):
        validate_manifest_workflow(log)


def test_manifest_workflow_accepts_replayed_handed_off_finding(tmp_path: Path) -> None:
    log = AuditLog(tmp_path / "audit.jsonl")
    log.append("tool_call_output", {"tool_call_id": "tc-1", "output_hash": "a" * 64})
    log.append(
        "verifier_action",
        {
            "finding_id": "f-1",
            "action": "approved",
            "replay_matched": True,
            "replay_artifact": {"entailment": {"passed": True}},
        },
    )
    log.append(
        "acp_handoff",
        {
            "correlation_id": "f-1",
            "from_role": "verifier",
            "to_role": "judge",
            "payload": {"finding_id": "f-1", "action": "approved"},
        },
    )
    log.append("finding_approved", {"finding_id": "f-1", "tool_call_id": "tc-1"})
    log.append("report_qa", _qa_payload())

    validate_manifest_workflow(log)
