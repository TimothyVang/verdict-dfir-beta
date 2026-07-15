from __future__ import annotations

import sys
from pathlib import Path

import pytest

_SCRIPTS = Path(__file__).resolve().parents[3] / "scripts"
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import find_evil_auto as fea  # noqa: E402


def test_evtx_agent_receives_only_evtx_tools() -> None:
    tools = [
        {"name": "evtx_query"},
        {"name": "vol_pslist"},
        {"name": "disk_mount"},
    ]

    scoped = fea._scope_agent_mcp_tools(tools, "evtx")

    assert [tool["name"] for tool in scoped] == ["evtx_query"]


def test_unknown_agent_evidence_keeps_available_tools() -> None:
    tools = [{"name": "evtx_query"}, {"name": "vol_pslist"}]

    assert fea._scope_agent_mcp_tools(tools, "unknown") == tools


def test_agent_directory_is_rejected_before_mcp_startup(monkeypatch, tmp_path: Path) -> None:
    investigation = object.__new__(fea.Investigation)
    investigation.evidence = str(tmp_path)
    investigation.case_id = "case-directory"
    investigation.run_id = "run-directory"
    investigation.unattended = True
    investigation.signer = "stub"
    investigation.agent_mode = True

    def unexpected_client(*_args, **_kwargs):
        raise AssertionError("MCP client started before agent directory guard")

    monkeypatch.setattr(fea, "StdioMcpClient", unexpected_client)
    monkeypatch.setattr(fea, "SshMcpClient", unexpected_client)

    with pytest.raises(
        ValueError,
        match=r"Phase 4 native agent currently supports single-file evidence only",
    ):
        investigation.run()


def test_agent_task_supplies_the_open_case_id() -> None:
    task = fea._agent_pod_task("/evidence/sample.evtx", "case-456", "evtx")

    assert "case-456" in task
    assert "already open" in task
    assert "without an eids filter" in task


def test_evtx_tool_arguments_are_bound_to_the_open_case() -> None:
    arguments = fea._bind_agent_tool_args(
        "evtx_query",
        {
            "case_id": "invented",
            "evtx_path": "/wrong/file.evtx",
            "eid": "[4624, 4688]",
            "limit": "100",
        },
        evidence_path="/evidence/sample.evtx",
        case_id="case-456",
    )

    assert arguments == {
        "case_id": "case-456",
        "evtx_path": "/evidence/sample.evtx",
        "eids": [4624, 4688],
        "limit": 100,
    }


def test_empty_agent_result_is_indeterminate_not_no_evil() -> None:
    investigation = object.__new__(fea.Investigation)
    investigation.agent_mode = True
    investigation.evidence = "/evidence/sample.evtx"
    investigation.evidence_inventory = None
    investigation.tool_calls = [{"tool": "evtx_query"}]
    investigation.verifier_replay_failures = []
    investigation._heartbeat_escalated = False
    investigation._unexamined_available_classes = lambda: []

    assert investigation.compute_verdict([]) == "INDETERMINATE"


def test_evtx_tool_arguments_reject_bad_filters_and_bound_limits() -> None:
    with pytest.raises(ValueError, match="eids"):
        fea._bind_agent_tool_args(
            "evtx_query",
            {"eids": [1102, "bad"]},
            evidence_path="/evidence/sample.evtx",
            case_id="case-456",
        )

    bounded = fea._bind_agent_tool_args(
        "evtx_query",
        {"eids": list(range(100)), "limit": 999999999},
        evidence_path="/evidence/sample.evtx",
        case_id="case-456",
    )
    assert len(bounded["eids"]) == 64
    assert bounded["limit"] == 10000
