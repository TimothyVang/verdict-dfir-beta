"""Tests for verify_finding wrapper.

Uses ``MockMcpClient`` via monkeypatching ``_make_mcp_client`` so we
don't spawn a real Rust subprocess in unit tests.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
from findevil_agent.mcp_client import (
    McpClientError,
    MockMcpClient,
)
from findevil_agent.mcp_client import (
    StdioMcpClient as RealStdioMcpClient,
)
from pydantic import ValidationError

from findevil_agent_mcp.tools import verify_finding as vf
from findevil_agent_mcp.tools.verify_finding import (
    SPEC,
    VerifyFindingInput,
    VerifyFindingOutput,
)


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _finding_dict(**over: Any) -> dict[str, Any]:
    base = {
        "case_id": "case-001",
        "finding_id": "f-1",
        "tool_call_id": "tc-1",
        "artifact_path": "C:\\Windows\\Temp\\x.exe",
        "confidence": "CONFIRMED",
        "mitre_technique": "T1059",
        "description": "scheduled task points at writable temp",
        "pool_origin": "A",
    }
    base.update(over)
    return base


def test_make_mcp_client_uses_slow_tool_replay_timeout() -> None:
    # Regression: the verify replay must allow slow memory plugins (vol_malfind
    # on a multi-GB image) the same budget the main run gives them, or legit
    # findings get rejected with "MCP request timed out after 120.0s".
    client = vf._make_mcp_client()
    try:
        assert client._request_timeout_s >= 1800.0
    finally:
        client.close()


def test_make_mcp_client_replay_env_excludes_ambient_credentials(
    monkeypatch: Any,
) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "openai-secret")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "aws-secret")
    monkeypatch.setenv("FINDEVIL_SIGNING_KEY", "/case/private-signing.key")
    monkeypatch.setenv("FINDEVIL_HOME", "/case/findevil")
    monkeypatch.setenv("FINDEVIL_OUTPUT_ROUTE", "local_dgx")

    client = vf._make_mcp_client()
    try:
        assert client._env is not None
        assert client._env["FINDEVIL_HOME"] == "/case/findevil"
        assert client._env["FINDEVIL_OUTPUT_ROUTE"] == "local_dgx"
        assert "OPENAI_API_KEY" not in client._env
        assert "AWS_SECRET_ACCESS_KEY" not in client._env
        assert "FINDEVIL_SIGNING_KEY" not in client._env
    finally:
        client.close()


def test_make_mcp_client_uses_fixed_docker_replay_without_signing_state(
    monkeypatch: Any,
) -> None:
    captured: dict[str, Any] = {}

    class _Client:
        def __init__(self, command: list[str], **kwargs: Any) -> None:
            captured["command"] = command
            captured.update(kwargs)

        def close(self) -> None:
            return None

    monkeypatch.setenv("FINDEVIL_REPLAY_TRANSPORT", "docker")
    monkeypatch.setenv("FINDEVIL_REPLAY_DOCKER_CONTAINER", "findevil-dfir")
    monkeypatch.setenv("FINDEVIL_SIGNING_KEY", "/host/private/signing.key")
    monkeypatch.setenv("FINDEVIL_BROWSER_SQLITE_MAX_OPS", "7654321")
    monkeypatch.setenv("FINDEVIL_FLS_TIMEOUT_SECONDS", "321")
    monkeypatch.setenv("FINDEVIL_ICAT_TIMEOUT_SECONDS", "123")
    monkeypatch.setenv("FINDEVIL_MMLS_TIMEOUT_SECONDS", "45")
    monkeypatch.setenv("FINDEVIL_OUTPUT_ROUTE", "local_controller")
    monkeypatch.setattr(vf, "StdioMcpClient", _Client)
    removals: list[tuple[list[str], dict[str, Any]]] = []
    monkeypatch.setattr(
        vf.subprocess,
        "run",
        lambda argv, **kwargs: removals.append((argv, kwargs)),
    )

    vf._make_mcp_client()

    command = captured["command"]
    # The docker binary resolves to a full path (e.g. C:\...\docker.EXE on
    # Windows), so compare the stem case-insensitively rather than the raw string.
    assert Path(command[0]).stem.lower() == "docker"
    assert command[1:4] == ["exec", "-i", "-e"]
    assert "FINDEVIL_BROWSER_SQLITE_MAX_OPS=7654321" in command
    assert "FINDEVIL_FLS_TIMEOUT_SECONDS=321" in command
    assert "FINDEVIL_ICAT_TIMEOUT_SECONDS=123" in command
    assert "FINDEVIL_MMLS_TIMEOUT_SECONDS=45" in command
    assert "FINDEVIL_OUTPUT_ROUTE=local_controller" in command
    assert command[-2:] == ["findevil-dfir", "/workspace/target/release/findevil-mcp"]
    assert all("SIGNING" not in part for part in command)
    assert "FINDEVIL_SIGNING_KEY" not in captured["env"]
    assert callable(captured["abort_callback"])
    captured["abort_callback"]()
    assert removals[0][0] == [command[0], "rm", "-f", "findevil-dfir"]
    assert "FINDEVIL_SIGNING_KEY" not in removals[0][1]["env"]


def test_malformed_replay_response_removes_docker_runtime(
    monkeypatch: Any,
) -> None:
    monkeypatch.setenv("FINDEVIL_REPLAY_TRANSPORT", "docker")
    monkeypatch.setenv("FINDEVIL_REPLAY_DOCKER_CONTAINER", "findevil-dfir-case")
    removals: list[list[str]] = []

    # Return a real CompletedProcess: on Windows the client's process-tree
    # teardown also routes through subprocess.run (taskkill) and reads
    # completed.returncode, so a None-returning stub would crash there before the
    # non-JSON error surfaces. On POSIX teardown uses killpg, so only the docker
    # removal is captured; on Windows the taskkill call is captured too, so the
    # assertions below select the docker call rather than assuming a single entry.
    def fake_run(argv: list[str], **_kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        removals.append(argv)
        return subprocess.CompletedProcess(argv, 0)

    monkeypatch.setattr(vf.subprocess, "run", fake_run)

    def local_malformed_client(_command: list[str], **kwargs: Any) -> RealStdioMcpClient:
        return RealStdioMcpClient(
            [
                sys.executable,
                "-c",
                "import sys; sys.stdin.buffer.readline(); print('{bad', flush=True)",
            ],
            abort_callback=kwargs["abort_callback"],
        )

    monkeypatch.setattr(vf, "StdioMcpClient", local_malformed_client)
    client = vf._make_mcp_client()
    try:
        with pytest.raises(McpClientError, match="non-JSON"):
            client.call_tool("probe", {})
    finally:
        client.close()

    docker_removals = [argv for argv in removals if Path(argv[0]).stem.lower() == "docker"]
    assert len(docker_removals) == 1
    assert docker_removals[0][1:] == ["rm", "-f", "findevil-dfir-case"]


def test_make_mcp_client_rejects_unsafe_docker_container_name(
    monkeypatch: Any,
) -> None:
    monkeypatch.setenv("FINDEVIL_REPLAY_TRANSPORT", "docker")
    monkeypatch.setenv("FINDEVIL_REPLAY_DOCKER_CONTAINER", "--privileged")
    with pytest.raises(RuntimeError, match="unsafe Docker replay container"):
        vf._make_mcp_client()


@pytest.mark.parametrize(
    "field,value",
    [
        ("findevil_mcp_command", ["sh", "-c", "id"]),
        ("command", ["/tmp/alternate-server"]),
        ("env", {"FINDEVIL_BROWSER_CASE_BINDING": "forged"}),
    ],
)
def test_verify_input_rejects_caller_controlled_process_configuration(
    field: str, value: object
) -> None:
    with pytest.raises(ValidationError):
        VerifyFindingInput.model_validate(
            {
                "finding": _finding_dict(),
                "tool_call_index": {},
                field: value,
            }
        )


def test_verify_input_rejects_oversized_tool_call_index() -> None:
    tool_call_index = {
        f"tc-{index}": {
            "tool_name": "hashset_lookup",
            "arguments": {"case_id": "case-001", "hashes": ["a" * 32]},
            "output_sha256": "0" * 64,
        }
        for index in range(257)
    }
    with pytest.raises(ValidationError):
        VerifyFindingInput(finding=_finding_dict(), tool_call_index=tool_call_index)


def test_verify_input_rejects_deeply_nested_replay_arguments() -> None:
    nested: dict[str, Any] = {"leaf": "value"}
    for _ in range(20):
        nested = {"next": nested}
    with pytest.raises(ValidationError, match="nesting depth limit"):
        VerifyFindingInput(
            finding=_finding_dict(),
            tool_call_index={
                "tc-1": {
                    "tool_name": "hashset_lookup",
                    "arguments": nested,
                    "output_sha256": "0" * 64,
                }
            },
        )


class TestVerifyFinding:
    @pytest.mark.parametrize(
        "tool_name",
        [
            "case_open",
            "disk_mount",
            "disk_extract_artifacts",
            "disk_unmount",
            "vss_mount",
            "mac_triage",
        ],
    )
    async def test_stateful_or_derived_output_tool_is_rejected_before_spawn(
        self, monkeypatch: Any, tool_name: str
    ) -> None:
        spawned = False

        def forbidden_spawn() -> MockMcpClient:
            nonlocal spawned
            spawned = True
            raise AssertionError("disallowed replay must not spawn Rust MCP")

        monkeypatch.setattr(vf, "_make_mcp_client", forbidden_spawn)
        result = await SPEC.handler(
            VerifyFindingInput(
                finding=_finding_dict(),
                tool_call_index={
                    "tc-1": {
                        "tool_name": tool_name,
                        "arguments": {"case_id": "forged"},
                        "output_sha256": "0" * 64,
                    }
                },
            )
        )

        assert result.action == "rejected"
        assert "not replay-safe" in result.reason
        assert spawned is False

    @pytest.mark.parametrize("tool_name", ["bulk_extract", "ez_parse", "plaso_parse"])
    async def test_finding_producing_derived_parser_is_replay_safe(
        self, monkeypatch: Any, tool_name: str
    ) -> None:
        canned_text = json.dumps(
            {"rows": [{"evidence": "derived parser output"}]},
            sort_keys=True,
            separators=(",", ":"),
        )
        expected_sha = _sha(canned_text)
        client = MockMcpClient()
        client.register(tool_name, lambda _args: canned_text)
        monkeypatch.setattr(vf, "_make_mcp_client", lambda: client)

        result = await SPEC.handler(
            VerifyFindingInput(
                finding=_finding_dict(),
                tool_call_index={
                    "tc-1": {
                        "tool_name": tool_name,
                        "arguments": {"case_id": "case-001"},
                        "output_sha256": expected_sha,
                    }
                },
            )
        )

        assert result.action == "approved"
        assert result.replay_tool_name == tool_name

    async def test_replay_match_approves(self, monkeypatch: Any) -> None:
        canned_text = json.dumps(
            {"rows": [{"id": 1, "data": "x"}]}, sort_keys=True, separators=(",", ":")
        )
        expected_sha = _sha(canned_text)

        client = MockMcpClient()
        client.register("evtx_query", lambda args: canned_text)

        monkeypatch.setattr(vf, "_make_mcp_client", lambda: client)

        result = await SPEC.handler(
            VerifyFindingInput(
                finding=_finding_dict(),
                tool_call_index={
                    "tc-1": {
                        "tool_name": "evtx_query",
                        "arguments": {"case_id": "case-001"},
                        "output_sha256": expected_sha,
                    }
                },
            )
        )
        assert isinstance(result, VerifyFindingOutput)
        assert result.action == "approved"
        assert result.replay_matched is True
        assert result.replay_actual_sha256 == expected_sha
        assert result.replay_artifact is not None
        assert result.replay_artifact.drift_class == "exact_match"
        assert result.replay_artifact.expected_sha256 == result.replay_expected_sha256

    async def test_replay_drift_on_confirmed_rejects_first_pass(self, monkeypatch: Any) -> None:
        # sha256 drift on a CONFIRMED finding is rejected on the first pass so
        # the orchestrator re-dispatches once with a fresh replay.
        client = MockMcpClient()
        client.register("evtx_query", lambda args: "DIFFERENT_OUTPUT")
        monkeypatch.setattr(vf, "_make_mcp_client", lambda: client)

        result = await SPEC.handler(
            VerifyFindingInput(
                finding=_finding_dict(),
                tool_call_index={
                    "tc-1": {
                        "tool_name": "evtx_query",
                        "arguments": {},
                        "output_sha256": "0" * 64,
                    }
                },
            )
        )
        assert isinstance(result, VerifyFindingOutput)
        assert result.action == "rejected"
        assert result.replay_matched is False
        assert result.replay_artifact is not None
        assert result.replay_artifact.drift_class == "material_drift"

    async def test_replay_drift_downgrades_on_redispatch(self, monkeypatch: Any) -> None:
        # The re-dispatch attempt passes downgrade_on_drift=True: persistent
        # drift takes the terminal downgrade.
        client = MockMcpClient()
        client.register("evtx_query", lambda args: "DIFFERENT_OUTPUT")
        monkeypatch.setattr(vf, "_make_mcp_client", lambda: client)

        result = await SPEC.handler(
            VerifyFindingInput(
                finding=_finding_dict(),
                tool_call_index={
                    "tc-1": {
                        "tool_name": "evtx_query",
                        "arguments": {},
                        "output_sha256": "0" * 64,
                    }
                },
                downgrade_on_drift=True,
            )
        )
        assert isinstance(result, VerifyFindingOutput)
        assert result.action == "downgraded"
        assert result.replay_matched is False
        assert result.replay_artifact is not None
        assert result.replay_artifact.drift_class == "material_drift"

    async def test_missing_tool_call_id_rejected(self, monkeypatch: Any) -> None:
        client = MockMcpClient()
        monkeypatch.setattr(vf, "_make_mcp_client", lambda: client)

        result = await SPEC.handler(
            VerifyFindingInput(
                finding=_finding_dict(tool_call_id="tc-missing"),
                tool_call_index={},
            )
        )
        assert isinstance(result, VerifyFindingOutput)
        assert result.action == "rejected"
        assert "tc-missing" in result.reason

    async def test_blank_tool_call_id_rejected_gracefully(self, monkeypatch: Any) -> None:
        # A model emitting a CONFIRMED finding with a BLANK tool_call_id hits the
        # schema firewall (events.py _require_tool_call_id_for_anchored). At this
        # untrusted-input boundary that ValidationError must become a structured
        # 'rejected' action — the same graceful veto the verifier gave before the
        # firewall landed — not an uncaught error that breaks the run loop.
        client = MockMcpClient()
        monkeypatch.setattr(vf, "_make_mcp_client", lambda: client)

        result = await SPEC.handler(
            VerifyFindingInput(
                finding=_finding_dict(tool_call_id=""),
                tool_call_index={},
            )
        )
        assert isinstance(result, VerifyFindingOutput)
        assert result.action == "rejected"
        assert "tool_call_id" in result.reason
