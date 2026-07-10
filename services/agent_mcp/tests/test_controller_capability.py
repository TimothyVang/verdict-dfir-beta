from __future__ import annotations

from types import MappingProxyType

import pytest

from findevil_agent_mcp.server import (
    ControllerCapabilityError,
    authorize_controller_call,
)

CAPABILITY = "a" * 64


@pytest.mark.parametrize(
    "tool_name",
    [
        "audit_append",
        "pool_handoff",
        "manifest_finalize",
        "manifest_verify",
        "memory_remember",
        "expert_miss_capture",
    ],
)
def test_privileged_controller_tools_require_hidden_capability(
    monkeypatch: pytest.MonkeyPatch, tool_name: str
) -> None:
    monkeypatch.setenv("FINDEVIL_CONTROLLER_CAPABILITY", CAPABILITY)

    with pytest.raises(ControllerCapabilityError, match="private controller"):
        authorize_controller_call(tool_name, {})
    with pytest.raises(ControllerCapabilityError, match="private controller"):
        authorize_controller_call(tool_name, {"_controller_capability": "b" * 64})


def test_valid_controller_capability_is_removed_before_schema_validation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("FINDEVIL_CONTROLLER_CAPABILITY", CAPABILITY)
    original = MappingProxyType({"_controller_capability": CAPABILITY, "path": "/case/audit.jsonl"})

    authorized = authorize_controller_call("audit_append", original)

    assert authorized == {"path": "/case/audit.jsonl"}
    assert "_controller_capability" not in authorized


def test_pure_tool_does_not_gain_or_require_controller_capability(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("FINDEVIL_CONTROLLER_CAPABILITY", raising=False)
    assert authorize_controller_call("detect_contradictions", {"pool_a": []}) == {"pool_a": []}
