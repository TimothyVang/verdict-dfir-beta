"""CONFIRMED execution findings cite two artifact classes (prefetch + UserAssist);
the Reproducibility Appendix must attest BOTH, not just the primary replay.

``_verify_execution_corroborations`` replays each corroborating tool call once
(deduped — many findings share one UserAssist call) and stashes the result so
``_embed_verifier_replays`` attaches it as ``corroboration_replays``. These tests
pin the custody logic without an SSH/MCP run, using a fake client.
"""

from __future__ import annotations

import sys
import types
from pathlib import Path

_SCRIPTS = Path(__file__).resolve().parents[3] / "scripts"
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import find_evil_auto as fea  # noqa: E402

_ARTIFACT = {
    "tool_name": "registry_query",
    "drift_class": "exact_match",
    "matched": True,
    "expected_sha256": "ab" * 32,
    "actual_sha256": "ab" * 32,
}


class _FakePy:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def call_tool(self, name, args, timeout=None):
        assert name == "verify_finding"
        self.calls.append(args["finding"]["tool_call_id"])
        return {"replay_artifact": dict(_ARTIFACT)}


def _fake_orchestrator() -> types.SimpleNamespace:
    fake = types.SimpleNamespace(
        execution_corroboration={"f1": ["tc-214"], "f2": ["tc-214"]},  # shared corr call
        corroboration_replays={},
        handle={"id": "case-1"},
        force_fresh_replay=False,
        _tool_call_index=lambda: {
            "tc-214": {"tool_name": "registry_query", "output_sha256": "ab" * 32}
        },
    )
    # bind the real methods to the fake self
    fake._replay_corroboration_tcid = types.MethodType(
        fea.Investigation._replay_corroboration_tcid, fake
    )
    fake._verify_execution_corroborations = types.MethodType(
        fea.Investigation._verify_execution_corroborations, fake
    )
    fake._embed_verifier_replays = types.MethodType(
        fea.Investigation._embed_verifier_replays, fake
    )
    fake.verifier_replays = {}
    return fake


def test_corroborating_call_replayed_once_and_attached_to_each_finding() -> None:
    fake = _fake_orchestrator()
    py = _FakePy()
    findings = [
        {"finding_id": "f1", "tool_call_id": "tc-010", "confidence": "CONFIRMED"},
        {"finding_id": "f2", "tool_call_id": "tc-011", "confidence": "CONFIRMED"},
    ]

    fake._verify_execution_corroborations(py, findings)

    # The shared UserAssist call is replayed exactly once (deduped)...
    assert py.calls == ["tc-214"]
    # ...but attached to both findings.
    assert fake.corroboration_replays["f1"][0]["tool_name"] == "registry_query"
    assert fake.corroboration_replays["f2"][0]["matched"] is True

    # Embedding surfaces it as corroboration_replays on the finding.
    enriched = fake._embed_verifier_replays(findings)
    by_id = {f["finding_id"]: f for f in enriched}
    assert by_id["f1"]["corroboration_replays"][0]["expected_sha256"] == "ab" * 32
    assert "corroboration_replays" not in {  # a finding with no corroboration stays clean
        **{"finding_id": "f3", "tool_call_id": "tc-9"}
    }


def test_primary_tcid_is_not_double_replayed_as_corroboration() -> None:
    fake = _fake_orchestrator()
    # corroboration tcid equals the finding's primary -> must be skipped
    fake.execution_corroboration = {"f1": ["tc-010"]}
    py = _FakePy()
    findings = [{"finding_id": "f1", "tool_call_id": "tc-010", "confidence": "CONFIRMED"}]

    fake._verify_execution_corroborations(py, findings)

    assert py.calls == []  # nothing replayed; primary != corroboration
    assert fake.corroboration_replays == {}
