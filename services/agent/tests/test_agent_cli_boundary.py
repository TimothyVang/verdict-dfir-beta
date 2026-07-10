"""No-network tests for provider custody at the ``scripts/verdict --agent`` seam."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest

_REPO = Path(__file__).resolve().parents[3]
_ENGINE_PATH = _REPO / "scripts" / "find_evil_auto.py"


@pytest.fixture(scope="module")
def engine() -> ModuleType:
    spec = importlib.util.spec_from_file_location("find_evil_auto_agent_boundary", _ENGINE_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _argv(provider: str, *, acknowledge: bool) -> list[str]:
    args = [
        str(_ENGINE_PATH),
        "unused.evtx",
        "--agent",
        "--agent-provider",
        provider,
        "--skip-preflight",
    ]
    if acknowledge:
        args.append("--acknowledge-evidence-egress")
    return args


@pytest.mark.parametrize("provider", ["anthropic", "claude_cli", "openai", "openrouter"])
def test_cloud_provider_without_ack_stops_before_evidence_access(
    engine: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    provider: str,
) -> None:
    monkeypatch.setattr(sys, "argv", _argv(provider, acknowledge=False))
    monkeypatch.setattr(
        engine,
        "resolve_evidence_path",
        lambda _path: pytest.fail("egress gate ran after evidence access"),
    )

    assert engine.main() == 2


@pytest.mark.parametrize(
    ("provider", "acknowledge"),
    [
        ("anthropic", True),
        ("claude_cli", True),
        ("openai", True),
        ("openrouter", True),
        ("local", False),
        ("dgx", False),
    ],
)
def test_provider_matrix_reaches_the_same_agent_investigation_spine(
    engine: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    provider: str,
    acknowledge: bool,
) -> None:
    captured: tuple[str, dict[str, object]] | None = None

    def fake_investigation(evidence_path: str, **kwargs: object) -> SimpleNamespace:
        nonlocal captured
        captured = (evidence_path, kwargs)
        return SimpleNamespace(
            run=lambda: {"verdict": "NO_EVIL", "packet_state": None},
        )

    monkeypatch.setattr(sys, "argv", _argv(provider, acknowledge=acknowledge))
    monkeypatch.setattr(engine, "resolve_evidence_path", lambda path: path)
    monkeypatch.setattr(engine, "Investigation", fake_investigation)

    assert engine.main() == 0
    assert captured is not None
    evidence_path, kwargs = captured
    assert evidence_path == "unused.evtx"
    assert kwargs["agent_mode"] is True
    assert kwargs["agent_provider"] == provider
    assert kwargs["agent_acknowledge_evidence_egress"] is acknowledge
