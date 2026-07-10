"""Increment 8a: ClaudeCliProvider — route inference through `claude -p` (headless).

The Claude Code CLI authenticates with the subscription entitlement, so it has
inference headroom the raw Messages API (rate-limited OAuth) does not. Since the CLI
is itself an agent (it executes tools), this provider does NOT hand it the real tools;
instead it renders system+tools+conversation into one prompt with a strict JSON
tool-call protocol and parses the model's decision back into a ProviderResponse. The
host loop still dispatches tool calls to the real MCP via the bridge (custody intact).

The subprocess is an injected ``runner`` (prompt -> parsed `claude -p` JSON), so the
prompt building and response parsing are tested with no process spawn.
"""

from __future__ import annotations

import json
from pathlib import Path

from findevil_agent.agentloop.claude_cli import (
    ClaudeCliProvider,
    _default_cli_runner,
    build_cli_prompt,
    parse_cli_result,
)

_TOOLS = [
    {
        "type": "function",
        "function": {"name": "evtx_query", "description": "Parse EVTX.", "parameters": {}},
    },
    {
        "type": "function",
        "function": {"name": "record_finding", "description": "Record.", "parameters": {}},
    },
]


def test_parse_tool_call_decision() -> None:
    resp = parse_cli_result('{"tool_calls": [{"name": "evtx_query", "arguments": {"path": "/e"}}]}')
    assert resp.stop_reason == "tool_use"
    assert len(resp.tool_calls) == 1
    assert resp.tool_calls[0].name == "evtx_query"
    assert resp.tool_calls[0].arguments == {"path": "/e"}
    assert resp.tool_calls[0].id  # a synthesized, non-empty id


def test_parse_final_decision() -> None:
    resp = parse_cli_result('{"final": "no reportable evidence"}')
    assert resp.stop_reason == "end_turn"
    assert resp.text == "no reportable evidence"
    assert resp.tool_calls == []


def test_parse_strips_code_fences_and_prose() -> None:
    text = 'Here is my decision:\n```json\n{"tool_calls": [{"name": "registry_query", "arguments": {}}]}\n```\n'
    resp = parse_cli_result(text)
    assert resp.stop_reason == "tool_use"
    assert resp.tool_calls[0].name == "registry_query"


def test_parse_handles_brace_inside_string_value() -> None:
    # a JSON string value containing `}` (e.g. a path) must not truncate the object
    resp = parse_cli_result('thinking… {"final": "path C:/a}b done"} trailing')
    assert resp.stop_reason == "end_turn"
    assert "C:/a}b" in resp.text


def test_parse_unparseable_is_end_turn_with_text() -> None:
    resp = parse_cli_result("I could not produce JSON.")
    assert resp.stop_reason == "end_turn"
    assert "could not" in resp.text


def test_build_prompt_includes_system_tools_and_protocol() -> None:
    prompt = build_cli_prompt(
        system="you are pool A",
        messages=[{"role": "user", "content": "investigate /e"}],
        tools=_TOOLS,
    )
    assert "you are pool A" in prompt
    assert "evtx_query" in prompt and "record_finding" in prompt
    assert "investigate /e" in prompt
    # the strict-protocol contract is stated
    assert "tool_calls" in prompt and "final" in prompt


def test_build_prompt_renders_tool_results() -> None:
    prompt = build_cli_prompt(
        system="s",
        messages=[
            {"role": "user", "content": "go"},
            {
                "role": "assistant",
                "content": "looking",
                "tool_calls": [{"id": "cli-0", "name": "evtx_query", "arguments": {"path": "/e"}}],
            },
            {"role": "tool", "tool_call_id": "cli-0", "content": "tool_call_id: tc-1\n{...}"},
        ],
        tools=_TOOLS,
    )
    assert "tc-1" in prompt  # the tool result (with its real citation handle) is in context


def test_provider_uses_injected_runner() -> None:
    seen: dict[str, str] = {}

    def runner(prompt: str) -> dict:
        seen["prompt"] = prompt
        return {"result": '{"final": "done"}', "is_error": False}

    p = ClaudeCliProvider(model="claude-opus-4-8", runner=runner)
    resp = p.complete([{"role": "user", "content": "hi"}], _TOOLS, system="s")
    assert resp.stop_reason == "end_turn"
    assert resp.text == "done"
    assert "hi" in seen["prompt"]


def test_default_runner_strips_controller_authority_and_disables_ambient_agents(
    monkeypatch,
) -> None:
    captured: dict = {}
    secret_names = {
        "FINDEVIL_CONTROLLER_CAPABILITY": "controller-secret",
        "FINDEVIL_ACTIVE_SIGNER": "ed25519",
        "FINDEVIL_ED25519_EXPECTED_FINGERPRINT": "trusted-pin",
        "FINDEVIL_SIGNING_KEY_PATH": "/secret/key",
        "OPENAI_API_KEY": "unrelated-provider-secret",
        "AWS_SECRET_ACCESS_KEY": "cloud-secret",
    }
    for name, value in secret_names.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "required-inference-credential")

    def fake_run(argv, **kwargs):
        captured["argv"] = argv
        captured["kwargs"] = kwargs
        cwd = Path(kwargs["cwd"])
        assert cwd.is_dir()
        assert not any(cwd.iterdir())

        class Result:
            returncode = 0
            stdout = json.dumps({"result": '{"final":"done"}', "is_error": False})
            stderr = ""

        return Result()

    monkeypatch.setattr("subprocess.run", fake_run)
    result = _default_cli_runner("claude-opus-test")("prompt")
    assert result["is_error"] is False

    argv = captured["argv"]
    kwargs = captured["kwargs"]
    assert "--safe-mode" in argv
    assert "--strict-mcp-config" in argv
    assert "--no-session-persistence" in argv
    assert "--no-chrome" in argv
    assert "--disable-slash-commands" in argv
    assert argv[argv.index("--tools") + 1] == ""
    assert argv[argv.index("--setting-sources") + 1] == ""
    assert json.loads(argv[argv.index("--mcp-config") + 1]) == {"mcpServers": {}}
    assert Path(kwargs["cwd"]).name.startswith("turn-")
    assert kwargs["env"]["ANTHROPIC_API_KEY"] == "required-inference-credential"
    assert all(name not in kwargs["env"] for name in secret_names)
    assert kwargs["env"]["TMPDIR"] == kwargs["cwd"]
    assert not Path(kwargs["cwd"]).exists()
