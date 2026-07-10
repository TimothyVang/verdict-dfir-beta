"""ClaudeCliProvider — drive inference through the headless Claude Code CLI (`claude -p`).

The CLI authenticates with the Claude subscription entitlement, so it has inference
headroom the raw Messages API (rate-limited OAuth token) lacks. The CLI is itself an
agent, so this provider does NOT give it the real MCP tools; it renders the
system+tools+conversation into one prompt under a strict JSON tool-call protocol and
parses the model's decision back into the canonical ``ProviderResponse``. The host loop
still dispatches any tool call to the real MCP servers via the bridge, so custody (the
audit chain + the fact-fidelity gate) is unchanged.

Each ``complete`` is a fresh ``claude -p`` invocation (stateless; the full conversation
is re-sent), so a long investigation pays per-turn context cost — fine for a bounded
run, but the OpenAI-compatible shim is the cheaper long-haul backend.
No langgraph/fastapi (Amendment A2 content rule).
"""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

from .types import ProviderResponse, ToolCall

CliRunner = Callable[[str], dict[str, Any]]

_DEFAULT_MODEL = "claude-opus-4-8"
_REPO_ROOT = Path(__file__).resolve().parents[4]
_PROJECT_LOCAL = _REPO_ROOT / ".project-local"
_EMPTY_MCP_CONFIG = json.dumps({"mcpServers": {}}, separators=(",", ":"))
_DENIED_BUILTIN_TOOLS = "Bash,Read,Write,Edit,Glob,Grep,WebFetch,WebSearch,NotebookEdit,Task,Skill"
_CLI_SYSTEM_PROMPT = (
    "Return only the JSON decision requested in the input. You have no direct tools, "
    "filesystem access, MCP servers, browser, skills, hooks, plugins, or subagents."
)
_CLI_SETTINGS = json.dumps(
    {
        "permissions": {
            "allow": [],
            "deny": _DENIED_BUILTIN_TOOLS.split(","),
        },
        "hooks": {},
    },
    separators=(",", ":"),
)
_CLI_ENV_ALLOWLIST = frozenset(
    {
        "HOME",
        "PATH",
        "USER",
        "LOGNAME",
        "SHELL",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "TERM",
        "ANTHROPIC_API_KEY",
        "ANTHROPIC_AUTH_TOKEN",
        "ANTHROPIC_BASE_URL",
        "ANTHROPIC_CUSTOM_HEADERS",
        "CLAUDE_CODE_OAUTH_TOKEN",
        "CLAUDE_CONFIG_DIR",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
        "NODE_EXTRA_CA_CERTS",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "NO_PROXY",
        "http_proxy",
        "https_proxy",
        "no_proxy",
    }
)

_PROTOCOL = (
    "You are driving a forensic tool loop. You do NOT have direct tool access; instead, "
    "respond with ONE JSON object and nothing else.\n"
    'To call tools, respond: {"tool_calls": [{"name": "<tool>", "arguments": {...}}]} '
    "(one or more calls).\n"
    'When you have no further leads, respond: {"final": "<short summary>"}.\n'
    "Output ONLY the JSON object — no prose, no markdown fences."
)


def _render_messages(messages: list[dict[str, Any]]) -> str:
    lines: list[str] = []
    for msg in messages:
        role = msg.get("role")
        if role == "tool":
            lines.append(f"[tool result for {msg.get('tool_call_id')}]\n{msg.get('content', '')}")
        elif role == "assistant" and msg.get("tool_calls"):
            calls = json.dumps(
                [
                    {"name": c["name"], "arguments": c.get("arguments", {})}
                    for c in msg["tool_calls"]
                ]
            )
            text = msg.get("content") or ""
            lines.append(f"[assistant]{(' ' + text) if text else ''}\n[tool_calls] {calls}")
        else:
            lines.append(f"[{role}] {msg.get('content', '')}")
    return "\n\n".join(lines)


def build_cli_prompt(
    *, system: str | None, messages: list[dict[str, Any]], tools: list[dict[str, Any]]
) -> str:
    """Render system + available tools + conversation + the JSON protocol into one prompt."""
    tool_specs = [t.get("function", t) for t in tools]
    parts = []
    if system:
        parts.append(f"=== SYSTEM ===\n{system}")
    parts.append(f"=== AVAILABLE TOOLS (JSON Schema) ===\n{json.dumps(tool_specs, indent=2)}")
    parts.append(f"=== PROTOCOL ===\n{_PROTOCOL}")
    parts.append(f"=== CONVERSATION ===\n{_render_messages(messages)}")
    parts.append("=== YOUR JSON RESPONSE ===")
    return "\n\n".join(parts)


def _extract_json_object(text: str) -> dict[str, Any] | None:
    """Parse the first JSON object in ``text``, tolerating leading/trailing prose.

    Uses ``JSONDecoder.raw_decode`` (stdlib) so braces inside string values don't
    truncate the object — a hand-rolled brace counter gets this wrong.
    """
    decoder = json.JSONDecoder()
    start = text.find("{")
    while start != -1:
        try:
            obj, _end = decoder.raw_decode(text, start)
        except json.JSONDecodeError:
            start = text.find("{", start + 1)
            continue
        return obj if isinstance(obj, dict) else None
    return None


def parse_cli_result(text: str) -> ProviderResponse:
    """Parse the CLI's result text (tool-call decision or final) into a ProviderResponse."""
    obj = _extract_json_object(text)
    if obj is None:
        # The model did not emit the protocol JSON; treat its prose as a final answer
        # rather than looping forever on a malformed turn.
        return ProviderResponse(text=text.strip(), stop_reason="end_turn")

    raw_calls = obj.get("tool_calls")
    if isinstance(raw_calls, list) and raw_calls:
        tool_calls = [
            ToolCall(
                id=f"cli-{i}",
                name=str(call.get("name", "")),
                arguments=call.get("arguments") or {},
            )
            for i, call in enumerate(raw_calls)
            if call.get("name")
        ]
        if tool_calls:
            return ProviderResponse(text="", tool_calls=tool_calls, stop_reason="tool_use")

    final = obj.get("final") or obj.get("answer") or obj.get("text") or ""
    return ProviderResponse(text=str(final), stop_reason="end_turn")


def _isolation_root() -> Path:
    _PROJECT_LOCAL.mkdir(mode=0o700, parents=True, exist_ok=True)
    if _PROJECT_LOCAL.is_symlink():
        raise RuntimeError(".project-local must not be a symlink")
    configured = os.environ.get("FINDEVIL_CLAUDE_CLI_TMP_ROOT", "").strip()
    root = Path(configured).expanduser() if configured else _PROJECT_LOCAL / "tmp" / "claude-cli"
    if not root.is_absolute():
        root = _REPO_ROOT / root
    root = root.resolve()
    project_local = _PROJECT_LOCAL.resolve()
    if not root.is_relative_to(project_local):
        raise RuntimeError("FINDEVIL_CLAUDE_CLI_TMP_ROOT must remain inside .project-local")
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    if root.is_symlink() or not root.is_dir():
        raise RuntimeError("Claude CLI isolation root must be a real directory")
    return root


def _sanitized_cli_env(isolated_cwd: Path) -> dict[str, str]:
    env = {name: os.environ[name] for name in _CLI_ENV_ALLOWLIST if name in os.environ}
    env.setdefault("PATH", os.defpath)
    isolated = str(isolated_cwd)
    env.update(
        {
            "TMPDIR": isolated,
            "TMP": isolated,
            "TEMP": isolated,
            "XDG_CACHE_HOME": str(isolated_cwd / ".cache"),
            "XDG_DATA_HOME": str(isolated_cwd / ".data"),
            "XDG_STATE_HOME": str(isolated_cwd / ".state"),
            "CLAUDE_CODE_SAFE_MODE": "1",
            "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
        }
    )
    return env


def _default_cli_runner(model: str) -> CliRunner:
    def runner(prompt: str) -> dict[str, Any]:
        # The prompt (system + all tool schemas + conversation) is large and grows each
        # turn, so it is fed on STDIN — passing it as an argv arg overruns ARG_MAX.
        with tempfile.TemporaryDirectory(prefix="turn-", dir=_isolation_root()) as temp_dir:
            isolated_cwd = Path(temp_dir)
            proc = subprocess.run(
                [
                    "claude",
                    "-p",
                    "--output-format",
                    "json",
                    "--model",
                    model,
                    "--system-prompt",
                    _CLI_SYSTEM_PROMPT,
                    "--safe-mode",
                    "--strict-mcp-config",
                    "--mcp-config",
                    _EMPTY_MCP_CONFIG,
                    "--setting-sources",
                    "",
                    "--settings",
                    _CLI_SETTINGS,
                    "--tools",
                    "",
                    "--disallowed-tools",
                    _DENIED_BUILTIN_TOOLS,
                    "--disable-slash-commands",
                    "--no-chrome",
                    "--no-session-persistence",
                ],
                input=prompt,
                capture_output=True,
                text=True,
                timeout=600,
                check=False,
                cwd=str(isolated_cwd),
                env=_sanitized_cli_env(isolated_cwd),
            )
        if proc.returncode != 0:
            raise RuntimeError(f"claude -p failed (rc={proc.returncode}): {proc.stderr[:400]}")
        return json.loads(proc.stdout)

    return runner


class ClaudeCliProvider:
    """ChatProvider backed by the headless Claude Code CLI."""

    def __init__(
        self,
        model: str | None = None,
        *,
        runner: CliRunner | None = None,
    ) -> None:
        self.model = model or _DEFAULT_MODEL
        self._runner = runner or _default_cli_runner(self.model)

    def complete(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        *,
        system: str | None = None,
        **_kwargs: Any,
    ) -> ProviderResponse:
        prompt = build_cli_prompt(system=system, messages=messages, tools=tools)
        raw = self._runner(prompt)
        if raw.get("is_error"):
            raise RuntimeError(f"claude -p returned an error: {raw.get('result', '')[:400]}")
        return parse_cli_result(str(raw.get("result", "")))
