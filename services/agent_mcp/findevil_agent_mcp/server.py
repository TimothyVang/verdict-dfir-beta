"""findevil-agent-mcp stdio server.

Spec #2 + Amendment A2. Boots the MCP Python SDK low-level
``Server`` over stdio, registers every tool exposed by
:mod:`findevil_agent_mcp.tools`, and returns each handler's output
as a single ``TextContent`` payload containing canonical JSON.

Boot:
    uv run --directory services/agent_mcp \\
        python -m findevil_agent_mcp.server

In normal operation the launcher is the repo-root ``.mcp.json`` —
Claude Code spawns this server alongside ``findevil-mcp`` (Rust)
when the user opens an investigation against a case directory.

Logging note: stdio is the wire; we MUST NOT print to stdout.
``structlog`` is configured to write to stderr only.
"""

from __future__ import annotations

import asyncio
import hmac
import json
import logging
import os
import sys
from collections.abc import Mapping
from typing import Any, cast

import anyio
import structlog
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool
from pydantic import ValidationError

from findevil_agent_mcp import injection_ledger
from findevil_agent_mcp.custody_path_policy import (
    CustodyPathPolicyError,
    enforce_tool_path_policy,
)
from findevil_agent_mcp.sanitize import sanitize_str, sanitize_value
from findevil_agent_mcp.tools import all_specs
from findevil_agent_mcp.tools._base import ToolSpec

SERVER_NAME = "findevil-agent-mcp"
SERVER_VERSION = "0.1.0"
MCP_STDIN_FRAME_MAX_BYTES = 64 * 1024 * 1024
_CONTROLLER_CAPABILITY_ENV = "FINDEVIL_CONTROLLER_CAPABILITY"
_CONTROLLER_CAPABILITY_FIELD = "_controller_capability"
_OUTPUT_ROUTE_ENV = "FINDEVIL_OUTPUT_ROUTE"
_PARSED_EVIDENCE_ACK_ENV = "FINDEVIL_ACKNOWLEDGE_PARSED_EVIDENCE_EGRESS"
_LOCAL_OUTPUT_ROUTES = frozenset({"local_controller", "local_dgx"})
_CONTROLLER_ONLY_TOOLS = frozenset(
    {
        "audit_append",
        "expert_miss_capture",
        "manifest_finalize",
        "manifest_verify",
        "memory_remember",
        "pool_handoff",
    }
)


class ControllerCapabilityError(PermissionError):
    """A model-facing caller attempted a controller-only custody operation."""


def parsed_evidence_route_authorized(
    environment: Mapping[str, str] | None = None,
) -> bool:
    """Return whether this process may emit evidence-derived tool output.

    The decision is exact and fail-closed: deterministic/local-DGX consumers
    use a reviewed local route, while any cloud/interactive consumer must set
    the explicit acknowledgment bit. Unknown route names and truthy-looking
    acknowledgment strings are deliberately rejected.
    """
    source = os.environ if environment is None else environment
    return (
        source.get(_OUTPUT_ROUTE_ENV) in _LOCAL_OUTPUT_ROUTES
        or source.get(_PARSED_EVIDENCE_ACK_ENV) == "1"
    )


def authorize_controller_call(tool_name: str, arguments: Mapping[str, Any]) -> dict[str, Any]:
    """Authenticate controller-only tools without advertising a secret field.

    The capability is removed before Pydantic schema validation and is never
    returned, logged, or written into the audit chain. The model-visible MCP
    schemas therefore contain no way to manufacture authoritative provenance.
    """
    sanitized = dict(arguments)
    provided = sanitized.pop(_CONTROLLER_CAPABILITY_FIELD, None)
    if tool_name not in _CONTROLLER_ONLY_TOOLS:
        return sanitized
    expected = os.environ.get(_CONTROLLER_CAPABILITY_ENV, "")
    if (
        len(expected) != 64
        or not isinstance(provided, str)
        or len(provided) != 64
        or not hmac.compare_digest(provided, expected)
    ):
        raise ControllerCapabilityError(f"{tool_name} is reserved for the private controller")
    return sanitized


class JsonRpcFrameError(ValueError):
    """Fatal framing violation on the stdio JSON-RPC transport."""


class BoundedStdin:
    """Async UTF-8 line source with a hard wire-byte ceiling.

    The MCP SDK's default stdio iterator reads an entire text line before
    validating it. This wrapper reads at most ``max_frame_bytes + 1`` raw
    bytes, rejects oversized/unterminated frames, and only then decodes. A
    framing error escapes the SDK reader task and closes the transport.
    """

    def __init__(self, stream: Any, *, max_frame_bytes: int) -> None:
        if max_frame_bytes < 1:
            raise ValueError("max_frame_bytes must be positive")
        self._stream = stream
        self._max_frame_bytes = max_frame_bytes

    def __aiter__(self) -> BoundedStdin:
        return self

    async def __anext__(self) -> str:
        frame = await anyio.to_thread.run_sync(self._stream.readline, self._max_frame_bytes + 1)
        if frame == b"":
            raise StopAsyncIteration
        if not isinstance(frame, bytes):
            raise JsonRpcFrameError("JSON-RPC stdin must yield bytes")
        if len(frame) > self._max_frame_bytes:
            raise JsonRpcFrameError(
                "JSON-RPC request exceeded the " f"{self._max_frame_bytes}-byte frame limit"
            )
        if not frame.endswith(b"\n"):
            raise JsonRpcFrameError("received an unterminated JSON-RPC request frame")
        try:
            return frame.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise JsonRpcFrameError("JSON-RPC request frame is not valid UTF-8") from exc


def _configure_logging() -> structlog.BoundLogger:
    """Send logs to stderr — stdio is the JSON-RPC channel.

    Stdout pollution corrupts the protocol stream; this function is
    the single place that controls log destination. Tests can
    monkeypatch the returned logger.
    """
    level_name = os.environ.get("FINDEVIL_LOG_LEVEL", "INFO").upper()
    level = getattr(logging, level_name, logging.INFO)
    logging.basicConfig(stream=sys.stderr, level=level, format="%(message)s")
    structlog.configure(
        processors=[
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(level),
        logger_factory=structlog.WriteLoggerFactory(file=sys.stderr),
        cache_logger_on_first_use=True,
    )
    return structlog.get_logger(SERVER_NAME)


def _build_specs_index() -> dict[str, ToolSpec]:
    """Materialize the registry once at startup.

    Importing the tool modules can be slow (sigstore is lazy but
    pydantic schema generation isn't); we pay that cost once before
    list_tools is first called.
    """
    return {spec.name: spec for spec in all_specs()}


def _to_text_content(payload: Any, *, tool: str | None = None) -> list[TextContent]:
    """Wrap a Pydantic model (or dict) as a single MCP ``TextContent``.

    The MCP wire format expects ``content[0].text`` to be a string;
    we always emit canonical JSON so downstream agents can ``json.loads``
    deterministically. ``tool`` is the dispatched tool name, recorded as
    context in the injection-alert ledger when something was neutralized.
    """
    if hasattr(payload, "model_dump"):
        body = payload.model_dump()
    elif isinstance(payload, dict):
        body = payload
    else:
        body = {"value": payload}
    # Neutralize attacker-controlled evidence text (chat/role tokens, invisible
    # Unicode) before it crosses the boundary to the model -- the Python half of
    # the MCP-output->LLM sanitizer (mirrors services/mcp/src/sanitize.rs). Log
    # what was neutralized as counts only, never the payload.
    body, sanitized = sanitize_value(body)
    text = json.dumps(body, sort_keys=True, separators=(",", ":"))
    if sanitized:
        structlog.get_logger(SERVER_NAME).warning(
            "agent_mcp_sanitized_tool_output",
            patterns=sanitized,
            total=sum(sanitized.values()),
        )
        # Mirror the warning into the counts-only injection-alert ledger (a
        # best-effort SIDECAR, never the audit chain). output_text is the already
        # -sanitized canonical JSON, so its digest matches what the model saw and
        # is the correlation key the judge escalation maps back to a tool_call_id.
        injection_ledger.record_neutralization(sanitized, tool=tool, output_text=text)
    return [TextContent(type="text", text=text)]


def _error_content(message: str, *, kind: str) -> list[TextContent]:
    """Stable error shape returned to the MCP client.

    ``kind`` is one of:
      - ``"validation"``: input failed pydantic validation.
      - ``"unknown_tool"``: name not in the registry.
      - ``"handler"``: the handler raised an unexpected exception.
    """
    # Error messages interpolate exception/validation text that can echo raw
    # evidence bytes, so the error path is an injection channel just like a
    # successful tool body. The success path neutralizes via ``_to_text_content``;
    # route the human-readable message through the SAME sanitizer here so
    # attacker-controlled chat/role tokens and invisible Unicode never reach the
    # model un-neutralized (mirrors ``make_error_response`` in
    # services/mcp/src/server.rs). Only the message string is sanitized -- the
    # ``kind`` and the error shape are unchanged, and a JSON-RPC error is a
    # protocol error, not a hashed tool output, so no audit-chain or
    # ``_meta.sanitized`` accounting is touched. The tally is intentionally
    # discarded.
    counts: dict[str, int] = {}
    safe_message = sanitize_str(message, counts)
    payload = {"error": {"kind": kind, "message": safe_message}}
    return [
        TextContent(
            type="text",
            text=json.dumps(payload, sort_keys=True, separators=(",", ":")),
        )
    ]


def build_server() -> tuple[Server, dict[str, ToolSpec]]:
    """Construct the Server + registered handlers without booting stdio.

    Tests use this entry point to drive the server in-process. The
    ``run`` coroutine is the production entry point; it calls this
    function then wires stdio.
    """
    server: Server = Server(SERVER_NAME)
    specs = _build_specs_index()
    privacy_authorized = parsed_evidence_route_authorized()
    log = _configure_logging()
    log.info(
        "agent_mcp_boot",
        server_name=SERVER_NAME,
        server_version=SERVER_VERSION,
        tool_count=len(specs),
        tools=sorted(specs.keys()),
    )

    @server.list_tools()
    async def list_tools() -> list[Tool]:
        return [
            Tool(
                name=spec.name,
                description=spec.description,
                inputSchema=spec.input_schema(),
            )
            for spec in specs.values()
        ]

    # Validation is performed below with the authoritative frozen Pydantic
    # model after the private controller capability has been authenticated and
    # removed. The SDK's pre-validation must stay disabled: it validates
    # against the model-visible schema first and would reject the deliberately
    # hidden capability before this trust-boundary hook can inspect it.
    @server.call_tool(validate_input=False)
    async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
        if not privacy_authorized:
            log.warning("agent_mcp_privacy_boundary_denied", tool=name)
            return _error_content(
                "parsed evidence egress is not authorized; set "
                "FINDEVIL_OUTPUT_ROUTE=local_controller or local_dgx for a reviewed "
                "local route, or "
                "FINDEVIL_ACKNOWLEDGE_PARSED_EVIDENCE_EGRESS=1 explicitly",
                kind="privacy_boundary",
            )
        spec = specs.get(name)
        if spec is None:
            log.warning("agent_mcp_unknown_tool", tool=name)
            return _error_content(f"unknown tool: {name!r}", kind="unknown_tool")

        try:
            arguments = authorize_controller_call(name, arguments)
        except ControllerCapabilityError as exc:
            log.warning("agent_mcp_controller_authority_denied", tool=name)
            return _error_content(str(exc), kind="controller_authority")

        try:
            validated = spec.input_model.model_validate(arguments)
        except ValidationError as exc:
            log.warning(
                "agent_mcp_validation_error",
                tool=name,
                errors=exc.errors(include_url=False),
            )
            return _error_content(f"input validation failed: {exc}", kind="validation")

        try:
            enforce_tool_path_policy(name, validated)
        except CustodyPathPolicyError as exc:
            log.warning("agent_mcp_custody_path_denied", tool=name, error=str(exc))
            return _error_content(str(exc), kind="custody_path_policy")

        try:
            result = await spec.handler(validated)
        except Exception as exc:
            log.error(
                "agent_mcp_handler_exception",
                tool=name,
                exc_type=type(exc).__name__,
                exc=str(exc),
            )
            return _error_content(f"{type(exc).__name__}: {exc}", kind="handler")

        return _to_text_content(result, tool=name)

    return server, specs


async def _async_main() -> None:
    """Production entry point — wires stdio to the Server."""
    server, _ = build_server()
    stdin = BoundedStdin(
        sys.stdin.buffer,
        max_frame_bytes=MCP_STDIN_FRAME_MAX_BYTES,
    )
    # The SDK annotation names AsyncFile[str], but its implementation only
    # requires an async string iterator. BoundedStdin deliberately implements
    # that narrower runtime protocol over a raw byte stream.
    async with stdio_server(stdin=cast(Any, stdin)) as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            server.create_initialization_options(),
        )


def run() -> None:
    """Synchronous wrapper for ``project.scripts`` entry point."""
    asyncio.run(_async_main())


if __name__ == "__main__":
    run()


__all__ = [
    "BoundedStdin",
    "JsonRpcFrameError",
    "MCP_STDIN_FRAME_MAX_BYTES",
    "SERVER_NAME",
    "SERVER_VERSION",
    "build_server",
    "parsed_evidence_route_authorized",
    "run",
]
