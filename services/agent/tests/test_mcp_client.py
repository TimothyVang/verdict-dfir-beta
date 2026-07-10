"""Tests for findevil_agent.mcp_client.

The MockMcpClient gets full coverage; StdioMcpClient is exercised
only for argument validation + closed-state semantics — the real
subprocess path requires the Rust binary at a known location, which
the integration suite covers.
"""

from __future__ import annotations

import json
import os
import sys
import textwrap
import time

import pytest

import findevil_agent.mcp_client as mcp_client_module
from findevil_agent.mcp_client import (
    McpClientError,
    McpRpcError,
    MockMcpClient,
    StdioMcpClient,
    ToolCallResult,
)


class TestMockMcpClient:
    def test_call_tool_dict_handler(self) -> None:
        c = MockMcpClient()
        c.register("evtx_query", lambda args: {"row_count": 42, "rows": []})
        r = c.call_tool("evtx_query", {"case_id": "c1", "evtx_path": "x"})
        assert isinstance(r, ToolCallResult)
        assert r.tool_name == "evtx_query"
        assert r.parsed == {"row_count": 42, "rows": []}
        assert len(r.output_sha256) == 64
        assert len(r.tool_call_id) == 36

    def test_call_tool_string_handler(self) -> None:
        c = MockMcpClient()
        c.register("hayabusa_scan", "raw text output")
        r = c.call_tool("hayabusa_scan", {})
        assert r.raw_output_text == "raw text output"
        assert r.parsed is None  # string isn't valid JSON

    def test_call_tool_records_call(self) -> None:
        c = MockMcpClient()
        c.register("x", {"k": 1})
        c.call_tool("x", {"a": 1})
        c.call_tool("x", {"a": 2})
        assert len(c.calls) == 2
        assert c.calls[0][0] == "x"
        assert c.calls[0][1] == {"a": 1}
        assert c.calls[1][1] == {"a": 2}

    def test_unknown_tool_raises_rpc_error(self) -> None:
        c = MockMcpClient()
        with pytest.raises(McpRpcError) as exc:
            c.call_tool("nope", {})
        assert exc.value.code == -32601

    def test_handler_can_be_callable_with_args(self) -> None:
        c = MockMcpClient()
        c.register(
            "echo",
            lambda args: {"echo": args["msg"]} if "msg" in args else {"echo": ""},
        )
        r = c.call_tool("echo", {"msg": "hello"})
        assert r.parsed == {"echo": "hello"}

    def test_output_sha_changes_with_payload(self) -> None:
        c = MockMcpClient()
        c.register(
            "var",
            lambda args: {"row_count": args.get("count", 0)},
        )
        r1 = c.call_tool("var", {"count": 1})
        r2 = c.call_tool("var", {"count": 99})
        assert r1.output_sha256 != r2.output_sha256

    def test_same_payload_same_sha(self) -> None:
        c = MockMcpClient()
        c.register("same", {"x": 1})
        r1 = c.call_tool("same", {})
        r2 = c.call_tool("same", {})
        # tool_call_ids differ (UUIDs) but output_sha256 matches
        # because the response payload is identical.
        assert r1.tool_call_id != r2.tool_call_id
        assert r1.output_sha256 == r2.output_sha256


class TestStdioMcpClientArgValidation:
    def test_close_idempotent(self) -> None:
        c = StdioMcpClient(["/nonexistent/findevil-mcp"])
        c.close()
        c.close()  # second close must not raise

    def test_call_after_close_raises(self) -> None:
        c = StdioMcpClient(["/nonexistent/findevil-mcp"])
        c.close()
        with pytest.raises(McpClientError):
            c.call_tool("evtx_query", {})

    def test_unspawnable_binary_surfaces_clean_error(self) -> None:
        c = StdioMcpClient(["/this/path/definitely/does/not/exist/findevil-mcp"])
        with pytest.raises(McpClientError) as exc:
            c.call_tool("evtx_query", {})
        assert "could not spawn MCP server" in str(exc.value)

    def test_broken_stdin_aborts_transport_once(self) -> None:
        aborts: list[str] = []
        client = StdioMcpClient(
            [sys.executable, "-c", "import os; os.close(0)"],
            abort_callback=lambda: aborts.append("aborted"),
        )
        client._ensure_started()
        assert client._proc is not None
        client._proc.wait(timeout=5)

        with pytest.raises(McpClientError, match="stdin write failed"):
            client.call_tool("probe", {})

        client._abort_transport()
        assert aborts == ["aborted"]

    def test_stdout_eof_aborts_transport_once(self) -> None:
        aborts: list[str] = []
        server = "import sys; sys.stdin.buffer.readline()"
        client = StdioMcpClient(
            [sys.executable, "-c", server],
            abort_callback=lambda: aborts.append("aborted"),
        )

        with pytest.raises(McpClientError, match="closed stdout"):
            client.call_tool("probe", {})

        client._abort_transport()
        assert aborts == ["aborted"]

    def test_malformed_json_aborts_transport_once(self) -> None:
        aborts: list[str] = []
        server = "import sys; sys.stdin.buffer.readline(); print('{bad', flush=True)"
        client = StdioMcpClient(
            [sys.executable, "-c", server],
            abort_callback=lambda: aborts.append("aborted"),
        )

        with pytest.raises(McpClientError, match="non-JSON"):
            client.call_tool("probe", {})

        client._abort_transport()
        assert aborts == ["aborted"]

    @pytest.mark.parametrize(
        ("response", "message"),
        [
            ([], "non-object"),
            ({"jsonrpc": "1.0", "id": 1, "result": {}}, "version"),
            ({"jsonrpc": "2.0", "id": 1, "result": []}, "result"),
            (
                {"jsonrpc": "2.0", "id": 1, "result": {"content": {}}},
                "content",
            ),
            (
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": {"content": [], "_meta": []},
                },
                "metadata",
            ),
            ({"jsonrpc": "2.0", "id": 1, "error": "bad"}, "error"),
            ({"jsonrpc": "2.0", "id": 1}, "result or error"),
        ],
    )
    def test_bad_jsonrpc_envelope_aborts_transport_once(
        self, response: object, message: str
    ) -> None:
        aborts: list[str] = []
        wire = json.dumps(response)
        server = (
            "import sys; sys.stdin.buffer.readline(); "
            f"sys.stdout.buffer.write({(wire + chr(10)).encode()!r}); "
            "sys.stdout.buffer.flush()"
        )
        client = StdioMcpClient(
            [sys.executable, "-c", server],
            abort_callback=lambda: aborts.append("aborted"),
        )

        with pytest.raises(McpClientError, match=message):
            client.call_tool("probe", {})

        client._abort_transport()
        assert aborts == ["aborted"]

    def test_multibyte_response_is_bounded_by_utf8_wire_bytes(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(mcp_client_module, "_MCP_STDOUT_FRAME_MAX_BYTES", 384)
        aborts: list[str] = []
        server = textwrap.dedent(
            """
            import json, sys
            request = json.loads(sys.stdin.buffer.readline())
            inner = json.dumps({"padding": "é" * 180}, ensure_ascii=False)
            response = {
                "jsonrpc": "2.0",
                "id": request["id"],
                "result": {"content": [{"type": "text", "text": inner}]},
            }
            wire = json.dumps(response, ensure_ascii=False).encode("utf-8") + b"\\n"
            assert len(wire) > 384
            assert len(wire.decode("utf-8")) < 384
            sys.stdout.buffer.write(wire)
            sys.stdout.buffer.flush()
            """
        )
        client = StdioMcpClient(
            [sys.executable, "-c", server],
            abort_callback=lambda: aborts.append("aborted"),
        )

        with pytest.raises(McpClientError, match="frame limit"):
            client.call_tool("probe", {})

        assert aborts == ["aborted"]

    def test_response_at_exact_wire_byte_ceiling_is_accepted(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        response = {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "content": [{"type": "text", "text": '{"ok":true}'}],
            },
        }
        wire = (json.dumps(response, separators=(",", ":")) + "\n").encode("utf-8")
        monkeypatch.setattr(mcp_client_module, "_MCP_STDOUT_FRAME_MAX_BYTES", len(wire))
        server = (
            "import sys; sys.stdin.buffer.readline(); "
            f"sys.stdout.buffer.write({wire!r}); sys.stdout.buffer.flush()"
        )
        client = StdioMcpClient([sys.executable, "-c", server])
        try:
            result = client.call_tool("probe", {})
        finally:
            client.close()

        assert result.parsed == {"ok": True}

    def test_oversized_unterminated_response_is_bounded(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(mcp_client_module, "_MCP_STDOUT_FRAME_MAX_BYTES", 128)
        aborts: list[str] = []
        server = (
            "import sys,time; "
            "sys.stdin.readline(); "
            "sys.stdout.write('x' * 4096); sys.stdout.flush(); time.sleep(10)"
        )
        client = StdioMcpClient(
            [sys.executable, "-c", server],
            request_timeout_s=2.0,
            abort_callback=lambda: aborts.append("aborted"),
        )
        with pytest.raises(McpClientError, match="frame limit"):
            client.call_tool("probe", {})
        assert client._proc is not None
        assert client._proc.poll() is not None
        assert aborts == ["aborted"]

    def test_timeout_kills_inherited_stdout_process_tree_without_blocking(self, tmp_path) -> None:
        grandchild_pid = tmp_path / "grandchild.pid"
        survived = tmp_path / "grandchild-survived"
        child = (
            "import pathlib,time; "
            "time.sleep(1); "
            f"pathlib.Path({str(survived)!r}).write_text('survived'); "
            "time.sleep(2)"
        )
        server = textwrap.dedent(
            f"""
            import pathlib, subprocess, sys, time
            sys.stdin.buffer.readline()
            proc = subprocess.Popen([sys.executable, "-c", {child!r}])
            pathlib.Path({str(grandchild_pid)!r}).write_text(str(proc.pid))
            time.sleep(30)
            """
        )
        aborts: list[str] = []
        client = StdioMcpClient(
            [sys.executable, "-c", server],
            request_timeout_s=0.2,
            abort_callback=lambda: aborts.append("aborted"),
        )

        started = time.monotonic()
        with pytest.raises(McpClientError, match="timed out"):
            client.call_tool("probe", {})
        elapsed = time.monotonic() - started
        client._abort_transport()

        assert grandchild_pid.is_file(), "fixture must spawn the inheriting grandchild"
        assert elapsed < 1.5, "abort must not block on the stdout reader lock"
        assert aborts == ["aborted"]
        time.sleep(1.1)
        assert not survived.exists(), "the parser grandchild must be terminated"
        if os.name == "posix":
            with pytest.raises(ProcessLookupError):
                os.kill(int(grandchild_pid.read_text()), 0)

    def test_close_kills_inherited_stdout_process_tree_without_blocking(self, tmp_path) -> None:
        grandchild_pid = tmp_path / "close-grandchild.pid"
        survived = tmp_path / "close-grandchild-survived"
        child = (
            "import pathlib,time; "
            "time.sleep(1); "
            f"pathlib.Path({str(survived)!r}).write_text('survived'); "
            "time.sleep(2)"
        )
        server = textwrap.dedent(
            f"""
            import pathlib, subprocess, sys
            proc = subprocess.Popen([sys.executable, "-c", {child!r}])
            pathlib.Path({str(grandchild_pid)!r}).write_text(str(proc.pid))
            sys.stdin.buffer.readline()
            """
        )
        client = StdioMcpClient([sys.executable, "-c", server])
        client._ensure_started()
        deadline = time.monotonic() + 2
        while not grandchild_pid.is_file() and time.monotonic() < deadline:
            time.sleep(0.01)
        assert grandchild_pid.is_file(), "fixture must spawn the inheriting grandchild"

        started = time.monotonic()
        client.close()
        elapsed = time.monotonic() - started

        assert elapsed < 1.5, "close must not block on a pipe reader lock"
        time.sleep(1.1)
        assert not survived.exists(), "close must terminate parser grandchildren"
        if os.name == "posix":
            with pytest.raises(ProcessLookupError):
                os.kill(int(grandchild_pid.read_text()), 0)

    def test_unterminated_response_is_rejected(self) -> None:
        server = textwrap.dedent(
            """
            import json, sys
            request = json.loads(sys.stdin.readline())
            response = {"jsonrpc": "2.0", "id": request["id"], "result": {}}
            sys.stdout.write(json.dumps(response))
            sys.stdout.flush()
            """
        )
        client = StdioMcpClient([sys.executable, "-c", server])
        try:
            with pytest.raises(McpClientError, match="unterminated"):
                client.call_tool("probe", {})
        finally:
            client.close()

    def test_stderr_flood_is_drained_with_bounded_retention(self) -> None:
        server = textwrap.dedent(
            """
            import json, sys
            request = json.loads(sys.stdin.readline())
            sys.stderr.write("x" * 300_000)
            sys.stderr.flush()
            response = {
                "jsonrpc": "2.0",
                "id": request["id"],
                "result": {"content": [{"type": "text", "text": "{\\\"ok\\\":true}"}]},
            }
            sys.stdout.write(json.dumps(response) + "\\n")
            sys.stdout.flush()
            """
        )
        client = StdioMcpClient([sys.executable, "-c", server], request_timeout_s=10.0)
        try:
            result = client.call_tool("probe", {})
            assert result.parsed == {"ok": True}
            assert len(client._stderr_tail) == 1
            assert client._stderr_tail[0].endswith("[truncated]")
        finally:
            client.close()


class TestParsing:
    """White-box coverage of _parse_response error paths."""

    def test_rpc_error_response_raises(self) -> None:
        c = StdioMcpClient(["/nonexistent"])
        try:
            with pytest.raises(McpRpcError) as exc:
                c._parse_response(  # type: ignore[attr-defined]
                    response={
                        "jsonrpc": "2.0",
                        "id": 1,
                        "error": {"code": -32602, "message": "bad params"},
                    },
                    tool_call_id="tc-1",
                    tool_name="evtx_query",
                    wall_ms=0,
                )
            assert exc.value.code == -32602
            assert "bad params" in str(exc.value)
        finally:
            c.close()

    def test_parsed_dict_when_json_text(self) -> None:
        c = StdioMcpClient(["/nonexistent"])
        try:
            r = c._parse_response(  # type: ignore[attr-defined]
                response={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": {
                        "content": [
                            {
                                "type": "text",
                                "text": json.dumps({"row_count": 7}),
                            }
                        ],
                        "_meta": {"ui": {"resourceUri": "ui://timeline"}},
                    },
                },
                tool_call_id="tc-1",
                tool_name="evtx_query",
                wall_ms=42,
            )
            assert r.parsed == {"row_count": 7}
            assert r.wall_clock_ms == 42
            assert r.meta["ui"]["resourceUri"] == "ui://timeline"
        finally:
            c.close()

    def test_non_json_text_leaves_parsed_none(self) -> None:
        c = StdioMcpClient(["/nonexistent"])
        try:
            r = c._parse_response(  # type: ignore[attr-defined]
                response={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": {"content": [{"type": "text", "text": "raw bytes"}]},
                },
                tool_call_id="tc-2",
                tool_name="hayabusa_scan",
                wall_ms=10,
            )
            assert r.parsed is None
            assert r.raw_output_text == "raw bytes"
            assert len(r.output_sha256) == 64
        finally:
            c.close()
