"""End-to-end stdio smoke test.

Spawns ``python -m findevil_agent_mcp.server`` as a subprocess and
drives the JSON-RPC handshake by hand: ``initialize`` → ``tools/list``
→ one ``tools/call``. This catches "did the MCP SDK API change under
us" and "does the wire format actually round-trip end-to-end".

Wire format reminder: MCP stdio is line-delimited JSON (one object
per line), NOT LSP-style Content-Length framing. See
``services/agent/findevil_agent/mcp_client.py`` for the canonical
description.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import subprocess
import sys
import threading
import time
from pathlib import Path
from queue import Empty, Queue
from typing import Any

import pytest

pytestmark = [
    pytest.mark.integration,
    # Subprocess pipe cleanup on Windows can leak file handles which
    # the project-wide filterwarnings=error config would otherwise
    # promote to test failures. Suppress just for this file.
    pytest.mark.filterwarnings("ignore::ResourceWarning"),
    pytest.mark.filterwarnings("ignore::pytest.PytestUnraisableExceptionWarning"),
]


class _LineReader:
    """Background-thread line reader so we can poll with a timeout."""

    def __init__(self, stream: Any) -> None:
        self._stream = stream
        self._queue: Queue[str | None] = Queue()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def _loop(self) -> None:
        try:
            for line in iter(self._stream.readline, ""):
                if not line:
                    break
                self._queue.put(line)
        except Exception:
            pass
        finally:
            self._queue.put(None)  # EOF sentinel

    def readline(self, timeout_s: float) -> str:
        try:
            line = self._queue.get(timeout=timeout_s)
        except Empty as exc:
            raise TimeoutError(
                f"timed out waiting for MCP server stdout line after {timeout_s}s"
            ) from exc
        if line is None:
            raise RuntimeError("MCP server closed stdout")
        return line


def _send_line(proc: subprocess.Popen[str], message: dict[str, Any]) -> None:
    """Write one JSON message followed by a newline to the server's stdin."""
    assert proc.stdin is not None
    proc.stdin.write(json.dumps(message, separators=(",", ":")) + "\n")
    proc.stdin.flush()


def _read_message(reader: _LineReader, timeout_s: float = 15.0) -> dict[str, Any]:
    """Read one JSON line, skipping any blank/non-JSON lines."""
    deadline = time.monotonic() + timeout_s
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("timed out waiting for MCP message")
        line = reader.readline(remaining)
        line = line.strip()
        if not line:
            continue
        try:
            return json.loads(line)
        except json.JSONDecodeError:
            # The server may emit logs to stderr only, but be defensive.
            continue


@pytest.mark.skipif(
    os.name == "nt",
    reason=(
        "every tool call in this smoke is reserved-custody routed, which is "
        "fail-closed disabled on native Windows by design; POSIX / WSL2 / Docker "
        "cover it (see test_custody_path_policy)"
    ),
)
def test_stdio_initialize_and_list_tools(tmp_path: Path) -> None:
    """Boot the server, complete initialize, list tools, call audit_verify."""
    case_dir = tmp_path / "case-001"
    case_dir.mkdir(mode=0o700)
    marker = case_dir / ".verdict-case-marker"
    marker.write_bytes(b"")
    if os.name != "nt":
        marker.chmod(0o600)
    memory_store = tmp_path / "private" / "memory.sqlite"
    expert_ledger = tmp_path / "private" / "expert_misses.jsonl"
    env = os.environ.copy()
    env["FINDEVIL_LOG_LEVEL"] = "WARNING"
    env["PYTHONUNBUFFERED"] = "1"
    controller_capability = "c" * 64
    env.update(
        {
            "FINDEVIL_CUSTODY_BOUNDARY": "reserved_case",
            "FINDEVIL_ACTIVE_CASE_DIR": str(case_dir),
            "FINDEVIL_ACTIVE_CASE_ID": "case-001",
            "FINDEVIL_ACTIVE_RUN_ID": "run-001",
            "FINDEVIL_ACTIVE_STARTED_AT": "2026-07-10T00:00:00Z",
            "FINDEVIL_ACTIVE_SIGNER": "ed25519",
            "FINDEVIL_MEMORY_STORE": str(memory_store),
            "FINDEVIL_EXPERT_MISS_LEDGER": str(expert_ledger),
            "FINDEVIL_CONTROLLER_CAPABILITY": controller_capability,
            "FINDEVIL_OUTPUT_ROUTE": "local_controller",
        }
    )

    cmd = [sys.executable, "-m", "findevil_agent_mcp.server"]
    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        text=True,
        encoding="utf-8",
        bufsize=1,
    )
    reader = _LineReader(proc.stdout)
    try:
        _send_line(
            proc,
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {"name": "smoke-test", "version": "0.0.0"},
                },
            },
        )
        init_resp = _read_message(reader)
        assert init_resp.get("id") == 1, init_resp
        assert "result" in init_resp, init_resp
        assert "capabilities" in init_resp["result"]

        _send_line(
            proc,
            {
                "jsonrpc": "2.0",
                "method": "notifications/initialized",
            },
        )

        _send_line(
            proc,
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        )
        list_resp = _read_message(reader)
        assert list_resp.get("id") == 2, list_resp
        tools = list_resp["result"]["tools"]
        names = sorted(t["name"] for t in tools)
        assert names == sorted(
            [
                "audit_append",
                "audit_verify",
                "manifest_finalize",
                "manifest_verify",
                "verify_finding",
                "detect_contradictions",
                "judge_findings",
                "correlate_findings",
                "memory_remember",
                "memory_recall",
                "pool_handoff",
                "expert_miss_capture",
                "accuracy_compare",
                "find_ai_signatures",
            ]
        )

        _send_line(
            proc,
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": "audit_verify",
                    "arguments": {"path": str(case_dir / "audit.jsonl")},
                },
            },
        )
        call_resp = _read_message(reader)
        assert call_resp.get("id") == 3, call_resp
        content = call_resp["result"]["content"]
        assert len(content) == 1
        body = json.loads(content[0]["text"])
        assert body == {"ok": True, "record_count": 0, "error": None}

        _send_line(
            proc,
            {
                "jsonrpc": "2.0",
                "id": 31,
                "method": "tools/call",
                "params": {
                    "name": "audit_append",
                    "arguments": {
                        "path": str(case_dir / "audit.jsonl"),
                        "kind": "tool_call_output",
                        "payload": {
                            "tool_call_id": "forged",
                            "output_hash": "f" * 64,
                        },
                    },
                },
            },
        )
        forged_audit = _read_message(reader)
        forged_body = json.loads(forged_audit["result"]["content"][0]["text"])
        assert forged_body["error"]["kind"] == "controller_authority"
        assert not (case_dir / "audit.jsonl").exists()

        evidence_db = tmp_path / "evidence.sqlite"
        with sqlite3.connect(evidence_db) as connection:
            connection.execute("CREATE TABLE evidence(value TEXT)")
            connection.execute("INSERT INTO evidence VALUES ('preserve-me')")
        before = hashlib.sha256(evidence_db.read_bytes()).hexdigest()
        _send_line(
            proc,
            {
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/call",
                "params": {
                    "name": "memory_remember",
                    "arguments": {
                        "store_path": str(evidence_db),
                        "case_id": "case-001",
                        "kind": "ioc",
                        "key": "blocked.example",
                        "value": "blocked.example",
                        "sha256": "sha256:" + "a" * 64,
                        "audit_log_path": str(case_dir / "audit.jsonl"),
                        "_controller_capability": controller_capability,
                    },
                },
            },
        )
        denied = _read_message(reader)
        denied_body = json.loads(denied["result"]["content"][0]["text"])
        assert denied_body["error"]["kind"] == "custody_path_policy"
        assert hashlib.sha256(evidence_db.read_bytes()).hexdigest() == before
        with sqlite3.connect(evidence_db) as connection:
            tables = {
                row[0]
                for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")
            }
        assert tables == {"evidence"}

        secret = tmp_path / "credentials.conf"
        secret.write_text("token=do-not-disclose api.openai.com adjacent-secret", encoding="utf-8")
        _send_line(
            proc,
            {
                "jsonrpc": "2.0",
                "id": 5,
                "method": "tools/call",
                "params": {
                    "name": "find_ai_signatures",
                    "arguments": {
                        "case_id": "case-001",
                        "paths": [str(secret)],
                    },
                },
            },
        )
        denied_scan = _read_message(reader)
        denied_scan_text = denied_scan["result"]["content"][0]["text"]
        assert "custody_path_policy" in denied_scan_text
        assert "do-not-disclose" not in denied_scan_text
    finally:
        if proc.stdin is not None and not proc.stdin.closed:
            proc.stdin.close()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)
        for stream in (proc.stdout, proc.stderr):
            if stream is not None and not stream.closed:
                stream.close()


def test_stdio_privacy_gate_allows_initialize_and_list_but_denies_tool_output(
    tmp_path: Path,
) -> None:
    env = os.environ.copy()
    env["FINDEVIL_LOG_LEVEL"] = "WARNING"
    env["PYTHONUNBUFFERED"] = "1"
    env.pop("FINDEVIL_OUTPUT_ROUTE", None)
    env.pop("FINDEVIL_ACKNOWLEDGE_PARSED_EVIDENCE_EGRESS", None)
    secret = "parsed-secret-must-not-cross-boundary"
    proc = subprocess.Popen(
        [sys.executable, "-m", "findevil_agent_mcp.server"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        text=True,
        encoding="utf-8",
        bufsize=1,
    )
    reader = _LineReader(proc.stdout)
    try:
        _send_line(
            proc,
            {
                "jsonrpc": "2.0",
                "id": 801,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {"name": "privacy-test", "version": "0.0.0"},
                },
            },
        )
        initialized = _read_message(reader)
        assert "result" in initialized
        _send_line(
            proc,
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
        )
        _send_line(
            proc,
            {"jsonrpc": "2.0", "id": 802, "method": "tools/list", "params": {}},
        )
        listed = _read_message(reader)
        assert listed["result"]["tools"]

        _send_line(
            proc,
            {
                "jsonrpc": "2.0",
                "id": 803,
                "method": "tools/call",
                "params": {
                    "name": "find_ai_signatures",
                    "arguments": {"case_id": "case-001", "text": secret},
                },
            },
        )
        denied = _read_message(reader)
        denied_text = denied["result"]["content"][0]["text"]
        denied_body = json.loads(denied_text)
        assert denied_body["error"]["kind"] == "privacy_boundary"
        assert set(denied_body) == {"error"}
        assert secret not in json.dumps(denied)
    finally:
        if proc.stdin is not None and not proc.stdin.closed:
            proc.stdin.close()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)
        for stream in (proc.stdout, proc.stderr):
            if stream is not None and not stream.closed:
                stream.close()
