"""Concurrency tests for the stdio MCP client in ``scripts/find_evil_auto.py``.

Parallel investigation/verification multiplexes many tool calls over a single
stdio connection, so the client MUST be thread-safe and route each JSON-RPC
response to the caller whose request id it answers. These tests import the engine
module (the same pattern as ``test_memory_hooks.py``) and exercise the actual
``StdioMcpClient`` with a fake stdio server:

- C1: N concurrent ``call()``s each receive the response for their OWN request
      id, even when the server emits responses OUT OF ORDER.
- C2: server EOF (stdout closed) mid-wait raises in every blocked caller (no hang).
- C3: a single sequential ``call()`` still returns its result (no regression).
"""

from __future__ import annotations

import json
import os
import sys
import textwrap
import threading
import time
from pathlib import Path
from queue import Queue

import pytest

_SCRIPTS = Path(__file__).resolve().parents[3] / "scripts"
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import find_evil_auto as fea  # noqa: E402


class _FakeStdin:
    """Captures whole-request writes from the client (one JSON line per write)."""

    def __init__(self, on_request) -> None:
        self._on_request = on_request
        self._lock = threading.Lock()
        self.closed = False

    def write(self, data: str) -> int:
        with self._lock:
            self._on_request(data)
        return len(data)

    def flush(self) -> None:
        pass

    def close(self) -> None:
        self.closed = True


class _BrokenStdin(_FakeStdin):
    def write(self, data: str) -> int:
        del data
        raise BrokenPipeError("closed")


class _FakeStdout:
    """Blocking line source fed by the test server; ``""`` signals EOF."""

    def __init__(self) -> None:
        self._q: Queue[str] = Queue()
        self.closed = False

    def feed(self, line: str) -> None:
        self._q.put(line)

    def readline(self, _size: int = -1) -> str:
        return self._q.get()

    def close(self) -> None:
        self.closed = True
        self._q.put("")


class _FakeProc:
    def __init__(self, stdin: _FakeStdin, stdout: _FakeStdout) -> None:
        self.stdin = stdin
        self.stdout = stdout
        self.stderr = _FakeStdout()
        self.killed = False

    def wait(self, timeout: float | None = None) -> int:
        return 0

    def kill(self) -> None:
        self.killed = True
        self.stdout.close()
        self.stderr.close()

    def poll(self) -> int | None:
        return None


class _Server:
    """Records incoming requests; lets the test feed responses on demand."""

    def __init__(self) -> None:
        self.requests: list[dict] = []
        self._lock = threading.Lock()
        self.stdout = _FakeStdout()
        self.stdin = _FakeStdin(self._on_request)
        self.proc = _FakeProc(self.stdin, self.stdout)

    def _on_request(self, data: str) -> None:
        for line in data.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                continue
            with self._lock:
                self.requests.append(msg)

    def wait_for(self, n: int, timeout: float = 5.0) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            with self._lock:
                if len(self.requests) >= n:
                    return True
            time.sleep(0.01)
        with self._lock:
            return len(self.requests) >= n

    def respond(self, msg_id: object, result: dict) -> None:
        self.stdout.feed(json.dumps({"jsonrpc": "2.0", "id": msg_id, "result": result}) + "\n")

    def close_stdout(self) -> None:
        self.stdout.feed("")


def _make_client(monkeypatch, server: _Server) -> fea.StdioMcpClient:
    monkeypatch.setattr(fea.subprocess, "Popen", lambda *a, **k: server.proc)
    return fea.StdioMcpClient("ignored-command", "test")


def test_concurrent_calls_match_by_id(monkeypatch) -> None:
    server = _Server()
    client = _make_client(monkeypatch, server)
    n = 8
    results: dict[int, dict] = {}
    errors: list[Exception] = []
    start = threading.Barrier(n)

    def worker(v: int) -> None:
        try:
            start.wait()
            results[v] = client.call("echo", {"n": v}, timeout=5.0)
        except Exception as exc:
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(v,)) for v in range(n)]
    for t in threads:
        t.start()

    assert server.wait_for(n), f"only {len(server.requests)} requests arrived"
    # Respond OUT OF ORDER (reverse id) — only id-matching can stay correct.
    for msg in sorted(server.requests, key=lambda m: m["id"], reverse=True):
        server.respond(msg["id"], {"n": msg["params"]["n"]})

    for t in threads:
        t.join(timeout=10)
    assert not errors, f"unexpected errors: {errors}"
    for v in range(n):
        assert results.get(v) == {"n": v}, f"worker {v} got {results.get(v)!r}"


def test_server_eof_wakes_every_waiter(monkeypatch) -> None:
    server = _Server()
    client = _make_client(monkeypatch, server)
    n = 4
    errors: list[Exception] = []
    start = threading.Barrier(n)

    def worker(v: int) -> None:
        try:
            start.wait()
            client.call("echo", {"n": v}, timeout=5.0)
        except RuntimeError as exc:
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(v,)) for v in range(n)]
    for t in threads:
        t.start()

    assert server.wait_for(n)
    server.close_stdout()
    for t in threads:
        t.join(timeout=10)
    assert len(errors) == n, f"expected {n} errors, got {len(errors)}: {errors}"


def test_sequential_call_returns_result(monkeypatch) -> None:
    server = _Server()
    client = _make_client(monkeypatch, server)
    done = threading.Event()
    box: dict[str, dict] = {}

    def caller() -> None:
        box["r"] = client.call("ping", {"n": 42}, timeout=5.0)
        done.set()

    t = threading.Thread(target=caller)
    t.start()
    assert server.wait_for(1)
    server.respond(server.requests[0]["id"], {"n": 42})
    assert done.wait(10)
    assert box["r"] == {"n": 42}


def test_sift_timeout_fails_the_shared_transport() -> None:
    server = _Server()
    client = fea.SshMcpClient.__new__(fea.SshMcpClient)
    client.label = "sift-test"
    client.proc = server.proc
    client._wire()

    try:
        with pytest.raises(RuntimeError, match="timed out"):
            client.call("ping", {}, timeout=0.01)
    finally:
        client.close()

    assert client._closed is True
    assert client._spawn_error is not None and "timed out" in client._spawn_error
    assert server.proc.killed is True


def test_oversized_unterminated_frame_fails_transport(monkeypatch) -> None:
    monkeypatch.setattr(fea, "MCP_STDOUT_FRAME_MAX_BYTES", 128)
    server = _Server()
    client = _make_client(monkeypatch, server)
    errors: list[Exception] = []

    def caller() -> None:
        try:
            client.call("ping", {}, timeout=5.0)
        except RuntimeError as exc:
            errors.append(exc)

    thread = threading.Thread(target=caller)
    thread.start()
    assert server.wait_for(1)
    server.stdout.feed("x" * 129)
    thread.join(timeout=10)

    assert len(errors) == 1
    assert "frame limit" in str(errors[0])
    assert server.proc.killed is True


def test_multibyte_frame_limit_counts_utf8_wire_bytes(monkeypatch) -> None:
    monkeypatch.setattr(fea, "MCP_STDOUT_FRAME_MAX_BYTES", 384)
    server = (
        "import json,sys; "
        "request=json.loads(sys.stdin.buffer.readline()); "
        "response={'jsonrpc':'2.0','id':request['id'],'result':{'padding':'é'*180}}; "
        "wire=json.dumps(response,ensure_ascii=False).encode('utf-8')+b'\\n'; "
        "assert len(wire)>384 and len(wire.decode('utf-8'))<384; "
        "sys.stdout.buffer.write(wire); sys.stdout.buffer.flush()"
    )
    client = fea.StdioMcpClient([sys.executable, "-c", server], "test")
    try:
        with pytest.raises(RuntimeError, match="frame limit"):
            client.call("ping", {}, timeout=5.0)
    finally:
        client.close()


def test_response_at_exact_wire_byte_ceiling_is_accepted(monkeypatch) -> None:
    response = {"jsonrpc": "2.0", "id": 1, "result": {"ok": True}}
    wire = (json.dumps(response, separators=(",", ":")) + "\n").encode("utf-8")
    monkeypatch.setattr(fea, "MCP_STDOUT_FRAME_MAX_BYTES", len(wire))
    server = (
        "import sys; sys.stdin.buffer.readline(); "
        f"sys.stdout.buffer.write({wire!r}); sys.stdout.buffer.flush()"
    )
    client = fea.StdioMcpClient([sys.executable, "-c", server], "test")
    try:
        assert client.call("ping", {}, timeout=5.0) == {"ok": True}
    finally:
        client.close()


@pytest.mark.parametrize(
    ("hostile_frame", "message"),
    [
        ("[]\n", "non-object"),
        ("null\n", "non-object"),
        ("{bad\n", "malformed JSON-RPC response"),
        ('{"jsonrpc":"1.0","id":1,"result":{}}\n', "JSON-RPC version"),
        ('{"jsonrpc":"2.0","id":null,"result":{}}\n', "response id"),
        ('{"jsonrpc":"2.0","id":[]}\n', "invalid JSON-RPC response id"),
        ('{"jsonrpc":"2.0","id":1,"error":"bad"}\n', "error object"),
        ('{"jsonrpc":"2.0","id":1,"result":[]}\n', "result object"),
        (
            '{"jsonrpc":"2.0","id":1,"result":{},"error":{}}\n',
            "exactly one result or error",
        ),
    ],
)
def test_hostile_json_envelope_fails_transport(
    monkeypatch, hostile_frame: str, message: str
) -> None:
    server = _Server()
    client = _make_client(monkeypatch, server)
    errors: list[Exception] = []

    def caller() -> None:
        try:
            client.call("ping", {}, timeout=1.0)
        except RuntimeError as exc:
            errors.append(exc)

    thread = threading.Thread(target=caller)
    thread.start()
    assert server.wait_for(1)
    server.stdout.feed(hostile_frame)
    thread.join(timeout=10)

    assert len(errors) == 1
    assert message in str(errors[0])
    assert server.proc.killed is True


def test_duplicate_response_id_cannot_block_reader(monkeypatch) -> None:
    server = _Server()
    client = _make_client(monkeypatch, server)
    occupied: Queue[dict | None] = Queue(maxsize=1)
    occupied.put({"jsonrpc": "2.0", "id": 99, "result": {}})
    with client._lock:
        client._waiters[99] = occupied

    server.stdout.feed('{"jsonrpc":"2.0","id":99,"result":{}}\n')
    deadline = time.monotonic() + 5
    while not server.proc.killed and time.monotonic() < deadline:
        time.sleep(0.01)

    assert server.proc.killed is True
    assert client._spawn_error is not None
    assert "duplicate JSON-RPC response id" in client._spawn_error


def test_stdin_write_failure_fails_transport(monkeypatch) -> None:
    server = _Server()
    server.proc.stdin = _BrokenStdin(server._on_request)
    client = _make_client(monkeypatch, server)

    with pytest.raises(RuntimeError, match="stdin closed"):
        client.call("ping", {}, timeout=1.0)

    assert server.proc.killed is True


def test_notification_write_failure_fails_transport(monkeypatch) -> None:
    server = _Server()
    server.proc.stdin = _BrokenStdin(server._on_request)
    client = _make_client(monkeypatch, server)

    with pytest.raises(RuntimeError, match="stdin closed"):
        client.notify("notifications/initialized")

    assert server.proc.killed is True


@pytest.mark.parametrize(
    "result",
    [
        {"content": None},
        {"content": []},
        {"content": [None]},
        {"content": [{"text": 7}]},
        {"content": [{"text": "[]"}]},
        {"content": [{"text": "null"}]},
        {"content": [{"text": "7"}]},
        {"content": [{"text": "{bad"}]},
        {"content": [{"text": "{}"}], "_meta": []},
    ],
)
def test_malformed_tool_result_fails_transport(monkeypatch, result: dict) -> None:
    server = _Server()
    client = _make_client(monkeypatch, server)
    results: list[dict] = []
    errors: list[BaseException] = []

    def caller() -> None:
        try:
            results.append(client.call_tool("probe", {}, timeout=1.0))
        except BaseException as exc:
            errors.append(exc)

    thread = threading.Thread(target=caller)
    thread.start()
    assert server.wait_for(1)
    server.respond(server.requests[0]["id"], result)
    thread.join(timeout=5)

    assert errors == []
    assert len(results) == 1
    assert "_error" in results[0]
    assert "malformed tool response" in results[0]["_error"]["message"]
    assert server.proc.killed is True


def test_local_timeout_kills_inherited_stdout_process_tree(tmp_path) -> None:
    grandchild_pid = tmp_path / "engine-timeout-grandchild.pid"
    survived = tmp_path / "engine-timeout-grandchild-survived"
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
        time.sleep(3)
        """
    )
    client = fea.StdioMcpClient([sys.executable, "-c", server], "test")
    started = time.monotonic()
    try:
        with pytest.raises(RuntimeError, match="timed out"):
            client.call("ping", {}, timeout=0.2)
        closed_after_timeout = client._closed
        timeout_error = client._spawn_error
    finally:
        client.close()
    elapsed = time.monotonic() - started

    assert grandchild_pid.is_file(), "fixture must spawn the inheriting grandchild"
    assert closed_after_timeout is True
    assert timeout_error is not None and "timed out" in timeout_error
    assert elapsed < 1.5, "timeout/close must not block on the stdout reader lock"
    time.sleep(1.1)
    assert not survived.exists(), "timeout must terminate parser grandchildren"
    if os.name == "posix":
        with pytest.raises(ProcessLookupError):
            os.kill(int(grandchild_pid.read_text()), 0)


def test_local_close_kills_inherited_stdout_process_tree(tmp_path) -> None:
    grandchild_pid = tmp_path / "engine-close-grandchild.pid"
    survived = tmp_path / "engine-close-grandchild-survived"
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
    client = fea.StdioMcpClient([sys.executable, "-c", server], "test")
    deadline = time.monotonic() + 2
    while not grandchild_pid.is_file() and time.monotonic() < deadline:
        time.sleep(0.01)
    assert grandchild_pid.is_file(), "fixture must spawn the inheriting grandchild"

    started = time.monotonic()
    client.close()
    elapsed = time.monotonic() - started

    assert elapsed < 1.5, "close must not block on the stdout reader lock"
    time.sleep(1.1)
    assert not survived.exists(), "close must terminate parser grandchildren"
    if os.name == "posix":
        with pytest.raises(ProcessLookupError):
            os.kill(int(grandchild_pid.read_text()), 0)
