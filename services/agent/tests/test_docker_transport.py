"""The deterministic engine's split-trust Docker transport (scripts/verdict
--docker). The evidence-facing Rust MCP runs inside the capability-free
container, while the Python custody/signing MCP stays on the host so native
parsers can never read the signing key or rewrite custody output.

These tests pin the transport selection + path mapping that make a deterministic
``scripts/verdict --docker`` run reach its MCP through the container rather than
degrading to an SSH-to-a-dead-host tool error.
"""

from __future__ import annotations

import contextlib
import importlib.util
import os
import signal
import sys
import textwrap
import time
from pathlib import Path

import pytest

_SCRIPTS = Path(__file__).resolve().parents[3] / "scripts"
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import find_evil_auto as fea  # noqa: E402


def _load_docker_engine(monkeypatch: pytest.MonkeyPatch):
    """Load a FRESH copy of find_evil_auto with FIND_EVIL_DOCKER=1 so its
    import-time constants (GUEST_REPO, RUST_BIN, the docker argvs) resolve for
    the container backend, without mutating the already-imported module."""
    monkeypatch.setenv("FIND_EVIL_DOCKER", "1")
    monkeypatch.delenv("FIND_EVIL_LOCAL", raising=False)
    monkeypatch.delenv("FIND_EVIL_GUEST_REPO", raising=False)
    spec = importlib.util.spec_from_file_location(
        "find_evil_auto_docker", _SCRIPTS / "find_evil_auto.py"
    )
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_docker_mode_selects_container_paths(monkeypatch) -> None:
    m = _load_docker_engine(monkeypatch)
    assert m.DOCKER_MODE is True
    assert m.LOCAL_MODE is False
    # /workspace is only a compatibility namespace assembled from narrow binds.
    assert m.GUEST_REPO == "/workspace"
    assert m.RUST_BIN == "/workspace/target/release/findevil-mcp"


def test_docker_mcp_argv_mirrors_mcp_json_docker(monkeypatch) -> None:
    m = _load_docker_engine(monkeypatch)
    # Rust: launched directly (tool env baked into the image), matching
    # .mcp.json.docker's findevil-mcp args.
    assert m.DOCKER_RUST_ARGV == [
        "docker",
        "exec",
        "-i",
        "findevil-dfir",
        "/workspace/target/release/findevil-mcp",
    ]
    # Python custody stays on-host behind the fixed project launcher.
    assert m.DOCKER_PY_ARGV[0] == "bash"
    assert m.DOCKER_PY_ARGV[1].endswith("scripts/run-mcp-python-docker.sh")


def test_docker_clients_receive_browser_case_binding(monkeypatch) -> None:
    binding = '{"case_id":"dir-docker","artifacts":[]}'
    monkeypatch.setenv("FINDEVIL_BROWSER_CASE_BINDING", binding)
    monkeypatch.setenv("FINDEVIL_BROWSER_SQLITE_MAX_OPS", "7654321")
    m = _load_docker_engine(monkeypatch)

    expected = f"FINDEVIL_BROWSER_CASE_BINDING={binding}"
    assert ["-e", expected] == m.docker_rust_argv()[3:5]
    resource = "FINDEVIL_BROWSER_SQLITE_MAX_OPS=7654321"
    assert resource in m.docker_rust_argv()
    py_env = m._docker_py_env()
    assert py_env["FINDEVIL_BROWSER_CASE_BINDING"] == binding
    assert py_env["FINDEVIL_BROWSER_SQLITE_MAX_OPS"] == "7654321"
    assert py_env["FINDEVIL_REPLAY_TRANSPORT"] == "docker"
    assert py_env["FINDEVIL_REPLAY_DOCKER_CONTAINER"] == "findevil-dfir"


def test_docker_container_name_is_overridable(monkeypatch) -> None:
    monkeypatch.setenv("FIND_EVIL_DOCKER_CONTAINER", "custom-ctr")
    m = _load_docker_engine(monkeypatch)
    assert m.DOCKER_CONTAINER == "custom-ctr"
    assert m.DOCKER_RUST_ARGV[3] == "custom-ctr"
    assert m._docker_py_env()["FINDEVIL_REPLAY_DOCKER_CONTAINER"] == "custom-ctr"


def test_docker_keeps_custody_output_off_parser_mount(monkeypatch) -> None:
    m = _load_docker_engine(monkeypatch)
    inv = m.Investigation("/evidence", case_id="case-split-trust")
    assert inv.case_dir == str(m.REPO_ROOT / "tmp" / "auto-runs" / "case-split-trust")
    assert inv.parser_case_dir == "/workspace/tmp/auto-runs/case-split-trust"
    assert inv.audit_path.startswith(str(m.REPO_ROOT / "tmp" / "auto-runs"))
    assert not inv.audit_path.startswith(inv.parser_case_dir)


def test_docker_default_yara_rule_uses_container_path(monkeypatch) -> None:
    m = _load_docker_engine(monkeypatch)
    assert m.DISK_YARA_RULES == "/workspace/assets/yara/disk-triage.yar"


def test_docker_hayabusa_staging_never_writes_parser_bind_from_host(monkeypatch) -> None:
    m = _load_docker_engine(monkeypatch)
    commands: list[str] = []
    scans: list[str] = []

    monkeypatch.setattr(
        m,
        "ssh_run",
        lambda command, **_kwargs: commands.append(command) or (0, "", ""),
    )
    monkeypatch.setattr(
        m.Investigation,
        "_host_visible_evidence_path",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("Docker staging must not copy from host into parser state")
        ),
    )
    monkeypatch.setattr(
        m.Investigation,
        "investigate_hayabusa_dir",
        lambda _self, _rust, _py, path: scans.append(path),
    )

    inv = m.Investigation("/evidence/sample.evtx", case_id="case-stage")
    inv._hayabusa_stage_single_files(object(), object(), ["/evidence/sample.evtx"])

    assert scans and scans[0].startswith(inv.parser_case_dir)
    assert commands
    assert "ln -s" in commands[0]
    assert str(m.REPO_ROOT) not in commands[0]


def test_docker_never_maps_parser_paths_back_to_host(monkeypatch, tmp_path) -> None:
    m = _load_docker_engine(monkeypatch)
    outside = tmp_path / "outside.evtx"
    outside.write_bytes(b"secret")
    inv = m.Investigation("/evidence", case_id="case-map")

    assert inv._host_visible_evidence_path("/evidence/sample.evtx") is None
    assert inv._host_visible_evidence_path("/evidence/../outside.evtx") is None
    assert inv._host_visible_evidence_path(str(outside)) is None


def test_docker_preflight_requires_host_custody_and_only_rust_in_container(
    monkeypatch,
) -> None:
    m = _load_docker_engine(monkeypatch)
    probes: list[str] = []
    monkeypatch.setattr(m.shutil, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(
        m,
        "ssh_run",
        lambda command, **_kwargs: probes.append(command) or (0, "ok", ""),
    )

    m.preflight_check()

    assert probes == [f"test -x {m.RUST_BIN_Q} && echo ok"]
    assert "agent_mcp" not in probes[0]
    assert "uv" not in probes[0]


def test_docker_never_interprets_parser_mount_root_on_host(monkeypatch) -> None:
    m = _load_docker_engine(monkeypatch)
    inv = m.Investigation("/evidence/disk.dd", case_id="case-dbx")

    class _Rust:
        def call_tool(self, *_args, **_kwargs):
            raise AssertionError("Docker DBX lane must not cross parser paths to host")

    monkeypatch.setattr(
        m,
        "Path",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("host Path must not inspect Docker fs_root")
        ),
    )
    inv.investigate_oe_dbx_stores(_Rust(), object(), "/")

    assert any("DBX" in item and "Docker" in item for item in inv.analysis_limitations)


def test_ssh_run_uses_docker_exec_in_docker_mode(monkeypatch) -> None:
    # ssh_run (guest-side mkdir/test/cat) routes through a bounded, profile-free
    # Docker exec command rather than trusting parser-writable HOME startup files.
    captured: dict[str, list[str]] = {}

    def _fake_bounded(argv, **kwargs):
        captured["argv"] = argv
        assert kwargs["timeout"] == 605
        return 0, "ok\n", ""

    monkeypatch.setattr(fea, "DOCKER_MODE", True)
    monkeypatch.setattr(fea, "LOCAL_MODE", False)
    monkeypatch.setattr(fea, "DOCKER_CONTAINER", "findevil-dfir")
    monkeypatch.setattr(fea, "_run_bounded_capture", _fake_bounded)

    code, _out, _ = fea.ssh_run("mkdir -p /workspace/tmp/auto-runs/case")
    assert code == 0
    assert captured["argv"][:4] == [
        "docker",
        "exec",
        "findevil-dfir",
        "/usr/bin/env",
    ]
    assert "BASH_ENV" in captured["argv"]
    assert "/usr/bin/timeout" in captured["argv"]
    assert captured["argv"][-5:-1] == [
        "/bin/bash",
        "--noprofile",
        "--norc",
        "-c",
    ]
    assert captured["argv"][-1] == "mkdir -p /workspace/tmp/auto-runs/case"


def test_bounded_helper_capture_kills_oversized_output() -> None:
    code, stdout, stderr = fea._run_bounded_capture(
        [
            sys.executable,
            "-c",
            "import sys,time; sys.stdout.buffer.write(b'x'*4096); "
            "sys.stdout.flush(); time.sleep(10)",
        ],
        timeout=5,
        stdout_max_bytes=128,
        stderr_max_bytes=128,
    )
    assert code == 125
    assert stdout == "x" * 128
    assert "stdout exceeded 128 bytes" in stderr


def test_bounded_capture_escaped_session_inherited_stdout_does_not_hang(
    tmp_path,
) -> None:
    grandchild_pid = tmp_path / "escaped-session.pid"
    leader = textwrap.dedent(
        f"""
        import pathlib, subprocess, sys
        child = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(3)"],
            start_new_session=True,
        )
        pathlib.Path({str(grandchild_pid)!r}).write_text(str(child.pid))
        """
    )

    started = time.monotonic()
    try:
        code, _stdout, stderr = fea._run_bounded_capture([sys.executable, "-c", leader], timeout=2)
    finally:
        if grandchild_pid.is_file():
            with contextlib.suppress(ProcessLookupError):
                os.kill(int(grandchild_pid.read_text()), signal.SIGKILL)
    elapsed = time.monotonic() - started

    assert elapsed < 1.5, "capture must not close a pipe with a live drain"
    assert code == 125
    assert "pipe remained open after leader exit" in stderr


def test_docker_bridge_overflow_removes_runtime(monkeypatch) -> None:
    removed: list[list[str]] = []
    monkeypatch.setattr(fea, "DOCKER_MODE", True)
    monkeypatch.setattr(fea, "LOCAL_MODE", False)
    monkeypatch.setattr(fea, "DOCKER_CONTAINER", "findevil-dfir")
    monkeypatch.setattr(
        fea,
        "_run_bounded_capture",
        lambda *_args, **_kwargs: (125, "", "bounded capture overflow"),
    )

    def _fake_run(argv, **_kwargs):
        removed.append(argv)

    monkeypatch.setattr(fea.subprocess, "run", _fake_run)
    code, _, _ = fea.ssh_run("probe")

    assert code == 125
    assert removed == [["docker", "rm", "-f", "findevil-dfir"]]


def test_docker_mcp_protocol_failure_removes_runtime(monkeypatch) -> None:
    removed: list[list[str]] = []
    monkeypatch.setattr(fea, "DOCKER_CONTAINER", "findevil-dfir-case")

    def _fake_run(argv, **_kwargs):
        removed.append(argv)

    monkeypatch.setattr(fea.subprocess, "run", _fake_run)
    server = "import sys; sys.stdin.readline(); print('[]', flush=True)"
    client = fea.DockerMcpClient([sys.executable, "-c", server], "probe")
    try:
        with pytest.raises(RuntimeError, match="non-object"):
            client.call("probe", {}, timeout=2)
    finally:
        client.close()

    assert removed == [["docker", "rm", "-f", "findevil-dfir-case"]]


def test_docker_mcp_malformed_tool_content_removes_runtime(monkeypatch) -> None:
    removed: list[list[str]] = []
    monkeypatch.setattr(fea, "DOCKER_CONTAINER", "findevil-dfir-case")
    monkeypatch.setattr(
        fea.subprocess,
        "run",
        lambda argv, **_kwargs: removed.append(argv),
    )
    server = textwrap.dedent(
        """
        import json, sys, time
        request = json.loads(sys.stdin.buffer.readline())
        response = {
            "jsonrpc": "2.0",
            "id": request["id"],
            "result": {"content": None},
        }
        print(json.dumps(response), flush=True)
        time.sleep(10)
        """
    )
    client = fea.DockerMcpClient([sys.executable, "-c", server], "probe")
    try:
        result = client.call_tool("probe", {}, timeout=2)
    finally:
        client.close()

    assert "malformed tool response" in result["_error"]["message"]
    assert removed == [["docker", "rm", "-f", "findevil-dfir-case"]]


def test_docker_mcp_timeout_removes_runtime(monkeypatch) -> None:
    removed: list[list[str]] = []
    monkeypatch.setattr(fea, "DOCKER_CONTAINER", "findevil-dfir-case")
    monkeypatch.setattr(fea.subprocess, "run", lambda argv, **_kwargs: removed.append(argv))
    server = "import sys,time; sys.stdin.readline(); time.sleep(10)"
    client = fea.DockerMcpClient([sys.executable, "-c", server], "probe")
    try:
        with pytest.raises(RuntimeError, match="timed out"):
            client.call("probe", {}, timeout=0.1)
    finally:
        client.close()

    assert removed == [["docker", "rm", "-f", "findevil-dfir-case"]]


def test_docker_directory_inventory_never_uses_colliding_host_path(monkeypatch) -> None:
    """A guest path such as /evidence may coincidentally exist on the host.

    Transport, not host ``Path.is_dir()``, decides where custody inventory is
    built. Otherwise Docker could hash an unrelated host directory and bind the
    browser allow-list to the wrong bytes.
    """
    remote_inventory = {"parent_case_id": "remote-case", "entries": []}
    calls: list[tuple[str, str]] = []

    monkeypatch.setattr(fea, "LOCAL_MODE", False)
    monkeypatch.setattr(fea, "DOCKER_MODE", True)
    monkeypatch.setattr(
        fea,
        "build_local_evidence_inventory",
        lambda path: calls.append(("local", path)) or {},
    )
    monkeypatch.setattr(
        fea,
        "build_remote_evidence_inventory",
        lambda path: calls.append(("remote", path)) or remote_inventory,
    )
    # Reproduce the collision explicitly: /evidence appears to be a host dir.
    monkeypatch.setattr(fea.Path, "is_dir", lambda _path: True)

    inv = fea.Investigation("/evidence", case_id="case-remote-inventory")
    assert inv._prepare_directory_inventory() is remote_inventory
    assert calls == [("remote", "/evidence")]


def test_missing_docker_binary_degrades_not_crashes(monkeypatch) -> None:
    # A host with no docker client must degrade to the same fast tool error as
    # an unreachable SIFT VM, not crash the engine at client construction.
    def _no_docker(*args, **kwargs):
        raise FileNotFoundError(2, "No such file or directory", "docker")

    monkeypatch.setattr(fea.subprocess, "Popen", _no_docker)

    client = fea.DockerMcpClient(["docker", "exec", "-i", "findevil-dfir", "x"], "rust-mcp")
    try:
        result = client.call_tool("case_open", {}, timeout=5.0)
        assert "_error" in result
        assert "docker" in result["_error"]["message"]
    finally:
        client.close()


# Responder for the large-response deadlock repro below. It reproduces the
# ROOT-CAUSE trigger deterministically without needing a real container:
#   1. emit one non-utf-8 byte on stderr — under strict decode this raised
#      UnicodeDecodeError (a ValueError) inside _drain_stderr, whose ``except``
#      swallowed it and KILLED the drain thread;
#   2. with the drain dead, flood stderr past the 64 KB pipe buffer;
#   3. only THEN read the JSON-RPC request and answer on stdout.
# With the drain dead (pre-fix) the flood fills the stderr pipe and the producer
# blocks on write(stderr) forever, so the response in step 3 never ships and the
# ``call`` times out — the same stall that, over ``docker exec``, is aggravated
# by stdcopy's single-goroutine stdout/stderr demux. With errors="replace" the
# drain survives step 1, keeps stderr drained, and the response ships promptly.
_DEADLOCK_RESPONDER = textwrap.dedent(
    """
    import sys, os, time, json
    os.write(2, b"\\xff\\n")          # non-utf-8 byte: kills a strict-decode drain
    time.sleep(0.3)                    # let the drain thread hit it
    os.write(2, b"E" * (1024 * 1024))  # flood the (now undrained) stderr pipe
    line = sys.stdin.readline()        # only reached if the drain kept up
    req = json.loads(line)
    resp = {"jsonrpc": "2.0", "id": req["id"], "result": {"ok": True, "rows": 2500}}
    os.write(1, (json.dumps(resp, separators=(",", ":")) + "\\n").encode())
    sys.stdout.flush()
    time.sleep(0.5)
    """
)


def test_docker_large_response_survives_stderr_backpressure() -> None:
    """A large response must ship even when the container floods stderr with a
    stray non-utf-8 byte in it. Pre-fix (strict decode) the drain thread died on
    that byte, stderr backed up, and the response never arrived — the run hung.
    errors="replace" keeps the drain alive so the response ships.

    Docker-free by design: DockerMcpClient just spawns whatever argv it is given,
    so a plain ``python3 -c`` producer exercises the exact reader/drain code the
    fix touches, deterministically and without a running container.
    """
    argv = [sys.executable, "-c", _DEADLOCK_RESPONDER]
    client = fea.DockerMcpClient(argv, "py-mcp")
    try:
        t0 = time.time()
        # Pre-fix this call blocks until the timeout; post-fix it returns in ~1s.
        result = client.call("tools/call", {"name": "x", "arguments": {}}, timeout=20.0)
        elapsed = time.time() - t0
        assert result == {"ok": True, "rows": 2500}
        # Comfortably under the timeout: proves the response shipped rather than
        # the caller being woken by a closing pipe near the deadline.
        assert elapsed < 15.0
    finally:
        client.close()


def test_subprocess_text_wrapper_decode_configuration_is_explicit() -> None:
    """The raw-byte readers own protocol decoding; wrapper configuration only
    records the backend's launch policy and must remain explicit."""
    # DockerMcpClient configures replacement on its text wrappers …
    docker = fea.DockerMcpClient([sys.executable, "-c", "pass"], "probe")
    try:
        assert docker.proc is not None
        assert docker.proc.stdout.errors == "replace"
        assert docker.proc.stderr.errors == "replace"
    finally:
        docker.close()
    # … while the local stdio wrapper retains Python's strict default. The
    # shared raw stderr drain replaces invalid diagnostic bytes for both.
    local = fea.StdioMcpClient("true", "probe")
    try:
        assert local.proc is not None
        assert local.proc.stdout.errors == "strict"
        assert local.proc.stderr.errors == "strict"
    finally:
        local.close()
