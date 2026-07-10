from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parents[3] / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import find_evil_auto as fea  # noqa: E402

_ACTIVE_ENV = {
    "FINDEVIL_CUSTODY_BOUNDARY": "reserved_case",
    "FINDEVIL_ACTIVE_CASE_DIR": "/trusted/cases/case-local",
    "FINDEVIL_ACTIVE_CASE_ID": "case-local",
    "FINDEVIL_ACTIVE_RUN_ID": "run-local",
    "FINDEVIL_ACTIVE_STARTED_AT": "2026-07-10T00:00:00Z",
    "FINDEVIL_ACTIVE_SIGNER": "ed25519",
}


@pytest.mark.parametrize(
    ("agent_mode", "provider", "acknowledged", "expected"),
    [
        (False, None, False, {"FINDEVIL_OUTPUT_ROUTE": "local_controller"}),
        (False, None, True, {"FINDEVIL_OUTPUT_ROUTE": "local_controller"}),
        (True, "local", False, {"FINDEVIL_OUTPUT_ROUTE": "local_dgx"}),
        (True, "local", True, {"FINDEVIL_OUTPUT_ROUTE": "local_dgx"}),
        (True, "dgx", False, {"FINDEVIL_OUTPUT_ROUTE": "local_dgx"}),
        (True, "anthropic", False, {}),
        (True, "claude_cli", False, {}),
        (True, "openai", False, {}),
        (True, "openrouter", False, {}),
        (
            True,
            "anthropic",
            True,
            {"FINDEVIL_ACKNOWLEDGE_PARSED_EVIDENCE_EGRESS": "1"},
        ),
        (True, "claude_cli", True, {"FINDEVIL_ACKNOWLEDGE_PARSED_EVIDENCE_EGRESS": "1"}),
        (True, "openai", True, {"FINDEVIL_ACKNOWLEDGE_PARSED_EVIDENCE_EGRESS": "1"}),
        (True, "openrouter", True, {"FINDEVIL_ACKNOWLEDGE_PARSED_EVIDENCE_EGRESS": "1"}),
        (True, "unknown-provider", True, {}),
    ],
)
def test_parser_output_route_provider_matrix(
    agent_mode: bool,
    provider: str | None,
    acknowledged: bool,
    expected: dict[str, str],
) -> None:
    assert (
        fea.parser_output_route_env(
            agent_mode=agent_mode,
            agent_provider=provider,
            acknowledged=acknowledged,
            environment={},
        )
        == expected
    )


def test_parser_output_route_uses_reviewed_provider_env_and_unknown_fails_closed() -> None:
    assert fea.parser_output_route_env(
        agent_mode=True,
        agent_provider=None,
        acknowledged=False,
        environment={"FINDEVIL_AGENT_PROVIDER": "local"},
    ) == {"FINDEVIL_OUTPUT_ROUTE": "local_dgx"}
    assert (
        fea.parser_output_route_env(
            agent_mode=True,
            agent_provider=None,
            acknowledged=True,
            environment={"FINDEVIL_AGENT_PROVIDER": "surprise-cloud"},
        )
        == {}
    )


def test_local_python_transport_receives_custody_reservation_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for name, value in _ACTIVE_ENV.items():
        monkeypatch.setenv(name, value)

    python_env = fea._local_py_env()
    rust_env = fea._local_rust_env()

    assert {name: python_env[name] for name in _ACTIVE_ENV} == _ACTIVE_ENV
    assert all(name not in rust_env for name in _ACTIVE_ENV)


def test_sift_python_launcher_receives_remote_reservation_and_fixed_writes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(fea, "LOCAL_MODE", False)
    monkeypatch.setattr(fea, "DOCKER_MODE", False)
    for name, value in _ACTIVE_ENV.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setenv("FINDEVIL_SIFT_MEMORY_STORE", "/guest/private/memory.sqlite")
    monkeypatch.setenv("FINDEVIL_SIFT_EXPERT_MISS_LEDGER", "/guest/private/expert_misses.jsonl")

    launcher = fea._sift_py_launcher()

    for name, value in _ACTIVE_ENV.items():
        assert f"{name}={value}" in launcher
    assert "FINDEVIL_MEMORY_STORE=/guest/private/memory.sqlite" in launcher
    assert "FINDEVIL_EXPERT_MISS_LEDGER=/guest/private/expert_misses.jsonl" in launcher
    assert "FINDEVIL_CUSTODY_BOUNDARY" not in fea._sift_rust_launcher()


def test_local_case_reservation_creates_private_owned_marker(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    evidence = tmp_path / "evidence.evtx"
    evidence.write_bytes(b"fixture")
    runs = tmp_path / "runs"
    monkeypatch.setattr(fea, "LOCAL_MODE", True)
    monkeypatch.setattr(fea, "DOCKER_MODE", False)
    monkeypatch.setattr(fea, "LOCAL_RUNS_DIR", runs)
    inv = fea.Investigation(str(evidence), case_id="case-local", with_report=False)

    inv._reserve_custody_case_dir()

    case_dir = runs / "case-local"
    marker = case_dir / ".verdict-case-marker"
    assert marker.is_file()
    if os.name != "nt":
        assert case_dir.stat().st_mode & 0o777 == 0o700
        assert marker.stat().st_mode & 0o777 == 0o600


def test_local_case_reservation_refuses_unowned_existing_directory(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    evidence = tmp_path / "evidence.evtx"
    evidence.write_bytes(b"fixture")
    runs = tmp_path / "runs"
    (runs / "case-local").mkdir(parents=True)
    monkeypatch.setattr(fea, "LOCAL_MODE", True)
    monkeypatch.setattr(fea, "DOCKER_MODE", False)
    monkeypatch.setattr(fea, "LOCAL_RUNS_DIR", runs)
    inv = fea.Investigation(str(evidence), case_id="case-local", with_report=False)

    with pytest.raises(RuntimeError, match="ownership marker"):
        inv._reserve_custody_case_dir()


def test_native_windows_custody_fails_closed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    evidence = tmp_path / "evidence.evtx"
    evidence.write_bytes(b"fixture")
    monkeypatch.setattr(fea, "LOCAL_MODE", True)
    monkeypatch.setattr(fea, "DOCKER_MODE", False)
    monkeypatch.setattr(fea, "LOCAL_RUNS_DIR", tmp_path / "runs")
    monkeypatch.setattr(fea, "_is_native_windows", lambda: True)
    inv = fea.Investigation(str(evidence), case_id="case-windows", with_report=False)

    with pytest.raises(RuntimeError, match="WSL2 or Docker"):
        inv._reserve_custody_case_dir()


def test_run_enables_boundary_before_spawning_local_python(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    evidence = tmp_path / "evidence.evtx"
    evidence.write_bytes(b"fixture")
    monkeypatch.setattr(fea, "LOCAL_MODE", True)
    monkeypatch.setattr(fea, "DOCKER_MODE", False)
    monkeypatch.setattr(fea, "LOCAL_RUNS_DIR", tmp_path / "runs")
    for name in _ACTIVE_ENV:
        monkeypatch.delenv(name, raising=False)

    captured: dict[str, str] = {}

    class StopAfterSpawn(RuntimeError):
        pass

    class FakeClient:
        def call(self, *_args: object, **_kwargs: object) -> None:
            raise StopAfterSpawn

        def close(self) -> None:
            return None

    monkeypatch.setattr(fea, "make_rust_client", lambda: FakeClient())

    def make_python() -> FakeClient:
        captured.update(fea._local_py_env())
        return FakeClient()

    monkeypatch.setattr(fea, "make_py_client", make_python)
    inv = fea.Investigation(str(evidence), case_id="case-local", with_report=False)

    with pytest.raises(StopAfterSpawn):
        inv.run()

    assert captured["FINDEVIL_CUSTODY_BOUNDARY"] == "reserved_case"
    assert captured["FINDEVIL_ACTIVE_CASE_DIR"] == str(tmp_path / "runs" / "case-local")
    assert captured["FINDEVIL_ACTIVE_CASE_ID"] == "case-local"
    assert captured["FINDEVIL_ACTIVE_RUN_ID"] == inv.run_id
    assert captured["FINDEVIL_ACTIVE_STARTED_AT"] == inv.started_at
    assert captured["FINDEVIL_ACTIVE_SIGNER"] == inv.signer
    assert len(captured[fea.CONTROLLER_CAPABILITY_ENV]) == 64
    assert captured[fea.CASE_OPEN_BINDING_ENV]
    assert captured["FINDEVIL_OUTPUT_ROUTE"] == "local_controller"
    assert "FINDEVIL_ACKNOWLEDGE_PARSED_EVIDENCE_EGRESS" not in captured
    assert all(name not in os.environ for name in _ACTIVE_ENV)
    assert fea.CONTROLLER_CAPABILITY_ENV not in os.environ
    assert fea.CASE_OPEN_BINDING_ENV not in os.environ
    assert "FINDEVIL_OUTPUT_ROUTE" not in os.environ
    assert "FINDEVIL_ACKNOWLEDGE_PARSED_EVIDENCE_EGRESS" not in os.environ


def test_single_file_registration_binding_is_hash_pinned(tmp_path: Path) -> None:
    evidence = tmp_path / "host.evtx"
    evidence.write_bytes(b"registered evidence")

    binding, expected = fea.single_evidence_registration(evidence)
    decoded = __import__("json").loads(binding)

    assert expected == fea.sha256_file_local(evidence)
    assert decoded == {
        "artifacts": [
            {
                "path": str(evidence.resolve()),
                "sha256": expected,
            }
        ]
    }


def test_split_ewf_registration_binds_every_segment_and_concat_hash(
    tmp_path: Path,
) -> None:
    first = tmp_path / "disk.E01"
    second = tmp_path / "disk.e02"
    first.write_bytes(b"first")
    second.write_bytes(b"second")

    binding, expected = fea.single_evidence_registration(first)
    decoded = __import__("json").loads(binding)

    assert [row["path"] for row in decoded["artifacts"]] == [
        str(first.resolve()),
        str(second.resolve()),
    ]
    assert [row["sha256"] for row in decoded["artifacts"]] == [
        fea.sha256_file_local(first),
        fea.sha256_file_local(second),
    ]
    import hashlib

    assert expected == hashlib.sha256(b"firstsecond").hexdigest()


def test_single_registration_rejects_hardlinks_and_segment_gaps(tmp_path: Path) -> None:
    original = tmp_path / "original.evtx"
    alias = tmp_path / "alias.evtx"
    original.write_bytes(b"shared")
    os.link(original, alias)
    with pytest.raises(ValueError, match="hard-linked"):
        fea.single_evidence_registration(alias)

    first = tmp_path / "gap.E01"
    third = tmp_path / "gap.E03"
    first.write_bytes(b"one")
    third.write_bytes(b"three")
    with pytest.raises(ValueError, match="missing split EWF segment"):
        fea.single_evidence_registration(first)


def test_local_and_remote_directory_inventory_reject_hardlinks(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    original = evidence / "Security.evtx"
    alias = evidence / "Security-copy.evtx"
    original.write_bytes(b"shared evidence")
    os.link(original, alias)

    local = fea.build_local_evidence_inventory(evidence)

    def local_ssh(command: str, *, timeout: int) -> tuple[int, str, str]:
        result = subprocess.run(
            ["bash", "-c", command],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return result.returncode, result.stdout, result.stderr

    monkeypatch.setattr(fea, "ssh_run", local_ssh)
    remote = fea.build_remote_evidence_inventory(str(evidence))

    for inventory in (local, remote):
        rows = {Path(str(entry["path"])).name: entry for entry in inventory["entries"]}
        assert rows[original.name]["custody_status"] == "rejected_hardlink"
        assert rows[alias.name]["custody_status"] == "rejected_hardlink"
        assert rows[original.name]["sha256"] is None
        assert rows[alias.name]["sha256"] is None


def test_case_open_binding_reaches_parser_and_replay_launchers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    binding = '{"artifacts":[{"path":"/evidence/a.evtx","sha256":"' + "a" * 64 + '"}]}'
    monkeypatch.setenv(fea.CASE_OPEN_BINDING_ENV, binding)

    assert fea._local_rust_env()[fea.CASE_OPEN_BINDING_ENV] == binding
    assert fea._local_py_env()[fea.CASE_OPEN_BINDING_ENV] == binding
    assert fea.CASE_OPEN_BINDING_ENV in fea._sift_rust_launcher()
    assert fea.CASE_OPEN_BINDING_ENV in fea._sift_py_launcher()


def test_output_route_reaches_every_parser_launcher(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("FINDEVIL_OUTPUT_ROUTE", "local_dgx")

    assert fea._local_rust_env()["FINDEVIL_OUTPUT_ROUTE"] == "local_dgx"
    assert fea._local_py_env()["FINDEVIL_OUTPUT_ROUTE"] == "local_dgx"
    assert fea._docker_py_env()["FINDEVIL_OUTPUT_ROUTE"] == "local_dgx"
    assert "FINDEVIL_OUTPUT_ROUTE=local_dgx" in fea._sift_rust_launcher()
    assert "FINDEVIL_OUTPUT_ROUTE=local_dgx" in fea._sift_py_launcher()
    assert "FINDEVIL_OUTPUT_ROUTE=local_dgx" in fea.docker_rust_argv()


def test_directory_reservation_supports_child_case_registrations(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()
    evtx = evidence_dir / "Security.evtx"
    first = evidence_dir / "disk.E01"
    second = evidence_dir / "disk.E02"
    evtx.write_bytes(b"event")
    first.write_bytes(b"first")
    second.write_bytes(b"second")
    monkeypatch.setattr(fea, "LOCAL_MODE", True)
    monkeypatch.setattr(fea, "DOCKER_MODE", False)
    monkeypatch.setattr(fea, "LOCAL_RUNS_DIR", tmp_path / "runs")
    inv = fea.Investigation(str(evidence_dir), case_id="case-directory", with_report=False)

    binding, expected_by_path = inv._prepare_case_open_reservation("directory")
    assert binding is not None
    decoded = __import__("json").loads(binding)
    bound_paths = {row["path"] for row in decoded["artifacts"]}

    assert str(evtx.resolve()) in bound_paths
    assert str(first.resolve()) in bound_paths
    assert str(second.resolve()) in bound_paths
    assert expected_by_path[str(evtx.resolve())] == fea.sha256_file_local(evtx)
    import hashlib

    assert expected_by_path[str(first.resolve())] == hashlib.sha256(b"firstsecond").hexdigest()


@pytest.mark.parametrize("case_id", ["../escape", "case/child", "-option", "", "a" * 129])
def test_investigation_rejects_unsafe_case_id(case_id: str) -> None:
    with pytest.raises(ValueError, match="case_id"):
        fea.Investigation("evidence.evtx", case_id=case_id, with_report=False)
