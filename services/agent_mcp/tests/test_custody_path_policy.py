from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from findevil_agent_mcp.custody_path_policy import (
    CustodyPathPolicyError,
    enforce_tool_path_policy,
)


@pytest.fixture
def bound_case(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    # These tests exercise the POSIX reserved-custody enforcement (symlink /
    # hard-link rejection, launcher-bound identity, case confinement). On native
    # Windows that enforcement is deliberately fail-closed off — custody requires
    # private DACLs and an interprocess audit lock the product does not yet verify
    # there, so `enforce_tool_path_policy` refuses before any path check (see
    # `test_native_windows_reserved_custody_fails_closed`, which runs everywhere).
    # There is nothing to assert on native Windows; POSIX / WSL2 / Docker cover it.
    if os.name == "nt":
        pytest.skip("reserved custody enforcement is disabled on native Windows by design")
    case_dir = tmp_path / "auto-runs" / "case-001"
    case_dir.mkdir(parents=True)
    marker = case_dir / ".verdict-case-marker"
    marker.write_text("", encoding="utf-8")
    if os.name != "nt":
        case_dir.chmod(0o700)
        marker.chmod(0o600)
    memory = tmp_path / "private" / "memory.sqlite"
    ledger = tmp_path / "private" / "expert_misses.jsonl"
    monkeypatch.setenv("FINDEVIL_CUSTODY_BOUNDARY", "reserved_case")
    monkeypatch.setenv("FINDEVIL_ACTIVE_CASE_DIR", str(case_dir))
    monkeypatch.setenv("FINDEVIL_ACTIVE_CASE_ID", "case-001")
    monkeypatch.setenv("FINDEVIL_ACTIVE_RUN_ID", "run-001")
    monkeypatch.setenv("FINDEVIL_ACTIVE_STARTED_AT", "2026-07-10T00:00:00Z")
    monkeypatch.setenv("FINDEVIL_ACTIVE_SIGNER", "ed25519")
    monkeypatch.setenv("FINDEVIL_MEMORY_STORE", str(memory))
    monkeypatch.setenv("FINDEVIL_EXPERT_MISS_LEDGER", str(ledger))
    return case_dir


def test_audit_path_is_exactly_reserved_case(bound_case: Path, tmp_path: Path) -> None:
    enforce_tool_path_policy("audit_append", SimpleNamespace(path=str(bound_case / "audit.jsonl")))
    with pytest.raises(CustodyPathPolicyError, match="reserved audit path"):
        enforce_tool_path_policy(
            "audit_append", SimpleNamespace(path=str(tmp_path / "outside.jsonl"))
        )


def test_writable_target_rejects_symlink_and_hardlink(bound_case: Path, tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.write_text("secret", encoding="utf-8")
    (bound_case / "audit.jsonl").symlink_to(outside)
    with pytest.raises(CustodyPathPolicyError, match="symlink"):
        enforce_tool_path_policy(
            "audit_append", SimpleNamespace(path=str(bound_case / "audit.jsonl"))
        )

    (bound_case / "audit.jsonl").unlink()
    os.link(outside, bound_case / "audit.jsonl")
    with pytest.raises(CustodyPathPolicyError, match="hard-linked"):
        enforce_tool_path_policy(
            "audit_append", SimpleNamespace(path=str(bound_case / "audit.jsonl"))
        )


def test_manifest_paths_and_signer_are_launcher_bound(bound_case: Path, tmp_path: Path) -> None:
    (bound_case / "audit.jsonl").write_text("", encoding="utf-8")
    valid = SimpleNamespace(
        case_id="case-001",
        run_id="run-001",
        started_at="2026-07-10T00:00:00Z",
        audit_log_path=str(bound_case / "audit.jsonl"),
        output_path=str(bound_case / "run.manifest.json"),
        signer="ed25519",
    )
    enforce_tool_path_policy("manifest_finalize", valid)

    with pytest.raises(CustodyPathPolicyError, match="manifest output"):
        enforce_tool_path_policy(
            "manifest_finalize",
            SimpleNamespace(
                case_id="case-001",
                run_id="run-001",
                started_at="2026-07-10T00:00:00Z",
                audit_log_path=str(bound_case / "audit.jsonl"),
                output_path=str(tmp_path / "forged.json"),
                signer="ed25519",
            ),
        )
    with pytest.raises(CustodyPathPolicyError, match="signer"):
        enforce_tool_path_policy(
            "manifest_finalize",
            SimpleNamespace(
                case_id="case-001",
                run_id="run-001",
                started_at="2026-07-10T00:00:00Z",
                audit_log_path=str(bound_case / "audit.jsonl"),
                output_path=str(bound_case / "run.manifest.json"),
                signer="sigstore",
            ),
        )


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("case_id", "case-forged", "case ID"),
        ("run_id", "run-forged", "run ID"),
        ("started_at", "2026-07-10T00:00:01Z", "start time"),
    ],
)
def test_manifest_identity_is_launcher_bound(
    bound_case: Path, field: str, value: str, message: str
) -> None:
    (bound_case / "audit.jsonl").write_text("", encoding="utf-8")
    values = {
        "case_id": "case-001",
        "run_id": "run-001",
        "started_at": "2026-07-10T00:00:00Z",
        "audit_log_path": str(bound_case / "audit.jsonl"),
        "output_path": str(bound_case / "run.manifest.json"),
        "signer": "ed25519",
    }
    values[field] = value
    with pytest.raises(CustodyPathPolicyError, match=message):
        enforce_tool_path_policy("manifest_finalize", SimpleNamespace(**values))


def test_memory_and_expert_ledgers_are_fixed(bound_case: Path, tmp_path: Path) -> None:
    memory = os.environ["FINDEVIL_MEMORY_STORE"]
    ledger = os.environ["FINDEVIL_EXPERT_MISS_LEDGER"]
    enforce_tool_path_policy(
        "memory_recall", SimpleNamespace(store_path=memory, audit_log_path=None)
    )
    enforce_tool_path_policy(
        "expert_miss_capture", SimpleNamespace(ledger_path=ledger, case_id="case-001")
    )
    with pytest.raises(CustodyPathPolicyError, match="memory store"):
        enforce_tool_path_policy(
            "memory_recall",
            SimpleNamespace(store_path=str(tmp_path / "other.sqlite"), audit_log_path=None),
        )

    memory_path = Path(memory)
    memory_path.parent.mkdir(parents=True)
    source = tmp_path / "hardlinked-memory.sqlite"
    source.write_bytes(b"sqlite")
    os.link(source, memory_path)
    with pytest.raises(CustodyPathPolicyError, match="hard-linked"):
        enforce_tool_path_policy(
            "memory_recall", SimpleNamespace(store_path=memory, audit_log_path=None)
        )


def test_cross_case_writes_are_launcher_bound(bound_case: Path) -> None:
    audit = bound_case / "audit.jsonl"
    audit.write_text("", encoding="utf-8")
    memory = os.environ["FINDEVIL_MEMORY_STORE"]
    ledger = os.environ["FINDEVIL_EXPERT_MISS_LEDGER"]
    valid_memory = {
        "store_path": memory,
        "audit_log_path": str(audit),
        "case_id": "case-001",
        "case_path": str(bound_case),
    }

    enforce_tool_path_policy("memory_remember", SimpleNamespace(**valid_memory))
    with pytest.raises(CustodyPathPolicyError, match="case ID"):
        enforce_tool_path_policy(
            "memory_remember",
            SimpleNamespace(**{**valid_memory, "case_id": "another-case"}),
        )
    with pytest.raises(CustodyPathPolicyError, match="audit path"):
        enforce_tool_path_policy(
            "memory_remember",
            SimpleNamespace(**{**valid_memory, "audit_log_path": None}),
        )
    with pytest.raises(CustodyPathPolicyError, match="case path"):
        enforce_tool_path_policy(
            "memory_remember",
            SimpleNamespace(**{**valid_memory, "case_path": str(bound_case.parent)}),
        )

    enforce_tool_path_policy(
        "expert_miss_capture", SimpleNamespace(ledger_path=ledger, case_id="case-001")
    )
    with pytest.raises(CustodyPathPolicyError, match="case ID"):
        enforce_tool_path_policy(
            "expert_miss_capture",
            SimpleNamespace(ledger_path=ledger, case_id="another-case"),
        )


def test_host_file_scanner_is_confined_to_case(bound_case: Path, tmp_path: Path) -> None:
    inside = bound_case / "report.txt"
    inside.write_text("safe", encoding="utf-8")
    outside = tmp_path / "secret.txt"
    outside.write_text("secret", encoding="utf-8")
    enforce_tool_path_policy("find_ai_signatures", SimpleNamespace(paths=[str(inside)]))
    with pytest.raises(CustodyPathPolicyError, match="outside reserved case"):
        enforce_tool_path_policy("find_ai_signatures", SimpleNamespace(paths=[str(outside)]))


def test_path_tools_fail_closed_without_launcher_reservation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.delenv("FINDEVIL_CUSTODY_BOUNDARY", raising=False)
    with pytest.raises(CustodyPathPolicyError, match="launcher reservation"):
        enforce_tool_path_policy(
            "audit_append", SimpleNamespace(path=str(tmp_path / "local-audit.jsonl"))
        )


def test_pure_non_filesystem_tool_remains_available_without_reservation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("FINDEVIL_CUSTODY_BOUNDARY", raising=False)
    enforce_tool_path_policy("detect_contradictions", SimpleNamespace())


def test_native_windows_reserved_custody_fails_closed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # Platform-independent: force the native-Windows branch and confirm custody
    # fails closed before any path resolution. Runs on every OS (it does not rely
    # on the POSIX-only `bound_case` fixture), so it also exercises the real guard
    # when the suite runs on native Windows.
    monkeypatch.setenv("FINDEVIL_CUSTODY_BOUNDARY", "reserved_case")
    monkeypatch.setattr("findevil_agent_mcp.custody_path_policy._is_native_windows", lambda: True)
    with pytest.raises(CustodyPathPolicyError, match="WSL2 or Docker"):
        enforce_tool_path_policy(
            "audit_verify", SimpleNamespace(path=str(tmp_path / "audit.jsonl"))
        )
