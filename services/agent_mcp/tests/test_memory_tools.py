"""Tests for memory_remember + memory_recall MCP tools (A3 §2.2)."""

from pathlib import Path

import pytest
from findevil_agent.crypto.audit_log import AuditLog
from findevil_agent.crypto.manifest import build_manifest
from findevil_agent.crypto.signer import StubSigner
from pydantic import ValidationError

from findevil_agent_mcp.tools.memory_recall import (
    SPEC as RECALL_SPEC,
)
from findevil_agent_mcp.tools.memory_recall import (
    MemoryRecallInput,
)
from findevil_agent_mcp.tools.memory_remember import (
    SPEC as REMEMBER_SPEC,
)
from findevil_agent_mcp.tools.memory_remember import (
    MemoryRememberInput,
)


async def _seed_one(db: Path) -> None:
    """Seed a single recallable row so recall returns a hit."""
    await REMEMBER_SPEC.handler(
        MemoryRememberInput(
            store_path=str(db),
            case_id="case-seed",
            kind="ioc",
            key="evil.example",
            value="evil.example c2 domain",
            sha256="sha256:" + "a" * 64,
        )
    )


class TestMemoryRecallAuditChaining:
    """memory_recall logs that recall happened (provenance) — never evidence."""

    @pytest.mark.asyncio
    async def test_recall_appends_memory_recall_record(self, tmp_path: Path) -> None:
        db, audit = tmp_path / "memory.sqlite", tmp_path / "audit.jsonl"
        await _seed_one(db)
        await RECALL_SPEC.handler(
            MemoryRecallInput(store_path=str(db), query="evil", limit=5, audit_log_path=str(audit))
        )
        records = [r for r in AuditLog(audit).iter_records() if r.kind == "memory_recall"]
        assert len(records) == 1
        # First record on a fresh chain links to the empty prev_hash.
        assert records[0].prev_hash == ""

    @pytest.mark.asyncio
    async def test_recall_record_is_not_a_merkle_leaf(self, tmp_path: Path) -> None:
        # G3: memory provenance is in the audit chain but never an evidence leaf.
        db, audit = tmp_path / "memory.sqlite", tmp_path / "audit.jsonl"
        await _seed_one(db)
        await RECALL_SPEC.handler(
            MemoryRecallInput(store_path=str(db), query="evil", audit_log_path=str(audit))
        )
        manifest = build_manifest(
            case_id="c-1",
            run_id="r-1",
            started_at="2026-01-01T00:00:00Z",
            audit_log=AuditLog(audit),
            signer=StubSigner(run_id="r-1"),
        )
        assert manifest.leaf_count == 0
        assert all(leaf.kind != "memory_recall" for leaf in manifest.leaves)

    @pytest.mark.asyncio
    async def test_recall_payload_has_no_tool_call_id(self, tmp_path: Path) -> None:
        # A recall record must never be mistaken for tool-call evidence.
        db, audit = tmp_path / "memory.sqlite", tmp_path / "audit.jsonl"
        await _seed_one(db)
        await RECALL_SPEC.handler(
            MemoryRecallInput(store_path=str(db), query="evil", audit_log_path=str(audit))
        )
        rec = next(r for r in AuditLog(audit).iter_records() if r.kind == "memory_recall")
        assert "tool_call_id" not in rec.payload
        assert rec.payload["hit_count"] >= 1

    @pytest.mark.asyncio
    async def test_recall_without_audit_path_writes_no_chain(self, tmp_path: Path) -> None:
        db, audit = tmp_path / "memory.sqlite", tmp_path / "audit.jsonl"
        await _seed_one(db)
        out = await RECALL_SPEC.handler(MemoryRecallInput(store_path=str(db), query="evil"))
        assert len(out.hits) == 1
        assert not audit.exists()  # no audit_log_path -> no chain writes


@pytest.mark.asyncio
async def test_memory_remember_writes_row(tmp_path: Path) -> None:
    db = tmp_path / "memory.sqlite"
    inp = MemoryRememberInput(
        store_path=str(db),
        case_id="case-001",
        kind="hash",
        key="evil.exe",
        value="evil.exe sha=abc",
        sha256="sha256:" + "a" * 64,
    )
    out = await REMEMBER_SPEC.handler(inp)
    assert out.case_id == "case-001"
    assert out.kind == "hash"
    assert db.exists()


@pytest.mark.asyncio
async def test_memory_recall_returns_remembered_row(tmp_path: Path) -> None:
    db = tmp_path / "memory.sqlite"
    # Seed via the remember tool.
    await REMEMBER_SPEC.handler(
        MemoryRememberInput(
            store_path=str(db),
            case_id="case-recall-1",
            kind="ioc",
            key="badguy.example",
            value="badguy.example c2 domain",
            sha256="sha256:" + "f" * 64,
        )
    )
    # Recall.
    out = await RECALL_SPEC.handler(MemoryRecallInput(store_path=str(db), query="badguy", limit=5))
    assert len(out.hits) == 1
    assert out.hits[0].case_id == "case-recall-1"
    assert out.hits[0].confidence > 0.0


# Explicit short ids keep the giant field values out of the test nodeid. pytest
# writes the nodeid into PYTEST_CURRENT_TEST, and Windows rejects an environment
# variable longer than 32767 chars, so an auto-generated id built from the
# 65537-char "value" case would fail at setup on native Windows.
@pytest.mark.parametrize(
    ("field", "value"),
    [
        pytest.param("case_id", "c" * 129, id="case_id-too-long"),
        pytest.param("kind", "not-a-memory-kind", id="kind-invalid"),
        pytest.param("key", "k" * 4097, id="key-too-long"),
        pytest.param("value", "v" * 65_537, id="value-too-long"),
        pytest.param("case_path", "p" * 4097, id="case_path-too-long"),
    ],
)
def test_memory_remember_rejects_oversized_or_invalid_fields(field: str, value: str) -> None:
    payload = {
        "store_path": "/tmp/memory.sqlite",
        "case_id": "case-1",
        "kind": "ioc",
        "key": "evil.example",
        "value": "evil.example",
        "sha256": "sha256:" + "a" * 64,
        field: value,
    }
    with pytest.raises(ValidationError):
        MemoryRememberInput.model_validate(payload)


def test_memory_recall_rejects_oversized_query_and_paths() -> None:
    with pytest.raises(ValidationError):
        MemoryRecallInput(store_path="/tmp/memory.sqlite", query="q" * 4097)
    with pytest.raises(ValidationError):
        MemoryRecallInput(store_path="s" * 4097, query="q")
    with pytest.raises(ValidationError):
        MemoryRecallInput(store_path="/tmp/memory.sqlite", query="q", audit_log_path="a" * 4097)


class TestMemoryRememberAuditChaining:
    """memory_remember logs that a write happened (provenance) — never evidence."""

    async def _remember(self, db: Path, audit: Path | None) -> None:
        await REMEMBER_SPEC.handler(
            MemoryRememberInput(
                store_path=str(db),
                case_id="case-001",
                kind="hash",
                key="evil.exe",
                value="evil.exe sha=abc",
                sha256="sha256:" + "a" * 64,
                audit_log_path=str(audit) if audit is not None else None,
            )
        )

    @pytest.mark.asyncio
    async def test_remember_appends_memory_remember_record(self, tmp_path: Path) -> None:
        db, audit = tmp_path / "memory.sqlite", tmp_path / "audit.jsonl"
        await self._remember(db, audit)
        records = [r for r in AuditLog(audit).iter_records() if r.kind == "memory_remember"]
        assert len(records) == 1
        assert records[0].prev_hash == ""

    @pytest.mark.asyncio
    async def test_remember_record_is_not_a_merkle_leaf(self, tmp_path: Path) -> None:
        # G3: a remember record is hash-chained provenance, never an evidence leaf.
        db, audit = tmp_path / "memory.sqlite", tmp_path / "audit.jsonl"
        await self._remember(db, audit)
        manifest = build_manifest(
            case_id="c-1",
            run_id="r-1",
            started_at="2026-01-01T00:00:00Z",
            audit_log=AuditLog(audit),
            signer=StubSigner(run_id="r-1"),
        )
        assert manifest.leaf_count == 0
        assert all(leaf.kind != "memory_remember" for leaf in manifest.leaves)

    @pytest.mark.asyncio
    async def test_remember_payload_shape(self, tmp_path: Path) -> None:
        db, audit = tmp_path / "memory.sqlite", tmp_path / "audit.jsonl"
        await self._remember(db, audit)
        rec = next(r for r in AuditLog(audit).iter_records() if r.kind == "memory_remember")
        assert set(rec.payload) == {"case_id", "kind", "key", "sha256"}
        assert "tool_call_id" not in rec.payload

    @pytest.mark.asyncio
    async def test_remember_without_audit_path_writes_no_chain(self, tmp_path: Path) -> None:
        db, audit = tmp_path / "memory.sqlite", tmp_path / "audit.jsonl"
        await self._remember(db, None)
        assert not audit.exists()
