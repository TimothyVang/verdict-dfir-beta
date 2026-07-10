"""Round-trip + FTS5 ranking tests for MemoryStore."""

import os
import stat
from collections.abc import Iterator
from pathlib import Path

import pytest

from findevil_agent.memory import store as store_module
from findevil_agent.memory.store import MemoryStore, MemoryStoreLimitError


@pytest.fixture
def store(tmp_path: Path) -> Iterator[MemoryStore]:
    s = MemoryStore(tmp_path / "memory.sqlite")
    try:
        yield s
    finally:
        s.close()


def test_remember_then_recall_exact_hash(store: MemoryStore) -> None:
    store.remember(
        case_id="case-001",
        kind="hash",
        key="malicious.exe",
        value="abc123def456",
        sha256="sha256:abc123def456" + "0" * 52,
    )
    hits = store.recall("malicious.exe")
    assert len(hits) == 1
    assert hits[0].case_id == "case-001"
    assert hits[0].kind == "hash"
    assert hits[0].confidence > 0.0


def test_recall_ranks_by_bm25_then_decay(store: MemoryStore) -> None:
    store.remember(
        case_id="case-old",
        kind="ttp",
        key="T1059.001",
        value="powershell encoded command",
        sha256="sha256:" + "1" * 64,
        ts="2025-01-01T00:00:00Z",
    )
    store.remember(
        case_id="case-new",
        kind="ttp",
        key="T1059.001",
        value="powershell encoded command",
        sha256="sha256:" + "2" * 64,
        ts="2026-04-01T00:00:00Z",
    )
    hits = store.recall("powershell")
    assert len(hits) == 2
    assert hits[0].case_id == "case-new"
    assert hits[0].confidence > hits[1].confidence


def test_recall_filters_by_kind(store: MemoryStore) -> None:
    store.remember(
        case_id="c1", kind="ioc", key="evil.com", value="evil.com", sha256="sha256:" + "a" * 64
    )
    store.remember(
        case_id="c2", kind="hash", key="evil.com", value="evil.com", sha256="sha256:" + "b" * 64
    )
    hits = store.recall("evil.com", kind="ioc")
    assert len(hits) == 1
    assert hits[0].kind == "ioc"


@pytest.mark.skipif(os.name != "posix", reason="POSIX ownership/mode contract")
def test_store_migrates_owned_file_and_parent_to_owner_only(tmp_path: Path) -> None:
    parent = tmp_path / "memory"
    parent.mkdir(mode=0o775)
    path = parent / "memory.sqlite"
    first = MemoryStore(path)
    first.close()
    parent.chmod(0o775)
    path.chmod(0o664)

    reopened = MemoryStore(path)
    reopened.close()

    assert stat.S_IMODE(parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_store_refuses_hardlinked_database(tmp_path: Path) -> None:
    source = tmp_path / "source.sqlite"
    source.write_bytes(b"not trusted")
    alias = tmp_path / "alias.sqlite"
    os.link(source, alias)

    with pytest.raises(PermissionError, match="non-hard-linked"):
        MemoryStore(alias)


def test_store_refuses_existing_database_above_persistent_quota(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "memory.sqlite"
    with path.open("wb") as stream:
        stream.truncate(1025)
    monkeypatch.setattr(store_module, "MAX_MEMORY_STORE_BYTES", 1024)

    with pytest.raises(MemoryStoreLimitError, match="size limit"):
        MemoryStore(path)


def test_remember_refuses_row_after_persistent_row_quota(
    store: MemoryStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(store_module, "MAX_MEMORY_ROWS", 1)
    store.remember(
        case_id="case-1",
        kind="ioc",
        key="first.example",
        value="first.example",
        sha256="sha256:" + "a" * 64,
    )

    with pytest.raises(MemoryStoreLimitError, match="row limit"):
        store.remember(
            case_id="case-2",
            kind="ioc",
            key="second.example",
            value="second.example",
            sha256="sha256:" + "b" * 64,
        )


def test_direct_store_rejects_oversized_value_without_writing(store: MemoryStore) -> None:
    with pytest.raises(MemoryStoreLimitError, match="value"):
        store.remember(
            case_id="case-1",
            kind="ioc",
            key="evil.example",
            value="x" * 65_537,
            sha256="sha256:" + "a" * 64,
        )
    assert store.recall("evil") == []


def test_direct_recall_rejects_oversized_query_and_limit(store: MemoryStore) -> None:
    with pytest.raises(MemoryStoreLimitError, match="query"):
        store.recall("x" * 4097)
    with pytest.raises(MemoryStoreLimitError, match="limit"):
        store.recall("evil", limit=101)
