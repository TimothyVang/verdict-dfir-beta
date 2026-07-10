"""Cross-case memory store backed by SQLite FTS5.

Schema and confidence formula: see Amendment A3 §2.4. Designed for
single-machine, single-thread callers; the underlying
sqlite3.Connection raises ProgrammingError if shared across threads
(`check_same_thread=True` is the Python default and we keep it).
Cross-process writers to the same file serialize on the default
sqlite3 file lock.
"""

from __future__ import annotations

import math
import os
import re
import sqlite3
import stat
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

_HALF_LIFE_DAYS = 90.0
MAX_MEMORY_STORE_BYTES = 64 * 1024 * 1024
MAX_MEMORY_ROWS = 100_000
MAX_CASE_ID_CHARS = 128
MAX_KIND_CHARS = 32
MAX_KEY_CHARS = 4_096
MAX_VALUE_CHARS = 65_536
MAX_CASE_PATH_CHARS = 4_096
MAX_QUERY_CHARS = 4_096
MAX_RECALL_LIMIT = 100
_ALLOWED_KINDS = frozenset({"ioc", "hash", "ttp", "hostname", "finding_summary"})
_SHA256_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")


class MemoryStoreLimitError(ValueError):
    """A memory-store operation exceeded a reviewed persistent/input budget."""


@dataclass(frozen=True)
class RecallHit:
    case_id: str
    kind: str
    key: str
    value: str
    sha256: str
    ts: str
    confidence: float


class MemoryStore:
    def __init__(self, path: Path) -> None:
        self.path = Path(os.path.abspath(path.expanduser()))
        self._prepare_private_path()
        self._conn = sqlite3.connect(str(self.path))
        try:
            if os.name == "posix":
                os.chmod(self.path, 0o600)
            self._conn.row_factory = sqlite3.Row
            self._configure_persistent_quota()
            self._init_schema()
        except Exception:
            self._conn.close()
            raise

    def _prepare_private_path(self) -> None:
        parent = self.path.parent
        parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        parent_metadata = os.lstat(parent)
        if stat.S_ISLNK(parent_metadata.st_mode) or not stat.S_ISDIR(parent_metadata.st_mode):
            raise PermissionError("memory-store parent is not a real directory")
        if os.name == "posix":
            if parent_metadata.st_uid != os.geteuid():
                raise PermissionError("memory-store parent is not owned by this user")
            os.chmod(parent, 0o700)
        try:
            metadata = os.lstat(self.path)
        except FileNotFoundError:
            return
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise PermissionError("memory store must be one non-hard-linked regular file")
        if metadata.st_size > MAX_MEMORY_STORE_BYTES:
            raise MemoryStoreLimitError(
                f"memory-store size limit exceeded ({MAX_MEMORY_STORE_BYTES} bytes)"
            )
        if os.name == "posix":
            if metadata.st_uid != os.geteuid():
                raise PermissionError("memory store is not owned by this user")
            os.chmod(self.path, 0o600)

    def _configure_persistent_quota(self) -> None:
        page_size_row = self._conn.execute("PRAGMA page_size").fetchone()
        page_count_row = self._conn.execute("PRAGMA page_count").fetchone()
        if page_size_row is None or page_count_row is None:
            raise MemoryStoreLimitError("cannot determine memory-store page budget")
        page_size = int(page_size_row[0])
        page_count = int(page_count_row[0])
        max_pages = max(1, MAX_MEMORY_STORE_BYTES // page_size)
        if page_count > max_pages:
            raise MemoryStoreLimitError(
                f"memory-store size limit exceeded ({MAX_MEMORY_STORE_BYTES} bytes)"
            )
        applied_row = self._conn.execute(f"PRAGMA max_page_count={max_pages}").fetchone()
        if applied_row is None or int(applied_row[0]) > max_pages:
            raise MemoryStoreLimitError("cannot apply memory-store persistent size limit")

    def _init_schema(self) -> None:
        self._conn.executescript(
            """
            CREATE VIRTUAL TABLE IF NOT EXISTS memories USING fts5(
                case_id UNINDEXED,
                kind,
                key,
                value,
                sha256 UNINDEXED,
                ts UNINDEXED,
                tokenize='porter unicode61'
            );
            CREATE TABLE IF NOT EXISTS meta (
                case_id TEXT PRIMARY KEY,
                case_path TEXT,
                first_seen_ts TEXT,
                last_updated_ts TEXT
            );
            """
        )
        self._conn.commit()

    def remember(
        self,
        *,
        case_id: str,
        kind: str,
        key: str,
        value: str,
        sha256: str,
        ts: str | None = None,
        case_path: str | None = None,
    ) -> None:
        _validate_remember_input(
            case_id=case_id,
            kind=kind,
            key=key,
            value=value,
            sha256=sha256,
            ts=ts,
            case_path=case_path,
        )
        row = self._conn.execute("SELECT count(*) FROM memories").fetchone()
        row_count = int(row[0]) if row is not None else 0
        if row_count >= MAX_MEMORY_ROWS:
            raise MemoryStoreLimitError(f"memory-store row limit exceeded ({MAX_MEMORY_ROWS})")
        now = ts or datetime.now(tz=UTC).isoformat().replace("+00:00", "Z")
        try:
            self._conn.execute(
                "INSERT INTO memories(case_id, kind, key, value, sha256, ts) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (case_id, kind, key, value, sha256, now),
            )
            self._conn.execute(
                "INSERT INTO meta(case_id, case_path, first_seen_ts, last_updated_ts) "
                "VALUES (?, ?, ?, ?) "
                "ON CONFLICT(case_id) DO UPDATE SET last_updated_ts=excluded.last_updated_ts, "
                "case_path=COALESCE(excluded.case_path, meta.case_path)",
                (case_id, case_path, now, now),
            )
            self._conn.commit()
        except sqlite3.DatabaseError as exc:
            self._conn.rollback()
            if "full" in str(exc).lower():
                raise MemoryStoreLimitError(
                    f"memory-store size limit exceeded ({MAX_MEMORY_STORE_BYTES} bytes)"
                ) from exc
            raise

    def recall(
        self,
        query: str,
        *,
        kind: str | None = None,
        limit: int = 10,
    ) -> list[RecallHit]:
        _require_bounded_string("query", query, MAX_QUERY_CHARS)
        if kind is not None and kind not in _ALLOWED_KINDS:
            raise MemoryStoreLimitError("kind is not an allowed memory kind")
        if (
            isinstance(limit, bool)
            or not isinstance(limit, int)
            or not 1 <= limit <= MAX_RECALL_LIMIT
        ):
            raise MemoryStoreLimitError(f"recall limit must be between 1 and {MAX_RECALL_LIMIT}")
        # FTS5 requires special characters (., @, -, etc.) to be phrase-quoted.
        fts_query = '"' + query.replace('"', '""') + '"'
        sql = (
            "SELECT case_id, kind, key, value, sha256, ts, "
            "       bm25(memories) AS score "
            "FROM memories "
            "WHERE memories MATCH ? "
        )
        params: list = [fts_query]
        if kind is not None:
            sql += "AND kind = ? "
            params.append(kind)
        # Fetch all candidates (up to limit) ordered by BM25 only; final sort
        # by combined confidence (relevance * decay) is done in Python below.
        sql += "ORDER BY score LIMIT ?"
        params.append(limit)

        now = datetime.now(tz=UTC)
        out: list[RecallHit] = []
        for row in self._conn.execute(sql, params):
            row_ts = datetime.fromisoformat(row["ts"].replace("Z", "+00:00"))
            days_old = max(0.0, (now - row_ts).total_seconds() / 86400.0)
            decay = math.exp(-days_old / _HALF_LIFE_DAYS)
            # bm25 returns negative scores in sqlite (lower = better);
            # invert so confidence rises with relevance.
            relevance = 1.0 / (1.0 + abs(row["score"]))
            out.append(
                RecallHit(
                    case_id=row["case_id"],
                    kind=row["kind"],
                    key=row["key"],
                    value=row["value"],
                    sha256=row["sha256"],
                    ts=row["ts"],
                    confidence=relevance * decay,
                )
            )
        # Re-rank by combined confidence descending so decay breaks BM25 ties.
        out.sort(key=lambda h: h.confidence, reverse=True)
        return out

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> MemoryStore:
        return self

    def __exit__(self, exc_type: object, exc_val: object, exc_tb: object) -> None:
        self.close()


def _require_bounded_string(name: str, value: object, max_chars: int) -> None:
    if not isinstance(value, str) or not value:
        raise MemoryStoreLimitError(f"{name} must be a non-empty string")
    if len(value) > max_chars:
        raise MemoryStoreLimitError(f"{name} exceeds limit {max_chars}")


def _validate_remember_input(
    *,
    case_id: str,
    kind: str,
    key: str,
    value: str,
    sha256: str,
    ts: str | None,
    case_path: str | None,
) -> None:
    _require_bounded_string("case_id", case_id, MAX_CASE_ID_CHARS)
    _require_bounded_string("kind", kind, MAX_KIND_CHARS)
    if kind not in _ALLOWED_KINDS:
        raise MemoryStoreLimitError("kind is not an allowed memory kind")
    _require_bounded_string("key", key, MAX_KEY_CHARS)
    _require_bounded_string("value", value, MAX_VALUE_CHARS)
    if not isinstance(sha256, str) or _SHA256_PATTERN.fullmatch(sha256) is None:
        raise MemoryStoreLimitError("sha256 must use lowercase sha256:<64-hex> form")
    if ts is not None:
        _require_bounded_string("ts", ts, 64)
    if case_path is not None:
        _require_bounded_string("case_path", case_path, MAX_CASE_PATH_CHARS)


__all__ = ["MemoryStore", "MemoryStoreLimitError", "RecallHit"]
