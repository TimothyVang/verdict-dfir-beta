"""Hash-chained append-only JSONL audit log.

Spec #2 §7.1 + invariant: every line embeds ``prev_hash`` linking to
the SHA-256 of the preceding line. Rewriting history breaks the
chain; the M2 crypto stack detects the break on verify.

Serialization uses the explicitly versioned VERDICT canonical JSON v1 form:
CPython JSON with sorted keys, tight separators, ASCII escapes, and finite
JSON numbers only. It is deterministic within the supported Python runtime but
is not RFC 8785/JCS (notably for floats and non-ASCII strings). The chain hashes
the exact serialized bytes; see ``docs/cryptographic-attestation.md``.

Design goals:

1. **Pure stdlib.** No sigstore, no network. Signing is a separate
   layer that reads this log as input.
2. **Crash-safe.** Every ``append`` fsyncs. If the writer crashes
   mid-line, the next writer detects a torn tail via hash mismatch
   and refuses to extend.
3. **Deterministic.** Given the same sequence of logical records,
   two writers produce byte-identical output files — important for
   reproducible CI runs and courtroom replay.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import stat
import threading
from collections.abc import Iterable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Canonicalization — VERDICT canonical JSON v1 (not RFC 8785/JCS).
#
# This intentionally preserves the long-standing CPython JSON wire format used
# by VERDICT. It is deterministic for the supported finite-JSON value domain,
# but it must not be described as the RFC 8785 JSON Canonicalization Scheme.
# ---------------------------------------------------------------------------

_CANONICAL_SEPARATORS = (",", ":")
_PATH_LOCKS_GUARD = threading.Lock()
_PATH_LOCKS: dict[str, threading.Lock] = {}
MAX_AUDIT_LOG_BYTES = 128 * 1024 * 1024
MAX_AUDIT_RECORD_BYTES = 4 * 1024 * 1024
MAX_AUDIT_RECORDS = 250_000
MAX_AUDIT_KIND_CHARS = 128
MAX_AUDIT_TIMESTAMP_CHARS = 64
MAX_AUDIT_JSON_DEPTH = 32
MAX_AUDIT_JSON_NODES = 100_000
MAX_AUDIT_JSON_CONTAINER_ITEMS = 50_000
MAX_AUDIT_JSON_STRING_CHARS = 2 * 1024 * 1024
MAX_AUDIT_JSON_TOTAL_STRING_CHARS = 4 * 1024 * 1024
MAX_AUDIT_JSON_KEY_CHARS = 1_024
_TAIL_READ_CHUNK_BYTES = 64 * 1024


def _shared_path_lock(path: Path) -> threading.Lock:
    """Return one process-wide writer lock for a canonical audit path."""
    key = os.fspath(path)
    with _PATH_LOCKS_GUARD:
        lock = _PATH_LOCKS.get(key)
        if lock is None:
            lock = threading.Lock()
            _PATH_LOCKS[key] = lock
        return lock


def canonicalize_json(obj: Any) -> bytes:
    """Return VERDICT canonical JSON v1 bytes for ``obj``.

    ``sort_keys=True`` + tightest separators + UTF-8 + escape
    non-ASCII to ``\\uXXXX``. Two logically-equal Python dicts
    produce byte-identical output regardless of key-insertion order.
    """
    return json.dumps(
        obj,
        sort_keys=True,
        separators=_CANONICAL_SEPARATORS,
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def hash_line(line: bytes) -> str:
    """SHA-256 of a full JSONL line (without the trailing newline)."""
    h = hashlib.sha256()
    h.update(line.rstrip(b"\n"))
    return h.hexdigest()


# ---------------------------------------------------------------------------
# Record shape.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AuditRecord:
    """One line of the audit log before hashing.

    ``seq`` is 0-based and monotonic. ``prev_hash`` is the SHA-256
    of the preceding line (empty string for the first record). The
    ``payload`` dict is the domain-specific event body — tool calls,
    findings, contradictions, etc.
    """

    seq: int
    ts: str  # UTC ISO-8601Z
    kind: str
    prev_hash: str
    payload: dict[str, Any]

    def to_canonical_dict(self) -> dict[str, Any]:
        """Dict shape written to disk. Field order matters for audit readability
        but doesn't affect hashing because VERDICT canonical JSON v1 sorts keys.
        """
        return {
            "seq": self.seq,
            "ts": self.ts,
            "kind": self.kind,
            "prev_hash": self.prev_hash,
            "payload": self.payload,
        }


@dataclass(frozen=True)
class AuditLogSnapshot:
    """One chain-verified immutable audit snapshot used for terminal sealing."""

    path: Path
    records: tuple[AuditRecord, ...]

    def iter_records(self) -> Iterable[AuditRecord]:
        yield from self.records


# ---------------------------------------------------------------------------
# AuditLog — the writer + reader.
# ---------------------------------------------------------------------------


class AuditLogError(RuntimeError):
    """Raised when the chain invariant is violated."""


class AuditLog:
    """Append-only hash-chained JSONL log.

    Usage:
        log = AuditLog(Path("~/.findevil/cases/<id>/audit.jsonl"))
        log.append("tool_call_start", {"tool": "evtx_query", ...})
        log.append("finding", {"tool_call_id": "tc-1", ...})
        log.verify()  # replays chain; raises AuditLogError on break
    """

    def __init__(self, path: Path) -> None:
        self.path = Path(os.path.abspath(Path(path).expanduser()))
        self._lock = _shared_path_lock(self.path)
        self._next_seq = 0
        self._last_hash = ""
        with self._lock:
            self._prepare_private_path()
            self._load_tail()

    @staticmethod
    def _validate_file_metadata(metadata: os.stat_result) -> None:
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise AuditLogError("audit log must be one non-hard-linked regular file")
        if os.name == "posix" and metadata.st_uid != os.geteuid():
            raise AuditLogError("audit log is not owned by the current user")
        if metadata.st_size > MAX_AUDIT_LOG_BYTES:
            raise AuditLogError(f"audit-log size limit exceeded ({MAX_AUDIT_LOG_BYTES} bytes)")

    def _prepare_private_path(self) -> None:
        parent = self.path.parent
        parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        parent_metadata = os.lstat(parent)
        if stat.S_ISLNK(parent_metadata.st_mode) or not stat.S_ISDIR(parent_metadata.st_mode):
            raise AuditLogError("audit-log parent is not a real directory")
        if os.name == "posix":
            if parent_metadata.st_uid != os.geteuid():
                raise AuditLogError("audit-log parent is not owned by this user")
            os.chmod(parent, 0o700)
        try:
            metadata = os.lstat(self.path)
        except FileNotFoundError:
            return
        self._validate_file_metadata(metadata)
        if os.name == "posix":
            os.chmod(self.path, 0o600)

    def _open_read(self) -> Any:
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(self.path, flags)
        except OSError as exc:
            raise AuditLogError(f"cannot safely open audit log: {exc}") from exc
        try:
            self._validate_file_metadata(os.fstat(descriptor))
        except Exception:
            os.close(descriptor)
            raise
        return os.fdopen(descriptor, "rb")

    @staticmethod
    def _lock_descriptor(descriptor: int, *, exclusive: bool) -> None:
        """Take an advisory process lock where the platform supports it."""
        if os.name == "posix":
            import fcntl

            operation = fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH
            fcntl.flock(descriptor, operation)

    @staticmethod
    def _unlock_descriptor(descriptor: int) -> None:
        if os.name == "posix":
            import fcntl

            fcntl.flock(descriptor, fcntl.LOCK_UN)

    # ------------------------------------------------------------------
    # Construction-time tail load.
    # ------------------------------------------------------------------

    def _load_tail(self) -> None:
        """Populate ``_next_seq`` + ``_last_hash`` from any existing file."""
        self._next_seq = 0
        self._last_hash = ""
        if not self.path.is_file():
            return
        with self._open_read() as f:
            self._lock_descriptor(f.fileno(), exclusive=False)
            try:
                self._load_tail_from_descriptor(f.fileno())
            finally:
                self._unlock_descriptor(f.fileno())

    def _load_tail_from_descriptor(self, descriptor: int) -> None:
        """Reload state from only the bounded final record under the file lock."""
        self._next_seq = 0
        self._last_hash = ""
        last_line = _read_final_record_line(descriptor)
        if last_line is None:
            return
        try:
            obj = json.loads(last_line)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise AuditLogError(
                f"audit log {self.path}: last line is not valid JSON: {exc}"
            ) from exc
        if not isinstance(obj, dict) or "seq" not in obj:
            raise AuditLogError(f"audit log {self.path}: last line is not an audit record")
        if canonicalize_json(obj) != last_line:
            raise AuditLogError(f"audit log {self.path}: last line is not in canonical form")
        seq = obj["seq"]
        if type(seq) is not int or seq < 0:
            raise AuditLogError(f"audit log {self.path}: last line has an invalid seq")
        self._next_seq = seq + 1
        if self._next_seq > MAX_AUDIT_RECORDS:
            raise AuditLogError(f"audit-log record limit exceeded ({MAX_AUDIT_RECORDS})")
        self._last_hash = hash_line(last_line)

    # ------------------------------------------------------------------
    # Writer.
    # ------------------------------------------------------------------

    def append(self, kind: str, payload: dict[str, Any], *, ts: str | None = None) -> AuditRecord:
        """Append one record. Thread-safe. fsyncs before returning."""
        _validate_append_input(kind=kind, payload=payload, ts=ts)
        with self._lock:
            self._prepare_private_path()
            flags = os.O_RDWR | os.O_APPEND | os.O_CREAT | getattr(os, "O_BINARY", 0)
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            descriptor = os.open(self.path, flags, 0o600)
            try:
                self._validate_file_metadata(os.fstat(descriptor))
                if hasattr(os, "fchmod"):
                    os.fchmod(descriptor, 0o600)
                self._lock_descriptor(descriptor, exclusive=True)
                self._load_tail_from_descriptor(descriptor)
                if self._next_seq >= MAX_AUDIT_RECORDS:
                    raise AuditLogError(f"audit-log record limit exceeded ({MAX_AUDIT_RECORDS})")
                record = AuditRecord(
                    seq=self._next_seq,
                    ts=ts or _utc_iso(),
                    kind=kind,
                    prev_hash=self._last_hash,
                    payload=payload,
                )
                line = canonicalize_json(record.to_canonical_dict())
                if len(line) > MAX_AUDIT_RECORD_BYTES:
                    raise AuditLogError(
                        f"audit record size limit exceeded ({MAX_AUDIT_RECORD_BYTES} bytes)"
                    )
                current_size = os.fstat(descriptor).st_size
                if current_size + len(line) + 1 > MAX_AUDIT_LOG_BYTES:
                    raise AuditLogError(
                        f"audit log size limit exceeded ({MAX_AUDIT_LOG_BYTES} bytes)"
                    )
                pending = memoryview(line + b"\n")
                while pending:
                    written = os.write(descriptor, pending)
                    if written <= 0:
                        raise AuditLogError("audit log append made no forward progress")
                    pending = pending[written:]
                os.fsync(descriptor)
            finally:
                try:
                    self._unlock_descriptor(descriptor)
                finally:
                    os.close(descriptor)
            self._last_hash = hash_line(line)
            self._next_seq += 1
            return record

    # ------------------------------------------------------------------
    # Reader / verifier.
    # ------------------------------------------------------------------

    def iter_records(self) -> Iterable[AuditRecord]:
        """Yield each record in order, without verifying."""
        records: list[AuditRecord] = []
        with self._lock:
            if not self.path.is_file():
                return
            with self._open_read() as f:
                self._lock_descriptor(f.fileno(), exclusive=False)
                try:
                    for raw in _bounded_audit_lines(f):
                        raw = raw.rstrip(b"\n")
                        if not raw:
                            continue
                        try:
                            obj = json.loads(raw)
                        except json.JSONDecodeError as exc:
                            raise AuditLogError(f"line is not valid JSON: {exc}") from exc
                        records.append(
                            AuditRecord(
                                seq=int(obj["seq"]),
                                ts=str(obj["ts"]),
                                kind=str(obj["kind"]),
                                prev_hash=str(obj["prev_hash"]),
                                payload=obj.get("payload") or {},
                            )
                        )
                finally:
                    self._unlock_descriptor(f.fileno())
        yield from records

    def verify(self) -> int:
        """Replay the chain. Returns the record count. Raises on break.

        Checks:
          * seq is monotonic starting at 0
          * each record's prev_hash equals SHA-256 of the previous
            line's exact bytes
          * canonicalization round-trip matches the on-disk line
        """
        with self._lock:
            if not self.path.is_file():
                return 0
            with self._open_read() as f:
                self._lock_descriptor(f.fileno(), exclusive=False)
                try:
                    records = self._read_verified_records(f)
                finally:
                    self._unlock_descriptor(f.fileno())
            return len(records)

    @contextmanager
    def verified_snapshot(self) -> Iterator[AuditLogSnapshot]:
        """Hold shared writer/file locks while yielding a verified snapshot.

        Terminal manifest derivation uses the returned immutable records, so
        separate validation/leaf/signing passes cannot observe different log
        versions. The shared descriptor lock also blocks cooperating appenders
        until the signed manifest body has been derived.
        """
        with self._lock:
            if not self.path.is_file():
                yield AuditLogSnapshot(path=self.path, records=())
                return
            with self._open_read() as f:
                self._lock_descriptor(f.fileno(), exclusive=False)
                try:
                    records = self._read_verified_records(f)
                    yield AuditLogSnapshot(path=self.path, records=records)
                finally:
                    self._unlock_descriptor(f.fileno())

    @classmethod
    def read_verified_snapshot(cls, path: Path) -> AuditLogSnapshot:
        """Verify an existing audit log without creating or chmodding paths.

        ``AuditLog`` construction prepares a private writable path, which is
        appropriate for the recorder but not for a verifier. This entry point
        opens one existing non-linked regular file read-only and confirms its
        descriptor/path identity remained stable across the bounded replay.
        """
        audit_path = Path(os.path.abspath(Path(path).expanduser()))
        path_lock = _shared_path_lock(audit_path)
        with path_lock:
            try:
                path_before = os.lstat(audit_path)
            except OSError as exc:
                raise AuditLogError(f"cannot inspect audit log safely: {exc}") from exc
            if stat.S_ISLNK(path_before.st_mode):
                raise AuditLogError("audit log must not be a symlink")
            cls._validate_file_metadata(path_before)

            flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_BINARY", 0)
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            try:
                descriptor = os.open(audit_path, flags)
            except OSError as exc:
                raise AuditLogError(f"cannot safely open audit log: {exc}") from exc
            try:
                before = os.fstat(descriptor)
                cls._validate_file_metadata(before)
                with os.fdopen(descriptor, "rb", closefd=False) as stream:
                    cls._lock_descriptor(descriptor, exclusive=False)
                    try:
                        records = cls._read_verified_records(stream)
                    finally:
                        cls._unlock_descriptor(descriptor)
                after = os.fstat(descriptor)
                cls._validate_file_metadata(after)
            finally:
                os.close(descriptor)

            try:
                path_after = os.lstat(audit_path)
            except OSError as exc:
                raise AuditLogError(f"audit-log path changed while reading: {exc}") from exc
            if stat.S_ISLNK(path_after.st_mode):
                raise AuditLogError("audit-log path changed while reading")
            cls._validate_file_metadata(path_after)
            stable_fields = (
                "st_mode",
                "st_nlink",
                "st_dev",
                "st_ino",
                "st_size",
                "st_mtime_ns",
                "st_ctime_ns",
            )

            def _identity(metadata: os.stat_result) -> tuple[Any, ...]:
                return tuple(getattr(metadata, field) for field in stable_fields)

            # The open descriptor must not have changed across the bounded read,
            # and the path entry must not have been swapped underneath it. These
            # are compared *within* each stat flavor (fd-vs-fd, path-vs-path):
            # Windows populates st_ino/st_nlink/st_*time_ns differently through
            # fstat than through lstat, so a cross-flavor equality check
            # false-positives there even with no concurrent writer.
            if _identity(before) != _identity(after):
                raise AuditLogError("audit log changed while it was being read")
            if _identity(path_before) != _identity(path_after):
                raise AuditLogError("audit log changed while it was being read")
            # On POSIX the descriptor and the path must additionally resolve to
            # the same underlying file (device + inode + size + type). Windows'
            # fstat/lstat device/inode reporting is not comparable across
            # flavors, so this cross-flavor check is POSIX-only.
            if os.name != "nt" and _identity(before) != _identity(path_before):
                raise AuditLogError("audit log changed while it was being read")
            return AuditLogSnapshot(path=audit_path, records=records)

    @staticmethod
    def _read_verified_records(stream: Any) -> tuple[AuditRecord, ...]:
        records: list[AuditRecord] = []
        prev_hash = ""
        for raw_line in _bounded_audit_lines(stream):
            if not raw_line.endswith(b"\n"):
                raise AuditLogError("audit log has a torn tail (missing final newline)")
            raw = raw_line[:-1]
            if not raw:
                raise AuditLogError(
                    f"seq {len(records)}: audit log contains an empty physical record"
                )
            count = len(records)
            if count >= MAX_AUDIT_RECORDS:
                raise AuditLogError(f"audit-log record limit exceeded ({MAX_AUDIT_RECORDS})")
            try:
                obj = json.loads(raw)
            except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                raise AuditLogError(f"seq {count}: line is not valid JSON: {exc}") from exc
            if not isinstance(obj, dict):
                raise AuditLogError(f"seq {count}: not a JSON object")
            seq = obj.get("seq")
            if seq != count:
                raise AuditLogError(f"seq {count}: expected seq={count}, got seq={seq}")
            declared = obj.get("prev_hash")
            if declared != prev_hash:
                raise AuditLogError(
                    f"seq {count}: prev_hash break (declared={declared!r}, expected={prev_hash!r})"
                )
            canonical = canonicalize_json(obj)
            if canonical != raw:
                raise AuditLogError(f"seq {count}: line is not in canonical form")
            payload = obj.get("payload") or {}
            if not isinstance(payload, dict):
                raise AuditLogError(f"seq {count}: payload is not a JSON object")
            records.append(
                AuditRecord(
                    seq=count,
                    ts=str(obj.get("ts") or ""),
                    kind=str(obj.get("kind") or ""),
                    prev_hash=str(declared or ""),
                    payload=payload,
                )
            )
            prev_hash = hash_line(raw)
        return tuple(records)

    # ------------------------------------------------------------------
    # Public inspection.
    # ------------------------------------------------------------------

    @property
    def next_seq(self) -> int:
        return self._next_seq

    @property
    def last_hash(self) -> str:
        return self._last_hash


def _utc_iso() -> str:
    from datetime import UTC, datetime

    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _bounded_audit_lines(stream: Any) -> Iterable[bytes]:
    """Yield audit lines while refusing a single allocation above the line cap."""
    total_bytes = 0
    while True:
        raw = stream.readline(MAX_AUDIT_RECORD_BYTES + 2)
        if not raw:
            return
        total_bytes += len(raw)
        if total_bytes > MAX_AUDIT_LOG_BYTES:
            raise AuditLogError(f"audit-log size limit exceeded ({MAX_AUDIT_LOG_BYTES} bytes)")
        line_length = len(raw) - (1 if raw.endswith(b"\n") else 0)
        if line_length > MAX_AUDIT_RECORD_BYTES:
            raise AuditLogError(
                f"audit record size limit exceeded ({MAX_AUDIT_RECORD_BYTES} bytes)"
            )
        yield raw


def _read_final_record_line(descriptor: int) -> bytes | None:
    """Read only the final complete JSONL record, bounded by the line cap."""
    size = os.fstat(descriptor).st_size
    if size == 0:
        return None

    os.lseek(descriptor, size - 1, os.SEEK_SET)
    if os.read(descriptor, 1) != b"\n":
        raise AuditLogError("audit log has a torn tail (missing final newline)")

    position = size - 1
    pieces: list[bytes] = []
    line_bytes = 0
    while position > 0:
        read_size = min(_TAIL_READ_CHUNK_BYTES, position)
        position -= read_size
        os.lseek(descriptor, position, os.SEEK_SET)
        chunk = os.read(descriptor, read_size)
        if len(chunk) != read_size:
            raise AuditLogError("audit log tail read made incomplete progress")
        separator = chunk.rfind(b"\n")
        fragment = chunk[separator + 1 :] if separator >= 0 else chunk
        line_bytes += len(fragment)
        if line_bytes > MAX_AUDIT_RECORD_BYTES:
            raise AuditLogError(
                f"audit record size limit exceeded ({MAX_AUDIT_RECORD_BYTES} bytes)"
            )
        pieces.append(fragment)
        if separator >= 0:
            break

    line = b"".join(reversed(pieces))
    if not line:
        raise AuditLogError("audit log has an empty final record")
    return line


def _validate_append_input(*, kind: object, payload: object, ts: object) -> None:
    if not isinstance(kind, str) or not kind:
        raise AuditLogError("audit kind must be a non-empty string")
    if len(kind) > MAX_AUDIT_KIND_CHARS:
        raise AuditLogError(f"audit kind exceeds limit {MAX_AUDIT_KIND_CHARS}")
    if not isinstance(payload, Mapping):
        raise AuditLogError("audit payload must be a JSON object")
    if ts is not None:
        if not isinstance(ts, str) or not ts:
            raise AuditLogError("audit timestamp must be a non-empty string")
        if len(ts) > MAX_AUDIT_TIMESTAMP_CHARS:
            raise AuditLogError(f"audit timestamp exceeds limit {MAX_AUDIT_TIMESTAMP_CHARS}")
    _validate_payload_budget(payload)


def _validate_payload_budget(payload: object) -> None:
    stack: list[tuple[object, int]] = [(payload, 0)]
    seen_containers: set[int] = set()
    nodes = 0
    total_string_chars = 0
    while stack:
        current, depth = stack.pop()
        nodes += 1
        if nodes > MAX_AUDIT_JSON_NODES:
            raise AuditLogError(f"audit payload JSON node limit exceeded ({MAX_AUDIT_JSON_NODES})")
        if depth > MAX_AUDIT_JSON_DEPTH:
            raise AuditLogError(
                f"audit payload JSON nesting depth limit exceeded ({MAX_AUDIT_JSON_DEPTH})"
            )
        if isinstance(current, str):
            if len(current) > MAX_AUDIT_JSON_STRING_CHARS:
                raise AuditLogError(
                    "audit payload JSON string length limit exceeded "
                    f"({MAX_AUDIT_JSON_STRING_CHARS})"
                )
            total_string_chars += len(current)
        elif isinstance(current, Mapping):
            identity = id(current)
            if identity in seen_containers:
                raise AuditLogError("audit payload contains a cyclic mapping")
            seen_containers.add(identity)
            if len(current) > MAX_AUDIT_JSON_CONTAINER_ITEMS:
                raise AuditLogError(
                    "audit payload JSON mapping item limit exceeded "
                    f"({MAX_AUDIT_JSON_CONTAINER_ITEMS})"
                )
            for key, child in current.items():
                if not isinstance(key, str):
                    raise AuditLogError("audit payload JSON mapping keys must be strings")
                if len(key) > MAX_AUDIT_JSON_KEY_CHARS:
                    raise AuditLogError(
                        f"audit payload JSON key length limit exceeded ({MAX_AUDIT_JSON_KEY_CHARS})"
                    )
                total_string_chars += len(key)
                stack.append((child, depth + 1))
        elif isinstance(current, list | tuple):
            identity = id(current)
            if identity in seen_containers:
                raise AuditLogError("audit payload contains a cyclic sequence")
            seen_containers.add(identity)
            if len(current) > MAX_AUDIT_JSON_CONTAINER_ITEMS:
                raise AuditLogError(
                    "audit payload JSON sequence item limit exceeded "
                    f"({MAX_AUDIT_JSON_CONTAINER_ITEMS})"
                )
            stack.extend((child, depth + 1) for child in current)
        elif current is None or isinstance(current, bool | int):
            pass
        elif isinstance(current, float):
            if not math.isfinite(current):
                raise AuditLogError("audit payload JSON numbers must be finite")
        else:
            raise AuditLogError(
                f"audit payload contains non-JSON value of type {type(current).__name__}"
            )
        if total_string_chars > MAX_AUDIT_JSON_TOTAL_STRING_CHARS:
            raise AuditLogError(
                "audit payload aggregate string limit exceeded "
                f"({MAX_AUDIT_JSON_TOTAL_STRING_CHARS})"
            )
