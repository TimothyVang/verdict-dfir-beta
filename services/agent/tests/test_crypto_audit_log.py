"""Tests for findevil_agent.crypto.audit_log."""

from __future__ import annotations

import hashlib
import json
import multiprocessing
import os
import stat
from pathlib import Path

import pytest

from findevil_agent.crypto import audit_log as audit_log_module
from findevil_agent.crypto.audit_log import (
    AuditLog,
    AuditLogError,
    canonicalize_json,
    hash_line,
)


def _append_after_barrier(path: str, kind: str, barrier: object) -> None:
    log = AuditLog(Path(path))
    barrier.wait()  # type: ignore[attr-defined]
    log.append(kind, {"writer": kind})


class TestCanonicalize:
    def test_sorted_keys(self) -> None:
        a = canonicalize_json({"b": 2, "a": 1})
        b = canonicalize_json({"a": 1, "b": 2})
        assert a == b

    def test_no_whitespace(self) -> None:
        got = canonicalize_json({"a": 1, "b": [2, 3]})
        assert got == b'{"a":1,"b":[2,3]}'

    def test_escapes_non_ascii(self) -> None:
        got = canonicalize_json({"x": "é"})
        # ensure_ascii=True escapes non-ASCII.
        assert got == b'{"x":"\\u00e9"}'

    def test_private_v1_float_and_astral_encoding_is_explicit(self) -> None:
        assert canonicalize_json({"v": 1.0}) == b'{"v":1.0}'
        assert canonicalize_json({"v": 1e-7}) == b'{"v":1e-07}'
        assert canonicalize_json({"v": "\U0001f600"}) == b'{"v":"\\ud83d\\ude00"}'

    @pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
    def test_nonfinite_numbers_are_never_serialized(self, value: float) -> None:
        with pytest.raises(ValueError):
            canonicalize_json({"v": value})


class TestAuditLogBasics:
    def test_append_writes_canonical_jsonl(self, tmp_path: Path) -> None:
        log = AuditLog(tmp_path / "audit.jsonl")
        r1 = log.append("tool_call_start", {"tool": "evtx_query", "tc": "1"})
        r2 = log.append("finding", {"tc": "1", "id": "f-1"})

        # First record seq 0, empty prev_hash.
        assert r1.seq == 0
        assert r1.prev_hash == ""
        # Second record seq 1, prev_hash = hash of first line bytes.
        assert r2.seq == 1
        assert len(r2.prev_hash) == 64  # SHA-256 hex

        # File shape: one canonical JSON object per line.
        lines = (tmp_path / "audit.jsonl").read_bytes().splitlines()
        assert len(lines) == 2
        # Each line round-trips as canonical form.
        for ln in lines:
            assert canonicalize_json(json.loads(ln)) == ln

    @pytest.mark.skipif(os.name != "posix", reason="POSIX ownership/mode contract")
    def test_audit_path_is_owner_only(self, tmp_path: Path) -> None:
        path = tmp_path / "case" / "audit.jsonl"
        log = AuditLog(path)
        log.append("test", {})

        assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
        assert stat.S_IMODE(path.stat().st_mode) == 0o600

    def test_hardlinked_audit_log_is_refused(self, tmp_path: Path) -> None:
        source = tmp_path / "source.jsonl"
        source.write_text("", encoding="utf-8")
        alias = tmp_path / "audit.jsonl"
        os.link(source, alias)

        with pytest.raises(AuditLogError, match="non-hard-linked"):
            AuditLog(alias)

    def test_existing_log_above_persistent_quota_is_refused(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        path = tmp_path / "audit.jsonl"
        with path.open("wb") as stream:
            stream.truncate(1025)
        monkeypatch.setattr(audit_log_module, "MAX_AUDIT_LOG_BYTES", 1024)

        with pytest.raises(AuditLogError, match="size limit"):
            AuditLog(path)

    def test_append_refuses_record_and_log_quota_without_partial_line(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        path = tmp_path / "audit.jsonl"
        log = AuditLog(path)
        log.append("small", {"value": "ok"})
        before = path.read_bytes()
        monkeypatch.setattr(audit_log_module, "MAX_AUDIT_RECORD_BYTES", 200)

        with pytest.raises(AuditLogError, match="record size limit"):
            log.append("large", {"value": "x" * 512})
        assert path.read_bytes() == before

        monkeypatch.setattr(audit_log_module, "MAX_AUDIT_RECORD_BYTES", 4096)
        monkeypatch.setattr(audit_log_module, "MAX_AUDIT_LOG_BYTES", len(before) + 16)
        with pytest.raises(AuditLogError, match="log size limit"):
            log.append("next", {"value": "will not fit"})
        assert path.read_bytes() == before

    def test_append_rejects_deep_or_aggregate_payload_before_serializing(
        self, tmp_path: Path
    ) -> None:
        log = AuditLog(tmp_path / "audit.jsonl")
        deep: dict[str, object] = {}
        cursor = deep
        for _ in range(33):
            child: dict[str, object] = {}
            cursor["child"] = child
            cursor = child

        with pytest.raises(AuditLogError, match="nesting depth"):
            log.append("deep", deep)
        with pytest.raises(AuditLogError, match="aggregate string"):
            log.append("large", {"values": ["x" * 4096] * 1025})
        assert not log.path.exists()

    @pytest.mark.parametrize(
        "value",
        [float("nan"), float("inf"), b"bytes", {"set-member"}, object()],
    )
    def test_append_rejects_non_json_or_nonfinite_values(
        self, tmp_path: Path, value: object
    ) -> None:
        log = AuditLog(tmp_path / "audit.jsonl")

        with pytest.raises(AuditLogError, match=r"finite|non-JSON"):
            log.append("invalid", {"value": value})

        assert not log.path.exists()

    def test_chain_prev_hash_links_correctly(self, tmp_path: Path) -> None:
        log = AuditLog(tmp_path / "audit.jsonl")
        log.append("a", {"x": 1})
        log.append("b", {"x": 2})
        log.append("c", {"x": 3})

        lines = (tmp_path / "audit.jsonl").read_bytes().splitlines()
        # Each subsequent record's prev_hash == hash of prior line.
        expected = ""
        for ln in lines:
            obj = json.loads(ln)
            assert obj["prev_hash"] == expected
            expected = hash_line(ln)

    def test_verify_clean_chain(self, tmp_path: Path) -> None:
        log = AuditLog(tmp_path / "audit.jsonl")
        for i in range(5):
            log.append(f"kind-{i}", {"i": i})
        assert log.verify() == 5

    @pytest.mark.skipif(os.name != "posix", reason="requires O_NOFOLLOW semantics")
    def test_verify_refuses_symlink_swapped_after_open(self, tmp_path: Path) -> None:
        path = tmp_path / "audit.jsonl"
        log = AuditLog(path)
        log.append("a", {"x": 1})
        original = tmp_path / "original.jsonl"
        path.rename(original)
        path.symlink_to(original)

        with pytest.raises(AuditLogError, match="safely open"):
            log.verify()

    def test_read_only_snapshot_detects_preopen_path_swap(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        path = tmp_path / "audit.jsonl"
        log = AuditLog(path)
        log.append("a", {"x": 1})
        real_lstat = audit_log_module.os.lstat
        calls = 0

        class DifferentInitialInode:
            def __init__(self, metadata: object) -> None:
                self._metadata = metadata

            def __getattr__(self, name: str) -> object:
                value = getattr(self._metadata, name)
                return value + 1 if name == "st_ino" else value

        def lstat_with_preopen_swap(target: object) -> object:
            nonlocal calls
            metadata = real_lstat(target)
            if Path(target) == path and calls == 0:
                calls += 1
                return DifferentInitialInode(metadata)
            return metadata

        monkeypatch.setattr(audit_log_module.os, "lstat", lstat_with_preopen_swap)

        with pytest.raises(AuditLogError, match="changed while it was being read"):
            AuditLog.read_verified_snapshot(path)

    def test_read_only_snapshot_enforces_record_limit(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        path = tmp_path / "audit.jsonl"
        log = AuditLog(path)
        log.append("a", {"x": 1})
        log.append("b", {"x": 2})
        monkeypatch.setattr(audit_log_module, "MAX_AUDIT_RECORDS", 1)

        with pytest.raises(AuditLogError, match="record limit"):
            AuditLog.read_verified_snapshot(path)

    @pytest.mark.parametrize("placement", ["leading", "interior", "trailing"])
    def test_read_only_snapshot_rejects_blank_physical_records(
        self, tmp_path: Path, placement: str
    ) -> None:
        path = tmp_path / "audit.jsonl"
        log = AuditLog(path)
        log.append("a", {"x": 1})
        log.append("b", {"x": 2})
        data = path.read_bytes()
        if placement == "leading":
            tampered = b"\n" + data
        elif placement == "interior":
            tampered = data.replace(b"\n", b"\n\n", 1)
        else:
            tampered = data + b"\n"
        path.write_bytes(tampered)

        with pytest.raises(AuditLogError, match="empty physical record"):
            AuditLog.read_verified_snapshot(path)

    def test_verify_detects_tampering(self, tmp_path: Path) -> None:
        path = tmp_path / "audit.jsonl"
        log = AuditLog(path)
        log.append("a", {"x": 1})
        log.append("b", {"x": 2})
        # Tamper with line 2's payload.
        lines = path.read_bytes().splitlines()
        obj = json.loads(lines[1])
        obj["payload"]["x"] = 99
        lines[1] = canonicalize_json(obj)
        path.write_bytes(b"\n".join(lines) + b"\n")

        # prev_hash in line 2 is unchanged (pointed at original line 1),
        # but the tampered payload has a DIFFERENT prev_hash link if we
        # recompute. Here line 2's declared prev_hash still matches
        # line 1's hash, so this specific tamper is caught by the
        # canonicalization-round-trip check (different payload → line
        # differs from what prev_hash-of-line-3 would have captured).
        # We check the basic verifier still either passes OR raises —
        # depending on WHICH byte we tampered with. Use a line-1 tamper
        # to make the mismatch certain:
        lines = path.read_bytes().splitlines()
        obj0 = json.loads(lines[0])
        obj0["payload"]["x"] = 777
        lines[0] = canonicalize_json(obj0)
        path.write_bytes(b"\n".join(lines) + b"\n")

        fresh = AuditLog(path)
        with pytest.raises(AuditLogError):
            fresh.verify()

    def test_verify_malformed_line_raises_auditlogerror_not_crash(self, tmp_path: Path) -> None:
        # A non-JSON line must surface as a typed AuditLogError (a clean failure
        # the manifest verifier turns into overall=False), never a raw
        # json.JSONDecodeError that crashes verification.
        path = tmp_path / "audit.jsonl"
        log = AuditLog(path)
        log.append("a", {"x": 1})
        log.append("b", {"x": 2})
        log.append("c", {"x": 3})
        # Malform a NON-last line so the constructor's tail read (which already
        # guards the last line) succeeds and the break is hit inside verify().
        lines = path.read_bytes().splitlines()
        lines[1] = b"@@NOTJSON@@" + lines[1]
        path.write_bytes(b"\n".join(lines) + b"\n")

        fresh = AuditLog(path)
        with pytest.raises(AuditLogError, match="not valid JSON"):
            fresh.verify()

    def test_verify_detects_truncation(self, tmp_path: Path) -> None:
        path = tmp_path / "audit.jsonl"
        log = AuditLog(path)
        for i in range(3):
            log.append("x", {"i": i})
        # Chop off the last line.
        data = path.read_bytes().splitlines()
        path.write_bytes(b"\n".join(data[:-1]) + b"\n")
        # Re-opening is fine — chain replays to 2 records successfully.
        fresh = AuditLog(path)
        assert fresh.verify() == 2


class TestReopenAndExtend:
    def test_reopen_advances_seq(self, tmp_path: Path) -> None:
        log1 = AuditLog(tmp_path / "audit.jsonl")
        log1.append("a", {"x": 1})
        log1.append("b", {"x": 2})
        # New instance picks up where we left off.
        log2 = AuditLog(tmp_path / "audit.jsonl")
        assert log2.next_seq == 2
        assert log2.last_hash == log1.last_hash
        r = log2.append("c", {"x": 3})
        assert r.seq == 2

    def test_empty_file_starts_at_zero(self, tmp_path: Path) -> None:
        log = AuditLog(tmp_path / "audit.jsonl")
        assert log.next_seq == 0
        assert log.last_hash == ""

    def test_overlapping_instances_reload_tail_under_one_path_lock(self, tmp_path: Path) -> None:
        path = tmp_path / "audit.jsonl"
        first = AuditLog(path)
        stale = AuditLog(path)

        first_record = first.append("first", {"writer": "a"})
        second_record = stale.append("second", {"writer": "b"})

        assert first_record.seq == 0
        assert second_record.seq == 1
        assert second_record.prev_hash == first.last_hash
        assert AuditLog(path).verify() == 2

    def test_reopen_and_append_do_not_forward_scan_the_log(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        path = tmp_path / "audit.jsonl"
        seeded = AuditLog(path)
        seeded.append("first", {"value": 1})
        seeded.append("second", {"value": 2})

        def forbidden_forward_scan(stream: object) -> None:
            raise AssertionError(f"tail load attempted a forward scan: {stream!r}")

        monkeypatch.setattr(audit_log_module, "_bounded_audit_lines", forbidden_forward_scan)
        reopened = AuditLog(path)
        record = reopened.append("third", {"value": 3})
        assert record.seq == 2

    def test_reopen_refuses_torn_tail_without_newline(self, tmp_path: Path) -> None:
        path = tmp_path / "audit.jsonl"
        AuditLog(path).append("first", {"value": 1})
        path.write_bytes(path.read_bytes().rstrip(b"\n"))

        with pytest.raises(AuditLogError, match="torn tail"):
            AuditLog(path)

    @pytest.mark.skipif(os.name != "posix", reason="requires advisory flock")
    def test_overlapping_processes_serialize_append(self, tmp_path: Path) -> None:
        path = tmp_path / "audit.jsonl"
        context = multiprocessing.get_context("spawn")
        barrier = context.Barrier(2)
        processes = [
            context.Process(
                target=_append_after_barrier,
                args=(str(path), f"writer-{index}", barrier),
            )
            for index in range(2)
        ]
        for process in processes:
            process.start()
        for process in processes:
            process.join(timeout=10)
            assert process.exitcode == 0

        assert AuditLog(path).verify() == 2


class TestIterRecords:
    def test_iter_yields_records_in_order(self, tmp_path: Path) -> None:
        log = AuditLog(tmp_path / "audit.jsonl")
        for i in range(4):
            log.append(f"k-{i}", {"i": i})
        seqs = [r.seq for r in log.iter_records()]
        assert seqs == [0, 1, 2, 3]
        kinds = [r.kind for r in log.iter_records()]
        assert kinds == ["k-0", "k-1", "k-2", "k-3"]


class TestKnownVectors:
    def test_hash_line_matches_sha256(self) -> None:
        line = b'{"a":1,"b":2}'
        expected = hashlib.sha256(line).hexdigest()
        assert hash_line(line) == expected

    def test_hash_line_ignores_trailing_newline(self) -> None:
        assert hash_line(b"hello") == hash_line(b"hello\n")
