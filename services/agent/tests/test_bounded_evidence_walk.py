from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import pytest

_SCRIPTS = Path(__file__).resolve().parents[3] / "scripts"
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import find_evil_auto as fea  # noqa: E402


def _limits(
    *,
    visited: int = 100,
    depth: int = 16,
    path_bytes: int = 4_096,
    directory_entries: int = 32,
) -> Any:
    return fea.EvidenceWalkLimits(
        max_entries_visited=visited,
        max_depth=depth,
        max_path_bytes=path_bytes,
        max_directory_entries=directory_entries,
    )


def _local_ssh(command: str, *, timeout: int) -> tuple[int, str, str]:
    result = subprocess.run(
        ["bash", "-c", command],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    return result.returncode, result.stdout, result.stderr


def _swap_path_on_open(
    monkeypatch: pytest.MonkeyPatch,
    *,
    target: Path,
    replacement: Path,
    target_is_directory: bool = False,
) -> None:
    real_open = os.open
    swapped = False

    def swapping_open(
        path: str | bytes | os.PathLike[str] | int,
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        nonlocal swapped
        if not swapped and not isinstance(path, int) and Path(path) == target:
            swapped = True
            target.rename(target.with_name(target.name + ".held"))
            target.symlink_to(replacement, target_is_directory=target_is_directory)
        if dir_fd is None:
            return real_open(path, flags, mode)
        return real_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(fea.os, "open", swapping_open)


def test_small_tree_retains_global_sorted_inventory_order(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    (evidence / "a").mkdir(parents=True)
    (evidence / "a.txt").write_bytes(b"sibling")
    (evidence / "a" / "nested.evtx").write_bytes(b"nested")
    (evidence / "z.mem").write_bytes(b"memory")

    expected = [
        str(path) for path in sorted(evidence.rglob("*")) if path.is_file() or path.is_symlink()
    ]
    first = fea.build_local_evidence_inventory(evidence)
    second = fea.build_local_evidence_inventory(evidence)

    assert [entry["path"] for entry in first["entries"]] == expected
    assert first["inventory_sha256"] == second["inventory_sha256"]
    assert first["truncated"] is False


def test_symlink_cycle_is_reported_once_and_never_followed(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    nested = evidence / "nested"
    nested.mkdir(parents=True)
    artifact = nested / "Security.evtx"
    artifact.write_bytes(b"event log")
    cycle = nested / "back-to-root"
    cycle.symlink_to(evidence, target_is_directory=True)

    inventory = fea.build_local_evidence_inventory(evidence)
    rows = {entry["path"]: entry for entry in inventory["entries"]}

    assert set(rows) == {str(cycle), str(artifact)}
    assert rows[str(cycle)]["custody_status"] == "rejected_symlink"
    assert rows[str(cycle)]["symlink_status"] == "rejected"
    assert inventory["truncated"] is False


@pytest.mark.parametrize(
    ("limits", "tree_builder", "expected_kind", "expected_reason"),
    [
        (
            _limits(directory_entries=2),
            lambda root: [
                (root / f"artifact-{index}.evtx").write_bytes(b"x") for index in range(3)
            ],
            "rejected_directory_entry_limit",
            "directory_entry_limit",
        ),
        (
            _limits(visited=2, directory_entries=8),
            lambda root: [(root / f"branch-{index}").mkdir() for index in range(2)],
            "rejected_entries_visited_limit",
            "entries_visited_limit",
        ),
        (
            _limits(depth=1),
            lambda root: (root / "level-one").mkdir(),
            "rejected_depth_limit",
            "depth_limit",
        ),
    ],
)
def test_walk_caps_reject_subtrees_without_unbounded_enumeration(
    tmp_path: Path,
    limits: Any,
    tree_builder: Any,
    expected_kind: str,
    expected_reason: str,
) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    tree_builder(evidence)
    walker = fea.BoundedEvidenceWalk(evidence, limits=limits)

    entries = list(walker)

    assert walker.truncated is True
    assert walker.entries_visited <= limits.max_entries_visited
    assert expected_reason in walker.truncation_reasons
    assert any(entry.kind == expected_kind for entry in entries)


def test_exact_global_visit_boundary_is_complete_not_truncated(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    for name in ("a.evtx", "b.evtx"):
        (evidence / name).write_bytes(name.encode())
    walker = fea.BoundedEvidenceWalk(
        evidence,
        limits=_limits(visited=2, directory_entries=8),
    )

    entries = list(walker)

    assert [(entry.path.name, entry.kind) for entry in entries] == [
        ("a.evtx", "file"),
        ("b.evtx", "file"),
    ]
    assert walker.entries_visited == 2
    assert walker.truncated is False


def test_embedded_remote_exact_global_boundary_is_not_truncated(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    for name in ("a.evtx", "b.evtx"):
        (evidence / name).write_bytes(name.encode())
    monkeypatch.setattr(fea, "ssh_run", _local_ssh)

    inventory = fea.build_remote_evidence_inventory(
        str(evidence),
        walk_limits=_limits(visited=2, directory_entries=8),
    )

    assert [Path(entry["path"]).name for entry in inventory["entries"]] == [
        "a.evtx",
        "b.evtx",
    ]
    assert inventory["truncated"] is False


def test_path_byte_cap_rejects_long_child_without_opening_it(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    long_child = evidence / ("x" * 40 + ".evtx")
    long_child.write_bytes(b"must not hash")
    cap = len(os.fsencode(evidence)) + 12
    walker = fea.BoundedEvidenceWalk(
        evidence,
        limits=_limits(path_bytes=cap),
    )

    entries = list(walker)

    assert [(entry.path, entry.kind) for entry in entries] == [(long_child, "rejected_path_length")]
    assert walker.truncated is True
    assert "path_length_limit" in walker.truncation_reasons


def test_walk_limits_cannot_raise_production_hard_caps(tmp_path: Path) -> None:
    limits = _limits(visited=fea.EVIDENCE_WALK_MAX_ENTRIES_VISITED + 1)

    with pytest.raises(ValueError, match="exceeds hard maximum"):
        fea.BoundedEvidenceWalk(tmp_path, limits=limits)


def test_local_inventory_rejects_leaf_swapped_before_open(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    artifact = evidence / "Security.evtx"
    artifact.write_bytes(b"registered evidence")
    outside = tmp_path / "outside-secret"
    outside.write_bytes(b"must never enter custody")
    _swap_path_on_open(monkeypatch, target=artifact, replacement=outside)

    inventory = fea.build_local_evidence_inventory(evidence)

    assert [entry["custody_status"] for entry in inventory["entries"]] == [
        "rejected_changed_during_read"
    ]
    assert fea.sha256_file_local(outside) not in str(inventory)


def test_bound_hash_detects_same_size_rewrite_with_restored_mtime(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    artifact = tmp_path / "artifact.evtx"
    artifact.write_bytes(b"good")
    original = artifact.stat()
    real_read = os.read
    mutated = False

    def racing_read(descriptor: int, size: int) -> bytes:
        nonlocal mutated
        chunk = real_read(descriptor, size)
        if chunk and not mutated:
            mutated = True
            time.sleep(0.02)  # Ensure coarse filesystems advance ctime.
            artifact.write_bytes(b"evil")
            os.utime(
                artifact,
                ns=(original.st_atime_ns, original.st_mtime_ns),
            )
        return chunk

    monkeypatch.setattr(fea.os, "read", racing_read)

    with pytest.raises(fea.EvidenceReadRaceError, match="changed during read"):
        fea.sha256_file_local(artifact)


def test_local_walk_rejects_directory_swapped_before_scandir(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    evidence = tmp_path / "evidence"
    nested = evidence / "nested"
    nested.mkdir(parents=True)
    (nested / "ordinary.evtx").write_bytes(b"ordinary")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.evtx").write_bytes(b"must not enumerate")
    _swap_path_on_open(
        monkeypatch,
        target=nested,
        replacement=outside,
        target_is_directory=True,
    )

    inventory = fea.build_local_evidence_inventory(evidence)

    assert [entry["custody_status"] for entry in inventory["entries"]] == [
        "rejected_directory_identity"
    ]
    assert "secret.evtx" not in str(inventory)


def test_walk_binds_root_directory_identity_at_construction(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    (evidence / "ordinary.evtx").write_bytes(b"ordinary")
    walker = fea.BoundedEvidenceWalk(evidence)
    evidence.rename(tmp_path / "evidence-held")
    evidence.mkdir()
    (evidence / "replacement-secret.evtx").write_bytes(b"must not enumerate")

    entries = list(walker)

    assert [(entry.path, entry.kind) for entry in entries] == [(evidence, "rejected_root_identity")]


def test_embedded_remote_walk_matches_local_rejections(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    for index in range(3):
        (evidence / f"artifact-{index}.evtx").write_bytes(b"x")
    limits = _limits(directory_entries=2)
    monkeypatch.setattr(fea, "ssh_run", _local_ssh)

    local = fea.build_local_evidence_inventory(evidence, walk_limits=limits)
    remote = fea.build_remote_evidence_inventory(str(evidence), walk_limits=limits)

    for inventory in (local, remote):
        assert inventory["truncated"] is True
        assert [entry["custody_status"] for entry in inventory["entries"]] == [
            "rejected_directory_entry_limit"
        ]


def test_embedded_remote_walk_preserves_order_and_rejects_symlink_cycle(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    evidence = tmp_path / "evidence"
    nested = evidence / "a"
    nested.mkdir(parents=True)
    (nested / "Security.evtx").write_bytes(b"event log")
    (evidence / "a.txt").write_bytes(b"sibling")
    (nested / "loop").symlink_to(evidence, target_is_directory=True)
    monkeypatch.setattr(fea, "ssh_run", _local_ssh)

    local = fea.build_local_evidence_inventory(evidence)
    remote = fea.build_remote_evidence_inventory(str(evidence))

    assert remote == local
    assert [entry["custody_status"] for entry in remote["entries"]] == [
        "custody_registered",
        "rejected_symlink",
        "custody_registered",
    ]


def test_dbx_discovery_rejects_overfull_mount_directory(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    mount = tmp_path / "mount"
    mount.mkdir()
    for index in range(3):
        (mount / f"mail-{index}.dbx").write_bytes(b"dbx")
    monkeypatch.setattr(
        fea,
        "DBX_EVIDENCE_WALK_LIMITS",
        _limits(directory_entries=2),
    )
    inv = fea.Investigation("disk.img", unattended=True, with_report=False)
    inv.handle = {"id": "case-bounded-dbx"}
    inv.audit_path = str(tmp_path / "run" / "audit.jsonl")

    class Rust:
        def call_tool(self, name: str, args: dict[str, Any]) -> dict[str, Any]:
            raise AssertionError(f"over-limit DBX must not be parsed: {name} {args}")

    inv.investigate_oe_dbx_stores(Rust(), object(), str(mount))

    assert any(
        "DBX" in limitation and "safety limit" in limitation
        for limitation in inv.analysis_limitations
    )


def test_dbx_copy_rejects_leaf_swapped_before_open(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    mount = tmp_path / "mount"
    mount.mkdir()
    dbx = mount / "Inbox.dbx"
    dbx.write_bytes(b"ordinary DBX")
    outside = tmp_path / "outside-secret"
    outside.write_bytes(b"must not be copied")
    _swap_path_on_open(monkeypatch, target=dbx, replacement=outside)
    inv = fea.Investigation("disk.img", unattended=True, with_report=False)
    inv.handle = {"id": "case-dbx-race"}
    inv.audit_path = str(tmp_path / "run" / "audit.jsonl")

    class Rust:
        def call_tool(self, name: str, args: dict[str, Any]) -> dict[str, Any]:
            raise AssertionError(f"swapped DBX must not be parsed: {name} {args}")

    inv.investigate_oe_dbx_stores(Rust(), object(), str(mount))

    assert not (Path(inv.audit_path).parent / "oe_dbx_stores" / "000_Inbox.dbx").exists()
    assert any(
        "DBX" in limitation and "changed" in limitation for limitation in inv.analysis_limitations
    )
