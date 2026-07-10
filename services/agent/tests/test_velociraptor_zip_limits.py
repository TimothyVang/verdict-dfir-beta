"""Resource-bound regression tests for Velociraptor ZIP staging."""

from __future__ import annotations

import hashlib
import subprocess
import sys
import zipfile
from pathlib import Path
from unittest.mock import MagicMock

import pytest

_SCRIPTS = Path(__file__).resolve().parents[3] / "scripts"
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import find_evil_auto as fea  # noqa: E402


def _extract_zip(zip_path: str, output_dir: str, **kwargs: object) -> dict[str, object]:
    archive = Path(zip_path)
    expected_sha256 = (
        hashlib.sha256(archive.read_bytes()).hexdigest() if archive.is_file() else "0" * 64
    )
    return fea.extract_velociraptor_zip_artifacts(
        zip_path,
        output_dir,
        expected_sha256=expected_sha256,
        **kwargs,
    )


@pytest.fixture(autouse=True)
def local_bridge(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(fea, "LOCAL_MODE", True)
    monkeypatch.setattr(fea, "DOCKER_MODE", False)


def test_zip_aggregate_ceiling_stops_before_partial_second_member(
    tmp_path: Path,
) -> None:
    archive = tmp_path / "collection.zip"
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_STORED) as zf:
        zf.writestr("host/first.evtx", b"a" * 80)
        zf.writestr("host/second.evtx", b"b" * 80)

    output = tmp_path / "derived"
    result = _extract_zip(
        str(archive),
        str(output),
        max_member_bytes=1000,
        max_total_bytes=100,
        max_compression_ratio=1000,
    )

    assert result["entry_count"] == 1
    assert result["total_extracted_bytes"] == 80
    assert result["aggregate_limit_hit"] is True
    assert result["truncated"] is True
    assert not list(output.rglob("second.evtx"))


def test_zip_compression_ratio_bomb_is_skipped(tmp_path: Path) -> None:
    archive = tmp_path / "ratio.zip"
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("host/repeated.evtx", b"z" * 100_000)

    result = _extract_zip(
        str(archive),
        str(tmp_path / "derived"),
        max_member_bytes=200_000,
        max_total_bytes=200_000,
        max_compression_ratio=2,
    )

    assert result["entry_count"] == 0
    assert result["skipped_ratio"] == 1
    assert result["total_extracted_bytes"] == 0


def test_zip_member_limit_is_hard_clamped_and_skips_before_write(
    tmp_path: Path,
) -> None:
    archive = tmp_path / "member.zip"
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_STORED) as zf:
        zf.writestr("host/large.evtx", b"x" * 129)

    output = tmp_path / "derived"
    result = _extract_zip(
        str(archive),
        str(output),
        limit=100_000,
        max_member_bytes=128,
        max_total_bytes=1024,
        max_compression_ratio=1000,
    )

    assert result["limit"] == 500
    assert result["entry_count"] == 0
    assert result["skipped_oversize"] == 1
    assert not list(output.rglob("large.evtx"))


def test_zip_member_cardinality_is_bounded_before_classification(
    tmp_path: Path,
) -> None:
    archive = tmp_path / "many-unsupported.zip"
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_STORED) as zf:
        for index in range(4):
            zf.writestr(f"unsupported/{index}.txt", b"x")

    output = tmp_path / "derived"
    result = _extract_zip(
        str(archive),
        str(output),
        max_archive_members=3,
    )

    assert result["archive_member_count"] == 4
    assert result["archive_member_limit_hit"] is True
    assert result["truncated"] is True
    assert result["limit_reasons"] == ["archive_member_count"]
    limitation = fea.velociraptor_empty_extraction_limitation(truncated=True)
    assert "remain unexamined" in limitation
    assert "contained no supported" not in limitation
    assert not output.exists()


def test_zip_underreported_eocd_count_is_bounded_before_zipfile_open(
    tmp_path: Path,
) -> None:
    archive = tmp_path / "underreported-count.zip"
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_STORED) as zf:
        for index in range(4):
            zf.writestr(f"unsupported/{index}.txt", b"x")

    with archive.open("r+b") as fh:
        payload = fh.read()
        eocd_offset = payload.rfind(zipfile.stringEndArchive)
        assert eocd_offset >= 0
        fh.seek(eocd_offset + 8)
        fh.write((1).to_bytes(2, "little"))
        fh.write((1).to_bytes(2, "little"))

    output = tmp_path / "derived"
    result = _extract_zip(
        str(archive),
        str(output),
        max_archive_members=3,
    )

    assert result["archive_member_count"] == 4
    assert result["archive_member_limit_hit"] is True
    assert result["truncated"] is True
    assert result["limit_reasons"] == ["archive_member_count"]
    assert not output.exists()


def test_zip_underreported_eocd_count_is_rejected_when_below_limit(
    tmp_path: Path,
) -> None:
    archive = tmp_path / "inconsistent-count.zip"
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_STORED) as zf:
        zf.writestr("unsupported/first.txt", b"x")
        zf.writestr("unsupported/second.txt", b"x")

    with archive.open("r+b") as fh:
        payload = fh.read()
        eocd_offset = payload.rfind(zipfile.stringEndArchive)
        assert eocd_offset >= 0
        fh.seek(eocd_offset + 8)
        fh.write((1).to_bytes(2, "little"))
        fh.write((1).to_bytes(2, "little"))

    output = tmp_path / "derived"
    with pytest.raises(RuntimeError, match="entry count disagrees with EOCD"):
        _extract_zip(
            str(archive),
            str(output),
            max_archive_members=10,
        )
    assert not output.exists()


def test_zip_source_digest_mismatch_is_rejected_before_staging(tmp_path: Path) -> None:
    archive = tmp_path / "changed-after-intake.zip"
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_STORED) as zf:
        zf.writestr("host/first.evtx", b"first")
    intake_sha256 = hashlib.sha256(archive.read_bytes()).hexdigest()
    with zipfile.ZipFile(archive, "a", compression=zipfile.ZIP_STORED) as zf:
        zf.writestr("host/replacement.evtx", b"replacement")

    output = tmp_path / "derived"
    with pytest.raises(RuntimeError, match="archive SHA-256 does not match"):
        fea.extract_velociraptor_zip_artifacts(
            str(archive),
            str(output),
            expected_sha256=intake_sha256,
        )
    assert not output.exists()


def test_zip_investigation_passes_and_audits_custody_digest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    archive = tmp_path / "collection.zip"
    archive.write_bytes(b"intake")
    expected_sha256 = hashlib.sha256(b"intake").hexdigest()
    captured: dict[str, object] = {}

    def fake_extract(zip_path: str, output_dir: str, **kwargs: object) -> dict[str, object]:
        captured.update(zip_path=zip_path, output_dir=output_dir, **kwargs)
        return {
            "output_dir": output_dir,
            "entries": [],
            "expected_archive_sha256": expected_sha256,
            "archive_sha256_before": expected_sha256,
            "archive_sha256_after": expected_sha256,
            "truncated": False,
        }

    monkeypatch.setattr(fea, "extract_velociraptor_zip_artifacts", fake_extract)
    inv = fea.Investigation(str(archive), unattended=True, with_report=False)
    inv.handle = {"id": "case-zip", "image_hash": expected_sha256}
    inv._audit = MagicMock()  # type: ignore[method-assign]

    inv.investigate_velociraptor_zip(MagicMock(), MagicMock())

    assert captured["expected_sha256"] == expected_sha256
    assert str(captured["output_dir"]).endswith(expected_sha256[:12])
    zip_audits = [
        call.args[2]
        for call in inv._audit.call_args_list
        if len(call.args) >= 3 and call.args[1] == "velociraptor_zip_extract"
    ]
    assert zip_audits[0]["expected_archive_sha256"] == expected_sha256
    assert zip_audits[0]["archive_sha256_before"] == expected_sha256
    assert zip_audits[0]["archive_sha256_after"] == expected_sha256


def test_zip_central_directory_bytes_are_bounded_before_open(
    tmp_path: Path,
) -> None:
    archive = tmp_path / "wide-directory.zip"
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_STORED) as zf:
        zf.writestr(f"unsupported/{'x' * 200}.txt", b"x")

    result = _extract_zip(
        str(archive),
        str(tmp_path / "derived"),
        max_central_directory_bytes=64,
    )

    assert result["central_directory_bytes"] > 64
    assert result["central_directory_limit_hit"] is True
    assert "central_directory_bytes" in result["limit_reasons"]


def test_zip_member_depth_is_rejected_before_directory_creation(tmp_path: Path) -> None:
    archive = tmp_path / "deep.zip"
    deep_member = "/".join(["a"] * 65 + ["event.evtx"])
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_STORED) as zf:
        zf.writestr(deep_member, b"event")

    output = tmp_path / "derived"
    result = _extract_zip(str(archive), str(output))

    assert fea.classify_velociraptor_zip_member(deep_member)["supported"] is False
    assert result["entry_count"] == 0
    assert result["skipped_unsafe"] == 1
    assert result["truncated"] is True
    assert "unsafe_member_path" in result["limit_reasons"]
    limitation = fea.velociraptor_empty_extraction_limitation(truncated=bool(result["truncated"]))
    assert "remain unexamined" in limitation
    assert "contained no supported" not in limitation
    assert not list(output.rglob("event.evtx"))


def test_zip_crc_failure_removes_all_partial_staging(tmp_path: Path) -> None:
    archive = tmp_path / "crc.zip"
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_STORED) as zf:
        zf.writestr("host/first.evtx", b"first")
        zf.writestr("host/second.evtx", b"second")
    with zipfile.ZipFile(archive) as zf:
        info = zf.getinfo("host/second.evtx")
        data_offset = info.header_offset + 30 + len(info.filename.encode()) + len(info.extra)
    with archive.open("r+b") as fh:
        fh.seek(data_offset)
        original = fh.read(1)
        fh.seek(data_offset)
        fh.write(bytes([original[0] ^ 0xFF]))

    output = tmp_path / "derived"
    with pytest.raises(RuntimeError, match="zip extraction failed"):
        _extract_zip(str(archive), str(output))
    assert not output.exists()


def test_zip_timeout_is_normalized_and_partial_staging_removed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output = tmp_path / "derived"
    output.mkdir()
    (output / "partial.evtx").write_bytes(b"partial")
    monkeypatch.setattr(
        fea,
        "ssh_run",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(subprocess.TimeoutExpired("zip", 1800)),
    )

    with pytest.raises(RuntimeError, match="timed out"):
        _extract_zip(str(tmp_path / "collection.zip"), str(output))
    assert not output.exists()


def test_zip_non_object_response_is_normalized_and_partial_staging_removed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output = tmp_path / "derived"
    output.mkdir()
    (output / "partial.evtx").write_bytes(b"partial")
    monkeypatch.setattr(fea, "ssh_run", lambda *_args, **_kwargs: (0, "[]", ""))

    with pytest.raises(RuntimeError, match="response was not an object"):
        _extract_zip(str(tmp_path / "collection.zip"), str(output))
    assert not output.exists()
