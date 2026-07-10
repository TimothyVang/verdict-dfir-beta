from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import os
import sys
from pathlib import Path
from types import ModuleType

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
OFFLINE_VERIFIER = REPO_ROOT / "scripts" / "manifest-verify-offline.py"
FIXTURE_DIR = REPO_ROOT / "apps" / "web" / "__tests__" / "fixtures" / "custody"
FIXTURE_FINGERPRINT = "74caeff180c363db854bc10e8a8f876f34457746268345f6d9e34dc90c70914e"


def _load_verifier() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "manifest_verify_offline_for_test", OFFLINE_VERIFIER
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _copy_fixture(tmp_path: Path) -> tuple[Path, Path]:
    audit_path = tmp_path / "audit.jsonl"
    manifest_path = tmp_path / "run.manifest.json"
    audit_path.write_bytes((FIXTURE_DIR / "audit.jsonl").read_bytes())
    manifest_path.write_bytes((FIXTURE_DIR / "run.manifest.json").read_bytes())
    return audit_path, manifest_path


def _write_stub_manifest(
    verifier: ModuleType,
    manifest_path: Path,
    obj: dict,
) -> None:
    """Write ``obj`` with a payload-bound test stub over its signed body."""
    signed_body = {
        key: value for key, value in obj.items() if key not in ("signature", "transparency_log")
    }
    obj["signature"] = {
        "kind": "stub",
        "payload_sha256": hashlib.sha256(verifier.canonicalize_json(signed_body)).hexdigest(),
        "bundle_b64": base64.b64encode(b"anchor-policy-test-stub").decode("ascii"),
    }
    manifest_path.write_text(json.dumps(obj), encoding="utf-8")


def test_offline_verifier_rejects_forged_sigstore_kind(tmp_path: Path) -> None:
    verifier = _load_verifier()
    audit_path, manifest_path = _copy_fixture(tmp_path)
    obj = json.loads(manifest_path.read_text(encoding="utf-8"))
    obj["signature"]["kind"] = "sigstore"
    obj["signature"]["bundle_b64"] = base64.b64encode(b'{"forged":true}').decode()
    manifest_path.write_text(json.dumps(obj), encoding="utf-8")

    # Signature metadata is outside the signed body, so the fixture's original
    # payload digest is still valid. A presence-only verifier used to accept
    # this forged tier as an authenticated Sigstore manifest.
    result = verifier.verify_manifest_offline(manifest_path, audit_log_path=audit_path)

    assert result.audit_chain_ok is True
    assert result.merkle_root_ok is True
    assert result.signature_kind == "sigstore"
    assert result.signature_verified is not True
    assert "expected signer identity" in str(result.signature_verified)
    assert result.overall is False


def test_current_ed25519_fixture_verifies_strictly() -> None:
    verifier = _load_verifier()

    result = verifier.verify_manifest_offline(
        FIXTURE_DIR / "run.manifest.json",
        audit_log_path=FIXTURE_DIR / "audit.jsonl",
        expected_ed25519_fingerprint=FIXTURE_FINGERPRINT,
    )

    assert result.signature_kind == "ed25519"
    assert result.signature_payload_ok is True
    assert result.signature_verified is True
    assert result.overall is True

    unpinned = verifier.verify_manifest_offline(
        FIXTURE_DIR / "run.manifest.json",
        audit_log_path=FIXTURE_DIR / "audit.jsonl",
    )
    assert unpinned.signature_verified is not True
    assert "externally trusted" in str(unpinned.signature_verified)
    assert unpinned.overall is False


@pytest.mark.parametrize("placement", ["leading", "interior", "trailing"])
def test_offline_verifier_rejects_blank_physical_audit_records(
    tmp_path: Path, placement: str
) -> None:
    verifier = _load_verifier()
    audit_path, manifest_path = _copy_fixture(tmp_path)
    data = audit_path.read_bytes()
    if placement == "leading":
        tampered = b"\n" + data
    elif placement == "interior":
        tampered = data.replace(b"\n", b"\n\n", 1)
    else:
        tampered = data + b"\n"
    audit_path.write_bytes(tampered)

    result = verifier.verify_manifest_offline(
        manifest_path,
        audit_log_path=audit_path,
        expected_ed25519_fingerprint=FIXTURE_FINGERPRINT,
    )

    assert "empty physical record" in str(result.audit_chain_ok)
    assert result.overall is False


def test_offline_verifier_binds_stub_to_manifest_payload(tmp_path: Path) -> None:
    verifier = _load_verifier()
    audit_path, manifest_path = _copy_fixture(tmp_path)
    obj = json.loads(manifest_path.read_text(encoding="utf-8"))
    obj["signature"]["kind"] = "stub"
    obj["signature"]["bundle_b64"] = base64.b64encode(b"dev-placeholder").decode()
    obj["case_id"] = "tampered-after-seal"
    manifest_path.write_text(json.dumps(obj), encoding="utf-8")

    result = verifier.verify_manifest_offline(manifest_path, audit_log_path=audit_path)

    assert "payload digest FAILED" in str(result.signature_verified)
    assert result.overall is False


def test_stdlib_verifier_never_authenticates_forged_rekor_proof() -> None:
    verifier = _load_verifier()
    merkle_root = "ab" * 32
    forged_body = b"not a signed DSSE statement and never submitted to Rekor"
    anchor = {
        "kind": "rekor",
        "subject": {"merkle_root_sha256": merkle_root},
        "rekor": {
            "body": base64.b64encode(forged_body).decode("ascii"),
            "bundle_b64": base64.b64encode(b'{"forged":true}').decode("ascii"),
            "inclusion_proof": {
                "checkpoint": "FORGED",
                "hashes": [],
                "log_index": 0,
                "root_hash": hashlib.sha256(b"\x00" + forged_body).hexdigest(),
                "tree_size": 1,
            },
        },
    }

    result = verifier._verify_transparency_offline(anchor, merkle_root)

    assert result is not True
    assert "full Sigstore verifier" in str(result)
    assert "identity" in str(result)


@pytest.mark.parametrize(
    ("proof_kind", "expected_reason"),
    [
        ("missing", "requested"),
        ("none", "rekor unavailable"),
        ("rfc3161", "issuing CA chain"),
        ("invalid-rekor", "malformed"),
    ],
)
def test_requested_transparency_proof_gates_offline_overall(
    tmp_path: Path,
    proof_kind: str,
    expected_reason: str,
) -> None:
    verifier = _load_verifier()
    audit_path, manifest_path = _copy_fixture(tmp_path)
    obj = json.loads(manifest_path.read_text(encoding="utf-8"))
    root = str(obj["merkle_root_hex"])
    obj["transparency_anchor_requested"] = True
    obj.pop("transparency_log", None)
    if proof_kind == "none":
        obj["transparency_log"] = {
            "kind": "none",
            "anchored": False,
            "subject": {"merkle_root_sha256": root},
            "fallback_reason": "rekor unavailable",
        }
    elif proof_kind == "rfc3161":
        obj["transparency_log"] = {
            "kind": "rfc3161",
            "anchored": False,
            "subject": {"merkle_root_sha256": root},
            "tsa": {"tsr_b64": base64.b64encode(b"token").decode("ascii")},
        }
    elif proof_kind == "invalid-rekor":
        obj["transparency_log"] = {
            "kind": "rekor",
            "anchored": True,
            "subject": {"merkle_root_sha256": root},
            "rekor": {"bundle_b64": "not-base64"},
        }
    _write_stub_manifest(verifier, manifest_path, obj)

    result = verifier.verify_manifest_offline(manifest_path, audit_log_path=audit_path)

    assert result.signature_payload_ok is True
    assert result.transparency_ok is not True
    assert expected_reason in str(result.transparency_ok)
    assert result.overall is False


def test_legacy_unrequested_invalid_anchor_remains_non_gating(tmp_path: Path) -> None:
    verifier = _load_verifier()
    audit_path, manifest_path = _copy_fixture(tmp_path)
    obj = json.loads(manifest_path.read_text(encoding="utf-8"))
    root = str(obj["merkle_root_hex"])
    obj.pop("transparency_anchor_requested", None)
    obj["transparency_log"] = {
        "kind": "none",
        "anchored": False,
        "subject": {"merkle_root_sha256": root},
        "fallback_reason": "legacy side-signal failed",
    }
    _write_stub_manifest(verifier, manifest_path, obj)

    result = verifier.verify_manifest_offline(manifest_path, audit_log_path=audit_path)

    assert result.transparency_ok is not True
    assert result.overall is True


def test_ed25519_accepts_rfc8032_empty_message_vector() -> None:
    verifier = _load_verifier()
    public_key = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
    signature = bytes.fromhex(
        "e5564300c360ac729086e2cc806e828a"
        "84877f1eb8e5d974d873e06522490155"
        "5fb8821590a33bacc61e39701cf9b46b"
        "d25bf5f0595bbe24655141438e7a100b"
    )

    assert verifier.ed25519_verify(signature, b"", public_key) is True


def test_ed25519_accepts_rfc8032_one_byte_message_vector() -> None:
    verifier = _load_verifier()
    public_key = bytes.fromhex("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c")
    signature = bytes.fromhex(
        "92a009a9f0d4cab8720e820b5f642540"
        "a2b27b5416503f8fb3762223ebdb69da"
        "085ac1e43e15996e458f3613d0f11d8"
        "c387b2eaeb4302aeeb00d291612bb0c00"
    )

    assert verifier.ed25519_verify(signature, b"\x72", public_key) is True


def test_ed25519_rejects_identity_key_identity_r_zero_s_forgery() -> None:
    verifier = _load_verifier()
    identity = b"\x01" + (b"\x00" * 31)
    forged_signature = identity + (b"\x00" * 32)

    assert (
        verifier.ed25519_verify(
            forged_signature,
            b"arbitrary attacker-selected manifest body",
            identity,
        )
        is False
    )


def test_manifest_rejects_identity_key_identity_r_zero_s_forgery(
    tmp_path: Path,
) -> None:
    verifier = _load_verifier()
    audit_path, manifest_path = _copy_fixture(tmp_path)
    obj = json.loads(manifest_path.read_text(encoding="utf-8"))
    signed_body = {
        key: value for key, value in obj.items() if key not in ("signature", "transparency_log")
    }
    identity = b"\x01" + (b"\x00" * 31)
    fingerprint = hashlib.sha256(identity).hexdigest()
    forged_bundle = {
        "public_key_b64": base64.b64encode(identity).decode("ascii"),
        "signature_b64": base64.b64encode(identity + (b"\x00" * 32)).decode("ascii"),
        "cert_fingerprint": fingerprint,
    }
    obj["signature"] = {
        "kind": "ed25519",
        "payload_sha256": hashlib.sha256(verifier.canonicalize_json(signed_body)).hexdigest(),
        "bundle_b64": base64.b64encode(json.dumps(forged_bundle).encode("utf-8")).decode("ascii"),
        "cert_fingerprint": fingerprint,
    }
    manifest_path.write_text(json.dumps(obj), encoding="utf-8")

    result = verifier.verify_manifest_offline(
        manifest_path,
        audit_log_path=audit_path,
        expected_ed25519_fingerprint=fingerprint,
    )

    assert result.signature_payload_ok is True
    assert result.signature_verified is not True
    assert result.overall is False


def test_ed25519_rejects_s_plus_group_order_malleability() -> None:
    verifier = _load_verifier()
    public_key = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
    signature = bytearray.fromhex(
        "e5564300c360ac729086e2cc806e828a"
        "84877f1eb8e5d974d873e06522490155"
        "5fb8821590a33bacc61e39701cf9b46b"
        "d25bf5f0595bbe24655141438e7a100b"
    )
    s_value = int.from_bytes(signature[32:], "little")
    signature[32:] = (s_value + verifier._ED_L).to_bytes(32, "little")

    assert verifier.ed25519_verify(bytes(signature), b"", public_key) is False


@pytest.mark.parametrize(
    "encoded",
    [
        # y = p aliases y = 0 after field reduction.
        (2**255 - 19).to_bytes(32, "little"),
        # x = 0 has only sign bit 0; sign bit 1 is a non-canonical alias.
        b"\x01" + (b"\x00" * 30) + b"\x80",
    ],
)
def test_ed25519_rejects_noncanonical_point_encodings(encoded: bytes) -> None:
    verifier = _load_verifier()

    with pytest.raises(ValueError, match="canonical"):
        verifier._ed_decodepoint(encoded)


def test_ed25519_rejects_small_order_public_key() -> None:
    verifier = _load_verifier()
    identity_r = b"\x01" + (b"\x00" * 31)
    order_two_public_key = bytes.fromhex("ec" + ("ff" * 30) + "7f")

    # For an order-two A, the legacy equation accepted S=0/R=identity whenever
    # H(R || A || M) was even. Find such a message deterministically.
    message = next(
        candidate
        for counter in range(256)
        if (candidate := f"small-order-forgery-{counter}".encode("ascii"))
        and int.from_bytes(
            hashlib.sha512(identity_r + order_two_public_key + candidate).digest(),
            "little",
        )
        % verifier._ED_L
        % 2
        == 0
    )
    forged_signature = identity_r + (b"\x00" * 32)

    assert verifier.ed25519_verify(forged_signature, message, order_two_public_key) is False


def test_ed25519_rejects_small_order_r_and_public_key() -> None:
    verifier = _load_verifier()
    order_two = bytes.fromhex("ec" + ("ff" * 30) + "7f")

    # With A=R at order two, S=0 passes the legacy equation when h is odd.
    message = next(
        candidate
        for counter in range(256)
        if (candidate := f"small-order-r-{counter}".encode("ascii"))
        and int.from_bytes(hashlib.sha512(order_two + order_two + candidate).digest(), "little")
        % verifier._ED_L
        % 2
        == 1
    )

    assert verifier.ed25519_verify(order_two + (b"\x00" * 32), message, order_two) is False


def test_ed25519_rejects_mixed_torsion_point_from_prime_subgroup() -> None:
    verifier = _load_verifier()
    order_two = verifier._ed_decodepoint(bytes.fromhex("ec" + ("ff" * 30) + "7f"))
    mixed_torsion = verifier._ed_add(verifier._ED_B, order_two)

    assert verifier._ed_on_curve(mixed_torsion) is True
    assert verifier._ed_has_prime_order(mixed_torsion) is False


def test_manifest_read_rejects_symlink(tmp_path: Path) -> None:
    verifier = _load_verifier()
    audit_path, manifest_path = _copy_fixture(tmp_path)
    symlink_path = tmp_path / "linked.manifest.json"
    try:
        symlink_path.symlink_to(manifest_path.name)
    except (NotImplementedError, OSError):
        pytest.skip("symlinks are unavailable on this platform")

    with pytest.raises(verifier.VerifyError, match=r"regular file|symbolic link"):
        verifier.verify_manifest_offline(symlink_path, audit_log_path=audit_path)


def test_manifest_read_is_size_bounded(tmp_path: Path) -> None:
    verifier = _load_verifier()
    manifest_path = tmp_path / "oversized.manifest.json"
    manifest_path.write_bytes(b"{" + (b" " * verifier._MAX_MANIFEST_BYTES) + b"}")

    with pytest.raises(verifier.VerifyError, match="size limit"):
        verifier.verify_manifest_offline(manifest_path)


def test_manifest_read_rejects_in_place_change_during_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    verifier = _load_verifier()
    audit_path, manifest_path = _copy_fixture(tmp_path)
    real_read = os.read
    changed = False

    def racing_read(fd: int, count: int) -> bytes:
        nonlocal changed
        chunk = real_read(fd, count)
        if chunk and not changed:
            changed = True
            manifest_path.write_bytes(manifest_path.read_bytes())
            metadata = manifest_path.stat()
            os.utime(
                manifest_path,
                ns=(metadata.st_atime_ns, metadata.st_mtime_ns + 1_000_000_000),
            )
        return chunk

    monkeypatch.setattr(verifier.os, "read", racing_read)

    with pytest.raises(verifier.VerifyError, match="changed during bounded read"):
        verifier.verify_manifest_offline(manifest_path, audit_log_path=audit_path)


def test_audit_read_rejects_symlink(tmp_path: Path) -> None:
    verifier = _load_verifier()
    audit_path, manifest_path = _copy_fixture(tmp_path)
    symlink_path = tmp_path / "linked-audit.jsonl"
    try:
        symlink_path.symlink_to(audit_path.name)
    except (NotImplementedError, OSError):
        pytest.skip("symlinks are unavailable on this platform")

    result = verifier.verify_manifest_offline(manifest_path, audit_log_path=symlink_path)

    assert result.audit_chain_ok is not True
    assert "regular file" in str(result.audit_chain_ok)
    assert result.overall is False


def test_cli_preserves_explicit_audit_symlink_for_secure_rejection(
    tmp_path: Path,
) -> None:
    verifier = _load_verifier()
    audit_path, manifest_path = _copy_fixture(tmp_path)
    linked_audit = tmp_path / "linked-audit.jsonl"
    try:
        linked_audit.symlink_to(audit_path.name)
    except (NotImplementedError, OSError):
        pytest.skip("symlinks are unavailable on this platform")

    exit_code = verifier.main(
        [
            "manifest-verify-offline.py",
            str(manifest_path),
            "--audit-log",
            str(linked_audit),
            "--expected-ed25519-fingerprint",
            FIXTURE_FINGERPRINT,
        ]
    )

    assert exit_code == 1


def test_cli_check_rejects_linked_sidecar(tmp_path: Path) -> None:
    verifier = _load_verifier()
    _audit_path, manifest_path = _copy_fixture(tmp_path)
    sidecar_source = tmp_path / "sidecar-source.json"
    sidecar_source.write_text("{}", encoding="utf-8")
    sidecar = tmp_path / "manifest_verify.json"
    try:
        sidecar.symlink_to(sidecar_source.name)
    except (NotImplementedError, OSError):
        pytest.skip("symlinks are unavailable on this platform")

    exit_code = verifier.main(
        [
            "manifest-verify-offline.py",
            str(manifest_path),
            "--check",
            "--expected-ed25519-fingerprint",
            FIXTURE_FINGERPRINT,
        ]
    )

    assert exit_code == 2


def test_cli_check_rejects_oversized_sidecar(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    verifier = _load_verifier()
    _audit_path, manifest_path = _copy_fixture(tmp_path)
    (tmp_path / "manifest_verify.json").write_text("{}", encoding="utf-8")
    monkeypatch.setattr(verifier, "_MAX_SIDECAR_BYTES", 1)

    exit_code = verifier.main(
        [
            "manifest-verify-offline.py",
            str(manifest_path),
            "--check",
            "--expected-ed25519-fingerprint",
            FIXTURE_FINGERPRINT,
        ]
    )

    assert exit_code == 2


def test_audit_read_is_size_bounded(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    verifier = _load_verifier()
    audit_path, manifest_path = _copy_fixture(tmp_path)
    monkeypatch.setattr(verifier, "_MAX_AUDIT_LOG_BYTES", 32)

    result = verifier.verify_manifest_offline(manifest_path, audit_log_path=audit_path)

    assert result.audit_chain_ok is not True
    assert "size limit" in str(result.audit_chain_ok)


def test_audit_read_is_line_bounded(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    verifier = _load_verifier()
    audit_path, manifest_path = _copy_fixture(tmp_path)
    monkeypatch.setattr(verifier, "_MAX_AUDIT_RECORD_BYTES", 16)

    result = verifier.verify_manifest_offline(manifest_path, audit_log_path=audit_path)

    assert result.audit_chain_ok is not True
    assert "record size limit" in str(result.audit_chain_ok)


def test_audit_read_is_record_count_bounded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    verifier = _load_verifier()
    audit_path, manifest_path = _copy_fixture(tmp_path)
    monkeypatch.setattr(verifier, "_MAX_AUDIT_RECORDS", 1)

    result = verifier.verify_manifest_offline(manifest_path, audit_log_path=audit_path)

    assert result.audit_chain_ok is not True
    assert "record limit" in str(result.audit_chain_ok)


def test_audit_read_rejects_change_during_stream(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    verifier = _load_verifier()
    audit_path, manifest_path = _copy_fixture(tmp_path)
    real_loads = json.loads
    changed = False

    def racing_loads(value: object, *args: object, **kwargs: object) -> object:
        nonlocal changed
        if isinstance(value, bytes) and not changed:
            changed = True
            audit_path.write_bytes(audit_path.read_bytes())
            metadata = audit_path.stat()
            os.utime(
                audit_path,
                ns=(metadata.st_atime_ns, metadata.st_mtime_ns + 1_000_000_000),
            )
        return real_loads(value, *args, **kwargs)

    monkeypatch.setattr(verifier.json, "loads", racing_loads)

    result = verifier.verify_manifest_offline(manifest_path, audit_log_path=audit_path)

    assert result.audit_chain_ok is not True
    assert "changed during bounded read" in str(result.audit_chain_ok)


def test_audit_nonfinite_json_fails_closed(tmp_path: Path) -> None:
    verifier = _load_verifier()
    audit_path, manifest_path = _copy_fixture(tmp_path)
    audit_path.write_bytes(
        b'{"kind":"test","payload":{"value":NaN},"prev_hash":"",'
        b'"seq":0,"ts":"2026-07-10T00:00:00Z"}\n'
    )

    result = verifier.verify_manifest_offline(manifest_path, audit_log_path=audit_path)

    assert result.audit_chain_ok is not True
    assert "non-finite" in str(result.audit_chain_ok)


@pytest.mark.parametrize(
    "payload",
    [
        b'{"leaf_count":NaN}',
        b'{"leaf_count":',
    ],
)
def test_manifest_invalid_json_fails_as_verify_error(tmp_path: Path, payload: bytes) -> None:
    verifier = _load_verifier()
    manifest_path = tmp_path / "invalid.manifest.json"
    manifest_path.write_bytes(payload)

    with pytest.raises(verifier.VerifyError, match=r"valid JSON|non-finite"):
        verifier.verify_manifest_offline(manifest_path)
