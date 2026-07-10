"""Release validation must authenticate, not merely parse, Ed25519 manifests."""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

REPO_ROOT = Path(__file__).resolve().parents[3]
VALIDATOR_PATH = REPO_ROOT / "scripts" / "validate-submission-assets.py"


def _load_validator():
    spec = importlib.util.spec_from_file_location(
        "submission_manifest_validator_under_test", VALIDATOR_PATH
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _signed_manifest(validator, *, transparency_anchor_requested: bool = False) -> tuple[dict, str]:
    body = {
        "version": "1",
        "case_id": "case-release-validator",
        "run_id": "run-release-validator",
        "audit_log_path": "audit.jsonl",
        "audit_log_final_hash": "0" * 64,
        "audit_log_record_count": 0,
        "merkle_root_hex": "0" * 64,
        "leaf_count": 0,
        "leaves": [],
        "transparency_anchor_requested": transparency_anchor_requested,
        "extra": {},
    }
    body_bytes = validator.canonicalize_json(body)
    private_key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    fingerprint = hashlib.sha256(public_key).hexdigest()
    bundle = {
        "kind": "ed25519",
        "public_key_b64": base64.b64encode(public_key).decode("ascii"),
        "signature_b64": base64.b64encode(private_key.sign(body_bytes)).decode("ascii"),
        "payload_sha256": hashlib.sha256(body_bytes).hexdigest(),
        "cert_fingerprint": fingerprint,
    }
    return (
        {
            **body,
            "signature": {
                "kind": "ed25519",
                "bundle_b64": base64.b64encode(
                    json.dumps(bundle, sort_keys=True, separators=(",", ":")).encode()
                ).decode("ascii"),
                "payload_sha256": hashlib.sha256(body_bytes).hexdigest(),
                "cert_fingerprint": fingerprint,
                "signed_at": "2026-07-10T00:00:00Z",
            },
        },
        fingerprint,
    )


def test_release_validator_requires_external_ed25519_pin() -> None:
    validator = _load_validator()
    manifest, _fingerprint = _signed_manifest(validator)
    blockers: list[str] = []

    validator.verify_manifest_signature(manifest, blockers, "fixture")

    assert any("externally trusted" in blocker for blocker in blockers)


def test_release_validator_accepts_valid_signature_only_with_matching_pin() -> None:
    validator = _load_validator()
    manifest, fingerprint = _signed_manifest(validator)
    blockers: list[str] = []

    validator.verify_manifest_signature(
        manifest,
        blockers,
        "fixture",
        expected_ed25519_fingerprint=fingerprint,
    )

    assert blockers == []


def test_release_validator_rejects_identity_key_forgery() -> None:
    validator = _load_validator()
    manifest, _fingerprint = _signed_manifest(validator)
    identity = b"\x01" + (b"\x00" * 31)
    forged_signature = identity + (b"\x00" * 32)
    fingerprint = hashlib.sha256(identity).hexdigest()
    bundle = {
        "kind": "ed25519",
        "public_key_b64": base64.b64encode(identity).decode("ascii"),
        "signature_b64": base64.b64encode(forged_signature).decode("ascii"),
        "payload_sha256": manifest["signature"]["payload_sha256"],
        "cert_fingerprint": fingerprint,
    }
    manifest["signature"] = {
        **manifest["signature"],
        "bundle_b64": base64.b64encode(
            json.dumps(bundle, sort_keys=True, separators=(",", ":")).encode()
        ).decode("ascii"),
        "cert_fingerprint": fingerprint,
    }
    blockers: list[str] = []

    validator.verify_manifest_signature(
        manifest,
        blockers,
        "fixture",
        expected_ed25519_fingerprint=fingerprint,
    )

    assert any("signature inputs rejected" in blocker for blocker in blockers)


def test_release_validator_configured_pin_cannot_be_overridden(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    validator = _load_validator()
    manifest, fingerprint = _signed_manifest(validator)
    monkeypatch.setenv("FINDEVIL_ED25519_EXPECTED_FINGERPRINT", "0" * 64)
    blockers: list[str] = []

    validator.verify_manifest_signature(
        manifest,
        blockers,
        "fixture",
        expected_ed25519_fingerprint=fingerprint,
    )

    assert any("conflicts with configured trust policy" in blocker for blocker in blockers)


def test_release_validator_fails_closed_on_requested_anchor_it_cannot_authenticate() -> None:
    validator = _load_validator()
    manifest, fingerprint = _signed_manifest(validator, transparency_anchor_requested=True)
    blockers: list[str] = []

    validator.validate_recomputed_manifest(
        manifest,
        "",
        blockers,
        "fixture",
        expected_ed25519_fingerprint=fingerprint,
    )

    assert any("requested transparency anchor" in blocker for blocker in blockers)


@pytest.mark.parametrize("placement", ["leading", "interior", "trailing", "torn"])
def test_release_validator_rejects_noncanonical_audit_framing(placement: str) -> None:
    validator = _load_validator()
    first = validator.canonicalize_json(
        {"kind": "first", "payload": {}, "prev_hash": "", "seq": 0, "ts": "t"}
    )
    first_hash = hashlib.sha256(first).hexdigest()
    second = validator.canonicalize_json(
        {
            "kind": "second",
            "payload": {},
            "prev_hash": first_hash,
            "seq": 1,
            "ts": "t",
        }
    )
    valid = first.decode("ascii") + "\n" + second.decode("ascii") + "\n"
    if placement == "leading":
        tampered = "\n" + valid
    elif placement == "interior":
        tampered = valid.replace("\n", "\n\n", 1)
    elif placement == "trailing":
        tampered = valid + "\n"
    else:
        tampered = valid.removesuffix("\n")

    parse_blockers: list[str] = []
    records = validator.parse_readiness_audit_text(tampered, parse_blockers)
    derive_blockers: list[str] = []
    derived = validator.derive_audit_manifest_state(tampered, derive_blockers, "fixture")

    assert records == []
    assert derived is None
    assert any(
        "empty physical record" in blocker or "terminal LF" in blocker
        for blocker in [*parse_blockers, *derive_blockers]
    )
