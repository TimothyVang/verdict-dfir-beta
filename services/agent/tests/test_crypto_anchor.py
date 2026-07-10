"""Tests for findevil_agent.crypto.anchor — opt-in Rekor transparency anchoring.

Never contacts the live Rekor log or a TSA: ``_submit_to_rekor`` and
``_rfc3161_timestamp`` are monkeypatched so the anchoring logic (block shape,
fallback ladder, offline verification) is exercised fully offline. Offline
verification uses a GENUINE minimal single-leaf RFC-6962 inclusion proof, so
``verify_anchor`` runs the real sigstore verifier — not a stub.
"""

from __future__ import annotations

import base64
import hashlib
import json

import pytest

from findevil_agent.crypto import anchor

_ROOT = "ab" * 32  # a valid 64-char SHA-256 hex string


def _statement_body(merkle_root_hex: str) -> bytes:
    """Canonical DSSE in-toto Statement bytes for the given root."""
    return anchor._build_statement(merkle_root_hex)._contents


def _single_leaf_root(body: bytes) -> str:
    """RFC-6962 leaf hash of ``body`` = the Merkle root of a size-1 tree."""
    return hashlib.sha256(b"\x00" + body).hexdigest()


def _fake_bundle(merkle_root_hex: str) -> tuple[str, str]:
    """A Sigstore v4-shaped Bundle with a genuine one-leaf inclusion proof."""
    body = _statement_body(merkle_root_hex)
    body_b64 = base64.b64encode(body).decode("ascii")
    root_hex = _single_leaf_root(body)
    bundle = {
        "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
        "verificationMaterial": {
            "certificate": {"rawBytes": base64.b64encode(b"certificate").decode("ascii")},
            "tlogEntries": [
                {
                    "logIndex": "0",
                    "logId": {"keyId": base64.b64encode(bytes.fromhex("c0ffee")).decode("ascii")},
                    "kindVersion": {"kind": "dsse", "version": "0.0.1"},
                    "integratedTime": "1700000000",
                    "inclusionPromise": {
                        "signedEntryTimestamp": base64.b64encode(b"set").decode("ascii")
                    },
                    "inclusionProof": {
                        "checkpoint": {"envelope": "rekor.sigstore.dev - 000\n1\n<root>\n"},
                        "hashes": [],
                        "logIndex": "0",
                        "rootHash": base64.b64encode(bytes.fromhex(root_hex)).decode("ascii"),
                        "treeSize": "1",
                    },
                    "canonicalizedBody": body_b64,
                }
            ],
        },
        "dsseEnvelope": {
            "payload": base64.b64encode(b"payload").decode("ascii"),
            "payloadType": "application/vnd.in-toto+json",
            "signatures": [{"keyid": "", "sig": base64.b64encode(b"sig").decode("ascii")}],
        },
    }
    return json.dumps(bundle, separators=(",", ":")), body_b64


class TestOptInGate:
    def test_disabled_by_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("FINDEVIL_REKOR_ENABLE", raising=False)
        assert anchor.rekor_enabled() is False
        with pytest.raises(anchor.RekorAnchorDisabledError):
            anchor.require_rekor_enabled()

    @pytest.mark.parametrize("val", ["", "0", "false", "no", "off"])
    def test_falsey_values_stay_disabled(self, monkeypatch: pytest.MonkeyPatch, val: str) -> None:
        monkeypatch.setenv("FINDEVIL_REKOR_ENABLE", val)
        assert anchor.rekor_enabled() is False

    @pytest.mark.parametrize("val", ["1", "true", "yes", "on"])
    def test_truthy_values_enable(self, monkeypatch: pytest.MonkeyPatch, val: str) -> None:
        monkeypatch.setenv("FINDEVIL_REKOR_ENABLE", val)
        assert anchor.rekor_enabled() is True
        anchor.require_rekor_enabled()  # must not raise


class TestAnchorMerkleRoot:
    def test_rekor_block_shape(self, monkeypatch: pytest.MonkeyPatch) -> None:
        bundle_json, body_b64 = _fake_bundle(_ROOT)
        monkeypatch.setattr(anchor, "_submit_to_rekor", lambda root: bundle_json)

        block = anchor.anchor_merkle_root(_ROOT)

        assert block is not None
        assert block["kind"] == "rekor"
        assert block["anchored"] is True
        assert block["subject"]["merkle_root_sha256"] == _ROOT
        assert block["statement_type"] == "https://in-toto.io/Statement/v1"
        assert block["predicate_type"].endswith("/audit-merkle-root/v1")
        rekor = block["rekor"]
        assert rekor["entry_uuid"] is None
        assert rekor["log_id"] == "c0ffee"
        assert rekor["log_index"] == 0
        assert rekor["body"] == body_b64
        assert base64.b64decode(rekor["bundle_b64"]).decode("utf-8") == bundle_json
        ip = rekor["inclusion_proof"]
        assert ip["tree_size"] == 1
        assert ip["root_hash"] == _single_leaf_root(_statement_body(_ROOT))
        assert block["tsa"] is None
        assert block["fallback_reason"] is None

    def test_invalid_root_returns_none_block(self) -> None:
        block = anchor.anchor_merkle_root("not-a-sha256")
        assert block is not None
        assert block["kind"] == "none"
        assert block["anchored"] is False
        assert "not a 64-char SHA-256" in block["fallback_reason"]

    def test_tsa_fallback_on_rekor_failure(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def _boom(root: str):
            raise RuntimeError("fulcio/rekor unreachable")

        canned_tsr = base64.b64encode(b"fake-rfc3161-token").decode("ascii")
        monkeypatch.setattr(anchor, "_submit_to_rekor", _boom)
        monkeypatch.setattr(anchor, "_rfc3161_timestamp", lambda root, tsa_url: canned_tsr)

        block = anchor.anchor_merkle_root(_ROOT)

        assert block is not None
        assert block["kind"] == "rfc3161"
        # The public TSA token is retained as an analyst side-signal, but it is
        # not authenticated without a pinned TSA certificate chain.
        assert block["anchored"] is False
        assert block["rekor"] is None
        assert block["tsa"]["tsr_b64"] == canned_tsr
        assert block["tsa"]["kind"] == "rfc3161"
        assert block["tsa"]["authenticated"] is False
        assert block["tsa"]["token_sha256"] == hashlib.sha256(b"fake-rfc3161-token").hexdigest()
        assert "rekor anchoring failed" in block["fallback_reason"]

    def test_no_tsa_fallback_when_disabled(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def _boom(root: str):
            raise RuntimeError("rekor down")

        monkeypatch.setattr(anchor, "_submit_to_rekor", _boom)
        block = anchor.anchor_merkle_root(_ROOT, allow_tsa_fallback=False)

        assert block is not None
        assert block["kind"] == "none"
        assert block["anchored"] is False
        assert "rekor down" in block["fallback_reason"]

    def test_total_failure_returns_none_block_never_raises(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def _boom_rekor(root: str):
            raise RuntimeError("rekor down")

        def _boom_tsa(root: str, tsa_url: str):
            raise RuntimeError("openssl missing")

        monkeypatch.setattr(anchor, "_submit_to_rekor", _boom_rekor)
        monkeypatch.setattr(anchor, "_rfc3161_timestamp", _boom_tsa)

        block = anchor.anchor_merkle_root(_ROOT)

        assert block is not None
        assert block["kind"] == "none"
        assert block["anchored"] is False
        assert "rekor down" in block["fallback_reason"]
        assert "tsa fallback failed" in block["fallback_reason"]


class TestVerifyAnchor:
    def _good_block(self, monkeypatch: pytest.MonkeyPatch, root: str = _ROOT) -> dict:
        bundle_json, _ = _fake_bundle(root)
        monkeypatch.setattr(anchor, "_submit_to_rekor", lambda r: bundle_json)
        monkeypatch.setenv("FINDEVIL_SIGSTORE_EXPECTED_IDENTITY", "release@example.test")
        monkeypatch.setenv("FINDEVIL_SIGSTORE_EXPECTED_ISSUER", "https://issuer.example.test")
        monkeypatch.setattr(
            anchor,
            "_verify_sigstore_dsse",
            lambda bundle, identity, issuer: (
                "application/vnd.in-toto+json",
                _statement_body(root),
            ),
        )
        block = anchor.anchor_merkle_root(root)
        assert block is not None
        return block

    def test_accepts_good_rekor_block(self, monkeypatch: pytest.MonkeyPatch) -> None:
        block = self._good_block(monkeypatch)
        # Real sigstore RFC-6962 inclusion verification over the embedded body.
        assert anchor.verify_anchor(block, _ROOT) is True

    def test_rejects_subject_root_mismatch(self, monkeypatch: pytest.MonkeyPatch) -> None:
        block = self._good_block(monkeypatch)
        result = anchor.verify_anchor(block, "ff" * 32)
        assert result is not True
        assert "subject digest" in str(result)

    def test_rejects_corrupted_bundle(self, monkeypatch: pytest.MonkeyPatch) -> None:
        block = self._good_block(monkeypatch)
        block["rekor"]["bundle_b64"] = base64.b64encode(b'{"forged":true}').decode()
        monkeypatch.setattr(
            anchor,
            "_verify_sigstore_dsse",
            lambda bundle, identity, issuer: (_ for _ in ()).throw(ValueError("bad checkpoint")),
        )
        result = anchor.verify_anchor(block, _ROOT)
        assert result is not True
        assert "Sigstore bundle did not verify" in str(result)
        assert "checkpoint" in str(result)

    def test_rejects_missing_full_bundle(self, monkeypatch: pytest.MonkeyPatch) -> None:
        block = self._good_block(monkeypatch)
        block["rekor"]["bundle_b64"] = None
        result = anchor.verify_anchor(block, _ROOT)
        assert result is not True
        assert "missing full Sigstore bundle" in str(result)

    def test_rejects_unrelated_signed_statement(self, monkeypatch: pytest.MonkeyPatch) -> None:
        block = self._good_block(monkeypatch)
        monkeypatch.setattr(
            anchor,
            "_verify_sigstore_dsse",
            lambda bundle, identity, issuer: (
                "application/vnd.in-toto+json",
                _statement_body("cd" * 32),
            ),
        )

        result = anchor.verify_anchor(block, _ROOT)

        assert result is not True
        assert "does not match the manifest" in str(result)

    def test_rejects_tampered_display_timestamp(self, monkeypatch: pytest.MonkeyPatch) -> None:
        block = self._good_block(monkeypatch)
        block["rekor"]["integrated_time"] = 42

        result = anchor.verify_anchor(block, _ROOT)

        assert result is not True
        assert "mirrored integrated_time" in str(result)

    def test_rejects_without_exact_identity_and_issuer(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        block = self._good_block(monkeypatch)
        monkeypatch.delenv("FINDEVIL_SIGSTORE_EXPECTED_IDENTITY", raising=False)
        monkeypatch.delenv("FINDEVIL_SIGSTORE_EXPECTED_ISSUER", raising=False)

        result = anchor.verify_anchor(block, _ROOT)

        assert result is not True
        assert "exact expected Sigstore identity and issuer" in str(result)

    def test_tsa_imprint_match_is_not_misreported_as_authenticated(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        token = base64.b64encode(b"syntactically-valid-tsr").decode("ascii")
        block = {
            "kind": "rfc3161",
            "anchored": False,
            "subject": {"merkle_root_sha256": _ROOT},
            "tsa": {"tsr_b64": token, "authenticated": False},
        }
        monkeypatch.setattr(anchor, "_openssl_available", lambda: True)
        monkeypatch.setattr(
            anchor,
            "_run_openssl",
            lambda args: f"Message data:\n    {_ROOT}\n",
        )

        result = anchor.verify_anchor(block, _ROOT)

        assert result is not True
        assert "certificate chain was not pinned or verified" in str(result)

    def test_none_kind_block_reports_reason(self) -> None:
        block = anchor.anchor_merkle_root("not-a-sha256")
        assert block is not None
        # subject digest for a none block is the (invalid) root string itself.
        result = anchor.verify_anchor(block, "not-a-sha256")
        assert result is not True
        assert "not a 64-char SHA-256" in str(result)
