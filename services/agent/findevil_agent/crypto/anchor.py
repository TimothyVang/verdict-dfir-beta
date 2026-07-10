"""Opt-in Sigstore Rekor transparency-log anchoring of the audit Merkle root.

This module publishes the run's audit-chain Merkle root to a public
transparency log so a third party can later prove *when* the sealed root
existed, independent of our servers. The proof block is additive, while a
separate signed request commitment makes the requested custody tier fail
closed:

  * **Absent by default.** Anchoring only happens when the operator opts in
    with ``FINDEVIL_REKOR_ENABLE`` *and* the caller sets the per-call
    ``anchor_transparency`` flag. With the flag unset no network is touched and
    no ``transparency_log`` block is written; new manifests sign an explicit
    ``transparency_anchor_requested=false`` policy for downgrade resistance.
  * **Never part of the signed body.** The block is attached *after* the
    manifest is signed and is excluded from the signed bytes (see
    ``manifest._to_json_safe`` / ``_verify_ed25519_signature``), so adding it
    cannot invalidate an existing Ed25519 signature.
  * **Conditionally gating.** ``verify_anchor`` reports ``transparency_ok``.
    When the signed request commitment is true, a missing, failed,
    unauthenticated, or invalid proof fails the manifest's ``overall`` custody
    verdict. Legacy/unrequested attached proofs remain non-gating for backward
    compatibility.

What leaves the host when anchoring fires is the bare 32-byte SHA-256 Merkle
root (a hash of hashes) — **no evidence text**, so the egress risk is low.
It is still gated opt-in per the project's fail-closed egress policy: a hash of
the sealed chain is metadata about the investigation, and publishing it is the
operator's decision, not a default.

Rekor submission is keyless (Fulcio/Rekor), so it needs an OIDC identity token
(``$SIGSTORE_ID_TOKEN``) and network at anchoring time. When Rekor is
unreachable (or no token is present) and ``allow_tsa_fallback`` is set, the root
digest is instead timestamped with an RFC-3161 Trusted Timestamp Authority via
``openssl ts``. On total failure the function returns an honest ``kind="none"``
block and NEVER raises into the run.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import subprocess  # only invokes the local `openssl` binary with fixed args, no shell
import tempfile
import urllib.request
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Constants.
# ---------------------------------------------------------------------------

_REKOR_ENABLE_ENV = "FINDEVIL_REKOR_ENABLE"
_ID_TOKEN_ENV = "SIGSTORE_ID_TOKEN"

_SUBJECT_NAME = "audit-merkle-root"
_STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
_PREDICATE_TYPE = "https://verdict.dev/attestations/audit-merkle-root/v1"

# Public production Rekor + an RFC-3161 imprint-only fallback. The TSA chain is
# not pinned here, so the fallback is never treated as authenticated time.
_DEFAULT_REKOR_URL = "https://rekor.sigstore.dev"
_DEFAULT_TSA_URL = "https://freetsa.org/tsr"

_OPENSSL_TIMEOUT_S = 30


class RekorAnchorDisabledError(RuntimeError):
    """Transparency anchoring was requested but ``FINDEVIL_REKOR_ENABLE`` is unset.

    Fail-closed sibling of :class:`agentloop.factory.EvidenceEgressError`: a
    network action (Rekor/TSA submission) must not fire unless the operator has
    explicitly opted in.
    """


# ---------------------------------------------------------------------------
# Opt-in gate.
# ---------------------------------------------------------------------------


def rekor_enabled() -> bool:
    """True iff the operator opted into transparency anchoring via the env flag.

    Default (unset/empty/``0``/``false``/``no``/``off``) is OFF: no anchoring,
    no network.
    """
    val = os.environ.get(_REKOR_ENABLE_ENV, "").strip().lower()
    return val not in ("", "0", "false", "no", "off")


def require_rekor_enabled() -> None:
    """Raise :class:`RekorAnchorDisabledError` unless the env opt-in is set."""
    if not rekor_enabled():
        raise RekorAnchorDisabledError(
            "transparency anchoring requested but disabled; set "
            f"{_REKOR_ENABLE_ENV}=1 to opt in (publishes the bare SHA-256 Merkle "
            "root to a public transparency log — no evidence text)"
        )


# ---------------------------------------------------------------------------
# Anchor.
# ---------------------------------------------------------------------------


def anchor_merkle_root(
    merkle_root_hex: str,
    *,
    rekor_url: str | None = None,
    allow_tsa_fallback: bool = True,
) -> dict[str, Any] | None:
    """Anchor ``merkle_root_hex`` in a transparency log and return the block.

    Builds an in-toto DSSE Statement whose subject is the Merkle root, submits
    it to Rekor keylessly, and returns the structured ``transparency_log`` block.
    On Rekor failure (and ``allow_tsa_fallback``) it degrades to an RFC-3161
    ``openssl ts`` timestamp over the root digest. On total failure it returns a
    ``kind="none"`` block recording the reason — it NEVER raises into the run.

    This function assumes the opt-in gate already passed; callers wanting the
    fail-closed behaviour call :func:`require_rekor_enabled` first.
    """
    if not _is_sha256_hex(merkle_root_hex):
        return _none_block(
            merkle_root_hex,
            "merkle_root_hex is not a 64-char SHA-256 hex string; nothing to anchor",
        )

    effective_rekor_url = rekor_url or _DEFAULT_REKOR_URL
    try:
        bundle_json = _submit_to_rekor(merkle_root_hex)
        return _rekor_block(merkle_root_hex, bundle_json, effective_rekor_url)
    except Exception as rekor_exc:  # degrade on ANY Rekor failure — never raise into the run
        rekor_reason = f"rekor anchoring failed: {rekor_exc}"
        if not allow_tsa_fallback:
            return _none_block(merkle_root_hex, rekor_reason)
        try:
            return _tsa_block(merkle_root_hex, _DEFAULT_TSA_URL, rekor_reason)
        except Exception as tsa_exc:  # the fallback must also never raise
            return _none_block(merkle_root_hex, f"{rekor_reason}; tsa fallback failed: {tsa_exc}")


def verify_anchor(
    block: dict[str, Any],
    merkle_root_hex: str,
    *,
    expected_identity: str | None = None,
    expected_issuer: str | None = None,
) -> bool | str:
    """Offline-verify a ``transparency_log`` block against ``merkle_root_hex``.

    Pure/offline — contacts no network. A Rekor Bundle is authenticated with
    Sigstore production roots plus exact identity and issuer policy. An
    RFC-3161 token is decoded only to check its imprint; because this module
    does not pin/verify a TSA certificate chain, that path returns an honest
    structural-only reason and never ``True``. Never raises.
    """
    if not isinstance(block, dict):
        return "transparency_log block is not an object"
    subject = _subject_digest(block)
    if subject != merkle_root_hex:
        return (
            f"transparency subject digest {subject!r} != manifest merkle root {merkle_root_hex!r}"
        )
    kind = block.get("kind")
    if kind == "none":
        return str(block.get("fallback_reason") or "root was not anchored")
    if kind == "rekor":
        return _verify_rekor_block(
            block,
            merkle_root_hex,
            expected_identity=expected_identity,
            expected_issuer=expected_issuer,
        )
    if kind == "rfc3161":
        return _verify_tsa_block(block, merkle_root_hex)
    return f"unknown transparency kind {kind!r}"


# ---------------------------------------------------------------------------
# Rekor path.
# ---------------------------------------------------------------------------


def _submit_to_rekor(merkle_root_hex: str) -> str:
    """Keyless-sign a DSSE Statement over the root and submit it to Rekor.

    Returns Sigstore's public Bundle JSON serialization. Requires
    ``$SIGSTORE_ID_TOKEN`` and network — raises on any missing prerequisite so
    the caller can degrade. Persisting the whole Bundle lets offline verification
    authenticate the certificate, SET/checkpoint, DSSE signature, and statement
    binding instead of trusting caller-supplied proof fields.
    Isolated as a single function so tests can monkeypatch it without touching
    the live log.
    """
    from sigstore.models import ClientTrustConfig  # type: ignore[import-not-found]
    from sigstore.oidc import IdentityToken  # type: ignore[import-not-found]
    from sigstore.sign import SigningContext  # type: ignore[import-not-found]

    token = os.environ.get(_ID_TOKEN_ENV)
    if not token:
        raise RuntimeError(
            f"no OIDC identity token in ${_ID_TOKEN_ENV}; keyless Rekor signing "
            "needs one (acquire via Sigstore's OIDC flow)"
        )

    statement = _build_statement(merkle_root_hex)
    ctx = SigningContext.from_trust_config(ClientTrustConfig.production())
    identity = IdentityToken(token)
    with ctx.signer(identity) as signer:
        bundle = signer.sign_dsse(statement)
    return bundle.to_json()


def _build_statement(merkle_root_hex: str) -> Any:
    """Build the in-toto DSSE Statement whose subject is the Merkle root."""
    from sigstore.dsse import StatementBuilder, Subject  # type: ignore[import-not-found]

    return StatementBuilder(
        subjects=[Subject(name=_SUBJECT_NAME, digest={"sha256": merkle_root_hex})],
        predicate_type=_PREDICATE_TYPE,
        predicate={
            "tool": "verdict-dfir",
            "note": "audit-chain Merkle root transparency anchor",
        },
    ).build()


def _rekor_block(
    merkle_root_hex: str,
    bundle_json: str,
    rekor_url: str,
) -> dict[str, Any]:
    """Normalize public Sigstore Bundle JSON into the manifest side-signal."""
    normalized = _normalized_rekor_entry(bundle_json)
    normalized["url"] = rekor_url
    normalized["bundle_b64"] = base64.b64encode(bundle_json.encode("utf-8")).decode("ascii")
    return {
        "kind": "rekor",
        "anchored": True,
        "subject": {"merkle_root_sha256": merkle_root_hex},
        "statement_type": _STATEMENT_TYPE,
        "predicate_type": _PREDICATE_TYPE,
        "rekor": normalized,
        "tsa": None,
        "fallback_reason": None,
    }


def _normalized_rekor_entry(bundle_json: str) -> dict[str, Any]:
    """Extract display fields exclusively from public Sigstore Bundle JSON."""
    try:
        bundle_obj = json.loads(bundle_json)
        entries = bundle_obj["verificationMaterial"]["tlogEntries"]
        if not isinstance(entries, list) or len(entries) != 1:
            raise ValueError("Sigstore Bundle must contain exactly one tlog entry")
        entry = entries[0]
        proof = entry["inclusionProof"]
        body_b64 = _validated_b64(entry["canonicalizedBody"], "canonicalizedBody")
        log_id = _b64_hex(entry["logId"]["keyId"], "logId.keyId")
        root_hash = _b64_hex(proof["rootHash"], "inclusionProof.rootHash")
        hashes = [
            _b64_hex(value, f"inclusionProof.hashes[{index}]")
            for index, value in enumerate(proof.get("hashes") or [])
        ]
        log_index = int(entry["logIndex"])
        proof_log_index = int(proof["logIndex"])
        if proof_log_index != log_index:
            raise ValueError("tlog entry and inclusion proof log indexes differ")
        integrated_time = int(entry["integratedTime"])
        tree_size = int(proof["treeSize"])
        checkpoint = str(proof["checkpoint"]["envelope"])
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise ValueError(f"malformed Sigstore v4 Bundle JSON: {exc}") from exc

    return {
        "log_id": log_id,
        "log_index": log_index,
        "integrated_time": integrated_time,
        # Sigstore Bundle v0.3 no longer exposes a Rekor UUID.
        "entry_uuid": None,
        "body": body_b64,
        "inclusion_proof": {
            "checkpoint": checkpoint,
            "hashes": hashes,
            "log_index": proof_log_index,
            "root_hash": root_hash,
            "tree_size": tree_size,
        },
    }


def _verify_rekor_block(
    block: dict[str, Any],
    merkle_root_hex: str,
    *,
    expected_identity: str | None,
    expected_issuer: str | None,
) -> bool | str:
    rekor = block.get("rekor") or {}
    bundle_b64 = rekor.get("bundle_b64")
    if not bundle_b64:
        return (
            "rekor block missing full Sigstore bundle; normalized proof fields "
            "alone cannot authenticate a transparency-log entry"
        )
    identity = (
        expected_identity or os.environ.get("FINDEVIL_SIGSTORE_EXPECTED_IDENTITY", "").strip()
    )
    issuer = expected_issuer or os.environ.get("FINDEVIL_SIGSTORE_EXPECTED_ISSUER", "").strip()
    if not identity or not issuer:
        return (
            "rekor verification requires exact expected Sigstore identity and issuer "
            "policy (FINDEVIL_SIGSTORE_EXPECTED_IDENTITY and "
            "FINDEVIL_SIGSTORE_EXPECTED_ISSUER)"
        )
    try:
        bundle_json = base64.b64decode(str(bundle_b64), validate=True).decode("utf-8")
        payload_type, payload = _verify_sigstore_dsse(bundle_json, identity, issuer)
        if payload_type != "application/vnd.in-toto+json":
            raise ValueError(f"unexpected DSSE payload type {payload_type!r}")
        statement = json.loads(payload)
        if statement.get("_type") != _STATEMENT_TYPE:
            raise ValueError("signed payload is not the required in-toto Statement type")
        if statement.get("predicateType") != _PREDICATE_TYPE:
            raise ValueError("signed payload has the wrong predicate type")
        subjects = statement.get("subject")
        if not isinstance(subjects, list) or len(subjects) != 1:
            raise ValueError("signed statement must contain exactly one subject")
        subject = subjects[0]
        if not isinstance(subject, dict):
            raise ValueError("signed statement subject is not an object")
        digest_obj = subject.get("digest")
        digest = digest_obj.get("sha256") if isinstance(digest_obj, dict) else None
        if subject.get("name") != _SUBJECT_NAME or not isinstance(digest, str):
            raise ValueError("signed statement does not identify the audit Merkle root")
        if not hmac.compare_digest(digest.lower(), merkle_root_hex.lower()):
            raise ValueError("signed statement Merkle root does not match the manifest")
        normalized = _normalized_rekor_entry(bundle_json)
        for field, trusted_value in normalized.items():
            if rekor.get(field) != trusted_value:
                raise ValueError(
                    f"mirrored {field} does not match the authenticated Sigstore Bundle"
                )
    except Exception as exc:  # honest reason, never a crash
        return f"rekor Sigstore bundle did not verify offline: {exc}"
    return True


def _verify_sigstore_dsse(
    bundle_json: str,
    expected_identity: str,
    expected_issuer: str,
) -> tuple[str, bytes]:
    """Verify a DSSE Bundle with Sigstore's production roots and exact policy."""
    from sigstore.models import Bundle  # type: ignore[import-not-found]
    from sigstore.verify import Verifier  # type: ignore[import-not-found]
    from sigstore.verify.policy import Identity  # type: ignore[import-not-found]

    bundle = Bundle.from_json(bundle_json)
    policy = Identity(identity=expected_identity, issuer=expected_issuer)
    return Verifier.production(offline=True).verify_dsse(bundle, policy)


# ---------------------------------------------------------------------------
# RFC-3161 TSA fallback (structural imprint only when Rekor is unreachable).
# ---------------------------------------------------------------------------


def _tsa_block(merkle_root_hex: str, tsa_url: str, fallback_reason: str) -> dict[str, Any]:
    """Countersign the root digest with an RFC-3161 timestamp via ``openssl ts``.

    Isolated so tests can monkeypatch :func:`_rfc3161_timestamp` (mock openssl /
    the TSA) or let it raise cleanly when ``openssl`` is absent.
    """
    tsr_b64 = _rfc3161_timestamp(merkle_root_hex, tsa_url)
    tsr_bytes = base64.b64decode(tsr_b64)
    return {
        "kind": "rfc3161",
        # A public TSA response without a pinned issuing chain is retained as
        # an analyst side-signal, never claimed as authenticated proof.
        "anchored": False,
        "subject": {"merkle_root_sha256": merkle_root_hex},
        "statement_type": _STATEMENT_TYPE,
        "predicate_type": _PREDICATE_TYPE,
        "rekor": None,
        "tsa": {
            "kind": "rfc3161",
            "tsa_url": tsa_url,
            "tsr_b64": tsr_b64,
            "authenticated": False,
            # SHA-256 over the DER token itself, explicitly not a certificate-
            # chain fingerprint.
            "token_sha256": hashlib.sha256(tsr_bytes).hexdigest(),
        },
        "fallback_reason": fallback_reason,
    }


def _rfc3161_timestamp(merkle_root_hex: str, tsa_url: str) -> str:
    """Return a base64 RFC-3161 timestamp token over the root digest.

    Builds an ``openssl ts`` query over the SHA-256 imprint (the Merkle root is
    already a SHA-256 digest) and POSTs it to the TSA. Requires ``openssl`` +
    network; raises otherwise so the caller degrades to a ``none`` block.
    """
    if not _openssl_available():
        raise RuntimeError("openssl not found on PATH; cannot build an RFC-3161 token")
    with tempfile.TemporaryDirectory() as td:
        tsq = Path(td) / "request.tsq"
        _run_openssl(
            [
                "ts",
                "-query",
                "-digest",
                merkle_root_hex,
                "-sha256",
                "-cert",
                "-out",
                str(tsq),
            ]
        )
        tsr_bytes = _post_timestamp(tsa_url, tsq.read_bytes())
    return base64.b64encode(tsr_bytes).decode("ascii")


def _verify_tsa_block(block: dict[str, Any], merkle_root_hex: str) -> bool | str:
    """Offline-verify an RFC-3161 token: parse it and match the imprint digest.

    Uses ``openssl ts -reply`` to decode the stored token and confirm its hashed
    message imprint equals the Merkle root. Full TSA-signature verification needs
    a pinned issuing CA chain, which this fallback does not bundle. A matching
    imprint is therefore structural evidence only and never returns ``True``.
    """
    tsa = block.get("tsa") or {}
    tsr_b64 = tsa.get("tsr_b64")
    if not tsr_b64:
        return "rfc3161 block missing tsr_b64; nothing to verify"
    if not _openssl_available():
        return "rfc3161 timestamp present but openssl is unavailable to verify it offline"
    try:
        tsr_bytes = base64.b64decode(str(tsr_b64))
    except Exception as exc:
        return f"rfc3161 tsr_b64 is not valid base64: {exc}"
    try:
        with tempfile.TemporaryDirectory() as td:
            tsr = Path(td) / "response.tsr"
            tsr.write_bytes(tsr_bytes)
            text = _run_openssl(["ts", "-reply", "-in", str(tsr), "-text"])
    except Exception as exc:
        return f"rfc3161 token did not parse under openssl: {exc}"
    imprint = merkle_root_hex.lower()
    normalized = text.lower().replace(":", "").replace(" ", "").replace("\n", "")
    if imprint not in normalized:
        return (
            "rfc3161 token message imprint does not match the Merkle root "
            "(timestamp is over a different digest)"
        )
    return (
        "rfc3161 token imprint matches the Merkle root, but its TSA signature/"
        "certificate chain was not pinned or verified"
    )


def _post_timestamp(tsa_url: str, request_bytes: bytes) -> bytes:
    # Fixed https TSA URL + RFC-3161 content type; only fires on the opt-in path.
    req = urllib.request.Request(
        tsa_url,
        data=request_bytes,
        headers={"Content-Type": "application/timestamp-query"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=_OPENSSL_TIMEOUT_S) as resp:
        return resp.read()


def _openssl_available() -> bool:
    try:
        # Fixed argv (no shell); `openssl` is a trusted local binary.
        subprocess.run(
            ["openssl", "version"],
            capture_output=True,
            check=True,
            timeout=_OPENSSL_TIMEOUT_S,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return True


def _run_openssl(args: list[str]) -> str:
    # Fixed argv (no shell); `openssl` is a trusted local binary.
    proc = subprocess.run(
        ["openssl", *args],
        capture_output=True,
        check=True,
        timeout=_OPENSSL_TIMEOUT_S,
    )
    return proc.stdout.decode("utf-8", errors="replace")


# ---------------------------------------------------------------------------
# Helpers.
# ---------------------------------------------------------------------------


def _none_block(merkle_root_hex: str, reason: str) -> dict[str, Any]:
    return {
        "kind": "none",
        "anchored": False,
        "subject": {"merkle_root_sha256": merkle_root_hex},
        "statement_type": _STATEMENT_TYPE,
        "predicate_type": _PREDICATE_TYPE,
        "rekor": None,
        "tsa": None,
        "fallback_reason": reason,
    }


def _subject_digest(block: dict[str, Any]) -> str | None:
    subject = block.get("subject")
    if not isinstance(subject, dict):
        return None
    val = subject.get("merkle_root_sha256")
    return str(val) if val is not None else None


def _validated_b64(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field} must be non-empty base64")
    try:
        base64.b64decode(value, validate=True)
    except Exception as exc:
        raise ValueError(f"{field} is not valid base64") from exc
    return value


def _b64_hex(value: Any, field: str) -> str:
    encoded = _validated_b64(value, field)
    decoded = base64.b64decode(encoded, validate=True)
    if not decoded:
        raise ValueError(f"{field} decodes to an empty value")
    return decoded.hex()


def _checkpoint_str(checkpoint: Any) -> str:
    """Best-effort string form of a LogInclusionProof checkpoint (str or model)."""
    if checkpoint is None:
        return ""
    if isinstance(checkpoint, str):
        return checkpoint
    for attr in ("signed_note", "note"):
        inner = getattr(checkpoint, attr, None)
        if isinstance(inner, str):
            return inner
    return str(checkpoint)


def _is_sha256_hex(value: Any) -> bool:
    if not isinstance(value, str) or len(value) != 64:
        return False
    try:
        bytes.fromhex(value)
    except ValueError:
        return False
    return True


__all__ = [
    "RekorAnchorDisabledError",
    "anchor_merkle_root",
    "rekor_enabled",
    "require_rekor_enabled",
    "verify_anchor",
]
