#!/usr/bin/env python3
"""manifest-verify-offline — re-derive a run.manifest custody chain with ZERO deps.

A third party can run this with NOTHING but a stock Python 3 interpreter — no
``uv``/venv, no ``cryptography`` wheel, no MCP server, no network, no production
``findevil_agent`` import — and re-prove, end to end, that a committed
``run.manifest.json`` is internally consistent and, for the Ed25519 tier,
authenticated under an externally trusted public-key fingerprint:

1. **Per-line hash chain.** Replays the linked ``audit.jsonl``: ``seq`` is
   contiguous from 0, every record's ``prev_hash`` equals the SHA-256 of the
   preceding line's exact bytes, and every line is in the versioned VERDICT
   canonical JSON v1 form (sorted keys, tight separators, and ASCII escapes).
   Any post-seal edit changes the canonical bytes and breaks the chain.

2. **Log-vs-manifest consistency.** A tail-truncated log still replays
   prefix-cleanly and a forged-but-internally-consistent leaf set still rebuilds
   its own root, so the verifier RE-DERIVES the record count, the audit-log final
   hash, and the full Merkle leaf set from the log itself and compares them to
   what the manifest declared — instead of trusting the manifest's own copies.

3. **Merkle root.** Rebuilds the Merkle root from the manifest's declared leaves
   (duplicate-last odd rule, internal node = ``SHA-256(left || right)``) and
   compares it to ``merkle_root_hex``; also checks ``leaf_count``.

4. **Manifest authentication.** Verifies the embedded Ed25519 signature over the
   VERDICT-canonical signed body (everything except ``signature`` and the
   post-signing ``transparency_log``) using a
   VENDORED, pure-Python RFC-8032 verifier (the only primitive: ``hashlib.sha512``
   from the stdlib). No third-party crypto library is imported. A ``stub`` bundle
   is reported as a non-cryptographic placeholder. A ``sigstore`` bundle cannot
   pass this zero-dependency verifier because certificate-identity policy is not
   available here; use the product verifier with Sigstore's production roots
   plus explicitly configured exact identity and OIDC issuer for a cryptographic
   Sigstore decision.

5. **Transparency request policy.** A new manifest signs
   ``transparency_anchor_requested`` before the post-signing proof is attached.
   When true, a missing, failed, unauthenticated, or invalid proof fails
   ``overall``. Legacy manifests without the field remain unrequested and
   preserve their historical non-gating behavior.

This is a deliberately INDEPENDENT re-implementation of
``findevil_agent.crypto.manifest.verify_manifest``. It shares no code with the
product so that agreement between the two is a real cross-check, not a tautology.

Usage:
    scripts/manifest-verify-offline.py <run.manifest.json> [--audit-log PATH]
                                       [--expected-ed25519-fingerprint HEX]
                                       [--check] [--json]

    --audit-log PATH  override the audit log location (default: the sibling
                      ``audit.jsonl`` next to the manifest, then the embedded
                      ``audit_log_path``).
    --expected-ed25519-fingerprint HEX
                      trusted public-key SHA-256 obtained outside the case;
                      required for an Ed25519 authentication pass.
    --check           also load the sibling ``manifest_verify.json`` and assert
                      this verifier AGREES with the committed product result on
                      every custody/signature field (exit non-zero on any
                      disagreement). This is the "agrees with a committed
                      sample-run manifest" gate.
    --json            print the structured result as JSON instead of a report.

Exit code 0 iff the manifest verifies (and, under ``--check``, agrees with the
committed sidecar); non-zero otherwise.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import stat
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

_CANONICAL_SEPARATORS = (",", ":")
_MAX_MANIFEST_BYTES = 64 * 1024 * 1024
_MAX_SIDECAR_BYTES = 16 * 1024 * 1024
_MAX_AUDIT_LOG_BYTES = 128 * 1024 * 1024
_MAX_AUDIT_RECORD_BYTES = 4 * 1024 * 1024
_MAX_AUDIT_RECORDS = 250_000
_FILE_READ_CHUNK_BYTES = 64 * 1024


# ---------------------------------------------------------------------------
# Canonicalization + hashing (mirror of crypto.audit_log, re-implemented).
# ---------------------------------------------------------------------------


def canonicalize_json(obj: Any) -> bytes:
    """VERDICT canonical JSON v1 bytes, independent of the product code.

    This deliberately mirrors the product's versioned CPython encoding and is
    not RFC 8785/JCS.
    """
    return json.dumps(
        obj,
        sort_keys=True,
        separators=_CANONICAL_SEPARATORS,
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# Vendored pure-Python Ed25519 verify (RFC 8032). Stdlib-only: the single
# primitive is hashlib.sha512. No third-party crypto library is imported.
# ---------------------------------------------------------------------------

_ED_P = 2**255 - 19
_ED_L = 2**252 + 27742317777372353535851937790883648493
_ED_D = (-121665 * pow(121666, _ED_P - 2, _ED_P)) % _ED_P
_ED_I = pow(2, (_ED_P - 1) // 4, _ED_P)


def _ed_inv(x: int) -> int:
    return pow(x, _ED_P - 2, _ED_P)


def _ed_xrecover(y: int) -> int:
    denominator = (_ED_D * y * y + 1) % _ED_P
    if denominator == 0:
        raise ValueError("Ed25519 point has no affine x coordinate")
    xx = (y * y - 1) * _ed_inv(denominator) % _ED_P
    x = pow(xx, (_ED_P + 3) // 8, _ED_P)
    if (x * x - xx) % _ED_P != 0:
        x = (x * _ED_I) % _ED_P
    if (x * x - xx) % _ED_P != 0:
        raise ValueError("encoded Ed25519 point is not on the curve")
    if x % 2 != 0:
        x = _ED_P - x
    return x


_ED_BY = (4 * _ed_inv(5)) % _ED_P
_ED_BX = _ed_xrecover(_ED_BY)
_ED_B = (_ED_BX % _ED_P, _ED_BY % _ED_P)


def _ed_add(point_p: tuple[int, int], point_q: tuple[int, int]) -> tuple[int, int]:
    x1, y1 = point_p
    x2, y2 = point_q
    denom = _ED_D * x1 * x2 * y1 * y2 % _ED_P
    x3 = (x1 * y2 + x2 * y1) * _ed_inv(1 + denom) % _ED_P
    y3 = (y1 * y2 + x1 * x2) * _ed_inv(1 - denom) % _ED_P
    return (x3 % _ED_P, y3 % _ED_P)


def _ed_scalarmult(point: tuple[int, int], scalar: int) -> tuple[int, int]:
    """Iterative double-and-add (no recursion, so no recursion-limit risk)."""
    result = (0, 1)
    addend = point
    while scalar > 0:
        if scalar & 1:
            result = _ed_add(result, addend)
        addend = _ed_add(addend, addend)
        scalar >>= 1
    return result


def _ed_on_curve(point: tuple[int, int]) -> bool:
    x, y = point
    return (-x * x + y * y - 1 - _ED_D * x * x * y * y) % _ED_P == 0


def _ed_decodepoint(s: bytes) -> tuple[int, int]:
    if len(s) != 32:
        raise ValueError("encoded Ed25519 point must be exactly 32 bytes")
    encoded = int.from_bytes(s, "little")
    sign = encoded >> 255
    y = encoded & ((1 << 255) - 1)
    if y >= _ED_P:
        raise ValueError("non-canonical Ed25519 point encoding: y >= p")
    x = _ed_xrecover(y)
    if x == 0 and sign != 0:
        raise ValueError("non-canonical Ed25519 point encoding: x=0 with sign=1")
    if (x & 1) != sign:
        x = _ED_P - x
    point = (x, y)
    if not _ed_on_curve(point):
        raise ValueError("decoded point is not on the Ed25519 curve")
    if _ed_encodepoint(point) != s:
        raise ValueError("non-canonical Ed25519 point encoding")
    return point


def _ed_encodepoint(point: tuple[int, int]) -> bytes:
    x, y = point
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _ed_has_prime_order(point: tuple[int, int]) -> bool:
    """Return whether ``point`` is a non-identity member of the order-L group.

    The full Edwards25519 group has cofactor 8. Merely checking that a decoded
    point is on the curve leaves identity, low-order, and mixed-torsion points
    available for signature forgeries. Since L is prime, ``[L]P = identity``
    plus ``P != identity`` proves that P has exactly the subgroup order L.
    """
    identity = (0, 1)
    return point != identity and _ed_scalarmult(point, _ED_L) == identity


def ed25519_verify(signature: bytes, message: bytes, public_key: bytes) -> bool:
    """Strict RFC-8032 Ed25519 verification. Returns True iff genuine.

    In addition to the signature equation this enforces canonical encodings,
    ``S < L``, and exact prime-order subgroup membership for both A and R.
    Those checks are performed here even when a platform crypto backend is
    available because some common backends accept low-order-key forgeries.
    """
    if len(signature) != 64 or len(public_key) != 32:
        return False
    s_int = int.from_bytes(signature[32:], "little")
    if s_int >= _ED_L:
        return False
    try:
        point_r = _ed_decodepoint(signature[:32])
        point_a = _ed_decodepoint(public_key)
    except ValueError:
        return False
    if not _ed_has_prime_order(point_a) or not _ed_has_prime_order(point_r):
        return False
    digest = hashlib.sha512(_ed_encodepoint(point_r) + public_key + message).digest()
    h_int = int.from_bytes(digest, "little") % _ED_L
    left = _ed_scalarmult(_ED_B, s_int)
    right = _ed_add(point_r, _ed_scalarmult(point_a, h_int))
    return left == right


# ---------------------------------------------------------------------------
# Audit-log replay + Merkle leaf re-derivation (mirror of crypto.manifest).
# ---------------------------------------------------------------------------


class VerifyError(RuntimeError):
    """A structural problem prevented verification (not a clean negative result)."""


def _stat_fingerprint(metadata: os.stat_result) -> tuple[int, int, int, int, int, int]:
    """Identity + mutation-sensitive metadata for one bound regular file."""
    mtime_ns = getattr(metadata, "st_mtime_ns", int(metadata.st_mtime * 1_000_000_000))
    ctime_ns = getattr(metadata, "st_ctime_ns", int(metadata.st_ctime * 1_000_000_000))
    return (
        metadata.st_dev,
        metadata.st_ino,
        stat.S_IFMT(metadata.st_mode),
        metadata.st_size,
        mtime_ns,
        ctime_ns,
    )


def _read_regular_file_bounded(path: Path, *, max_bytes: int, label: str) -> bytes:
    """Read one identity-bound regular file without following a final symlink.

    The pre-open pathname, opened descriptor, post-read descriptor, and
    post-read pathname must all describe the same unchanged object. This keeps
    the standalone verifier fail-closed under symlink swaps and in-place edits
    while retaining a zero-dependency implementation on stock Python.
    """
    try:
        before_path = os.lstat(path)
    except OSError as exc:
        raise VerifyError(f"{label} could not be inspected safely: {exc}") from exc
    if not stat.S_ISREG(before_path.st_mode) or before_path.st_nlink != 1:
        raise VerifyError(
            f"{label} is not one non-hard-linked regular file "
            "(symbolic links are not accepted)"
        )
    if before_path.st_size > max_bytes:
        raise VerifyError(
            f"{label} exceeds the {max_bytes}-byte size limit ({before_path.st_size} bytes)"
        )

    flags = os.O_RDONLY
    for flag_name in ("O_CLOEXEC", "O_BINARY", "O_NOFOLLOW"):
        flags |= getattr(os, flag_name, 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise VerifyError(f"{label} could not be opened safely: {exc}") from exc

    try:
        bound = os.fstat(descriptor)
        if not stat.S_ISREG(bound.st_mode) or bound.st_nlink != 1:
            raise VerifyError(f"{label} descriptor is not one regular unlinked file")
        if _stat_fingerprint(bound) != _stat_fingerprint(before_path):
            raise VerifyError(f"{label} changed while it was being opened")

        content = bytearray()
        while len(content) <= max_bytes:
            try:
                chunk = os.read(
                    descriptor,
                    min(_FILE_READ_CHUNK_BYTES, max_bytes + 1 - len(content)),
                )
            except OSError as exc:
                raise VerifyError(f"{label} could not be read safely: {exc}") from exc
            if not chunk:
                break
            content.extend(chunk)
        if len(content) > max_bytes:
            raise VerifyError(f"{label} exceeds the {max_bytes}-byte size limit")

        after_descriptor = os.fstat(descriptor)
        try:
            after_path = os.lstat(path)
        except OSError as exc:
            raise VerifyError(f"{label} changed during bounded read: {exc}") from exc
        expected = _stat_fingerprint(before_path)
        if (
            _stat_fingerprint(after_descriptor) != expected
            or _stat_fingerprint(after_path) != expected
        ):
            raise VerifyError(f"{label} changed during bounded read")
        return bytes(content)
    finally:
        os.close(descriptor)


@dataclass(frozen=True)
class DerivedLeaf:
    seq: int
    kind: str
    digest_hex: str
    record_id: str

    def as_tuple(self) -> tuple[int, str, str, str]:
        return (self.seq, self.kind, self.digest_hex, self.record_id)


def _is_hex64(value: Any) -> bool:
    if not isinstance(value, str) or len(value) != 64:
        return False
    try:
        bytes.fromhex(value)
    except ValueError:
        return False
    return True


def _replay_audit_log(log_path: Path) -> tuple[list[DerivedLeaf], int, str]:
    """Replay the chain and re-derive (leaves, record_count, final_line_hash).

    Raises :class:`VerifyError` on any chain break — seq gap, prev_hash mismatch,
    or a non-canonical line (byte-level tampering inside a record)."""
    try:
        path_before = os.lstat(log_path)
    except OSError as exc:
        raise VerifyError(f"audit log could not be inspected safely: {exc}") from exc
    if not stat.S_ISREG(path_before.st_mode) or path_before.st_nlink != 1:
        raise VerifyError(
            "audit log is not one non-hard-linked regular file "
            "(symbolic links are not accepted)"
        )
    if path_before.st_size > _MAX_AUDIT_LOG_BYTES:
        raise VerifyError(
            f"audit log size limit exceeded ({_MAX_AUDIT_LOG_BYTES} bytes)"
        )

    flags = os.O_RDONLY
    for flag_name in ("O_CLOEXEC", "O_BINARY", "O_NOFOLLOW"):
        flags |= getattr(os, flag_name, 0)
    try:
        descriptor = os.open(log_path, flags)
    except OSError as exc:
        raise VerifyError(f"audit log could not be opened safely: {exc}") from exc

    leaves: list[DerivedLeaf] = []
    count = 0
    prev_hash = ""
    final_hash = ""
    total_bytes = 0
    try:
        bound = os.fstat(descriptor)
        if not stat.S_ISREG(bound.st_mode) or bound.st_nlink != 1:
            raise VerifyError("audit log descriptor is not one regular unlinked file")
        if _stat_fingerprint(bound) != _stat_fingerprint(path_before):
            raise VerifyError("audit log changed while it was being opened")
        if bound.st_size > _MAX_AUDIT_LOG_BYTES:
            raise VerifyError(
                f"audit log size limit exceeded ({_MAX_AUDIT_LOG_BYTES} bytes)"
            )

        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            while True:
                raw_line = handle.readline(_MAX_AUDIT_RECORD_BYTES + 2)
                if not raw_line:
                    break
                total_bytes += len(raw_line)
                if total_bytes > _MAX_AUDIT_LOG_BYTES:
                    raise VerifyError(
                        f"audit log size limit exceeded ({_MAX_AUDIT_LOG_BYTES} bytes)"
                    )
                line_bytes = len(raw_line) - (1 if raw_line.endswith(b"\n") else 0)
                if line_bytes > _MAX_AUDIT_RECORD_BYTES:
                    raise VerifyError(
                        "audit record size limit exceeded "
                        f"({_MAX_AUDIT_RECORD_BYTES} bytes)"
                    )
                if count >= _MAX_AUDIT_RECORDS:
                    raise VerifyError(
                        f"audit record limit exceeded ({_MAX_AUDIT_RECORDS})"
                    )
                if not raw_line.endswith(b"\n"):
                    raise VerifyError(
                        "audit log has a torn tail (missing final newline)"
                    )
                raw = raw_line[:-1]
                if not raw:
                    raise VerifyError(
                        f"seq {count}: audit log contains an empty physical record"
                    )
                try:
                    obj = json.loads(raw, parse_constant=_reject_nonfinite_json)
                except (json.JSONDecodeError, ValueError) as exc:
                    raise VerifyError(
                        f"seq {count}: line is not valid JSON: {exc}"
                    ) from exc
                if not isinstance(obj, dict):
                    raise VerifyError(f"seq {count}: line is not a JSON object")
                seq = obj.get("seq")
                if seq != count:
                    raise VerifyError(
                        f"seq {count}: expected seq={count}, got seq={seq!r}"
                    )
                declared_prev = obj.get("prev_hash")
                if declared_prev != prev_hash:
                    raise VerifyError(
                        f"seq {count}: prev_hash break "
                        f"(declared={declared_prev!r}, expected={prev_hash!r})"
                    )
                try:
                    canonical = canonicalize_json(obj)
                except (TypeError, ValueError) as exc:
                    raise VerifyError(
                        f"seq {count}: line contains non-JSON data: {exc}"
                    ) from exc
                if canonical != raw:
                    raise VerifyError(
                        f"seq {count}: line is not in canonical form (tampered)"
                    )

                kind = str(obj.get("kind", ""))
                payload = obj.get("payload") or {}
                if not isinstance(payload, dict):
                    raise VerifyError(f"seq {count}: payload is not a JSON object")
                if kind == "tool_call_output":
                    output_hash = payload.get("output_hash")
                    digest = (
                        output_hash
                        if _is_hex64(output_hash)
                        else _sha256_hex(canonical)
                    )
                    leaves.append(
                        DerivedLeaf(
                            seq=count,
                            kind="tool_call_output",
                            digest_hex=str(digest),
                            record_id=str(payload.get("tool_call_id", "")),
                        )
                    )
                elif kind == "finding_approved":
                    leaves.append(
                        DerivedLeaf(
                            seq=count,
                            kind="finding",
                            digest_hex=_sha256_hex(canonical),
                            record_id=str(payload.get("finding_id", "")),
                        )
                    )

                prev_hash = _sha256_hex(canonical)
                final_hash = prev_hash
                count += 1
        after_descriptor = os.fstat(descriptor)
        try:
            path_after = os.lstat(log_path)
        except OSError as exc:
            raise VerifyError(
                f"audit log changed during bounded replay: {exc}"
            ) from exc
        expected = _stat_fingerprint(path_before)
        if (
            _stat_fingerprint(after_descriptor) != expected
            or _stat_fingerprint(path_after) != expected
        ):
            raise VerifyError("audit log changed during bounded read/replay")
    finally:
        os.close(descriptor)
    if count == 0:
        raise VerifyError(f"{log_path.name}: no records")
    return leaves, count, final_hash


def _reject_nonfinite_json(value: str) -> None:
    raise ValueError(f"non-finite JSON number is forbidden: {value}")


def _merkle_root_hex(leaf_digests_hex: list[str]) -> str:
    """Rebuild the Merkle root from leaf SHA-256 digests.

    Duplicate-last odd rule; internal node = ``SHA-256(left || right)`` over raw
    32-byte digests; empty tree = 32 zero bytes. Mirrors crypto.merkle."""
    if not leaf_digests_hex:
        return "00" * 32
    tier = [bytes.fromhex(h) for h in leaf_digests_hex]
    while len(tier) > 1:
        if len(tier) % 2:
            tier.append(tier[-1])
        tier = [
            hashlib.sha256(tier[i] + tier[i + 1]).digest()
            for i in range(0, len(tier), 2)
        ]
    return tier[0].hex()


# ---------------------------------------------------------------------------
# Transparency anchor (optional Sigstore Rekor / RFC-3161) — stdlib-only and
# deliberately fail-closed. RFC-6962 path arithmetic by itself does not
# authenticate a Rekor checkpoint or bind a DSSE statement to the manifest.
# Only the product verifier, with Sigstore's trusted roots and an exact
# identity/issuer policy, can return True for this side-signal.
# ---------------------------------------------------------------------------


def _verify_rekor_inclusion(rekor: dict[str, Any]) -> bool | str:
    """Refuse to authenticate Rekor with proof arithmetic alone.

    The full Bundle is retained so an operator can pass it to the product
    verifier. Parsing it here only distinguishes missing/malformed data; it is
    never a substitute for certificate, SET/checkpoint, DSSE, and identity
    verification.
    """
    bundle_b64 = rekor.get("bundle_b64")
    if not bundle_b64:
        return (
            "rekor block missing full Sigstore bundle; normalized inclusion "
            "proof fields cannot authenticate a transparency-log entry"
        )
    try:
        raw = base64.b64decode(str(bundle_b64), validate=True)
        parsed = json.loads(raw)
        if not isinstance(parsed, dict):
            raise ValueError("Bundle JSON is not an object")
    except (ValueError, TypeError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        return f"rekor Sigstore bundle is malformed: {exc}"
    return (
        "rekor Bundle present but this zero-dependency verifier cannot "
        "authenticate it; use the full Sigstore verifier with pinned trusted "
        "roots and exact expected identity/issuer policy"
    )


def _verify_transparency_offline(
    anchor: dict[str, Any],
    merkle_root_hex: str,
    *,
    required: bool = False,
) -> bool | str:
    """Offline check of the optional transparency anchor.

    An absent unrequested/legacy anchor is vacuously True. A missing requested
    anchor fails. Rekor and RFC-3161 authentication require trusted
    cryptographic material outside this zero-dependency verifier's scope, so
    both are reported honestly as non-verified. The caller gates ``overall``
    on this result only when the signed request commitment is true.
    """
    if not isinstance(anchor, dict) or not anchor:
        if required:
            return (
                "authenticated transparency anchor was requested but "
                "transparency_log is missing"
            )
        return True
    subject = anchor.get("subject")
    subject_digest = (
        subject.get("merkle_root_sha256") if isinstance(subject, dict) else None
    )
    if str(subject_digest) != merkle_root_hex:
        return (
            f"transparency subject digest {subject_digest!r} != manifest merkle "
            f"root {merkle_root_hex!r}"
        )
    kind = anchor.get("kind")
    if kind == "none":
        return str(anchor.get("fallback_reason") or "root was not anchored")
    if kind == "rekor":
        return _verify_rekor_inclusion(anchor.get("rekor") or {})
    if kind == "rfc3161":
        return (
            "rfc3161 timestamp present; offline verification of the TSA token is "
            "out of this zero-dependency verifier's scope (needs openssl + the "
            "issuing CA chain)"
        )
    return f"unknown transparency kind {kind!r}"


# ---------------------------------------------------------------------------
# Result shape + signature verification.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class OfflineVerification:
    """Mirror of the product ``ManifestVerification`` custody fields. Each *_ok
    field is ``True`` (passed) or a reason string (failed)."""

    audit_chain_ok: bool | str
    merkle_root_ok: bool | str
    leaf_count_ok: bool | str
    signature_present: bool
    signature_payload_ok: bool | str
    signature_kind: str
    signature_verified: bool | str
    transparency_ok: bool | str
    overall: bool


_ADVISORY_SIG_KINDS = ("stub",)


def _signature_payload_status(
    sig: dict[str, Any], manifest_obj: dict[str, Any]
) -> bool | str:
    kind = str(sig.get("kind") or "stub")
    present = bool(sig.get("bundle_b64") and sig.get("payload_sha256"))
    if not present:
        return "no signature payload digest verified"
    body = {
        k: v
        for k, v in manifest_obj.items()
        if k not in ("signature", "transparency_log")
    }
    declared_payload = str(sig.get("payload_sha256") or "").lower()
    actual_payload = _sha256_hex(canonicalize_json(body))
    if declared_payload != actual_payload:
        return (
            f"{kind} signature payload digest FAILED: canonical manifest body "
            "does not match signature.payload_sha256"
        )
    return True


def _verify_signature(
    sig: dict[str, Any],
    manifest_obj: dict[str, Any],
    *,
    payload_status: bool | str | None = None,
    expected_ed25519_fingerprint: str | None = None,
) -> bool | str:
    """Honest signature-verification status.

    Ed25519 is verified locally. Stub is an explicit development advisory.
    Sigstore fails closed because this stdlib-only verifier has no trusted
    exact identity + issuer policy or Sigstore production roots with which to
    authenticate its certificate and bundle.
    """
    kind = str(sig.get("kind") or "stub")
    present = bool(sig.get("bundle_b64") and sig.get("payload_sha256"))
    if not present:
        return "no signature bundle present"
    payload_status = (
        _signature_payload_status(sig, manifest_obj)
        if payload_status is None
        else payload_status
    )
    if payload_status is not True:
        return f"{kind} verification blocked: {payload_status}"
    body = {
        k: v
        for k, v in manifest_obj.items()
        if k not in ("signature", "transparency_log")
    }
    body_bytes = canonicalize_json(body)
    if kind == "stub":
        return "stub signature: deterministic dev/offline placeholder, not cryptographic proof"
    if kind == "sigstore":
        return (
            "sigstore bundle present and recorded; offline cryptographic verification "
            "requires the full Sigstore verifier, production roots, and the expected signer "
            "identity plus exact OIDC issuer (deployment policy)"
        )
    if kind != "ed25519":
        return f"unknown signer kind {kind!r}"
    try:
        bundle_bytes = base64.b64decode(str(sig.get("bundle_b64") or ""), validate=True)
        bundle = json.loads(bundle_bytes.decode("utf-8"))
        if not isinstance(bundle, dict):
            raise ValueError("bundle JSON is not an object")
        public_key = base64.b64decode(str(bundle["public_key_b64"]), validate=True)
        signature = base64.b64decode(str(bundle["signature_b64"]), validate=True)
    except (KeyError, ValueError, TypeError, UnicodeDecodeError) as exc:
        return f"ed25519 bundle malformed: {exc}"
    actual_fingerprint = hashlib.sha256(public_key).hexdigest()
    outer_fingerprint = str(sig.get("cert_fingerprint") or "").lower()
    bundled_fingerprint = str(bundle.get("cert_fingerprint") or "").lower()
    if outer_fingerprint != actual_fingerprint:
        return "ed25519 public-key fingerprint does not match signature metadata"
    if bundled_fingerprint != actual_fingerprint:
        return "ed25519 public-key fingerprint does not match signer bundle"
    trusted_fingerprint = (
        expected_ed25519_fingerprint
        or os.environ.get("FINDEVIL_ED25519_EXPECTED_FINGERPRINT", "").strip()
    ).lower()
    if not trusted_fingerprint:
        return (
            "ed25519 verification requires an externally trusted public-key "
            "fingerprint"
        )
    if len(trusted_fingerprint) != 64 or any(
        char not in "0123456789abcdef" for char in trusted_fingerprint
    ):
        return "expected Ed25519 fingerprint is not a SHA-256 digest"
    if trusted_fingerprint != actual_fingerprint:
        return "ed25519 public key does not match the trusted fingerprint"
    if not ed25519_verify(signature, body_bytes, public_key):
        return "ed25519 signature verification FAILED: manifest body does not match the signature"
    return True


def verify_manifest_offline(
    manifest_path: Path,
    *,
    audit_log_path: Path | None = None,
    expected_ed25519_fingerprint: str | None = None,
) -> OfflineVerification:
    """Re-derive the full custody chain of ``manifest_path`` with stdlib only."""
    manifest_bytes = _read_regular_file_bounded(
        manifest_path,
        max_bytes=_MAX_MANIFEST_BYTES,
        label=f"manifest {manifest_path.name}",
    )
    try:
        manifest_text = manifest_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise VerifyError(f"{manifest_path.name}: manifest is not UTF-8") from exc
    try:
        obj = json.loads(manifest_text, parse_constant=_reject_nonfinite_json)
    except (json.JSONDecodeError, ValueError) as exc:
        raise VerifyError(
            f"{manifest_path.name}: manifest is not valid JSON: {exc}"
        ) from exc
    if not isinstance(obj, dict):
        raise VerifyError(f"{manifest_path.name}: manifest is not a JSON object")

    # 1. Locate the audit log. Precedence: explicit override -> sibling next to
    # the manifest (a copied case dir verifies anywhere) -> embedded path.
    embedded = Path(str(obj.get("audit_log_path") or ""))
    sibling = manifest_path.parent / (embedded.name or "audit.jsonl")
    log_path = audit_log_path or (sibling if sibling.is_file() else embedded)

    # 1a + 1b. Replay the chain, then re-derive count/final-hash/leaves and
    # compare to what the manifest declared.
    audit_status: bool | str
    if not (log_path and log_path.is_file()):
        audit_status = f"audit log not found at {log_path}"
        derived_leaves: list[DerivedLeaf] = []
    else:
        try:
            derived_leaves, replayed_count, replayed_final = _replay_audit_log(log_path)
            audit_status = True
        except VerifyError as exc:
            audit_status = f"audit chain break: {exc}"
            derived_leaves = []
        if audit_status is True:
            audit_status = _consistency_status(
                obj, derived_leaves, replayed_count, replayed_final
            )

    # 2. Merkle root, rebuilt from the manifest's DECLARED leaves.
    declared_leaves = obj.get("leaves", [])
    declared_root = str(obj.get("merkle_root_hex", ""))
    try:
        rebuilt = _merkle_root_hex(
            [str(leaf.get("digest_hex", "")) for leaf in declared_leaves]
        )
        merkle_status: bool | str = (
            True
            if rebuilt == declared_root
            else f"declared root {declared_root} != rebuilt {rebuilt}"
        )
    except ValueError as exc:
        merkle_status = f"merkle rebuild failed: {exc}"

    # 3. Leaf count.
    declared_count = obj.get("leaf_count")
    actual_count = len(declared_leaves)
    count_status: bool | str = (
        True
        if declared_count == actual_count
        else f"leaf_count {declared_count} != actual {actual_count}"
    )

    # 4. Signature.
    sig = obj.get("signature") or {}
    sig_present = bool(sig.get("bundle_b64") and sig.get("payload_sha256"))
    sig_kind = str(sig.get("kind") or "stub")
    sig_payload_status = _signature_payload_status(sig, obj)
    sig_verified = _verify_signature(
        sig,
        obj,
        payload_status=sig_payload_status,
        expected_ed25519_fingerprint=expected_ed25519_fingerprint,
    )

    # 5. Optional transparency anchor. The boolean request commitment is part
    # of the signed body; the proof block remains post-signing. Legacy manifests
    # omit the commitment and are treated as unrequested for compatibility.
    raw_anchor_request = obj.get("transparency_anchor_requested", False)
    anchor_request_valid = isinstance(raw_anchor_request, bool)
    anchor_required = raw_anchor_request is True
    transparency_status = _verify_transparency_offline(
        obj.get("transparency_log") or {},
        declared_root,
        required=anchor_required,
    )
    if not anchor_request_valid:
        transparency_status = "transparency_anchor_requested must be a JSON boolean"

    known_sig_kinds = {"stub", "ed25519", "sigstore"}
    sig_failed = sig_present and (
        sig_payload_status is not True
        or sig_kind not in known_sig_kinds
        or (sig_kind not in _ADVISORY_SIG_KINDS and sig_verified is not True)
    )
    overall = (
        audit_status is True
        and merkle_status is True
        and count_status is True
        and sig_present
        and not sig_failed
        and anchor_request_valid
        and (not anchor_required or transparency_status is True)
    )
    return OfflineVerification(
        audit_chain_ok=audit_status,
        merkle_root_ok=merkle_status,
        leaf_count_ok=count_status,
        signature_present=sig_present,
        signature_payload_ok=sig_payload_status,
        signature_kind=sig_kind,
        signature_verified=sig_verified,
        transparency_ok=transparency_status,
        overall=overall,
    )


def _consistency_status(
    obj: dict[str, Any],
    derived_leaves: list[DerivedLeaf],
    replayed_count: int,
    replayed_final: str,
) -> bool | str:
    """Compare re-derived count/final-hash/leaves to the manifest's declarations."""
    if replayed_count != obj.get("audit_log_record_count"):
        return (
            f"audit log has {replayed_count} record(s) but the manifest declares "
            f"{obj.get('audit_log_record_count')} (tail truncation or post-seal append)"
        )
    if replayed_final != str(obj.get("audit_log_final_hash") or ""):
        return "audit log final hash does not match the manifest's audit_log_final_hash"
    declared = [
        (
            int(leaf.get("seq", -1)),
            str(leaf.get("kind", "")),
            str(leaf.get("digest_hex", "")),
            str(leaf.get("record_id", "")),
        )
        for leaf in obj.get("leaves", [])
    ]
    if [leaf.as_tuple() for leaf in derived_leaves] != declared:
        return "leaves re-derived from the audit log do not match the manifest's declared leaves"
    return True


# ---------------------------------------------------------------------------
# --check: agreement with the committed product sidecar.
# ---------------------------------------------------------------------------

# manifest_verify.json field name -> OfflineVerification attribute. Only the
# custody/signature fields this independent verifier re-derives are compared;
# the product's separate entailment side-signal is out of this verifier's scope.
_SIDECAR_FIELD_MAP: dict[str, str] = {
    "audit_chain_ok": "audit_chain_ok",
    "merkle_root_ok": "merkle_root_ok",
    "leaf_count_ok": "leaf_count_ok",
    "signature_present": "signature_present",
    "signature_payload_ok": "signature_payload_ok",
    "signature_kind": "signature_kind",
    "signature_verified": "signature_verified",
    "transparency_ok": "transparency_ok",
    "overall": "overall",
}


def _as_bool_field(value: Any) -> bool | str:
    """The product sidecar stores each *_ok as a bare ``true`` plus an optional
    ``<field>_detail`` reason; collapse a non-true value to its boolean polarity
    so we compare pass/fail, not two differently-worded reason strings."""
    return True if value is True else False if value is False else bool(value)


def check_agreement(result: OfflineVerification, sidecar: dict[str, Any]) -> list[str]:
    """Return a list of disagreements between this verifier and the committed
    product sidecar. Empty list means full agreement on the custody fields."""
    disagreements: list[str] = []
    result_d = asdict(result)
    for sidecar_field, attr in _SIDECAR_FIELD_MAP.items():
        if sidecar_field not in sidecar:
            continue
        product_val = sidecar[sidecar_field]
        offline_val = result_d[attr]
        if sidecar_field in ("signature_present", "overall"):
            if bool(product_val) != bool(offline_val):
                disagreements.append(
                    f"{sidecar_field}: product={product_val!r} offline={offline_val!r}"
                )
        elif sidecar_field == "signature_kind":
            if str(product_val) != str(offline_val):
                disagreements.append(
                    f"{sidecar_field}: product={product_val!r} offline={offline_val!r}"
                )
        else:
            # *_ok / signature_verified: compare pass/fail polarity.
            if _as_bool_field(product_val) != _as_bool_field(offline_val):
                disagreements.append(
                    f"{sidecar_field}: product={product_val!r} offline={offline_val!r}"
                )
    return disagreements


# ---------------------------------------------------------------------------
# CLI.
# ---------------------------------------------------------------------------


def _format_field(label: str, value: bool | str) -> str:
    if value is True:
        return f"  [PASS]  {label}"
    return f"  [FAIL]  {label}  -  {value}"


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("manifest", help="path to run.manifest.json")
    parser.add_argument("--audit-log", default=None, help="override the audit log path")
    parser.add_argument(
        "--expected-ed25519-fingerprint",
        help=(
            "trusted SHA-256 fingerprint obtained outside the case artifacts; "
            "required for an Ed25519 authentication pass"
        ),
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="also assert agreement with the sibling manifest_verify.json",
    )
    parser.add_argument(
        "--json", action="store_true", help="emit JSON instead of a report"
    )
    args = parser.parse_args(argv[1:])

    # ``abspath`` normalizes the operator's path without resolving its final
    # symlink; the bounded reader must inspect and reject that pathname itself.
    manifest_path = Path(os.path.abspath(args.manifest))
    audit_log = (
        Path(os.path.abspath(Path(args.audit_log).expanduser()))
        if args.audit_log
        else None
    )

    try:
        result = verify_manifest_offline(
            manifest_path,
            audit_log_path=audit_log,
            expected_ed25519_fingerprint=args.expected_ed25519_fingerprint,
        )
    except (VerifyError, json.JSONDecodeError) as exc:
        print(f"verification could not run: {exc}", file=sys.stderr)
        return 2

    disagreements: list[str] = []
    sidecar_checked = False
    if args.check:
        sidecar_path = manifest_path.parent / "manifest_verify.json"
        try:
            sidecar_bytes = _read_regular_file_bounded(
                sidecar_path,
                max_bytes=_MAX_SIDECAR_BYTES,
                label="manifest verification sidecar",
            )
            sidecar = json.loads(
                sidecar_bytes.decode("utf-8", errors="strict"),
                parse_constant=_reject_nonfinite_json,
            )
        except (
            VerifyError,
            UnicodeDecodeError,
            json.JSONDecodeError,
            ValueError,
        ) as exc:
            print(
                f"--check: unsafe or invalid sibling manifest_verify.json: {exc}",
                file=sys.stderr,
            )
            return 2
        if not isinstance(sidecar, dict):
            print("--check: manifest_verify.json is not a JSON object", file=sys.stderr)
            return 2
        disagreements = check_agreement(result, sidecar)
        sidecar_checked = True

    if args.json:
        out = asdict(result)
        out["agrees_with_committed_sidecar"] = (
            (not disagreements) if sidecar_checked else None
        )
        out["disagreements"] = disagreements
        print(json.dumps(out, indent=2, sort_keys=True))
    else:
        print(f"offline manifest verification: {manifest_path}")
        print(
            _format_field(
                "audit chain (per-line hash chain + log/manifest consistency)",
                result.audit_chain_ok,
            )
        )
        print(_format_field("merkle root", result.merkle_root_ok))
        print(_format_field("leaf count", result.leaf_count_ok))
        print(
            f"  [{'PASS' if result.signature_present else 'FAIL'}]  signature present (kind={result.signature_kind})"
        )
        print(_format_field("signature payload digest", result.signature_payload_ok))
        print(
            _format_field(
                f"signature verified ({result.signature_kind})",
                result.signature_verified,
            )
        )
        print(
            _format_field(
                "transparency anchor (gates when signed request=true)",
                result.transparency_ok,
            )
        )
        print(f"  overall: {'PASS' if result.overall else 'FAIL'}")
        if sidecar_checked:
            if disagreements:
                print("  [FAIL]  agreement with committed manifest_verify.json:")
                for line in disagreements:
                    print(f"            - {line}")
            else:
                print(
                    "  [PASS]  agrees with committed manifest_verify.json on every custody field"
                )

    ok = result.overall and (not disagreements if sidecar_checked else True)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
