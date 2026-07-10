"""Run manifest assembly + verification.

Spec #2 §7.1 + §7.2. Ties the current custody layers together:

  * walks the hash-chained ``audit.jsonl``
  * extracts every ``tool_call_output_hash`` and every approved-
    finding hash into a Merkle tree
  * asks the ``Signer`` to sign the canonicalized manifest body
  * writes ``run.manifest.json``

Verification is the symmetric operation:

  * ``audit.verify()`` replays the chain
  * ``MerkleTree`` rebuilds from the leaves declared in the
    manifest, comparing the recomputed root to the manifest's
    ``merkle_root``
  * the signature tier is reported honestly: Ed25519 verifies offline only
    against an externally trusted public-key fingerprint,
    Sigstore verifies only against an explicit expected-identity policy,
    and stub remains a payload-bound development placeholder
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import stat
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from findevil_agent.crypto.audit_log import (
    AuditLog,
    AuditLogError,
    AuditLogSnapshot,
    canonicalize_json,
    hash_line,
)
from findevil_agent.crypto.ed25519_strict import validate_strict_ed25519_inputs
from findevil_agent.crypto.merkle import MerkleError, MerkleTree
from findevil_agent.crypto.signer import SignedBundle, Signer, StubSigner
from findevil_agent.entailment import recheck_entailment_slice

MANIFEST_VERSION = "1"
MAX_MANIFEST_BYTES = 64 * 1024 * 1024


class UncitedFindingError(ValueError):
    """Refusal to seal: a ``finding_approved`` record does not cite a
    ``tool_call_id`` recorded earlier in the audit chain. Sealing is the
    last code-enforced citation gate ("every Finding cites a
    tool_call_id"), independent of prompt discipline in interactive
    mode."""


# ---------------------------------------------------------------------------
# Dataclasses (frozen — manifests are immutable once finalized).
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ManifestLeaf:
    """One Merkle leaf — sourced from an audit-log record."""

    seq: int
    """Audit-log sequence number."""

    kind: str
    """One of: ``tool_call_output``, ``finding``."""

    digest_hex: str
    """SHA-256 hex of the leaf payload (the canonicalized record)."""

    record_id: str
    """For tool_call_output: the tool_call_id. For finding: the
    finding_id. Required for audit-trail traceability — every
    Merkle leaf links back to a specific event."""


@dataclass(frozen=True)
class RunManifest:
    """The signed run manifest.

    Field ordering matters here for human readability of the
    written JSON — sort_keys still applies during canonicalization.
    """

    version: str
    case_id: str
    run_id: str
    started_at: str
    finalized_at: str
    audit_log_path: str
    audit_log_final_hash: str
    audit_log_record_count: int
    merkle_root_hex: str
    leaf_count: int
    leaves: list[ManifestLeaf]
    transparency_anchor_requested: bool = False
    """Signed policy commitment for Merkle-root transparency anchoring.

    New manifests commit this boolean before signing. Legacy manifests that
    predate the field are interpreted as ``False``. When ``True``, verification
    requires an authenticated anchor and gates ``overall`` on it, so stripping
    the post-signing ``transparency_log`` cannot silently lower the requested
    custody tier.
    """
    signature: dict[str, Any] = field(default_factory=dict)
    """SignedBundle of the canonicalized manifest body (without the
    ``signature`` field). Filled by ``finalize`` after signing."""

    transparency_log: dict[str, Any] = field(default_factory=dict)
    """Optional Sigstore Rekor (or RFC-3161) anchor of ``merkle_root_hex``.
    Empty by default. Attached AFTER signing and EXCLUDED from the signed body
    (see ``_to_json_safe`` / ``_verify_ed25519_signature``), so it can never
    invalidate the signature. The separate signed
    ``transparency_anchor_requested`` commitment determines whether this block
    is a compatibility side-signal or a required, overall-gating proof."""

    extra: dict[str, Any] = field(default_factory=dict)
    """Free-form metadata: image_path, image_hash, model name,
    agent version, etc. Captured but not part of Merkle leaves —
    if you want it tamper-evident, sign the manifest body."""


# ---------------------------------------------------------------------------
# Build path.
# ---------------------------------------------------------------------------


AuditSource = AuditLog | AuditLogSnapshot


def _uncited_findings(audit_log: AuditSource) -> list[str]:
    """finding_approved records whose tool_call_id is absent from the chain
    so far. Chain order matters: a finding cannot cite a future tool call."""
    seen_tool_calls: set[str] = set()
    uncited: list[str] = []
    for record in audit_log.iter_records():
        if record.kind == "tool_call_output":
            tcid = str(record.payload.get("tool_call_id") or "")
            if tcid:
                seen_tool_calls.add(tcid)
        elif record.kind == "finding_approved":
            cited = str(record.payload.get("tool_call_id") or "")
            if not cited or cited not in seen_tool_calls:
                uncited.append(str(record.payload.get("finding_id") or f"seq-{record.seq}"))
    return uncited


def _walk_audit_log(audit_log: AuditSource) -> tuple[list[ManifestLeaf], int, str]:
    """Replay the audit log once: derive the Merkle-eligible leaves, count the
    records, and compute the final line hash. Shared by the build path and by
    ``verify_manifest`` so the verifier re-derives the same values the sealer
    declared, instead of trusting the manifest's own copies."""
    leaves: list[ManifestLeaf] = []
    record_count = 0
    final_hash = ""
    for record in audit_log.iter_records():
        record_count += 1
        # The audit log final hash is the hash of the line bytes for
        # the last record, computed on-the-fly because AuditLog only
        # remembers ``last_hash`` for newly-appended records, and
        # we want a value that works for the reader path too.
        canonical_line = canonicalize_json(record.to_canonical_dict())
        final_hash = hash_line(canonical_line)

        # Identify Merkle-eligible records.
        if record.kind == "tool_call_output":
            digest = _payload_digest(record.payload, "output_hash") or _record_digest(
                canonical_line
            )
            leaves.append(
                ManifestLeaf(
                    seq=record.seq,
                    kind="tool_call_output",
                    digest_hex=digest,
                    record_id=str(record.payload.get("tool_call_id", "")),
                )
            )
        elif record.kind == "finding_approved":
            digest = _record_digest(canonical_line)
            leaves.append(
                ManifestLeaf(
                    seq=record.seq,
                    kind="finding",
                    digest_hex=digest,
                    record_id=str(record.payload.get("finding_id", "")),
                )
            )
        # Other kinds (agent_message, plan_proposed, etc.) are in
        # the audit chain but not in the Merkle root — they're
        # observable via the chain hash, not separately.
    return leaves, record_count, final_hash


def build_manifest(
    *,
    case_id: str,
    run_id: str,
    started_at: str,
    audit_log: AuditSource,
    signer: Signer,
    extra: dict[str, Any] | None = None,
    transparency_anchor_requested: bool = False,
) -> RunManifest:
    """Assemble + sign a RunManifest from a finalized audit log.

    Caller is responsible for not appending to the audit log after
    this returns — manifests describe a snapshot.

    Raises :class:`UncitedFindingError` when the log contains a
    ``finding_approved`` record without a ``tool_call_id`` recorded
    earlier in the chain — an uncited finding must never be sealed.
    """
    uncited = _uncited_findings(audit_log)
    if uncited:
        raise UncitedFindingError(
            "refusing to seal: finding(s) without a tool_call_id recorded "
            f"earlier in the audit chain: {', '.join(uncited[:5])}"
        )
    leaves, record_count, final_hash = _walk_audit_log(audit_log)

    tree = MerkleTree()
    for leaf in leaves:
        tree.append(bytes.fromhex(leaf.digest_hex))
    root_hex = tree.root_hex()

    finalized_at = _utc_iso()

    body = RunManifest(
        version=MANIFEST_VERSION,
        case_id=case_id,
        run_id=run_id,
        started_at=started_at,
        finalized_at=finalized_at,
        audit_log_path=audit_log.path.name,
        audit_log_final_hash=final_hash,
        audit_log_record_count=record_count,
        merkle_root_hex=root_hex,
        leaf_count=len(leaves),
        leaves=leaves,
        transparency_anchor_requested=transparency_anchor_requested,
        signature={},
        extra=extra or {},
    )

    # Sign the canonicalized body sans signature.
    body_bytes = canonicalize_json(_to_json_safe(body, exclude_signature=True))
    bundle: SignedBundle = signer.sign(body_bytes)

    # Re-construct with signature populated.
    signed_body = RunManifest(
        version=body.version,
        case_id=body.case_id,
        run_id=body.run_id,
        started_at=body.started_at,
        finalized_at=body.finalized_at,
        audit_log_path=body.audit_log_path,
        audit_log_final_hash=body.audit_log_final_hash,
        audit_log_record_count=body.audit_log_record_count,
        merkle_root_hex=body.merkle_root_hex,
        leaf_count=body.leaf_count,
        leaves=body.leaves,
        transparency_anchor_requested=body.transparency_anchor_requested,
        signature={
            "payload_sha256": bundle.payload_sha256,
            "bundle_b64": bundle.bundle_b64,
            "cert_fingerprint": bundle.cert_fingerprint,
            "signed_at": bundle.signed_at,
            "kind": bundle.kind,
            # Only present when a sigstore attempt honestly degraded to stub.
            **(
                {"fallback_reason": bundle.fallback_reason}
                if bundle.fallback_reason is not None
                else {}
            ),
        },
        extra=body.extra,
    )
    return signed_body


def write_manifest(manifest: RunManifest, path: Path) -> Path:
    """Write the manifest to ``path`` as canonical pretty JSON."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(_to_json_safe(manifest), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="",
    )
    return path


# ---------------------------------------------------------------------------
# Verify path.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ManifestVerification:
    """Result of ``verify_manifest``. Each field is either ``True``
    (passed) or a reason string explaining the failure."""

    audit_chain_ok: bool | str
    merkle_root_ok: bool | str
    leaf_count_ok: bool | str
    signature_present: bool
    signature_payload_ok: bool | str = "no signature payload digest verified"
    """Whether ``signature.payload_sha256`` matches the canonical body."""
    signature_kind: str = "stub"
    """Which signer sealed the run: ``"ed25519"``, ``"sigstore"``, or
    ``"stub"`` (default for pre-``kind`` manifests)."""
    signature_verified: bool | str = (
        "stub signature: deterministic dev/offline placeholder, not cryptographic proof"
    )
    """Honest cryptographic-verification status. ``True`` only when a real
    pinned Ed25519 bundle verifies offline; otherwise a reason string. A stub bundle
    is never ``True``, and a Sigstore bundle reports that identity-policy-aware
    verification is required — this field stops the chain from *implying* proof
    a placeholder or unbound identity bundle can't provide. It gates
    ``overall`` for the Ed25519 and Sigstore cryptographic tiers; a stub remains
    a development advisory only when its payload digest matches."""
    entailment_ok: bool | str = True
    """Offline re-verification of the sealed entailment slices: re-runs the
    matcher over the matched evidence values recorded in the audit chain
    (no tool re-run) and confirms each still entails its finding. ``True`` when
    every slice re-checks (and vacuously when a run carries none). It is a
    separate honest signal and does NOT gate
    ``overall``; byte-tampering of a slice is already caught by the Merkle
    root, so this reports the semantic check."""
    transparency_ok: bool | str = True
    """Verification of the optional transparency block. Authenticated Rekor
    Bundles can return ``True`` under exact identity + issuer policy. RFC-3161
    is structural-imprint-only until a trusted TSA chain is configured. Legacy
    runs without an anchor are vacuously ``True``; a signed request commitment
    can make a missing/invalid anchor fail the requested tier."""
    overall: bool = False


def _verify_entailment_slices(audit_log: AuditSource) -> bool | str:
    """Re-verify every sealed entailment slice in the audit chain offline.

    Each ``replay`` record carries the replay artifact, whose ``entailment``
    slice (when present) is the value the parser re-extracted from the evidence.
    Re-running the matcher over those sealed values confirms — with no tool
    re-run — that the facts sealed into the signed chain still entail their
    findings. Returns ``True`` (all slices re-check, or none present) or the
    first failure reason."""
    for record in audit_log.iter_records():
        if record.kind != "replay":
            continue
        artifact = record.payload.get("replay_artifact")
        if not isinstance(artifact, dict):
            continue
        slice_ = artifact.get("entailment")
        if slice_ is None:
            continue
        result = recheck_entailment_slice(slice_)
        if result is not True:
            fid = (
                record.payload.get("finding_id")
                or artifact.get("tool_call_id")
                or f"seq-{record.seq}"
            )
            return f"entailment re-check failed for {fid}: {result}"
    return True


def _read_manifest_object(path: Path) -> dict[str, Any]:
    """Read one regular, non-linked manifest through a bounded stable descriptor."""
    manifest_path = Path(os.path.abspath(path.expanduser()))
    try:
        path_before = os.lstat(manifest_path)
    except OSError as exc:
        raise ValueError(f"cannot inspect manifest safely: {exc}") from exc
    if stat.S_ISLNK(path_before.st_mode) or not stat.S_ISREG(path_before.st_mode):
        raise ValueError("manifest must be a regular file, not a symlink")
    if path_before.st_nlink != 1:
        raise ValueError("manifest must not be hard-linked")

    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_BINARY", 0)
    )
    try:
        descriptor = os.open(manifest_path, flags)
    except OSError as exc:
        raise ValueError(f"cannot open manifest safely: {exc}") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise ValueError("manifest must be one non-hard-linked regular file")
        if before.st_size > MAX_MANIFEST_BYTES:
            raise ValueError(f"manifest size limit exceeded ({MAX_MANIFEST_BYTES} bytes)")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            raw = stream.read(MAX_MANIFEST_BYTES + 1)
        after = os.fstat(descriptor)
        if not stat.S_ISREG(after.st_mode) or after.st_nlink != 1:
            raise ValueError("manifest changed while it was being read")
    finally:
        os.close(descriptor)

    try:
        path_after = os.lstat(manifest_path)
    except OSError as exc:
        raise ValueError(f"manifest path changed while reading: {exc}") from exc
    if (
        stat.S_ISLNK(path_after.st_mode)
        or not stat.S_ISREG(path_after.st_mode)
        or path_after.st_nlink != 1
    ):
        raise ValueError("manifest changed while it was being read")
    stable_fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
    before_identity = tuple(getattr(before, field) for field in stable_fields)
    after_identity = tuple(getattr(after, field) for field in stable_fields)
    path_identity = tuple(getattr(path_after, field) for field in stable_fields)
    # The open descriptor must not have changed across the bounded read (fd-vs-fd
    # comparison, valid on every platform).
    if before_identity != after_identity:
        raise ValueError("manifest changed while it was being read")
    # On POSIX the descriptor and the path must additionally resolve to the same
    # underlying file. Windows populates st_ino/st_*time_ns differently through
    # fstat than through lstat, so this cross-flavor equality is POSIX-only to
    # avoid a false positive with no concurrent writer.
    if os.name != "nt" and after_identity != path_identity:
        raise ValueError("manifest changed while it was being read")
    if len(raw) != before.st_size or len(raw) > MAX_MANIFEST_BYTES:
        raise ValueError(f"manifest size limit exceeded ({MAX_MANIFEST_BYTES} bytes)")
    try:
        obj = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"manifest is not valid UTF-8 JSON: {exc}") from exc
    if not isinstance(obj, dict):
        raise ValueError("manifest must contain one JSON object")
    return obj


def verify_manifest(
    manifest_path: Path,
    *,
    audit_log_path: Path | None = None,
    expected_ed25519_fingerprint: str | None = None,
    expected_sigstore_identity: str | None = None,
    expected_sigstore_issuer: str | None = None,
) -> ManifestVerification:
    """Run the offline-verifiable parts of Spec #2 §7.2.

    Returns:
      * ``audit_chain_ok``: True if the linked audit log replays
        cleanly, else the AuditLogError message.
      * ``merkle_root_ok``: True if leaves declared in the manifest
        rebuild to the manifest's ``merkle_root_hex``, else a reason.
      * ``leaf_count_ok``: True if ``leaves`` length matches
        ``leaf_count``, else a reason.
      * ``signature_present``: True if ``signature`` is non-empty.
      * ``signature_payload_ok``: True when the declared payload digest binds
        the canonical signed body.
      * ``signature_verified``: True for a verified Ed25519 manifest or for a
        Sigstore bundle authenticated against the explicit expected identity;
        stub returns an honest development-placeholder reason.
      * ``overall``: chain + Merkle root + leaf count + payload digest verify;
        Ed25519/Sigstore additionally require cryptographic verification. Stub
        is advisory only after its payload digest passes. A signed request for
        transparency anchoring additionally requires a valid authenticated
        anchor. ``entailment_ok`` is reported as a separate non-gating
        side-signal.
    """
    obj = _read_manifest_object(manifest_path)

    # 1. Audit chain. Precedence: explicit override → the audit log sitting
    # next to the manifest (a copied case dir verifies on any machine; the
    # chain itself proves it is the right file) → the embedded absolute path.
    embedded = Path(obj.get("audit_log_path") or "")
    sibling = manifest_path.parent / (embedded.name or "audit.jsonl")
    log_path = audit_log_path or (sibling if sibling.is_file() else embedded)
    audit_status: bool | str = "audit_log_path missing"
    entailment_status: bool | str = True
    if log_path and log_path.is_file():
        try:
            # Verify once and derive every downstream custody signal from the
            # same frozen record set. Reopening between these passes allowed a
            # path swap to mix a verified chain with unverified later records.
            snapshot = AuditLog.read_verified_snapshot(log_path)
            audit_status = True
            derived, replayed_count, replayed_final = _walk_audit_log(snapshot)
            entailment_status = _verify_entailment_slices(snapshot)
        except AuditLogError as exc:
            audit_status = f"audit chain break: {exc}"

    # 1b. Log-vs-manifest consistency. A tail-truncated log still replays
    # prefix-cleanly, and a forged-but-internally-consistent leaf set still
    # rebuilds its own root — so re-derive count, final hash, and leaves from
    # the actual log and compare them to what the manifest declared.
    if audit_status is True:
        declared_count = obj.get("audit_log_record_count")
        declared_final = str(obj.get("audit_log_final_hash") or "")
        declared_leaves = [
            (
                int(leaf.get("seq", -1)),
                str(leaf.get("kind", "")),
                str(leaf.get("digest_hex", "")),
                str(leaf.get("record_id", "")),
            )
            for leaf in obj.get("leaves", [])
        ]
        derived_leaves = [
            (leaf.seq, leaf.kind, leaf.digest_hex, leaf.record_id) for leaf in derived
        ]
        if replayed_count != declared_count:
            audit_status = (
                f"audit log has {replayed_count} record(s) but the manifest "
                f"declares {declared_count} (tail truncation or post-seal append)"
            )
        elif replayed_final != declared_final:
            audit_status = "audit log final hash does not match the manifest's audit_log_final_hash"
        elif derived_leaves != declared_leaves:
            audit_status = (
                "leaves re-derived from the audit log do not match the manifest's declared leaves"
            )

    # 2. Merkle root.
    declared_root = obj.get("merkle_root_hex", "")
    leaves = obj.get("leaves", [])
    tree = MerkleTree()
    rebuild_status: bool | str = True
    try:
        for leaf in leaves:
            digest_hex = leaf.get("digest_hex", "")
            tree.append(bytes.fromhex(digest_hex))
        rebuilt = tree.root_hex()
        if rebuilt != declared_root:
            rebuild_status = f"declared root {declared_root} != rebuilt {rebuilt}"
    except (MerkleError, ValueError) as exc:
        rebuild_status = f"merkle rebuild failed: {exc}"

    # 3. Leaf count.
    declared_count = obj.get("leaf_count")
    actual_count = len(leaves)
    count_status: bool | str = True
    if declared_count != actual_count:
        count_status = f"leaf_count {declared_count} != actual {actual_count}"

    # 4. Signature presence + honest verification status.
    sig = obj.get("signature") or {}
    sig_present = bool(sig.get("bundle_b64") and sig.get("payload_sha256"))
    sig_kind = str(sig.get("kind") or "stub")
    sig_payload_ok = _signature_payload_verified(sig_present, sig, obj)
    sig_verified = (
        _signature_verified(
            sig_present,
            sig_kind,
            sig,
            obj,
            expected_ed25519_fingerprint=expected_ed25519_fingerprint,
            expected_sigstore_identity=expected_sigstore_identity,
            expected_sigstore_issuer=expected_sigstore_issuer,
        )
        if sig_payload_ok is True
        else f"{sig_kind} verification blocked: {sig_payload_ok}"
    )

    # 5. Offline entailment re-verification (separate honest signal, like
    # signature_verified — does NOT gate overall). Vacuously True when the log
    # is unreadable (the chain failure above is the real error) or carries no
    # slices (pre-entailment runs stay verifiable end-to-end).
    if audit_status is not True and entailment_status is True:
        entailment_status = "entailment re-check blocked: audit chain did not verify"

    # 6. Optional transparency anchor. New manifests sign a boolean policy
    # commitment before the after-signing proof is attached. A requested
    # anchor therefore gates overall and cannot be stripped without leaving a
    # signed request behind. Legacy manifests omit the commitment and are
    # treated as unrequested; manually attached anchors remain non-gating
    # compatibility side-signals.
    transparency_status: bool | str = True
    raw_anchor_request = obj.get("transparency_anchor_requested", False)
    anchor_request_valid = isinstance(raw_anchor_request, bool)
    anchor_required = raw_anchor_request is True
    anchor = obj.get("transparency_log") or {}
    if not anchor_request_valid:
        transparency_status = "transparency_anchor_requested must be a JSON boolean"
    elif anchor:
        from findevil_agent.crypto.anchor import verify_anchor

        transparency_status = verify_anchor(
            anchor,
            declared_root,
            expected_identity=expected_sigstore_identity,
            expected_issuer=expected_sigstore_issuer,
        )
    elif anchor_required:
        transparency_status = (
            "authenticated transparency anchor was requested but transparency_log is missing"
        )

    # Stub remains an explicit development tier, but even its declared payload
    # digest must match. Ed25519 and Sigstore are cryptographic tiers and never
    # pass overall unless verification succeeds. In particular, a `kind` label
    # plus arbitrary Sigstore-shaped bytes is not authentication.
    known_sig_kinds = {"stub", "ed25519", "sigstore"}
    sig_failed = bool(
        sig_present
        and (
            sig_payload_ok is not True
            or sig_kind not in known_sig_kinds
            or (sig_kind in {"ed25519", "sigstore"} and sig_verified is not True)
        )
    )
    overall = (
        audit_status is True
        and rebuild_status is True
        and count_status is True
        and sig_present
        and not sig_failed
        and anchor_request_valid
        and (not anchor_required or transparency_status is True)
    )
    return ManifestVerification(
        audit_chain_ok=audit_status,
        merkle_root_ok=rebuild_status,
        leaf_count_ok=count_status,
        signature_present=sig_present,
        signature_payload_ok=sig_payload_ok,
        signature_kind=sig_kind,
        signature_verified=sig_verified,
        entailment_ok=entailment_status,
        transparency_ok=transparency_status,
        overall=overall,
    )


def _signature_verified(
    present: bool,
    kind: str,
    sig: dict[str, Any] | None = None,
    manifest_obj: dict[str, Any] | None = None,
    *,
    expected_ed25519_fingerprint: str | None = None,
    expected_sigstore_identity: str | None = None,
    expected_sigstore_issuer: str | None = None,
) -> bool | str:
    """Honest answer to 'was the signature cryptographically verified?'.

    Never returns ``True`` for a stub (a deterministic placeholder is not
    proof) and never falsely claims to have verified a sigstore bundle it did
    not. An ``ed25519`` bundle is accepted only when its signature verifies and
    the public-key SHA-256 matches an external trusted pin. Embedding a public
    key proves self-consistency, not key continuity. A Sigstore bundle is
    accepted only after full offline Bundle verification against production
    roots and an exact expected identity plus OIDC issuer. Without both policy
    values it fails closed rather than trusting bundle presence.
    """
    if not present:
        return "no signature bundle present"
    if kind == "stub":
        return "stub signature: deterministic dev/offline placeholder, not cryptographic proof"
    if kind == "ed25519":
        return _verify_ed25519_signature(
            sig or {},
            manifest_obj or {},
            expected_fingerprint=expected_ed25519_fingerprint,
        )
    if kind == "sigstore":
        return _verify_sigstore_signature(
            sig or {},
            manifest_obj or {},
            expected_identity=expected_sigstore_identity,
            expected_issuer=expected_sigstore_issuer,
        )
    return f"unknown signer kind {kind!r}"


def _signed_body(manifest_obj: dict[str, Any]) -> bytes:
    body = {
        key: value
        for key, value in manifest_obj.items()
        if key not in ("signature", "transparency_log")
    }
    return canonicalize_json(body)


def _signature_payload_verified(
    present: bool,
    sig: dict[str, Any],
    manifest_obj: dict[str, Any],
) -> bool | str:
    if not present:
        return "no signature bundle present"
    declared = str(sig.get("payload_sha256") or "").lower()
    if re.fullmatch(r"[0-9a-f]{64}", declared) is None:
        return "signature payload_sha256 is not a SHA-256 digest"
    actual = hashlib.sha256(_signed_body(manifest_obj)).hexdigest()
    if not hmac.compare_digest(declared, actual):
        return (
            "signature payload digest FAILED: canonical manifest body does not "
            "match signature.payload_sha256"
        )
    return True


def _verify_sigstore_signature(
    sig: dict[str, Any],
    manifest_obj: dict[str, Any],
    *,
    expected_identity: str | None,
    expected_issuer: str | None,
) -> bool | str:
    """Verify a Sigstore bundle offline against an explicit identity policy."""
    import base64

    identity = (
        expected_identity or os.environ.get("FINDEVIL_SIGSTORE_EXPECTED_IDENTITY", "").strip()
    )
    issuer = expected_issuer or os.environ.get("FINDEVIL_SIGSTORE_EXPECTED_ISSUER", "").strip()
    if not identity:
        return (
            "sigstore verification requires FINDEVIL_SIGSTORE_EXPECTED_IDENTITY "
            "or an explicit expected_sigstore_identity policy"
        )
    if not issuer:
        return (
            "sigstore verification requires FINDEVIL_SIGSTORE_EXPECTED_ISSUER "
            "or an explicit expected_sigstore_issuer policy; identity and issuer "
            "must both be pinned"
        )
    try:
        from sigstore.models import Bundle
        from sigstore.verify import Verifier
        from sigstore.verify.policy import Identity

        raw_bundle = base64.b64decode(str(sig.get("bundle_b64") or ""), validate=True).decode(
            "utf-8"
        )
        bundle = Bundle.from_json(raw_bundle)
        policy = Identity(identity=identity, issuer=issuer)
        Verifier.production(offline=True).verify_artifact(
            _signed_body(manifest_obj), bundle, policy
        )
    except Exception as exc:
        return f"sigstore signature verification failed: {exc}"
    return True


def _verify_ed25519_signature(
    sig: dict[str, Any],
    manifest_obj: dict[str, Any],
    *,
    expected_fingerprint: str | None,
) -> bool | str:
    """Offline cryptographic verification of a LocalEd25519Signer bundle.

    Rebuilds the exact bytes that were signed — the VERDICT canonical JSON v1 manifest
    body with the ``signature`` field removed (mirror of ``build_manifest``,
    which signs ``canonicalize_json(_to_json_safe(body, exclude_signature=True))``)
    — and verifies the embedded Ed25519 signature against the embedded public
    key. Returns ``True`` only when the signature is genuine and that key
    matches an externally supplied trusted fingerprint.
    """
    import base64

    try:
        bundle = json.loads(
            base64.b64decode(str(sig.get("bundle_b64") or ""), validate=True).decode("utf-8")
        )
        public_key = base64.b64decode(bundle["public_key_b64"], validate=True)
        signature = base64.b64decode(bundle["signature_b64"], validate=True)
    except (KeyError, ValueError, TypeError) as exc:
        return f"ed25519 bundle malformed: {exc}"
    if not isinstance(bundle, dict) or len(public_key) != 32 or len(signature) != 64:
        return "ed25519 bundle malformed: key/signature length is invalid"

    actual_fingerprint = hashlib.sha256(public_key).hexdigest()
    outer_fingerprint = str(sig.get("cert_fingerprint") or "").lower()
    bundled_fingerprint = str(bundle.get("cert_fingerprint") or "").lower()
    if not hmac.compare_digest(outer_fingerprint, actual_fingerprint):
        return "ed25519 public-key fingerprint does not match signature metadata"
    if not hmac.compare_digest(bundled_fingerprint, actual_fingerprint):
        return "ed25519 public-key fingerprint does not match signer bundle"

    configured_fingerprint = (
        os.environ.get("FINDEVIL_ED25519_EXPECTED_FINGERPRINT", "").strip().lower()
    )
    supplied_fingerprint = str(expected_fingerprint or "").strip().lower()
    if (
        configured_fingerprint
        and supplied_fingerprint
        and not hmac.compare_digest(configured_fingerprint, supplied_fingerprint)
    ):
        return "expected Ed25519 fingerprint conflicts with configured trust policy"
    trusted_fingerprint = configured_fingerprint or supplied_fingerprint
    if not trusted_fingerprint:
        return (
            "ed25519 verification requires an externally trusted public-key "
            "fingerprint; pass expected_ed25519_fingerprint or set "
            "FINDEVIL_ED25519_EXPECTED_FINGERPRINT"
        )
    if re.fullmatch(r"[0-9a-f]{64}", trusted_fingerprint) is None:
        return "expected Ed25519 fingerprint is not a SHA-256 digest"
    if not hmac.compare_digest(trusted_fingerprint, actual_fingerprint):
        return "ed25519 public key does not match the trusted fingerprint"
    # Mirror the sign path: the signed body excludes BOTH ``signature`` and the
    # after-signing ``transparency_log`` anchor, so exclude both when rebuilding
    # the bytes to verify. (See ``_to_json_safe(exclude_signature=True)``.)
    body_bytes = _signed_body(manifest_obj)
    strict_error = validate_strict_ed25519_inputs(public_key, signature)
    if strict_error is not None:
        return f"ed25519 signature inputs rejected: {strict_error}"
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        pub = Ed25519PublicKey.from_public_bytes(public_key)
        pub.verify(signature, body_bytes)
    except InvalidSignature:
        return "ed25519 signature verification FAILED: manifest body does not match the signature"
    except Exception as exc:  # key decode / import errors — honest reason, never a crash
        return f"ed25519 signature verification failed: {exc}"
    return True


# ---------------------------------------------------------------------------
# Helpers.
# ---------------------------------------------------------------------------


def _payload_digest(payload: dict[str, Any], key: str) -> str | None:
    val = payload.get(key)
    if isinstance(val, str) and len(val) == 64:
        try:
            bytes.fromhex(val)
            return val
        except ValueError:
            return None
    return None


def _record_digest(canonical_line: bytes) -> str:
    return hashlib.sha256(canonical_line).hexdigest()


def _to_json_safe(manifest: RunManifest, *, exclude_signature: bool = False) -> dict[str, Any]:
    """Convert the dataclass to a JSON-safe dict.

    Used both for canonicalizing-then-signing (with
    ``exclude_signature=True``) and for the on-disk write (with
    the signature included).
    """
    out: dict[str, Any] = asdict(manifest)
    if exclude_signature:
        out.pop("signature", None)
        # The transparency anchor is attached AFTER signing, so it must never be
        # part of the signed bytes — strip it on the sign/verify path exactly
        # like ``signature``. The on-disk write (exclude_signature=False) keeps
        # both, so a re-write that adds the anchor does not invalidate the
        # already-computed signature.
        out.pop("transparency_log", None)
    return out


def _utc_iso() -> str:
    from datetime import UTC, datetime

    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


__all__ = [
    "MANIFEST_VERSION",
    "ManifestLeaf",
    "ManifestVerification",
    "RunManifest",
    "UncitedFindingError",
    "build_manifest",
    "verify_manifest",
    "write_manifest",
]


# Convenience for one-shot demo.
def _demo_run() -> None:  # pragma: no cover
    import tempfile

    with tempfile.TemporaryDirectory() as td:
        log = AuditLog(Path(td) / "audit.jsonl")
        log.append(
            "tool_call_start",
            {"tool_call_id": "tc-1", "tool": "evtx_query"},
        )
        log.append(
            "tool_call_output",
            {
                "tool_call_id": "tc-1",
                "output_hash": "a" * 64,
            },
        )
        log.append(
            "finding_approved",
            {"finding_id": "f-1", "tool_call_id": "tc-1"},
        )
        signer = StubSigner(run_id="demo")
        m = build_manifest(
            case_id="case-1",
            run_id="demo",
            started_at="2026-04-24T00:00:00Z",
            audit_log=log,
            signer=signer,
            extra={"image_path": "/tmp/x.e01"},
        )
        path = write_manifest(m, Path(td) / "run.manifest.json")
        result = verify_manifest(path)
        print(result)
