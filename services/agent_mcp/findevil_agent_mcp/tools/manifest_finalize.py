"""``manifest_finalize`` tool — build, sign, and write run.manifest.json.

Wraps :func:`findevil_agent.crypto.manifest.build_manifest` plus
:func:`write_manifest`. Three signer modes are exposed:

* ``signer="ed25519"`` — default real local-keypair signature; authenticates
  only against a trusted public-key fingerprint supplied outside the bundle.
* ``signer="sigstore"`` — keyless sigstore signing via Fulcio + Rekor;
  the customer-release identity + transparency-log tier.
* ``signer="stub"`` — deterministic ``StubSigner``; used by tests
  and explicit dry-runs. Requires no network and produces a deterministic
  bundle keyed on the ``run_id`` for replay, but is never cryptographic proof.

The choice is exposed at the tool boundary because the agent often
wants to distinguish local integrity proof, customer-release identity proof,
and test-only placeholders.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import replace
from pathlib import Path
from typing import Any, Literal

from findevil_agent.crypto.anchor import (
    anchor_merkle_root,
    require_rekor_enabled,
)
from findevil_agent.crypto.audit_log import AuditLog, AuditLogSnapshot
from findevil_agent.crypto.manifest import build_manifest, write_manifest
from findevil_agent.crypto.signer import FallbackSigner, Signer, StubSigner, make_signer
from pydantic import BaseModel, ConfigDict, Field

from findevil_agent_mcp.tools._base import ToolSpec

# Explicit opt-in for tests / deterministic dry-runs. Without this, a model
# that passes signer:"stub" is coerced to ed25519 so local seals stay real.
_STUB_ALLOW_ENV = "FINDEVIL_ALLOW_STUB_SIGNER"


class ManifestWorkflowError(RuntimeError):
    """The audit chain lacks controller-authenticated workflow prerequisites."""


def validate_manifest_workflow(log: AuditLog | AuditLogSnapshot) -> None:
    """Require verifier acceptance, handoff, and report QA before sealing.

    This is defense in depth behind the private controller capability: even a
    buggy controller cannot turn an uncited or unverified model assertion into
    signed provenance merely by appending ``finding_approved``.
    """
    verifier_actions: dict[str, str] = {}
    verifier_handoffs: dict[str, str] = {}
    report_qa_seen = False
    for record in log.iter_records():
        payload = record.payload
        if record.kind == "verifier_action":
            finding_id = str(payload.get("finding_id") or "")
            action = str(payload.get("action") or payload.get("verifier_action") or "")
            replay = payload.get("replay_artifact")
            entailment = replay.get("entailment") if isinstance(replay, dict) else None
            replay_matched = payload.get("replay_matched") is True or (
                isinstance(replay, dict) and replay.get("matched") is True
            )
            entailment_ok = not isinstance(entailment, dict) or entailment.get("passed") is True
            if (
                finding_id
                and action in {"approved", "downgraded"}
                and replay_matched
                and entailment_ok
            ):
                verifier_actions[finding_id] = action
        elif record.kind == "acp_handoff":
            finding_id = str(payload.get("correlation_id") or "")
            nested = payload.get("payload")
            if (
                payload.get("from_role") == "verifier"
                and payload.get("to_role") == "judge"
                and isinstance(nested, dict)
                and str(nested.get("finding_id") or "") == finding_id
            ):
                verifier_handoffs[finding_id] = str(nested.get("action") or "")
        elif record.kind == "finding_approved":
            finding_id = str(payload.get("finding_id") or f"seq-{record.seq}")
            action = verifier_actions.get(finding_id)
            if action not in {"approved", "downgraded"}:
                raise ManifestWorkflowError(
                    f"finding {finding_id} lacks a successful verifier replay"
                )
            if verifier_handoffs.get(finding_id) != action:
                raise ManifestWorkflowError(
                    f"finding {finding_id} lacks its verifier-to-judge handoff"
                )
        elif record.kind == "report_qa":
            report = payload.get("report_qa")
            declared = str(payload.get("report_qa_sha256") or "")
            if not isinstance(report, dict):
                raise ManifestWorkflowError("report_qa record lacks its QA document")
            actual = hashlib.sha256(
                json.dumps(report, separators=(",", ":"), sort_keys=True).encode("utf-8")
            ).hexdigest()
            if declared != actual:
                raise ManifestWorkflowError("report_qa digest does not match its QA document")
            report_qa_seen = True
    if not report_qa_seen:
        raise ManifestWorkflowError("an audited report_qa record is required before sealing")


def _stub_signer_allowed() -> bool:
    return os.environ.get(_STUB_ALLOW_ENV, "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def _resolve_signer_request(requested: str) -> tuple[str, str | None]:
    """Return (effective_request, coerce_reason).

    Coerces ``stub`` → ``ed25519`` unless :envvar:`FINDEVIL_ALLOW_STUB_SIGNER`
    is set. Does not alter sigstore/ed25519 requests.
    """
    if requested != "stub":
        return requested, None
    if _stub_signer_allowed():
        return "stub", None
    return (
        "ed25519",
        f"stub coerced to ed25519 (set {_STUB_ALLOW_ENV}=1 for the test-only stub placeholder)",
    )


class ManifestFinalizeInput(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    case_id: str = Field(..., description="UUID4 of the case.", min_length=1)
    run_id: str = Field(..., description="Run identifier (UUID4 or ULID).", min_length=1)
    started_at: str = Field(..., description="UTC ISO-8601Z timestamp of run start.", min_length=1)
    audit_log_path: str = Field(..., description="Absolute path to audit.jsonl.")
    output_path: str = Field(..., description="Where to write run.manifest.json.")
    signer: Literal["stub", "ed25519", "sigstore"] = Field(
        default="ed25519",
        description=(
            "ed25519 = REAL local-keypair signature, verifies offline against a trusted fingerprint (default); "
            "sigstore = keyless Fulcio+Rekor, identity + transparency log "
            "(Spec #2 §7.1 tier 1; the customer-release tier); "
            "stub = deterministic test placeholder (explicit opt-in, never proof)."
        ),
    )
    extra: dict[str, Any] = Field(
        default_factory=dict,
        description="Free-form metadata embedded in the manifest (image_path, model, etc.).",
    )
    anchor_transparency: bool = Field(
        default=False,
        description=(
            "OPT-IN: publish the audit Merkle root to a public Sigstore Rekor "
            "transparency log. The RFC-3161 fallback records only a structural "
            "imprint until a TSA chain is pinned; it is not authenticated time. "
            "Absent by default — when false no network is touched. The request "
            "boolean is committed inside the signed manifest body so a requested "
            "anchor cannot be stripped as a silent downgrade. Requires the "
            "operator to also set FINDEVIL_REKOR_ENABLE=1; requesting it without "
            "that opt-in fails closed. Only the bare 32-byte SHA-256 root leaves "
            "the host (no evidence text). The proof block is attached AFTER "
            "signing and excluded from the signed body; the request commitment "
            "itself is signed and gates verification when true."
        ),
    )


class ManifestFinalizeOutput(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    manifest_path: str
    merkle_root_hex: str
    leaf_count: int
    audit_log_record_count: int
    audit_log_final_hash: str
    signature_payload_sha256: str = Field(
        ..., description="SHA-256 of the canonicalized signed body."
    )
    signature_cert_fingerprint: str | None = Field(
        default=None,
        description=(
            "SHA-256 fingerprint of the Sigstore certificate or Ed25519 public key; "
            "null only when the signer produced no fingerprint."
        ),
    )
    signer_effective: str = Field(
        default="stub",
        description=(
            "Signer that ACTUALLY sealed the run ('sigstore', 'ed25519' or 'stub'). "
            "May differ from the requested signer: a failed request honestly degrades "
            "(sigstore -> ed25519 -> stub) when Fulcio/Rekor, an OIDC token, or the "
            "local signing key is unavailable."
        ),
    )
    fallback_reason: str | None = Field(
        default=None,
        description="Why the requested signer degraded, when it did; null otherwise.",
    )
    transparency_requested: bool = Field(
        default=False,
        description=(
            "The signed transparency-anchor policy commitment. When true, "
            "manifest_verify requires an authenticated anchor for overall=True."
        ),
    )
    transparency_anchored: bool = Field(
        default=False,
        description=(
            "True iff an authenticated Rekor transparency anchor was attached. "
            "An RFC-3161 fallback remains structural-only until a pinned TSA "
            "certificate chain is verified."
        ),
    )
    transparency_kind: str | None = Field(
        default=None,
        description=(
            "The transparency proof kind actually recorded: 'rekor', 'rfc3161', "
            "'none' (attempted but failed), or null when anchoring was not requested."
        ),
    )


async def _handle(inp: BaseModel) -> ManifestFinalizeOutput:
    assert isinstance(inp, ManifestFinalizeInput)
    log = AuditLog(Path(inp.audit_log_path))
    reserved_custody = (
        os.environ.get("FINDEVIL_CUSTODY_BOUNDARY", "").strip() == "reserved_case"
        and len(os.environ.get("FINDEVIL_CONTROLLER_CAPABILITY", "")) == 64
    )
    # sigstore lazy-imports its identity token from $SIGSTORE_ID_TOKEN inside
    # the signer; ed25519 signs with the local keypair (offline). Requests are
    # wrapped so a failed signer honestly degrades — sigstore -> ed25519 ->
    # stub, ed25519 -> stub — with the reason recorded; never crashes the run.
    # Agent-supplied signer:"stub" is coerced to ed25519 unless the operator
    # explicitly opts into the test placeholder via FINDEVIL_ALLOW_STUB_SIGNER.
    requested, coerce_reason = _resolve_signer_request(inp.signer)
    if requested == "stub":
        signer: Signer = StubSigner(run_id=inp.run_id)
    elif requested == "ed25519":
        signer = FallbackSigner(make_signer(kind="ed25519"), StubSigner(run_id=inp.run_id))
    else:  # sigstore
        signer = FallbackSigner(
            make_signer(kind="sigstore"),
            FallbackSigner(make_signer(kind="ed25519"), StubSigner(run_id=inp.run_id)),
        )

    # Verify once and hold a shared writer/file lock while workflow checks,
    # leaf derivation, and signing consume one immutable record snapshot.
    with log.verified_snapshot() as sealed_log:
        if reserved_custody:
            validate_manifest_workflow(sealed_log)
        manifest = build_manifest(
            case_id=inp.case_id,
            run_id=inp.run_id,
            started_at=inp.started_at,
            audit_log=sealed_log,
            signer=signer,
            extra=inp.extra,
            transparency_anchor_requested=inp.anchor_transparency,
        )
    sig = manifest.signature or {}
    signer_effective = str(sig.get("kind") or "stub")
    if (
        os.environ.get("FINDEVIL_CUSTODY_BOUNDARY", "").strip() == "reserved_case"
        and signer_effective != inp.signer
    ):
        raise RuntimeError(
            "reserved custody signer degraded: "
            f"requested {inp.signer}, effective {signer_effective}; "
            "refusing to write a weaker manifest"
        )
    # Optional, opt-in transparency anchoring. Absent by default: with
    # anchor_transparency=False (the default) NOTHING below runs and no network
    # is touched. The request boolean was committed before signing above. When
    # requested, the env opt-in must also be set (fail-closed), then the proof
    # is attached AFTER signing. The proof block is excluded from the signed
    # body while the request itself is included, closing anchor-stripping
    # downgrades without making a network response part of the signature.
    transparency_anchored = False
    transparency_kind: str | None = None
    if inp.anchor_transparency:
        require_rekor_enabled()  # fail-closed when the network action lacks the opt-in
        block = anchor_merkle_root(manifest.merkle_root_hex)
        if block is not None:
            manifest = replace(manifest, transparency_log=block)
            transparency_kind = str(block.get("kind") or "none")
            transparency_anchored = bool(block.get("anchored"))
        else:
            transparency_kind = "none"

    # Write once, after any requested proof attempt, so a failed network opt-in
    # cannot leave a transient requested-but-unattempted manifest on disk.
    out_path = write_manifest(manifest, Path(inp.output_path))

    sig = manifest.signature or {}
    degrade_reason = str(sig.get("fallback_reason")) if sig.get("fallback_reason") else None
    if coerce_reason and degrade_reason:
        combined_reason = f"{coerce_reason}; {degrade_reason}"
    else:
        combined_reason = coerce_reason or degrade_reason
    return ManifestFinalizeOutput(
        manifest_path=str(out_path),
        merkle_root_hex=manifest.merkle_root_hex,
        leaf_count=manifest.leaf_count,
        audit_log_record_count=manifest.audit_log_record_count,
        audit_log_final_hash=manifest.audit_log_final_hash,
        signature_payload_sha256=str(sig.get("payload_sha256", "")),
        signature_cert_fingerprint=(
            str(sig.get("cert_fingerprint")) if sig.get("cert_fingerprint") else None
        ),
        signer_effective=str(sig.get("kind") or "stub"),
        fallback_reason=combined_reason,
        transparency_requested=inp.anchor_transparency,
        transparency_anchored=transparency_anchored,
        transparency_kind=transparency_kind,
    )


SPEC = ToolSpec(
    name="manifest_finalize",
    description=(
        "TERMINAL crypto-custody step (M2). Call this AFTER every finding is verified, "
        "every contradiction is resolved, and the audit chain is settled — once the "
        "manifest is written, no further tool calls should append to the audit log for "
        "this run. Builds run.manifest.json by: (1) iterating the audit log, (2) "
        "extracting tool_call_output digests + finding digests as Merkle leaves, (3) "
        "computing the SHA-256 root, (4) signing the canonicalized body. "
        "signer='ed25519' (default) is a REAL local-keypair signature that verifies "
        "offline against an external trusted fingerprint; signer='sigstore' for production identity + transparency log "
        "(keyless Fulcio/Rekor — requires $SIGSTORE_ID_TOKEN); signer='stub' is an "
        "explicit dev placeholder. This is the terminal step — once the manifest is signed "
        "the run is closed. REFUSES to seal a run containing any finding_approved "
        "record without a tool_call_id recorded earlier in the audit chain — the "
        "'every Finding cites a tool_call_id' invariant is enforced here in code, "
        "not just by prompts. anchor_transparency commits the request inside the "
        "signed body before attaching the proof; when true, manifest_verify gates "
        "overall on an authenticated Rekor anchor. RFC-3161 remains structural-only "
        "until its TSA chain is pinned and verified. "
        "On error: most common cause is the audit_log_path doesn't exist or has been "
        "tampered with — run audit_verify first to confirm the chain is clean."
    ),
    input_model=ManifestFinalizeInput,
    output_model=ManifestFinalizeOutput,
    handler=_handle,
)

__all__ = ["SPEC", "ManifestFinalizeInput", "ManifestFinalizeOutput"]
