"""``manifest_verify`` tool — offline verification of run.manifest.json.

Wraps :func:`findevil_agent.crypto.manifest.verify_manifest`. Runs
the audit-chain replay, the Merkle-root rebuild, the leaf-count sanity check,
the signed-payload digest, and tier-appropriate signature verification. Stays
offline; Sigstore requires an explicitly configured expected identity.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from findevil_agent.crypto.manifest import verify_manifest
from pydantic import BaseModel, ConfigDict, Field, model_validator

from findevil_agent_mcp.tools._base import ToolSpec


class ManifestVerifyInput(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    manifest_path: str = Field(..., description="Absolute path to run.manifest.json.")
    audit_log_path: str | None = Field(
        default=None,
        description=(
            "Override audit_log_path embedded in the manifest. Useful when "
            "verifying a manifest copied to a different directory."
        ),
    )
    expected_ed25519_fingerprint: str | None = Field(
        default=None,
        pattern=r"^[0-9a-fA-F]{64}$",
        description=(
            "Externally trusted SHA-256 fingerprint of the Ed25519 public key. "
            "Never copy this value from the manifest being verified."
        ),
    )

    @model_validator(mode="before")
    @classmethod
    def _accept_path_alias(cls, data: Any) -> Any:
        # Local models routinely call this tool with {"path": ...} instead of
        # the canonical {"manifest_path": ...}. Under extra="forbid" that hard-
        # fails and derails the seal sequence, forcing the deterministic
        # fallback. Accept `path` as an alias so one arg slip does not cost a
        # tool call — while still rejecting an ambiguous both-keys-differ call
        # and every other unexpected key.
        if not isinstance(data, dict) or "path" not in data:
            return data
        alias = data["path"]
        canonical = data.get("manifest_path")
        if canonical is not None and canonical != alias:
            raise ValueError(
                "pass either manifest_path or path (they are aliases), "
                "not both with different values"
            )
        return {**{k: v for k, v in data.items() if k != "path"}, "manifest_path": alias}


class ManifestVerifyOutput(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    overall: bool
    audit_chain_ok: bool
    audit_chain_detail: str | None
    merkle_root_ok: bool
    merkle_root_detail: str | None
    leaf_count_ok: bool
    leaf_count_detail: str | None
    signature_present: bool
    signature_kind: str
    signature_verified: bool
    signature_verified_detail: str | None
    entailment_ok: bool
    entailment_ok_detail: str | None
    transparency_ok: bool
    transparency_ok_detail: str | None


async def _handle(inp: BaseModel) -> ManifestVerifyOutput:
    assert isinstance(inp, ManifestVerifyInput)
    audit_path = Path(inp.audit_log_path) if inp.audit_log_path else None
    result = verify_manifest(
        Path(inp.manifest_path),
        audit_log_path=audit_path,
        expected_ed25519_fingerprint=inp.expected_ed25519_fingerprint,
    )

    def _split(value: bool | str) -> tuple[bool, str | None]:
        if value is True:
            return True, None
        if value is False:
            return False, None
        return False, str(value)

    audit_ok, audit_detail = _split(result.audit_chain_ok)
    merkle_ok, merkle_detail = _split(result.merkle_root_ok)
    count_ok, count_detail = _split(result.leaf_count_ok)
    sig_verified, sig_verified_detail = _split(result.signature_verified)
    entail_ok, entail_detail = _split(result.entailment_ok)
    transparency_ok, transparency_detail = _split(result.transparency_ok)
    return ManifestVerifyOutput(
        overall=result.overall,
        audit_chain_ok=audit_ok,
        audit_chain_detail=audit_detail,
        merkle_root_ok=merkle_ok,
        merkle_root_detail=merkle_detail,
        leaf_count_ok=count_ok,
        leaf_count_detail=count_detail,
        signature_present=result.signature_present,
        signature_kind=result.signature_kind,
        signature_verified=sig_verified,
        signature_verified_detail=sig_verified_detail,
        entailment_ok=entail_ok,
        entailment_ok_detail=entail_detail,
        transparency_ok=transparency_ok,
        transparency_ok_detail=transparency_detail,
    )


SPEC = ToolSpec(
    name="manifest_verify",
    description=(
        "Offline verify of run.manifest.json — a technical digital-identification "
        "check supporting FRE 902(14); qualified-person certification and Rule "
        "902(11) notice remain external. Performs four "
        "independent checks: (1) audit_chain_ok — replays the linked audit.jsonl; "
        "(2) merkle_root_ok — rebuilds the tree from declared leaves and compares to "
        "merkle_root_hex; (3) leaf_count_ok — sanity check on the leaves array length; "
        "(4) signature_present — confirms a signer bundle is attached; "
        "signature_kind reports ed25519/sigstore/stub and signature_verified is True "
        "for an Ed25519 signature verified against an external trusted fingerprint, or "
        "when Sigstore verifies against the configured "
        "FINDEVIL_SIGSTORE_EXPECTED_IDENTITY/ISSUER policy. Stub bundles are dev "
        "placeholders. overall=True requires the chain, Merkle, leaf-count, payload "
        "digest, and signature rules for the effective tier to pass; an unverified "
        "Sigstore label/bundle fails closed. transparency_ok is True for an "
        "authenticated Rekor Bundle under exact identity + issuer policy, and "
        "vacuously True when a legacy/unrequested manifest has no proof. RFC-3161 "
        "is structural-imprint-only until a TSA chain is pinned. A signed request "
        "commitment makes a missing, unauthenticated, or invalid requested anchor "
        "fail overall. Legacy and explicitly unrequested anchors remain non-gating "
        "for compatibility. "
        "If the manifest was moved/renamed, pass audit_log_path explicitly to override "
        "the path embedded in the manifest. "
        "On verify failure: the per-field detail string identifies which check failed "
        "and shows the specific mismatch (e.g. 'declared root abc... != rebuilt def...')."
    ),
    input_model=ManifestVerifyInput,
    output_model=ManifestVerifyOutput,
    handler=_handle,
)

__all__ = ["SPEC", "ManifestVerifyInput", "ManifestVerifyOutput"]
