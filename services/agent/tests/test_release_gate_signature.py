"""Customer release requires verified Sigstore identity, not a kind label."""

from __future__ import annotations

import sys
from pathlib import Path

_SCRIPTS = Path(__file__).resolve().parents[3] / "scripts"
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import find_evil_auto as fea  # noqa: E402


def test_release_gate_rejects_unverified_sigstore_bundle() -> None:
    investigation = fea.Investigation("evidence.mem", with_report=False)
    report_qa = {
        "status": "PASS",
        "packet_state": "READY_FOR_EXPERT_SIGNOFF",
        "expert_decision": "approved",
        "checks": [],
        "customer_release_blockers": [],
    }

    gate = investigation._build_release_gate(
        report_qa,
        manifest_verification={
            "overall": True,
            "signature_verified": "sigstore identity policy was not supplied",
        },
        manifest={
            "signature": {
                "kind": "sigstore",
                "bundle_b64": "ZmFrZQ==",
                "payload_sha256": "0" * 64,
            }
        },
    )

    assert gate["customer_releasable"] is False
    assert any("cryptographically verified" in blocker for blocker in gate["release_blockers"])
