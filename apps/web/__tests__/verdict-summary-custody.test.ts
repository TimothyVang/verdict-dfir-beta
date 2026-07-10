import { describe, expect, it } from "vitest";

import { describeCustody } from "@/components/investigation/VerdictSummary";
import type { CustodyVerification } from "@/lib/verify-chain";

function integrityOnly(kind: string): CustodyVerification {
  return {
    available: true,
    auditChainOk: true,
    merkleRootOk: true,
    leafCountOk: true,
    signaturePresent: true,
    signaturePayloadOk: true,
    signatureKind: kind,
    signatureVerified: `${kind} is not authenticated`,
    transparencyOk: true,
    verdictArtifactOk: true,
    verdictSha256: "a".repeat(64),
    verdict: {
      case_id: "case-1",
      run_id: "run-1",
      verdict: "INDETERMINATE",
    },
    overall: false,
  };
}

describe("browser custody badge", () => {
  it.each(["stub", "sigstore", "ed25519"])(
    "never renders an unauthenticated %s case as PASS",
    (kind) => {
      const badge = describeCustody(integrityOnly(kind), null);

      expect(badge.label).not.toContain("PASS");
      expect(badge.label).toContain("UNAUTHENTICATED");
      expect(badge.detail).toContain("not authenticated");
    },
  );

  it("renders a requested-but-unverified transparency anchor as FAILED", () => {
    const custody: CustodyVerification = {
      ...integrityOnly("ed25519"),
      signatureVerified: true,
      transparencyOk: "requested Rekor anchor is unsupported in the browser",
    };

    const badge = describeCustody(custody, null);

    expect(badge.label).toContain("FAILED");
    expect(badge.label).not.toContain("PASS");
    expect(badge.detail).toContain("transparency anchor");
  });

  it("never renders PASS when verdict bytes are not audit-bound", () => {
    const custody: CustodyVerification = {
      ...integrityOnly("ed25519"),
      signatureVerified: true,
      verdictArtifactOk: "verdict_artifact sha256 mismatch",
    };

    const badge = describeCustody(custody, null);

    expect(badge.label).toContain("FAILED");
    expect(badge.label).not.toContain("PASS");
    expect(badge.detail).toContain("verdict artifact");
  });
});
