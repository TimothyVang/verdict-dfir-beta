// Unit tests for the independent, browser-side custody re-verifier
// (lib/verify-chain). The committed fixture under fixtures/custody/ was sealed
// by the REAL production Python stack (findevil_agent.crypto: AuditLog +
// LocalEd25519Signer + build_manifest) and verifies under verify_manifest, so
// these tests prove the TypeScript second implementation agrees with the
// canonical Rust/Python verifier: a valid chain verifies, a tampered one fails.

import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import {
  canonicalizeJson,
  extractContentRecord,
  foldAuditChain,
  merkleRootHex,
  parseAuditRecord,
  sha256Hex,
  splitAuditLines,
  verifyVerdictArtifactBinding,
  verifyTransparencyAnchor,
  verifyCustodyChain,
  verifyManifestSignature,
  type JsonValue,
  type ParsedAuditRecord,
} from "@/lib/verify-chain";

const here = path.dirname(fileURLToPath(import.meta.url));
const FIXTURE_DIR = path.resolve(here, "fixtures", "custody");
const AUDIT_PATH = path.join(FIXTURE_DIR, "audit.jsonl");
const MANIFEST_PATH = path.join(FIXTURE_DIR, "run.manifest.json");
const FIXTURE_ED25519_FINGERPRINT =
  "74caeff180c363db854bc10e8a8f876f34457746268345f6d9e34dc90c70914e";

function loadFixture(): {
  auditText: string;
  manifest: Record<string, JsonValue>;
  expectedEd25519Fingerprint: string;
} {
  const auditText = readFileSync(AUDIT_PATH, "utf-8");
  const manifest = JSON.parse(
    readFileSync(MANIFEST_PATH, "utf-8"),
  ) as Record<string, JsonValue>;
  return {
    auditText,
    manifest,
    expectedEd25519Fingerprint: FIXTURE_ED25519_FINGERPRINT,
  };
}

describe("canonicalizeJson", () => {
  it("byte-matches each on-disk line via the CONTENT_FIELDS projection", () => {
    // The on-disk line uses VERDICT canonical JSON v1 for the content fields, so
    // re-canonicalizing the parsed record must reproduce the exact bytes —
    // including the float (50.396626) and the escaped non-ASCII string.
    const { auditText } = loadFixture();
    const lines = splitAuditLines(auditText);
    expect(lines.length).toBeGreaterThan(0);
    for (const raw of lines) {
      const parsed = JSON.parse(raw) as Record<string, JsonValue>;
      expect(canonicalizeJson(extractContentRecord(parsed))).toBe(raw);
    }
  });

  it("sorts object keys and escapes non-ASCII to lowercase \\uXXXX", () => {
    expect(canonicalizeJson({ b: 1, a: 2 } as JsonValue)).toBe('{"a":2,"b":1}');
    expect(canonicalizeJson("unicóde ✓")).toBe('"unic\\u00f3de \\u2713"');
    expect(canonicalizeJson([true, null, 3])).toBe("[true,null,3]");
  });

  it("rejects integers that JavaScript cannot represent portably", () => {
    expect(() =>
      canonicalizeJson({ unsafe: Number.MAX_SAFE_INTEGER + 1 } as JsonValue),
    ).toThrow(/unsafe JSON integer/);
    expect(() =>
      canonicalizeJson({ unsafe: -(Number.MAX_SAFE_INTEGER + 1) } as JsonValue),
    ).toThrow(/unsafe JSON integer/);
  });

  it("drops non-content fields when projecting onto CONTENT_FIELDS", () => {
    const projected = extractContentRecord({
      seq: 1,
      kind: "x",
      ts: "t",
      prev_hash: "",
      payload: { a: 1 },
      line_hash: "should-be-dropped",
    } as Record<string, JsonValue>);
    expect(JSON.parse(canonicalizeJson(projected))).not.toHaveProperty(
      "line_hash",
    );
  });

  it("rejects non-canonical audit JSON bytes even when the JSON value is valid", () => {
    const nonCanonical =
      '{"seq":0,"kind":"case_open","ts":"2026-07-10T00:00:00Z","prev_hash":"","payload":{}}';

    expect(parseAuditRecord(nonCanonical)).toBeNull();
  });

  it("preserves CR bytes so LF-to-CRLF tampering cannot verify", async () => {
    const { auditText } = loadFixture();
    const crlf = auditText.replaceAll("\n", "\r\n");

    const fold = await foldAuditChain(splitAuditLines(crlf));

    expect(fold.ok).not.toBe(true);
  });

  it.each([
    ["leading", "\n"],
    ["interior", "after-first"],
    ["extra-trailing", "\n\n"],
    ["missing-terminal-lf", "missing-final-lf"],
  ])("rejects %s blank-line / framing drift", async (_name, mutation) => {
    const { auditText } = loadFixture();
    let tampered: string;
    if (mutation === "after-first") {
      tampered = auditText.replace("\n", "\n\n");
    } else if (mutation === "missing-final-lf") {
      tampered = auditText.slice(0, -1);
    } else if (mutation === "\n") {
      tampered = `\n${auditText}`;
    } else {
      tampered = `${auditText}\n`;
    }

    const fold = await foldAuditChain(splitAuditLines(tampered));

    expect(fold.ok).not.toBe(true);
  });
});

function artifactRecord(
  payload: Record<string, JsonValue>,
  seq = 5,
): ParsedAuditRecord {
  return {
    seq,
    kind: "verdict_artifact",
    ts: "2026-07-10T00:00:00Z",
    prevHash: "a".repeat(64),
    payload,
    raw: "",
  };
}

async function boundVerdictFixture(verdictText?: string): Promise<{
  verdictText: string;
  record: ParsedAuditRecord;
  manifest: Record<string, JsonValue>;
}> {
  const text =
    verdictText ??
    '{"case_id":"fixture-case","run_id":"fixture-run","verdict":"INDETERMINATE"}\n';
  const digest = await sha256Hex(new TextEncoder().encode(text));
  return {
    verdictText: text,
    record: artifactRecord({
      path: "verdict.json",
      sha256: digest,
      byte_count: new TextEncoder().encode(text).length,
    }),
    manifest: {
      case_id: "fixture-case",
      run_id: "fixture-run",
      extra: {
        packet_attestation: {
          verdict_artifact_path: "verdict.json",
          verdict_artifact_sha256: digest,
          verdict_artifact_bytes: new TextEncoder().encode(text).length,
        },
      },
    },
  };
}

describe("verdict artifact binding", () => {
  it("accepts exactly one current-case verdict bound by audit and manifest", async () => {
    const fixture = await boundVerdictFixture();

    const result = await verifyVerdictArtifactBinding({
      records: [fixture.record],
      manifest: fixture.manifest,
      verdictText: fixture.verdictText,
    });

    expect(result.ok).toBe(true);
    expect(result.verdict?.case_id).toBe("fixture-case");
  });

  it("fails closed for a missing or duplicate verdict_artifact record", async () => {
    const fixture = await boundVerdictFixture();

    const missing = await verifyVerdictArtifactBinding({
      records: [],
      manifest: fixture.manifest,
      verdictText: fixture.verdictText,
    });
    const duplicate = await verifyVerdictArtifactBinding({
      records: [fixture.record, { ...fixture.record, seq: fixture.record.seq + 1 }],
      manifest: fixture.manifest,
      verdictText: fixture.verdictText,
    });

    expect(missing.ok).not.toBe(true);
    expect(String(missing.ok)).toContain("exactly one");
    expect(duplicate.ok).not.toBe(true);
    expect(String(duplicate.ok)).toContain("exactly one");
  });

  it("rejects tampered and post-seal substituted verdict bytes", async () => {
    const fixture = await boundVerdictFixture();
    const substituted = fixture.verdictText.replace("INDETERMINATE", "SUSPICIOUS");

    const result = await verifyVerdictArtifactBinding({
      records: [fixture.record],
      manifest: fixture.manifest,
      verdictText: substituted,
    });

    expect(result.ok).not.toBe(true);
    expect(String(result.ok)).toContain("sha256");
    expect(result.verdict).toBeNull();
  });

  it("rejects a verdict from the wrong case or run", async () => {
    const fixture = await boundVerdictFixture(
      '{"case_id":"other-case","run_id":"fixture-run","verdict":"NO_EVIL"}\n',
    );

    const result = await verifyVerdictArtifactBinding({
      records: [fixture.record],
      manifest: fixture.manifest,
      verdictText: fixture.verdictText,
    });

    expect(result.ok).not.toBe(true);
    expect(String(result.ok)).toContain("case_id");
  });

  it("rejects unsafe integers before a verdict payload reaches the UI", async () => {
    const fixture = await boundVerdictFixture(
      '{"case_id":"fixture-case","run_id":"fixture-run","verdict":"NO_EVIL","count":9007199254740993}\n',
    );

    const result = await verifyVerdictArtifactBinding({
      records: [fixture.record],
      manifest: fixture.manifest,
      verdictText: fixture.verdictText,
    });

    expect(result.ok).not.toBe(true);
    expect(String(result.ok)).toContain("unsafe JSON integer");
  });

  it("rejects conflicting signed packet-attestation metadata", async () => {
    const fixture = await boundVerdictFixture();
    const extra = fixture.manifest.extra as Record<string, JsonValue>;
    const packet = extra.packet_attestation as Record<string, JsonValue>;

    const result = await verifyVerdictArtifactBinding({
      records: [fixture.record],
      manifest: {
        ...fixture.manifest,
        extra: {
          ...extra,
          packet_attestation: {
            ...packet,
            verdict_artifact_sha256: "f".repeat(64),
          },
        },
      },
      verdictText: fixture.verdictText,
    });

    expect(result.ok).not.toBe(true);
    expect(String(result.ok)).toContain("packet_attestation");
  });
});

describe("merkleRootHex", () => {
  it("returns 32 zero bytes for an empty leaf set", async () => {
    expect(await merkleRootHex([])).toBe("00".repeat(32));
  });
});

describe("transparency anchor policy", () => {
  it("keeps legacy and explicitly unrequested anchors compatible", () => {
    expect(verifyTransparencyAnchor({})).toBe(true);
    expect(
      verifyTransparencyAnchor({
        transparency_anchor_requested: false,
        transparency_log: { kind: "untrusted-legacy-side-signal" },
      }),
    ).toBe(true);
  });

  it("fails a signed request when the anchor is missing", () => {
    const status = verifyTransparencyAnchor({
      transparency_anchor_requested: true,
    });

    expect(status).not.toBe(true);
    expect(String(status)).toContain("requested");
    expect(String(status)).toContain("missing");
  });

  it("fails malformed or browser-unsupported requested anchors", () => {
    expect(
      String(
        verifyTransparencyAnchor({
          transparency_anchor_requested: "true",
        }),
      ),
    ).toContain("JSON boolean");

    const rfc3161 = verifyTransparencyAnchor({
      transparency_anchor_requested: true,
      transparency_log: { kind: "rfc3161", anchored: true },
    });
    expect(rfc3161).not.toBe(true);
    expect(String(rfc3161)).toContain("unsupported");

    const rekor = verifyTransparencyAnchor({
      merkle_root_hex: "a".repeat(64),
      transparency_anchor_requested: true,
      transparency_log: {
        kind: "rekor",
        anchored: true,
        subject: { merkle_root_sha256: "a".repeat(64) },
        rekor: { bundle_b64: "e30=" },
      },
    });
    expect(rekor).not.toBe(true);
    expect(String(rekor)).toContain("production Rekor roots");
  });
});

describe("verifyCustodyChain (valid fixture)", () => {
  it("does not authenticate a sealed display when verdict bytes are missing", async () => {
    const result = await verifyCustodyChain(loadFixture());
    expect(result.auditChainOk).toBe(true);
    expect(result.merkleRootOk).toBe(true);
    expect(result.leafCountOk).toBe(true);
    expect(result.signaturePresent).toBe(true);
    expect(result.signatureKind).toBe("ed25519");
    expect(result.signatureVerified).toBe(true);
    expect(result.verdictArtifactOk).not.toBe(true);
    expect(result.overall).toBe(false);
  });
});

describe("verifyCustodyChain (tamper detection)", () => {
  it("fails when an audit line's bytes are altered (chain break)", async () => {
    const { auditText, manifest } = loadFixture();
    // Alter the finding_approved line — the NEXT line's prev_hash no longer
    // links, so the fold breaks.
    const tampered = auditText.replace("demo finding", "demo findinX");
    expect(tampered).not.toBe(auditText);
    const result = await verifyCustodyChain({ auditText: tampered, manifest });
    expect(result.auditChainOk).not.toBe(true);
    expect(result.overall).toBe(false);
  });

  it("fails when a manifest Merkle leaf digest is swapped", async () => {
    const { auditText, manifest } = loadFixture();
    const leaves = (manifest.leaves as JsonValue[]).map((leaf) => ({
      ...(leaf as Record<string, JsonValue>),
    }));
    (leaves[0] as Record<string, JsonValue>).digest_hex = "b".repeat(64);
    const result = await verifyCustodyChain({
      auditText,
      manifest: { ...manifest, leaves },
    });
    expect(result.merkleRootOk).not.toBe(true);
    expect(result.overall).toBe(false);
  });

  it("fails when the signed manifest body is changed", async () => {
    const { auditText, manifest } = loadFixture();
    const result = await verifyCustodyChain({
      auditText,
      manifest: { ...manifest, case_id: "tampered-case" },
    });
    expect(result.signatureVerified).not.toBe(true);
    expect(result.overall).toBe(false);
  });

  it("rejects a forged sigstore kind even when the payload digest is valid", async () => {
    const { auditText, manifest } = loadFixture();
    const originalSignature = manifest.signature as Record<string, JsonValue>;
    const forged = {
      ...manifest,
      signature: {
        ...originalSignature,
        kind: "sigstore",
        bundle_b64: btoa('{"forged":true}'),
      },
    } as Record<string, JsonValue>;

    // The signature block is outside the signed body, so the real fixture's
    // payload digest remains structurally valid after changing only its kind
    // and bundle. This was the old presence-only authentication bypass.
    const result = await verifyCustodyChain({ auditText, manifest: forged });
    expect(result.auditChainOk).toBe(true);
    expect(result.merkleRootOk).toBe(true);
    expect(result.signatureKind).toBe("sigstore");
    expect(result.signatureVerified).not.toBe(true);
    expect(result.overall).toBe(false);
  });

  it("fails when the audit tail is truncated", async () => {
    const { auditText, manifest } = loadFixture();
    const lines = splitAuditLines(auditText);
    const truncated = lines.slice(0, -1).join("\n") + "\n";
    const result = await verifyCustodyChain({ auditText: truncated, manifest });
    expect(result.auditChainOk).not.toBe(true);
    expect(result.overall).toBe(false);
  });

  it("does not authenticate an integrity-only stub manifest", async () => {
    const { auditText, manifest } = loadFixture();
    const original = manifest.signature as Record<string, JsonValue>;
    const result = await verifyCustodyChain({
      auditText,
      manifest: {
        ...manifest,
        signature: {
          kind: "stub",
          bundle_b64: "development-placeholder",
          payload_sha256: original.payload_sha256,
        },
      },
    });

    expect(result.auditChainOk).toBe(true);
    expect(result.merkleRootOk).toBe(true);
    expect(result.leafCountOk).toBe(true);
    expect(result.signaturePayloadOk).toBe(true);
    expect(result.signatureVerified).not.toBe(true);
    expect(result.overall).toBe(false);
  });

  it("fails overall when a signed anchor request has no proof", async () => {
    const { auditText, manifest } = loadFixture();
    const result = await verifyCustodyChain({
      auditText,
      manifest: { ...manifest, transparency_anchor_requested: true },
    });

    expect(result.transparencyOk).not.toBe(true);
    expect(String(result.transparencyOk)).toContain("missing");
    expect(result.overall).toBe(false);
  });
});

describe("verifyManifestSignature (honest tiers)", () => {
  it.each(["unsigned_extra", "__proto__"])(
    "treats an added own %s key as signed-body tampering",
    async (key) => {
      const { manifest } = loadFixture();
      const tampered = { ...manifest } as Record<string, JsonValue>;
      Object.defineProperty(tampered, key, {
        value: { attacker_controlled: true },
        enumerable: true,
        configurable: true,
      });

      const result = await verifyManifestSignature(
        tampered,
        FIXTURE_ED25519_FINGERPRINT,
      );

      expect(result.payloadOk).not.toBe(true);
      expect(result.verified).not.toBe(true);
    },
  );

  it("rejects the identity-key/identity-R/S=0 forged signature", async () => {
    const body = { case_id: "forged-case" } as Record<string, JsonValue>;
    const payload = await sha256Hex(
      new TextEncoder().encode(canonicalizeJson(body)),
    );
    const identity = new Uint8Array(32);
    identity[0] = 1;
    const signature = new Uint8Array(64);
    signature[0] = 1;
    const fingerprint = await sha256Hex(identity);
    const bundle = {
      public_key_b64: Buffer.from(identity).toString("base64"),
      signature_b64: Buffer.from(signature).toString("base64"),
      cert_fingerprint: fingerprint,
    };
    const res = await verifyManifestSignature(
      {
        ...body,
        signature: {
          kind: "ed25519",
          bundle_b64: Buffer.from(JSON.stringify(bundle)).toString("base64"),
          payload_sha256: payload,
          cert_fingerprint: fingerprint,
        },
      } as Record<string, JsonValue>,
      fingerprint,
    );

    expect(res.payloadOk).toBe(true);
    expect(res.verified).not.toBe(true);
  });

  it("requires an external Ed25519 fingerprint pin", async () => {
    const { manifest } = loadFixture();

    const unpinned = await verifyManifestSignature(manifest);
    const pinned = await verifyManifestSignature(
      manifest,
      FIXTURE_ED25519_FINGERPRINT,
    );

    expect(unpinned.verified).not.toBe(true);
    expect(pinned.verified).toBe(true);
  });

  it("rejects S plus the Ed25519 group order", async () => {
    const { manifest } = loadFixture();
    const original = manifest.signature as Record<string, JsonValue>;
    const bundle = JSON.parse(
      Buffer.from(String(original.bundle_b64), "base64").toString("utf-8"),
    ) as Record<string, JsonValue>;
    const signature = Buffer.from(String(bundle.signature_b64), "base64");
    const groupOrder =
      (1n << 252n) + 27742317777372353535851937790883648493n;
    let s = 0n;
    for (let index = 63; index >= 32; index -= 1) {
      s = (s << 8n) | BigInt(signature[index]);
    }
    let malleable = s + groupOrder;
    for (let index = 32; index < 64; index += 1) {
      signature[index] = Number(malleable & 0xffn);
      malleable >>= 8n;
    }
    bundle.signature_b64 = signature.toString("base64");
    const forged = {
      ...manifest,
      signature: {
        ...original,
        bundle_b64: Buffer.from(JSON.stringify(bundle)).toString("base64"),
      },
    } as Record<string, JsonValue>;

    const result = await verifyManifestSignature(
      forged,
      FIXTURE_ED25519_FINGERPRINT,
    );

    expect(result.payloadOk).toBe(true);
    expect(result.verified).not.toBe(true);
    expect(String(result.verified)).toContain("scalar S");
  });

  it("never reports a valid-payload stub bundle as cryptographically verified", async () => {
    const body = { case_id: "dev-case" } as Record<string, JsonValue>;
    const payload = await sha256Hex(
      new TextEncoder().encode(canonicalizeJson(body)),
    );
    const res = await verifyManifestSignature({
      ...body,
      signature: { kind: "stub", bundle_b64: "x", payload_sha256: payload },
    } as Record<string, JsonValue>);
    expect(res.present).toBe(true);
    expect(res.kind).toBe("stub");
    expect(res.verified).not.toBe(true);
  });

  it("reports an absent signature as not present", async () => {
    const res = await verifyManifestSignature(
      {} as Record<string, JsonValue>,
    );
    expect(res.present).toBe(false);
    expect(res.verified).not.toBe(true);
  });

  it("fails a valid-payload sigstore bundle without identity verification", async () => {
    const body = { case_id: "forged-case" } as Record<string, JsonValue>;
    const payload = await sha256Hex(
      new TextEncoder().encode(canonicalizeJson(body)),
    );
    const res = await verifyManifestSignature({
      ...body,
      signature: {
        kind: "sigstore",
        bundle_b64: btoa('{"forged":true}'),
        payload_sha256: payload,
      },
    } as Record<string, JsonValue>);
    expect(res.kind).toBe("sigstore");
    expect(res.verified).not.toBe(true);
    expect(String(res.verified)).toContain("exact trusted signer identity");
    expect(String(res.verified)).toContain("exact OIDC issuer");
    expect(String(res.verified)).toContain("production Fulcio/Rekor roots");
  });

  it("fails closed before hashing a manifest with an unsafe integer", async () => {
    const { manifest } = loadFixture();
    const result = await verifyManifestSignature({
      ...manifest,
      unsafe_counter: Number.MAX_SAFE_INTEGER + 1,
    });

    expect(result.payloadOk).not.toBe(true);
    expect(result.verified).not.toBe(true);
    expect(String(result.payloadOk)).toContain("unsafe JSON integer");
  });
});

describe("parseAuditRecord", () => {
  it("returns null for malformed JSON", () => {
    expect(parseAuditRecord("{not json")).toBeNull();
  });

  it("rejects an unsafe audit sequence number", () => {
    expect(
      parseAuditRecord(
        '{"kind":"agent_message","payload":{},"prev_hash":"","seq":9007199254740992,"ts":"t"}',
      ),
    ).toBeNull();
  });

  it("parses a well-formed record", () => {
    const rec = parseAuditRecord(
      '{"kind":"agent_message","payload":{"a":1},"prev_hash":"","seq":0,"ts":"t"}',
    );
    expect(rec?.seq).toBe(0);
    expect(rec?.kind).toBe("agent_message");
    expect(rec?.prevHash).toBe("");
  });
});

// Anchor canonicalization parity against committed PRODUCTION sample runs when
// present (skipped in a stripped release checkout that drops docs/sample-run).
describe("canonicalization parity vs committed sample runs", () => {
  const repoRoot = path.resolve(here, "..", "..", "..");
  const sampleAudit = path.join(
    repoRoot,
    "docs",
    "sample-run",
    "synthetic-benign",
    "audit.jsonl",
  );
  it.skipIf(!existsSync(sampleAudit))(
    "re-canonicalizes every sample-run line byte-for-byte",
    () => {
      const lines = splitAuditLines(readFileSync(sampleAudit, "utf-8"));
      expect(lines.length).toBeGreaterThan(0);
      for (const raw of lines) {
        const parsed = JSON.parse(raw) as Record<string, JsonValue>;
        expect(canonicalizeJson(extractContentRecord(parsed))).toBe(raw);
      }
    },
  );
});
