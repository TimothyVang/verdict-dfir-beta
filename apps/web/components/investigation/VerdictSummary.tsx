"use client";

import { useEffect, useMemo, useState } from "react";
import { deriveInvestigationStream } from "./InvestigationStreamPanel";
import {
  buildVerdictSummaryLine,
  deriveVerdictWord,
  summarizeVerdictCaveats,
  type VerdictPayload,
  type VerdictWord,
} from "@/lib/verdict-summary-policy";
import {
  selectCustodyDisplayEvents,
  type BrowserAuditLine,
} from "@/lib/custody-display";
import { validateCustodySnapshotResponse } from "@/lib/custody-snapshot";
import {
  VERDICT,
  SERIF,
  GROTESK,
  BODY,
  EvidenceTag,
  Kicker,
  Stamp,
} from "@/lib/verdict-ui";
import {
  parseAuditRecord,
  splitAuditLines,
  verifyCustodyChain,
  type CustodyVerification,
  type JsonValue,
} from "@/lib/verify-chain";

type AuditLine = BrowserAuditLine;

interface VerdictMeta {
  color: string;
  line: string;
}

const VERDICT_META: Record<VerdictWord, VerdictMeta> = {
  SUSPICIOUS: {
    color: VERDICT.alertRed,
    line: "Evidence of compromise — treat as a positive and escalate.",
  },
  INDETERMINATE: {
    color: VERDICT.inferred,
    line: "Leads found, but none meet the two-source bar — corroboration needed.",
  },
  "NO EVIL": {
    color: VERDICT.confirmed,
    line: "No reportable findings in examined artifacts; scope remains explicit.",
  },
  INVESTIGATING: {
    color: VERDICT.accentPurpleLight,
    line: "Investigation in progress…",
  },
};

interface VerdictSummaryProps {
  events: AuditLine[];
  caseDir: string;
  manifestDone: boolean;
  evidenceName?: string;
  onAuthenticatedSnapshot?: (
    snapshot: AuthenticatedCustodyDisplaySnapshot | null,
  ) => void;
}

export interface AuthenticatedCustodyDisplaySnapshot {
  events: BrowserAuditLine[];
  verdict: VerdictPayload;
  custody: CustodyVerification;
  snapshotSha256: string;
}

export interface CustodyBadge {
  label: string;
  color: string;
  detail: string;
}

/**
 * Turn the browser re-verification result into a small, honest badge. PASS
 * means a second, in-browser implementation re-derived the chain + Merkle root
 * + leaf count and (for ed25519) re-checked the signature — it does not
 * upgrade the verdict or replace the authoritative manifest_verify.json.
 */
export function describeCustody(
  custody: CustodyVerification | null,
  custodyError: string | null,
): CustodyBadge {
  if (custodyError) {
    return {
      label: "Browser re-verify unavailable",
      color: VERDICT.muted,
      detail: custodyError,
    };
  }
  if (!custody) {
    return {
      label: "Re-verifying in browser…",
      color: VERDICT.muted,
      detail: "Recomputing the custody chain with Web Crypto.",
    };
  }
  if (custody.overall && custody.signatureVerified === true) {
    return {
      label: "Independent browser re-verify: PASS",
      color: VERDICT.confirmed,
      detail:
        "Chain, Merkle root, leaf count, and verdict bytes re-derived offline; " +
        `${custody.signatureKind} signature verified.`,
    };
  }
  const integrityOk =
    custody.auditChainOk === true &&
    custody.merkleRootOk === true &&
    custody.leafCountOk === true &&
    custody.signaturePayloadOk === true &&
    custody.transparencyOk === true &&
    custody.verdictArtifactOk === true;
  if (integrityOk && custody.signatureVerified !== true) {
    const reason = custody.signaturePresent
      ? String(custody.signatureVerified)
      : "no authenticated signature is present";
    return {
      label: "Independent browser integrity: UNAUTHENTICATED",
      color: VERDICT.inferred,
      detail: reason,
    };
  }
  const fails: string[] = [];
  if (custody.auditChainOk !== true) fails.push(`chain (${custody.auditChainOk})`);
  if (custody.merkleRootOk !== true) fails.push(`Merkle (${custody.merkleRootOk})`);
  if (custody.leafCountOk !== true) fails.push(`leaf count (${custody.leafCountOk})`);
  if (custody.transparencyOk !== true) {
    fails.push(`transparency anchor (${custody.transparencyOk})`);
  }
  if (custody.verdictArtifactOk !== true) {
    fails.push(`verdict artifact (${custody.verdictArtifactOk})`);
  }
  if (!custody.signaturePresent) {
    fails.push("signature absent");
  } else if (custody.signaturePayloadOk !== true) {
    fails.push(`signature payload (${custody.signaturePayloadOk})`);
  } else if (custody.signatureVerified !== true) {
    fails.push(`signature (${custody.signatureVerified})`);
  }
  return {
    label: "Independent browser re-verify: FAILED",
    color: VERDICT.alertRed,
    detail: fails.join("; ") || "custody re-derivation did not match the manifest",
  };
}

/**
 * VerdictSummary — the human-first headline that answers, at a glance:
 * "is this machine compromised, how sure are we, and is it proven?" — before
 * the reader has to wade through the live terminal stream below it.
 *
 * The verdict word is taken from hash-bound verdict.json bytes only after the
 * joint audit/manifest/verdict snapshot authenticates;
 * until then (or for curated cases without a verdict.json) it is DERIVED from
 * the live findings' confidence tiers, so the banner is correct for both a
 * live run and a replayed/curated case.
 */
export function VerdictSummary({
  events,
  caseDir,
  manifestDone,
  evidenceName,
  onAuthenticatedSnapshot,
}: VerdictSummaryProps) {
  const [snapshotState, setSnapshotState] = useState<{
    custody: CustodyVerification;
    events: BrowserAuditLine[];
    verdict: VerdictPayload | null;
    snapshotSha256: string;
  } | null>(null);
  const [custodyError, setCustodyError] = useState<string | null>(null);
  const custody = snapshotState?.custody ?? null;
  const custodyAuthenticated =
    custody?.overall === true &&
    custody.signatureVerified === true &&
    custody.verdictArtifactOk === true &&
    snapshotState?.verdict !== null;
  const displayEvents = useMemo(
    () =>
      selectCustodyDisplayEvents({
        liveEvents: events,
        snapshotEvents: snapshotState?.events ?? [],
        custodyAuthenticated,
        sealObserved: manifestDone,
      }),
    [events, snapshotState, custodyAuthenticated, manifestDone],
  );
  const findings = useMemo(
    () => deriveInvestigationStream(displayEvents).findings,
    [displayEvents],
  );

  const tally = useMemo(() => {
    let confirmed = 0;
    let inferred = 0;
    let hypothesis = 0;
    for (const f of findings) {
      const c = (f.confidence ?? "").toUpperCase();
      if (c === "CONFIRMED") confirmed += 1;
      else if (c === "INFERRED") inferred += 1;
      else if (c === "HYPOTHESIS") hypothesis += 1;
    }
    return { confirmed, inferred, hypothesis, total: findings.length };
  }, [findings]);

  // Independent browser-side re-verification once a terminal packet makes the
  // three-artifact snapshot ready to attempt.
  // re-derive the chain from one jointly stability-checked audit + manifest +
  // verdict snapshot with Web Crypto
  // (lib/verify-chain) — a second implementation of the offline manifest_verify
  // path — instead of trusting the displayed values. PURE READ-SIDE: it only
  // fetches the paired artifacts and recomputes; it never mutates anything.
  useEffect(() => {
    if (!manifestDone || !caseDir) {
      setSnapshotState(null);
      setCustodyError(null);
      onAuthenticatedSnapshot?.(null);
      return;
    }
    let cancelled = false;
    let retry: ReturnType<typeof setTimeout> | null = null;
    const deadline = Date.now() + 12_000;
    const reverify = async () => {
      try {
        const [snapshotRes, policyRes] = await Promise.all([
          fetch(
            `/api/custody-snapshot?case=${encodeURIComponent(caseDir)}`,
          ),
          fetch("/api/custody-policy"),
        ]);
        if (!snapshotRes.ok || !policyRes.ok) {
          throw new Error("stable custody snapshot is unavailable");
        }
        const snapshot = await validateCustodySnapshotResponse(
          await snapshotRes.json(),
          snapshotRes.headers.get("etag"),
        );
        const parsedManifest = JSON.parse(snapshot.manifestText) as unknown;
        if (
          typeof parsedManifest !== "object" ||
          parsedManifest === null ||
          Array.isArray(parsedManifest)
        ) {
          throw new Error("custody manifest is not an object");
        }
        const policy = (await policyRes.json()) as {
          ed25519ExpectedFingerprint?: string | null;
        };
        const result = await verifyCustodyChain({
          auditText: snapshot.auditText,
          manifest: parsedManifest as Record<string, JsonValue>,
          verdictText: snapshot.verdictText,
          expectedEd25519Fingerprint:
            policy.ed25519ExpectedFingerprint ?? undefined,
        });
        const snapshotEvents = splitAuditLines(snapshot.auditText).map((rawLine) => {
          const record = parseAuditRecord(rawLine);
          if (!record) throw new Error("custody audit contains an invalid record");
          return {
            seq: record.seq,
            kind: record.kind,
            ts: record.ts,
            payload: record.payload as Record<string, unknown>,
            raw_line: rawLine,
          } satisfies BrowserAuditLine;
        });
        const verdict = result.verdict as VerdictPayload | null;
        if (!cancelled) {
          setSnapshotState({
            custody: result,
            events: snapshotEvents,
            verdict,
            snapshotSha256: snapshot.snapshotSha256,
          });
          setCustodyError(null);
          if (
            result.overall === true &&
            result.signatureVerified === true &&
            result.verdictArtifactOk === true &&
            verdict !== null
          ) {
            onAuthenticatedSnapshot?.({
              custody: result,
              events: snapshotEvents,
              verdict,
              snapshotSha256: snapshot.snapshotSha256,
            });
            return;
          }
          onAuthenticatedSnapshot?.(null);
        }
      } catch (err) {
        if (!cancelled) {
          setCustodyError(err instanceof Error ? err.message : String(err));
          setSnapshotState(null);
          onAuthenticatedSnapshot?.(null);
        }
      }
      if (!cancelled && Date.now() < deadline) {
        retry = setTimeout(() => void reverify(), 2_000);
      }
    };
    void reverify();
    return () => {
      cancelled = true;
      if (retry) clearTimeout(retry);
    };
  }, [manifestDone, caseDir, onAuthenticatedSnapshot]);

  const verdictPayload = custodyAuthenticated ? snapshotState?.verdict ?? null : null;

  const verdict = useMemo(
    () =>
      manifestDone && !custodyAuthenticated
        ? "INDETERMINATE"
        : deriveVerdictWord(verdictPayload?.verdict, tally, manifestDone),
    [verdictPayload, tally, manifestDone, custodyAuthenticated],
  );

  const caveats = useMemo(
    () => summarizeVerdictCaveats(verdictPayload),
    [verdictPayload],
  );

  // Nothing connected yet — let the empty-state of the page speak.
  if (!caseDir && events.length === 0) return null;

  const meta = VERDICT_META[verdict];
  const summaryLine =
    manifestDone && !custodyAuthenticated
      ? "The terminal Case state is not authenticated; no verdict or finding tally is trusted for display."
      : buildVerdictSummaryLine(verdict, tally, evidenceName, caveats);
  const custodyBadge = describeCustody(custody, custodyError);

  return (
    <section
      aria-label="verdict summary"
      style={{
        background: VERDICT.surface,
        border: `1px solid ${VERDICT.border}`,
        borderLeft: `4px solid ${meta.color}`,
        borderRadius: 12,
        padding: "24px 28px",
        marginBottom: 24,
        display: "flex",
        flexWrap: "wrap",
        alignItems: "center",
        justifyContent: "space-between",
        gap: 24,
      }}
    >
      {/* Left — the answer */}
      <div style={{ minWidth: 0, flex: "1 1 420px" }}>
        <Kicker color={VERDICT.muted}>Verdict</Kicker>
        <div
          style={{
            fontFamily: SERIF,
            fontSize: 52,
            fontWeight: 900,
            lineHeight: 1.02,
            letterSpacing: -1,
            color: meta.color,
            margin: "8px 0 10px",
          }}
        >
          {verdict}
        </div>
        <div
          style={{
            fontFamily: BODY,
            fontSize: 17,
            lineHeight: 1.5,
            color: VERDICT.text,
            maxWidth: 640,
          }}
        >
          {summaryLine}
        </div>
        {caveats.length > 0 ? (
          <div
            aria-label="scope caveats"
            style={{
              display: "flex",
              flexWrap: "wrap",
              gap: 8,
              marginTop: 14,
            }}
          >
            {caveats.slice(0, 6).map((caveat) => (
              <span
                key={caveat}
                style={{
                  fontFamily: BODY,
                  fontSize: 11,
                  color: VERDICT.inferred,
                  border: `1px solid ${VERDICT.inferred}`,
                  borderRadius: 999,
                  padding: "4px 9px",
                  background: `${VERDICT.inferred}16`,
                  whiteSpace: "nowrap",
                }}
              >
                {caveat}
              </span>
            ))}
          </div>
        ) : null}
      </div>

      {/* Right — the tallies + proof state */}
      <div
        style={{
          display: "flex",
          flexDirection: "column",
          gap: 12,
          alignItems: "flex-end",
        }}
      >
        {/* Case-file stamp — brand tactile accent, mirroring the video's
            CASE OPENED / CASE CLOSED letterpress stamps. */}
        <Stamp
          label={
            custodyAuthenticated
              ? "Case Closed"
              : manifestDone
                ? "Case Unverified"
                : "Case Open"
          }
          color={
            custodyAuthenticated
              ? VERDICT.confirmed
              : manifestDone
                ? VERDICT.inferred
                : VERDICT.accentPurpleLight
          }
          rotate={-6}
          fontSize={13}
          style={{ marginBottom: 2 }}
        />
        <div style={{ display: "flex", flexWrap: "wrap", gap: 8, justifyContent: "flex-end" }}>
          {tally.confirmed > 0 && (
            <EvidenceTag label={`${tally.confirmed} confirmed`} tier="CONFIRMED" />
          )}
          {tally.inferred > 0 && (
            <EvidenceTag label={`${tally.inferred} inferred`} tier="INFERRED" />
          )}
          {tally.hypothesis > 0 && (
            <EvidenceTag label={`${tally.hypothesis} hypothesis`} tier="HYPOTHESIS" />
          )}
          {tally.total === 0 && (
            <span style={{ fontFamily: BODY, fontSize: 13, color: VERDICT.muted }}>
              no findings yet
            </span>
          )}
        </div>
        <span
          style={{
            fontFamily: GROTESK,
            fontSize: 13,
            fontWeight: 600,
            letterSpacing: 1,
            textTransform: "uppercase",
            color: custodyAuthenticated
              ? VERDICT.confirmed
              : manifestDone
                ? VERDICT.inferred
                : VERDICT.muted,
            display: "inline-flex",
            alignItems: "center",
            gap: 7,
          }}
        >
          <span
            aria-hidden
            style={{
              width: 8,
              height: 8,
              borderRadius: "50%",
              background: custodyAuthenticated
                ? VERDICT.confirmed
                : manifestDone
                  ? VERDICT.inferred
                  : VERDICT.mutedDark,
            }}
          />
          {custodyAuthenticated
            ? "Signed · authenticated offline"
            : manifestDone
              ? custody
                ? "Terminal state · authentication failed"
                : "Terminal state · verification pending"
              : "Investigation running · live stream unverified"}
        </span>
        {manifestDone ? (
          <span
            aria-label="independent browser custody re-verification"
            title={custodyBadge.detail}
            style={{
              fontFamily: BODY,
              fontSize: 11,
              color: custodyBadge.color,
              display: "inline-flex",
              alignItems: "center",
              gap: 6,
            }}
          >
            <span
              aria-hidden
              style={{
                width: 7,
                height: 7,
                borderRadius: "50%",
                background: custodyBadge.color,
              }}
            />
            {custodyBadge.label}
          </span>
        ) : null}
      </div>
    </section>
  );
}

export default VerdictSummary;
