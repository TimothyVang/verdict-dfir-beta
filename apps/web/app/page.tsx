// VERDICT live dashboard — the polished port of the demo video's
// single-host investigation scene (Beat 3) into the real product.
//
// Subscribes to /api/audit?case=<path> via EventSource, accumulates the
// audit-line stream, and feeds it to <InvestigationStreamPanel>, which
// reduces the raw stream into the terminal view + finding cards. The
// design system lives in @/lib/verdict-ui (ported 1:1 from the Remotion
// scenes). The NES.css placeholder + role-sprite grid this replaced are
// kept on disk (components/sprites/*) for the /codex + /debug views.
//
// Honest scope: this page ships the genuinely live-now panels only
// (investigation stream). ACH columns, fleet grid, cluster timeline, and
// the merkle/sigstore chain right-rail are gated behind backend routes
// that don't exist yet (see docs / workflow blueprint) and are NOT
// rendered with placeholder data.

"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import { DashboardNav } from "@/components/DashboardNav";
import { EvidenceBanner } from "@/components/investigation/EvidenceBanner";
import { GroundingPanel } from "@/components/investigation/GroundingPanel";
import { InvestigationStreamPanel } from "@/components/investigation/InvestigationStreamPanel";
import { LiveTimeline } from "@/components/investigation/LiveTimeline";
import { ReportPanel } from "@/components/investigation/ReportPanel";
import { StageRail } from "@/components/investigation/StageRail";
import {
  VerdictSummary,
  type AuthenticatedCustodyDisplaySnapshot,
} from "@/components/investigation/VerdictSummary";
import {
  isCustodySnapshotReadyHint,
  selectionMatchesConnectedCase,
  selectCustodyDisplayEvents,
  type BrowserAuditLine,
} from "@/lib/custody-display";
import { deriveEvidenceMeta } from "@/lib/evidence-meta";
import { deriveStageStates } from "@/lib/stage-state";
import { BODY, BrandMark, Kicker, RuleLine, SerifHeadline, VERDICT } from "@/lib/verdict-ui";

// Mirror /debug's local AuditLine shape — importing from @/lib/audit-tail
// would drag node:fs + chokidar into the client bundle. Keep in sync with
// `apps/web/lib/audit-tail.ts:AuditLine`.
type AuditLine = BrowserAuditLine;

type ConnState = "disconnected" | "connecting" | "live";

const MAX_EVENTS = 500;

export default function DashboardPage() {
  const [casePath, setCasePath] = useState("");
  const [connectedCasePath, setConnectedCasePath] = useState("");
  const [cases, setCases] = useState<{ path: string; name: string; mtime: number }[]>([]);
  const [events, setEvents] = useState<AuditLine[]>([]);
  const [conn, setConn] = useState<ConnState>("disconnected");
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [authenticatedSnapshot, setAuthenticatedSnapshot] =
    useState<AuthenticatedCustodyDisplaySnapshot | null>(null);
  const [reportReady, setReportReady] = useState(false);
  const esRef = useRef<EventSource | null>(null);

  const disconnect = useCallback(() => {
    if (esRef.current) {
      esRef.current.close();
      esRef.current = null;
    }
    setConn("disconnected");
    setConnectedCasePath("");
    setEvents([]);
    setAuthenticatedSnapshot(null);
    setReportReady(false);
  }, []);

  const connect = useCallback(
    (pathArg?: string) => {
      const target = (pathArg ?? casePath).trim();
      if (!target) {
        setErrorMsg("Enter an absolute case directory path first.");
        return;
      }
      if (esRef.current) {
        esRef.current.close();
        esRef.current = null;
      }
      setErrorMsg(null);
      setConn("connecting");
      setCasePath(target);
      setConnectedCasePath(target);
      setEvents([]);
      setAuthenticatedSnapshot(null);
      setReportReady(false);

      const url = `/api/audit?case=${encodeURIComponent(target)}`;
      const es = new EventSource(url);
      esRef.current = es;

      es.addEventListener("open", () => {
        setConn("live");
      });

      es.addEventListener("audit_line", (raw: MessageEvent) => {
        try {
          const line = JSON.parse(raw.data) as AuditLine;
          setEvents((prev) => {
            const next = [...prev, line];
            return next.length > MAX_EVENTS
              ? next.slice(next.length - MAX_EVENTS)
              : next;
          });
        } catch (err) {
          const msg = err instanceof Error ? err.message : String(err);
          setErrorMsg(`failed to parse audit_line: ${msg}`);
        }
      });

      es.addEventListener("error", (raw: Event) => {
        const maybeMsg = (raw as MessageEvent).data;
        if (typeof maybeMsg === "string" && maybeMsg.length > 0) {
          try {
            const parsed = JSON.parse(maybeMsg) as { error?: string };
            setErrorMsg(parsed.error ?? maybeMsg);
          } catch {
            setErrorMsg(maybeMsg);
          }
        } else {
          setErrorMsg(
            "EventSource error (connection refused, 400 from API, or stream closed). Check the case path and that audit.jsonl exists.",
          );
        }
        setConn("disconnected");
        es.close();
        esRef.current = null;
      });
    },
    [casePath],
  );

  // Tear down on unmount.
  useEffect(() => {
    return () => {
      if (esRef.current) {
        esRef.current.close();
        esRef.current = null;
      }
    };
  }, []);

  // Populate the case picker from the allow-listed roots (newest-first).
  useEffect(() => {
    let cancelled = false;
    fetch("/api/cases")
      .then((r) => r.json())
      .then((d: { cases?: { path: string; name: string; mtime: number }[] }) => {
        if (!cancelled) setCases(d.cases ?? []);
      })
      .catch(() => {
        /* leave empty — picker shows the no-cases hint */
      });
    return () => {
      cancelled = true;
    };
  }, []);

  // Deep link: ?case=... auto-populates and starts streaming on first mount.
  useEffect(() => {
    if (typeof window === "undefined") return;
    const params = new URLSearchParams(window.location.search);
    const c = params.get("case");
    if (c) {
      setCasePath(c);
      connect(c);
    }
    // Mount-only: fire the deep-link connect once.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const dotColor =
    conn === "live"
      ? VERDICT.confirmed
      : conn === "connecting"
        ? VERDICT.inferred
        : VERDICT.alertRed;

  // Stale-data warning (critic gap A1): the stream dropped but we still hold
  // events — surface it so a judge doesn't trust frozen data.
  const showStaleBanner = conn === "disconnected" && events.length > 0;

  // A verdict_packet is only a readiness hint. Closed/sealed language remains
  // gated on a fully authenticated joint custody snapshot below.
  const manifestDone = useMemo(
    () => isCustodySnapshotReadyHint(events),
    [events],
  );

  const custodyAuthenticated = authenticatedSnapshot !== null;
  const displayEvents = useMemo(
    () =>
      selectCustodyDisplayEvents({
        liveEvents: events,
        snapshotEvents: authenticatedSnapshot?.events ?? [],
        custodyAuthenticated,
        sealObserved: manifestDone,
      }),
    [events, authenticatedSnapshot, custodyAuthenticated, manifestDone],
  );

  // The connected case dir (deep-link or the connect form), drives the report
  // and timeline fetches.
  const connectedCase = connectedCasePath;

  // Pipeline progression for the stage rail (mission-control glance).
  const stages = useMemo(
    () => deriveStageStates(displayEvents, custodyAuthenticated && reportReady),
    [displayEvents, custodyAuthenticated, reportReady],
  );

  // What's under investigation — surfaced as the sticky evidence banner. Pulled
  // from the case_open audit events (path/sha256/size); null until they stream.
  const evidenceMeta = useMemo(
    () => deriveEvidenceMeta(displayEvents),
    [displayEvents],
  );

  return (
    <main
      style={{
        position: "relative",
        minHeight: "100vh",
        background: "transparent",
        color: VERDICT.text,
        fontFamily: BODY,
        overflowX: "hidden",
      }}
    >
      <div
        className="verdict-reveal"
        style={{
          position: "relative",
          maxWidth: 1600,
          margin: "0 auto",
          padding: "clamp(20px, 4vw, 40px)",
        }}
      >
        {/* Masthead */}
        <header
          style={{
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            flexWrap: "wrap",
            gap: 20,
            marginBottom: 16,
          }}
        >
          <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
            <Kicker>Live Investigation</Kicker>
            <SerifHeadline size={44}>Mission Control</SerifHeadline>
            <BrandMark size={56} withWordmark withTagline />
          </div>
          <span
            style={{
              display: "inline-flex",
              alignItems: "center",
              gap: 8,
              fontSize: 13,
              color: VERDICT.muted,
            }}
          >
            <span
              aria-label={`stream ${conn}`}
              style={{
                display: "inline-block",
                width: "0.7rem",
                height: "0.7rem",
                borderRadius: "9999px",
                background: dotColor,
                boxShadow: `0 0 8px ${dotColor}`,
              }}
            />
            {conn}
          </span>
        </header>

        <RuleLine style={{ marginBottom: 24 }} />

        {/* The human-first headline: verdict + plain summary + tallies, above
            the live machine stream. Renders once a case is connected. */}
        <VerdictSummary
          key={connectedCase || "no-connected-case"}
          events={events}
          caseDir={connectedCase}
          manifestDone={manifestDone}
          evidenceName={evidenceMeta?.name ?? undefined}
          onAuthenticatedSnapshot={setAuthenticatedSnapshot}
        />

        {/* What's under investigation — sticky so it stays in view while the
            terminal stream scrolls. */}
        <EvidenceBanner meta={evidenceMeta} />

        <DashboardNav active="audit" variant="dark" />

        {/* Connect control */}
        <section
          style={{
            background: VERDICT.surface,
            border: `1px solid ${VERDICT.border}`,
            borderRadius: 12,
            padding: 20,
            marginBottom: 24,
          }}
        >
          <label
            htmlFor="case-select"
            style={{
              display: "block",
              fontSize: 13,
              color: VERDICT.muted,
              marginBottom: 8,
            }}
          >
            Case — pick an investigation to open ({cases.length} available)
          </label>
          <div style={{ display: "flex", flexWrap: "wrap", gap: 12, minWidth: 0 }}>
            <select
              id="case-select"
              value={casePath}
              onChange={(e) => {
                const selected = e.target.value;
                setCasePath(selected);
                if (!selectionMatchesConnectedCase(selected, connectedCasePath)) {
                  setConnectedCasePath("");
                  setEvents([]);
                  setAuthenticatedSnapshot(null);
                  setReportReady(false);
                }
              }}
              disabled={conn !== "disconnected"}
              style={{
                flex: "1 1 260px",
                minWidth: 0,
                maxWidth: "100%",
                background: VERDICT.bg,
                border: `1px solid ${VERDICT.border}`,
                borderRadius: 8,
                padding: "10px 14px",
                color: VERDICT.text,
                fontFamily: BODY,
                fontSize: 14,
                outline: "none",
                cursor: conn !== "disconnected" ? "default" : "pointer",
              }}
            >
              <option value="">— select a case —</option>
              {casePath && !cases.some((c) => c.path === casePath) && (
                <option value={casePath}>
                  {casePath.split("/").filter(Boolean).pop()} (linked)
                </option>
              )}
              {cases.map((c) => (
                <option key={c.path} value={c.path}>
                  {c.name}
                </option>
              ))}
            </select>
            {conn === "disconnected" ? (
              <button
                type="button"
                onClick={() => connect()}
                style={{
                  background: `${VERDICT.accentPurple}26`,
                  border: `1px solid ${VERDICT.accentPurple}`,
                  color: VERDICT.accentPurpleLight,
                  borderRadius: 8,
                  padding: "10px 24px",
                  fontFamily: BODY,
                  fontWeight: 700,
                  fontSize: 14,
                  cursor: "pointer",
                }}
              >
                Connect
              </button>
            ) : (
              <button
                type="button"
                onClick={disconnect}
                style={{
                  background: `${VERDICT.alertRed}26`,
                  border: `1px solid ${VERDICT.alertRed}`,
                  color: VERDICT.alertRed,
                  borderRadius: 8,
                  padding: "10px 24px",
                  fontFamily: BODY,
                  fontWeight: 700,
                  fontSize: 14,
                  cursor: "pointer",
                }}
              >
                Disconnect
              </button>
            )}
            <span
              style={{
                alignSelf: "center",
                fontSize: 13,
                color: VERDICT.muted,
              }}
            >
              events: {events.length}
            </span>
          </div>

          {errorMsg ? (
            <div
              style={{
                marginTop: 14,
                background: `${VERDICT.alertRed}1a`,
                border: `1px solid ${VERDICT.alertRed}44`,
                borderRadius: 8,
                padding: "10px 14px",
                fontSize: 13,
                color: VERDICT.alertRed,
              }}
            >
              <strong>error:</strong> {errorMsg}
            </div>
          ) : null}

          {showStaleBanner ? (
            <div
              style={{
                marginTop: 14,
                background: `${VERDICT.inferred}1a`,
                border: `1px solid ${VERDICT.inferred}44`,
                borderRadius: 8,
                padding: "10px 14px",
                fontSize: 13,
                color: VERDICT.inferred,
              }}
            >
              stream disconnected — showing {events.length} buffered events;
              data may be stale. Reconnect to resume.
            </div>
          ) : null}
        </section>

        {/* Pipeline progression — the "is the machine alive?" glance */}
        <StageRail stages={stages} />

        {/* Mission control: stream + timeline (left), report (right) */}
        <style>{`
          .verdict-mission-grid {
            display: grid;
            grid-template-columns: minmax(0, 1.7fr) minmax(0, 1fr);
            gap: clamp(16px, 2vw, 28px);
            align-items: start;
          }
          @media (max-width: 1080px) {
            .verdict-mission-grid { grid-template-columns: 1fr; }
          }
        `}</style>
        <div className="verdict-mission-grid">
          <div style={{ minWidth: 0 }}>
            <InvestigationStreamPanel events={displayEvents as AuditLine[]} />
            <LiveTimeline
              events={displayEvents as AuditLine[]}
              sealObserved={manifestDone}
              authenticatedVerdict={authenticatedSnapshot?.verdict ?? null}
              custodyAuthenticated={custodyAuthenticated}
            />
          </div>
          <div style={{ display: "flex", flexDirection: "column", gap: 24, minWidth: 0 }}>
            <ReportPanel
              caseDir={connectedCase}
              manifestDone={manifestDone}
              onReadyChange={setReportReady}
            />
            <GroundingPanel caseDir={connectedCase} />
          </div>
        </div>
      </div>
    </main>
  );
}
