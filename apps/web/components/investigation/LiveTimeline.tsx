// LiveTimeline — the headline "watch the timeline build" moment of mission
// control. A horizontal swimlane (one lane per artifact class) of event dots
// positioned by UTC time, mirroring the engine's own fig_timeline_overview so
// the in-app view and the PDF figure tell the same story.
//
// Before seal, provisional dots stream from the explicitly unverified live
// audit feed. After seal, the only authenticated source is normalized_timeline
// inside the hash-bound verdict snapshot; standalone timeline sidecars are
// presentation-only and never inherit the custody badge.

"use client";

import { useMemo } from "react";

import type { AuditLine } from "@/lib/audit-tail";
import type { VerdictPayload } from "@/lib/verdict-summary-policy";
import {
  layoutTimeline,
  selectTimelineForCustody,
} from "@/lib/timeline-data";
import { BODY, MONO, RADIUS, SectionHeading, VERDICT } from "@/lib/verdict-ui";

interface LiveTimelineProps {
  events: AuditLine[];
  sealObserved: boolean;
  custodyAuthenticated: boolean;
  authenticatedVerdict: VerdictPayload | null;
}

const LANE_HEIGHT = 30;
const PLOT_LEFT = 150; // px gutter for lane labels

const SIGNIFICANCE_COLOR: Record<string, string> = {
  finding_support: VERDICT.alertRed,
  triage_lead: VERDICT.inferred,
  context: VERDICT.hypothesis,
};

function significanceColor(sig: string): string {
  return SIGNIFICANCE_COLOR[sig] ?? VERDICT.muted;
}

function fmtTs(ts: number): string {
  if (!ts) return "";
  return new Date(ts).toISOString().slice(0, 16).replace("T", " ") + "Z";
}

export function LiveTimeline({
  events,
  sealObserved,
  custodyAuthenticated,
  authenticatedVerdict,
}: LiveTimelineProps) {
  const selection = useMemo(
    () =>
      selectTimelineForCustody({
        liveEvents: events,
        sealObserved,
        custodyAuthenticated,
        authenticatedVerdict,
      }),
    [events, sealObserved, custodyAuthenticated, authenticatedVerdict],
  );
  const merged = selection.events;
  const layout = useMemo(() => layoutTimeline(merged), [merged]);

  const hasData = merged.length > 0;

  return (
    <section
      aria-label="Event timeline"
      style={{
        background: VERDICT.surface,
        border: `1px solid ${VERDICT.border}`,
        borderRadius: RADIUS.card,
        padding: 18,
        marginTop: 24,
      }}
    >
      <style>{`
        @keyframes verdictDotIn { from { opacity: 0; transform: scale(0.4); } to { opacity: 1; transform: scale(1); } }
        .verdict-tl-dot { animation: verdictDotIn 280ms cubic-bezier(0.16,1,0.3,1); }
        @media (prefers-reduced-motion: reduce) { .verdict-tl-dot { animation: none; } }
      `}</style>

      <SectionHeading
        right={
          <>
            {merged.length} event{merged.length === 1 ? "" : "s"}
            {selection.source === "verdict-authenticated"
              ? " · authenticated verdict snapshot"
              : selection.source === "live-unverified" && merged.length > 0
                ? " · live · unverified"
                : selection.source === "terminal-unverified"
                  ? " · terminal state unverified"
                  : ""}
          </>
        }
      >
        EVENT TIMELINE
      </SectionHeading>

      {!hasData ? (
        <p style={{ fontFamily: BODY, fontSize: 13, color: VERDICT.mutedDark, margin: "8px 0" }}>
          {selection.source === "terminal-unverified"
            ? "timeline withheld until the joint verdict snapshot authenticates."
            : "timeline builds from the unverified live stream; authenticated events come only from the bound verdict snapshot."}
        </p>
      ) : (
        <>
          <div style={{ position: "relative" }}>
            {layout.lanes.map((lane) => {
              const laneEvents = merged.filter((e) => e.artifactClass === lane);
              return (
                <div
                  key={lane}
                  style={{
                    position: "relative",
                    height: LANE_HEIGHT,
                    borderTop: `1px solid ${VERDICT.borderSubtle}`,
                  }}
                >
                  <span
                    style={{
                      position: "absolute",
                      left: 0,
                      top: "50%",
                      transform: "translateY(-50%)",
                      width: PLOT_LEFT - 12,
                      fontFamily: MONO,
                      fontSize: 12,
                      color: VERDICT.muted,
                      whiteSpace: "nowrap",
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                    }}
                  >
                    {lane}
                  </span>
                  <div
                    style={{
                      position: "absolute",
                      left: PLOT_LEFT,
                      right: 8,
                      top: 0,
                      bottom: 0,
                    }}
                  >
                    {laneEvents.map((e) => {
                      const color = significanceColor(e.significance);
                      return (
                        <span
                          key={e.id}
                          className="verdict-tl-dot"
                          title={`${fmtTs(e.ts)} · ${e.significance}${e.confidence ? " · " + e.confidence : ""}\n${e.summary}`}
                          style={{
                            position: "absolute",
                            left: `${layout.xFor(e.ts) * 100}%`,
                            top: "50%",
                            transform: "translate(-50%, -50%)",
                            width: 9,
                            height: 9,
                            borderRadius: "50%",
                            background: color,
                            border: e.provisional ? `1px dashed ${color}` : "none",
                            opacity: e.provisional ? 0.5 : 0.9,
                            boxShadow: `0 0 6px ${color}66`,
                          }}
                        />
                      );
                    })}
                  </div>
                </div>
              );
            })}
            <div style={{ borderTop: `1px solid ${VERDICT.borderSubtle}` }} />
          </div>

          {/* time axis */}
          <div
            style={{
              display: "flex",
              justifyContent: "space-between",
              marginLeft: PLOT_LEFT,
              marginTop: 8,
              fontFamily: MONO,
              fontSize: 11,
              color: VERDICT.mutedDark,
            }}
          >
            <span>{fmtTs(layout.minTs)}</span>
            <span>{fmtTs(layout.maxTs)}</span>
          </div>

          {/* legend */}
          <div style={{ display: "flex", gap: 16, marginTop: 12, flexWrap: "wrap" }}>
            {[
              ["finding_support", "finding"],
              ["triage_lead", "triage lead"],
              ["context", "context"],
            ].map(([sig, label]) => (
              <span key={sig} style={{ display: "inline-flex", alignItems: "center", gap: 6, fontFamily: MONO, fontSize: 11, color: VERDICT.muted }}>
                <span style={{ width: 8, height: 8, borderRadius: "50%", background: significanceColor(sig) }} />
                {label}
              </span>
            ))}
          </div>
        </>
      )}
    </section>
  );
}
