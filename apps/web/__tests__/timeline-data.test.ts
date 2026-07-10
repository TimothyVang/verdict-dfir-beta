import { describe, expect, it } from "vitest";

import { selectTimelineForCustody } from "@/lib/timeline-data";

const boundTimeline = {
  events: [
    {
      event_id: "bound-event",
      timestamp_utc: "2026-07-10T00:00:00Z",
      artifact_class: "evtx",
      significance: "finding_support",
      summary: "bound",
    },
  ],
};

const replacementTimeline = {
  events: [
    {
      event_id: "replacement-event",
      timestamp_utc: "2026-07-10T00:00:01Z",
      artifact_class: "network",
      significance: "finding_support",
      summary: "post-seal replacement",
    },
  ],
};

describe("timeline custody source", () => {
  it("uses only normalized_timeline from the authenticated verdict snapshot", () => {
    const result = selectTimelineForCustody({
      sealObserved: true,
      custodyAuthenticated: true,
      authenticatedVerdict: { normalized_timeline: boundTimeline },
      standaloneTimeline: replacementTimeline,
      liveEvents: [],
    });

    expect(result.source).toBe("verdict-authenticated");
    expect(result.events.map((event) => event.id)).toEqual(["bound-event"]);
    expect(result.events.map((event) => event.id)).not.toContain(
      "replacement-event",
    );
  });

  it("never calls an unbound standalone timeline authoritative after seal", () => {
    const result = selectTimelineForCustody({
      sealObserved: true,
      custodyAuthenticated: false,
      authenticatedVerdict: null,
      standaloneTimeline: replacementTimeline,
      liveEvents: [],
    });

    expect(result.source).toBe("terminal-unverified");
    expect(result.events).toEqual([]);
  });
});
