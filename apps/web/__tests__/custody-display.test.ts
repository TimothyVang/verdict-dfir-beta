import { describe, expect, it } from "vitest";

import {
  isCustodySnapshotReadyHint,
  selectionMatchesConnectedCase,
  selectCustodyDisplayEvents,
  type BrowserAuditLine,
} from "@/lib/custody-display";

function line(
  seq: number,
  kind: string,
  payload: Record<string, unknown> = {},
): BrowserAuditLine {
  return {
    seq,
    kind,
    ts: "2026-07-10T00:00:00Z",
    payload,
    raw_line: "{}",
  };
}

describe("custody-bound dashboard display", () => {
  it("replaces hostile or capped SSE state with the exact authenticated snapshot", () => {
    const hostileLive = [
      line(499, "finding_approved", {
        finding_id: "attacker-live",
        confidence: "CONFIRMED",
      }),
      line(500, "verdict_packet"),
    ];
    const restoredSnapshot = [
      line(0, "agent_message"),
      line(1, "finding_approved", {
        finding_id: "signed-snapshot",
        confidence: "INFERRED",
      }),
      line(2, "verdict_packet"),
    ];

    const selected = selectCustodyDisplayEvents({
      liveEvents: hostileLive,
      snapshotEvents: restoredSnapshot,
      custodyAuthenticated: true,
      sealObserved: true,
    });

    expect(selected).toEqual(restoredSnapshot);
    expect(selected).not.toContainEqual(hostileLive[0]);
  });

  it("shows no sealed findings or tallies when snapshot authentication fails", () => {
    const selected = selectCustodyDisplayEvents({
      liveEvents: [line(10, "finding_approved"), line(11, "verdict_packet")],
      snapshotEvents: [line(0, "finding_approved")],
      custodyAuthenticated: false,
      sealObserved: true,
    });

    expect(selected).toEqual([]);
  });

  it("keeps live pre-seal events explicitly separate from sealed custody", () => {
    const live = [line(0, "finding_approved")];

    expect(
      selectCustodyDisplayEvents({
        liveEvents: live,
        snapshotEvents: [],
        custodyAuthenticated: false,
        sealObserved: false,
      }),
    ).toEqual(live);
  });

  it("does not treat finalize start, failure, or a bare artifact record as closed", () => {
    expect(
      isCustodySnapshotReadyHint([
        line(1, "tool_call_start", { tool: "manifest_finalize" }),
      ]),
    ).toBe(false);
    expect(
      isCustodySnapshotReadyHint([
        line(1, "tool_call_output", {
          tool: "manifest_finalize",
          error: "signer failed",
        }),
      ]),
    ).toBe(false);
    expect(isCustodySnapshotReadyHint([line(1, "verdict_artifact")])).toBe(false);
    expect(isCustodySnapshotReadyHint([line(1, "verdict_packet")])).toBe(true);
  });

  it("invalidates Case A display before disconnected selection moves to Case B", () => {
    const authenticatedCaseA = "/cases/A";

    expect(
      selectionMatchesConnectedCase(authenticatedCaseA, authenticatedCaseA),
    ).toBe(true);
    expect(
      selectionMatchesConnectedCase("/cases/B", authenticatedCaseA),
    ).toBe(false);
    expect(selectionMatchesConnectedCase("/cases/B", "")).toBe(false);
  });
});
