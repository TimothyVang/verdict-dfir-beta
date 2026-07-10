export interface BrowserAuditLine {
  seq: number;
  kind: string;
  ts: string;
  payload: Record<string, unknown>;
  line_hash?: string;
  raw_line: string;
}

export function isCustodySnapshotReadyHint(
  events: ReadonlyArray<BrowserAuditLine>,
): boolean {
  // verdict_packet is appended only after the verdict artifact and release
  // packet have been committed. A finalize start/error or bare artifact is
  // merely a retry hint and must never close the Case in the UI.
  return events.some((event) => event.kind === "verdict_packet");
}

/** Only the exact selected Case may retain an already-rendered Case binding. */
export function selectionMatchesConnectedCase(
  selectedCasePath: string,
  connectedCasePath: string,
): boolean {
  return (
    connectedCasePath.length > 0 && selectedCasePath === connectedCasePath
  );
}

export interface CustodyDisplayInputs {
  liveEvents: ReadonlyArray<BrowserAuditLine>;
  snapshotEvents: ReadonlyArray<BrowserAuditLine>;
  custodyAuthenticated: boolean;
  sealObserved: boolean;
}

/** Select the only audit sequence allowed to sit beside an authenticated badge. */
export function selectCustodyDisplayEvents(
  inputs: CustodyDisplayInputs,
): ReadonlyArray<BrowserAuditLine> {
  if (!inputs.sealObserved) return inputs.liveEvents;
  return inputs.custodyAuthenticated ? inputs.snapshotEvents : [];
}
