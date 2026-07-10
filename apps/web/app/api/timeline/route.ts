// Presentation-only normalized-timeline endpoint. These independently mutable
// sidecars are useful for export, but are not custody-authenticated. The main
// dashboard derives authenticated timeline state only from verdict.json bytes
// in /api/custody-snapshot.
//
// Usage: GET /api/timeline?case=<dir>  ->  { version, events: [...], ... }
//
// `case` is validated against the same allow-list as /api/audit.

import path from "node:path";

import {
  readAllowedCaseFile,
  resolveAllowedCasePath,
} from "@/lib/audit-tail";
import { authorizeDashboardRequest } from "@/lib/dashboard-auth";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const PRESENTATION_HEADERS = {
  "Cache-Control": "no-store",
  "X-Verdict-Artifact-Trust": "presentation-only-unverified",
};

async function readJson(caseDir: string, file: string): Promise<unknown | null> {
  try {
    const data = await readAllowedCaseFile(caseDir, file);
    return data ? JSON.parse(data.toString("utf-8")) : null;
  } catch {
    return null;
  }
}

export async function GET(request: Request): Promise<Response> {
  const denied = authorizeDashboardRequest(request);
  if (denied) return denied;
  const url = new URL(request.url);
  const caseDir = url.searchParams.get("case");
  if (!caseDir) {
    return new Response("missing required ?case=<absolute-case-dir>", { status: 400 });
  }
  const requested = path.resolve(caseDir);
  const resolved = resolveAllowedCasePath(requested);
  if (!resolved) {
    return new Response(
      JSON.stringify({ error: "case path not in allow-list", reason: requested }),
      { status: 400, headers: { "Content-Type": "application/json" } },
    );
  }

  // Prefer the standalone presentation sidecar; this route's trust header
  // explicitly prevents callers from confusing it with custody verification.
  const timeline = await readJson(resolved, "timeline.json");
  if (timeline && typeof timeline === "object") {
    return Response.json(timeline, { headers: PRESENTATION_HEADERS });
  }

  const verdict = await readJson(resolved, "verdict.json");
  if (verdict && typeof verdict === "object") {
    const nt = (verdict as Record<string, unknown>).normalized_timeline;
    if (nt && typeof nt === "object") {
      return Response.json(nt, { headers: PRESENTATION_HEADERS });
    }
  }

  return new Response(
    JSON.stringify({ error: "no timeline available yet", events: [] }),
    {
      status: 404,
      headers: { "Content-Type": "application/json", ...PRESENTATION_HEADERS },
    },
  );
}
