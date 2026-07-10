import { createHash } from "node:crypto";
import path from "node:path";

import {
  readAllowedCaseFilesSnapshot,
  resolveAllowedCasePath,
} from "@/lib/audit-tail";
import { authorizeDashboardRequest } from "@/lib/dashboard-auth";
import {
  CUSTODY_SNAPSHOT_PATHS,
  CUSTODY_SNAPSHOT_SCHEMA,
  custodySnapshotDescriptor,
  type CustodyArtifactIdentity,
} from "@/lib/custody-snapshot";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const SNAPSHOT_ATTEMPTS = 3;

function sha256(data: Buffer | string): string {
  return createHash("sha256").update(data).digest("hex");
}

function exactUtf8(data: Buffer): string | null {
  const text = data.toString("utf-8");
  return Buffer.from(text, "utf-8").equals(data) ? text : null;
}

/** Return audit + manifest + verdict from one jointly stability-checked read. */
export async function GET(request: Request): Promise<Response> {
  const denied = authorizeDashboardRequest(request);
  if (denied) return denied;

  const requested = new URL(request.url).searchParams.get("case");
  if (!requested) {
    return Response.json({ error: "missing required ?case=" }, { status: 400 });
  }
  const caseDir = resolveAllowedCasePath(path.resolve(requested));
  if (!caseDir) {
    return Response.json({ error: "case path not in allow-list" }, { status: 400 });
  }

  let snapshot: Map<string, Buffer> | null = null;
  for (let attempt = 0; attempt < SNAPSHOT_ATTEMPTS && !snapshot; attempt += 1) {
    snapshot = await readAllowedCaseFilesSnapshot(caseDir, [
      { relativeFile: "audit.jsonl" },
      { relativeFile: "run.manifest.json" },
      { relativeFile: "verdict.json" },
    ]);
  }
  const audit = snapshot?.get("audit.jsonl");
  const manifestBytes = snapshot?.get("run.manifest.json");
  const verdictBytes = snapshot?.get("verdict.json");
  if (!audit || !manifestBytes || !verdictBytes) {
    return Response.json(
      { error: "custody files changed during the snapshot or are unavailable" },
      { status: 409, headers: { "Cache-Control": "no-store" } },
    );
  }

  const auditText = exactUtf8(audit);
  const manifestText = exactUtf8(manifestBytes);
  const verdictText = exactUtf8(verdictBytes);
  if (auditText === null || manifestText === null || verdictText === null) {
    return Response.json(
      { error: "custody artifacts must be exact UTF-8" },
      { status: 422, headers: { "Cache-Control": "no-store" } },
    );
  }

  try {
    for (const [name, text] of [
      ["run.manifest.json", manifestText],
      ["verdict.json", verdictText],
    ] as const) {
      const parsed = JSON.parse(text) as unknown;
      if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
        throw new Error(`${name} must be an object`);
      }
    }
  } catch {
    return Response.json(
      { error: "manifest or verdict artifact is not valid object JSON" },
      { status: 422, headers: { "Cache-Control": "no-store" } },
    );
  }

  const buffers = [audit, manifestBytes, verdictBytes] as const;
  const artifacts: CustodyArtifactIdentity[] = CUSTODY_SNAPSHOT_PATHS.map(
    (artifactPath, index) => ({
      path: artifactPath,
      byteCount: buffers[index].byteLength,
      sha256: sha256(buffers[index]),
    }),
  );
  const snapshotSha256 = sha256(custodySnapshotDescriptor(artifacts));
  return Response.json(
    {
      schemaVersion: CUSTODY_SNAPSHOT_SCHEMA,
      snapshotSha256,
      artifacts,
      auditText,
      manifestText,
      verdictText,
    },
    {
      headers: {
        "Cache-Control": "no-store",
        ETag: `"${snapshotSha256}"`,
        "X-Content-Type-Options": "nosniff",
      },
    },
  );
}
