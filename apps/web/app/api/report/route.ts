// Report-artifact serve endpoint — lets the dashboard view/download the
// presentation PDF (and sibling artifacts) for a case, same-origin, so the
// browser's native PDF viewer can render it in an iframe with no X-Frame
// issues. `buildReportLinks()` (lib/codex-server.ts) emits file:// links the
// browser blocks from an http://localhost origin; this route is the http shim.
//
// Usage:
//   GET  /api/report?case=<dir>&file=REPORT.pdf          -> inline file
//   GET  /api/report?case=<dir>&file=REPORT.pdf&dl=1     -> attachment
//   GET  /api/report?case=<dir>&list=1                   -> { files: [...] }
//   HEAD /api/report?case=<dir>&file=REPORT.pdf          -> 200/404 (poll)
//
// The `case` dir is validated against the same allow-list as /api/audit
// (`isAllowedCasePath`); `file` is validated against a hard allow-list of
// known artifact names (+ figures/<name>.png) so no arbitrary path escapes.

import path from "node:path";

import {
  readAllowedCaseFile,
  resolveAllowedCasePath,
  statAllowedCaseFile,
} from "@/lib/audit-tail";
import { authorizeDashboardRequest } from "@/lib/dashboard-auth";
import { REPORT_ARTIFACT_NAMES, REPORT_ARTIFACTS } from "@/lib/report-artifacts";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const CONTENT_TYPES: Record<string, string> = {
  ".pdf": "application/pdf",
  ".html": "text/html; charset=utf-8",
  ".md": "text/markdown; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".jsonl": "application/x-ndjson; charset=utf-8",
  ".csv": "text/csv; charset=utf-8",
  ".png": "image/png",
};

const ARTIFACT_SECURITY_HEADERS: Readonly<Record<string, string>> = {
  // REPORT.html intentionally contains presentation JavaScript. CSP sandbox
  // permits that rendering while withholding same-origin authority, cookies,
  // network access, navigation, forms, and external assets.
  "Content-Security-Policy": [
    "sandbox allow-scripts",
    "default-src 'none'",
    "script-src 'unsafe-inline'",
    "style-src 'unsafe-inline' data:",
    "img-src data:",
    "font-src data:",
    "connect-src 'none'",
    "form-action 'none'",
    "base-uri 'none'",
    "frame-src 'none'",
    "object-src 'none'",
  ].join("; "),
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "no-referrer",
  "Cache-Control": "no-store",
};

function artifactTrust(file: string): string {
  return file.startsWith("REPORT") || file.startsWith("timeline.")
    ? "presentation-only-unverified"
    : "independent-read-unverified";
}

/** Validate the requested file name. Returns the safe relative path, or null. */
function safeFile(file: string | null): string | null {
  if (!file) return null;
  if (file.includes("..") || file.includes("\\")) return null;
  if (REPORT_ARTIFACT_NAMES.has(file)) return file;
  // figures/<name>.png — a single subdir, png only, no nested traversal.
  const figMatch = /^figures\/[A-Za-z0-9_-]+\.png$/.exec(file);
  if (figMatch) return file;
  return null;
}

function contentTypeFor(file: string): string {
  return CONTENT_TYPES[path.extname(file).toLowerCase()] ?? "application/octet-stream";
}

/** Resolve + allow-list-check the case dir. Returns the resolved dir or a 400. */
function resolveCase(url: URL): { dir: string } | { error: Response } {
  const caseDir = url.searchParams.get("case");
  if (!caseDir) {
    return { error: new Response("missing required ?case=<absolute-case-dir>", { status: 400 }) };
  }
  const requested = path.resolve(caseDir);
  const resolved = resolveAllowedCasePath(requested);
  if (!resolved) {
    return {
      error: new Response(
        JSON.stringify({ error: "case path not in allow-list", reason: requested }),
        { status: 400, headers: { "Content-Type": "application/json" } },
      ),
    };
  }
  return { dir: resolved };
}

export async function GET(request: Request): Promise<Response> {
  const denied = authorizeDashboardRequest(request);
  if (denied) return denied;
  const url = new URL(request.url);
  const resolved = resolveCase(url);
  if ("error" in resolved) return resolved.error;
  const caseDir = resolved.dir;

  // ?list=1 — report which artifacts are present (drives the report panel).
  if (url.searchParams.get("list") === "1") {
    const files = await Promise.all(
      REPORT_ARTIFACTS.map(async ({ name }) => {
        try {
          const stat = await statAllowedCaseFile(caseDir, name);
          return stat
            ? { name, available: true, bytes: stat.size }
            : { name, available: false, bytes: 0 };
        } catch {
          return { name, available: false, bytes: 0 };
        }
      }),
    );
    return Response.json({ case: caseDir, files });
  }

  const file = safeFile(url.searchParams.get("file"));
  if (!file) {
    return new Response(JSON.stringify({ error: "missing or disallowed ?file=" }), {
      status: 400,
      headers: { "Content-Type": "application/json" },
    });
  }

  const filePath = path.resolve(caseDir, file);
  // Defense in depth: the resolved path must stay inside the case dir.
  if (filePath !== caseDir && !filePath.startsWith(caseDir + path.sep)) {
    return new Response("forbidden", { status: 400 });
  }

  const data = await readAllowedCaseFile(caseDir, file);
  if (!data) {
    return new Response("not found", { status: 404 });
  }

  const disposition = url.searchParams.get("dl") === "1" ? "attachment" : "inline";
  return new Response(new Uint8Array(data), {
    headers: {
      "Content-Type": contentTypeFor(file),
      "Content-Disposition": `${disposition}; filename="${path.basename(file)}"`,
      "X-Verdict-Artifact-Trust": artifactTrust(file),
      ...ARTIFACT_SECURITY_HEADERS,
    },
  });
}

export async function HEAD(request: Request): Promise<Response> {
  const denied = authorizeDashboardRequest(request);
  if (denied) return denied;
  const url = new URL(request.url);
  const resolved = resolveCase(url);
  if ("error" in resolved) return new Response(null, { status: 400 });
  const file = safeFile(url.searchParams.get("file"));
  if (!file) return new Response(null, { status: 400 });
  const filePath = path.resolve(resolved.dir, file);
  if (filePath !== resolved.dir && !filePath.startsWith(resolved.dir + path.sep)) {
    return new Response(null, { status: 400 });
  }
  const stat = await statAllowedCaseFile(resolved.dir, file);
  return new Response(null, { status: stat ? 200 : 404 });
}
