import { createHash } from "node:crypto";
import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { GET as reportGet } from "@/app/api/report/route";
import { GET as custodySnapshotGet } from "@/app/api/custody-snapshot/route";
import { POST as sessionPost } from "@/app/api/session/route";
import { GET as timelineGet } from "@/app/api/timeline/route";
import { validateCustodySnapshotResponse } from "@/lib/custody-snapshot";

let tmpDir: string;
let repo: string;
let caseDir: string;
const DASHBOARD_CAPABILITY = "a".repeat(64);
const DASHBOARD_EXCHANGE = "e".repeat(64);

function authorizedRequest(url: string): Request {
  return new Request(url, {
    headers: {
      Cookie: `verdict_dashboard_session=${DASHBOARD_CAPABILITY}`,
    },
  });
}

function exchangeRequest(params: URLSearchParams): Request {
  const body = params.toString();
  return new Request("http://verdict-test.localhost/api/session", {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      "Content-Length": String(Buffer.byteLength(body, "utf-8")),
    },
    body,
  });
}

beforeEach(async () => {
  tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "verdict-route-security-"));
  repo = path.join(tmpDir, "repo");
  await fs.mkdir(path.join(repo, "scripts"), { recursive: true });
  await fs.mkdir(path.join(repo, "apps", "web"), { recursive: true });
  await fs.writeFile(path.join(repo, "scripts", "doctor.sh"), "\n");
  await fs.writeFile(path.join(repo, "apps", "web", "package.json"), "{}\n");
  await fs.writeFile(path.join(repo, "pnpm-workspace.yaml"), "packages: []\n");
  caseDir = path.join(repo, "tmp", "auto-runs", "case-001");
  await fs.mkdir(caseDir, { recursive: true });
  process.env.FINDEVIL_REPO_ROOT = repo;
  process.env.FINDEVIL_DASHBOARD_CAPABILITY = DASHBOARD_CAPABILITY;
  const exchangeFile = path.join(tmpDir, "dashboard-exchange");
  await fs.writeFile(exchangeFile, DASHBOARD_EXCHANGE + "\n", { mode: 0o600 });
  process.env.FINDEVIL_DASHBOARD_EXCHANGE_FILE = exchangeFile;
});

afterEach(async () => {
  delete process.env.FINDEVIL_REPO_ROOT;
  delete process.env.FINDEVIL_DASHBOARD_EXTRA_ROOTS;
  delete process.env.FINDEVIL_DASHBOARD_CAPABILITY;
  delete process.env.FINDEVIL_DASHBOARD_EXCHANGE_FILE;
  await fs.rm(tmpDir, { recursive: true, force: true });
});

describe("dashboard route filesystem boundary", () => {
  it("exchanges the per-launch token for an HttpOnly same-site session", async () => {
    const wrong = await sessionPost(
      exchangeRequest(new URLSearchParams({ token: "b".repeat(64), next: "/" })),
    );
    expect(wrong.status).toBe(401);

    const next = `/?case=${encodeURIComponent(caseDir)}`;
    const accepted = await sessionPost(
      exchangeRequest(new URLSearchParams({ token: DASHBOARD_EXCHANGE, next })),
    );
    expect(accepted.status).toBe(303);
    expect(accepted.headers.get("set-cookie")).toContain("HttpOnly");
    expect(accepted.headers.get("set-cookie")).toContain("SameSite=Strict");
    expect(accepted.headers.get("set-cookie")).toContain("Path=/api");
    expect(accepted.headers.get("location")).not.toContain("token=");

    const replay = await sessionPost(
      exchangeRequest(new URLSearchParams({ token: DASHBOARD_EXCHANGE, next: "/" })),
    );
    expect(replay.status).toBe(401);
  });

  it("rejects unbounded or multipart session exchange bodies before parsing", async () => {
    const missingLength = await sessionPost(
      new Request("http://verdict-test.localhost/api/session", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: `token=${DASHBOARD_EXCHANGE}`,
      }),
    );
    const multipart = await sessionPost(
      new Request("http://verdict-test.localhost/api/session", {
        method: "POST",
        headers: {
          "Content-Type": "multipart/form-data; boundary=x",
          "Content-Length": "9000",
        },
        body: "--x--\r\n",
      }),
    );

    expect(missingLength.status).toBe(400);
    expect(multipart.status).toBe(400);
    expect(multipart.headers.get("cross-origin-resource-policy")).toBe("same-origin");
  });

  it("denies report APIs without the per-launch dashboard session", async () => {
    await fs.writeFile(path.join(caseDir, "REPORT.md"), "private report\n");
    const query = new URLSearchParams({ case: caseDir, file: "REPORT.md" });
    const url = `http://localhost/api/report?${query.toString()}`;

    const missing = await reportGet(new Request(url));
    const wrong = await reportGet(
      new Request(url, {
        headers: { Cookie: `verdict_dashboard_session=${"b".repeat(64)}` },
      }),
    );

    expect(missing.status).toBe(401);
    expect(wrong.status).toBe(401);

    const custody = await custodySnapshotGet(
      new Request(
        `http://localhost/api/custody-snapshot?case=${encodeURIComponent(caseDir)}`,
      ),
    );
    expect(custody.status).toBe(401);
  });

  it("pins every supported dashboard launcher to loopback", async () => {
    const webRoot = path.resolve(process.cwd());
    const projectRoot = path.resolve(webRoot, "..", "..");
    const packageJson = JSON.parse(
      await fs.readFile(path.join(webRoot, "package.json"), "utf-8"),
    ) as { scripts: Record<string, string> };
    expect(packageJson.scripts.dev).toContain("--hostname 127.0.0.1");
    expect(packageJson.scripts.start).toContain("--hostname 127.0.0.1");

    for (const script of [
      "scripts/verdict",
      "scripts/codex-dashboard.sh",
      "scripts/codex-dashboard.ps1",
    ]) {
      const source = await fs.readFile(path.join(projectRoot, script), "utf-8");
      expect(source).toContain("--hostname");
      expect(source).toContain("127.0.0.1");
      expect(source).toContain("FINDEVIL_DASHBOARD_CAPABILITY");
      expect(
        source.includes("/api/session") || source.includes("dashboard_launch_file"),
      ).toBe(true);
    }

    const windowsLauncher = await fs.readFile(
      path.join(projectRoot, "scripts", "codex-dashboard.ps1"),
      "utf-8",
    );
    expect(windowsLauncher).toContain("LocalEd25519Signer");
    expect(windowsLauncher).toContain("public_fingerprint");
    expect(windowsLauncher).toContain(
      "FINDEVIL_ED25519_EXPECTED_FINGERPRINT",
    );
  });

  it("serves audit, manifest, and verdict from one content-bound stable snapshot", async () => {
    const auditText =
      '{"kind":"case_open","payload":{},"prev_hash":"","seq":0,"ts":"2026-07-10T00:00:00Z"}\n';
    const manifest = { case_id: "case-001", audit_log_record_count: 1 };
    const manifestText = JSON.stringify(manifest);
    const verdictText = JSON.stringify({
      case_id: "case-001",
      verdict: "INDETERMINATE",
    });
    await fs.writeFile(path.join(caseDir, "audit.jsonl"), auditText);
    await fs.writeFile(path.join(caseDir, "run.manifest.json"), manifestText);
    await fs.writeFile(path.join(caseDir, "verdict.json"), verdictText);
    const query = new URLSearchParams({ case: caseDir });

    const response = await custodySnapshotGet(
      authorizedRequest(
        `http://localhost/api/custody-snapshot?${query.toString()}`,
      ),
    );

    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(response.headers.get("etag")).toMatch(/^"[0-9a-f]{64}"$/);
    const body = (await response.json()) as {
      schemaVersion: string;
      snapshotSha256: string;
      auditText: string;
      manifestText: string;
      verdictText: string;
      artifacts: Array<{ path: string; byteCount: number; sha256: string }>;
    };
    expect(body.schemaVersion).toBe("verdict.custody-snapshot.v1");
    expect(body.auditText).toBe(auditText);
    expect(body.manifestText).toBe(manifestText);
    expect(body.verdictText).toBe(verdictText);
    expect(body.artifacts.map((artifact) => artifact.path)).toEqual([
      "audit.jsonl",
      "run.manifest.json",
      "verdict.json",
    ]);
    for (const [index, text] of [auditText, manifestText, verdictText].entries()) {
      expect(body.artifacts[index].byteCount).toBe(Buffer.byteLength(text));
      expect(body.artifacts[index].sha256).toBe(
        createHash("sha256").update(text).digest("hex"),
      );
    }
    expect(response.headers.get("etag")).toBe(`"${body.snapshotSha256}"`);
    await expect(
      validateCustodySnapshotResponse(body, response.headers.get("etag")),
    ).resolves.toEqual(body);
    await expect(
      validateCustodySnapshotResponse(
        { ...body, verdictText: verdictText.replace("INDETERMINATE", "NO_EVIL") },
        response.headers.get("etag"),
      ),
    ).rejects.toThrow(/does not match bytes/);
  });

  it("fails closed when verdict.json is absent from the joint snapshot", async () => {
    await fs.writeFile(
      path.join(caseDir, "audit.jsonl"),
      '{"kind":"case_open","payload":{},"prev_hash":"","seq":0,"ts":"2026-07-10T00:00:00Z"}\n',
    );
    await fs.writeFile(
      path.join(caseDir, "run.manifest.json"),
      '{"case_id":"case-001"}',
    );

    const response = await custodySnapshotGet(
      authorizedRequest(
        `http://localhost/api/custody-snapshot?case=${encodeURIComponent(caseDir)}`,
      ),
    );

    expect(response.status).toBe(409);
  });

  it("binds the ETag to verdict bytes so a replacement cannot reuse custody", async () => {
    await fs.writeFile(path.join(caseDir, "audit.jsonl"), "audit\n");
    await fs.writeFile(path.join(caseDir, "run.manifest.json"), "{}\n");
    await fs.writeFile(
      path.join(caseDir, "verdict.json"),
      '{"case_id":"case-001","verdict":"INDETERMINATE"}\n',
    );
    const url = `http://localhost/api/custody-snapshot?case=${encodeURIComponent(caseDir)}`;
    const before = await custodySnapshotGet(authorizedRequest(url));

    await fs.writeFile(
      path.join(caseDir, "verdict.json"),
      '{"case_id":"case-001","verdict":"SUSPICIOUS"}\n',
    );
    const after = await custodySnapshotGet(authorizedRequest(url));

    expect(before.status).toBe(200);
    expect(after.status).toBe(200);
    expect(after.headers.get("etag")).not.toBe(before.headers.get("etag"));
  });

  it("does not follow an allowlisted report filename symlink", async () => {
    if (process.platform === "win32") return;
    const external = path.join(tmpDir, "external-secret.md");
    await fs.writeFile(external, "DO-NOT-DISCLOSE\n");
    await fs.symlink(external, path.join(caseDir, "REPORT.md"));

    const query = new URLSearchParams({ case: caseDir, file: "REPORT.md" });
    const response = await reportGet(
      authorizedRequest(`http://localhost/api/report?${query.toString()}`),
    );

    expect(response.status).toBe(404);
    expect(await response.text()).not.toContain("DO-NOT-DISCLOSE");
  });

  it("does not follow a timeline.json symlink outside the case", async () => {
    if (process.platform === "win32") return;
    const external = path.join(tmpDir, "external-timeline.json");
    await fs.writeFile(
      external,
      JSON.stringify({ events: [{ summary: "DO-NOT-DISCLOSE" }] }),
    );
    await fs.symlink(external, path.join(caseDir, "timeline.json"));

    const query = new URLSearchParams({ case: caseDir });
    const response = await timelineGet(
      authorizedRequest(`http://localhost/api/timeline?${query.toString()}`),
    );

    expect(response.status).toBe(404);
    expect(await response.text()).not.toContain("DO-NOT-DISCLOSE");
  });

  it("still serves a regular report file inside a real case directory", async () => {
    await fs.writeFile(path.join(caseDir, "REPORT.md"), "scoped report\n");
    const query = new URLSearchParams({ case: caseDir, file: "REPORT.md" });

    const response = await reportGet(
      authorizedRequest(`http://localhost/api/report?${query.toString()}`),
    );

    expect(response.status).toBe(200);
    expect(await response.text()).toBe("scoped report\n");
    expect(response.headers.get("x-verdict-artifact-trust")).toBe(
      "presentation-only-unverified",
    );
  });

  it("serves active HTML reports in an opaque, no-network CSP sandbox", async () => {
    await fs.writeFile(
      path.join(caseDir, "REPORT.html"),
      "<script>document.body.textContent = 'rendered'</script>\n",
    );
    const query = new URLSearchParams({ case: caseDir, file: "REPORT.html" });

    const response = await reportGet(
      authorizedRequest(`http://localhost/api/report?${query.toString()}`),
    );

    expect(response.status).toBe(200);
    const csp = response.headers.get("content-security-policy") ?? "";
    expect(csp).toContain("sandbox allow-scripts");
    expect(csp).not.toContain("allow-same-origin");
    expect(csp).toContain("connect-src 'none'");
    expect(response.headers.get("x-content-type-options")).toBe("nosniff");
    expect(response.headers.get("referrer-policy")).toBe("no-referrer");
  });
});
