import path from "node:path";
import { fileURLToPath } from "node:url";

import { afterEach, describe, expect, it, vi } from "vitest";

import { GET } from "@/app/api/doctor/route";

const testDir = path.dirname(fileURLToPath(import.meta.url));
const appRoot = path.resolve(testDir, "..");
const dashboardCapability = "d".repeat(64);

describe("GET /api/doctor", () => {
  afterEach(() => {
    vi.restoreAllMocks();
    delete process.env.FINDEVIL_REPO_ROOT;
    delete process.env.FINDEVIL_DASHBOARD_CAPABILITY;
  });

  it("finds the repo root when the dashboard cwd is apps/web", async () => {
    delete process.env.FINDEVIL_REPO_ROOT;
    process.env.FINDEVIL_DASHBOARD_CAPABILITY = dashboardCapability;
    vi.spyOn(process, "cwd").mockReturnValue(appRoot);

    const response = await GET(
      new Request("http://localhost/api/doctor", {
        headers: {
          Cookie: `verdict_dashboard_session=${dashboardCapability}`,
        },
      }),
    );
    const body = (await response.json()) as { error?: string; checks?: unknown[] };

    expect(response.status).toBe(200);
    expect(body.error).toBeUndefined();
    expect(Array.isArray(body.checks)).toBe(true);
  }, 35_000);
});
