import { afterEach, describe, expect, it } from "vitest";

import { GET } from "@/app/api/custody-policy/route";

const CAPABILITY = "a".repeat(64);
const FINGERPRINT = "b".repeat(64);

afterEach(() => {
  delete process.env.FINDEVIL_DASHBOARD_CAPABILITY;
  delete process.env.FINDEVIL_ED25519_EXPECTED_FINGERPRINT;
});

describe("GET /api/custody-policy", () => {
  it("returns only the launcher-supplied public-key pin", async () => {
    process.env.FINDEVIL_DASHBOARD_CAPABILITY = CAPABILITY;
    process.env.FINDEVIL_ED25519_EXPECTED_FINGERPRINT = FINGERPRINT;

    const response = await GET(
      new Request("http://localhost/api/custody-policy", {
        headers: {
          cookie: `verdict_dashboard_session=${CAPABILITY}`,
        },
      }),
    );

    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({
      ed25519ExpectedFingerprint: FINGERPRINT,
      configured: true,
    });
    expect(response.headers.get("cache-control")).toBe("no-store");
  });

  it("fails closed for an invalid pin and an unauthenticated request", async () => {
    process.env.FINDEVIL_DASHBOARD_CAPABILITY = CAPABILITY;
    process.env.FINDEVIL_ED25519_EXPECTED_FINGERPRINT = "from-the-manifest";

    const unauthorized = await GET(
      new Request("http://localhost/api/custody-policy"),
    );
    expect(unauthorized.status).toBe(401);

    const response = await GET(
      new Request("http://localhost/api/custody-policy", {
        headers: {
          cookie: `verdict_dashboard_session=${CAPABILITY}`,
        },
      }),
    );
    expect(await response.json()).toEqual({
      ed25519ExpectedFingerprint: null,
      configured: false,
    });
  });
});
