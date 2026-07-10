import { authorizeDashboardRequest } from "@/lib/dashboard-auth";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const RESPONSE_HEADERS = {
  "Cache-Control": "no-store",
  "Content-Type": "application/json; charset=utf-8",
  "Cross-Origin-Resource-Policy": "same-origin",
  "Referrer-Policy": "no-referrer",
  "X-Content-Type-Options": "nosniff",
};

/** Expose only the trusted public-key pin injected by the host launcher. */
export async function GET(request: Request): Promise<Response> {
  const denied = authorizeDashboardRequest(request);
  if (denied) return denied;
  const candidate =
    process.env.FINDEVIL_ED25519_EXPECTED_FINGERPRINT?.trim().toLowerCase() ??
    "";
  const fingerprint = /^[0-9a-f]{64}$/.test(candidate) ? candidate : null;
  return new Response(
    JSON.stringify({
      ed25519ExpectedFingerprint: fingerprint,
      configured: fingerprint !== null,
    }),
    { status: 200, headers: RESPONSE_HEADERS },
  );
}
