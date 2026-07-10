import {
  consumeDashboardExchange,
  DASHBOARD_SESSION_COOKIE,
} from "@/lib/dashboard-auth";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";
const MAX_EXCHANGE_BODY_BYTES = 8 * 1024;
const SESSION_RESPONSE_HEADERS = {
  "Cache-Control": "no-store",
  "Cross-Origin-Resource-Policy": "same-origin",
  "Referrer-Policy": "no-referrer",
  "X-Content-Type-Options": "nosniff",
} as const;

export async function POST(request: Request): Promise<Response> {
  const url = new URL(request.url);
  const contentType = request.headers.get("content-type")?.split(";", 1)[0].trim();
  const declaredLength = Number(request.headers.get("content-length"));
  if (
    contentType !== "application/x-www-form-urlencoded" ||
    !Number.isSafeInteger(declaredLength) ||
    declaredLength < 1 ||
    declaredLength > MAX_EXCHANGE_BODY_BYTES
  ) {
    return new Response("invalid exchange request", {
      status: 400,
      headers: SESSION_RESPONSE_HEADERS,
    });
  }
  let form: URLSearchParams;
  try {
    const body = await request.text();
    if (Buffer.byteLength(body, "utf-8") > MAX_EXCHANGE_BODY_BYTES) {
      throw new Error("exchange body exceeds limit");
    }
    form = new URLSearchParams(body);
  } catch {
    return new Response("invalid exchange request", {
      status: 400,
      headers: SESSION_RESPONSE_HEADERS,
    });
  }
  const exchange = String(form.get("token") ?? "");
  if (!(await consumeDashboardExchange(exchange))) {
    return new Response("unauthorized", {
      status: 401,
      headers: SESSION_RESPONSE_HEADERS,
    });
  }

  const next = String(form.get("next") ?? "/");
  if (!next.startsWith("/") || next.startsWith("//") || next.includes("\\")) {
    return new Response("invalid redirect target", {
      status: 400,
      headers: SESSION_RESPONSE_HEADERS,
    });
  }
  const destination = new URL(next, url.origin);
  if (destination.origin !== url.origin) {
    return new Response("invalid redirect target", {
      status: 400,
      headers: SESSION_RESPONSE_HEADERS,
    });
  }

  return new Response(null, {
    status: 303,
    headers: {
      ...SESSION_RESPONSE_HEADERS,
      Location: destination.pathname + destination.search + destination.hash,
      "Set-Cookie": `${DASHBOARD_SESSION_COOKIE}=${process.env.FINDEVIL_DASHBOARD_CAPABILITY}; HttpOnly; SameSite=Strict; Path=/api; Max-Age=28800`,
    },
  });
}

export async function GET(): Promise<Response> {
  return new Response("use the one-time POST exchange", {
    status: 405,
    headers: { Allow: "POST", ...SESSION_RESPONSE_HEADERS },
  });
}
