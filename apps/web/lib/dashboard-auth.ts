import { createHash, timingSafeEqual } from "node:crypto";
import { promises as fs } from "node:fs";
import path from "node:path";

export const DASHBOARD_CAPABILITY_ENV = "FINDEVIL_DASHBOARD_CAPABILITY";
export const DASHBOARD_EXCHANGE_FILE_ENV = "FINDEVIL_DASHBOARD_EXCHANGE_FILE";
export const DASHBOARD_SESSION_COOKIE = "verdict_dashboard_session";

function configuredCapability(): string | null {
  const value = process.env[DASHBOARD_CAPABILITY_ENV]?.trim() ?? "";
  return /^[0-9a-f]{64}$/.test(value) ? value : null;
}

function constantTimeMatch(candidate: string, expected: string): boolean {
  if (candidate.length > 256) return false;
  const candidateDigest = createHash("sha256").update(candidate, "utf-8").digest();
  const expectedDigest = createHash("sha256").update(expected, "utf-8").digest();
  return timingSafeEqual(candidateDigest, expectedDigest);
}

function cookieValue(request: Request, name: string): string {
  const raw = request.headers.get("cookie") ?? "";
  for (const part of raw.split(";")) {
    const separator = part.indexOf("=");
    if (separator < 0) continue;
    if (part.slice(0, separator).trim() === name) {
      return part.slice(separator + 1).trim();
    }
  }
  return "";
}

export function verifyDashboardCapability(candidate: string): boolean {
  const expected = configuredCapability();
  return expected !== null && constantTimeMatch(candidate, expected);
}

/** Atomically consume one private launcher-to-browser exchange nonce. */
export async function consumeDashboardExchange(candidate: string): Promise<boolean> {
  if (!/^[0-9a-f]{64}$/.test(candidate)) return false;
  const configured = process.env[DASHBOARD_EXCHANGE_FILE_ENV]?.trim() ?? "";
  if (!path.isAbsolute(configured)) return false;
  let expected: string;
  try {
    const metadata = await fs.lstat(configured);
    if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.nlink !== 1) {
      return false;
    }
    expected = (await fs.readFile(configured, "ascii")).trim();
  } catch {
    return false;
  }
  if (!/^[0-9a-f]{64}$/.test(expected) || !constantTimeMatch(candidate, expected)) {
    return false;
  }

  const claimed = `${configured}.claimed-${process.pid}-${Date.now()}`;
  try {
    await fs.rename(configured, claimed);
    const claimedMetadata = await fs.lstat(claimed);
    if (
      !claimedMetadata.isFile() ||
      claimedMetadata.isSymbolicLink() ||
      claimedMetadata.nlink !== 1
    ) {
      return false;
    }
    const claimedValue = (await fs.readFile(claimed, "ascii")).trim();
    return constantTimeMatch(candidate, claimedValue);
  } catch {
    return false;
  } finally {
    await fs.rm(claimed, { force: true }).catch(() => undefined);
  }
}

/** Return null when authorized, otherwise a fail-closed API response. */
export function authorizeDashboardRequest(request: Request): Response | null {
  const expected = configuredCapability();
  if (!expected) {
    return new Response("dashboard capability is not configured", {
      status: 503,
      headers: { "Cache-Control": "no-store" },
    });
  }
  const supplied = cookieValue(request, DASHBOARD_SESSION_COOKIE);
  if (!constantTimeMatch(supplied, expected)) {
    return new Response("unauthorized", {
      status: 401,
      headers: {
        "Cache-Control": "no-store",
        "Content-Type": "text/plain; charset=utf-8",
      },
    });
  }
  return null;
}
