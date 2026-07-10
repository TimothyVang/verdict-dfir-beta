export const CUSTODY_SNAPSHOT_SCHEMA = "verdict.custody-snapshot.v1";

export const CUSTODY_SNAPSHOT_PATHS = [
  "audit.jsonl",
  "run.manifest.json",
  "verdict.json",
] as const;

export interface CustodyArtifactIdentity {
  path: (typeof CUSTODY_SNAPSHOT_PATHS)[number];
  byteCount: number;
  sha256: string;
}

export interface CustodySnapshotResponse {
  schemaVersion: typeof CUSTODY_SNAPSHOT_SCHEMA;
  snapshotSha256: string;
  artifacts: CustodyArtifactIdentity[];
  auditText: string;
  manifestText: string;
  verdictText: string;
}

/** Domain-separated content descriptor hashed into the response ETag. */
export function custodySnapshotDescriptor(
  artifacts: readonly CustodyArtifactIdentity[],
): string {
  return [
    CUSTODY_SNAPSHOT_SCHEMA,
    ...artifacts.flatMap((artifact) => [
      artifact.path,
      String(artifact.byteCount),
      artifact.sha256,
    ]),
    "",
  ].join("\n");
}

const SHA256_HEX = /^[0-9a-f]{64}$/;

function record(value: unknown): Record<string, unknown> | null {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

async function sha256Text(value: string): Promise<string> {
  const bytes = new TextEncoder().encode(value);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest), (byte) =>
    byte.toString(16).padStart(2, "0"),
  ).join("");
}

/** Validate response metadata and the ETag against every returned text byte. */
export async function validateCustodySnapshotResponse(
  value: unknown,
  etag: string | null,
): Promise<CustodySnapshotResponse> {
  const obj = record(value);
  if (!obj || obj.schemaVersion !== CUSTODY_SNAPSHOT_SCHEMA) {
    throw new Error("custody snapshot schema is missing or unsupported");
  }
  const auditText = obj.auditText;
  const manifestText = obj.manifestText;
  const verdictText = obj.verdictText;
  const snapshotSha256 = obj.snapshotSha256;
  if (
    typeof auditText !== "string" ||
    typeof manifestText !== "string" ||
    typeof verdictText !== "string" ||
    typeof snapshotSha256 !== "string" ||
    !SHA256_HEX.test(snapshotSha256)
  ) {
    throw new Error("custody snapshot content fields are malformed");
  }
  if (!Array.isArray(obj.artifacts) || obj.artifacts.length !== 3) {
    throw new Error("custody snapshot must identify exactly three artifacts");
  }

  const texts = [auditText, manifestText, verdictText] as const;
  const artifacts: CustodyArtifactIdentity[] = [];
  for (let index = 0; index < CUSTODY_SNAPSHOT_PATHS.length; index += 1) {
    const raw = record(obj.artifacts[index]);
    const expectedPath = CUSTODY_SNAPSHOT_PATHS[index];
    if (
      !raw ||
      raw.path !== expectedPath ||
      !Number.isSafeInteger(raw.byteCount) ||
      (raw.byteCount as number) < 0 ||
      typeof raw.sha256 !== "string" ||
      !SHA256_HEX.test(raw.sha256)
    ) {
      throw new Error(`custody identity for ${expectedPath} is malformed`);
    }
    const bytes = new TextEncoder().encode(texts[index]);
    const actualSha256 = await sha256Text(texts[index]);
    if (raw.byteCount !== bytes.byteLength || raw.sha256 !== actualSha256) {
      throw new Error(`custody identity for ${expectedPath} does not match bytes`);
    }
    artifacts.push({
      path: expectedPath,
      byteCount: bytes.byteLength,
      sha256: actualSha256,
    });
  }
  const actualSnapshotSha256 = await sha256Text(
    custodySnapshotDescriptor(artifacts),
  );
  if (
    actualSnapshotSha256 !== snapshotSha256 ||
    etag !== `"${snapshotSha256}"`
  ) {
    throw new Error("custody snapshot ETag does not bind the returned artifacts");
  }
  return {
    schemaVersion: CUSTODY_SNAPSHOT_SCHEMA,
    snapshotSha256,
    artifacts,
    auditText,
    manifestText,
    verdictText,
  };
}
