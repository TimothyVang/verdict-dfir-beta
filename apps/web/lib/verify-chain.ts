// Independent, browser-side custody re-verifier — a SECOND implementation of
// the offline manifest_verify path, recomputed in the client with the Web
// Crypto API (SubtleCrypto). It re-derives the custody chain from the audit
// tail + run.manifest.json instead of trusting the values the dashboard
// merely displays, so a zero-trust reader can confirm in-browser that:
//
//   1. the hash chain folds (each line's prev_hash == SHA-256 of the prior
//      line, seq monotonic from 0),
//   2. the audit log is consistent with what the manifest declares (record
//      count, final hash, and the re-derived Merkle leaves),
//   3. the Merkle root rebuilds from those leaves to the manifest's
//      merkle_root_hex, and
//   4. an Ed25519 manifest signature verifies cryptographically offline.
//
// This MIRRORS the canonical algorithm in services/agent/findevil_agent/crypto
// (audit_log.py + manifest.py), which the Rust/Python `manifest_verify` tool
// uses, so a valid chain verifies here and a tampered one fails — identically.
//
// PURE READ-SIDE. This module never writes, never calls a mutating endpoint,
// and never touches the audit chain or the manifest. It only recomputes.
// It depends solely on Web Crypto + pure TS, so it is safe to import into both
// a client component and the Node server tail.

/** Recursive JSON value shape produced by JSON.parse. */
export type JsonValue =
  | null
  | boolean
  | number
  | string
  | JsonValue[]
  | { [key: string]: JsonValue };

/**
 * The audit-record fields that are hashed into the chain — the on-disk line is
 * exactly the VERDICT canonical JSON v1 encoding of these five keys (see
 * audit_log.py:AuditRecord.to_canonical_dict). Selecting them explicitly
 * mirrors the Python "content fields" selection and strips any non-content key
 * (for example a display-only `line_hash`) before canonicalizing.
 */
export const CONTENT_FIELDS = [
  "kind",
  "payload",
  "prev_hash",
  "seq",
  "ts",
] as const;

/** One parsed audit line, kept in original order with its exact on-disk bytes. */
export interface ParsedAuditRecord {
  seq: number;
  kind: string;
  ts: string;
  prevHash: string;
  payload: Record<string, JsonValue>;
  /** Exact on-disk line (no trailing newline) — what the chain commits to. */
  raw: string;
}

/** One Merkle leaf re-derived from the audit log, in the manifest's shape. */
export interface DerivedLeaf {
  seq: number;
  kind: string;
  digest_hex: string;
  record_id: string;
}

/** Result of re-verifying the whole custody chain in the browser. */
export interface CustodyVerification {
  /** True once both an audit tail and a manifest were supplied to verify. */
  available: boolean;
  /** Chain fold + log/manifest consistency (count, final hash, leaves). */
  auditChainOk: boolean | string;
  /** Merkle root rebuilt from the manifest's declared leaves. */
  merkleRootOk: boolean | string;
  /** Declared leaf_count matches the actual leaves array length. */
  leafCountOk: boolean | string;
  /** A signature bundle is present in the manifest. */
  signaturePresent: boolean;
  /** Declared payload digest matches the canonical signed manifest body. */
  signaturePayloadOk: boolean | string;
  /** Which signer sealed the run: "ed25519" | "sigstore" | "stub". */
  signatureKind: string;
  /**
   * Honest cryptographic-verification status. True only for an Ed25519 bundle
   * that verifies offline; stub/sigstore return an explicit reason string.
   */
  signatureVerified: boolean | string;
  /** Requested transparency-anchor policy, including authenticated proof. */
  transparencyOk: boolean | string;
  /** Exact verdict.json bytes match one current-case signed audit commitment. */
  verdictArtifactOk: boolean | string;
  /** SHA-256 of the jointly fetched verdict bytes, when available. */
  verdictSha256: string;
  /** Parsed verdict payload, exposed only when the artifact binding passes. */
  verdict: Record<string, JsonValue> | null;
  /**
   * Authenticated browser result: chain + Merkle + leaf count + payload digest
   * and a cryptographic signature all pass. This is deliberately stricter than
   * development-tier structural verification: a stub never passes, and Sigstore
   * cannot pass in this browser without full identity-policy verification.
   */
  overall: boolean;
}

const SHA256_HEX = /^[0-9a-fA-F]{64}$/;
const ZERO_ROOT = "00".repeat(32);

// ---------------------------------------------------------------------------
// Canonicalization — a browser mirror of VERDICT canonical JSON v1 for the
// finite JSON subset that JavaScript can represent without losing numeric
// spelling. Audit-chain hashes use raw line bytes; this helper is used for the
// signed manifest body and validated against committed fixtures. It is not JCS.
// ---------------------------------------------------------------------------

/** Return VERDICT canonical JSON v1 text for a JavaScript JSON value. */
export function canonicalizeJson(value: JsonValue): string {
  assertPortableJsonNumbers(value);
  return canonicalizeJsonUnchecked(value);
}

/** Refuse numbers whose parsed JavaScript value cannot preserve a JSON integer. */
function assertPortableJsonNumbers(value: JsonValue): void {
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new Error("cannot canonicalize a non-finite number");
    }
    if (Number.isInteger(value) && !Number.isSafeInteger(value)) {
      throw new Error("cannot canonicalize an unsafe JSON integer");
    }
    return;
  }
  if (Array.isArray(value)) {
    for (const item of value) assertPortableJsonNumbers(item);
    return;
  }
  if (typeof value === "object" && value !== null) {
    for (const item of Object.values(value)) assertPortableJsonNumbers(item);
  }
}

function canonicalizeJsonUnchecked(value: JsonValue): string {
  if (value === null) return "null";
  switch (typeof value) {
    case "boolean":
      return value ? "true" : "false";
    case "number":
      return canonicalizeNumber(value);
    case "string":
      return encodeString(value);
    case "object": {
      if (Array.isArray(value)) {
        return "[" + value.map(canonicalizeJsonUnchecked).join(",") + "]";
      }
      // Sort keys ascending. Keys in this domain are ASCII identifiers, for
      // which UTF-16 lexicographic order equals Python's code-point order.
      const keys = Object.keys(value).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
      const parts = keys.map(
        (k) => encodeString(k) + ":" + canonicalizeJsonUnchecked(value[k]),
      );
      return "{" + parts.join(",") + "}";
    }
    default:
      throw new Error(`cannot canonicalize value of type ${typeof value}`);
  }
}

function canonicalizeNumber(value: number): string {
  return String(value);
}

/** Escape a string exactly as CPython's ensure_ascii encoder does. */
function encodeString(s: string): string {
  let out = '"';
  for (let i = 0; i < s.length; i += 1) {
    const code = s.charCodeAt(i);
    const ch = s[i];
    if (ch === '"') out += '\\"';
    else if (ch === "\\") out += "\\\\";
    else if (code === 0x08) out += "\\b";
    else if (code === 0x09) out += "\\t";
    else if (code === 0x0a) out += "\\n";
    else if (code === 0x0c) out += "\\f";
    else if (code === 0x0d) out += "\\r";
    else if (code < 0x20 || code > 0x7e) {
      out += "\\u" + code.toString(16).padStart(4, "0");
    } else {
      out += ch;
    }
  }
  return out + '"';
}

/**
 * Project a parsed record onto CONTENT_FIELDS only. The on-disk audit line is
 * the canonicalization of exactly these keys; selecting them drops any
 * presentation-only field a producer might attach.
 */
export function extractContentRecord(obj: Record<string, JsonValue>): JsonValue {
  const record: Record<string, JsonValue> = {};
  for (const field of CONTENT_FIELDS) {
    if (field in obj) record[field] = obj[field];
  }
  return record;
}

// ---------------------------------------------------------------------------
// Byte / hash helpers (Web Crypto).
// ---------------------------------------------------------------------------

function bytesToHex(bytes: Uint8Array): string {
  let hex = "";
  for (const b of bytes) hex += b.toString(16).padStart(2, "0");
  return hex;
}

function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) throw new Error("odd-length hex string");
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function base64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i += 1) out[i] = bin.charCodeAt(i);
  return out;
}

/** SHA-256 hex of raw bytes, via SubtleCrypto. */
export async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", bytes as BufferSource);
  return bytesToHex(new Uint8Array(digest));
}

/** SHA-256 hex of the UTF-8 bytes of an audit line — the per-line chain hash. */
async function hashLine(rawLine: string): Promise<string> {
  return sha256Hex(new TextEncoder().encode(rawLine));
}

// ---------------------------------------------------------------------------
// Audit-tail parsing + chain fold.
// ---------------------------------------------------------------------------

/** Split an audit.jsonl blob into non-empty lines (matching the writer). */
export function splitAuditLines(text: string): string[] {
  // Split only on the byte the Python writer emits. A CR is evidence bytes,
  // not a line-ending convenience: stripping it would let LF->CRLF tampering
  // verify against hashes computed over different bytes.
  if (text.length === 0) return [];
  const lines = text.split("\n");
  if (lines[lines.length - 1] !== "") {
    // Preserve a synthetic invalid physical record so foldAuditChain rejects a
    // non-empty file that lacks the writer's required terminal LF.
    return [...lines, ""];
  }
  lines.pop(); // consume exactly one required terminal LF
  return lines; // all other empty physical records remain and fail parsing
}

/** Parse one raw line into a ParsedAuditRecord, or null when malformed. */
export function parseAuditRecord(rawLine: string): ParsedAuditRecord | null {
  let obj: unknown;
  try {
    obj = JSON.parse(rawLine);
  } catch {
    return null;
  }
  if (typeof obj !== "object" || obj === null || Array.isArray(obj)) return null;
  const record = obj as Record<string, JsonValue>;
  try {
    assertPortableJsonNumbers(record);
    if (canonicalizeJson(extractContentRecord(record)) !== rawLine) {
      return null;
    }
  } catch {
    return null;
  }
  const seq = record.seq;
  const prevHash = record.prev_hash;
  if (
    typeof seq !== "number" ||
    !Number.isSafeInteger(seq) ||
    typeof prevHash !== "string"
  ) {
    return null;
  }
  const payload =
    typeof record.payload === "object" &&
    record.payload !== null &&
    !Array.isArray(record.payload)
      ? (record.payload as Record<string, JsonValue>)
      : {};
  return {
    seq,
    kind: typeof record.kind === "string" ? record.kind : "unknown",
    ts: typeof record.ts === "string" ? record.ts : "",
    prevHash,
    payload,
    raw: rawLine,
  };
}

interface ChainFold {
  ok: boolean | string;
  records: ParsedAuditRecord[];
  recordCount: number;
  finalHash: string;
}

/**
 * Re-fold the hash chain from raw lines. Independently re-derives each
 * per-line hash (SHA-256 of the on-disk bytes) and checks seq monotonicity +
 * prev_hash linkage — exactly the invariant AuditLog.verify() enforces.
 * Hashing the on-disk bytes (rather than re-serializing the parsed value)
 * reproduces the Python value for every canonical line, including whole-number
 * floats that a JS number cannot round-trip back to text.
 */
export async function foldAuditChain(rawLines: string[]): Promise<ChainFold> {
  const records: ParsedAuditRecord[] = [];
  let prevHash = "";
  let finalHash = "";
  for (let i = 0; i < rawLines.length; i += 1) {
    const parsed = parseAuditRecord(rawLines[i]);
    if (!parsed) {
      return {
        ok: `seq ${i}: line is not a valid audit record`,
        records,
        recordCount: records.length,
        finalHash,
      };
    }
    if (parsed.seq !== i) {
      return {
        ok: `seq ${i}: expected seq=${i}, got seq=${parsed.seq}`,
        records,
        recordCount: records.length,
        finalHash,
      };
    }
    if (parsed.prevHash !== prevHash) {
      return {
        ok: `seq ${i}: prev_hash break (declared=${parsed.prevHash}, expected=${prevHash})`,
        records,
        recordCount: records.length,
        finalHash,
      };
    }
    const lineHash = await hashLine(parsed.raw);
    prevHash = lineHash;
    finalHash = lineHash;
    records.push(parsed);
  }
  return { ok: true, records, recordCount: records.length, finalHash };
}

// ---------------------------------------------------------------------------
// Merkle root + leaf derivation.
// ---------------------------------------------------------------------------

/**
 * Rebuild the Merkle root from leaf digests (hex). Mirrors merkle.py: leaves
 * in insertion order, duplicate-last on an odd tier, internal node =
 * SHA-256(left || right), empty tree => 32 zero bytes.
 */
export async function merkleRootHex(leafHexes: string[]): Promise<string> {
  if (leafHexes.length === 0) return ZERO_ROOT;
  let tier = leafHexes.map(hexToBytes);
  while (tier.length > 1) {
    if (tier.length % 2 === 1) tier.push(tier[tier.length - 1]);
    const next: Uint8Array[] = [];
    for (let i = 0; i < tier.length; i += 2) {
      const left = tier[i];
      const right = tier[i + 1];
      const concat = new Uint8Array(left.length + right.length);
      concat.set(left, 0);
      concat.set(right, left.length);
      const digest = await crypto.subtle.digest("SHA-256", concat as BufferSource);
      next.push(new Uint8Array(digest));
    }
    tier = next;
  }
  return bytesToHex(tier[0]);
}

/**
 * Re-derive the Merkle-eligible leaves from the audit records, matching
 * manifest.py:_walk_audit_log. A tool_call_output contributes its payload
 * output_hash (when it is a valid 64-hex digest) else the SHA-256 of its line;
 * a finding_approved contributes the SHA-256 of its line.
 */
export async function deriveLeaves(
  records: ParsedAuditRecord[],
): Promise<DerivedLeaf[]> {
  const leaves: DerivedLeaf[] = [];
  for (const record of records) {
    if (record.kind === "tool_call_output") {
      const outputHash = record.payload.output_hash;
      const digest =
        typeof outputHash === "string" && SHA256_HEX.test(outputHash)
          ? outputHash
          : await hashLine(record.raw);
      leaves.push({
        seq: record.seq,
        kind: "tool_call_output",
        digest_hex: digest,
        record_id: stringField(record.payload.tool_call_id),
      });
    } else if (record.kind === "finding_approved") {
      leaves.push({
        seq: record.seq,
        kind: "finding",
        digest_hex: await hashLine(record.raw),
        record_id: stringField(record.payload.finding_id),
      });
    }
  }
  return leaves;
}

function stringField(value: JsonValue | undefined): string {
  return value === undefined || value === null ? "" : String(value);
}

// ---------------------------------------------------------------------------
// Ed25519 manifest-signature verification.
// ---------------------------------------------------------------------------

/**
 * Honest signature status, mirroring manifest.py:_signature_verified. Never
 * returns true for a stub (a deterministic placeholder, not proof) and never
 * claims to have cryptographically checked a sigstore bundle it cannot verify
 * offline without an expected identity. Sigstore therefore fails `overall` in
 * this browser implementation instead of being treated as presence evidence.
 */
export async function verifyManifestSignature(
  manifest: Record<string, JsonValue>,
  expectedEd25519Fingerprint?: string,
): Promise<{
  present: boolean;
  kind: string;
  payloadOk: boolean | string;
  verified: boolean | string;
}> {
  const sig =
    typeof manifest.signature === "object" &&
    manifest.signature !== null &&
    !Array.isArray(manifest.signature)
      ? (manifest.signature as Record<string, JsonValue>)
      : {};
  const present = Boolean(sig.bundle_b64 && sig.payload_sha256);
  const kind = typeof sig.kind === "string" ? sig.kind : "stub";
  if (!present) {
    const reason = "no signature bundle present";
    return { present, kind, payloadOk: reason, verified: reason };
  }
  // Object.fromEntries defines own data properties, including `__proto__`.
  // Assigning attacker-controlled keys into `{}` invokes the legacy prototype
  // setter and can silently omit an unsigned top-level key from the body.
  const body = Object.fromEntries(
    Object.entries(manifest).filter(
      ([key]) => key !== "signature" && key !== "transparency_log",
    ),
  ) as Record<string, JsonValue>;
  let bodyBytes: Uint8Array;
  try {
    bodyBytes = new TextEncoder().encode(canonicalizeJson(body));
  } catch (err) {
    const reason = `${kind} manifest body rejected: ${errorMessage(err)}`;
    return { present, kind, payloadOk: reason, verified: reason };
  }
  const declaredPayload = String(sig.payload_sha256 ?? "").toLowerCase();
  const actualPayload = await sha256Hex(bodyBytes);
  if (!SHA256_HEX.test(declaredPayload) || declaredPayload !== actualPayload) {
    const reason =
      `${kind} signature payload digest FAILED: canonical manifest body ` +
      "does not match signature.payload_sha256";
    return {
      present,
      kind,
      payloadOk: reason,
      verified: `${kind} verification blocked: ${reason}`,
    };
  }
  if (kind === "stub") {
    return {
      present,
      kind,
      payloadOk: true,
      verified:
        "stub signature: deterministic dev/offline placeholder, not cryptographic proof",
    };
  }
  if (kind === "sigstore") {
    return {
      present,
      kind,
      payloadOk: true,
      verified:
        "sigstore browser verification unavailable: full verification requires " +
        "an exact trusted signer identity and exact OIDC issuer against production " +
        "Fulcio/Rekor roots",
    };
  }
  if (kind === "ed25519") {
    return {
      present,
      kind,
      payloadOk: true,
      verified: await verifyEd25519(
        sig,
        bodyBytes,
        expectedEd25519Fingerprint,
      ),
    };
  }
  return {
    present,
    kind,
    payloadOk: true,
    verified: `unknown signer kind '${kind}'`,
  };
}

async function verifyEd25519(
  sig: Record<string, JsonValue>,
  bodyBytes: Uint8Array,
  expectedFingerprint?: string,
): Promise<boolean | string> {
  let publicKey: Uint8Array;
  let signature: Uint8Array;
  let bundledFingerprint: string;
  try {
    const bundleJson = new TextDecoder().decode(
      base64ToBytes(String(sig.bundle_b64 ?? "")),
    );
    const parsed = JSON.parse(bundleJson) as unknown;
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
      throw new Error("bundle JSON is not an object");
    }
    const bundle = parsed as Record<string, JsonValue>;
    if (!bundle.public_key_b64 || !bundle.signature_b64) {
      throw new Error("missing public_key_b64 / signature_b64");
    }
    publicKey = base64ToBytes(String(bundle.public_key_b64));
    signature = base64ToBytes(String(bundle.signature_b64));
    bundledFingerprint = String(bundle.cert_fingerprint ?? "").toLowerCase();
  } catch (err) {
    return `ed25519 bundle malformed: ${errorMessage(err)}`;
  }

  if (publicKey.length !== 32 || signature.length !== 64) {
    return "ed25519 bundle malformed: key/signature length is invalid";
  }
  const actualFingerprint = await sha256Hex(publicKey);
  const outerFingerprint = String(sig.cert_fingerprint ?? "").toLowerCase();
  if (outerFingerprint !== actualFingerprint) {
    return "ed25519 public-key fingerprint does not match signature metadata";
  }
  if (bundledFingerprint !== actualFingerprint) {
    return "ed25519 public-key fingerprint does not match signer bundle";
  }
  const trustedFingerprint = expectedFingerprint?.trim().toLowerCase() ?? "";
  if (!trustedFingerprint) {
    return (
      "ed25519 verification requires an externally trusted public-key " +
      "fingerprint"
    );
  }
  if (!SHA256_HEX.test(trustedFingerprint)) {
    return "expected Ed25519 fingerprint is not a SHA-256 digest";
  }
  if (trustedFingerprint !== actualFingerprint) {
    return "ed25519 public key does not match the trusted fingerprint";
  }
  const strictError = validateStrictEd25519Inputs(publicKey, signature);
  if (strictError !== null) {
    return `ed25519 signature inputs rejected: ${strictError}`;
  }

  try {
    const key = await crypto.subtle.importKey(
      "raw",
      publicKey as BufferSource,
      { name: "Ed25519" },
      false,
      ["verify"],
    );
    const ok = await crypto.subtle.verify(
      { name: "Ed25519" },
      key,
      signature as BufferSource,
      bodyBytes as BufferSource,
    );
    return ok
      ? true
      : "ed25519 signature verification FAILED: manifest body does not match the signature";
  } catch (err) {
    return `ed25519 signature verification failed: ${errorMessage(err)}`;
  }
}

type EdwardsPoint = readonly [bigint, bigint];

const ED_P = (1n << 255n) - 19n;
const ED_L =
  (1n << 252n) + 27742317777372353535851937790883648493n;
const ED_D = mod(-121665n * modInverse(121666n, ED_P), ED_P);
const ED_I = modPow(2n, (ED_P - 1n) / 4n, ED_P);
const ED_IDENTITY: EdwardsPoint = [0n, 1n];

/** Validate canonical scalar/point encodings and exact prime-order membership. */
function validateStrictEd25519Inputs(
  publicKey: Uint8Array,
  signature: Uint8Array,
): string | null {
  if (publicKey.length !== 32) return "public key must be exactly 32 bytes";
  if (signature.length !== 64) return "signature must be exactly 64 bytes";
  if (littleEndianToBigInt(signature.slice(32)) >= ED_L) {
    return "signature scalar S is non-canonical";
  }
  let pointA: EdwardsPoint;
  let pointR: EdwardsPoint;
  try {
    pointA = decodeEdwardsPoint(publicKey);
    pointR = decodeEdwardsPoint(signature.slice(0, 32));
  } catch (err) {
    return errorMessage(err);
  }
  if (!hasPrimeOrder(pointA)) {
    return "public key is not a non-identity prime-order point";
  }
  if (!hasPrimeOrder(pointR)) {
    return "signature R is not a non-identity prime-order point";
  }
  return null;
}

function decodeEdwardsPoint(encodedBytes: Uint8Array): EdwardsPoint {
  if (encodedBytes.length !== 32) {
    throw new Error("encoded Ed25519 point must be exactly 32 bytes");
  }
  const encoded = littleEndianToBigInt(encodedBytes);
  const sign = encoded >> 255n;
  const y = encoded & ((1n << 255n) - 1n);
  if (y >= ED_P) throw new Error("non-canonical Ed25519 point encoding");
  let x = recoverEdwardsX(y);
  if (x === 0n && sign !== 0n) {
    throw new Error("non-canonical Ed25519 x=0 sign encoding");
  }
  if ((x & 1n) !== sign) x = ED_P - x;
  const point: EdwardsPoint = [x, y];
  if (!edwardsPointOnCurve(point)) {
    throw new Error("encoded Ed25519 point is not on the curve");
  }
  if (!bytesEqual(encodeEdwardsPoint(point), encodedBytes)) {
    throw new Error("non-canonical Ed25519 point encoding");
  }
  return point;
}

function recoverEdwardsX(y: bigint): bigint {
  const denominator = mod(ED_D * y * y + 1n, ED_P);
  if (denominator === 0n) {
    throw new Error("Ed25519 point has no affine x coordinate");
  }
  const xx = mod((y * y - 1n) * modInverse(denominator, ED_P), ED_P);
  let x = modPow(xx, (ED_P + 3n) / 8n, ED_P);
  if (mod(x * x - xx, ED_P) !== 0n) x = mod(x * ED_I, ED_P);
  if (mod(x * x - xx, ED_P) !== 0n) {
    throw new Error("encoded Ed25519 point is not on the curve");
  }
  if ((x & 1n) !== 0n) x = ED_P - x;
  return x;
}

function edwardsPointOnCurve([x, y]: EdwardsPoint): boolean {
  return mod(-x * x + y * y - 1n - ED_D * x * x * y * y, ED_P) === 0n;
}

function encodeEdwardsPoint([x, y]: EdwardsPoint): Uint8Array {
  return bigIntToLittleEndian(y | ((x & 1n) << 255n), 32);
}

function addEdwardsPoints(
  [x1, y1]: EdwardsPoint,
  [x2, y2]: EdwardsPoint,
): EdwardsPoint {
  const product = mod(ED_D * x1 * x2 * y1 * y2, ED_P);
  const x3 = mod(
    (x1 * y2 + x2 * y1) * modInverse(1n + product, ED_P),
    ED_P,
  );
  const y3 = mod(
    (y1 * y2 + x1 * x2) * modInverse(1n - product, ED_P),
    ED_P,
  );
  return [x3, y3];
}

function scalarMultiplyEdwards(
  point: EdwardsPoint,
  scalar: bigint,
): EdwardsPoint {
  let result = ED_IDENTITY;
  let addend = point;
  let remaining = scalar;
  while (remaining > 0n) {
    if ((remaining & 1n) !== 0n) result = addEdwardsPoints(result, addend);
    addend = addEdwardsPoints(addend, addend);
    remaining >>= 1n;
  }
  return result;
}

function hasPrimeOrder(point: EdwardsPoint): boolean {
  return (
    !pointsEqual(point, ED_IDENTITY) &&
    pointsEqual(scalarMultiplyEdwards(point, ED_L), ED_IDENTITY)
  );
}

function mod(value: bigint, modulus: bigint): bigint {
  const reduced = value % modulus;
  return reduced >= 0n ? reduced : reduced + modulus;
}

function modInverse(value: bigint, modulus: bigint): bigint {
  return modPow(mod(value, modulus), modulus - 2n, modulus);
}

function modPow(base: bigint, exponent: bigint, modulus: bigint): bigint {
  let result = 1n;
  let factor = mod(base, modulus);
  let remaining = exponent;
  while (remaining > 0n) {
    if ((remaining & 1n) !== 0n) result = (result * factor) % modulus;
    factor = (factor * factor) % modulus;
    remaining >>= 1n;
  }
  return result;
}

function littleEndianToBigInt(bytes: Uint8Array): bigint {
  let value = 0n;
  for (let index = bytes.length - 1; index >= 0; index -= 1) {
    value = (value << 8n) | BigInt(bytes[index]);
  }
  return value;
}

function bigIntToLittleEndian(value: bigint, length: number): Uint8Array {
  const bytes = new Uint8Array(length);
  let remaining = value;
  for (let index = 0; index < length; index += 1) {
    bytes[index] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  return bytes;
}

function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  for (let index = 0; index < left.length; index += 1) {
    if (left[index] !== right[index]) return false;
  }
  return true;
}

function pointsEqual(left: EdwardsPoint, right: EdwardsPoint): boolean {
  return left[0] === right[0] && left[1] === right[1];
}

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

// ---------------------------------------------------------------------------
// Bound verdict artifact.
// ---------------------------------------------------------------------------

export interface VerdictArtifactInputs {
  records: readonly ParsedAuditRecord[];
  manifest: Record<string, JsonValue>;
  verdictText: string | undefined;
}

export interface VerdictArtifactVerification {
  ok: boolean | string;
  sha256: string;
  verdict: Record<string, JsonValue> | null;
}

function verdictBasename(value: JsonValue | undefined): boolean {
  if (typeof value !== "string" || value.length === 0) return false;
  const parts = value.replaceAll("\\", "/").split("/");
  return parts[parts.length - 1] === "verdict.json";
}

function objectField(
  value: JsonValue | undefined,
): Record<string, JsonValue> | null {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as Record<string, JsonValue>)
    : null;
}

/** Bind exact verdict bytes to one audit record and the signed Case identity. */
export async function verifyVerdictArtifactBinding(
  inputs: VerdictArtifactInputs,
): Promise<VerdictArtifactVerification> {
  const fail = (reason: string, sha256 = ""): VerdictArtifactVerification => ({
    ok: reason,
    sha256,
    verdict: null,
  });
  if (typeof inputs.verdictText !== "string") {
    return fail("verdict.json is missing from the joint custody snapshot");
  }

  const verdictBytes = new TextEncoder().encode(inputs.verdictText);
  const actualSha256 = await sha256Hex(verdictBytes);
  const commitments = inputs.records.filter(
    (record) => record.kind === "verdict_artifact",
  );
  if (commitments.length !== 1) {
    return fail(
      `expected exactly one verdict_artifact record, found ${commitments.length}`,
      actualSha256,
    );
  }
  const commitment = commitments[0].payload;
  if (!verdictBasename(commitment.path)) {
    return fail("verdict_artifact does not point at verdict.json", actualSha256);
  }
  const declaredSha256 = commitment.sha256;
  if (
    typeof declaredSha256 !== "string" ||
    !SHA256_HEX.test(declaredSha256) ||
    declaredSha256.toLowerCase() !== actualSha256
  ) {
    return fail("verdict_artifact sha256 does not match verdict.json", actualSha256);
  }
  if (
    !Number.isSafeInteger(commitment.byte_count) ||
    commitment.byte_count !== verdictBytes.byteLength
  ) {
    return fail("verdict_artifact byte_count does not match verdict.json", actualSha256);
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(inputs.verdictText);
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
      throw new Error("verdict.json must be an object");
    }
    assertPortableJsonNumbers(parsed as JsonValue);
  } catch (err) {
    return fail(`verdict.json rejected: ${errorMessage(err)}`, actualSha256);
  }
  const verdict = parsed as Record<string, JsonValue>;
  const manifestCaseId = inputs.manifest.case_id;
  const verdictCaseId = verdict.case_id;
  if (
    typeof manifestCaseId !== "string" ||
    manifestCaseId.length === 0 ||
    verdictCaseId !== manifestCaseId
  ) {
    return fail("verdict.json case_id does not match the signed manifest", actualSha256);
  }
  const manifestRunId = inputs.manifest.run_id;
  if (
    typeof manifestRunId !== "string" ||
    manifestRunId.length === 0 ||
    verdict.run_id !== manifestRunId
  ) {
    return fail("verdict.json run_id does not match the signed manifest", actualSha256);
  }

  const extra = objectField(inputs.manifest.extra);
  const rawPacket = extra?.packet_attestation;
  if (rawPacket !== undefined) {
    const packet = objectField(rawPacket);
    if (!packet) {
      return fail("manifest packet_attestation is malformed", actualSha256);
    }
    if (
      !verdictBasename(packet.verdict_artifact_path) ||
      typeof packet.verdict_artifact_sha256 !== "string" ||
      packet.verdict_artifact_sha256.toLowerCase() !== actualSha256 ||
      !Number.isSafeInteger(packet.verdict_artifact_bytes) ||
      packet.verdict_artifact_bytes !== verdictBytes.byteLength
    ) {
      return fail(
        "manifest packet_attestation conflicts with verdict.json",
        actualSha256,
      );
    }
  }

  return { ok: true, sha256: actualSha256, verdict };
}

// ---------------------------------------------------------------------------
// Signed transparency-anchor request policy.
// ---------------------------------------------------------------------------

/**
 * Enforce the signed anchor-request commitment without overstating browser
 * capabilities. Legacy/missing and explicit `false` remain compatible. A
 * requested proof cannot pass here because the browser does not carry the
 * production Sigstore roots plus exact identity/issuer policy needed to
 * authenticate Rekor, and RFC-3161 is not authenticated without a TSA chain.
 */
export function verifyTransparencyAnchor(
  manifest: Record<string, JsonValue>,
): boolean | string {
  const requested = manifest.transparency_anchor_requested;
  if (requested === undefined || requested === false) return true;
  if (typeof requested !== "boolean") {
    return "transparency_anchor_requested must be a JSON boolean";
  }

  const rawAnchor = manifest.transparency_log;
  if (
    typeof rawAnchor !== "object" ||
    rawAnchor === null ||
    Array.isArray(rawAnchor) ||
    Object.keys(rawAnchor).length === 0
  ) {
    return "authenticated transparency anchor was requested but transparency_log is missing";
  }
  const anchor = rawAnchor as Record<string, JsonValue>;
  if (anchor.anchored !== true) {
    return "requested transparency_log is not marked as successfully anchored";
  }
  const kind = typeof anchor.kind === "string" ? anchor.kind : "";
  if (kind !== "rekor") {
    return `requested transparency anchor kind '${kind || "unknown"}' is unsupported in the browser`;
  }

  const subject =
    typeof anchor.subject === "object" &&
    anchor.subject !== null &&
    !Array.isArray(anchor.subject)
      ? (anchor.subject as Record<string, JsonValue>)
      : {};
  const subjectRoot = stringField(subject.merkle_root_sha256);
  const manifestRoot = stringField(manifest.merkle_root_hex);
  if (!SHA256_HEX.test(subjectRoot) || subjectRoot !== manifestRoot) {
    return "requested Rekor anchor subject does not match the manifest Merkle root";
  }
  const rekor =
    typeof anchor.rekor === "object" &&
    anchor.rekor !== null &&
    !Array.isArray(anchor.rekor)
      ? (anchor.rekor as Record<string, JsonValue>)
      : {};
  if (typeof rekor.bundle_b64 !== "string" || rekor.bundle_b64.length === 0) {
    return "requested Rekor anchor is missing its full Sigstore bundle";
  }
  return (
    "requested Rekor anchor is unsupported in the browser: authenticated " +
    "verification requires production Rekor roots and exact signer identity/OIDC issuer policy"
  );
}

// ---------------------------------------------------------------------------
// Top-level: re-verify the whole custody chain.
// ---------------------------------------------------------------------------

export interface CustodyInputs {
  /** Verbatim audit.jsonl contents. */
  auditText: string;
  /** Parsed run.manifest.json object. */
  manifest: Record<string, JsonValue>;
  /** Verbatim verdict.json contents from the same stable snapshot. */
  verdictText?: string;
  /** Trusted key pin supplied outside the case artifacts. */
  expectedEd25519Fingerprint?: string;
}

/**
 * Re-derive and verify the custody chain entirely in the browser. Returns a
 * structured pass/fail mirroring verify_manifest's fields. Reads only — never
 * mutates the chain, the manifest, or any server state.
 */
export async function verifyCustodyChain(
  inputs: CustodyInputs,
): Promise<CustodyVerification> {
  const { auditText, manifest, verdictText, expectedEd25519Fingerprint } = inputs;
  const fold = await foldAuditChain(splitAuditLines(auditText));

  let auditChainOk = fold.ok;

  // Log-vs-manifest consistency: a tail-truncated log still folds cleanly and a
  // self-consistent forged leaf set still rebuilds its own root, so compare the
  // re-derived count / final hash / leaves to the manifest's declarations
  // (mirror of verify_manifest step 1b).
  let derivedLeaves: DerivedLeaf[] = [];
  if (auditChainOk === true) {
    derivedLeaves = await deriveLeaves(fold.records);
    const declaredCount = manifest.audit_log_record_count;
    const declaredFinal = stringField(manifest.audit_log_final_hash);
    const declaredLeaves = Array.isArray(manifest.leaves) ? manifest.leaves : [];
    if (declaredCount !== fold.recordCount) {
      auditChainOk =
        `audit log has ${fold.recordCount} record(s) but the manifest ` +
        `declares ${String(declaredCount)} (tail truncation or post-seal append)`;
    } else if (declaredFinal !== fold.finalHash) {
      auditChainOk =
        "audit log final hash does not match the manifest's audit_log_final_hash";
    } else if (!leavesEqual(derivedLeaves, declaredLeaves)) {
      auditChainOk =
        "leaves re-derived from the audit log do not match the manifest's declared leaves";
    }
  }

  // Merkle root rebuilt from the manifest's DECLARED leaves (matches
  // verify_manifest, which rebuilds from obj["leaves"]).
  const declaredLeaves = Array.isArray(manifest.leaves) ? manifest.leaves : [];
  let merkleRootOk: boolean | string = true;
  try {
    const declaredRoot = stringField(manifest.merkle_root_hex);
    const rebuilt = await merkleRootHex(
      declaredLeaves.map((leaf) => leafDigestHex(leaf)),
    );
    if (rebuilt !== declaredRoot) {
      merkleRootOk = `declared root ${declaredRoot} != rebuilt ${rebuilt}`;
    }
  } catch (err) {
    merkleRootOk = `merkle rebuild failed: ${errorMessage(err)}`;
  }

  // Leaf count.
  const declaredLeafCount = manifest.leaf_count;
  const actualLeafCount = declaredLeaves.length;
  const leafCountOk: boolean | string =
    declaredLeafCount === actualLeafCount
      ? true
      : `leaf_count ${String(declaredLeafCount)} != actual ${actualLeafCount}`;

  const { present, kind, payloadOk, verified } =
    await verifyManifestSignature(manifest, expectedEd25519Fingerprint);
  const transparencyOk = verifyTransparencyAnchor(manifest);
  const verdictArtifact =
    fold.ok === true
      ? await verifyVerdictArtifactBinding({
          records: fold.records,
          manifest,
          verdictText,
        })
      : {
          ok: "verdict binding blocked because the audit chain did not verify",
          sha256: "",
          verdict: null,
        };

  const overall =
    auditChainOk === true &&
    merkleRootOk === true &&
    leafCountOk === true &&
    present &&
    payloadOk === true &&
    verified === true &&
    transparencyOk === true &&
    verdictArtifact.ok === true;

  return {
    available: true,
    auditChainOk,
    merkleRootOk,
    leafCountOk,
    signaturePresent: present,
    signaturePayloadOk: payloadOk,
    signatureKind: kind,
    signatureVerified: verified,
    transparencyOk,
    verdictArtifactOk: verdictArtifact.ok,
    verdictSha256: verdictArtifact.sha256,
    verdict: verdictArtifact.verdict,
    overall,
  };
}

function leafDigestHex(leaf: JsonValue): string {
  if (typeof leaf === "object" && leaf !== null && !Array.isArray(leaf)) {
    return stringField((leaf as Record<string, JsonValue>).digest_hex);
  }
  return "";
}

function leavesEqual(derived: DerivedLeaf[], declared: JsonValue[]): boolean {
  if (derived.length !== declared.length) return false;
  for (let i = 0; i < derived.length; i += 1) {
    const d = derived[i];
    const raw = declared[i];
    if (typeof raw !== "object" || raw === null || Array.isArray(raw)) return false;
    const obj = raw as Record<string, JsonValue>;
    if (
      d.seq !== obj.seq ||
      d.kind !== obj.kind ||
      d.digest_hex !== obj.digest_hex ||
      d.record_id !== stringField(obj.record_id)
    ) {
      return false;
    }
  }
  return true;
}
