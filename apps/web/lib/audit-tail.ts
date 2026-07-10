// Server-side audit-log tail: watch a case's audit.jsonl, yield each
// event as it's appended. The route handler in
// app/api/audit/route.ts wraps this in an SSE stream; tests in
// __tests__/audit-tail.test.ts drive it directly without HTTP.
//
// Per A3 plan Task 4.2.

import { createHash } from "node:crypto";
import { constants, lstatSync, realpathSync, type Stats } from "node:fs";
import { promises as fs } from "node:fs";
import type { FileHandle } from "node:fs/promises";
import path from "node:path";
import { StringDecoder } from "node:string_decoder";

import chokidar, { type FSWatcher } from "chokidar";

import type { AgentEvent } from "@/lib/events";
import { repoRoot } from "@/lib/repo-root";

/**
 * Default allow-listed case roots, resolved against the repo root. repoRoot()
 * honors FINDEVIL_REPO_ROOT when set; otherwise it walks upward from the
 * dashboard process cwd so `pnpm --dir apps/web` and repo-root launches behave
 * the same. The route handler uses isAllowedCasePath() to reject `?case=` paths
 * that don't sit inside one of these roots, closing the path-traversal hole
 * flagged in PR #7's `route.ts` comment + this README's "Path allow-list"
 * section.
 *
 *  - `goldens/`        committed test fixtures
 *  - `tmp/auto-runs/`  find-evil-auto headless output
 *  - `tmp/smoke/`      synthetic smoke output
 *  - `test-forensics/` operator's local DFIR corpus (gitignored)
 *
 * Operators can extend this set without code changes via the
 * `FINDEVIL_DASHBOARD_EXTRA_ROOTS` env var (path-delimiter-separated:
 * `:` on POSIX, `;` on Windows — i.e. `path.delimiter`).
 */
const DEFAULT_ALLOWED_ROOTS = [
  "goldens",
  "tmp/auto-runs",
  "tmp/smoke",
  "test-forensics",
];

const DEFAULT_MAX_CASE_FILE_BYTES = 64 * 1024 * 1024;
const DEFAULT_MAX_AUDIT_STREAM_BYTES = 256 * 1024 * 1024;
const DEFAULT_MAX_AUDIT_LINE_BYTES = 4 * 1024 * 1024;
const AUDIT_READ_CHUNK_BYTES = 64 * 1024;

/**
 * Return true iff `absPath` resolves to a location strictly INSIDE
 * one of the allow-listed roots (default roots + any
 * `FINDEVIL_DASHBOARD_EXTRA_ROOTS` entries). The trailing-separator
 * check guards against the prefix-match foot-gun where, given an
 * allowed root `/foo/bar`, a path like `/foo/baroot/case` would
 * otherwise pass a naive `startsWith`.
 *
 * The path itself is allowed when it is exactly equal to a root
 * (operators sometimes point the dashboard at the root directory
 * itself for a smoke check).
 *
 * Relative default roots resolve against the repo root. `pnpm --filter
 * @findevil/web dev` can run with cwd=apps/web, so repoRoot() walks up to the
 * repository marker unless `FINDEVIL_REPO_ROOT` is set explicitly.
 */
function configuredAllowedRoots(): string[] {
  let base: string;
  try {
    base = repoRoot();
  } catch {
    return [];
  }
  const extraRaw = process.env.FINDEVIL_DASHBOARD_EXTRA_ROOTS ?? "";
  const extras = extraRaw
    .split(path.delimiter)
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
  return [...DEFAULT_ALLOWED_ROOTS, ...extras].map((root) =>
    path.isAbsolute(root) ? path.resolve(root) : path.resolve(base, root),
  );
}

function isInside(root: string, candidate: string): boolean {
  return candidate === root || candidate.startsWith(root + path.sep);
}

/**
 * Resolve an existing Case directory through the filesystem, rejecting every
 * symlink/junction component beneath its configured root. Returning the real
 * path (instead of the lexical request) lets routes keep one canonical trust
 * boundary for all subsequent file reads.
 */
export function resolveAllowedCasePath(absPath: string): string | null {
  const requested = path.resolve(absPath);
  for (const rootAbs of configuredAllowedRoots()) {
    if (!isInside(rootAbs, requested)) continue;
    try {
      const rootStat = lstatSync(rootAbs);
      if (!rootStat.isDirectory() || rootStat.isSymbolicLink()) continue;
      const relative = path.relative(rootAbs, requested);
      if (relative.startsWith("..") || path.isAbsolute(relative)) continue;

      let current = rootAbs;
      let rejected = false;
      for (const component of relative.split(path.sep).filter(Boolean)) {
        current = path.join(current, component);
        const metadata = lstatSync(current);
        if (metadata.isSymbolicLink() || !metadata.isDirectory()) {
          rejected = true;
          break;
        }
      }
      if (rejected) continue;

      const rootReal = realpathSync(rootAbs);
      const caseReal = realpathSync(requested);
      if (isInside(rootReal, caseReal)) return caseReal;
    } catch {
      // Missing, inaccessible, raced, or non-directory paths fail closed.
    }
  }
  return null;
}

export function isAllowedCasePath(absPath: string): boolean {
  return resolveAllowedCasePath(absPath) !== null;
}

interface OpenedCaseFile {
  handle: FileHandle;
  stat: Stats;
  target: string;
  casePath: string;
}

function stableRegularFile(left: Stats, right: Stats): boolean {
  return (
    left.isFile() &&
    right.isFile() &&
    left.nlink === 1 &&
    right.nlink === 1 &&
    left.dev === right.dev &&
    left.ino === right.ino &&
    left.size === right.size &&
    left.mtimeMs === right.mtimeMs &&
    left.ctimeMs === right.ctimeMs
  );
}

async function openAllowedCaseFile(
  caseDir: string,
  relativeFile: string,
): Promise<OpenedCaseFile | null> {
  if (!relativeFile || path.isAbsolute(relativeFile)) return null;
  const canonicalCase = resolveAllowedCasePath(caseDir);
  if (!canonicalCase) return null;
  const target = path.resolve(canonicalCase, relativeFile);
  if (!isInside(canonicalCase, target) || target === canonicalCase) return null;

  const relative = path.relative(canonicalCase, target);
  let current = canonicalCase;
  const components = relative.split(path.sep).filter(Boolean);
  try {
    for (const [index, component] of components.entries()) {
      current = path.join(current, component);
      const metadata = await fs.lstat(current);
      if (metadata.isSymbolicLink()) return null;
      const final = index === components.length - 1;
      if ((!final && !metadata.isDirectory()) || (final && !metadata.isFile())) {
        return null;
      }
      if (final && metadata.nlink !== 1) return null;
    }
  } catch {
    return null;
  }

  let handle: FileHandle | null = null;
  try {
    const flags =
      process.platform === "win32"
        ? constants.O_RDONLY
        : constants.O_RDONLY | constants.O_NOFOLLOW;
    handle = await fs.open(target, flags);
    const openedStat = await handle.stat();
    if (!openedStat.isFile() || openedStat.nlink !== 1) return null;

    const targetReal = await fs.realpath(target);
    if (!isInside(canonicalCase, targetReal)) return null;
    const pathStat = await fs.lstat(target);
    if (
      pathStat.isSymbolicLink() ||
      !stableRegularFile(pathStat, openedStat)
    ) {
      return null;
    }
    const result = {
      handle,
      stat: openedStat,
      target,
      casePath: canonicalCase,
    };
    handle = null;
    return result;
  } catch {
    return null;
  } finally {
    if (handle) await handle.close().catch(() => undefined);
  }
}

async function readOpenedFile(
  opened: OpenedCaseFile,
  maxBytes: number,
): Promise<Buffer | null> {
  if (
    !Number.isSafeInteger(maxBytes) ||
    maxBytes < 0 ||
    !Number.isSafeInteger(opened.stat.size) ||
    opened.stat.size > maxBytes
  ) {
    return null;
  }
  const expected = opened.stat.size;
  const data = Buffer.alloc(expected);
  let offset = 0;
  while (offset < expected) {
    const { bytesRead } = await opened.handle.read(
      data,
      offset,
      Math.min(AUDIT_READ_CHUNK_BYTES, expected - offset),
      offset,
    );
    if (bytesRead === 0) return null;
    offset += bytesRead;
  }
  return data;
}

async function openedFileRemainsStable(opened: OpenedCaseFile): Promise<boolean> {
  try {
    const descriptorStat = await opened.handle.stat();
    const pathStat = await fs.lstat(opened.target);
    if (
      pathStat.isSymbolicLink() ||
      !stableRegularFile(opened.stat, descriptorStat) ||
      !stableRegularFile(descriptorStat, pathStat)
    ) {
      return false;
    }
    const relative = path.relative(opened.casePath, opened.target);
    let current = opened.casePath;
    const components = relative.split(path.sep).filter(Boolean);
    for (const [index, component] of components.entries()) {
      current = path.join(current, component);
      const componentStat = await fs.lstat(current);
      const final = index === components.length - 1;
      if (
        componentStat.isSymbolicLink() ||
        (!final && !componentStat.isDirectory()) ||
        (final && !componentStat.isFile())
      ) {
        return false;
      }
    }
    const targetReal = await fs.realpath(opened.target);
    return (
      isInside(opened.casePath, targetReal) &&
      resolveAllowedCasePath(opened.casePath) === opened.casePath
    );
  } catch {
    return false;
  }
}

export interface CaseFileSnapshotRequest {
  relativeFile: string;
  maxBytes?: number;
}

/**
 * Read a set of Case files while every descriptor remains open, then validate
 * every descriptor and path again. A writer/replacer racing any read rejects
 * the whole set, preventing mixed custody artifacts from reaching the client.
 */
export async function readAllowedCaseFilesSnapshot(
  caseDir: string,
  requests: readonly CaseFileSnapshotRequest[],
): Promise<Map<string, Buffer> | null> {
  if (requests.length === 0) return new Map();
  const openedFiles: OpenedCaseFile[] = [];
  const names = new Set<string>();
  try {
    for (const request of requests) {
      if (names.has(request.relativeFile)) return null;
      names.add(request.relativeFile);
      const opened = await openAllowedCaseFile(caseDir, request.relativeFile);
      if (!opened) return null;
      if (
        openedFiles.length > 0 &&
        opened.casePath !== openedFiles[0].casePath
      ) {
        await opened.handle.close().catch(() => undefined);
        return null;
      }
      openedFiles.push(opened);
    }

    const result = new Map<string, Buffer>();
    for (let index = 0; index < openedFiles.length; index += 1) {
      const request = requests[index];
      const data = await readOpenedFile(
        openedFiles[index],
        request.maxBytes ?? DEFAULT_MAX_CASE_FILE_BYTES,
      );
      if (!data) return null;
      result.set(request.relativeFile, data);
    }

    for (const opened of openedFiles) {
      if (!(await openedFileRemainsStable(opened))) return null;
    }
    return result;
  } finally {
    await Promise.all(
      openedFiles.map((opened) =>
        opened.handle.close().catch(() => undefined),
      ),
    );
  }
}

/** Read one regular, non-linked file that remains stable inside a Case. */
export async function readAllowedCaseFile(
  caseDir: string,
  relativeFile: string,
  maxBytes = DEFAULT_MAX_CASE_FILE_BYTES,
): Promise<Buffer | null> {
  const snapshot = await readAllowedCaseFilesSnapshot(caseDir, [
    { relativeFile, maxBytes },
  ]);
  return snapshot?.get(relativeFile) ?? null;
}

/** Stat one allowed Case file without following caller-created links. */
export async function statAllowedCaseFile(
  caseDir: string,
  relativeFile: string,
): Promise<Stats | null> {
  const opened = await openAllowedCaseFile(caseDir, relativeFile);
  if (!opened) return null;
  await opened.handle.close().catch(() => undefined);
  return opened.stat;
}

async function openRegularFileNoLinks(
  filePath: string,
): Promise<OpenedCaseFile | null> {
  let handle: FileHandle | null = null;
  try {
    const before = await fs.lstat(filePath);
    if (before.isSymbolicLink() || !before.isFile() || before.nlink !== 1) {
      return null;
    }
    const flags =
      process.platform === "win32"
        ? constants.O_RDONLY
        : constants.O_RDONLY | constants.O_NOFOLLOW;
    handle = await fs.open(filePath, flags);
    const opened = await handle.stat();
    if (
      !opened.isFile() ||
      opened.nlink !== 1 ||
      opened.dev !== before.dev ||
      opened.ino !== before.ino
    ) {
      return null;
    }
    const result = {
      handle,
      stat: opened,
      target: filePath,
      casePath: path.dirname(filePath),
    };
    handle = null;
    return result;
  } catch {
    return null;
  } finally {
    if (handle) await handle.close().catch(() => undefined);
  }
}

/** One selectable case in the dashboard picker. */
export interface CaseEntry {
  /** Absolute case directory. */
  path: string;
  /** Directory basename, shown in the picker. */
  name: string;
  /** audit.jsonl mtime (ms) — used to sort newest-first. */
  mtime: number;
}

/**
 * List case directories (immediate children of the allow-listed roots that
 * contain an audit.jsonl), newest-first. Powers the dashboard case picker so
 * an investigator selects a case instead of pasting an absolute path.
 */
export async function listCases(): Promise<CaseEntry[]> {
  let base: string;
  try {
    base = repoRoot();
  } catch {
    return [];
  }
  const extraRaw = process.env.FINDEVIL_DASHBOARD_EXTRA_ROOTS ?? "";
  const extras = extraRaw
    .split(path.delimiter)
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
  const roots = [...DEFAULT_ALLOWED_ROOTS, ...extras].map((r) =>
    path.isAbsolute(r) ? r : path.resolve(base, r),
  );

  const out: CaseEntry[] = [];
  const seen = new Set<string>();
  for (const root of roots) {
    let entries;
    try {
      entries = await fs.readdir(root, { withFileTypes: true });
    } catch {
      continue; // root doesn't exist on this host — skip
    }
    for (const e of entries) {
      if (!e.isDirectory()) continue;
      const dir = path.join(root, e.name);
      const canonicalDir = resolveAllowedCasePath(dir);
      if (!canonicalDir || seen.has(canonicalDir)) continue;
      try {
        const s = await statAllowedCaseFile(canonicalDir, "audit.jsonl");
        if (!s) continue;
        out.push({ path: canonicalDir, name: e.name, mtime: s.mtimeMs });
        seen.add(canonicalDir);
      } catch {
        // no audit.jsonl → not a case dir
      }
    }
  }
  out.sort((a, b) => b.mtime - a.mtime);
  return out;
}

/**
 * One yielded record. We surface the raw parsed JSON object plus a
 * `kind` tag because audit.jsonl carries lines OUTSIDE the
 * AgentEvent union too — `audit_append`, `acp_handoff`, etc. The
 * `event` field is the typed AgentEvent subset; everything else
 * falls into `raw`.
 */
export interface AuditLine {
  /** Sequence number from the audit chain (added by the agent's
   *  AuditLog.append; present on every well-formed line). */
  seq: number;
  /** Audit-log "kind" field — distinguishes AgentEvent variants from
   *  the bookkeeping records (acp_handoff, …). */
  kind: string;
  /** ISO-8601Z timestamp from the line. */
  ts: string;
  /** Parsed payload (the typed AgentEvent for kind∈AgentEvent.event_type;
   *  arbitrary object otherwise). */
  payload: AgentEvent | Record<string, unknown>;
  /** SHA-256 of the canonicalized line — for the hash-chain badge. */
  line_hash?: string;
  /** Raw JSON line, byte-identical to what's in audit.jsonl. Useful
   *  for re-verifying the chain client-side. */
  raw_line: string;
}

/**
 * Open a tail over a case's audit.jsonl. Yields every existing line
 * first (so a late-connecting consumer doesn't miss earlier events),
 * then continues yielding appended lines until the abort signal
 * fires.
 */
export async function* tailAuditLog(
  auditPath: string,
  signal: AbortSignal,
  trustedCaseDir?: string,
  limits: { maxBytes?: number; maxLineBytes?: number } = {},
): AsyncGenerator<AuditLine, void, void> {
  const absPath = path.resolve(auditPath);
  const opened = await (
    trustedCaseDir
      ? openAllowedCaseFile(trustedCaseDir, path.basename(absPath))
      : openRegularFileNoLinks(absPath)
  );
  if (!opened) return;
  const maxBytes = limits.maxBytes ?? DEFAULT_MAX_AUDIT_STREAM_BYTES;
  const maxLineBytes = limits.maxLineBytes ?? DEFAULT_MAX_AUDIT_LINE_BYTES;
  if (
    !Number.isSafeInteger(maxBytes) ||
    maxBytes <= 0 ||
    !Number.isSafeInteger(maxLineBytes) ||
    maxLineBytes <= 0
  ) {
    await opened.handle.close().catch(() => undefined);
    throw new Error("audit-tail limits must be positive safe integers");
  }

  // Set up abort tracking up-front so a mid-drain abort doesn't get
  // lost. Without this, `signal.addEventListener("abort", …)` would
  // be registered AFTER the initial drain — and abort events fire
  // exactly once, so a missed event = a hung iterator.
  let done = false;
  let watcher: FSWatcher | null = null;
  let resolve: (() => void) | null = null;
  let wakePending = false;

  const wakeup = (): void => {
    if (resolve) {
      const r = resolve;
      resolve = null;
      r();
    } else {
      wakePending = true;
    }
  };

  const onAbort = (): void => {
    done = true;
    if (watcher) {
      watcher.close().catch(() => {
        // best-effort
      });
    }
    wakeup();
  };

  if (signal.aborted) {
    await opened.handle.close().catch(() => undefined);
    return;
  }
  signal.addEventListener("abort", onAbort);

  try {
    let position = 0;
    let totalRead = 0;
    let lineBuffer = "";
    const decoder = new StringDecoder("utf8");

    // Attach before the initial drain; wakePending coalesces events that race
    // with the drain or arrive before the iterator begins waiting.
    watcher = chokidar.watch(absPath, {
      persistent: true,
      awaitWriteFinish: false,
      ignoreInitial: true,
    });

    watcher.on("add", (changedPath: string) => {
      if (path.resolve(changedPath) === absPath) wakeup();
    });
    watcher.on("change", (changedPath: string) => {
      if (path.resolve(changedPath) === absPath) wakeup();
    });
    watcher.on("ready", wakeup);
    watcher.on("error", (err: unknown) => {
      console.error("audit-tail watcher error:", err);
    });

    while (!done) {
      const handleStat = await opened.handle.stat();
      const pathStat = await fs.lstat(absPath);
      if (
        !handleStat.isFile() ||
        handleStat.nlink !== 1 ||
        pathStat.isSymbolicLink() ||
        !pathStat.isFile() ||
        pathStat.nlink !== 1 ||
        pathStat.dev !== handleStat.dev ||
        pathStat.ino !== handleStat.ino
      ) {
        throw new Error("audit log identity changed while streaming");
      }
      if (handleStat.size < position) {
        throw new Error("audit log was truncated while streaming");
      }
      if (handleStat.size > maxBytes) {
        throw new Error(`audit log exceeds the ${maxBytes}-byte stream limit`);
      }

      let readAny = false;
      while (!done && position < handleStat.size) {
        const remaining = Number(handleStat.size - position);
        const buffer = Buffer.alloc(Math.min(AUDIT_READ_CHUNK_BYTES, remaining));
        const { bytesRead } = await opened.handle.read(buffer, 0, buffer.length, position);
        if (bytesRead === 0) break;
        readAny = true;
        position += bytesRead;
        totalRead += bytesRead;
        if (totalRead > maxBytes) {
          throw new Error(`audit stream exceeds the ${maxBytes}-byte connection limit`);
        }
        lineBuffer += decoder.write(buffer.subarray(0, bytesRead));

        let newlineIndex = lineBuffer.indexOf("\n");
        while (newlineIndex !== -1) {
          let line = lineBuffer.slice(0, newlineIndex);
          lineBuffer = lineBuffer.slice(newlineIndex + 1);
          if (line.endsWith("\r")) line = line.slice(0, -1);
          if (Buffer.byteLength(line, "utf8") > maxLineBytes) {
            throw new Error(`audit line exceeds the ${maxLineBytes}-byte limit`);
          }
          if (line.length > 0) {
            const parsed = parseLine(line);
            if (parsed) yield parsed;
          }
          newlineIndex = lineBuffer.indexOf("\n");
        }
        if (Buffer.byteLength(lineBuffer, "utf8") > maxLineBytes) {
          throw new Error(`audit line exceeds the ${maxLineBytes}-byte limit`);
        }
      }

      if (done) break;
      if (readAny) continue;
      if (wakePending) {
        wakePending = false;
        continue;
      }
      await new Promise<void>((r) => {
        resolve = r;
      });
      wakePending = false;
    }
  } finally {
    signal.removeEventListener("abort", onAbort);
    if (watcher) {
      await watcher.close().catch(() => undefined);
    }
    await opened.handle.close().catch(() => undefined);
  }
}

function parseLine(line: string): AuditLine | null {
  try {
    const obj = JSON.parse(line) as Record<string, unknown>;
    const seq = typeof obj.seq === "number" ? obj.seq : -1;
    const kind = typeof obj.kind === "string" ? obj.kind : "unknown";
    const ts = typeof obj.ts === "string" ? obj.ts : "";
    return {
      seq,
      kind,
      ts,
      payload: (obj.payload ?? obj) as AgentEvent | Record<string, unknown>,
      // Hash the exact bytes the stream read. Never trust an evidence-controlled
      // line_hash field or reserialize floats/Unicode on this presentation path.
      line_hash: createHash("sha256").update(line, "utf-8").digest("hex"),
      raw_line: line,
    };
  } catch {
    // Malformed line — skip silently rather than abort the stream.
    // Future: surface as a `kind=tail_parse_error` synthetic event.
    return null;
  }
}
