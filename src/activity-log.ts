import { mkdir, open, rename, stat, unlink, chmod } from "node:fs/promises";
import { randomUUID } from "node:crypto";
import { dirname, resolve } from "node:path";
import { boundActivityResponseBody, MAX_ACTIVITY_BATCH } from "./activity-batch.js";

export const MAX_ACTIVITY_ENTRIES = 2_000;
export { MAX_ACTIVITY_BATCH } from "./activity-batch.js";

const MAX_ACTIVITY_ID_CHARS = 128;
const MAX_ACTIVITY_TIMESTAMP_CHARS = 64;
const MAX_ACTIVITY_CONTEXT_CHARS = 256;
const MAX_ACTIVITY_TITLE_CHARS = 256;
const MAX_ACTIVITY_DETAIL_CHARS = 4_096;
const MAX_ACTIVITY_VALUE_CHARS = 4_096;
const MAX_ACTIVITY_VALUE_DEPTH = 4;
const MAX_ACTIVITY_VALUE_ITEMS = 24;
const MAX_ACTIVITY_VALUE_KEYS = 32;
const MAX_ACTIVITY_KEY_CHARS = 80;
const MAX_ACTIVITY_LINE_BYTES = 64 * 1024;
const MAX_ACTIVITY_READ_BYTES = 16 * 1024 * 1024;
const COMPACTION_APPEND_INTERVAL = 100;
const COMPACTION_FILE_BYTES = 4 * 1024 * 1024;

export type ActivityLevel = "info" | "warn" | "error";
export type ActivityOperation = "session" | "upload" | "download" | "queue" | "api" | "client";

export interface ActivityResponse {
  status?: number;
  body?: unknown;
}

export interface ActivityLogEntry {
  id: string;
  timestamp: string;
  level: ActivityLevel;
  operation: ActivityOperation;
  context: string;
  title: string;
  detail: string;
  response?: ActivityResponse;
}

const SENSITIVE_ACTIVITY_KEY = /authorization|(?:api[_-]?)?key|password|passwd|cookie|secret|session|credential|bearer|token|auth(?:entication|orization)?|pass(?:word|phrase)?/i;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** Keep diagnostic text useful while preventing credential-like values from reaching disk. */
export function sanitizeActivityText(value: string): string {
  return value
    .slice(0, MAX_ACTIVITY_VALUE_CHARS)
    .replace(/https?:\/\/[^/\s@]+:[^@\s]+@/gi, "https://[redacted]@")
    .replace(/(?<![?&#A-Za-z0-9_.-])(["'“]?)([A-Za-z0-9_.-]*(?:authorization|(?:api[_-]?)?key|password|passwd|cookie|secret|session|credential|bearer|token|auth|pass)[A-Za-z0-9_.-]*)(["'”’]?)\s*[:=]\s*(?:(?:(?:bearer|basic)\s+)?(?:"[^"]*"|'[^']*'|“[^”]*”|‘[^’]*’|[^\s,;}]+))/gi, (_match, open: string, key: string, close: string) => `${open}${key}${close}: [redacted]`)
    .replace(/\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]+/gi, "$1 [redacted]")
    .replace(/([?&#][A-Za-z0-9_.-]*(?:authorization|(?:api[_-]?)?key|password|passwd|cookie|secret|session|credential|bearer|token|auth|pass)[A-Za-z0-9_.-]*=)[^&#\s]+/gi, "$1[redacted]");
}

function sanitizeActivityValue(value: unknown, depth = 0): unknown {
  if (depth > MAX_ACTIVITY_VALUE_DEPTH) return "[truncated]";
  if (typeof value === "string") return sanitizeActivityText(value);
  if (typeof value === "number") return Number.isFinite(value) ? value : "[invalid number]";
  if (typeof value === "boolean" || value === null) return value;
  if (Array.isArray(value)) return value.slice(0, MAX_ACTIVITY_VALUE_ITEMS).map((item) => sanitizeActivityValue(item, depth + 1));
  if (!isRecord(value)) return "[unsupported value]";

  const result: Record<string, unknown> = {};
  for (const [key, item] of Object.entries(value).slice(0, MAX_ACTIVITY_VALUE_KEYS)) {
    if (SENSITIVE_ACTIVITY_KEY.test(key)) continue;
    const boundedKey = key.slice(0, MAX_ACTIVITY_KEY_CHARS);
    Object.defineProperty(result, boundedKey, {
      configurable: true,
      enumerable: true,
      value: sanitizeActivityValue(item, depth + 1),
      writable: true,
    });
  }
  return result;
}

function boundedString(value: unknown, maximum: number, truncate: boolean): string | null {
  if (typeof value !== "string" || value.length === 0) return null;
  if (!truncate && value.length > maximum) return null;
  return sanitizeActivityText(value).slice(0, maximum);
}

function boundedText(value: unknown, maximum: number): string | null {
  if (typeof value !== "string" || value.length === 0) return null;
  return sanitizeActivityText(value).slice(0, maximum);
}

function activityLevel(value: unknown): value is ActivityLevel {
  return value === "info" || value === "warn" || value === "error";
}

function activityOperation(value: unknown): value is ActivityOperation {
  return value === "session" || value === "upload" || value === "download" || value === "queue" || value === "api" || value === "client";
}

function normalizeResponse(value: unknown, truncate: boolean): ActivityResponse | null {
  if (!isRecord(value)) return null;
  const response: ActivityResponse = {};
  if (value.status !== undefined) {
    if (typeof value.status !== "number" || !Number.isSafeInteger(value.status) || value.status < 100 || value.status > 599) return null;
    response.status = value.status;
  }
  if (value.body !== undefined) {
    const sanitizedBody = sanitizeActivityValue(value.body);
    try {
      response.body = boundActivityResponseBody(sanitizedBody);
    } catch {
      response.body = "[truncated]";
    }
  }
  if (Object.keys(response).length === 0 && Object.keys(value).length > 0 && !truncate) return null;
  return response;
}

function normalizeActivityEntry(value: unknown, truncate: boolean): ActivityLogEntry | null {
  if (!isRecord(value)) return null;
  const id = boundedString(value.id, MAX_ACTIVITY_ID_CHARS, truncate);
  const timestamp = boundedString(value.timestamp, MAX_ACTIVITY_TIMESTAMP_CHARS, truncate);
  const context = boundedText(value.context, MAX_ACTIVITY_CONTEXT_CHARS);
  const title = boundedText(value.title, MAX_ACTIVITY_TITLE_CHARS);
  const detail = boundedText(value.detail, MAX_ACTIVITY_DETAIL_CHARS);
  if (!id || !timestamp || !context || !title || detail === null || !activityLevel(value.level) || !activityOperation(value.operation)) return null;
  if (!Number.isFinite(Date.parse(timestamp))) return null;
  const entry: ActivityLogEntry = { id, timestamp, level: value.level, operation: value.operation, context, title, detail };
  if (value.response !== undefined) {
    const response = normalizeResponse(value.response, truncate);
    if (!response) return null;
    entry.response = response;
  }
  return entry;
}

/** Validate and sanitize one client-supplied event before it is persisted. */
export function validateActivityEntry(value: unknown): ActivityLogEntry | null {
  return normalizeActivityEntry(value, false);
}

function sanitizePersistedEntry(value: unknown): ActivityLogEntry | null {
  return normalizeActivityEntry(value, true);
}

export function defaultActivityLogPath(nodeEnv = process.env.NODE_ENV ?? "development"): string {
  return nodeEnv === "production" ? "/data/activity-log.jsonl" : resolve(process.cwd(), ".data/activity-log.jsonl");
}

interface ReadResult {
  entries: ActivityLogEntry[];
  needsCompaction: boolean;
}

async function readRecentEntries(path: string): Promise<ReadResult> {
  let fileSize = 0;
  try {
    fileSize = (await stat(path)).size;
  } catch (error: unknown) {
    if (isNodeError(error) && error.code === "ENOENT") return { entries: [], needsCompaction: false };
    throw error;
  }
  if (fileSize === 0) return { entries: [], needsCompaction: false };

  const start = Math.max(0, fileSize - MAX_ACTIVITY_READ_BYTES);
  const length = fileSize - start;
  const handle = await open(path, "r");
  let buffer: Buffer;
  try {
    buffer = Buffer.alloc(length);
    await handle.read(buffer, 0, length, start);
  } finally {
    await handle.close();
  }

  let text = buffer.toString("utf8");
  let needsCompaction = start > 0;
  if (start > 0) {
    const firstNewline = text.indexOf("\n");
    if (firstNewline < 0) return { entries: [], needsCompaction: true };
    text = text.slice(firstNewline + 1);
  }

  const parsedEntries: ActivityLogEntry[] = [];
  for (const line of text.split("\n")) {
    if (!line) continue;
    if (Buffer.byteLength(line, "utf8") > MAX_ACTIVITY_LINE_BYTES) {
      needsCompaction = true;
      continue;
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(line) as unknown;
    } catch {
      needsCompaction = true;
      continue;
    }
    const entry = sanitizePersistedEntry(parsed);
    if (!entry) {
      needsCompaction = true;
      continue;
    }
    if (JSON.stringify(parsed) !== JSON.stringify(entry)) needsCompaction = true;
    parsedEntries.push(entry);
  }

  if (text.length > 0 && !text.endsWith("\n")) needsCompaction = true;
  const entries: ActivityLogEntry[] = [];
  const seenIds = new Set<string>();
  for (const entry of parsedEntries.reverse()) {
    if (seenIds.has(entry.id)) {
      needsCompaction = true;
      continue;
    }
    seenIds.add(entry.id);
    entries.push(entry);
  }
  if (entries.length > MAX_ACTIVITY_ENTRIES) needsCompaction = true;
  return { entries: entries.slice(0, MAX_ACTIVITY_ENTRIES), needsCompaction };
}

function isNodeError(error: unknown): error is NodeJS.ErrnoException {
  return error instanceof Error && "code" in error;
}

async function bestEffortChmod(path: string, mode: number): Promise<void> {
  try {
    await chmod(path, mode);
  } catch (error: unknown) {
    if (!isNodeError(error) || (error.code !== "EPERM" && error.code !== "EACCES" && error.code !== "EROFS")) throw error;
  }
}

export class ActivityLogStore {
  private readonly path: string;
  private entries: ActivityLogEntry[] = [];
  private fileSize = 0;
  private appendsSinceCompaction = 0;
  private initialized: Promise<void> | undefined;
  private queue: Promise<void> = Promise.resolve();

  public constructor(path = defaultActivityLogPath()) {
    this.path = resolve(path);
  }

  public get filePath(): string {
    return this.path;
  }

  public list(): Promise<ActivityLogEntry[]> {
    return this.serialized(async () => [...this.entries]);
  }

  public append(values: readonly unknown[]): Promise<ActivityLogEntry[]> {
    return this.serialized(async () => {
      const accepted: ActivityLogEntry[] = [];
      const knownIds = new Set(this.entries.map((entry) => entry.id));
      for (const value of values) {
        const entry = sanitizePersistedEntry(value);
        if (!entry || knownIds.has(entry.id)) continue;
        knownIds.add(entry.id);
        accepted.push(entry);
      }
      if (accepted.length === 0) return [];

      const handle = await open(this.path, "a", 0o600);
      try {
        await bestEffortChmod(this.path, 0o600);
        for (const entry of accepted) {
          const line = `${JSON.stringify(entry)}\n`;
          await handle.writeFile(line, { encoding: "utf8" });
          this.fileSize += Buffer.byteLength(line, "utf8");
        }
        await handle.sync();
      } finally {
        await handle.close();
      }

      const newest = accepted.slice().reverse();
      this.entries = [...newest, ...this.entries].slice(0, MAX_ACTIVITY_ENTRIES);
      this.appendsSinceCompaction += accepted.length;
      if (this.appendsSinceCompaction >= COMPACTION_APPEND_INTERVAL || this.fileSize >= COMPACTION_FILE_BYTES) await this.compact();
      return newest;
    });
  }

  private serialized<T>(task: () => Promise<T>): Promise<T> {
    const run = this.queue.then(async () => {
      await this.ensureInitialized();
      return task();
    });
    this.queue = run.then(() => undefined, () => undefined);
    return run;
  }

  private async ensureInitialized(): Promise<void> {
    if (!this.initialized) {
      this.initialized = this.initialize().catch((error: unknown) => {
        this.initialized = undefined;
        throw error;
      });
    }
    await this.initialized;
  }

  private async initialize(): Promise<void> {
    const directory = dirname(this.path);
    await mkdir(directory, { recursive: true, mode: 0o700 });
    await bestEffortChmod(directory, 0o700);
    const file = await open(this.path, "a", 0o600);
    await file.close();
    await bestEffortChmod(this.path, 0o600);
    const existing = await readRecentEntries(this.path);
    this.entries = existing.entries;
    try {
      this.fileSize = (await stat(this.path)).size;
    } catch (error: unknown) {
      if (!isNodeError(error) || error.code !== "ENOENT") throw error;
      this.fileSize = 0;
    }
    if (existing.needsCompaction) await this.compact();
    else if (this.fileSize > 0) await bestEffortChmod(this.path, 0o600);
  }

  private async compact(): Promise<void> {
    const temporaryPath = `${this.path}.${randomUUID()}.tmp`;
    let handle: Awaited<ReturnType<typeof open>> | undefined;
    try {
      handle = await open(temporaryPath, "wx", 0o600);
      for (const entry of [...this.entries].reverse()) await handle.writeFile(`${JSON.stringify(entry)}\n`, { encoding: "utf8" });
      await handle.sync();
      await handle.close();
      handle = undefined;
      await rename(temporaryPath, this.path);
      await bestEffortChmod(this.path, 0o600);
      this.fileSize = (await stat(this.path)).size;
      this.appendsSinceCompaction = 0;
    } catch (error: unknown) {
      if (handle) await handle.close().catch(() => undefined);
      await unlink(temporaryPath).catch(() => undefined);
      throw error;
    }
  }
}
