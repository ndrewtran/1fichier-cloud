import type { Readable } from "node:stream";
import { request as httpsRequest } from "node:https";
import { randomBytes } from "node:crypto";
import { Transform } from "node:stream";
import { URL } from "node:url";
import { ApiRateLimiter } from "./rate-limit.js";

const API_ORIGIN = "https://api.1fichier.com";
const TOKEN_PATH = "/v1/download/get_token.cgi";
const UPLOAD_SERVER_PATH = "/v1/upload/get_upload_server.cgi";
const USER_INFO_PATH = "/v1/user/info.cgi";
const MAX_API_RESPONSE_BYTES = 256 * 1024;
const MAX_DIAGNOSTIC_CHARS = 4_096;
const MAX_DIAGNOSTIC_DEPTH = 4;
const MAX_DIAGNOSTIC_KEYS = 32;
const MAX_DIAGNOSTIC_ITEMS = 24;
export const API_STATUS_CACHE_TTL_MS = 6 * 60 * 1000;

export type FichierApiStatus = "connected" | "not_configured" | "invalid_key" | "unavailable";

const PLACEHOLDER_API_KEYS = new Set([
  "SET_ME_IN_EASYPANEL",
  "replace-with-your-1fichier-api-key",
]);

export interface UploadServer {
  url: string;
  id: string;
}

export interface DownloadToken {
  url: string;
  status?: string;
  message?: string;
}

export interface UploadResponse {
  statusCode: number;
  location?: string;
  body: string;
}

/** A bounded upstream response safe to expose to the authenticated client. */
export interface FichierResponseDiagnostic {
  status?: number;
  body?: unknown;
}

export interface FichierApiStatusResult {
  status: FichierApiStatus;
  response?: FichierResponseDiagnostic;
}

export type Fetcher = (input: string | URL, init?: RequestInit) => Promise<Response>;

export class FichierError extends Error {
  public readonly statusCode: number | undefined;
  public readonly upstreamMessage: string | undefined;
  public readonly response: FichierResponseDiagnostic | undefined;

  public constructor(message: string, statusCode?: number, upstreamMessage?: string, response?: FichierResponseDiagnostic) {
    super(message);
    this.name = "FichierError";
    this.statusCode = statusCode;
    this.upstreamMessage = upstreamMessage ? sanitizeDiagnosticText(upstreamMessage) : undefined;
    this.response = response ? createResponseDiagnostic(statusCode ?? response.status, response.body) : undefined;
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function stringField(value: Record<string, unknown>, key: string): string | undefined {
  const field = value[key];
  return typeof field === "string" && field.length > 0 ? field : undefined;
}

function responseMessage(value: unknown): string | undefined {
  if (!isRecord(value)) return undefined;
  return stringField(value, "message")
    ?? stringField(value, "Message")
    ?? stringField(value, "error")
    ?? stringField(value, "status")
    ?? stringField(value, "Status");
}

const SENSITIVE_DIAGNOSTIC_KEY = /authorization|(?:api[_-]?)?key|password|passwd|cookie|secret|session|credential|bearer|token|auth(?:entication|orization)?|pass(?:word|phrase)?/i;

function sanitizeDiagnosticText(value: string): string {
  return value
    .slice(0, MAX_DIAGNOSTIC_CHARS)
    .replace(/https?:\/\/[^/\s@]+:[^@\s]+@/gi, "https://[redacted]@")
    .replace(/(["']?)(authorization|(?:api[_-]?)?key|password|passwd|cookie|secret|session|credential|bearer|token|auth(?:entication|orization)?|pass(?:word|phrase)?)\1\s*[:=]\s*(?:(?:bearer|basic)\s+)?(?:"[^"]*"|'[^']*'|[^\s,;}]+)/gi, (_match, quote: string, key: string) => `${quote}${key}${quote}: [redacted]`);
}

function sanitizeDiagnosticValue(value: unknown, depth = 0): unknown {
  if (depth > MAX_DIAGNOSTIC_DEPTH) return "[truncated]";
  if (typeof value === "string") return sanitizeDiagnosticText(value);
  if (typeof value === "number") return Number.isFinite(value) ? value : "[invalid number]";
  if (typeof value === "boolean" || value === null) return value;
  if (Array.isArray(value)) return value.slice(0, MAX_DIAGNOSTIC_ITEMS).map((item) => sanitizeDiagnosticValue(item, depth + 1));
  if (!isRecord(value)) return "[unsupported value]";
  const result: Record<string, unknown> = {};
  for (const [key, item] of Object.entries(value).slice(0, MAX_DIAGNOSTIC_KEYS)) {
    if (SENSITIVE_DIAGNOSTIC_KEY.test(key)) continue;
    result[key.slice(0, 80)] = sanitizeDiagnosticValue(item, depth + 1);
  }
  return result;
}

export function createResponseDiagnostic(status: number | undefined, body: unknown): FichierResponseDiagnostic {
  const diagnostic: FichierResponseDiagnostic = {};
  if (typeof status === "number" && Number.isSafeInteger(status) && status > 0) diagnostic.status = status;
  if (typeof body === "string") {
    const text = sanitizeDiagnosticText(body);
    if (text) diagnostic.body = text;
  } else if (body !== undefined) {
    diagnostic.body = sanitizeDiagnosticValue(body);
  }
  return diagnostic;
}

function networkResponse(error: unknown): FichierResponseDiagnostic {
  const name = error instanceof Error && error.name ? error.name : "Error";
  const message = error instanceof Error && error.message ? error.message : "Network request failed";
  return createResponseDiagnostic(undefined, { kind: "network", name, message });
}

async function readResponseBody(response: Response): Promise<string> {
  if (!response.body) return "";
  const reader = response.body.getReader();
  const chunks: Buffer[] = [];
  let total = 0;
  let done = false;
  try {
    while (!done && total < MAX_API_RESPONSE_BYTES) {
      const result = await reader.read();
      done = result.done;
      if (done || !result.value) continue;
      const remaining = MAX_API_RESPONSE_BYTES - total;
      const chunk = result.value.byteLength > remaining ? result.value.subarray(0, remaining) : result.value;
      chunks.push(Buffer.from(chunk));
      total += chunk.byteLength;
    }
    if (!done && total >= MAX_API_RESPONSE_BYTES) await reader.cancel();
  } finally {
    reader.releaseLock();
  }
  return Buffer.concat(chunks, total).toString("utf8");
}

async function parseJsonBody(response: Response): Promise<unknown> {
  const text = await readResponseBody(response);
  if (!text) return {};
  try {
    return JSON.parse(text) as unknown;
  } catch {
    throw new FichierError("1fichier returned an invalid response", response.status, undefined, createResponseDiagnostic(response.status, text));
  }
}

function authHeaders(apiKey: string): HeadersInit {
  return { Authorization: `Bearer ${apiKey}`, Accept: "application/json" };
}

function isAllowedFichierHostname(hostname: string): boolean {
  const normalized = hostname.toLowerCase();
  return normalized === "1fichier.com" || normalized.endsWith(".1fichier.com");
}

function hasExplicitPortOrCredentials(raw: string): boolean {
  const authority = raw.slice("https://".length).split(/[/?#]/, 1)[0] ?? "";
  return authority.includes(":") || authority.includes("@");
}

function normalizeUploadServerUrl(value: string): string | null {
  const raw = value.trim();
  if (!raw || /[\s/?#]/.test(raw) && !/^https:\/\//i.test(raw)) return null;

  if (/^https:\/\//i.test(raw)) {
    try {
      if (hasExplicitPortOrCredentials(raw)) return null;
      const parsed = new URL(raw);
      if (parsed.protocol !== "https:" || parsed.username || parsed.password || parsed.port || parsed.pathname !== "/" || parsed.search || parsed.hash || !isAllowedFichierHostname(parsed.hostname)) return null;
      return `https://${parsed.hostname}`;
    } catch {
      return null;
    }
  }

  if (!/^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?(?:\.[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?)+$/i.test(raw)) return null;
  const hostname = raw.toLowerCase();
  return isAllowedFichierHostname(hostname) ? `https://${hostname}` : null;
}

function normalizeDownloadTokenUrl(value: string): string | null {
  try {
    if (!/^https:\/\//i.test(value.trim()) || hasExplicitPortOrCredentials(value.trim())) return null;
    const parsed = new URL(value);
    if (parsed.protocol !== "https:" || parsed.username || parsed.password || parsed.port || parsed.hash || !isAllowedFichierHostname(parsed.hostname)) return null;
    return parsed.toString();
  } catch {
    return null;
  }
}

function canonicalLink(value: string): string | null {
  const match = /^https:\/\/(?:www\.)?1fichier\.com\/\?([a-z0-9]{5,20})$/.exec(value.trim());
  return match?.[1] ? `https://1fichier.com/?${match[1]}` : null;
}

export function normalizeFichierLink(value: string): string | null {
  return canonicalLink(value);
}

export function normalizeFichierLinks(values: string[]): { links: string[]; invalid: string[] } {
  const links: string[] = [];
  const invalid: string[] = [];
  for (const value of values) {
    const normalized = canonicalLink(value);
    if (normalized) links.push(normalized);
    else invalid.push(value);
  }
  return { links, invalid };
}

export class FichierClient {
  private readonly apiKey: string;
  private readonly limiter: ApiRateLimiter;
  private readonly fetcher: Fetcher;
  private statusCache: { status: FichierApiStatus; expiresAt: number; response?: FichierResponseDiagnostic } | undefined;
  private statusRequest: Promise<FichierApiStatusResult> | undefined;

  public constructor(apiKey: string, fetcher: Fetcher = globalThis.fetch.bind(globalThis), limiter = new ApiRateLimiter(3)) {
    this.apiKey = apiKey;
    this.fetcher = fetcher;
    this.limiter = limiter;
  }

  /** Validate the configured key without exposing account details to callers. */
  public getApiStatus(): Promise<FichierApiStatus> {
    return this.getApiStatusResult().then((result) => result.status);
  }

  public getApiStatusResponse(): FichierResponseDiagnostic | undefined {
    return this.statusCache?.response;
  }

  /** Validate the configured key and retain only bounded diagnostics for failures. */
  public getApiStatusResult(): Promise<FichierApiStatusResult> {
    if (PLACEHOLDER_API_KEYS.has(this.apiKey)) return Promise.resolve({ status: "not_configured" });

    const now = Date.now();
    if (this.statusCache && this.statusCache.expiresAt > now) {
      return Promise.resolve(this.statusCache.response ? { status: this.statusCache.status, response: this.statusCache.response } : { status: this.statusCache.status });
    }
    if (this.statusRequest) return this.statusRequest;

    const request = this.fetchApiStatus()
      .catch((error: unknown): FichierApiStatusResult => ({ status: "unavailable", response: networkResponse(error) }))
      .then((result) => {
        this.statusCache = { status: result.status, expiresAt: Date.now() + API_STATUS_CACHE_TTL_MS, ...(result.response ? { response: result.response } : {}) };
        this.statusRequest = undefined;
        return result;
      });
    this.statusRequest = request;
    return request;
  }

  private async fetchApiStatus(): Promise<FichierApiStatusResult> {
    try {
      const response = await this.limiter.enqueue(() => this.fetcher(`${API_ORIGIN}${USER_INFO_PATH}`, {
        method: "POST",
        headers: { ...authHeaders(this.apiKey), "Content-Type": "application/json" },
        body: "{}",
        redirect: "error",
        signal: AbortSignal.timeout(10_000),
      }));
      if (response.status === 401) {
        return { status: "invalid_key", response: createResponseDiagnostic(response.status, await readResponseBody(response)) };
      }
      // A 403 can also indicate an upstream flood or temporary IP lock.
      if (!response.ok) {
        const text = await readResponseBody(response);
        let body: unknown = text;
        try { body = text ? JSON.parse(text) as unknown : {}; } catch { /* retain bounded text */ }
        return { status: "unavailable", response: createResponseDiagnostic(response.status, body) };
      }
      const body = await parseJsonBody(response);
      if (!isRecord(body)) return { status: "unavailable", response: createResponseDiagnostic(response.status, body) };
      const email = body.email;
      return typeof email === "string" && email.trim().length > 0
        ? { status: "connected" }
        : { status: "unavailable", response: createResponseDiagnostic(response.status, body) };
    } catch (error: unknown) {
      if (error instanceof FichierError && error.response) return { status: "unavailable", response: error.response };
      return { status: "unavailable", response: networkResponse(error) };
    }
  }

  public getUploadServer(): Promise<UploadServer> {
    const requestServer = (method: "GET" | "POST"): Promise<Response> => this.limiter.enqueue(async () => {
      const headers = authHeaders(this.apiKey);
      return this.fetcher(`${API_ORIGIN}${UPLOAD_SERVER_PATH}`, {
        method,
        headers,
        signal: AbortSignal.timeout(30_000),
      });
    });

    return requestServer("GET").then(async (initialResponse) => {
      // Some versions of the official cURL sample use POST. Only retry when
      // the server explicitly rejects the method, never for auth or quota errors.
      let response = initialResponse;
      if (response.status === 405 || response.status === 501) {
        await response.body?.cancel();
        response = await requestServer("POST");
      }
      const body = await parseJsonBody(response);
      if (!response.ok) {
        throw new FichierError("Could not get an upload server", response.status, responseMessage(body), createResponseDiagnostic(response.status, body));
      }
      if (!isRecord(body)) throw new FichierError("1fichier returned an invalid upload server", response.status, undefined, createResponseDiagnostic(response.status, body));
      const url = stringField(body, "url");
      const id = stringField(body, "id");
      if (!url || !id) throw new FichierError("1fichier returned an incomplete upload server", response.status, undefined, createResponseDiagnostic(response.status, body));
      const normalizedUrl = normalizeUploadServerUrl(url);
      if (!normalizedUrl) throw new FichierError("1fichier returned an unsafe upload server", response.status, undefined, createResponseDiagnostic(response.status, body));
      return { url: normalizedUrl, id };
    });
  }

  public getUploadStatus(statusUrl: string, id: string): Promise<unknown> {
    return this.limiter.enqueue(async () => {
      const url = new URL(statusUrl);
      if (url.protocol !== "https:" || url.username || url.password || url.port || !isAllowedFichierHostname(url.hostname)) {
        throw new FichierError("1fichier returned an unsafe upload status URL");
      }
      url.searchParams.set("xid", id);
      const response = await this.fetcher(url, {
        method: "GET",
        headers: { ...authHeaders(this.apiKey), JSON: "1" },
        redirect: "error",
        signal: AbortSignal.timeout(30_000),
      });
      const body = await parseJsonBody(response);
      if (!response.ok) {
        throw new FichierError("1fichier could not finish the upload", response.status, responseMessage(body), createResponseDiagnostic(response.status, body));
      }
      return body;
    });
  }

  public getDownloadToken(link: string, pass?: string): Promise<DownloadToken> {
    return this.limiter.enqueue(async () => {
      const payload: Record<string, string | number> = {
        url: link,
        inline: 0,
        cdn: 0,
        restrict_ip: 0,
        single: 0,
        no_ssl: 0,
      };
      if (pass) payload.pass = pass;
      const response = await this.fetcher(`${API_ORIGIN}${TOKEN_PATH}`, {
        method: "POST",
        headers: { ...authHeaders(this.apiKey), "Content-Type": "application/json" },
        body: JSON.stringify(payload),
        signal: AbortSignal.timeout(30_000),
      });
      const body = await parseJsonBody(response);
      if (!response.ok) {
        const message = responseMessage(body);
        throw new FichierError(
          response.status === 401 || response.status === 403
            ? "Download tokens require a Premium, Premium GOLD, Access, or CDN plan"
            : "Could not create a download token",
          response.status,
          message,
          createResponseDiagnostic(response.status, body),
        );
      }
      if (!isRecord(body)) throw new FichierError("1fichier returned an invalid download token", response.status, undefined, createResponseDiagnostic(response.status, body));
      const rawUrl = stringField(body, "url");
      if (!rawUrl) {
        const detail = responseMessage(body);
        throw new FichierError(
          "Could not create a download token. This capability requires a Premium, Premium GOLD, Access, or CDN plan",
          response.status,
          detail,
          createResponseDiagnostic(response.status, body),
        );
      }
      const url = normalizeDownloadTokenUrl(rawUrl);
      if (!url) throw new FichierError("1fichier returned an unsafe download token", response.status, undefined, createResponseDiagnostic(response.status, body));
      const token: DownloadToken = { url };
      const status = stringField(body, "status");
      const message = stringField(body, "message");
      if (status) token.status = status;
      if (message) token.message = message;
      return token;
    });
  }

  public async uploadMultipart(
    uploadServer: UploadServer,
    filename: string,
    size: number,
    fileStream: Readable,
  ): Promise<UploadResponse> {
    const normalizedServerUrl = normalizeUploadServerUrl(uploadServer.url);
    if (!normalizedServerUrl) throw new FichierError("1fichier returned an unsafe upload server");
    const target = new URL(normalizedServerUrl);
    target.pathname = "/upload.cgi";
    target.search = `?id=${encodeURIComponent(uploadServer.id)}`;
    const boundary = `----1fichier-${randomBytes(12).toString("hex")}`;
    const preamble = Buffer.from(
      `--${boundary}\r\nContent-Disposition: form-data; name="file[]"; filename="${safeFilename(filename)}"\r\nContent-Type: application/octet-stream\r\n\r\n`,
      "utf8",
    );
    const epilogue = Buffer.from(`\r\n--${boundary}--\r\n`, "utf8");
    return new Promise<UploadResponse>((resolve, reject) => {
      const request = httpsRequest(target, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${this.apiKey}`,
          "Content-Type": `multipart/form-data; boundary=${boundary}`,
          "Content-Length": preamble.length + size + epilogue.length,
          Accept: "application/json, text/plain, */*",
        },
      });
      let responseBody = Buffer.alloc(0);
      request.on("response", (response) => {
        response.on("data", (chunk: Buffer) => {
          if (responseBody.length < MAX_API_RESPONSE_BYTES) {
            responseBody = Buffer.concat([responseBody, chunk]).subarray(0, MAX_API_RESPONSE_BYTES);
          }
        });
        response.on("end", () => {
          const result: UploadResponse = {
            statusCode: response.statusCode ?? 0,
            body: responseBody.toString("utf8"),
          };
          if (typeof response.headers.location === "string") result.location = response.headers.location;
          resolve(result);
        });
      });
      request.on("error", reject);
      request.write(preamble);
      const countedStream = new Transform({
        transform(chunk: Buffer, _encoding, callback) {
          bytesSent += chunk.length;
          if (bytesSent > size) callback(new Error("Uploaded file is larger than declared"));
          else callback(null, chunk);
        },
        flush(callback) {
          if (bytesSent !== size) callback(new Error("Uploaded file size did not match its declaration"));
          else callback();
        },
      });
      let bytesSent = 0;
      const fail = (error: Error): void => {
        request.destroy(error);
        reject(error);
      };
      fileStream.on("error", fail);
      countedStream.on("error", fail);
      countedStream.on("finish", () => request.end(epilogue));
      fileStream.pipe(countedStream).pipe(request, { end: false });
    });
  }
}

function safeFilename(filename: string): string {
  const normalized = filename.replace(/[\r\n"\\]/g, "_").slice(0, 255);
  return normalized || "upload.bin";
}

export function uploadStatusUrl(response: UploadResponse, uploadServer: UploadServer): string {
  const normalizedServerUrl = normalizeUploadServerUrl(uploadServer.url);
  if (!normalizedServerUrl) throw new FichierError("1fichier returned an unsafe upload server");
  const base = new URL(normalizedServerUrl);
  let status: URL;
  try {
    status = response.location ? new URL(response.location, normalizedServerUrl) : new URL("/end.pl", normalizedServerUrl);
  } catch {
    throw new FichierError("1fichier returned an invalid upload status URL");
  }
  if (status.protocol !== "https:" || status.hostname !== base.hostname || status.username || status.password || status.port || status.hash) {
    throw new FichierError("1fichier returned an unsafe upload status URL");
  }
  return status.toString();
}

export function parseUploadLinks(value: unknown): string[] {
  if (!isRecord(value)) return [];
  const possible = [value.links, value.url, value.download, value.downloads];
  const links: string[] = [];
  const addLink = (candidate: string): void => {
    const normalized = canonicalLink(candidate);
    if (normalized) links.push(normalized);
  };
  for (const candidate of possible) {
    if (typeof candidate === "string") addLink(candidate);
    if (Array.isArray(candidate)) {
      for (const item of candidate) {
        if (typeof item === "string") addLink(item);
        else if (isRecord(item)) {
          const download = stringField(item, "download");
          if (download) addLink(download);
        }
      }
    }
  }
  return [...new Set(links)];
}
