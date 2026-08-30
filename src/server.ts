import express, { type ErrorRequestHandler, type NextFunction, type Request, type Response } from "express";
import type { Server as HttpServer } from "node:http";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { existsSync } from "node:fs";
import { timingSafeEqual } from "node:crypto";
import { loadConfig, type AppConfig } from "./config.js";
import {
  clearSessionCookie,
  hasValidSession,
  LoginThrottleStore,
  setSessionCookie,
} from "./auth.js";
import {
  createResponseDiagnostic,
  normalizeFichierLinks,
  FichierClient,
  FichierError,
  type FichierResponseDiagnostic,
} from "./1fichier.js";
import { handleUpload, sendUploadError } from "./upload.js";
import {
  ActivityLogStore,
  defaultActivityLogPath,
  validateActivityEntry,
} from "./activity-log.js";
import { MAX_ACTIVITY_BATCH } from "./activity-batch.js";

const here = dirname(fileURLToPath(import.meta.url));
export const UPLOAD_REQUEST_TIMEOUT_MS = (4 * 60 * 60 + 5 * 60) * 1000;

export function configureServerTimeouts(server: HttpServer): void {
  // Keep Node's default headersTimeout so slow header attacks remain bounded;
  // only the body request timeout is extended for the documented upload window.
  server.requestTimeout = UPLOAD_REQUEST_TIMEOUT_MS;
}

function sameOrigin(request: Request, config: AppConfig): boolean {
  const origin = request.get("origin");
  const forwardedProto = request.get("x-forwarded-proto")?.split(",")[0]?.trim();
  const protocol = forwardedProto || (request.secure ? "https" : "http");
  const expected = `${protocol}://${request.get("host")}`;
  if (origin) return origin === expected;
  const referer = request.get("referer");
  if (referer) {
    try {
      return new URL(referer).origin === expected;
    } catch {
      return false;
    }
  }
  return config.nodeEnv !== "production";
}

function isAuthenticated(request: Request, config: AppConfig): boolean {
  return hasValidSession(request, config.sessionSecret);
}

function requireAuth(request: Request, response: Response, config: AppConfig): boolean {
  if (isAuthenticated(request, config)) return true;
  response.status(401).json({ error: "Authentication required" });
  return false;
}

function publicError(error: unknown): string {
  if (error instanceof FichierError) {
    const detail = error.upstreamMessage?.replace(/https?:\/\/\S+/gi, "[redacted]");
    return detail ? `${error.message}: ${detail}` : error.message;
  }
  return error instanceof Error ? error.message : "Request failed";
}

function publicResponse(error: unknown): FichierResponseDiagnostic {
  if (error instanceof FichierError && error.response) return error.response;
  return createResponseDiagnostic(undefined, { error: error instanceof Error ? error.message : "Request failed" });
}

function passwordMatches(input: string, expected: string): boolean {
  const inputBuffer = Buffer.from(input, "utf8");
  const expectedBuffer = Buffer.from(expected, "utf8");
  return inputBuffer.length === expectedBuffer.length && timingSafeEqual(inputBuffer, expectedBuffer);
}

function clientIp(request: Request): string {
  return request.ip || "unknown";
}

function requestErrorStatus(error: unknown): number {
  if (typeof error !== "object" || error === null) return 500;
  const status = (error as { status?: unknown }).status;
  return typeof status === "number" && Number.isInteger(status) && status >= 400 && status < 500 ? status : 500;
}

export function createApp(
  config: AppConfig,
  client = new FichierClient(config.apiKey),
  activityLog = new ActivityLogStore(config.activityLogPath ?? defaultActivityLogPath(config.nodeEnv)),
): express.Express {
  const app = express();
  const throttle = new LoginThrottleStore();
  app.set("trust proxy", 1);
  app.disable("x-powered-by");

  app.use((_request, response, next) => {
    response.setHeader("X-Content-Type-Options", "nosniff");
    response.setHeader("X-Frame-Options", "DENY");
    response.setHeader("Referrer-Policy", "no-referrer");
    response.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
    response.setHeader("Cross-Origin-Opener-Policy", "same-origin");
    response.setHeader("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; object-src 'none'");
    next();
  });

  app.get("/healthz", (_request, response) => response.status(200).json({ ok: true }));
  app.post("/api/activity-log", express.json({ limit: "64kb", strict: true }), async (request, response) => {
    if (!sameOrigin(request, config)) {
      response.status(403).json({ error: "Cross-origin request rejected" });
      return;
    }
    if (!requireAuth(request, response, config)) return;
    const body = request.body as { entries?: unknown };
    if (!body || !Array.isArray(body.entries) || body.entries.length < 1 || body.entries.length > MAX_ACTIVITY_BATCH) {
      response.status(400).json({ error: `Provide between 1 and ${MAX_ACTIVITY_BATCH} activity entries` });
      return;
    }
    const entries = [];
    for (const value of body.entries) {
      const entry = validateActivityEntry(value);
      if (!entry) {
        response.status(400).json({ error: "One or more activity entries are invalid" });
        return;
      }
      entries.push(entry);
    }
    try {
      const persisted = await activityLog.append(entries);
      response.status(201).json({ entries: persisted });
    } catch {
      response.status(503).json({ error: "Activity log unavailable" });
    }
  });

  app.use(express.json({ limit: "32kb", strict: true }));

  app.post("/api/login", (request, response) => {
    if (!sameOrigin(request, config)) {
      response.status(403).json({ error: "Cross-origin request rejected" });
      return;
    }
    const key = clientIp(request);
    const state = throttle.check(key);
    if (!state.allowed) {
      response.setHeader("Retry-After", state.retryAfterSeconds);
      response.status(429).json({ error: "Too many login attempts", retryAfterSeconds: state.retryAfterSeconds });
      return;
    }
    const password = request.body as { password?: unknown };
    if (typeof password.password !== "string" || !passwordMatches(password.password, config.appPassword)) {
      const next = throttle.recordFailure(key);
      if (!next.allowed) response.setHeader("Retry-After", next.retryAfterSeconds);
      response.status(next.allowed ? 401 : 429).json({ error: next.allowed ? "Invalid password" : "Too many login attempts" });
      return;
    }
    throttle.clear(key);
    setSessionCookie(response, config.sessionSecret, config.cookieSecure);
    response.json({ ok: true });
  });

  app.get("/api/session", (request, response) => {
    response.json({ authenticated: isAuthenticated(request, config), maxUploadBytes: config.maxUploadBytes });
  });

  app.get("/api/activity-log", async (request, response) => {
    if (!requireAuth(request, response, config)) return;
    response.setHeader("Cache-Control", "no-store");
    try {
      response.json({ entries: await activityLog.list() });
    } catch {
      response.status(503).json({ error: "Activity log unavailable" });
    }
  });

  app.get("/api/1fichier/status", async (request, response) => {
    if (!requireAuth(request, response, config)) return;
    try {
      const status = await client.getApiStatus();
      const diagnostic = client.getApiStatusResponse();
      if (diagnostic) response.json({ status, response: diagnostic });
      else response.json({ status });
    } catch (error: unknown) {
      response.json({ status: "unavailable", response: publicResponse(error) });
    }
  });

  app.post("/api/logout", (request, response) => {
    if (!sameOrigin(request, config)) {
      response.status(403).json({ error: "Cross-origin request rejected" });
      return;
    }
    clearSessionCookie(response, config.cookieSecure);
    response.json({ ok: true });
  });

  app.post("/api/upload", (request, response, next) => {
    if (!sameOrigin(request, config)) {
      response.status(403).json({ error: "Cross-origin request rejected" });
      return;
    }
    if (!requireAuth(request, response, config)) return;
    handleUpload(request, response, client, config.maxUploadBytes).catch((error: unknown) => {
      if (!response.headersSent) sendUploadError(response, error);
      else next(error);
    });
  });

  app.post("/api/download/token", async (request, response) => {
    if (!sameOrigin(request, config)) {
      response.status(403).json({ error: "Cross-origin request rejected" });
      return;
    }
    if (!requireAuth(request, response, config)) return;
    const body = request.body as { links?: unknown; pass?: unknown };
    if (!Array.isArray(body.links) || body.links.length < 1 || body.links.length > 50 || !body.links.every((value) => typeof value === "string")) {
      response.status(400).json({ error: "Provide between 1 and 50 1fichier links" });
      return;
    }
    if (body.pass !== undefined && (typeof body.pass !== "string" || body.pass.length > 256)) {
      response.status(400).json({ error: "The optional password is invalid" });
      return;
    }
    const normalized = normalizeFichierLinks(body.links);
    if (normalized.invalid.length > 0) {
      response.status(400).json({ error: "Only canonical https://1fichier.com/? links are accepted", invalid: normalized.invalid });
      return;
    }

    const results: Array<{ link: string; token?: string; error?: string; response?: FichierResponseDiagnostic }> = [];
    for (const link of normalized.links) {
      try {
        const token = await client.getDownloadToken(link, body.pass as string | undefined);
        results.push({ link, token: token.url });
      } catch (error: unknown) {
        results.push({ link, error: publicError(error), response: publicResponse(error) });
      }
    }
    response.status(results.some((result) => result.token) ? 200 : 502).json({ results });
  });

  const publicDirectory = existsSync(resolve(here, "public")) ? resolve(here, "public") : resolve(here, "../public");
  app.use(express.static(publicDirectory, { index: "index.html", extensions: ["html"] }));

  const errorHandler: ErrorRequestHandler = (error, _request, response, _next) => {
    if (response.headersSent) return;
    response.status(requestErrorStatus(error)).json({ error: publicError(error) });
  };
  app.use(errorHandler);
  return app;
}

if (process.env.NODE_ENV !== "test") {
  const config = loadConfig();
  const app = createApp(config);
  const server = app.listen(config.port, config.host, () => {
    console.log(`1fichier client listening on ${config.host}:${config.port}`);
  });
  configureServerTimeouts(server);
}
