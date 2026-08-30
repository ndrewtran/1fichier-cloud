import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { createServer, request as httpRequest, type Server } from "node:http";
import test, { after, before } from "node:test";
import { Readable } from "node:stream";
import { createSession, LoginThrottleStore, verifySession } from "../src/auth.js";
import { type AppConfig } from "../src/config.js";
import { API_STATUS_CACHE_TTL_MS, createResponseDiagnostic, normalizeFichierLink, FichierClient, FichierError, type DownloadToken, type FichierApiStatus, type UploadServer, type UploadResponse } from "../src/1fichier.js";
import { ApiRateLimiter } from "../src/rate-limit.js";
import { configureServerTimeouts, createApp, UPLOAD_REQUEST_TIMEOUT_MS } from "../src/server.js";

test("sessions are signed, expiring, and reject tampering", () => {
  const session = createSession("test-secret", 1_000);
  assert.equal(verifySession(session, "test-secret", 1_001), true);
  assert.equal(verifySession(`${session}x`, "test-secret", 1_001), false);
  assert.equal(verifySession(session, "wrong-secret", 1_001), false);
  assert.equal(verifySession(session, "test-secret", 8 * 60 * 60 * 1000 + 1_001), false);
});

test("login throttling blocks repeated failures and clears on success", () => {
  const throttle = new LoginThrottleStore();
  for (let attempt = 0; attempt < 4; attempt += 1) assert.equal(throttle.recordFailure("127.0.0.1", 1_000 + attempt).allowed, true);
  assert.equal(throttle.recordFailure("127.0.0.1", 2_000).allowed, false);
  assert.equal(throttle.check("127.0.0.1", 2_001).allowed, false);
  throttle.clear("127.0.0.1");
  assert.equal(throttle.check("127.0.0.1", 2_001).allowed, true);
});

test("canonical link validation rejects arbitrary hosts and query strings", () => {
  assert.equal(normalizeFichierLink("https://1fichier.com/?abcde"), "https://1fichier.com/?abcde");
  assert.equal(normalizeFichierLink("https://www.1fichier.com/?abcde"), "https://1fichier.com/?abcde");
  assert.equal(normalizeFichierLink("https://1fichier.com/?ABCde"), null);
  assert.equal(normalizeFichierLink("https://evil.example/?abcde"), null);
  assert.equal(normalizeFichierLink("https://1fichier.com/?abcde&redirect=https://evil.example"), null);
});

test("upstream diagnostics are bounded and redact credentials", () => {
  const diagnostic = createResponseDiagnostic(502, {
    message: "upstream refused request",
    Authorization: "Bearer do-not-expose",
    apiKey: "do-not-expose",
    password: "do-not-expose",
    pass: "do-not-expose",
    token: "do-not-expose",
    nested: { detail: "safe context" },
  });
  assert.equal(diagnostic.status, 502);
  assert.deepEqual(diagnostic.body, { message: "upstream refused request", nested: { detail: "safe context" } });

  const bounded = createResponseDiagnostic(500, "x".repeat(20_000));
  assert.equal(typeof bounded.body, "string");
  assert.equal((bounded.body as string).length, 4_096);

  const text = createResponseDiagnostic(500, '{"token":"do-not-expose","message":"safe"}');
  assert.equal(text.body, '{"token": [redacted],"message":"safe"}');

  const headerText = createResponseDiagnostic(401, "Authorization: Bearer do-not-expose");
  assert.equal(headerText.body, "Authorization: [redacted]");
  const passText = createResponseDiagnostic(401, "pass: do-not-expose");
  assert.equal(passText.body, "pass: [redacted]");
});

test("failed API calls retain a safe response diagnostic", async () => {
  const client = new FichierClient("api-key", async () => new Response(JSON.stringify({ error: "plan required", token: "private-token" }), { status: 403 }));
  await assert.rejects(client.getDownloadToken("https://1fichier.com/?abcde"), (error: unknown) => {
    assert.ok(error instanceof FichierError);
    assert.deepEqual(error.response, { status: 403, body: { error: "plan required" } });
    return true;
  });

  const plainTextClient = new FichierClient("api-key", async () => new Response("gateway unavailable", { status: 502 }));
  await assert.rejects(plainTextClient.getDownloadToken("https://1fichier.com/?abcde"), (error: unknown) => {
    assert.ok(error instanceof FichierError);
    assert.deepEqual(error.response, { status: 502, body: "gateway unavailable" });
    return true;
  });
});

test("API status network diagnostics retain a safe error name and message", async () => {
  const client = new FichierClient("api-key", async () => { throw new TypeError("socket closed"); });
  assert.deepEqual(await client.getApiStatusResult(), {
    status: "unavailable",
    response: { body: { kind: "network", name: "TypeError", message: "socket closed" } },
  });
});

test("API client retries upload server with POST only after method rejection", async () => {
  const methods: string[] = [];
  const client = new FichierClient("api-key", async (_input, init) => {
    methods.push(init?.method ?? "GET");
    if (methods.length === 1) return new Response("method", { status: 405 });
    return new Response(JSON.stringify({ url: "https://upload.1fichier.com/", id: "upload-id" }), { status: 200, headers: { "Content-Type": "application/json" } });
  });
  assert.deepEqual(await client.getUploadServer(), { url: "https://upload.1fichier.com", id: "upload-id" });
  assert.deepEqual(methods, ["GET", "POST"]);
});

test("API client normalizes the official host-only upload server response", async () => {
  const client = new FichierClient("api-key", async () => new Response(JSON.stringify({ url: "invalid_node.1fichier.com", id: "upload-id" }), { status: 200 }));
  assert.deepEqual(await client.getUploadServer(), { url: "https://invalid_node.1fichier.com", id: "upload-id" });
});

test("API status recognizes placeholders without making an upstream request", async () => {
  for (const apiKey of ["SET_ME_IN_EASYPANEL", "replace-with-your-1fichier-api-key"]) {
    let calls = 0;
    const client = new FichierClient(apiKey, async () => {
      calls += 1;
      throw new Error("upstream must not be called");
    });
    assert.equal(await client.getApiStatus(), "not_configured");
    assert.equal(calls, 0);
  }
});

class RecordingRateLimiter extends ApiRateLimiter {
  public enqueued = 0;

  public constructor() {
    super(1_000);
  }

  public override enqueue<T>(task: () => Promise<T>): Promise<T> {
    this.enqueued += 1;
    return task();
  }
}

test("API status uses the official user-info request and accepts a non-empty email", async () => {
  let input: string | URL | undefined;
  let requestInit: RequestInit | undefined;
  const limiter = new RecordingRateLimiter();
  const client = new FichierClient("server-only-key", async (request, init) => {
    input = request;
    requestInit = init;
    return new Response(JSON.stringify({ email: "owner@example.test", plan: "Premium" }), { status: 200 });
  }, limiter);
  assert.equal(await client.getApiStatus(), "connected");
  assert.equal(limiter.enqueued, 1);
  assert.equal(input, "https://api.1fichier.com/v1/user/info.cgi");
  assert.equal(requestInit?.method, "POST");
  const headers = new Headers(requestInit?.headers);
  assert.equal(headers.get("authorization"), "Bearer server-only-key");
  assert.equal(headers.get("content-type"), "application/json");
  assert.equal(requestInit?.body, "{}");
  assert.equal(requestInit?.redirect, "error");
  assert.ok(requestInit?.signal);
});

test("API status classifies auth, upstream, malformed, and network failures safely", async () => {
  const responses: Array<{ response?: Response; error?: Error; expected: FichierApiStatus }> = [
    { response: new Response("unauthorized", { status: 401 }), expected: "invalid_key" },
    { response: new Response(JSON.stringify({ error: "temporary IP lock after too many requests" }), { status: 403 }), expected: "unavailable" },
    { response: new Response("upstream failure", { status: 503 }), expected: "unavailable" },
    { response: new Response(JSON.stringify({ account: "missing-email" }), { status: 200 }), expected: "unavailable" },
    { error: new Error("network failure"), expected: "unavailable" },
  ];
  for (const entry of responses) {
    const client = new FichierClient("server-only-key", async () => {
      if (entry.error) throw entry.error;
      return entry.response ?? new Response(null, { status: 500 });
    });
    assert.equal(await client.getApiStatus(), entry.expected);
  }
});

test("API status caches results and deduplicates concurrent validation", async () => {
  assert.ok(API_STATUS_CACHE_TTL_MS >= 6 * 60 * 1000);
  let calls = 0;
  let resolveResponse: ((response: Response) => void) | undefined;
  const response = new Promise<Response>((resolve) => { resolveResponse = resolve; });
  const client = new FichierClient("server-only-key", async () => {
    calls += 1;
    return response;
  }, new RecordingRateLimiter());
  const first = client.getApiStatus();
  const second = client.getApiStatus();
  assert.equal(calls, 1);
  resolveResponse?.(new Response(JSON.stringify({ email: "owner@example.test" }), { status: 200 }));
  assert.deepEqual(await Promise.all([first, second]), ["connected", "connected"]);
  assert.equal(await client.getApiStatus(), "connected");
  assert.equal(calls, 1);
});

test("upload status links extract documented link objects", async () => {
  const { parseUploadLinks } = await import("../src/1fichier.js");
  assert.deepEqual(parseUploadLinks({ links: [
    { download: "https://1fichier.com/?abcde", filename: "notes.txt", size: 12 },
    { download: "javascript:alert(1)", filename: "bad.txt" },
    { download: "https://evil.example/?abcde", filename: "bad2.txt" },
  ] }), ["https://1fichier.com/?abcde"]);
});

test("upload status fetch disables redirects", async () => {
  const client = new FichierClient("api-key", async (_input, init) => {
    assert.equal(init?.redirect, "error");
    return new Response(JSON.stringify({ links: [] }), { status: 200 });
  });
  assert.deepEqual(await client.getUploadStatus("https://upload.1fichier.com/end.pl", "upload-id"), { links: [] });
});

test("upstream response parsing stops at the bounded response cap", async () => {
  let cancelled = false;
  const body = new ReadableStream<Uint8Array>({
    pull(controller) {
      controller.enqueue(new Uint8Array(300 * 1024).fill(97));
    },
    cancel() {
      cancelled = true;
    },
  });
  const client = new FichierClient("api-key", async () => new Response(body, { status: 200 }));
  await assert.rejects(client.getUploadServer(), /invalid response/);
  assert.equal(cancelled, true);
});

test("download token responses reject non-1fichier URLs", async () => {
  const client = new FichierClient("api-key", async () => new Response(JSON.stringify({ url: "https://evil.example/token", status: "OK" }), { status: 200 }));
  await assert.rejects(client.getDownloadToken("https://1fichier.com/?abcde"), /unsafe download token/);
});

test("upload request timeout is extended without changing header timeout", () => {
  const timeoutServer = createServer();
  const defaultHeadersTimeout = timeoutServer.headersTimeout;
  configureServerTimeouts(timeoutServer);
  assert.equal(timeoutServer.requestTimeout, UPLOAD_REQUEST_TIMEOUT_MS);
  assert.equal(timeoutServer.headersTimeout, defaultHeadersTimeout);
});

class MockClient extends FichierClient {
  public readonly requestedLinks: string[] = [];
  public statusChecks = 0;

  public constructor() {
    super("mock-key", async () => new Response("{}"));
  }

  public override async getDownloadToken(link: string, _pass?: string): Promise<DownloadToken> {
    this.requestedLinks.push(link);
    return { url: "https://download.1fichier.com/private-token" };
  }

  public override async getApiStatus(): Promise<FichierApiStatus> {
    this.statusChecks += 1;
    return "connected";
  }

  public override async getUploadServer(): Promise<UploadServer> {
    return { url: "https://upload.1fichier.com/", id: "test-id" };
  }

  public override async uploadMultipart(_server: UploadServer, _filename: string, _size: number, stream: Readable): Promise<UploadResponse> {
    for await (const _chunk of stream) {
      // Consume the stream just as the real upstream request does.
    }
    return { statusCode: 302, location: "https://upload.1fichier.com/end.pl" , body: "" };
  }

  public override async getUploadStatus(_statusUrl: string, _id: string): Promise<unknown> {
    return { links: ["https://1fichier.com/?result1"] };
  }
}

const config: AppConfig = {
  appPassword: "correct horse battery staple",
  sessionSecret: "test-session-secret",
  apiKey: "test-api-key",
  host: "127.0.0.1",
  port: 0,
  nodeEnv: "test",
  cookieSecure: false,
  maxUploadBytes: 1024 * 1024,
};
let server: Server;
let origin: string;
let mockClient: MockClient;

before(async () => {
  mockClient = new MockClient();
  server = createServer(createApp(config, mockClient));
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("test server did not start");
  origin = `http://127.0.0.1:${address.port}`;
});

after(async () => {
  await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
});

test("health endpoint is public and token route is protected", async () => {
  const health = await fetch(`${origin}/healthz`);
  assert.equal(health.status, 200);
  const token = await fetch(`${origin}/api/download/token`, { method: "POST", headers: { Origin: origin, "Content-Type": "application/json" }, body: JSON.stringify({ links: ["https://1fichier.com/?abcde"] }) });
  assert.equal(token.status, 401);
});

test("API status route requires a session and exposes only the status enum", async () => {
  const unauthenticated = await fetch(`${origin}/api/1fichier/status`);
  assert.equal(unauthenticated.status, 401);
  assert.equal(mockClient.statusChecks, 0);

  const login = await fetch(`${origin}/api/login`, { method: "POST", headers: { Origin: origin, "Content-Type": "application/json" }, body: JSON.stringify({ password: config.appPassword }) });
  const cookie = login.headers.get("set-cookie")?.split(";", 1)[0];
  assert.ok(cookie);
  const response = await fetch(`${origin}/api/1fichier/status`, { headers: { Cookie: cookie } });
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), { status: "connected" });
  assert.equal(mockClient.statusChecks, 1);
});

test("Nightdesk keeps session and API status visible with mobile sign-out", async () => {
  const [page, styles, mockup] = await Promise.all([
    readFile(new URL("../src/public/index.html", import.meta.url), "utf8"),
    readFile(new URL("../src/public/styles.css", import.meta.url), "utf8"),
    readFile(new URL("../design/mockups/index.html", import.meta.url), "utf8"),
  ]);
  assert.match(page, /<span class="status status--ok">signed in<\/span>/);
  assert.match(page, /id="api-status"[^>]*role="status"[^>]*aria-live="polite"/);
  assert.match(styles, /\.night-header \.header-actions \{ display: flex; flex: 1 0 100%;/);
  assert.match(mockup, /<span class="status status--ok">signed in<\/span>\s*<span class="status status--ok">API connected<\/span>/);
  assert.doesNotMatch(mockup, /<span class="status status--working">connected<\/span>/);
});

test("Nightdesk wires recent activity buttons to the full bottom log drawer", async () => {
  const [page, script, styles] = await Promise.all([
    readFile(new URL("../src/public/index.html", import.meta.url), "utf8"),
    readFile(new URL("../src/public/app.ts", import.meta.url), "utf8"),
    readFile(new URL("../src/public/styles.css", import.meta.url), "utf8"),
  ]);
  assert.match(page, /id="activity-drawer"[^>]*aria-label="Activity log drawer"/);
  assert.match(page, /id="drawer-minimize"[^>]*data-drawer-action="minimize"/);
  assert.match(page, /id="drawer-close"[^>]*data-drawer-action="close"/);
  assert.match(script, /class="activity-item" type="button" aria-pressed=/);
  assert.match(script, /data-activity-id=/);
  assert.match(script, /<details class="log-response"><summary>Response<\/summary>/);
  assert.match(script, /scrollIntoView\(\{ block: "nearest" \}\)/);
  assert.match(script, /const text = value\.trim\(\);/);
  assert.match(script, /catch \{ return sanitizeResponseText\(text\); \}/);
  assert.match(script, /pass\(\?:word\|phrase\)\?/);
  assert.match(script, /const MAX_ACTIVITY_ENTRIES = 2_000/);
  assert.match(script, /activities\.splice\(MAX_ACTIVITY_ENTRIES\)/);
  assert.match(script, /activities\.length = 0/);
  assert.match(script, /selectedActivityId = undefined/);
  assert.match(script, /drawerState = "closed"/);
  assert.match(script, /lastLoggedApiStatus = undefined/);
  assert.match(script, /drawerRestore\.focus\(\)/);
  assert.match(script, /drawerOpen\.focus\(\)/);
  assert.match(script, /function focusDrawerContent\(\)/);
  assert.match(script, /drawerMinimize\.focus\(\)/);
  assert.match(script, /if \(selectedActivityId && !activities\.some/);
  assert.match(script, /let logoutPending = false/);
  assert.match(script, /deskView\.inert = true/);
  assert.match(script, /AbortSignal\.timeout\(10_000\)/);
  assert.match(script, /if \(logoutPending\) return;/);
  const logoutStart = script.indexOf('logoutButton.addEventListener("click"');
  assert.ok(logoutStart >= 0);
  const logoutBlock = script.slice(logoutStart, script.indexOf("fileInput.addEventListener", logoutStart));
  assert.match(logoutBlock, /deskView\.inert = true[\s\S]*await fetch\([\s\S]*finally[\s\S]*deskView\.inert = false[\s\S]*setVisible\(false\)/);
  assert.match(page, /id="drawer-restore"[^>]*data-drawer-action="restore"/);
  assert.match(styles, /\.log-drawer \{[^}]*border-top: 2px solid var\(--amber\)/s);
});

test("login and canonical download handoff use the mocked client", async () => {
  const login = await fetch(`${origin}/api/login`, { method: "POST", headers: { Origin: origin, "Content-Type": "application/json" }, body: JSON.stringify({ password: config.appPassword }) });
  assert.equal(login.status, 200);
  const cookie = login.headers.get("set-cookie")?.split(";", 1)[0];
  assert.ok(cookie);
  const response = await fetch(`${origin}/api/download/token`, { method: "POST", headers: { Origin: origin, Cookie: cookie, "Content-Type": "application/json" }, body: JSON.stringify({ links: ["https://www.1fichier.com/?abcde"] }) });
  assert.equal(response.status, 200);
  const body = await response.json() as { results: Array<{ link: string; token: string }> };
  assert.equal(body.results[0]?.link, "https://1fichier.com/?abcde");
  assert.equal(body.results[0]?.token, "https://download.1fichier.com/private-token");
  assert.deepEqual(mockClient.requestedLinks, ["https://1fichier.com/?abcde"]);
});

test("upload route rejects missing Content-Length before reading the body", async () => {
  const login = await fetch(`${origin}/api/login`, { method: "POST", headers: { Origin: origin, "Content-Type": "application/json" }, body: JSON.stringify({ password: config.appPassword }) });
  const cookie = login.headers.get("set-cookie")?.split(";", 1)[0];
  assert.ok(cookie);
  const response = await new Promise<{ status: number; body: string }>((resolve, reject) => {
    const request = httpRequest(new URL(`${origin}/api/upload`), {
      method: "POST",
      headers: { Origin: origin, Cookie: cookie, "Content-Type": "multipart/form-data; boundary=missing" },
    }, (result) => {
      let body = "";
      result.setEncoding("utf8");
      result.on("data", (chunk: string) => { body += chunk; });
      result.on("end", () => resolve({ status: result.statusCode ?? 0, body }));
    });
    request.on("error", reject);
    request.write("not-a-multipart-body");
    request.end();
  });
  assert.equal(response.status, 411);
});

test("upload route streams a multipart file through the mocked upstream", async () => {
  const login = await fetch(`${origin}/api/login`, { method: "POST", headers: { Origin: origin, "Content-Type": "application/json" }, body: JSON.stringify({ password: config.appPassword }) });
  const cookie = login.headers.get("set-cookie")?.split(";", 1)[0];
  assert.ok(cookie);
  const file = new File(["streamed file"], "notes.txt", { type: "text/plain" });
  const form = new FormData();
  form.append("file[]", file);
  const response = await fetch(`${origin}/api/upload`, { method: "POST", headers: { Origin: origin, Cookie: cookie, "X-File-Size": String(file.size) }, body: form });
  assert.equal(response.status, 200);
  const body = await response.json() as { file: { links: string[] } };
  assert.deepEqual(body.file.links, ["https://1fichier.com/?result1"]);
});

test("API queue spaces control calls", async () => {
  const limiter = new ApiRateLimiter(3);
  const started: number[] = [];
  await Promise.all([0, 1, 2].map(() => limiter.enqueue(async () => { started.push(Date.now()); return true; })));
  assert.ok((started[2] ?? 0) - (started[0] ?? 0) >= 600);
});
