import assert from "node:assert/strict";
import { createServer, request as httpRequest, type Server } from "node:http";
import test, { after, before } from "node:test";
import { Readable } from "node:stream";
import { createSession, LoginThrottleStore, verifySession } from "../src/auth.js";
import { type AppConfig } from "../src/config.js";
import { normalizeFichierLink, FichierClient, type DownloadToken, type UploadServer, type UploadResponse } from "../src/1fichier.js";
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

  public constructor() {
    super("mock-key", async () => new Response("{}"));
  }

  public override async getDownloadToken(link: string, _pass?: string): Promise<DownloadToken> {
    this.requestedLinks.push(link);
    return { url: "https://download.1fichier.com/private-token" };
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
