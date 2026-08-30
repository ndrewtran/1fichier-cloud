import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { createServer, type Server } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import {
  ActivityLogStore,
  MAX_ACTIVITY_BATCH,
  MAX_ACTIVITY_ENTRIES,
  defaultActivityLogPath,
  type ActivityLogEntry,
  validateActivityEntry,
} from "../src/activity-log.js";
import {
  activityBatchBodyBytes,
  boundActivityResponseBody,
  MAX_ACTIVITY_BATCH_BYTES,
  MAX_ACTIVITY_RESPONSE_BYTES,
  splitActivityBatches,
} from "../src/activity-batch.js";
import { type AppConfig } from "../src/config.js";
import { createApp } from "../src/server.js";

function entry(id: string, detail = id): ActivityLogEntry {
  return {
    id,
    timestamp: new Date(1_700_000_000_000 + Number(id.replace(/\D/g, "") || 0)).toISOString(),
    level: "info",
    operation: "client",
    context: "test",
    title: "Test event",
    detail,
  };
}

async function temporaryDirectory(): Promise<string> {
  return mkdtemp(join(tmpdir(), "1fichier-activity-"));
}

test("activity log survives a store reload and creates restrictive storage", async () => {
  const directory = await temporaryDirectory();
  try {
    const path = join(directory, "nested", "activity.jsonl");
    const first = new ActivityLogStore(path);
    await first.append([entry("one"), entry("two")]);
    assert.deepEqual((await first.list()).map((value) => value.id), ["two", "one"]);

    const second = new ActivityLogStore(path);
    assert.deepEqual((await second.list()).map((value) => value.id), ["two", "one"]);
    const file = await stat(path);
    assert.equal(file.mode & 0o777, 0o600);
    const parent = await stat(join(directory, "nested"));
    assert.equal(parent.mode & 0o777, 0o700);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("activity log retains newest entries and compacts the JSONL file", async () => {
  const directory = await temporaryDirectory();
  try {
    const path = join(directory, "activity.jsonl");
    const store = new ActivityLogStore(path);
    await store.append(Array.from({ length: MAX_ACTIVITY_ENTRIES + 25 }, (_, index) => entry(`event-${index}`)));
    const values = await store.list();
    assert.equal(values.length, MAX_ACTIVITY_ENTRIES);
    assert.equal(values[0]?.id, "event-2024");
    const lines = (await readFile(path, "utf8")).trim().split("\n");
    assert.equal(lines.length, MAX_ACTIVITY_ENTRIES);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("activity log skips corrupt lines and sanitizes valid lines during recovery", async () => {
  const directory = await temporaryDirectory();
  try {
    const path = join(directory, "activity.jsonl");
    const unsafe = { ...entry("unsafe", "pass=secret-value"), response: { status: 500, body: { pass: "secret-value", safe: "kept" } } };
    await writeFile(path, `${JSON.stringify(entry("first"))}\nnot-json\n${JSON.stringify(unsafe)}\n`, { mode: 0o600 });
    const store = new ActivityLogStore(path);
    const values = await store.list();
    assert.deepEqual(values.map((value) => value.id), ["unsafe", "first"]);
    assert.equal(values[0]?.detail, "pass: [redacted]");
    assert.deepEqual(values[0]?.response?.body, { safe: "kept" });
    const raw = await readFile(path, "utf8");
    assert.doesNotMatch(raw, /secret-value/);
    assert.doesNotMatch(raw, /not-json/);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("activity log redacts JSON-like credentials and sensitive query values", async () => {
  const directory = await temporaryDirectory();
  try {
    const path = join(directory, "activity.jsonl");
    const store = new ActivityLogStore(path);
    await store.append([entry("redaction", "{\"access_token\":\"secret-access\",\"client_secret\":\"secret-client\",\"key\":\"top-secret\",\"private_key\":\"other-secret\"} {“access_token”:“secret-smart”,“client_secret”:“secret-smart-client”} https://example.test/?access_token=secret-query&client_secret=secret-client-query&password=secret-password&pass=secret-pass&ok=kept")]);
    const values = await store.list();
    const detail = values[0]?.detail ?? "";
    assert.doesNotMatch(detail, /secret-access|secret-client|top-secret|other-secret|secret-smart|secret-smart-client|secret-query|secret-client-query|secret-password|secret-pass/);
    assert.match(detail, /access_token.*\[redacted\]/);
    assert.match(detail, /client_secret.*\[redacted\]/);
    assert.match(detail, /key.*\[redacted\]/);
    assert.match(detail, /private_key.*\[redacted\]/);
    assert.match(detail, /“access_token”: \[redacted\]/);
    assert.match(detail, /“client_secret”: \[redacted\]/);
    assert.match(detail, /access_token=\[redacted\]/);
    assert.match(detail, /client_secret=\[redacted\]/);
    assert.match(detail, /password=\[redacted\]/);
    assert.match(detail, /pass=\[redacted\]/);
    const raw = await readFile(path, "utf8");
    assert.doesNotMatch(raw, /secret-access|secret-client|top-secret|other-secret|secret-smart|secret-smart-client|secret-query|secret-client-query|secret-password|secret-pass/);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("concurrent appends are serialized without duplicate or partial records", async () => {
  const directory = await temporaryDirectory();
  try {
    const path = join(directory, "activity.jsonl");
    const store = new ActivityLogStore(path);
    await Promise.all(Array.from({ length: 120 }, (_, index) => store.append([entry(`event-${index}`)])));
    const values = await store.list();
    assert.equal(values.length, 120);
    assert.equal(new Set(values.map((value) => value.id)).size, 120);
    for (const line of (await readFile(path, "utf8")).trim().split("\n")) assert.doesNotThrow(() => JSON.parse(line));
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("activity batches split large diagnostics below the UTF-8 request ceiling", () => {
  const largeEntry = (id: string): ActivityLogEntry => ({ ...entry(id), response: { body: "x".repeat(32_000) } });
  const batches = splitActivityBatches([largeEntry("large-one"), largeEntry("large-two")]);
  assert.equal(batches.length, 2);
  for (const batch of batches) assert.ok(activityBatchBodyBytes(batch) <= MAX_ACTIVITY_BATCH_BYTES);
  assert.equal(MAX_ACTIVITY_BATCH, 10);
});

test("worst-case sanitized response bodies stay bounded and flush as one batch", () => {
  const body = Object.fromEntries(Array.from({ length: 32 }, (_, index) => [`field-${index}`, "x".repeat(4_096)]));
  const boundedBody = boundActivityResponseBody(body);
  const normalized = validateActivityEntry({ ...entry("worst-case"), response: { body: boundedBody } });
  assert.ok(normalized);
  assert.equal(normalized.response?.body, "[truncated]");
  const batches = splitActivityBatches([normalized]);
  assert.equal(batches.length, 1);
  assert.ok(activityBatchBodyBytes(batches[0] ?? []) <= MAX_ACTIVITY_BATCH_BYTES);
  assert.ok(new TextEncoder().encode(JSON.stringify(normalized.response?.body)).byteLength <= MAX_ACTIVITY_RESPONSE_BYTES);
});

const apiConfig: AppConfig = {
  appPassword: "correct password",
  sessionSecret: "activity-test-secret",
  apiKey: "test-key",
  host: "127.0.0.1",
  port: 0,
  nodeEnv: "test",
  cookieSecure: false,
  maxUploadBytes: 1024,
};

async function listen(app: ReturnType<typeof createApp>): Promise<{ server: Server; origin: string }> {
  const server = createServer(app);
  await new Promise<void>((resolve, reject) => {
    server.listen(0, "127.0.0.1", () => resolve());
    server.once("error", reject);
  });
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("test server did not start");
  return { server, origin: `http://127.0.0.1:${address.port}` };
}

test("activity API enforces auth, same-origin, bounded batches, and validation", async () => {
  const directory = await temporaryDirectory();
  let server: Server | undefined;
  try {
    const store = new ActivityLogStore(join(directory, "activity.jsonl"));
    const running = await listen(createApp(apiConfig, undefined, store));
    server = running.server;
    const { origin } = running;
    const unauthenticated = await fetch(`${origin}/api/activity-log`);
    assert.equal(unauthenticated.status, 401);

    const login = await fetch(`${origin}/api/login`, {
      method: "POST",
      headers: { Origin: origin, "Content-Type": "application/json" },
      body: JSON.stringify({ password: apiConfig.appPassword }),
    });
    assert.equal(login.status, 200);
    const cookie = login.headers.get("set-cookie")?.split(";", 1)[0];
    assert.ok(cookie);

    const crossOriginRead = await fetch(`${origin}/api/activity-log`, { headers: { Origin: "https://evil.example", Cookie: cookie } });
    assert.equal(crossOriginRead.status, 200);
    const crossOrigin = await fetch(`${origin}/api/activity-log`, { method: "POST", headers: { Origin: "https://evil.example", Cookie: cookie, "Content-Type": "application/json" }, body: JSON.stringify({ entries: [entry("cross-origin")] }) });
    assert.equal(crossOrigin.status, 403);
    const invalid = await fetch(`${origin}/api/activity-log`, {
      method: "POST",
      headers: { Origin: origin, Cookie: cookie, "Content-Type": "application/json" },
      body: JSON.stringify({ entries: [{ ...entry("bad"), level: "debug" }] }),
    });
    assert.equal(invalid.status, 400);

    const appended = await fetch(`${origin}/api/activity-log`, {
      method: "POST",
      headers: { Origin: origin, Cookie: cookie, "Content-Type": "application/json" },
      body: JSON.stringify({ entries: [{ ...entry("api-entry"), detail: "pass=secret-value" }] }),
    });
    assert.equal(appended.status, 201);
    const history = await fetch(`${origin}/api/activity-log`, { headers: { Cookie: cookie } });
    assert.equal(history.status, 200);
    const body = await history.json() as { entries: ActivityLogEntry[] };
    assert.equal(body.entries[0]?.id, "api-entry");
    assert.equal(body.entries[0]?.detail, "pass: [redacted]");

    const longEntryResponse = await fetch(`${origin}/api/activity-log`, {
      method: "POST",
      headers: { Origin: origin, Cookie: cookie, "Content-Type": "application/json" },
      body: JSON.stringify({ entries: [{ ...entry("long-text"), context: "c".repeat(300), title: "t".repeat(300), detail: "d".repeat(5_000) }] }),
    });
    assert.equal(longEntryResponse.status, 201);
    const longEntryBody = await longEntryResponse.json() as { entries: ActivityLogEntry[] };
    assert.equal(longEntryBody.entries[0]?.context.length, 256);
    assert.equal(longEntryBody.entries[0]?.title.length, 256);
    assert.equal(longEntryBody.entries[0]?.detail.length, 4_096);

    const tooMany = await fetch(`${origin}/api/activity-log`, {
      method: "POST",
      headers: { Origin: origin, Cookie: cookie, "Content-Type": "application/json" },
      body: JSON.stringify({ entries: Array.from({ length: MAX_ACTIVITY_BATCH + 1 }, (_, index) => entry(`too-many-${index}`)) }),
    });
    assert.equal(tooMany.status, 400);

    const oversized = await fetch(`${origin}/api/activity-log`, {
      method: "POST",
      headers: { Origin: origin, Cookie: cookie, "Content-Type": "application/json" },
      body: JSON.stringify({ entries: [{ ...entry("oversized"), response: { body: "x".repeat(70_000) } }] }),
    });
    assert.equal(oversized.status, 413);
  } finally {
    const activeServer = server;
    if (activeServer) await new Promise<void>((resolve) => activeServer.close(() => resolve()));
    await rm(directory, { recursive: true, force: true });
  }
});

test("production activity history allows an authenticated read without Origin or Referer", async () => {
  const directory = await temporaryDirectory();
  let server: Server | undefined;
  try {
    const store = new ActivityLogStore(join(directory, "activity.jsonl"));
    await store.append([entry("production-entry")]);
    const running = await listen(createApp({ ...apiConfig, nodeEnv: "production" }, undefined, store));
    server = running.server;
    const login = await fetch(`${running.origin}/api/login`, {
      method: "POST",
      headers: { Origin: running.origin, "Content-Type": "application/json" },
      body: JSON.stringify({ password: apiConfig.appPassword }),
    });
    const cookie = login.headers.get("set-cookie")?.split(";", 1)[0];
    assert.ok(cookie);
    const history = await fetch(`${running.origin}/api/activity-log`, { headers: { Cookie: cookie } });
    assert.equal(history.status, 200);
    const body = await history.json() as { entries: ActivityLogEntry[] };
    assert.equal(body.entries[0]?.id, "production-entry");
  } finally {
    const activeServer = server;
    if (activeServer) await new Promise<void>((resolve) => activeServer.close(() => resolve()));
    await rm(directory, { recursive: true, force: true });
  }
});

test("client activity history is wired for authenticated hydration and bounded batching", async () => {
  const [script, page, batch] = await Promise.all([
    readFile(new URL("../src/public/app.ts", import.meta.url), "utf8"),
    readFile(new URL("../src/public/index.html", import.meta.url), "utf8"),
    readFile(new URL("../src/activity-batch.ts", import.meta.url), "utf8"),
  ]);
  assert.match(script, /async function hydrateActivity\(\)/);
  assert.match(script, /fetch\("\/api\/activity-log"/);
  assert.match(batch, /MAX_ACTIVITY_BATCH = 10/);
  assert.match(batch, /MAX_ACTIVITY_BATCH_BYTES = 60 \* 1024/);
  assert.match(batch, /MAX_ACTIVITY_RESPONSE_BYTES = 40 \* 1024/);
  assert.match(script, /boundActivityResponseBody/);
  assert.match(script, /takeActivityBatch/);
  assert.match(script, /JSON\.stringify\(\{ entries: batch \}\)/);
  assert.match(script, /if \(!authenticated \|\| !activityPersistenceController\) return;/);
  assert.match(script, /Activity history unavailable/);
  assert.match(script, /activityFlushPromise/);
  assert.match(script, /requeueActivityBatch/);
  assert.match(script, /ACTIVITY_RETRY_MAX_DELAY_MS/);
  assert.match(script, /drainActivityBeforeLogout/);
  assert.doesNotMatch(script, /sendBeacon/);
  assert.match(script, /keepalive: true/);
  assert.match(script, /response\.status === 401[\s\S]*clearSessionState\(\)[\s\S]*setVisible\(false\)[\s\S]*Session expired/);
  assert.match(script, /const seenIds = new Set\(activities\.map\(\(entry\) => entry\.id\)\)/);
  assert.match(page, /id="activity-persistence-status"/);
});

test("local development uses a writable activity path while production defaults to /data", () => {
  assert.match(defaultActivityLogPath("development"), /\.data[\\/]activity-log\.jsonl$/);
  assert.equal(defaultActivityLogPath("production"), "/data/activity-log.jsonl");
});
