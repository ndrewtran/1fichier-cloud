# 1fichier transfer desk

A small, single-user web client for the official [1fichier API](https://api.1fichier.com/). It provides a Nightdesk-style upload and download workspace while keeping API credentials and short-lived download tokens on the server side.

## Run locally

Node.js 22 or newer is required.

```sh
cp .env.example .env
# Set APP_PASSWORD, SESSION_SECRET, and 1FICHIER_API_KEY in .env
npm ci
npm run dev
```

Open `http://localhost:3000`. For local HTTP, set `COOKIE_SECURE=false` in `.env`. The production default is secure cookies, which is appropriate when Easypanel terminates HTTPS. The health endpoint is `GET /healthz`.

## Docker and Easypanel

```sh
docker compose up --build -d
```

The image listens on `0.0.0.0:3000` inside the container, runs as the non-root `node` user, and stores the bounded activity history at `/data/activity-log.jsonl`. The compose example publishes it only on `127.0.0.1:3000`, so direct local access cannot spoof proxy headers, and declares a named `activity-log-data` volume mounted at `/data`. In Easypanel, deploy the Dockerfile, expose container port `3000`, configure the three required secrets from `.env.example` as environment variables, and create a persistent volume named for example `activity-log-data` mounted at `/data`. Without that mount, activity history is lost when the container is replaced. Keep `COOKIE_SECURE=true` behind the HTTPS domain.

`ACTIVITY_LOG_PATH` may be set when a different writable path is needed. The server creates the containing directory and JSONL file with restrictive permissions where the filesystem supports them. The authenticated activity endpoints hydrate the drawer after sign-in and accept small batches of sanitized events; login failures are never persisted.

The JSONL writer is process-local, so configure Easypanel to run exactly one application replica per activity-log file. A fresh empty managed Docker/Easypanel volume inherits the image's `node` runtime ownership through Docker copy-up. An existing volume or host bind mount must be writable by UID/GID `1000:1000` (the container's `node` user). The browser makes a best-effort final batch flush during pagehide, but a sudden process or browser crash can still lose events that have not reached the server.

## Architecture and security

- The Node/TypeScript server owns the API key and app password. The browser receives only session state and the links it explicitly requests.
- The header separates the app session (`signed in`) from the 1fichier API status. The authenticated `GET /api/1fichier/status` check uses the official user-info endpoint, keeps the key server-side, and caches every result for at least six minutes. This stays below 1fichier's documented limits of one user-info request per minute per IP and one per five minutes per user; `SET_ME_IN_EASYPANEL` and the example key are reported as not configured without an upstream request.
- Sessions are signed HMAC cookies with `HttpOnly`, `SameSite=Lax`, expiry, constant-time verification, and security headers. Login failures are throttled in memory per client IP. Mutation routes enforce same-origin `Origin` or `Referer` checks.
- Uploads are parsed as one browser multipart file at a time and streamed directly to the 1fichier upload server. The server sends the upstream multipart request with an explicit `Content-Length`; it never buffers the file or follows the expected upload redirect. The browser queue supports up to the documented 500-file hard limit.
- API control calls use a simple process-local queue at no more than three calls per second. The queue does not hold the multi-hour upload body.
- Download tokens are held in the browser only after the user requests them and are opened by a separate user action. Canonical `https://1fichier.com/?` links are validated before any API call; arbitrary URLs are never fetched or proxied.

The official API's capability and limits still apply: token downloads require Premium, Premium GOLD, Access, or CDN access; documented file limits are 50 GB on registered accounts and 300 GB on premium plans, with 500 files per upload. `MAX_UPLOAD_BYTES` defaults to 300 GB. The Node request body timeout is set just over four hours while the header timeout remains bounded. Reverse proxies and platform timeouts must allow the potentially multi-hour streamed upload and must preserve the request `Content-Length`.

Tests mock upstream responses only and never make live 1fichier requests.

## Checks

```sh
npm run typecheck
npm test
npm run build
```
