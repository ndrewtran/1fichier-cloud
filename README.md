# 1fichier transfer desk

A small, single-user web client for the official [1fichier API](https://api.1fichier.com/). It provides a Nightdesk-style upload and download workspace while keeping API credentials and short-lived download tokens on the server side.

## Run locally

Node.js 22 or newer is required.

```sh
cp .env.example .env
# Set APP_PASSWORD, SESSION_SECRET, and ONEFICHIER_API_KEY in .env
npm ci
npm run dev
```

Open `http://localhost:3000`. For local HTTP, set `COOKIE_SECURE=false` in `.env`. The production default is secure cookies, which is appropriate when Easypanel terminates HTTPS. The health endpoint is `GET /healthz`.

## Docker and Easypanel

```sh
docker compose up --build -d
```

The image listens on `0.0.0.0:3000` inside the container, runs as the non-root `node` user, and does not require a persistent volume. The compose example publishes it only on `127.0.0.1:3000`, so direct local access cannot spoof proxy headers. In Easypanel, deploy the Dockerfile, expose container port `3000`, and configure the three required secrets from `.env.example` as environment variables. Keep `COOKIE_SECURE=true` behind the HTTPS domain.

## Architecture and security

- The Node/TypeScript server owns the API key and app password. The browser receives only session state and the links it explicitly requests.
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
