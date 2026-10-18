# Whatscraft relay

The backend for [Whatscraft](../README.md): a REST API for accounts, friends
and conversation state, plus a WebSocket relay that forwards end-to-end
encrypted messages. **It only ever sees ciphertext.**

Bun + Postgres. Runs against any Postgres (a free
[Neon](https://neon.tech) database works well) or an embedded PGlite file for
local development.

## Run locally

```sh
bun install
bun run src/index.ts        # http://localhost:8080, PGlite -> ./.data
```

## Deploy on Render (free, no credit card)

1. Push this repo to GitHub (or fork it).
2. Render Dashboard -> **New +** -> **Blueprint** -> pick this repo -> **Apply**.
   The included `render.yaml` creates a free Docker web service in Ohio.
3. When prompted, paste your Postgres connection string as `DATABASE_URL`
   (the `JWT_SECRET` is generated automatically).
   Optionally set `REGISTER_CODE` to keep the relay invite-only.
4. After the first deploy, note the service URL
   (`https://whatscraft-relay-xxxx.onrender.com`) and put it in the app's
   **Server** setting.

Free instances sleep after 15 minutes without traffic and wake in about a
minute. An incoming WebSocket message also counts as traffic, so the relay
stays awake while any phone is connected; for always-on, point a free uptime
pinger (e.g. UptimeRobot) at `/v1/health` every 10 minutes.

## Environment

| Variable | Purpose |
| --- | --- |
| `PORT` | HTTP port (Render sets this; defaults to 8080) |
| `DATABASE_URL` | Postgres connection string; empty = embedded PGlite |
| `JWT_SECRET` | Signing secret for access tokens; required in production |
| `REGISTER_CODE` | When set, new registrations must present this code |
| `ACCESS_TTL_SECONDS`, `REFRESH_TTL_DAYS` | Token lifetimes |
| `FCM_PROJECT_ID`, `FCM_CLIENT_EMAIL`, `FCM_PRIVATE_KEY` | Optional background push (Firebase HTTP v1) |

## Tests

With a server running locally:

```sh
BASE_URL=http://127.0.0.1:8080 bun run smoke            # 41 assertions
BASE_URL=https://your-service.onrender.com REGISTER_CODE=... bun run smoke
```
