# Whatscraft relay

The backend for [Whatscraft](../README.md): a REST API for accounts, friends
and conversation state, plus a WebSocket relay for live messages.

**Messages are stored in the cloud as plain text**, so the same history loads
on every device a person signs in to. That is the trade-off this project makes:
simple, Messenger-like chats instead of end-to-end encryption. Passwords are
argon2id hashes, sessions use short-lived access tokens plus rotating refresh
tokens, and only the account owner can read their own conversations.

Bun + Postgres. Runs against any Postgres (a free
[Neon](https://neon.tech) database works well) or an embedded PGlite file for
local development.

## Run locally

```sh
bun install
bun run src/index.ts        # http://localhost:8080, PGlite -> ./.data
```

The schema is applied on boot. It is safe to run repeatedly: it also deletes
legacy ciphertext rows from the old end-to-end design, which nobody can read
anymore.

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

## Message API

| Route | Purpose |
| --- | --- |
| `POST /v1/conversations/:id/messages` | Send `{ id, kind, body: { text } }` |
| `GET /v1/conversations/:id/messages?before=&limit=` | Newest window, oldest-first |
| `POST /v1/conversations/:id/read` | Advance unread (`{ seq, receipt }`); `receipt:false` keeps the position private |
| `POST /v1/conversations/:id/clear` | Hide the history for my account |
| `POST /v1/messages/clear` | Hide every chat's history for my account |

`clear` is per account: it records how far each member has cleared, so new
messages keep arriving while the other person keeps their copy. Message rows
are ordinary JSON; reactions are rows of kind `reaction`. The old encrypted
body shape (`{ alg, iv, ct, sig }` plus per-device envelopes) is still
*accepted* from phones that have not updated, but those rows are no longer
displayed by the current app and are removed on boot.

Read receipts are a separate per-member watermark (`receipt_seq`), returned to
the other side as `peerLastReadSeq`. It only moves when receipts are switched
on, so blue ticks survive a restart while people who disabled receipts never
reveal their read position.

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
BASE_URL=http://127.0.0.1:8080 bun run smoke            # 59 assertions
BASE_URL=https://your-service.onrender.com REGISTER_CODE=... bun run smoke
```

The final smoke section covers the cloud model directly: plaintext bodies with
no envelopes, readable previews, per-account clear, and keyless device
registration. Earlier sections still exercise the legacy frame shape so the
compatibility path stays working.
