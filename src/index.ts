/**
 * Whatscraft relay server.
 *
 *  - REST API under /v1      (auth, friends, conversations, history)
 *  - WebSocket under /ws     (realtime delivery, typing, presence, receipts)
 *
 * The relay stores ciphertext and public keys only; it cannot read messages.
 */
import { handleApi, sweepRateLimits } from "./api.ts";
import { config } from "./config.ts";
import { createDb, migrate } from "./db.ts";
import { Hub, type WsData } from "./hub.ts";
import { Store } from "./store.ts";
import { onClose, onMessage, onOpen } from "./ws.ts";
import { pushEnabled } from "./push.ts";
import type { ApiContext } from "./messages.ts";

const db = await createDb();
const schema = await Bun.file(new URL("../schema.sql", import.meta.url)).text();
await migrate(db, schema);
console.log("[db] schema ready");

const store = new Store(db);
const hub = new Hub();
const ctx: ApiContext = { store, hub };

// Presence is derived from live sockets: first connection => online, last => offline.
hub.onPresenceChange = (userId, online) => {
  void (async () => {
    try {
      if (!online) await store.touchLastSeen(userId);
      const [friends, user] = await Promise.all([
        store.friendIds(userId),
        store.findPublicUserById(userId),
      ]);
      hub.sendToUsers(friends, {
        t: "presence",
        userId,
        online,
        lastSeen: user?.lastSeen ?? new Date().toISOString(),
      });
    } catch (error) {
      console.error("[presence] failed:", error);
    }
  })();
};

const server = Bun.serve<WsData, Record<string, never>>({
  port: config.port,
  hostname: "0.0.0.0",
  development: process.env.NODE_ENV !== "production",

  fetch(request, server_) {
    const url = new URL(request.url);

    if (url.pathname === "/ws") {
      const upgraded = server_.upgrade(request, {
        data: { connectionId: crypto.randomUUID(), authorized: false },
      });
      if (upgraded) return undefined;
      return new Response("WebSocket upgrade failed", { status: 400 });
    }

    if (url.pathname.startsWith("/v1/")) return handleApi(request, ctx);

    return new Response("whatscraft relay is running\n", {
      status: 200,
      headers: { "content-type": "text/plain; charset=utf-8" },
    });
  },

  websocket: {
    open(ws) {
      onOpen(ws, ctx);
    },
    async message(ws, message) {
      await onMessage(ws, message as string | Buffer, ctx);
    },
    close(ws) {
      onClose(ws, ctx);
    },
    idleTimeout: 120,
    maxPayloadLength: 256 * 1024,
    perMessageDeflate: true,
    sendPings: true,
  },
});

// Housekeeping: expire stale access tokens and empty the rate-limit map.
const housekeeping = setInterval(() => {
  hub.sweepExpiredTokens();
  sweepRateLimits();
}, 30_000);
housekeeping.unref?.();

console.log(
  `[server] listening on http://0.0.0.0:${server.port} ` +
    `(push: ${pushEnabled ? "fcm" : "disabled"})`,
);

async function shutdown(signal: string) {
  console.log(`[server] ${signal} received, shutting down`);
  clearInterval(housekeeping);
  try {
    await server.stop(true);
  } catch {
    /* ignore */
  }
  await db.close();
  process.exit(0);
}

process.on("SIGINT", () => void shutdown("SIGINT"));
process.on("SIGTERM", () => void shutdown("SIGTERM"));
