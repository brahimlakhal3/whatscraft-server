/**
 * WebSocket protocol.
 *
 * client -> server
 *   { t:"auth",   token }                                   access token
 *   { t:"send",   clientId, conversationId, kind, body, envelopes }
 *   { t:"typing", conversationId, state:"start"|"stop" }
 *   { t:"read",   conversationId, seq }
 *   { t:"ping" }
 *
 * server -> client
 *   { t:"ready",  user, conversations }
 *   { t:"msg",    conversationId, message }
 *   { t:"ack",    clientId, id, conversationId, seq, createdAt }
 *   { t:"typing", conversationId, userId, state }
 *   { t:"read",   conversationId, userId, seq }
 *   { t:"presence", userId, online, lastSeen }
 *   { t:"friend", kind:"request"|"accepted"|"removed", user, requestId? }
 *   { t:"conversation", conversation }
 *   { t:"err",    code, message, clientId? }
 *   { t:"pong" }
 *
 * Close codes: 4001 token expired (reconnect with a fresh token),
 *              4002 device removed, 4003 account deleted, 4408 auth timeout.
 */
import type { ServerWebSocket } from "bun";
import { config } from "./config.ts";
import { verifyAccessToken } from "./crypto.ts";
import type { Hub, WsData } from "./hub.ts";
import { ApiError, deliverMessage, type ApiContext } from "./messages.ts";

const AUTH_TIMEOUT_MS = 15_000;

function send(ws: ServerWebSocket<WsData>, frame: Record<string, unknown>): void {
  try {
    ws.send(JSON.stringify(frame));
  } catch {
    /* socket already gone */
  }
}

function fail(ws: ServerWebSocket<WsData>, error: unknown): void {
  if (error instanceof ApiError) {
    send(ws, { t: "err", code: error.code, message: error.message });
  } else {
    console.error("[ws] unhandled error:", error);
    send(ws, { t: "err", code: "internal_error", message: "Something went wrong." });
  }
}

export function onOpen(ws: ServerWebSocket<WsData>, ctx: ApiContext): void {
  ctx.hub.registerPending(ws);
  // Unauthenticated sockets are closed quickly so they cannot pile up.
  setTimeout(() => {
    if (!ws.data.authorized) {
      try {
        ws.close(4408, "auth_timeout");
      } catch {
        /* ignore */
      }
    }
  }, AUTH_TIMEOUT_MS);
}

export function onClose(ws: ServerWebSocket<WsData>, ctx: ApiContext): void {
  ctx.hub.remove(ws.data.connectionId);
}

export async function onMessage(
  ws: ServerWebSocket<WsData>,
  raw: string | Buffer,
  ctx: ApiContext,
): Promise<void> {
  const { store, hub } = ctx;

  let frame: Record<string, any>;
  try {
    frame = JSON.parse(typeof raw === "string" ? raw : raw.toString());
    if (typeof frame !== "object" || frame === null) throw new Error("not an object");
  } catch {
    send(ws, { t: "err", code: "invalid_frame", message: "Frames must be JSON objects." });
    return;
  }

  // ------------------------------------------------------------- authenticate --
  if (!ws.data.authorized) {
    if (frame.t !== "auth" || typeof frame.token !== "string") {
      send(ws, { t: "err", code: "auth_required", message: "Send { t:'auth', token } first." });
      return;
    }
    const claims = await verifyAccessToken(frame.token, config.jwtSecret);
    if (!claims) {
      send(ws, { t: "err", code: "unauthorized", message: "Invalid or expired access token." });
      try {
        ws.close(4001, "token_expired");
      } catch {
        /* ignore */
      }
      return;
    }

    const user = await store.findUserById(claims.sub);
    if (!user) {
      try {
        ws.close(4003, "account_deleted");
      } catch {
        /* ignore */
      }
      return;
    }

    hub.attach(ws, claims.sub, claims.did, (claims.exp ?? 0) * 1000);
    await store.touchDevice(claims.did);
    await store.touchLastSeen(claims.sub);

    send(ws, {
      t: "ready",
      user: {
        id: user.id,
        username: user.username,
        displayName: user.displayName,
        about: user.about,
        shade: user.shade,
        lastSeen: user.lastSeen,
      },
      conversations: await store.listConversations(user.id),
      serverTime: new Date().toISOString(),
    });
    return;
  }

  const userId = ws.data.userId!;
  const deviceId = ws.data.deviceId!;

  try {
    switch (frame.t) {
      // ------------------------------------------------------------ keepalive --
      case "ping": {
        send(ws, { t: "pong", time: Date.now() });
        return;
      }

      // ---------------------------------------------------------- send message --
      case "send": {
        const clientId = typeof frame.clientId === "string" ? frame.clientId : undefined;
        try {
          const result = await deliverMessage(ctx, { userId, deviceId }, {
            id: frame.id,
            conversationId: frame.conversationId,
            kind: frame.kind,
            body: frame.body,
            envelopes: Array.isArray(frame.envelopes) ? frame.envelopes : [],
            clientId,
          });
          if (result.duplicate) {
            send(ws, {
              t: "ack",
              clientId: clientId ?? null,
              id: result.message.id,
              conversationId: result.message.conversationId,
              seq: result.message.seq,
              createdAt: result.message.createdAt,
              duplicate: true,
            });
          }
        } catch (error) {
          if (error instanceof ApiError) {
            send(ws, { t: "err", code: error.code, message: error.message, clientId: clientId ?? null });
          } else {
            throw error;
          }
        }
        return;
      }

      // ----------------------------------------------------------------- typing --
      case "typing": {
        const conversationId = String(frame.conversationId ?? "");
        if (!conversationId) return;
        if (!(await store.isMember(conversationId, userId))) return;
        const state = frame.state === "stop" ? "stop" : "start";
        const members = await store.memberIds(conversationId);
        hub.sendToUsers(
          members,
          { t: "typing", conversationId, userId, state },
          { exceptUserId: userId },
        );
        return;
      }

      // ----------------------------------------------------------- read receipt --
      case "read": {
        const conversationId = String(frame.conversationId ?? "");
        const seq = Number(frame.seq ?? 0);
        if (!conversationId || !Number.isFinite(seq)) return;
        if (!(await store.isMember(conversationId, userId))) return;
        await store.updateLastRead(conversationId, userId, Math.trunc(seq));
        const members = await store.memberIds(conversationId);
        hub.sendToUsers(
          members,
          { t: "read", conversationId, userId, seq: Math.trunc(seq) },
          { exceptUserId: userId },
        );
        return;
      }

      default: {
        send(ws, { t: "err", code: "unknown_type", message: `Unknown frame type: ${frame.t}` });
      }
    }
  } catch (error) {
    fail(ws, error);
  }
}
