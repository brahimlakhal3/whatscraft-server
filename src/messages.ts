/**
 * Message delivery - the single code path shared by the REST fallback and the
 * WebSocket handler, so both behave identically.
 *
 * Messages are stored as plain JSON in the cloud:
 *   body = { text: "hello" }
 *
 * The legacy encrypted shape ({ alg, iv, ct, sig } + per-device envelopes) is
 * still accepted so a phone that has not updated yet can keep sending, but its
 * bodies are never shown by the current client.
 */
import { config } from "./config.ts";
import type { Store, Envelope, MessageDto } from "./store.ts";
import type { Hub } from "./hub.ts";
import { notifyNewMessage } from "./push.ts";

export class ApiError extends Error {
  constructor(
    public status: number,
    public code: string,
    message?: string,
  ) {
    super(message ?? code);
  }
}

export interface ApiContext {
  store: Store;
  hub: Hub;
}

export interface Sender {
  userId: string;
  deviceId: string;
}

export interface SendMessageInput {
  id: string;
  conversationId: string;
  kind?: string;
  body: unknown;
  envelopes?: Array<{ deviceId: string; wrappedKey: unknown }>;
  /** Echoed back in the ack so the client can match optimistic UI state. */
  clientId?: string;
}

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** The new, cloud-visible message text. Null for a legacy encrypted body. */
function plaintextOf(body: unknown): string | null {
  if (typeof body !== "object" || body === null) {
    throw new ApiError(400, "invalid_body", "Message body must be an object.");
  }
  const text = (body as Record<string, unknown>).text;
  if (typeof text !== "string") return null;
  if (text.trim().length === 0) {
    throw new ApiError(400, "empty_text", "A message cannot be empty.");
  }
  return text;
}

function assertPayloadShape(body: unknown): void {
  if (typeof body !== "object" || body === null) {
    throw new ApiError(400, "invalid_body", "Message body must be an object.");
  }
  const record = body as Record<string, unknown>;
  for (const field of ["iv", "ct"]) {
    if (typeof record[field] !== "string" || (record[field] as string).length === 0) {
      throw new ApiError(400, "invalid_body", `Message body.${field} must be a base64 string.`);
    }
  }
  if (record.sig !== undefined && typeof record.sig !== "string") {
    throw new ApiError(400, "invalid_body", "Message body.sig must be a base64 string.");
  }
}

export async function deliverMessage(
  ctx: ApiContext,
  sender: Sender,
  input: SendMessageInput,
): Promise<{ message: MessageDto; duplicate: boolean }> {
  const { store, hub } = ctx;

  if (!UUID_RE.test(input.id)) {
    throw new ApiError(400, "invalid_id", "Message id must be a UUID.");
  }
  if (!UUID_RE.test(input.conversationId)) {
    throw new ApiError(400, "invalid_conversation", "conversationId must be a UUID.");
  }
  if (!(await store.isMember(input.conversationId, sender.userId))) {
    throw new ApiError(403, "not_a_member", "You are not a member of this conversation.");
  }

  const text = plaintextOf(input.body);
  const legacy = text === null;
  if (legacy) assertPayloadShape(input.body);

  const bodyJson = JSON.stringify(input.body);
  if (bodyJson.length > config.limits.maxMessageBytes) {
    throw new ApiError(413, "message_too_large", "Message is too large.");
  }

  const envelopes = Array.isArray(input.envelopes) ? input.envelopes : [];
  if (legacy && envelopes.length === 0) {
    throw new ApiError(400, "missing_envelopes", "At least one recipient envelope is required.");
  }
  if (envelopes.length > config.limits.maxEnvelopesPerMessage) {
    throw new ApiError(400, "too_many_envelopes", "Too many recipient devices.");
  }

  // Only devices that belong to a member of this conversation may receive keys.
  const members = await store.memberIds(input.conversationId);
  const memberDevices = new Map<string, string>(); // deviceId -> userId
  if (legacy) {
    for (const memberId of members) {
      for (const device of await store.listDevices(memberId)) {
        memberDevices.set(device.id, memberId);
      }
    }
    for (const envelope of envelopes) {
      if (!UUID_RE.test(envelope.deviceId)) {
        throw new ApiError(400, "invalid_envelope", "Envelope deviceId must be a UUID.");
      }
      if (!memberDevices.has(envelope.deviceId)) {
        throw new ApiError(400, "invalid_envelope", "Envelope targets a device outside this conversation.");
      }
      if (typeof envelope.wrappedKey !== "object" || envelope.wrappedKey === null) {
        throw new ApiError(400, "invalid_envelope", "wrappedKey must be an object.");
      }
    }
  }

  const message = await store.insertMessage({
    id: input.id,
    conversationId: input.conversationId,
    senderId: sender.userId,
    senderDeviceId: sender.deviceId,
    kind: input.kind === "text" || !input.kind ? "text" : String(input.kind).slice(0, 16),
    body: input.body,
  });

  if (!message) {
    // Same message id sent twice (retry after a flaky connection): replay the
    // stored copy instead of creating a duplicate.
    const existing = await store.getMessage(input.id);
    if (!existing) throw new ApiError(500, "store_failed", "Could not store message.");
    return { message: existing, duplicate: true };
  }

  if (legacy) {
    for (const envelope of envelopes) {
      await store.insertEnvelope(
        message.id,
        memberDevices.get(envelope.deviceId)!,
        envelope.deviceId,
        envelope.wrappedKey,
      );
    }
  }

  const envelopesByUser = new Map<string, Envelope[]>();
  if (legacy) {
    for (const envelope of envelopes) {
      const ownerId = memberDevices.get(envelope.deviceId)!;
      const list = envelopesByUser.get(ownerId) ?? [];
      list.push({ deviceId: envelope.deviceId, wrappedKey: envelope.wrappedKey });
      envelopesByUser.set(ownerId, list);
    }
  }

  // Fan out: everyone except the sending device gets `msg` (also the sender's
  // own other devices). The sending device gets an `ack` with the real seq.
  for (const memberId of members) {
    if (memberId === sender.userId) {
      hub.sendToUser(
        memberId,
        {
          t: "msg",
          conversationId: message.conversationId,
          message: { ...message, envelopes: envelopesByUser.get(memberId) ?? [] },
        },
        { exceptDevice: sender.deviceId },
      );
      continue;
    }
    hub.sendToUser(memberId, {
      t: "msg",
      conversationId: message.conversationId,
      message: { ...message, envelopes: envelopesByUser.get(memberId) ?? [] },
    });
  }

  hub.sendToDevice(sender.deviceId, {
    t: "ack",
    clientId: input.clientId ?? null,
    id: message.id,
    conversationId: message.conversationId,
    seq: message.seq,
    createdAt: message.createdAt,
  });

  const recipients = members.filter((memberId) => memberId !== sender.userId);
  // Reactions are not messages a phone should buzz for.
  if (message.kind !== "reaction") {
    const senderProfile = await store.findPublicUserById(sender.userId);
    await notifyNewMessage(
      store,
      recipients,
      (userId) => hub.isUserOnline(userId),
      {
        title: senderProfile?.displayName || senderProfile?.username || "New message",
        body: "New message",
        data: { type: "message", conversationId: message.conversationId },
      },
      sender.deviceId,
    ).catch((error) => console.error("[push] failed:", error));
  }

  return { message, duplicate: false };
}
