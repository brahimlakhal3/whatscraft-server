/**
 * REST API.
 *
 * Auth model:
 *   - `POST /v1/auth/register` / `login` return an access token (JWT HS256,
 *     short lived) plus an opaque refresh token (stored hashed, rotated on use).
 *   - Passwords are argon2id. A recovery code (argon2id hashed) allows a
 *     password reset without any email infrastructure.
 *
 * Everything else is scoped to the authenticated user. The server never
 * receives a plaintext message.
 */
import { config } from "./config.ts";
import {
  generateRecoveryCode,
  hashPassword,
  normalizeRecoveryCode,
  randomToken,
  sha256Hex,
  signAccessToken,
  verifyAccessToken,
  verifyPassword,
} from "./crypto.ts";
import { ApiError, deliverMessage, type ApiContext } from "./messages.ts";
import type { SelfUser } from "./store.ts";

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const USERNAME_RE = /^[a-z0-9][a-z0-9_.]{2,23}$/;

// ------------------------------------------------------------- HTTP plumbing --

const CORS_HEADERS: Record<string, string> = {
  "access-control-allow-origin": "*",
  "access-control-allow-headers": "authorization, content-type",
  "access-control-allow-methods": "GET, POST, PATCH, DELETE, OPTIONS",
  "access-control-max-age": "86400",
};

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...CORS_HEADERS, "content-type": "application/json; charset=utf-8" },
  });
}

function noContent(): Response {
  return new Response(null, { status: 204, headers: CORS_HEADERS });
}

async function readJson(req: Request): Promise<Record<string, any>> {
  const text = await req.text();
  if (text.length > 512 * 1024) throw new ApiError(413, "payload_too_large", "Body too large.");
  if (!text) return {};
  try {
    const parsed = JSON.parse(text);
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
      throw new Error("not an object");
    }
    return parsed as Record<string, any>;
  } catch {
    throw new ApiError(400, "invalid_json", "Request body must be a JSON object.");
  }
}

function str(
  value: unknown,
  field: string,
  options: { min?: number; max?: number; pattern?: RegExp; patternHint?: string; trim?: boolean } = {},
): string {
  if (typeof value !== "string") {
    throw new ApiError(400, "invalid_field", `${field} must be a string.`);
  }
  const result = options.trim === false ? value : value.trim();
  if (options.min !== undefined && result.length < options.min) {
    throw new ApiError(400, "invalid_field", `${field} must be at least ${options.min} characters.`);
  }
  if (options.max !== undefined && result.length > options.max) {
    throw new ApiError(400, "invalid_field", `${field} must be at most ${options.max} characters.`);
  }
  if (options.pattern && !options.pattern.test(result)) {
    throw new ApiError(400, "invalid_field", `${field} is invalid. ${options.patternHint ?? ""}`.trim());
  }
  return result;
}

function uuid(value: unknown, field: string): string {
  const result = str(value, field, { min: 36, max: 36 });
  if (!UUID_RE.test(result)) throw new ApiError(400, "invalid_field", `${field} must be a UUID.`);
  return result;
}

function int(value: unknown, field: string, options: { min?: number; max?: number } = {}): number {
  const parsed = typeof value === "number" ? value : Number(value);
  if (!Number.isFinite(parsed)) throw new ApiError(400, "invalid_field", `${field} must be a number.`);
  const rounded = Math.trunc(parsed);
  if (options.min !== undefined && rounded < options.min) {
    throw new ApiError(400, "invalid_field", `${field} must be >= ${options.min}.`);
  }
  if (options.max !== undefined && rounded > options.max) {
    throw new ApiError(400, "invalid_field", `${field} must be <= ${options.max}.`);
  }
  return rounded;
}

// --------------------------------------------------------------- rate limits --

const buckets = new Map<string, { count: number; resetAt: number }>();

function rateLimit(key: string, limit: number, windowMs = 60_000): void {
  const now = Date.now();
  const bucket = buckets.get(key);
  if (!bucket || bucket.resetAt <= now) {
    buckets.set(key, { count: 1, resetAt: now + windowMs });
    return;
  }
  bucket.count += 1;
  if (bucket.count > limit) {
    throw new ApiError(429, "rate_limited", "Too many attempts. Please wait a minute and try again.");
  }
}

/** Keeps the rate-limit map from growing forever. */
export function sweepRateLimits(): void {
  const now = Date.now();
  for (const [key, bucket] of buckets) {
    if (bucket.resetAt <= now) buckets.delete(key);
  }
}

// ---------------------------------------------------------------- auth types --

interface Auth {
  userId: string;
  deviceId: string;
  sessionId: string;
}

interface RouteContext {
  req: Request;
  params: Record<string, string>;
  auth: Auth | null;
  ctx: ApiContext;
  ip: string;
}

type Handler = (c: RouteContext) => Promise<Response>;
type Route = { method: string; segments: string[]; handler: Handler; auth: boolean };

const routes: Route[] = [];

function route(method: string, path: string, auth: boolean, handler: Handler): void {
  routes.push({ method, segments: path.split("/").filter(Boolean), handler, auth });
}

function needAuth(auth: Auth | null): Auth {
  if (!auth) throw new ApiError(401, "unauthorized", "Missing or invalid access token.");
  return auth;
}

async function authenticate(req: Request): Promise<Auth | null> {
  const header = req.headers.get("authorization") ?? "";
  if (!header.toLowerCase().startsWith("bearer ")) return null;
  const claims = await verifyAccessToken(header.slice(7).trim(), config.jwtSecret);
  if (!claims) return null;
  return { userId: claims.sub, deviceId: claims.did, sessionId: claims.sid };
}

// -------------------------------------------------------------- token issuing --

async function issueTokens(ctx: ApiContext, userId: string, deviceId: string) {
  const refreshToken = randomToken(32);
  const expiresAt = new Date(Date.now() + config.refreshTtlDays * 86_400_000);
  const sessionId = await ctx.store.createSession({
    userId,
    deviceId,
    refreshHash: sha256Hex(refreshToken),
    expiresAt,
  });
  const accessToken = await signAccessToken(
    { sub: userId, did: deviceId, sid: sessionId },
    config.jwtSecret,
    config.accessTtlSeconds,
  );
  return {
    accessToken,
    refreshToken,
    accessExpiresIn: config.accessTtlSeconds,
    refreshExpiresAt: expiresAt.toISOString(),
  };
}

function parseDevice(input: unknown) {
  const device = (input ?? {}) as Record<string, any>;
  // Device key pairs were part of the old end-to-end design. They are optional
  // now: the app only sends an id and a name, while older installs can keep
  // presenting their public keys.
  const identityKey = device.identityKey
    ? str(device.identityKey, "device.identityKey", { min: 40, max: 64 })
    : "";
  return {
    id: uuid(device.id, "device.id"),
    name: str(device.name ?? "Phone", "device.name", { min: 1, max: 40 }),
    platform: str(device.platform ?? "android", "device.platform", { min: 1, max: 20 }),
    identityKey,
    signingKey: device.signingKey
      ? str(device.signingKey, "device.signingKey", { min: 40, max: 64 })
      : null,
  };
}

function publicUser(user: SelfUser) {
  return {
    id: user.id,
    username: user.username,
    displayName: user.displayName,
    about: user.about,
    shade: user.shade,
    lastSeen: user.lastSeen,
  };
}

// --------------------------------------------------------------------- routes --

route("GET", "/v1/health", false, async ({ ctx }) =>
  json({
    ok: true,
    service: "whatscraft-relay",
    version: "1.0.0",
    connections: ctx.hub.connectionCount(),
    push: Boolean(config.fcm.projectId),
    time: new Date().toISOString(),
  }),
);

// -- registration -------------------------------------------------------------

route("POST", "/v1/auth/register", false, async ({ req, ctx, ip }) => {
  rateLimit(`register:${ip}`, config.limits.rateRegisterPerMinute);
  const body = await readJson(req);

  const username = str(body.username, "username", {
    min: 3,
    max: config.limits.maxUsernameLength,
    pattern: USERNAME_RE,
    patternHint: "Use 3-24 characters: a-z, 0-9, dot or underscore.",
  }).toLowerCase();
  const displayName = str(body.displayName || username, "displayName", {
    min: 1,
    max: config.limits.maxDisplayNameLength,
  });
  const password = str(body.password, "password", {
    min: config.limits.minPasswordLength,
    max: config.limits.maxPasswordLength,
  });
  const device = parseDevice(body.device);

  if (await ctx.store.findUserByUsername(username)) {
    throw new ApiError(409, "username_taken", "This username is already taken.");
  }

  const recoveryCode = generateRecoveryCode();
  const user = await ctx.store.createUser({
    username,
    displayName,
    passwordHash: await hashPassword(password),
    recoveryHash: await hashPassword(normalizeRecoveryCode(recoveryCode)),
    shade: Math.floor(Math.random() * 8),
  });

  await ctx.store.upsertDevice({ ...device, userId: user.id, signingKey: device.signingKey });
  const tokens = await issueTokens(ctx, user.id, device.id);

  console.log(`[auth] registered @${username} (${user.id})`);
  return json({ user: publicUser(user), device, recoveryCode, ...tokens }, 201);
});

route("POST", "/v1/auth/login", false, async ({ req, ctx, ip }) => {
  rateLimit(`login:${ip}`, config.limits.rateLoginPerMinute);
  const body = await readJson(req);
  const username = str(body.username, "username", { min: 1, max: 64 }).toLowerCase();
  const password = str(body.password, "password", { min: 1, max: config.limits.maxPasswordLength });
  const device = parseDevice(body.device);

  const user = await ctx.store.findUserByUsername(username);
  // Always run a hash comparison so timing does not reveal whether the user exists.
  const ok = user
    ? await verifyPassword(password, user.password_hash)
    : await verifyPassword(password, "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHQ$0000000000000000000000000000000000000000000");

  if (!user || !ok) {
    rateLimit(`login-fail:${ip}`, config.limits.rateLoginFailuresPerMinute);
    throw new ApiError(401, "invalid_credentials", "Incorrect username or password.");
  }

  const existing = await ctx.store.getDevice(device.id);
  if (existing && existing.userId !== user.id) {
    throw new ApiError(409, "device_taken", "This device id belongs to another account.");
  }
  if (!existing && (await ctx.store.countDevices(user.id)) >= config.limits.maxDevicesPerUser) {
    throw new ApiError(403, "too_many_devices", "Too many devices linked to this account.");
  }

  await ctx.store.upsertDevice({ ...device, userId: user.id, signingKey: device.signingKey });
  await ctx.store.touchLastSeen(user.id);
  const tokens = await issueTokens(ctx, user.id, device.id);
  return json({ user: publicUser(user), device, ...tokens });
});

route("POST", "/v1/auth/refresh", false, async ({ req, ctx }) => {
  const body = await readJson(req);
  const refreshToken = str(body.refreshToken, "refreshToken", { min: 20, max: 200 });
  const session = await ctx.store.findSessionByRefreshHash(sha256Hex(refreshToken));

  if (!session || session.revoked_at || new Date(session.expires_at).getTime() < Date.now()) {
    throw new ApiError(401, "invalid_refresh_token", "Session expired. Please sign in again.");
  }

  // Rotate: the old refresh token can never be used twice.
  await ctx.store.revokeSession(session.id);
  const user = await ctx.store.findUserById(session.user_id);
  if (!user) throw new ApiError(401, "invalid_refresh_token", "Account no longer exists.");

  const tokens = await issueTokens(ctx, user.id, session.device_id);
  return json({ user: publicUser(user), ...tokens });
});

route("POST", "/v1/auth/logout", false, async ({ req, ctx }) => {
  const body = await readJson(req);
  const refreshToken = str(body.refreshToken, "refreshToken", { min: 20, max: 200 });
  const session = await ctx.store.findSessionByRefreshHash(sha256Hex(refreshToken));
  if (session) await ctx.store.revokeSession(session.id);
  return noContent();
});

route("POST", "/v1/auth/recover", false, async ({ req, ctx, ip }) => {
  rateLimit(`recover:${ip}`, config.limits.rateRecoverPerMinute);
  const body = await readJson(req);
  const username = str(body.username, "username", { min: 1, max: 64 }).toLowerCase();
  const code = str(body.recoveryCode, "recoveryCode", { min: 10, max: 64 });
  const newPassword = str(body.newPassword, "newPassword", {
    min: config.limits.minPasswordLength,
    max: config.limits.maxPasswordLength,
  });

  const user = await ctx.store.findUserByUsername(username);
  const ok = user?.recovery_hash
    ? await verifyPassword(normalizeRecoveryCode(code), user.recovery_hash)
    : false;

  if (!user || !ok) {
    throw new ApiError(401, "invalid_recovery_code", "That recovery code does not match this account.");
  }

  await ctx.store.setPassword(user.id, await hashPassword(newPassword));
  await ctx.store.revokeAllSessions(user.id);
  console.log(`[auth] password reset via recovery code for @${user.username}`);
  return json({ ok: true, message: "Password updated. Sign in with your new password." });
});

route("POST", "/v1/auth/recovery-code", true, async ({ auth, ctx }) => {
  const me = needAuth(auth);
  const code = generateRecoveryCode();
  await ctx.store.setRecoveryHash(me.userId, await hashPassword(normalizeRecoveryCode(code)));
  return json({ recoveryCode: code });
});

// -- account ------------------------------------------------------------------

route("GET", "/v1/me", true, async ({ auth, ctx }) => {
  const me = needAuth(auth);
  const user = await ctx.store.findUserById(me.userId);
  if (!user) throw new ApiError(404, "not_found", "Account not found.");
  return json({ user: publicUser(user), settings: user.settings, devices: await ctx.store.listDevices(user.id) });
});

route("PATCH", "/v1/me", true, async ({ req, auth, ctx }) => {
  const me = needAuth(auth);
  const body = await readJson(req);
  const patch: Record<string, unknown> = {};

  if (body.displayName !== undefined) {
    patch.displayName = str(body.displayName, "displayName", {
      min: 1,
      max: config.limits.maxDisplayNameLength,
    });
  }
  if (body.about !== undefined) patch.about = str(body.about, "about", { min: 0, max: 140 });
  if (body.shade !== undefined) patch.shade = int(body.shade, "shade", { min: 0, max: 7 });
  if (body.settings !== undefined) {
    if (typeof body.settings !== "object" || body.settings === null) {
      throw new ApiError(400, "invalid_field", "settings must be an object.");
    }
    const current = await ctx.store.findUserById(me.userId);
    patch.settings = { ...(current?.settings ?? {}), ...(body.settings as Record<string, unknown>) };
  }

  const user = await ctx.store.updateUser(me.userId, patch as never);
  if (!user) throw new ApiError(404, "not_found", "Account not found.");
  return json({ user: publicUser(user), settings: user.settings });
});

route("POST", "/v1/me/password", true, async ({ req, auth, ctx }) => {
  const me = needAuth(auth);
  const body = await readJson(req);
  const currentPassword = str(body.currentPassword, "currentPassword", { min: 1, max: 200 });
  const newPassword = str(body.newPassword, "newPassword", {
    min: config.limits.minPasswordLength,
    max: config.limits.maxPasswordLength,
  });

  const currentHash = await ctx.store.getPasswordHash(me.userId);
  if (!currentHash || !(await verifyPassword(currentPassword, currentHash))) {
    throw new ApiError(401, "invalid_credentials", "Your current password is incorrect.");
  }

  await ctx.store.setPassword(me.userId, await hashPassword(newPassword));
  await ctx.store.revokeOtherSessions(me.userId, me.sessionId);
  return json({ ok: true });
});

route("GET", "/v1/me/sessions", true, async ({ auth, ctx }) => {
  const me = needAuth(auth);
  return json({ sessions: await ctx.store.listSessions(me.userId) });
});

route("DELETE", "/v1/me", true, async ({ req, auth, ctx }) => {
  const me = needAuth(auth);
  const body = await readJson(req);
  const password = str(body.password, "password", { min: 1, max: 200 });
  const hash = await ctx.store.getPasswordHash(me.userId);
  if (!hash || !(await verifyPassword(password, hash))) {
    throw new ApiError(401, "invalid_credentials", "Password is incorrect.");
  }

  for (const device of await ctx.store.listDevices(me.userId)) {
    ctx.hub.closeAllForDevice(device.id, 4003, "account_deleted");
  }
  await ctx.store.deleteUser(me.userId);
  return noContent();
});

// -- users --------------------------------------------------------------------

// Everyone on this relay, for the invitation directory. The app filters this
// list locally, so the relay only has to return the first page of accounts.
route("GET", "/v1/people", true, async ({ req, auth, ctx }) => {
  const me = needAuth(auth);
  const url = new URL(req.url);
  const q = (url.searchParams.get("q") ?? "").trim().toLowerCase().slice(0, 64);
  const people = await ctx.store.listDirectory(me.userId, q, 200);
  return json({ people });
});

route("GET", "/v1/users/:username", true, async ({ params, auth, ctx }) => {
  const me = needAuth(auth);
  const username = str(params.username, "username", { min: 1, max: 64 }).toLowerCase();
  const user = await ctx.store.findUserByUsername(username);
  if (!user) throw new ApiError(404, "not_found", "No user with that username.");

  let relationship:
    | "self"
    | "friends"
    | "pending_outgoing"
    | "pending_incoming"
    | "none" = "none";
  if (user.id === me.userId) {
    relationship = "self";
  } else if (await ctx.store.areFriends(me.userId, user.id)) {
    relationship = "friends";
  } else {
    const friendship = await ctx.store.getFriendshipBetween(me.userId, user.id);
    if (friendship && friendship.status === "pending") {
      relationship = friendship.requester_id === me.userId ? "pending_outgoing" : "pending_incoming";
    }
  }

  return json({
    user: publicUser(user),
    relationship,
    // Public keys are needed to start an encrypted conversation.
    devices:
      relationship === "self"
        ? []
        : (await ctx.store.listDevices(user.id)).map((device) => ({
            id: device.id,
            name: device.name,
            platform: device.platform,
            identityKey: device.identityKey,
            signingKey: device.signingKey,
          })),
  });
});

// -- friends ------------------------------------------------------------------

route("GET", "/v1/friends", true, async ({ auth, ctx }) => {
  const me = needAuth(auth);
  const graph = await ctx.store.listFriendGraph(me.userId);
  const withPresence = <T extends { user: { id: string } }>(items: T[]) =>
    items.map((item) => ({ ...item, online: ctx.hub.isUserOnline(item.user.id) }));

  return json({
    friends: withPresence(graph.friends),
    incoming: withPresence(graph.incoming),
    outgoing: withPresence(graph.outgoing),
  });
});

route("POST", "/v1/friends/requests", true, async ({ req, auth, ctx }) => {
  const me = needAuth(auth);
  const body = await readJson(req);
  const username = str(body.username, "username", { min: 1, max: 64 }).toLowerCase().replace(/^@/, "");

  const target = await ctx.store.findUserByUsername(username);
  if (!target) throw new ApiError(404, "not_found", "No user with that username.");
  if (target.id === me.userId) throw new ApiError(400, "self_request", "You cannot add yourself.");

  const existing = await ctx.store.getFriendshipBetween(me.userId, target.id);
  if (existing?.status === "accepted") {
    throw new ApiError(409, "already_friends", "You are already connected.");
  }

  const meUser = await ctx.store.findUserById(me.userId);
  let requestId: string;
  let acceptedImmediately = false;

  if (existing && existing.status === "pending" && existing.requester_id === target.id) {
    // Both sides asked for each other - become friends right away.
    await ctx.store.acceptFriendRequest(existing.id);
    requestId = existing.id;
    acceptedImmediately = true;
  } else {
    const created = await ctx.store.createFriendRequest(me.userId, target.id);
    requestId = created.id;
  }

  if (acceptedImmediately) {
    const conversationId = await ctx.store.getOrCreateDirect(me.userId, target.id);
    for (const viewer of [me.userId, target.id]) {
      const dto = await ctx.store.getConversationDto(viewer, conversationId);
      ctx.hub.sendToUser(viewer, { t: "conversation", conversation: dto });
    }
    ctx.hub.sendToUser(target.id, { t: "friend", kind: "accepted", user: meUser && publicUser(meUser) });
  } else {
    ctx.hub.sendToUser(target.id, {
      t: "friend",
      kind: "request",
      requestId,
      user: meUser && publicUser(meUser),
    });
  }

  return json({ requestId, accepted: acceptedImmediately }, acceptedImmediately ? 200 : 201);
});

route("POST", "/v1/friends/requests/:id/accept", true, async ({ params, auth, ctx }) => {
  const me = needAuth(auth);
  const request = await ctx.store.getFriendshipById(uuid(params.id, "id"));
  if (!request || request.addressee_id !== me.userId || request.status !== "pending") {
    throw new ApiError(404, "not_found", "No pending request with that id.");
  }

  await ctx.store.acceptFriendRequest(request.id);
  const conversationId = await ctx.store.getOrCreateDirect(request.requester_id, me.userId);
  const meUser = await ctx.store.findUserById(me.userId);

  for (const viewer of [me.userId, request.requester_id]) {
    const dto = await ctx.store.getConversationDto(viewer, conversationId);
    ctx.hub.sendToUser(viewer, { t: "conversation", conversation: dto });
  }
  ctx.hub.sendToUser(request.requester_id, {
    t: "friend",
    kind: "accepted",
    user: meUser && publicUser(meUser),
  });

  return json({ ok: true, conversationId });
});

route("POST", "/v1/friends/requests/:id/decline", true, async ({ params, auth, ctx }) => {
  const me = needAuth(auth);
  const request = await ctx.store.getFriendshipById(uuid(params.id, "id"));
  if (!request || request.addressee_id !== me.userId) {
    throw new ApiError(404, "not_found", "No request with that id.");
  }
  await ctx.store.deleteFriendship(request.id);
  return noContent();
});

route("DELETE", "/v1/friends/:userId", true, async ({ params, auth, ctx }) => {
  const me = needAuth(auth);
  const otherId = uuid(params.userId, "userId");
  if (otherId === me.userId) return noContent();

  // Removing a connection is mutual: both friendship rows go, and so does the
  // direct conversation. Neither side can write to the other until a new
  // invitation is accepted (which creates a fresh, empty conversation).
  await ctx.store.deleteFriendshipBetween(me.userId, otherId);
  const removedConversations = await ctx.store.deleteDirect(me.userId, otherId);
  for (const conversationId of removedConversations) {
    for (const viewer of [me.userId, otherId]) {
      ctx.hub.sendToUser(viewer, { t: "conversation_removed", conversationId });
    }
  }

  const meUser = await ctx.store.findUserById(me.userId);
  ctx.hub.sendToUser(otherId, { t: "friend", kind: "removed", user: meUser && publicUser(meUser) });
  return noContent();
});

// -- conversations ------------------------------------------------------------

route("GET", "/v1/conversations", true, async ({ auth, ctx }) => {
  const me = needAuth(auth);
  return json({ conversations: await ctx.store.listConversations(me.userId) });
});

route("POST", "/v1/conversations", true, async ({ req, auth, ctx }) => {
  const me = needAuth(auth);
  const body = await readJson(req);
  const peerId = uuid(body.peerId, "peerId");
  if (peerId === me.userId) throw new ApiError(400, "self_conversation", "Cannot chat with yourself.");
  if (!(await ctx.store.areFriends(me.userId, peerId))) {
    throw new ApiError(403, "not_friends", "You can only message people you are connected with.");
  }

  const conversationId = await ctx.store.getOrCreateDirect(me.userId, peerId);
  const dto = await ctx.store.getConversationDto(me.userId, conversationId);
  if (!dto) throw new ApiError(500, "conversation_failed", "Could not open conversation.");

  // Let the peer know a chat appeared (first message usually follows).
  const peerDto = await ctx.store.getConversationDto(peerId, conversationId);
  if (peerDto) ctx.hub.sendToUser(peerId, { t: "conversation", conversation: peerDto });

  return json({ conversation: dto });
});

route("POST", "/v1/conversations/group", true, async ({ req, auth, ctx }) => {
  const me = needAuth(auth);
  const body = await readJson(req);
  const title = str(body.title, "title", { min: 1, max: 60 });
  const memberIds: string[] = Array.isArray(body.memberIds)
    ? body.memberIds.map((value: unknown) => uuid(value, "memberIds[]"))
    : [];
  if (memberIds.length === 0) throw new ApiError(400, "no_members", "Add at least one member.");

  for (const memberId of memberIds) {
    if (!(await ctx.store.areFriends(me.userId, memberId))) {
      throw new ApiError(403, "not_friends", "All members must be your connections.");
    }
  }

  const conversationId = await ctx.store.createGroup(title, me.userId, memberIds);
  const dto = await ctx.store.getConversationDto(me.userId, conversationId);
  for (const memberId of memberIds) {
    const memberDto = await ctx.store.getConversationDto(memberId, conversationId);
    if (memberDto) ctx.hub.sendToUser(memberId, { t: "conversation", conversation: memberDto });
  }
  return json({ conversation: dto }, 201);
});

route("GET", "/v1/conversations/:id", true, async ({ params, auth, ctx }) => {
  const me = needAuth(auth);
  const conversationId = uuid(params.id, "id");
  const dto = await ctx.store.getConversationDto(me.userId, conversationId);
  if (!dto) throw new ApiError(404, "not_found", "Conversation not found.");
  return json({
    conversation: dto,
    members: await ctx.store.getConversationMembers(conversationId),
  });
});

route("GET", "/v1/conversations/:id/keys", true, async ({ params, auth, ctx }) => {
  const me = needAuth(auth);
  const conversationId = uuid(params.id, "id");
  if (!(await ctx.store.isMember(conversationId, me.userId))) {
    throw new ApiError(403, "not_a_member", "You are not a member of this conversation.");
  }
  const members = await ctx.store.getConversationMembers(conversationId);
  return json({
    members: members.map((member) => ({
      userId: member.user.id,
      username: member.user.username,
      displayName: member.user.displayName,
      shade: member.user.shade,
      devices: member.devices,
    })),
  });
});

route("GET", "/v1/conversations/:id/messages", true, async ({ req, params, auth, ctx }) => {
  const me = needAuth(auth);
  const conversationId = uuid(params.id, "id");
  if (!(await ctx.store.isMember(conversationId, me.userId))) {
    throw new ApiError(403, "not_a_member", "You are not a member of this conversation.");
  }
  const url = new URL(req.url);
  const before = url.searchParams.get("before");
  const limit = url.searchParams.get("limit");

  const page = await ctx.store.listMessages(conversationId, me.userId, {
    before: before ? Number(before) : undefined,
    limit: limit ? Number(limit) : undefined,
  });
  // Oldest first makes the client's list append trivial.
  return json({ messages: page.messages.reverse(), hasMore: page.hasMore });
});

route("POST", "/v1/conversations/:id/messages", true, async ({ req, params, auth, ctx }) => {
  const me = needAuth(auth);
  const conversationId = uuid(params.id, "id");
  const body = await readJson(req);

  const result = await deliverMessage(ctx, { userId: me.userId, deviceId: me.deviceId }, {
    id: uuid(body.id, "id"),
    conversationId,
    kind: body.kind,
    body: body.body,
    envelopes: Array.isArray(body.envelopes) ? body.envelopes : [],
    clientId: typeof body.clientId === "string" ? body.clientId : undefined,
  });

  return json({ message: { ...result.message, envelopes: [] }, duplicate: result.duplicate }, result.duplicate ? 200 : 201);
});

route("POST", "/v1/conversations/:id/read", true, async ({ req, params, auth, ctx }) => {
  const me = needAuth(auth);
  const conversationId = uuid(params.id, "id");
  const body = await readJson(req);
  const seq = int(body.seq, "seq", { min: 0 });
  if (!(await ctx.store.isMember(conversationId, me.userId))) {
    throw new ApiError(403, "not_a_member", "You are not a member of this conversation.");
  }
  await ctx.store.updateLastRead(conversationId, me.userId, seq);
  return json({ ok: true });
});

route("POST", "/v1/conversations/:id/mute", true, async ({ req, params, auth, ctx }) => {
  const me = needAuth(auth);
  const conversationId = uuid(params.id, "id");
  const body = await readJson(req);
  if (!(await ctx.store.isMember(conversationId, me.userId))) {
    throw new ApiError(403, "not_a_member", "You are not a member of this conversation.");
  }
  await ctx.store.setMuted(conversationId, me.userId, Boolean(body.muted));
  return json({ ok: true, muted: Boolean(body.muted) });
});

route("POST", "/v1/conversations/:id/clear", true, async ({ params, auth, ctx }) => {
  const me = needAuth(auth);
  const conversationId = uuid(params.id, "id");
  if (!(await ctx.store.isMember(conversationId, me.userId))) {
    throw new ApiError(403, "not_a_member", "You are not a member of this conversation.");
  }
  const clearedSeq = await ctx.store.clearConversation(conversationId, me.userId);
  return json({ ok: true, clearedSeq });
});

/** The "delete all messages" switch: hides history in every chat for me. */
route("POST", "/v1/messages/clear", true, async ({ auth, ctx }) => {
  const me = needAuth(auth);
  await ctx.store.clearAllConversations(me.userId);
  return json({ ok: true });
});

// -- devices ------------------------------------------------------------------

route("POST", "/v1/devices", true, async ({ req, auth, ctx }) => {
  const me = needAuth(auth);
  const body = await readJson(req);
  const device = parseDevice({ ...(body.device ?? {}), id: (body.device ?? {}).id ?? me.deviceId });
  const existing = await ctx.store.getDevice(device.id);
  if (existing && existing.userId !== me.userId) {
    throw new ApiError(409, "device_taken", "This device id belongs to another account.");
  }
  const saved = await ctx.store.upsertDevice({ ...device, userId: me.userId, signingKey: device.signingKey });
  return json({ device: saved });
});

route("POST", "/v1/devices/:id/push", true, async ({ req, params, auth, ctx }) => {
  const me = needAuth(auth);
  const deviceId = uuid(params.id, "id");
  const device = await ctx.store.getDevice(deviceId);
  if (!device || device.userId !== me.userId) {
    throw new ApiError(404, "not_found", "Device not found.");
  }
  const body = await readJson(req);
  const token = body.token === null ? null : str(body.token, "token", { min: 8, max: 4096 });
  await ctx.store.setPushToken(deviceId, token);
  return json({ ok: true });
});

route("DELETE", "/v1/devices/:id", true, async ({ params, auth, ctx }) => {
  const me = needAuth(auth);
  const deviceId = uuid(params.id, "id");
  const device = await ctx.store.getDevice(deviceId);
  if (!device || device.userId !== me.userId) {
    throw new ApiError(404, "not_found", "Device not found.");
  }
  ctx.hub.closeAllForDevice(deviceId, 4002, "device_removed");
  await ctx.store.deleteDevice(deviceId);
  return noContent();
});

// ----------------------------------------------------------------- dispatcher --

export async function handleApi(req: Request, ctx: ApiContext): Promise<Response> {
  if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: CORS_HEADERS });

  const url = new URL(req.url);
  const segments = url.pathname.split("/").filter(Boolean);
  const ip =
    req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ||
    req.headers.get("fly-client-ip") ||
    "unknown";

  try {
    for (const candidate of routes) {
      if (candidate.method !== req.method) continue;
      if (candidate.segments.length !== segments.length) continue;

      const params: Record<string, string> = {};
      let matched = true;
      for (let i = 0; i < candidate.segments.length; i++) {
        const pattern = candidate.segments[i]!;
        const value = segments[i]!;
        if (pattern.startsWith(":")) params[pattern.slice(1)] = decodeURIComponent(value);
        else if (pattern !== value) {
          matched = false;
          break;
        }
      }
      if (!matched) continue;

      const auth = await authenticate(req);
      if (candidate.auth && !auth) {
        throw new ApiError(401, "unauthorized", "Missing or invalid access token.");
      }
      if (!candidate.auth) {
        rateLimit(`api:${ip}`, config.limits.rateAnonymousPerMinute);
      } else {
        rateLimit(`api:${auth!.userId}`, config.limits.rateUserPerMinute);
      }
      return await candidate.handler({ req, params, auth, ctx, ip });
    }
    throw new ApiError(404, "not_found", `No route for ${req.method} ${url.pathname}.`);
  } catch (error) {
    if (error instanceof ApiError) {
      return json({ error: error.code, message: error.message }, error.status);
    }
    console.error("[api] unhandled error:", error);
    return json({ error: "internal_error", message: "Something went wrong." }, 500);
  }
}
