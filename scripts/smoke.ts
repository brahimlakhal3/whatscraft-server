/**
 * End-to-end smoke test against a running relay.
 *
 *   bun run src/index.ts        # terminal 1
 *   bun run scripts/smoke.ts    # terminal 2
 *
 * It registers two accounts (one with two devices), connects real WebSockets,
 * encrypts with the real X25519/AES-256-GCM scheme and verifies decryption,
 * signatures, typing, receipts, history, dedup and account recovery.
 */
import {
  generateIdentity,
  openMessage,
  safetyNumber,
  sealMessage,
  type Identity,
  type RecipientDevice,
} from "./client-crypto.ts";

const BASE = (process.env.BASE_URL ?? "http://127.0.0.1:8080").replace(/\/$/, "");
const WS_URL = `${BASE.replace(/^http/, "ws")}/ws`;

// When the server sets REGISTER_CODE, new accounts must present it.
const REGISTER_CODE = (process.env.REGISTER_CODE ?? "").trim();
const gate = REGISTER_CODE ? { registerCode: REGISTER_CODE } : {};

let passed = 0;
let failed = 0;

function check(name: string, condition: boolean, detail?: unknown): void {
  if (condition) {
    passed++;
    console.log(`  \u001b[32m✓\u001b[0m ${name}`);
  } else {
    failed++;
    console.log(`  \u001b[31m✗\u001b[0m ${name}${detail !== undefined ? ` -> ${JSON.stringify(detail)}` : ""}`);
  }
}

function section(title: string): void {
  console.log(`\n\u001b[1m${title}\u001b[0m`);
}

// ------------------------------------------------------------------- helpers --

async function api(
  path: string,
  options: { method?: string; body?: unknown; token?: string } = {},
): Promise<{ status: number; data: any }> {
  const response = await fetch(BASE + path, {
    method: options.method ?? "GET",
    headers: {
      ...(options.body !== undefined ? { "content-type": "application/json" } : {}),
      ...(options.token ? { authorization: `Bearer ${options.token}` } : {}),
    },
    body: options.body !== undefined ? JSON.stringify(options.body) : undefined,
  });
  const text = await response.text();
  return { status: response.status, data: text ? JSON.parse(text) : null };
}

async function ok(path: string, options: Parameters<typeof api>[1] = {}): Promise<any> {
  const result = await api(path, options);
  if (result.status >= 400) {
    throw new Error(`${options.method ?? "GET"} ${path} -> ${result.status} ${JSON.stringify(result.data)}`);
  }
  return result.data;
}

/** Minimal WebSocket client with a frame queue and awaitable matchers. */
class TestClient {
  ws!: WebSocket;
  private queue: any[] = [];
  private waiters: Array<{
    match: (frame: any) => boolean;
    resolve: (frame: any) => void;
    timer: ReturnType<typeof setTimeout>;
  }> = [];

  constructor(readonly name: string) {}

  async connect(): Promise<any> {
    this.ws = new WebSocket(WS_URL);
    this.ws.addEventListener("message", (event) => {
      this.dispatch(JSON.parse(String((event as MessageEvent).data)));
    });
    await new Promise<void>((resolve, reject) => {
      this.ws.addEventListener("open", () => resolve());
      this.ws.addEventListener("error", () => reject(new Error(`${this.name}: socket error`)));
    });
  }

  private dispatch(frame: any): void {
    for (let i = 0; i < this.waiters.length; i++) {
      const waiter = this.waiters[i]!;
      if (waiter.match(frame)) {
        this.waiters.splice(i, 1);
        clearTimeout(waiter.timer);
        waiter.resolve(frame);
        return;
      }
    }
    this.queue.push(frame);
  }

  expect(match: (frame: any) => boolean, timeoutMs = 6000): Promise<any> {
    const index = this.queue.findIndex(match);
    if (index >= 0) return Promise.resolve(this.queue.splice(index, 1)[0]);
    return new Promise((resolve, reject) => {
      const timer = setTimeout(
        () => reject(new Error(`${this.name}: timed out waiting for a frame`)),
        timeoutMs,
      );
      this.waiters.push({ match, resolve, timer });
    });
  }

  ofType(type: string, timeoutMs = 6000): Promise<any> {
    return this.expect((frame) => frame.t === type, timeoutMs);
  }

  send(frame: unknown): void {
    this.ws.send(JSON.stringify(frame));
  }

  async handshake(token: string): Promise<any> {
    this.send({ t: "auth", token });
    const ready = await this.ofType("ready");
    return ready;
  }

  close(): void {
    try {
      this.ws.close();
    } catch {
      /* ignore */
    }
  }
}

function makeDevice(identity: Identity) {
  return {
    id: crypto.randomUUID(),
    name: "Test device",
    platform: "android",
    identityKey: identity.identityPublic,
    signingKey: identity.signingPublic,
  };
}

async function registerUser(identity: Identity, username: string, displayName: string) {
  const device = makeDevice(identity);
  const data = await ok("/v1/auth/register", {
    method: "POST",
    body: { username, displayName, password: "correct horse battery", device, ...gate },
  });
  return { ...data, username, device, identity };
}

function toRecipients(devices: Array<{ id: string; identityKey: string }>): RecipientDevice[] {
  return devices.map((device) => ({ deviceId: device.id, identityPublic: device.identityKey }));
}

// ---------------------------------------------------------------------- main --

const suffix = Math.random().toString(36).slice(2, 8);
const password = "correct horse battery";

const aliceIdentity = await generateIdentity();
const bobIdentity = await generateIdentity();
const carolIdentity = await generateIdentity();

section("1. Accounts");
const alice = await registerUser(aliceIdentity, `alice${suffix}`, "Alice");
const bob = await registerUser(bobIdentity, `bob${suffix}`, "Bob");
check("alice registered with an access token", Boolean(alice.accessToken));
check("registration returns a recovery code once", /^[A-Z0-9]{5}(-[A-Z0-9]{5}){3}$/.test(alice.recoveryCode ?? ""), alice.recoveryCode);

const weak = await api("/v1/auth/register", {
  method: "POST",
  body: {
    username: `weak${suffix}`,
    displayName: "Weak",
    password: "short",
    device: makeDevice(await generateIdentity()),
    ...gate,
  },
});
check("short passwords are rejected", weak.status === 400, weak.data);

const dupe = await api("/v1/auth/register", {
  method: "POST",
  body: {
    username: alice.username,
    displayName: "Impostor",
    password,
    device: makeDevice(await generateIdentity()),
    ...gate,
  },
});
check("duplicate usernames are rejected", dupe.status === 409, dupe.data);

const badLogin = await api("/v1/auth/login", {
  method: "POST",
  body: { username: alice.username, password: "wrong password", device: alice.device },
});
check("wrong password is rejected", badLogin.status === 401, badLogin.data);

section("2. Safety number");
const aliceSafety = await safetyNumber(alice.identity, bob.identity);
const bobSafety = await safetyNumber(bob.identity, alice.identity);
check("safety numbers match on both sides", aliceSafety === bobSafety, aliceSafety);

section("3. Friends");
await ok("/v1/friends/requests", {
  method: "POST",
  token: alice.accessToken,
  body: { username: bob.username },
});
const bobFriends = await ok("/v1/friends", { token: bob.accessToken });
check("bob sees one incoming request", bobFriends.incoming.length === 1, bobFriends.incoming.length);
check("request carries alice's profile", bobFriends.incoming[0]?.user?.username === alice.username);

const accepted = await ok(`/v1/friends/requests/${bobFriends.incoming[0].id}/accept`, {
  method: "POST",
  token: bob.accessToken,
});
check("accepting returns a direct conversation", Boolean(accepted.conversationId));

const aliceConversations = await ok("/v1/conversations", { token: alice.accessToken });
check("alice now has one conversation", aliceConversations.conversations.length === 1);
const conversationId = aliceConversations.conversations[0].id as string;

section("4. Second device for bob");
const bobSecondIdentity = await generateIdentity();
const bobSecondDevice = makeDevice(bobSecondIdentity);
const bobSecondLogin = await ok("/v1/auth/login", {
  method: "POST",
  body: { username: bob.username, password, device: bobSecondDevice },
});
check("bob can sign in on a second device", Boolean(bobSecondLogin.accessToken));

section("5. Directory / device keys");
const keys = await ok(`/v1/conversations/${conversationId}/keys`, { token: alice.accessToken });
const aliceMember = keys.members.find((m: any) => m.userId === alice.user.id);
const bobMember = keys.members.find((m: any) => m.userId === bob.user.id);
check("conversation exposes both members", Boolean(aliceMember && bobMember));
check("bob has two devices with identity keys", bobMember.devices.length === 2,
  bobMember.devices.map((d: any) => d.id));

const aliceDevices = toRecipients(aliceMember.devices);
const bobDevices = toRecipients(bobMember.devices);
const allDevices = [...aliceDevices, ...bobDevices];

section("6. Realtime");
const aliceClient = new TestClient("alice");
const bobClient = new TestClient("bob");
const bobSecondClient = new TestClient("bob-2");
await aliceClient.connect();
await bobClient.connect();
await bobSecondClient.connect();

const aliceReady = await aliceClient.handshake(alice.accessToken);
check("server sends ready frame with user", aliceReady.user?.username === alice.username);
await bobClient.handshake(bob.accessToken);
await bobSecondClient.handshake(bobSecondLogin.accessToken);

const presence = await aliceClient.ofType("presence");
check("alice is told bob came online", presence.userId === bob.user.id && presence.online === true, presence);

const unauth = new TestClient("unauth");
await unauth.connect();
unauth.send({ t: "send", id: crypto.randomUUID(), conversationId, body: {}, envelopes: [] });
const authError = await unauth.ofType("err");
check("unauthenticated sockets cannot send", authError.code === "auth_required", authError);
unauth.close();

section("7. Encrypted message, one device -> three devices");
const firstMessageId = crypto.randomUUID();
const firstPlaintext = "Salut Bob! 🔒 This text never leaves the phone unencrypted.";
const sealed = await sealMessage(alice.identity, conversationId, firstMessageId, firstPlaintext, allDevices);
aliceClient.send({
  t: "send",
  id: firstMessageId,
  clientId: "local-1",
  conversationId,
  kind: "text",
  body: sealed.body,
  envelopes: sealed.envelopes,
});

const ack = await aliceClient.ofType("ack");
check("sender gets an ack with a server sequence", Number(ack.seq) > 0 && ack.clientId === "local-1", ack);

for (const [label, client, identity, deviceId] of [
  ["bob's phone", bobClient, bob.identity, bob.device.id],
  ["bob's second device", bobSecondClient, bobSecondIdentity, bobSecondDevice.id],
] as const) {
  const frame = await client.expect((f) => f.t === "msg" && f.message?.id === firstMessageId);
  const envelope = frame.message.envelopes.find((e: any) => e.deviceId === deviceId);
  check(`${label} received an envelope for itself`, Boolean(envelope));
  const plaintext = await openMessage({
    identity: identity as Identity,
    myDeviceId: deviceId,
    conversationId,
    messageId: firstMessageId,
    senderIdentityPublic: aliceIdentity.identityPublic,
    senderSigningPublic: aliceIdentity.signingPublic,
    body: frame.message.body,
    envelope: envelope.wrappedKey,
  });
  check(`${label} decrypted the message`, plaintext === firstPlaintext, plaintext);
}

section("8. Tamper detection");
const tampered = await openMessage({
  identity: bob.identity,
  myDeviceId: bob.device.id,
  conversationId,
  messageId: firstMessageId,
  senderIdentityPublic: aliceIdentity.identityPublic,
  senderSigningPublic: aliceIdentity.signingPublic,
  body: { ...sealed.body, ct: Buffer.from("not the real ciphertext").toString("base64") },
  envelope: sealed.envelopes.find((e) => e.deviceId === bob.device.id)!.wrappedKey,
}).then(() => "decrypted").catch((error: Error) => error.message);
check("a modified ciphertext is rejected", tampered !== "decrypted", tampered);

section("9. Reply and read receipts");
const replyId = crypto.randomUUID();
const replyText = "Reçu 5/5 ✅";
const replySealed = await sealMessage(bob.identity, conversationId, replyId, replyText, allDevices);
bobClient.send({ t: "send", id: replyId, clientId: "local-2", conversationId, kind: "text", body: replySealed.body, envelopes: replySealed.envelopes });
const replyAck = await bobClient.ofType("ack");
check("bob's reply is acked", Number(replyAck.seq) > Number(ack.seq));

const incomingForAlice = await aliceClient.expect((f) => f.t === "msg" && f.message?.id === replyId);
const aliceEnvelope = incomingForAlice.message.envelopes.find((e: any) => e.deviceId === alice.device.id);
const decryptedReply = await openMessage({
  identity: alice.identity,
  myDeviceId: alice.device.id,
  conversationId,
  messageId: replyId,
  senderIdentityPublic: bobIdentity.identityPublic,
  senderSigningPublic: bobIdentity.signingPublic,
  body: incomingForAlice.message.body,
  envelope: aliceEnvelope.wrappedKey,
});
check("alice decrypted bob's reply", decryptedReply === replyText, decryptedReply);

bobClient.send({ t: "typing", conversationId, state: "start" });
const typing = await aliceClient.ofType("typing");
check("typing indicator arrives", typing.userId === bob.user.id && typing.state === "start", typing);

bobClient.send({ t: "read", conversationId, seq: Number(replyAck.seq) });
const read = await aliceClient.ofType("read");
check("read receipt arrives", read.userId === bob.user.id && Number(read.seq) === Number(replyAck.seq), read);

section("10. History");
const history = await ok(`/v1/conversations/${conversationId}/messages?limit=50`, { token: bobSecondLogin.accessToken });
check("history contains both messages", history.messages.length === 2, history.messages.length);
const firstFromHistory = history.messages.find((m: any) => m.id === firstMessageId);
const historyEnvelope = firstFromHistory.envelopes.find((e: any) => e.deviceId === bobSecondDevice.id);
const historyPlaintext = await openMessage({
  identity: bobSecondIdentity,
  myDeviceId: bobSecondDevice.id,
  conversationId,
  messageId: firstMessageId,
  senderIdentityPublic: aliceIdentity.identityPublic,
  senderSigningPublic: aliceIdentity.signingPublic,
  body: firstFromHistory.body,
  envelope: historyEnvelope.wrappedKey,
});
check("server-stored ciphertext decrypts on a fresh device", historyPlaintext === firstPlaintext);
check("messages are ordered oldest first", history.messages[0].seq < history.messages[1].seq);

section("11. Idempotency and authorisation");
aliceClient.send({ t: "send", id: firstMessageId, clientId: "retry", conversationId, kind: "text", body: sealed.body, envelopes: sealed.envelopes });
const duplicateAck = await aliceClient.expect((f) => f.t === "ack" && f.clientId === "retry");
check("re-sending the same id is deduplicated", duplicateAck.id === firstMessageId, duplicateAck);

const carol = await registerUser(carolIdentity, `carol${suffix}`, "Carol");
const outsider = await api(`/v1/conversations/${conversationId}/messages`, {
  method: "POST",
  token: carol.accessToken,
  body: { id: crypto.randomUUID(), kind: "text", body: sealed.body, envelopes: sealed.envelopes },
});
check("outsiders cannot post into a conversation", outsider.status === 403, outsider.data);

const readOutsider = await api(`/v1/conversations/${conversationId}/messages`, { token: carol.accessToken });
check("outsiders cannot read history", readOutsider.status === 403, readOutsider.data);

const unauthorisedEnvelope = await api(`/v1/conversations/${conversationId}/messages`, {
  method: "POST",
  token: alice.accessToken,
  body: {
    id: crypto.randomUUID(),
    kind: "text",
    body: sealed.body,
    envelopes: [{ deviceId: carol.device.id, wrappedKey: { iv: "AAAA", ct: "AAAA" } }],
  },
});
check("envelopes for foreign devices are refused", unauthorisedEnvelope.status === 400, unauthorisedEnvelope.data);

section("12. Profile and settings");
const patched = await ok("/v1/me", {
  method: "PATCH",
  token: alice.accessToken,
  body: { displayName: "Alice 🌙", settings: { readReceipts: true, theme: "black" } },
});
check("display name updated", patched.user.displayName === "Alice 🌙", patched.user);
const patchedAgain = await ok("/v1/me", {
  method: "PATCH",
  token: alice.accessToken,
  body: { settings: { enterToSend: true } },
});
check(
  "settings merge instead of replacing",
  patchedAgain.settings.readReceipts === true && patchedAgain.settings.enterToSend === true,
  patchedAgain.settings,
);

section("13. Password reset with the recovery code");
const wrongRecovery = await api("/v1/auth/recover", {
  method: "POST",
  body: { username: bob.username, recoveryCode: "AAAAA-BBBBB-CCCCC-DDDDD", newPassword: "a brand new password" },
});
check("a wrong recovery code is rejected", wrongRecovery.status === 401, wrongRecovery.data);

const recovered = await ok("/v1/auth/recover", {
  method: "POST",
  body: { username: bob.username, recoveryCode: bob.recoveryCode, newPassword: "a brand new password" },
});
check("recovery code resets the password", recovered.ok === true);

const oldRefresh = await api("/v1/auth/refresh", {
  method: "POST",
  body: { refreshToken: bob.refreshToken },
});
check("old sessions are revoked after a reset", oldRefresh.status === 401, oldRefresh.data);

const newLogin = await ok("/v1/auth/login", {
  method: "POST",
  body: { username: bob.username, password: "a brand new password", device: bob.device },
});
check("bob can sign in with the new password", Boolean(newLogin.accessToken));

section("14. Recovery code rotation");
const rotated = await ok("/v1/auth/recovery-code", { method: "POST", token: newLogin.accessToken });
check("a fresh recovery code can be generated", /^[A-Z0-9]{5}(-[A-Z0-9]{5}){3}$/.test(rotated.recoveryCode), rotated.recoveryCode);

section("15. Unread counters");
await ok(`/v1/conversations/${conversationId}/read`, {
  method: "POST",
  token: newLogin.accessToken,
  body: { seq: Number(replyAck.seq) },
});
const bobConversations = await ok("/v1/conversations", { token: newLogin.accessToken });
check("unread count resets after reading", bobConversations.conversations[0].unread === 0,
  bobConversations.conversations[0].unread);

// ------------------------------------------------------------------- teardown --
aliceClient.close();
bobClient.close();
bobSecondClient.close();

console.log(
  `\n\u001b[1mResult\u001b[0m: ${passed} passed, ${failed} failed ` +
    `(${failed === 0 ? "\u001b[32mall good\u001b[0m" : "\u001b[31mfailures above\u001b[0m"})`,
);
process.exit(failed === 0 ? 0 : 1);
