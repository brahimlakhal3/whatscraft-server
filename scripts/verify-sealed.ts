/**
 * Opens a message sealed by the Android client with the reference
 * implementation.
 *
 * The Android unit test (app/src/test/.../MessageCipherTest.kt) writes
 * app/build/kotlin-sealed.json; this script imports the same seeds and keys into
 * WebCrypto, unwraps every envelope and checks the signature. If it prints "ok",
 * the phone and the relay agree on the wire format byte for byte.
 *
 * Run (after ./gradlew :app:testDebugUnitTest):
 *   bun run scripts/verify-sealed.ts [path/to/kotlin-sealed.json]
 */
import { resolve } from "node:path";
import { openMessage, type Identity, type OpenOptions } from "./client-crypto";

function unb64(value: string): Uint8Array {
  return new Uint8Array(Buffer.from(value, "base64"));
}

/** JWK text is base64url without padding; the relay speaks padded base64. */
function normalizeBase64(value: string): string {
  return value.replace(/-/g, "+").replace(/_/g, "/").replace(/=+$/, "");
}

/** PKCS#8 wrappers: fixed 16-byte prefix + 32-byte seed. */
const X25519_PREFIX = new Uint8Array([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20,
]);
const ED25519_PREFIX = new Uint8Array([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
]);

function wrap(prefix: Uint8Array, seedB64: string): Uint8Array {
  const seed = unb64(seedB64);
  if (seed.length !== 32) throw new Error(`expected a 32-byte seed, got ${seed.length}`);
  const der = new Uint8Array(prefix.length + seed.length);
  der.set(prefix, 0);
  der.set(seed, prefix.length);
  return der;
}

async function importIdentity(
  seedB64: string,
  signingSeedB64: string,
  expectedIdentityPublic: string,
  expectedSigningPublic: string,
): Promise<Identity> {
  const identity = (await crypto.subtle.importKey(
    "pkcs8",
    wrap(X25519_PREFIX, seedB64),
    { name: "X25519" } as never,
    true,
    ["deriveBits"],
  )) as CryptoKey;
  const signing = (await crypto.subtle.importKey(
    "pkcs8",
    wrap(ED25519_PREFIX, signingSeedB64),
    { name: "Ed25519" } as never,
    true,
    ["sign"],
  )) as CryptoKey;

  // JWK text is base64url; the relay (and every AAD) uses padded standard
  // base64, so the canonical strings from the payload are what must be used.
  const publicOf = async (key: CryptoKey): Promise<string> => {
    const jwk = (await crypto.subtle.exportKey("jwk", key)) as { x?: string };
    if (!jwk.x) throw new Error("imported key has no public part");
    return jwk.x;
  };

  const derivedIdentity = await publicOf(identity);
  const derivedSigning = await publicOf(signing);
  if (normalizeBase64(derivedIdentity) !== normalizeBase64(expectedIdentityPublic)) {
    throw new Error("the seed does not match the published identity key");
  }
  if (normalizeBase64(derivedSigning) !== normalizeBase64(expectedSigningPublic)) {
    throw new Error("the seed does not match the published signing key");
  }

  return {
    identityPrivate: identity,
    signingPrivate: signing,
    identityPublic: expectedIdentityPublic,
    signingPublic: expectedSigningPublic,
  };
}

interface Payload {
  conversationId: string;
  messageId: string;
  plaintext: string;
  sender: { deviceId: string; identityPublic: string; signingPublic: string };
  sealed: {
    body: { alg: string; iv: string; ct: string; sig: string };
    envelopes: Array<{ deviceId: string; wrappedKey: { iv: string; ct: string } }>;
  };
  recipients: Array<{
    deviceId: string;
    identityPublic: string;
    signingPublic: string;
    identitySeed: string;
    signingSeed: string;
  }>;
}

async function main() {
  const path = resolve(import.meta.dir, `../../app/build/${process.argv[2] ?? "kotlin-sealed.json"}`);
  const payload = (await Bun.file(path).json()) as Payload;

  console.log(`reading ${path}`);
  console.log(`body: ${payload.sealed.body.alg}, ${payload.sealed.envelopes.length} envelope(s)`);

  for (const recipient of payload.recipients) {
    const envelope = payload.sealed.envelopes.find((entry) => entry.deviceId === recipient.deviceId);
    if (!envelope) throw new Error(`no envelope for ${recipient.deviceId} - the sender skipped a device`);

    const identity = await importIdentity(
      recipient.identitySeed,
      recipient.signingSeed,
      recipient.identityPublic,
      recipient.signingPublic,
    );

    const options: OpenOptions = {
      identity,
      myDeviceId: recipient.deviceId,
      conversationId: payload.conversationId,
      messageId: payload.messageId,
      senderIdentityPublic: payload.sender.identityPublic,
      senderSigningPublic: payload.sender.signingPublic,
      body: payload.sealed.body,
      envelope: envelope.wrappedKey,
    };

    const opened = await openMessage(options);
    if (opened !== payload.plaintext) {
      throw new Error(`${recipient.deviceId} decrypted to the wrong plaintext`);
    }
    console.log(`ok  ${recipient.deviceId} -> ${JSON.stringify(opened)}`);
  }

  // A tampered body must not open.
  const victim = payload.recipients[0]!;
  const envelope = payload.sealed.envelopes.find((entry) => entry.deviceId === victim.deviceId)!;
  const tampered = unb64(payload.sealed.body.ct);
  tampered[0] = tampered[0]! ^ 0x01;
  const identity = await importIdentity(
    victim.identitySeed,
    victim.signingSeed,
    victim.identityPublic,
    victim.signingPublic,
  );
  let rejected = false;
  try {
    await openMessage({
      identity,
      myDeviceId: victim.deviceId,
      conversationId: payload.conversationId,
      messageId: payload.messageId,
      senderIdentityPublic: payload.sender.identityPublic,
      senderSigningPublic: payload.sender.signingPublic,
      body: { ...payload.sealed.body, ct: Buffer.from(tampered).toString("base64") },
      envelope: envelope.wrappedKey,
    });
  } catch {
    rejected = true;
  }
  if (!rejected) throw new Error("a tampered message opened - integrity check failed");

  console.log("ok  tampered message rejected");
  console.log("\nThe Android client and the reference implementation agree.");
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
