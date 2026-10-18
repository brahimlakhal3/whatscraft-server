/**
 * Reference implementation of the Whatscraft client crypto.
 *
 * The Android client implements exactly this scheme (see
 * app/src/main/java/com/brahim/whatscraft/crypto/), and this file is used by
 * scripts/smoke.ts to verify the relay end to end with real crypto.
 *
 * Scheme ("sealed sender keys", v1)
 * -------------------------------------------------------------------------
 *  Every install generates two key pairs:
 *    - X25519  identity key  -> key agreement
 *    - Ed25519 signing key   -> authenticity of message content
 *
 *  To send one message:
 *    1. MK = 32 random bytes (message key), IV = 12 random bytes.
 *    2. ct = AES-256-GCM(MK, IV, plaintext, aad = "whatscraft/v1/msg|conv|msg")
 *       sig = Ed25519(sign, "whatscraft/v1/msg|conv|msg|iv|ct|signingPub")
 *    3. For every recipient device:
 *         shared = X25519(myIdentityPriv, deviceIdentityPub)
 *         salt   = SHA-256(myIdentityPub || deviceIdentityPub)
 *         KEK    = HKDF-SHA256(ikm=shared, salt=salt, info="whatscraft/v1/kek", 32)
 *         wrap   = AES-256-GCM(KEK, wiv, MK,
 *                       aad = "whatscraft/v1/wrap|conv|msg|deviceId")
 *    4. The relay stores { iv, ct, sig } plus one wrap per device. It has no
 *       private keys, so it can never read or forge a message.
 */

const encoder = new TextEncoder();

function b64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64");
}

function unb64(value: string): Uint8Array {
  return new Uint8Array(Buffer.from(value, "base64"));
}

export interface Identity {
  /** base64 raw X25519 public key */
  identityPublic: string;
  /** base64 raw Ed25519 public key */
  signingPublic: string;
  identityPrivate: CryptoKey;
  signingPrivate: CryptoKey;
}

export async function generateIdentity(): Promise<Identity> {
  const identity = (await crypto.subtle.generateKey({ name: "X25519" } as never, true, [
    "deriveBits",
  ])) as CryptoKeyPair;
  const signing = (await crypto.subtle.generateKey({ name: "Ed25519" } as never, true, [
    "sign",
    "verify",
  ])) as CryptoKeyPair;

  return {
    identityPublic: b64(new Uint8Array(await crypto.subtle.exportKey("raw", identity.publicKey))),
    signingPublic: b64(new Uint8Array(await crypto.subtle.exportKey("raw", signing.publicKey))),
    identityPrivate: identity.privateKey,
    signingPrivate: signing.privateKey,
  };
}

async function importIdentityPublic(base64: string): Promise<CryptoKey> {
  return crypto.subtle.importKey("raw", unb64(base64), { name: "X25519" } as never, false, []);
}

async function importSigningPublic(base64: string): Promise<CryptoKey> {
  return crypto.subtle.importKey("raw", unb64(base64), { name: "Ed25519" } as never, false, [
    "verify",
  ]);
}

/**
 * KEK = HKDF-SHA256(X25519(myPriv, peerPub), salt = SHA256(senderPub|recipientPub)).
 *
 * The salt is always built in (sender, recipient) order, so both sides derive
 * the same key regardless of who computes it. `senderPublic`/`recipientPublic`
 * are *not* derived from the ordering of my own key - they are passed in.
 */
async function deriveKek(
  myIdentityPrivate: CryptoKey,
  peerIdentityPublic: string,
  senderPublic: string,
  recipientPublic: string,
): Promise<CryptoKey> {
  const shared = await crypto.subtle.deriveBits(
    { name: "X25519", public: await importIdentityPublic(peerIdentityPublic) } as never,
    myIdentityPrivate,
    256,
  );
  const salt = new Uint8Array(
    await crypto.subtle.digest("SHA-256", encoder.encode(`${senderPublic}|${recipientPublic}`)),
  );
  const hkdfKey = await crypto.subtle.importKey("raw", new Uint8Array(shared), "HKDF", false, [
    "deriveBits",
  ]);
  const kekBytes = await crypto.subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt, info: encoder.encode("whatscraft/v1/kek") },
    hkdfKey,
    256,
  );
  return crypto.subtle.importKey("raw", kekBytes, { name: "AES-GCM" }, false, [
    "encrypt",
    "decrypt",
  ]);
}

export interface RecipientDevice {
  deviceId: string;
  identityPublic: string;
}

export interface SealedMessage {
  body: { alg: string; iv: string; ct: string; sig: string };
  envelopes: Array<{ deviceId: string; wrappedKey: { iv: string; ct: string } }>;
}

function messageAad(conversationId: string, messageId: string): Uint8Array {
  return encoder.encode(`whatscraft/v1/msg|${conversationId}|${messageId}`);
}

/** Encrypts `plaintext` for every device listed in `devices`. */
export async function sealMessage(
  identity: Identity,
  conversationId: string,
  messageId: string,
  plaintext: string,
  devices: RecipientDevice[],
): Promise<SealedMessage> {
  // 1. Random message key + content encryption.
  const messageKey = crypto.getRandomValues(new Uint8Array(32));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const contentKey = await crypto.subtle.importKey("raw", messageKey, { name: "AES-GCM" }, false, [
    "encrypt",
  ]);
  const ct = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-GCM", iv, additionalData: messageAad(conversationId, messageId) },
      contentKey,
      encoder.encode(plaintext),
    ),
  );

  // 2. Signature over the content and the claimed sender key (TOFU verified).
  const signatureInput = `whatscraft/v1/msg|${conversationId}|${messageId}|${b64(iv)}|${b64(ct)}|${identity.signingPublic}`;
  const signature = new Uint8Array(
    await crypto.subtle.sign({ name: "Ed25519" } as never, identity.signingPrivate, encoder.encode(signatureInput)),
  );

  // 3. One wrapped copy of the message key per recipient device.
  const envelopes: SealedMessage["envelopes"] = [];
  for (const device of devices) {
    const kek = await deriveKek(
      identity.identityPrivate,
      device.identityPublic,
      identity.identityPublic,
      device.identityPublic,
    );
    const wrapIv = crypto.getRandomValues(new Uint8Array(12));
    const wrapped = new Uint8Array(
      await crypto.subtle.encrypt(
        {
          name: "AES-GCM",
          iv: wrapIv,
          additionalData: encoder.encode(
            `whatscraft/v1/wrap|${conversationId}|${messageId}|${device.deviceId}`,
          ),
        },
        kek,
        messageKey,
      ),
    );
    envelopes.push({
      deviceId: device.deviceId,
      wrappedKey: { iv: b64(wrapIv), ct: b64(wrapped) },
    });
  }

  return {
    body: { alg: "A256GCM", iv: b64(iv), ct: b64(ct), sig: b64(signature) },
    envelopes,
  };
}

export interface OpenOptions {
  identity: Identity;
  myDeviceId: string;
  conversationId: string;
  messageId: string;
  /** Claimed sender identity, from the sender's device record. */
  senderIdentityPublic: string;
  /** Claimed sender signing key, from the sender's device record. */
  senderSigningPublic: string;
  body: { iv: string; ct: string; sig: string };
  envelope: { iv: string; ct: string };
}

/** Verifies the signature, unwraps the key and decrypts. Throws on tampering. */
export async function openMessage(options: OpenOptions): Promise<string> {
  const { identity, body, envelope } = options;

  // 1. Unwrap the message key with our own identity key.
  const kek = await deriveKek(
    identity.identityPrivate,
    options.senderIdentityPublic,
    options.senderIdentityPublic,
    identity.identityPublic,
  );
  const messageKey = await crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: unb64(envelope.iv),
      additionalData: encoder.encode(
        `whatscraft/v1/wrap|${options.conversationId}|${options.messageId}|${options.myDeviceId}`,
      ),
    },
    kek,
    unb64(envelope.ct),
  );

  // 2. Decrypt the content.
  const contentKey = await crypto.subtle.importKey("raw", messageKey, { name: "AES-GCM" }, false, [
    "decrypt",
  ]);
  const plaintext = await crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: unb64(body.iv),
      additionalData: messageAad(options.conversationId, options.messageId),
    },
    contentKey,
    unb64(body.ct),
  );

  // 3. Check the sender's signature before trusting the content.
  const signatureInput = `whatscraft/v1/msg|${options.conversationId}|${options.messageId}|${body.iv}|${body.ct}|${options.senderSigningPublic}`;
  const valid = await crypto.subtle.verify(
    { name: "Ed25519" } as never,
    await importSigningPublic(options.senderSigningPublic),
    unb64(body.sig),
    encoder.encode(signatureInput),
  );
  if (!valid) throw new Error("Message signature is invalid (possible tampering).");

  return new TextDecoder().decode(plaintext);
}

/**
 * Sixty-digit human-comparable fingerprint of two identities ("safety number").
 *
 * Must stay byte-for-byte identical to `MessageCipher.safetyNumber` on the
 * clients: both sides sort the two base64 identity keys, hash
 * `"a|b"` with SHA-512, and take the low digit of each of the first 60 bytes.
 */
export async function safetyNumber(a: Identity, b: Identity): Promise<string> {
  const parts = [a.identityPublic, b.identityPublic].sort();
  const digest = new Uint8Array(
    await crypto.subtle.digest("SHA-512", encoder.encode(`${parts[0]}|${parts[1]}`)),
  );
  let digits = "";
  for (let index = 0; index < 60; index += 1) digits += (digest[index] % 10).toString();
  return digits.match(/.{1,5}/g)!.join(" ");
}
