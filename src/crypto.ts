/**
 * Server-side crypto helpers.
 *
 * The server never sees plaintext or private keys. It only:
 *   - hashes passwords with argon2id,
 *   - signs short-lived access tokens (HS256 JWT),
 *   - stores opaque refresh tokens (hashed) and recovery codes (hashed).
 */

const encoder = new TextEncoder();

export function base64Url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64url");
}

export function fromBase64Url(value: string): Uint8Array {
  return new Uint8Array(Buffer.from(value, "base64url"));
}

// ---------------------------------------------------------------- passwords --

const ARGON2_OPTIONS = {
  algorithm: "argon2id" as const,
  memoryCost: 19_456, // 19 MiB - OWASP minimum for argon2id
  timeCost: 2,
  outputLen: 32,
};

export async function hashPassword(password: string): Promise<string> {
  return Bun.password.hash(password, ARGON2_OPTIONS);
}

export async function verifyPassword(password: string, hash: string): Promise<boolean> {
  try {
    return await Bun.password.verify(password, hash);
  } catch {
    return false;
  }
}

// ------------------------------------------------------------------ tokens --

export function randomToken(bytes = 32): string {
  return base64Url(crypto.getRandomValues(new Uint8Array(bytes)));
}

export function sha256Hex(input: string): string {
  return new Bun.CryptoHasher("sha256").update(input).digest("hex");
}

// ---------------------------------------------------------- recovery codes --

/** Unambiguous alphabet: no I/O/0/1. Exactly 32 symbols => no modulo bias. */
const RECOVERY_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

/** e.g. `K7M2P-9QXR4-BVTZ8-FH3W6` (100 bits of entropy). */
export function generateRecoveryCode(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(20));
  let out = "";
  for (let i = 0; i < bytes.length; i++) {
    out += RECOVERY_ALPHABET[bytes[i]! % RECOVERY_ALPHABET.length];
    if (i % 5 === 4 && i !== bytes.length - 1) out += "-";
  }
  return out;
}

/** Case- and separator-insensitive form used for hashing/lookup. */
export function normalizeRecoveryCode(code: string): string {
  return code.toUpperCase().replace(/[^A-Z0-9]/g, "");
}

// --------------------------------------------------------------------- JWT --

let cachedKey: { secret: string; key: CryptoKey } | null = null;

async function hmacKey(secret: string): Promise<CryptoKey> {
  if (cachedKey?.secret === secret) return cachedKey.key;
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"],
  );
  cachedKey = { secret, key };
  return key;
}

export interface AccessClaims {
  /** user id */
  sub: string;
  /** device id */
  did: string;
  /** session id */
  sid: string;
  iat?: number;
  exp?: number;
}

export async function signAccessToken(
  claims: Omit<AccessClaims, "iat" | "exp">,
  secret: string,
  ttlSeconds: number,
): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const header = base64Url(encoder.encode(JSON.stringify({ alg: "HS256", typ: "JWT" })));
  const payload = base64Url(
    encoder.encode(JSON.stringify({ ...claims, iat: now, exp: now + ttlSeconds })),
  );
  const signingInput = `${header}.${payload}`;
  const signature = await crypto.subtle.sign("HMAC", await hmacKey(secret), encoder.encode(signingInput));
  return `${signingInput}.${base64Url(new Uint8Array(signature))}`;
}

export async function verifyAccessToken(token: string, secret: string): Promise<AccessClaims | null> {
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  const [header, payload, signature] = parts as [string, string, string];

  const valid = await crypto.subtle.verify(
    "HMAC",
    await hmacKey(secret),
    fromBase64Url(signature),
    encoder.encode(`${header}.${payload}`),
  );
  if (!valid) return null;

  try {
    const claims = JSON.parse(Buffer.from(payload, "base64url").toString()) as AccessClaims;
    if (!claims.exp || claims.exp * 1000 < Date.now()) return null;
    return claims;
  } catch {
    return null;
  }
}
