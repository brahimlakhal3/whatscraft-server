/**
 * Runtime configuration, read from environment variables.
 * See .env.example for the full list.
 */
export const config = {
  port: Number(process.env.PORT ?? 8080),

  /** Postgres URL. Empty string => embedded PGlite database (local dev). */
  databaseUrl: (process.env.DATABASE_URL ?? "").trim(),

  /** Where the embedded PGlite database lives when DATABASE_URL is unset. */
  pgliteDataDir: process.env.PGLITE_DIR ?? ".data/whatscraft",

  jwtSecret: process.env.JWT_SECRET ?? "dev-only-insecure-secret-change-me",

  /**
   * When set, POST /v1/auth/register requires a matching `registerCode`.
   * Keeps a public relay friends-only. Empty = open registration (dev).
   */
  registerCode: (process.env.REGISTER_CODE ?? "").trim(),

  accessTtlSeconds: Number(process.env.ACCESS_TTL_SECONDS ?? 900),
  refreshTtlDays: Number(process.env.REFRESH_TTL_DAYS ?? 60),

  fcm: {
    projectId: process.env.FCM_PROJECT_ID ?? "",
    clientEmail: process.env.FCM_CLIENT_EMAIL ?? "",
    privateKey: (process.env.FCM_PRIVATE_KEY ?? "").replace(/\\n/g, "\n"),
  },

  /** Hard limits that keep a friends-only relay cheap and abuse-resistant. */
  limits: {
    maxDevicesPerUser: 10,
    maxUsernameLength: 24,
    minPasswordLength: 8,
    maxPasswordLength: 200,
    maxDisplayNameLength: 40,
    maxMessageBytes: 64 * 1024,
    maxEnvelopesPerMessage: 64,

    /** Requests per minute, per IP / per account. */
    rateRegisterPerMinute: Number(process.env.RATE_LIMIT_REGISTER ?? 30),
    rateLoginPerMinute: Number(process.env.RATE_LIMIT_LOGIN ?? 30),
    rateLoginFailuresPerMinute: Number(process.env.RATE_LIMIT_LOGIN_FAIL ?? 15),
    rateRecoverPerMinute: Number(process.env.RATE_LIMIT_RECOVER ?? 15),
    rateAnonymousPerMinute: Number(process.env.RATE_LIMIT_ANON ?? 300),
    rateUserPerMinute: Number(process.env.RATE_LIMIT_USER ?? 900),
  },
} as const;

export const isProduction = process.env.NODE_ENV === "production";

if (isProduction && config.jwtSecret.includes("dev-only")) {
  console.warn(
    "[config] WARNING: JWT_SECRET is still the development default. " +
      "Run `openssl rand -base64 48` and set it as a secret before going live.",
  );
}

export const fcmEnabled = Boolean(
  config.fcm.projectId && config.fcm.clientEmail && config.fcm.privateKey,
);
