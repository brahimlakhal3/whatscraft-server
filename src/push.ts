/**
 * Firebase Cloud Messaging (HTTP v1) push, used only to *wake up* a device that
 * has no live WebSocket. Payloads carry a generic title and no message text: the
 * app loads the conversation from the relay when it opens.
 *
 * Entirely optional - if FCM_* is not configured every function degrades to a
 * no-op and background delivery relies on the app's foreground service.
 */
import { config, fcmEnabled } from "./config.ts";
import type { Store } from "./store.ts";

type PushPayload = {
  title: string;
  body: string;
  data?: Record<string, string>;
};

let cachedToken: { value: string; expiresAt: number } | null = null;

function pemToArrayBuffer(pem: string): ArrayBuffer {
  const base64 = pem
    .replace(/-----BEGIN [^-]+-----/, "")
    .replace(/-----END [^-]+-----/, "")
    .replace(/\s+/g, "");
  const binary = Buffer.from(base64, "base64");
  return binary.buffer.slice(binary.byteOffset, binary.byteOffset + binary.byteLength) as ArrayBuffer;
}

function base64Url(input: string | ArrayBuffer): string {
  return Buffer.from(input as never).toString("base64url");
}

async function getAccessToken(): Promise<string | null> {
  if (!fcmEnabled) return null;
  if (cachedToken && cachedToken.expiresAt > Date.now() + 60_000) return cachedToken.value;

  const now = Math.floor(Date.now() / 1000);
  const header = base64Url(JSON.stringify({ alg: "RS256", typ: "JWT" }));
  const claims = base64Url(
    JSON.stringify({
      iss: config.fcm.clientEmail,
      scope: "https://www.googleapis.com/auth/firebase.messaging",
      aud: "https://oauth2.googleapis.com/token",
      iat: now,
      exp: now + 3600,
    }),
  );
  const signingInput = `${header}.${claims}`;

  try {
    const key = await crypto.subtle.importKey(
      "pkcs8",
      pemToArrayBuffer(config.fcm.privateKey),
      { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
      false,
      ["sign"],
    );
    const signature = await crypto.subtle.sign(
      "RSASSA-PKCS1-v1_5",
      key,
      new TextEncoder().encode(signingInput),
    );
    const assertion = `${signingInput}.${base64Url(signature)}`;

    const response = await fetch("https://oauth2.googleapis.com/token", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
        assertion,
      }),
    });
    if (!response.ok) {
      console.error("[push] token exchange failed:", response.status, await response.text());
      return null;
    }
    const json = (await response.json()) as { access_token: string; expires_in: number };
    cachedToken = {
      value: json.access_token,
      expiresAt: Date.now() + json.expires_in * 1000,
    };
    return cachedToken.value;
  } catch (error) {
    console.error("[push] could not sign FCM assertion:", error);
    return null;
  }
}

async function sendToToken(
  token: string,
  payload: PushPayload,
): Promise<"ok" | "invalid" | "error"> {
  const accessToken = await getAccessToken();
  if (!accessToken) return "error";

  try {
    const response = await fetch(
      `https://fcm.googleapis.com/v1/projects/${config.fcm.projectId}/messages:send`,
      {
        method: "POST",
        headers: {
          authorization: `Bearer ${accessToken}`,
          "content-type": "application/json",
        },
        body: JSON.stringify({
          message: {
            token,
            notification: { title: payload.title, body: payload.body },
            data: payload.data ?? {},
            android: {
              priority: "high",
              notification: {
                channel_id: "messages",
                sound: "default",
                // Monochrome app: a small white-on-transparent icon.
                icon: "ic_notification",
              },
            },
            apns: {
              headers: { "apns-priority": "10" },
              payload: { aps: { sound: "default", badge: 1, "mutable-content": 1 } },
            },
          },
        }),
      },
    );

    if (response.ok) return "ok";
    const text = await response.text();
    // UNREGISTERED / INVALID_ARGUMENT => the token is dead, forget it.
    if (response.status === 404 || /UNREGISTERED|INVALID_ARGUMENT/.test(text)) return "invalid";
    console.error("[push] FCM error:", response.status, text);
    return "error";
  } catch (error) {
    console.error("[push] network error:", error);
    return "error";
  }
}

/**
 * Notifies every offline device of the given users about a new message.
 * Devices that are currently connected over WebSocket are skipped (they already
 * got the frame) and stale tokens are pruned from the database.
 */
export async function notifyNewMessage(
  store: Store,
  recipientUserIds: string[],
  involvingOnline: (userId: string) => boolean,
  payload: PushPayload,
  senderDeviceId?: string,
): Promise<void> {
  if (!fcmEnabled || recipientUserIds.length === 0) return;

  const offlineUserIds = recipientUserIds.filter((userId) => !involvingOnline(userId));
  if (offlineUserIds.length === 0) return;

  const devices = await store.devicesWithPushToken(
    offlineUserIds,
    senderDeviceId ? [senderDeviceId] : [],
  );

  await Promise.all(
    devices.map(async (device) => {
      const token = device.pushToken;
      if (!token) return;
      const result = await sendToToken(token, payload);
      if (result === "invalid") {
        // Token is stale (app uninstalled / reinstalled) - forget it.
        await store.setPushToken(device.id, null);
      }
    }),
  );
}

export const pushEnabled = fcmEnabled;
