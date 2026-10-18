/**
 * WebSocket connection registry.
 *
 * A user may be connected from several devices at once; every frame is fanned
 * out to all of them (the sender's other devices included, so history stays in
 * sync without a server-side plaintext copy).
 */
import type { ServerWebSocket } from "bun";

export interface WsData {
  connectionId: string;
  authorized: boolean;
  userId?: string;
  deviceId?: string;
  /** Set when `auth` succeeded; used to close connections on token expiry. */
  expiresAt?: number;
}

export interface Connection {
  id: string;
  userId: string;
  deviceId: string;
  ws: ServerWebSocket<WsData>;
}

export type Frame = Record<string, unknown>;

export class Hub {
  private connections = new Map<string, Connection>();
  private byUser = new Map<string, Set<string>>();

  /** Called when a user's online state flips. Wired up in index.ts. */
  onPresenceChange?: (userId: string, online: boolean) => void;

  /** Raw connections that have not authenticated yet. */
  private pending = new Map<string, ServerWebSocket<WsData>>();

  registerPending(ws: ServerWebSocket<WsData>): void {
    this.pending.set(ws.data.connectionId, ws);
  }

  /** Promotes a pending socket to an authenticated connection. */
  attach(ws: ServerWebSocket<WsData>, userId: string, deviceId: string, expiresAt: number): Connection {
    this.pending.delete(ws.data.connectionId);

    const connection: Connection = { id: ws.data.connectionId, userId, deviceId, ws };
    const wasOffline = !this.isUserOnline(userId);

    this.connections.set(connection.id, connection);
    let set = this.byUser.get(userId);
    if (!set) {
      set = new Set();
      this.byUser.set(userId, set);
    }
    set.add(connection.id);

    ws.data.userId = userId;
    ws.data.deviceId = deviceId;
    ws.data.authorized = true;
    ws.data.expiresAt = expiresAt;

    if (wasOffline) this.onPresenceChange?.(userId, true);
    return connection;
  }

  remove(connectionId: string): void {
    this.pending.delete(connectionId);
    const connection = this.connections.get(connectionId);
    if (!connection) return;

    this.connections.delete(connectionId);
    const set = this.byUser.get(connection.userId);
    if (set) {
      set.delete(connectionId);
      if (set.size === 0) {
        this.byUser.delete(connection.userId);
        this.onPresenceChange?.(connection.userId, false);
      }
    }
  }

  send(connectionId: string, frame: Frame): void {
    const connection = this.connections.get(connectionId);
    if (!connection) return;
    try {
      connection.ws.send(JSON.stringify(frame));
    } catch {
      // Socket is already closing; drop it.
      this.remove(connectionId);
    }
  }

  /** Every device of one user. `exceptDevice` skips the originating device. */
  sendToUser(userId: string, frame: Frame, options: { exceptDevice?: string } = {}): number {
    const set = this.byUser.get(userId);
    if (!set) return 0;
    const payload = JSON.stringify(frame);
    let delivered = 0;
    for (const connectionId of set) {
      const connection = this.connections.get(connectionId);
      if (!connection || connection.deviceId === options.exceptDevice) continue;
      try {
        connection.ws.send(payload);
        delivered++;
      } catch {
        this.remove(connectionId);
      }
    }
    return delivered;
  }

  sendToUsers(userIds: Iterable<string>, frame: Frame, options: { exceptUserId?: string } = {}): void {
    const payload = JSON.stringify(frame);
    const seen = new Set<string>();
    for (const userId of userIds) {
      if (userId === options.exceptUserId || seen.has(userId)) continue;
      seen.add(userId);
      const set = this.byUser.get(userId);
      if (!set) continue;
      for (const connectionId of set) {
        const connection = this.connections.get(connectionId);
        if (!connection) continue;
        try {
          connection.ws.send(payload);
        } catch {
          this.remove(connectionId);
        }
      }
    }
  }

  /** All live sockets of one device (a device may have reconnected twice). */
  sendToDevice(deviceId: string, frame: Frame): number {
    const payload = JSON.stringify(frame);
    let delivered = 0;
    for (const connection of this.connections.values()) {
      if (connection.deviceId !== deviceId) continue;
      try {
        connection.ws.send(payload);
        delivered++;
      } catch {
        this.remove(connection.id);
      }
    }
    return delivered;
  }

  isUserOnline(userId: string): boolean {
    const set = this.byUser.get(userId);
    return Boolean(set && set.size > 0);
  }

  isDeviceOnline(deviceId: string): boolean {
    for (const connection of this.connections.values()) {
      if (connection.deviceId === deviceId) return true;
    }
    return false;
  }

  connectionCount(): number {
    return this.connections.size;
  }

  closeAllForDevice(deviceId: string, code = 4002, reason = "device_removed"): void {
    for (const connection of Array.from(this.connections.values())) {
      if (connection.deviceId === deviceId) {
        try {
          connection.ws.close(code, reason);
        } catch {
          /* ignore */
        }
      }
    }
  }

  /** Housekeeping: drop sockets whose access token has expired. */
  sweepExpiredTokens(now = Date.now()): void {
    for (const connection of Array.from(this.connections.values())) {
      if (connection.ws.data.expiresAt && connection.ws.data.expiresAt < now) {
        try {
          connection.ws.close(4001, "token_expired");
        } catch {
          /* ignore */
        }
      }
    }
  }
}
