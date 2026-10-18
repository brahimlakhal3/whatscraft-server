/**
 * Data access layer. Every method returns plain JSON-friendly objects so the
 * HTTP and WebSocket layers can serialise them directly.
 */
import type { Db } from "./db.ts";

// ------------------------------------------------------------------- types --

export interface PublicUser {
  id: string;
  username: string;
  displayName: string;
  about: string;
  /** 0..7 monochrome avatar shade - the client turns this into a grey tone. */
  shade: number;
  lastSeen: string;
}

export interface SelfUser extends PublicUser {
  settings: Record<string, unknown>;
  createdAt: string;
}

export interface DeviceInfo {
  id: string;
  userId: string;
  name: string;
  platform: string;
  identityKey: string;
  signingKey: string | null;
  createdAt: string;
  lastSeen: string;
  /** Only populated by `devicesWithPushToken`. */
  pushToken?: string | null;
}

export interface Envelope {
  deviceId: string;
  wrappedKey: unknown;
}

export interface MessageDto {
  id: string;
  conversationId: string;
  senderId: string;
  senderDeviceId: string | null;
  seq: number;
  kind: string;
  body: unknown;
  createdAt: string;
  editedAt: string | null;
  envelopes: Envelope[];
}

export interface ConversationMemberDto {
  user: PublicUser;
  devices: Array<Pick<DeviceInfo, "id" | "identityKey" | "signingKey" | "platform" | "name">>;
}

export interface ConversationDto {
  id: string;
  kind: "direct" | "group";
  title: string | null;
  createdBy: string | null;
  createdAt: string;
  lastReadSeq: number;
  unread: number;
  muted: boolean;
  members: PublicUser[];
  lastMessage: MessageDto | null;
}

export interface FriendshipDto {
  id: string;
  status: "pending" | "accepted";
  createdAt: string;
  respondedAt: string | null;
  user: PublicUser;
}

// ----------------------------------------------------------------- helpers --

/** Normalises a timestamptz coming out of either driver into an ISO string. */
function iso(value: unknown): string {
  if (value instanceof Date) return value.toISOString();
  if (typeof value === "string") return new Date(value).toISOString();
  if (typeof value === "number") return new Date(value).toISOString();
  return new Date(0).toISOString();
}

function isoOrNull(value: unknown): string | null {
  return value === null || value === undefined ? null : iso(value);
}

/** jsonb columns arrive parsed, text columns arrive raw - normalise both. */
function parseJson(value: unknown): unknown {
  if (value === null || value === undefined) return null;
  if (typeof value === "string") {
    try {
      return JSON.parse(value);
    } catch {
      return null;
    }
  }
  return value;
}

function rowToUser(row: Record<string, any>): PublicUser {
  return {
    id: row.id,
    username: row.username,
    displayName: row.display_name,
    about: row.about ?? "",
    shade: Number(row.avatar_shade ?? 0),
    lastSeen: iso(row.last_seen),
  };
}

function rowToDevice(row: Record<string, any>): DeviceInfo {
  return {
    id: row.id,
    userId: row.user_id,
    name: row.name,
    platform: row.platform,
    identityKey: row.identity_key,
    signingKey: row.signing_key ?? null,
    createdAt: iso(row.created_at),
    lastSeen: iso(row.last_seen),
    pushToken: row.push_token ?? null,
  };
}

function rowToMessage(row: Record<string, any>, envelopes: Envelope[] = []): MessageDto {
  return {
    id: row.id,
    conversationId: row.conversation_id,
    senderId: row.sender_id,
    senderDeviceId: row.sender_device_id ?? null,
    seq: Number(row.seq),
    kind: row.kind,
    body: parseJson(row.body),
    createdAt: iso(row.created_at),
    editedAt: isoOrNull(row.edited_at),
    envelopes,
  };
}

// ------------------------------------------------------------------- store --

export class Store {
  constructor(private db: Db) {}

  private query<T = Record<string, any>>(text: string, params: unknown[] = []): Promise<T[]> {
    return this.db.query<T>(text, params);
  }

  // -- users ---------------------------------------------------------------

  async createUser(input: {
    username: string;
    displayName: string;
    passwordHash: string;
    recoveryHash: string;
    shade: number;
  }): Promise<SelfUser> {
    const rows = await this.query(
      `insert into users (username, username_lower, display_name, password_hash, recovery_hash, avatar_shade)
       values ($1, $2, $3, $4, $5, $6)
       returning *`,
      [
        input.username,
        input.username.toLowerCase(),
        input.displayName,
        input.passwordHash,
        input.recoveryHash,
        input.shade,
      ],
    );
    return this.mapSelf(rows[0]!);
  }

  private mapSelf(row: Record<string, any>): SelfUser {
    return {
      ...rowToUser(row),
      settings: (parseJson(row.settings) as Record<string, unknown>) ?? {},
      createdAt: iso(row.created_at),
    };
  }

  async findUserByUsername(username: string): Promise<(SelfUser & { password_hash: string; recovery_hash: string | null }) | null> {
    const rows = await this.query(`select * from users where username_lower = $1`, [username.toLowerCase()]);
    const row = rows[0];
    if (!row) return null;
    return {
      ...this.mapSelf(row),
      password_hash: row.password_hash,
      recovery_hash: row.recovery_hash ?? null,
    };
  }

  async findUserById(id: string): Promise<SelfUser | null> {
    const rows = await this.query(`select * from users where id = $1`, [id]);
    return rows[0] ? this.mapSelf(rows[0]) : null;
  }

  async findPublicUserById(id: string): Promise<PublicUser | null> {
    const rows = await this.query(`select * from users where id = $1`, [id]);
    return rows[0] ? rowToUser(rows[0]) : null;
  }

  async updateUser(
    id: string,
    patch: { displayName?: string; about?: string; shade?: number; settings?: Record<string, unknown> },
  ): Promise<SelfUser | null> {
    const sets: string[] = [];
    const params: unknown[] = [];
    const push = (fragment: string, value: unknown) => {
      params.push(value);
      sets.push(fragment.replace("$?", `$${params.length}`));
    };

    if (patch.displayName !== undefined) push("display_name = $?", patch.displayName);
    if (patch.about !== undefined) push("about = $?", patch.about);
    if (patch.shade !== undefined) push("avatar_shade = $?", patch.shade);
    if (patch.settings !== undefined) push("settings = $?::jsonb", JSON.stringify(patch.settings));

    if (sets.length === 0) return this.findUserById(id);
    params.push(id);
    const rows = await this.query(
      `update users set ${sets.join(", ")} where id = $${params.length} returning *`,
      params,
    );
    return rows[0] ? this.mapSelf(rows[0]) : null;
  }

  async setPassword(userId: string, passwordHash: string): Promise<void> {
    await this.query(`update users set password_hash = $1 where id = $2`, [passwordHash, userId]);
  }

  async getPasswordHash(userId: string): Promise<string | null> {
    const rows = await this.query<{ password_hash: string }>(
      `select password_hash from users where id = $1`,
      [userId],
    );
    return rows[0]?.password_hash ?? null;
  }

  async setRecoveryHash(userId: string, recoveryHash: string): Promise<void> {
    await this.query(`update users set recovery_hash = $1 where id = $2`, [recoveryHash, userId]);
  }

  async deleteUser(userId: string): Promise<void> {
    await this.query(`delete from users where id = $1`, [userId]);
  }

  async touchLastSeen(userId: string): Promise<void> {
    await this.query(`update users set last_seen = now() where id = $1`, [userId]);
  }

  // -- devices -------------------------------------------------------------

  async upsertDevice(input: {
    id: string;
    userId: string;
    name: string;
    platform: string;
    identityKey: string;
    signingKey: string | null;
  }): Promise<DeviceInfo> {
    const rows = await this.query(
      `insert into devices (id, user_id, name, platform, identity_key, signing_key)
       values ($1, $2, $3, $4, $5, $6)
       on conflict (id) do update
         set name = excluded.name,
             platform = excluded.platform,
             identity_key = excluded.identity_key,
             signing_key = excluded.signing_key,
             last_seen = now()
       returning *`,
      [input.id, input.userId, input.name, input.platform, input.identityKey, input.signingKey],
    );
    return rowToDevice(rows[0]!);
  }

  async listDevices(userId: string): Promise<DeviceInfo[]> {
    const rows = await this.query(`select * from devices where user_id = $1 order by created_at`, [userId]);
    return rows.map(rowToDevice);
  }

  async getDevice(id: string): Promise<DeviceInfo | null> {
    const rows = await this.query(`select * from devices where id = $1`, [id]);
    return rows[0] ? rowToDevice(rows[0]) : null;
  }

  async countDevices(userId: string): Promise<number> {
    const rows = await this.query<{ n: number }>(
      `select count(*)::int as n from devices where user_id = $1`,
      [userId],
    );
    return Number(rows[0]?.n ?? 0);
  }

  async deleteDevice(id: string): Promise<void> {
    await this.query(`delete from devices where id = $1`, [id]);
  }

  async setPushToken(deviceId: string, token: string | null): Promise<void> {
    await this.query(`update devices set push_token = $1 where id = $2`, [token, deviceId]);
  }

  async devicesWithPushToken(userIds: string[], excludeDeviceIds: string[] = []): Promise<DeviceInfo[]> {
    if (userIds.length === 0) return [];
    const rows = await this.query(
      `select * from devices
       where user_id = any($1::uuid[])
         and push_token is not null
         and not (id = any($2::uuid[]))`,
      [userIds, excludeDeviceIds],
    );
    return rows.map(rowToDevice);
  }

  async touchDevice(deviceId: string): Promise<void> {
    await this.query(`update devices set last_seen = now() where id = $1`, [deviceId]);
  }

  // -- sessions ------------------------------------------------------------

  async createSession(input: {
    userId: string;
    deviceId: string;
    refreshHash: string;
    expiresAt: Date;
  }): Promise<string> {
    const rows = await this.query<{ id: string }>(
      `insert into sessions (user_id, device_id, refresh_hash, expires_at)
       values ($1, $2, $3, $4) returning id`,
      [input.userId, input.deviceId, input.refreshHash, input.expiresAt.toISOString()],
    );
    return rows[0]!.id;
  }

  async findSessionByRefreshHash(hash: string) {
    const rows = await this.query(
      `select s.*, u.id as user_id from sessions s
       join users u on u.id = s.user_id
       where s.refresh_hash = $1`,
      [hash],
    );
    return rows[0] ?? null;
  }

  async revokeSession(sessionId: string): Promise<void> {
    await this.query(`update sessions set revoked_at = now() where id = $1`, [sessionId]);
  }

  async revokeAllSessions(userId: string): Promise<void> {
    await this.query(`update sessions set revoked_at = now() where user_id = $1 and revoked_at is null`, [userId]);
  }

  /** Used after a password change: other phones must sign in again. */
  async revokeOtherSessions(userId: string, keepSessionId: string): Promise<void> {
    await this.query(
      `update sessions set revoked_at = now()
       where user_id = $1 and id <> $2 and revoked_at is null`,
      [userId, keepSessionId],
    );
  }

  async listSessions(userId: string) {
    const rows = await this.query(
      `select s.id, s.device_id, s.created_at, s.expires_at, s.revoked_at, d.name as device_name, d.platform
       from sessions s left join devices d on d.id = s.device_id
       where s.user_id = $1 and s.revoked_at is null and s.expires_at > now()
       order by s.created_at desc`,
      [userId],
    );
    return rows.map((row) => ({
      id: row.id,
      deviceId: row.device_id,
      deviceName: row.device_name ?? "Unknown device",
      platform: row.platform ?? "android",
      createdAt: iso(row.created_at),
      expiresAt: iso(row.expires_at),
    }));
  }

  // -- friendships ---------------------------------------------------------

  async getFriendshipBetween(a: string, b: string) {
    const rows = await this.query(
      `select * from friendships
       where (requester_id = $1 and addressee_id = $2) or (requester_id = $2 and addressee_id = $1)
       order by created_at desc limit 1`,
      [a, b],
    );
    return rows[0] ?? null;
  }

  async getFriendshipById(id: string) {
    const rows = await this.query(`select * from friendships where id = $1`, [id]);
    return rows[0] ?? null;
  }

  async areFriends(a: string, b: string): Promise<boolean> {
    const rows = await this.query<{ n: number }>(
      `select count(*)::int as n from friendships
       where status = 'accepted'
         and ((requester_id = $1 and addressee_id = $2) or (requester_id = $2 and addressee_id = $1))`,
      [a, b],
    );
    return Number(rows[0]?.n ?? 0) > 0;
  }

  async createFriendRequest(requesterId: string, addresseeId: string) {
    const rows = await this.query(
      `insert into friendships (requester_id, addressee_id, status)
       values ($1, $2, 'pending')
       on conflict (requester_id, addressee_id) do update set status = 'pending', created_at = now()
       returning *`,
      [requesterId, addresseeId],
    );
    return rows[0]!;
  }

  async acceptFriendRequest(id: string) {
    const rows = await this.query(
      `update friendships set status = 'accepted', responded_at = now() where id = $1 returning *`,
      [id],
    );
    return rows[0] ?? null;
  }

  async deleteFriendship(id: string): Promise<void> {
    await this.query(`delete from friendships where id = $1`, [id]);
  }

  async deleteFriendshipBetween(a: string, b: string): Promise<void> {
    await this.query(
      `delete from friendships
       where (requester_id = $1 and addressee_id = $2) or (requester_id = $2 and addressee_id = $1)`,
      [a, b],
    );
  }

  /** Accepted friends, pending incoming requests and pending outgoing requests. */
  async listFriendGraph(userId: string): Promise<{
    friends: FriendshipDto[];
    incoming: FriendshipDto[];
    outgoing: FriendshipDto[];
  }> {
    const rows = await this.query(
      `select f.id, f.status, f.created_at, f.responded_at,
              f.requester_id, f.addressee_id,
              u.id as u_id, u.username, u.display_name, u.about, u.avatar_shade, u.last_seen
       from friendships f
       join users u on u.id = case when f.requester_id = $1 then f.addressee_id else f.requester_id end
       where f.requester_id = $1 or f.addressee_id = $1
       order by f.created_at desc`,
      [userId],
    );

    const friends: FriendshipDto[] = [];
    const incoming: FriendshipDto[] = [];
    const outgoing: FriendshipDto[] = [];

    for (const row of rows) {
      const dto: FriendshipDto = {
        id: row.id,
        status: row.status,
        createdAt: iso(row.created_at),
        respondedAt: isoOrNull(row.responded_at),
        user: rowToUser({
          id: row.u_id,
          username: row.username,
          display_name: row.display_name,
          about: row.about,
          avatar_shade: row.avatar_shade,
          last_seen: row.last_seen,
        }),
      };
      if (row.status === "accepted") friends.push(dto);
      else if (row.addressee_id === userId) incoming.push(dto);
      else outgoing.push(dto);
    }

    return { friends, incoming, outgoing };
  }

  async friendIds(userId: string): Promise<string[]> {
    const rows = await this.query<{ id: string }>(
      `select case when requester_id = $1 then addressee_id else requester_id end as id
       from friendships where status = 'accepted' and (requester_id = $1 or addressee_id = $1)`,
      [userId],
    );
    return rows.map((row) => row.id);
  }

  // -- conversations -------------------------------------------------------

  async getOrCreateDirect(userA: string, userB: string): Promise<string> {
    const directKey = [userA, userB].sort().join(":");
    const inserted = await this.query<{ id: string }>(
      `insert into conversations (kind, direct_key, created_by)
       values ('direct', $1, $2)
       on conflict (direct_key) do update set direct_key = excluded.direct_key
       returning id`,
      [directKey, userA],
    );
    const conversationId = inserted[0]!.id;
    await this.query(
      `insert into conversation_members (conversation_id, user_id)
       values ($1, $2), ($1, $3)
       on conflict (conversation_id, user_id) do nothing`,
      [conversationId, userA, userB],
    );
    return conversationId;
  }

  async createGroup(title: string, createdBy: string, memberIds: string[]): Promise<string> {
    const rows = await this.query<{ id: string }>(
      `insert into conversations (kind, title, created_by) values ('group', $1, $2) returning id`,
      [title, createdBy],
    );
    const conversationId = rows[0]!.id;
    const members = Array.from(new Set([createdBy, ...memberIds]));
    for (const userId of members) {
      await this.query(
        `insert into conversation_members (conversation_id, user_id, role)
         values ($1, $2, $3) on conflict (conversation_id, user_id) do nothing`,
        [conversationId, userId, userId === createdBy ? "owner" : "member"],
      );
    }
    return conversationId;
  }

  async isMember(conversationId: string, userId: string): Promise<boolean> {
    const rows = await this.query<{ n: number }>(
      `select count(*)::int as n from conversation_members where conversation_id = $1 and user_id = $2`,
      [conversationId, userId],
    );
    return Number(rows[0]?.n ?? 0) > 0;
  }

  async memberIds(conversationId: string): Promise<string[]> {
    const rows = await this.query<{ user_id: string }>(
      `select user_id from conversation_members where conversation_id = $1`,
      [conversationId],
    );
    return rows.map((row) => row.user_id);
  }

  /** Shared SELECT for conversation lists / single conversation views. */
  private conversationSelect(filter: string): string {
    return `
      select c.id, c.kind, c.title, c.created_by, c.created_at,
             m.last_read_seq, m.muted,
             lm.id as last_id, lm.body as last_body, lm.seq as last_seq,
             lm.sender_id as last_sender_id, lm.sender_device_id as last_sender_device_id,
             lm.kind as last_kind, lm.created_at as last_created_at,
             coalesce(members.list, '[]'::json) as members,
             coalesce(unread.n, 0)::int as unread
      from conversation_members m
      join conversations c on c.id = m.conversation_id
      left join lateral (
        select id, body, seq, sender_id, sender_device_id, kind, created_at
        from messages
        where conversation_id = c.id and deleted_at is null
        order by seq desc limit 1
      ) lm on true
      left join lateral (
        select json_agg(json_build_object(
                 'id', u.id, 'username', u.username, 'display_name', u.display_name,
                 'about', u.about, 'avatar_shade', u.avatar_shade, 'last_seen', u.last_seen)
               order by u.username) as list
        from conversation_members cm
        join users u on u.id = cm.user_id
        where cm.conversation_id = c.id
      ) members on true
      left join lateral (
        select count(*) as n from messages msg
        where msg.conversation_id = c.id and msg.seq > m.last_read_seq
          and msg.sender_id <> $1 and msg.deleted_at is null
      ) unread on true
      where ${filter}
      order by coalesce(lm.created_at, c.created_at) desc`;
  }

  private mapConversationRow(row: Record<string, any>): ConversationDto {
    const members = ((row.members ?? []) as any[]).map((u) => rowToUser(u));
    const lastMessage: MessageDto | null = row.last_id
      ? {
          id: row.last_id,
          conversationId: row.id,
          senderId: row.last_sender_id,
          senderDeviceId: row.last_sender_device_id ?? null,
          seq: Number(row.last_seq),
          kind: row.last_kind,
          body: parseJson(row.last_body),
          createdAt: iso(row.last_created_at),
          editedAt: null,
          envelopes: [],
        }
      : null;

    return {
      id: row.id,
      kind: row.kind,
      title: row.title ?? null,
      createdBy: row.created_by ?? null,
      createdAt: iso(row.created_at),
      lastReadSeq: Number(row.last_read_seq ?? 0),
      unread: Number(row.unread ?? 0),
      muted: Boolean(row.muted),
      members,
      lastMessage,
    } satisfies ConversationDto;
  }

  async listConversations(userId: string): Promise<ConversationDto[]> {
    const rows = await this.query(this.conversationSelect("m.user_id = $1"), [userId]);
    return rows.map((row) => this.mapConversationRow(row));
  }

  async getConversationDto(userId: string, conversationId: string): Promise<ConversationDto | null> {
    const rows = await this.query(this.conversationSelect("m.user_id = $1 and c.id = $2"), [
      userId,
      conversationId,
    ]);
    return rows[0] ? this.mapConversationRow(rows[0]) : null;
  }

  async getConversationMembers(conversationId: string): Promise<ConversationMemberDto[]> {
    const rows = await this.query(
      `select u.id as user_id, u.username, u.display_name, u.about, u.avatar_shade, u.last_seen,
              d.id as device_id, d.identity_key, d.signing_key, d.platform, d.name as device_name
       from conversation_members cm
       join users u on u.id = cm.user_id
       left join devices d on d.user_id = u.id
       where cm.conversation_id = $1
       order by u.username`,
      [conversationId],
    );

    const byUser = new Map<string, ConversationMemberDto>();
    for (const row of rows) {
      let entry = byUser.get(row.user_id);
      if (!entry) {
        entry = {
          user: rowToUser({
            id: row.user_id,
            username: row.username,
            display_name: row.display_name,
            about: row.about,
            avatar_shade: row.avatar_shade,
            last_seen: row.last_seen,
          }),
          devices: [],
        };
        byUser.set(row.user_id, entry);
      }
      if (row.device_id) {
        entry.devices.push({
          id: row.device_id,
          identityKey: row.identity_key,
          signingKey: row.signing_key ?? null,
          platform: row.platform,
          name: row.device_name,
        });
      }
    }
    return Array.from(byUser.values());
  }

  async updateLastRead(conversationId: string, userId: string, seq: number): Promise<void> {
    await this.query(
      `update conversation_members set last_read_seq = greatest(last_read_seq, $3)
       where conversation_id = $1 and user_id = $2`,
      [conversationId, userId, seq],
    );
  }

  async setMuted(conversationId: string, userId: string, muted: boolean): Promise<void> {
    await this.query(
      `update conversation_members set muted = $3 where conversation_id = $1 and user_id = $2`,
      [conversationId, userId, muted],
    );
  }

  // -- messages ------------------------------------------------------------

  async insertMessage(input: {
    id: string;
    conversationId: string;
    senderId: string;
    senderDeviceId: string | null;
    kind: string;
    body: unknown;
  }): Promise<MessageDto | null> {
    const rows = await this.query(
      `insert into messages (id, conversation_id, sender_id, sender_device_id, kind, body)
       values ($1, $2, $3, $4, $5, $6)
       on conflict (id) do nothing
       returning *`,
      [
        input.id,
        input.conversationId,
        input.senderId,
        input.senderDeviceId,
        input.kind,
        JSON.stringify(input.body),
      ],
    );
    return rows[0] ? rowToMessage(rows[0]) : null;
  }

  async insertEnvelope(
    messageId: string,
    recipientUserId: string,
    recipientDeviceId: string,
    wrappedKey: unknown,
  ): Promise<void> {
    await this.query(
      `insert into envelopes (message_id, recipient_user_id, recipient_device_id, wrapped_key)
       values ($1, $2, $3, $4)
       on conflict (message_id, recipient_device_id) do update set wrapped_key = excluded.wrapped_key`,
      [messageId, recipientUserId, recipientDeviceId, JSON.stringify(wrappedKey)],
    );
  }

  async getMessage(id: string): Promise<MessageDto | null> {
    const rows = await this.query(`select * from messages where id = $1`, [id]);
    return rows[0] ? rowToMessage(rows[0]) : null;
  }

  /**
   * Page of messages, newest first, with only the envelopes addressed to the
   * caller's own account (the client picks the one for its device).
   */
  async listMessages(
    conversationId: string,
    viewerUserId: string,
    options: { before?: number; limit?: number } = {},
  ): Promise<{ messages: MessageDto[]; hasMore: boolean }> {
    const limit = Math.min(Math.max(options.limit ?? 40, 1), 100);
    const params: unknown[] = [conversationId, viewerUserId];
    let cursor = "";
    if (options.before && options.before > 0) {
      params.push(options.before);
      cursor = `and m.seq < $${params.length}`;
    }
    params.push(limit + 1);

    const rows = await this.query(
      `select m.*, coalesce(env.list, '[]'::json) as envelope_list
       from messages m
       left join lateral (
         select json_agg(json_build_object('deviceId', e.recipient_device_id, 'wrappedKey', e.wrapped_key)) as list
         from envelopes e
         where e.message_id = m.id and e.recipient_user_id = $2
       ) env on true
       where m.conversation_id = $1 ${cursor}
       order by m.seq desc
       limit $${params.length}`,
      params,
    );

    const hasMore = rows.length > limit;
    const page = hasMore ? rows.slice(0, limit) : rows;

    const messages = page.map((row) => {
      const envelopes: Envelope[] = ((row.envelope_list ?? []) as any[]).map((e) => ({
        deviceId: e.deviceId,
        wrappedKey: parseJson(e.wrappedKey),
      }));
      return rowToMessage(row, envelopes);
    });

    return { messages, hasMore };
  }

  async deleteMessage(messageId: string, senderId: string): Promise<boolean> {
    const rows = await this.query(
      `update messages set deleted_at = now(), body = '"deleted"'
       where id = $1 and sender_id = $2 and deleted_at is null
       returning id`,
      [messageId, senderId],
    );
    return rows.length > 0;
  }

  async conversationHasMessages(conversationId: string): Promise<boolean> {
    const rows = await this.query<{ n: number }>(
      `select count(*)::int as n from messages where conversation_id = $1`,
      [conversationId],
    );
    return Number(rows[0]?.n ?? 0) > 0;
  }
}
