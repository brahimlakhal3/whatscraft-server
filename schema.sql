-- Whatscraft schema (PostgreSQL 13+). Applied idempotently at boot.
-- The server is a blind relay: it stores ciphertext and public keys only.

CREATE TABLE IF NOT EXISTS users (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  username        text        NOT NULL,              -- display form, e.g. "brahim"
  username_lower  text        NOT NULL UNIQUE,       -- lookup form
  display_name    text        NOT NULL,
  password_hash   text        NOT NULL,              -- argon2id
  recovery_hash   text,                              -- argon2id of the recovery code
  about           text        NOT NULL DEFAULT '',
  avatar_shade    integer     NOT NULL DEFAULT 0,    -- 0..7, monochrome avatar shade
  settings        jsonb       NOT NULL DEFAULT '{}',
  created_at      timestamptz NOT NULL DEFAULT now(),
  last_seen       timestamptz NOT NULL DEFAULT now()
);

-- One row per installed app instance. Each device holds its own X25519 identity key
-- so a user can read their history on several phones without sharing private keys.
CREATE TABLE IF NOT EXISTS devices (
  id            uuid PRIMARY KEY,                    -- client generated
  user_id       uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name          text NOT NULL DEFAULT 'Phone',
  platform      text NOT NULL DEFAULT 'android',
  identity_key  text NOT NULL,                       -- base64 X25519 public key
  signing_key   text,                                -- base64 Ed25519 public key
  push_token    text,                                -- optional FCM registration token
  created_at    timestamptz NOT NULL DEFAULT now(),
  last_seen     timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS devices_user_idx ON devices(user_id);

-- Refresh-token sessions. Only the SHA-256 of the token is stored.
CREATE TABLE IF NOT EXISTS sessions (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id       uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  device_id     uuid NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  refresh_hash  text NOT NULL UNIQUE,
  created_at    timestamptz NOT NULL DEFAULT now(),
  expires_at    timestamptz NOT NULL,
  revoked_at    timestamptz
);
CREATE INDEX IF NOT EXISTS sessions_user_idx ON sessions(user_id);

-- Friendship requests / accepted contacts.
CREATE TABLE IF NOT EXISTS friendships (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  requester_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  addressee_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  status       text NOT NULL DEFAULT 'pending',      -- pending | accepted
  created_at   timestamptz NOT NULL DEFAULT now(),
  responded_at timestamptz,
  UNIQUE (requester_id, addressee_id),
  CHECK (requester_id <> addressee_id)
);
CREATE INDEX IF NOT EXISTS friendships_addressee_idx ON friendships(addressee_id, status);
CREATE INDEX IF NOT EXISTS friendships_requester_idx ON friendships(requester_id, status);

CREATE TABLE IF NOT EXISTS conversations (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  kind        text NOT NULL DEFAULT 'direct',        -- direct | group
  title       text,
  created_by  uuid REFERENCES users(id) ON DELETE SET NULL,
  direct_key  text UNIQUE,                           -- "minUser:maxUser" dedupes direct chats
  created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS conversation_members (
  conversation_id uuid NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
  user_id         uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role            text NOT NULL DEFAULT 'member',
  joined_at       timestamptz NOT NULL DEFAULT now(),
  last_read_seq   bigint NOT NULL DEFAULT 0,
  muted           boolean NOT NULL DEFAULT false,
  PRIMARY KEY (conversation_id, user_id)
);
CREATE INDEX IF NOT EXISTS members_user_idx ON conversation_members(user_id);

CREATE TABLE IF NOT EXISTS messages (
  id               uuid PRIMARY KEY,                 -- client generated (idempotent send)
  conversation_id  uuid NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
  sender_id        uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  sender_device_id uuid,
  seq              bigserial,
  kind             text NOT NULL DEFAULT 'text',
  body             text NOT NULL,                    -- JSON: {alg,iv,ct,sig}
  created_at       timestamptz NOT NULL DEFAULT now(),
  edited_at        timestamptz,
  deleted_at       timestamptz
);
CREATE INDEX IF NOT EXISTS messages_conversation_idx ON messages(conversation_id, seq DESC);

-- One wrapped copy of the random message key per recipient device.
-- The server can never unwrap these (it has no X25519 private keys).
CREATE TABLE IF NOT EXISTS envelopes (
  message_id          uuid NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
  recipient_user_id   uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  recipient_device_id uuid NOT NULL,
  wrapped_key         text NOT NULL,                 -- JSON: {iv,ct}
  PRIMARY KEY (message_id, recipient_device_id)
);
CREATE INDEX IF NOT EXISTS envelopes_recipient_idx ON envelopes(recipient_user_id);
