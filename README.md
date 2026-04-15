# sshkey-chat

Expect breaking changes until v1.0.

Private messaging server over SSH with end-to-end encryption. No accounts, no passwords -- your identity is your SSH key.

The server is a blind relay. It routes, stores, and sequences encrypted blobs. It sees metadata (who, when, where, sizes) but never message content. Same trust model as Signal.

Inspired by [ssh-chat](https://github.com/shazow/ssh-chat).

## Features

- **E2E encrypted** -- server stores opaque blobs, never sees message content
- **SSH identity** -- no accounts, no passwords, your Ed25519 key is your permanent identity (no key rotation; lost or compromised keys require account retirement + a fresh account)
- **Rooms** with epoch-based key rotation (forward secrecy, bounded exposure) and admin-initiated retirement
- **1:1 DMs and group DMs** with per-message keys (Signal-level forward secrecy), separate protocol verbs for each
- **Group DMs are self-governed by in-group admins** (Phase 14) — creator becomes the first admin; admins can add, remove, promote, demote, and rename. Server operators stay out of group membership. At-least-one-admin invariant enforced at every mutation path; retirement cascade auto-promotes the oldest remaining member as successor.
- **`/leave` and `/delete`** for rooms, 1:1 DMs, and group DMs with multi-device sync via server-side sidecar tables
- **Admin-initiated room retirement** (`sshkey-ctl retire-room`) — read-only, display-name suffixed to free the original, broadcast to connected members
- **File sharing** via encrypted upload/download channels (server can't see filenames, types, or content)
- **Sync on reconnect** -- paginated catch-up with bundled epoch keys; retired and deleted contexts propagate via catchup lists
- **Lazy scroll-back** -- on-demand history, no bulk download on connect
- **Reactions, typing indicators, read receipts, presence, pins**
- **Push notifications** -- content-free APNs/FCM wake pushes (app syncs over SSH)
- **Admin CLI** -- manage users, rooms, devices, pending keys from the server shell (local-only; no remote admin RPC)
- **User self-service** -- retire own account, list and revoke own devices from the client
- **Pure Go** -- server has no cgo, no external dependencies, single binary (clients may use cgo for SQLCipher)

## Architecture

```
Server (:2222)                           Clients
┌─────────────────────────┐
│  SSH listener            │◄──── sshkey-term  (terminal, Go)
│  NDJSON protocol (Ch 1)  │◄──── sshkey-app   (GUI, Rust)
│  Downloads      (Ch 2)   │◄──── any other client that speaks the protocol
│  Uploads        (Ch 3)   │
│  SQLite WAL storage      │
└─────────────────────────┘
```

Three SSH channels per connection: Channel 1 carries NDJSON protocol messages, Channel 2 carries download file bytes (server → client), Channel 3 carries upload file bytes (client → server). Splitting uploads and downloads onto separate channels lets a large transfer in one direction run in parallel with the other. All message content is encrypted client-side before reaching the server.

### Encryption

| Context | Model | Forward secrecy |
|---|---|---|
| **Rooms** | Epoch keys (AES-256-GCM, rotated every 100 msgs or 1 hour) | Bounded -- max 100 messages exposed per key compromise |
| **DMs** | Per-message keys (fresh AES-256 key per message, wrapped per member) | Per-message -- one key = one message |

Key wrapping: Ed25519 -> X25519 conversion, ephemeral ECDH, HKDF-SHA256, AES-256-GCM. Same algorithm for both epoch keys and per-message keys.

Only Ed25519 SSH keys are supported. The server rejects RSA, ECDSA, and other key types.

## Binaries

| Binary | Description |
|---|---|
| `sshkey-server` | Chat server -- SSH listener, protocol handler, SQLite storage |
| `sshkey-ctl` | Local admin tool -- manages users, rooms, devices, and retirement via direct SQLite access |

## Quick start

### Docker (recommended)

```bash
# 1. (Optional) Edit docker/config/users.toml and docker/config/rooms.toml
#    to seed initial users and rooms on first start.
#    cat ~/.ssh/id_ed25519.pub

# 2. Start the server
docker compose up -d

# 3. Connect with the terminal client (unknown keys go to the pending queue)
sshkey-term --host localhost --key ~/.ssh/id_ed25519
```

Manage the server:

```bash
# View pending key requests
docker exec sshkey-server sshkey-ctl pending

# Approve a user and add them to rooms
docker exec sshkey-server sshkey-ctl approve --key "ssh-ed25519 AAAA... Alice" --rooms general,support

# List users / rooms
docker exec sshkey-server sshkey-ctl list-users
docker exec sshkey-server sshkey-ctl list-rooms

# Promote/demote admin status (lives in users.db, NOT server.toml)
docker exec sshkey-server sshkey-ctl promote usr_abc123
docker exec sshkey-server sshkey-ctl demote usr_abc123

# Create a new room
docker exec sshkey-server sshkey-ctl add-room --name engineering --topic "Engineering chat"

# Retire a room (read-only for everyone; display name gets a random suffix)
docker exec sshkey-server sshkey-ctl retire-room --room engineering --reason "project ended"

# Revoke a device
docker exec sshkey-server sshkey-ctl revoke-device --user usr_abc123 --device dev_x

# View logs
docker logs -f sshkey-server
```

> **Note:** `users.toml` and `rooms.toml` are seed files -- they are only processed on first server start to bootstrap initial users and rooms. After that, `users.db` and `rooms.db` are the source of truth and all management happens through `sshkey-ctl`.

### Install

```bash
# Install via go install
go install github.com/brushtailmedia/sshkey-chat/cmd/sshkey-server@latest
go install github.com/brushtailmedia/sshkey-chat/cmd/sshkey-ctl@latest
```

Or download pre-built binaries from [Releases](https://github.com/brushtailmedia/sshkey-chat/releases).

### Build from source

#### Requirements

- Go 1.25 or later

#### Build

```bash
go build -o sshkey-server ./cmd/sshkey-server
go build -o sshkey-ctl ./cmd/sshkey-ctl
```

### Configure

```bash
mkdir -p /etc/sshkey-chat /var/sshkey-chat
```

Create the config files:

> **Note:** `users.toml` and `rooms.toml` are **seed files only** -- they are processed on first server start to bootstrap initial users and rooms. After that, use `sshkey-ctl` for all user and room management. `server.toml` remains the runtime config file for server settings.

**`/etc/sshkey-chat/server.toml`**

```toml
[server]
port = 2222
bind = "0.0.0.0"

# Self-leave policy — do users control their own room membership?
# Defaults are safe (admin-managed active rooms, user-cleanup for retired rooms).
# allow_self_leave_rooms         = false   # default: active-room membership is admin-managed
# allow_self_leave_retired_rooms = true    # default: users can /delete retired rooms from their view

[devices]
max_per_user = 10

[rate_limits]
messages_per_second = 5
uploads_per_minute = 60
history_per_minute = 50
deletes_per_minute = 10
admin_deletes_per_minute = 50
reactions_per_minute = 30
dm_creates_per_minute = 5
profiles_per_minute = 5
pins_per_minute = 10
```

See `testdata/config/server.toml` for a complete example with all options.

**`/etc/sshkey-chat/users.toml`** -- Seed file, processed on first server start only. After that, use `sshkey-ctl` to manage users and rooms.

```toml
[alice]
key = "ssh-ed25519 AAAA... alice@laptop"
display_name = "Alice"
rooms = ["general", "support"]

[bob]
key = "ssh-ed25519 AAAA... bob@desktop"
display_name = "Bob"
rooms = ["general", "support"]
```

**`/etc/sshkey-chat/rooms.toml`** -- Seed file, processed on first server start only. After that, use `sshkey-ctl` to manage users and rooms.

```toml
[general]
topic = "General chat"

[support]
topic = "Requests, questions, and admin help"
```

### Run

```bash
./sshkey-server -config /etc/sshkey-chat -data /var/sshkey-chat
```

The server generates an Ed25519 host key on first run and stores it in the config directory.

### Deploy (systemd)

Install the binaries and set up a dedicated service user:

```bash
# Install binaries
sudo cp sshkey-server sshkey-ctl /usr/local/bin/

# Create service user
sudo useradd -r -s /usr/sbin/nologin sshkey

# Create directories with correct ownership
sudo mkdir -p /etc/sshkey-chat /var/sshkey-chat
sudo chown sshkey:sshkey /var/sshkey-chat
sudo chmod 750 /var/sshkey-chat

# Copy config files
sudo cp testdata/config/*.toml /etc/sshkey-chat/
# Edit users.toml and rooms.toml for your setup

# Install and enable the service
sudo cp init/sshkey-server.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now sshkey-server
```

The server runs as a systemd service with automatic restart on failure. Config changes are picked up automatically via fsnotify, or you can trigger a manual reload:

```bash
sudo systemctl reload sshkey-server   # sends SIGHUP, reloads config
sudo systemctl restart sshkey-server  # full restart (only needed for port/bind changes)
sudo journalctl -u sshkey-server -f   # follow logs
```

### Admin

`sshkey-ctl` runs locally on the server box only. It writes directly to the SQLite databases and does not go over the wire — there is no remote admin protocol. For CLI commands that need to reach connected clients (retirement, room retirement), a small in-server polling goroutine picks up queued events from `pending_*` tables and broadcasts them within a few seconds.

**Pending keys:**

```bash
sshkey-ctl pending                                             # view pending key requests
sshkey-ctl approve --key "ssh-ed25519 AAAA... name" --rooms general,support  # approve (name from key comment)
sshkey-ctl approve --key "ssh-ed25519 AAAA..." --name NAME --rooms general,support  # approve (override name)
sshkey-ctl reject --fingerprint FP                             # reject a pending key
```

**Users:**

```bash
sshkey-ctl list-users                                          # list all users
sshkey-ctl remove-user usr_abc123                              # remove a user
sshkey-ctl retire-user usr_abc123 --reason key_lost            # permanently retire an account
sshkey-ctl list-retired                                        # list retired accounts
sshkey-ctl promote usr_abc123                                  # grant admin status
sshkey-ctl demote usr_abc123                                   # revoke admin status
```

**Rooms:**

```bash
sshkey-ctl add-room --name engineering --topic "Engineering chat"  # create a new room
sshkey-ctl list-rooms                                          # list all rooms
sshkey-ctl add-to-room --user usr_abc123 --room engineering    # add user to a room
sshkey-ctl remove-from-room --user usr_abc123 --room engineering  # remove user from a room
sshkey-ctl retire-room --room engineering --reason "project ended"  # archive a room server-wide
sshkey-ctl list-retired-rooms                                  # list retired rooms
```

**Groups:**

```bash
sshkey-ctl list-groups                                         # list all group DMs
```

Group DMs are self-governed by in-group admins (Phase 14). The creator becomes the first admin; admins can add/remove/promote/demote/rename via in-group slash commands. The server operator stays out of group membership — there is no `sshkey-ctl remove-from-group` or similar. For ToS violations that require operator intervention, retire the offending account (`sshkey-ctl retire-user`), which triggers a cascading per-group leave + last-admin succession.

**Devices:**

```bash
sshkey-ctl revoke-device --user usr_abc123 --device dev_x      # revoke a stolen device
sshkey-ctl restore-device --user usr_abc123 --device dev_x     # re-authorize a device
```

**Server:**

```bash
sshkey-ctl status                                              # show server overview
sshkey-ctl host-key                                            # print server host key fingerprint
sshkey-ctl purge --older-than 5y                               # delete old messages + vacuum
sshkey-ctl purge --older-than 1y --dry-run                     # preview what would be deleted
```

## Protocol

NDJSON (newline-delimited JSON) over SSH. One JSON object per line. Capabilities are individually negotiated on connect.

### Handshake

```
Client connects via SSH with Ed25519 key
  Server -> server_hello (capabilities)
  Client -> client_hello (device_id, requested capabilities)
  Server -> welcome (user, active capabilities)
  Server -> retired_rooms, deleted_rooms  (Phase 12 catchup — BEFORE room_list)
  Server -> deleted_groups                (Phase 11 catchup — BEFORE group_list)
  Server -> room_list, group_list, dm_list
  Server -> profiles, epoch_keys, unread counts, pins
  Server -> sync_batch (catch-up messages) ...
  Server -> sync_complete
  -- real-time push --
```

The `retired_rooms` / `deleted_rooms` / `deleted_groups` lists are delivered **before** the active list messages so the client has the full "archived" picture before populating its active list.

### Message types

| Category | Client -> Server | Server -> Client |
|---|---|---|
| **Handshake** | `client_hello` | `server_hello`, `welcome` |
| **Rooms** | `send`, `leave_room`, `delete_room` | `message`, `room_list`, `room_event`, `room_left`, `room_deleted`, `deleted_rooms`, `room_retired`, `retired_rooms` |
| **Group DMs** | `create_group`, `send_group`, `leave_group`, `delete_group`, `rename_group` | `group_message`, `group_created`, `group_list`, `group_event`, `group_left`, `group_deleted`, `deleted_groups`, `group_renamed` |
| **1:1 DMs** | `create_dm`, `send_dm`, `leave_dm` | `dm`, `dm_created`, `dm_list`, `dm_left` |
| **Sync** | -- | `sync_batch`, `sync_complete` |
| **History** | `history` | `history_result` |
| **Epoch keys** | `epoch_rotate` | `epoch_trigger`, `epoch_key`, `epoch_confirmed` |
| **Deletion** | `delete` | `deleted` |
| **Typing** | `typing` | `typing` |
| **Read receipts** | `read` | `read`, `unread` |
| **Reactions** | `react`, `unreact` | `reaction`, `reaction_removed` |
| **Pins** | `pin`, `unpin` | `pinned`, `unpinned`, `pins` |
| **Profiles** | `set_profile`, `set_status` | `profile`, `presence` |
| **Files** | `upload_start`, `download` | `upload_ready`, `upload_complete`, `upload_error`, `download_start`, `download_complete`, `download_error` |
| **Push** | `push_register` | `push_registered` |
| **Retirement** | `retire_me` | `user_retired`, `retired_users` |
| **Device management** | `list_devices`, `revoke_device` | `device_list`, `device_revoke_result` |
| **Membership** | `room_members` | `room_members_list` |
| **Admin** | `list_pending_keys` | `admin_notify`, `pending_keys_list`, `device_revoked`, `server_shutdown` |
| **Errors** | -- | `error` |

## Storage

### Server-side

SQLite in WAL mode. The server stores encrypted blobs only -- it cannot read message content. Data is split across three identity DBs plus one DB per room/group/DM, keeping each message database scoped to a single access boundary.

```
/var/sshkey-chat/data/
├── data.db                        # devices, epoch keys, group/DM membership, profiles, push tokens, read positions, sidecars
├── users.db                       # user identity, keys, admin status, retirement (Phase 9)
├── rooms.db                       # room identity, membership, topics, retirement flags (Phases 2-6, 12)
├── room-room_V1StGXR8_Z5jdHi6B.db  # one file per room (encrypted messages, reactions, pins)
├── group-group_xK9mQ2pR.db         # one file per group DM
├── dm-dm_yL0nR3qS.db               # one file per 1:1 DM
└── files/                          # encrypted file blobs
```

**DB-per-context** keeps access boundaries simple: when a user is removed from a room, the server's per-user file ACL is "they can read `data.db` for their own rows plus the specific `room-*.db` / `group-*.db` / `dm-*.db` files they're a member of". No per-row filtering in queries, no accidental cross-room reads.

### Schema: users.db

```sql
-- User identity, keys, admin status, retirement
CREATE TABLE users (
    id             TEXT PRIMARY KEY,   -- nanoid (usr_ prefix)
    key            TEXT NOT NULL,      -- SSH public key
    display_name   TEXT NOT NULL,
    admin          INTEGER NOT NULL DEFAULT 0,
    retired        INTEGER NOT NULL DEFAULT 0,
    retired_at     TEXT NOT NULL DEFAULT '',
    retired_reason TEXT NOT NULL DEFAULT ''
);

CREATE UNIQUE INDEX idx_users_key ON users(key);
```

### Schema: rooms.db

```sql
-- Room identity, metadata, retirement flags
CREATE TABLE rooms (
    id           TEXT PRIMARY KEY,   -- nanoid (room_ prefix)
    display_name TEXT NOT NULL,      -- suffixed on retire (e.g. "general_V1St") to free the original
    topic        TEXT NOT NULL DEFAULT '',
    retired      INTEGER NOT NULL DEFAULT 0,
    retired_at   TEXT NOT NULL DEFAULT '',
    retired_by   TEXT NOT NULL DEFAULT '',
    created_at   TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE UNIQUE INDEX idx_rooms_display_name_lower ON rooms(LOWER(display_name));

-- Per-user room membership (first_epoch bounds history decryption)
CREATE TABLE room_members (
    room_id     TEXT NOT NULL,
    user_id     TEXT NOT NULL,
    first_epoch INTEGER NOT NULL DEFAULT 0,
    joined_at   TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (room_id, user_id)
);

CREATE INDEX idx_room_members_user ON room_members(user_id);
```

### Schema: data.db

```sql
-- Device registry (per user, per device)
CREATE TABLE devices (
    user TEXT, device_id TEXT, last_synced TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (user, device_id)
);

-- Wrapped epoch keys (rooms only, per user per epoch)
CREATE TABLE epoch_keys (
    room TEXT, epoch INTEGER, user TEXT, wrapped_key TEXT,
    PRIMARY KEY (room, epoch, user)
);

-- Group DMs: fixed-membership peer conversations (3+ members, creator sets
-- the member list, membership is immutable unless a moderation escape
-- hatch is used).
CREATE TABLE group_conversations (
    id         TEXT PRIMARY KEY,
    name       TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE group_members (
    group_id  TEXT NOT NULL,
    user      TEXT NOT NULL,
    joined_at TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (group_id, user),
    FOREIGN KEY (group_id) REFERENCES group_conversations(id)
);

-- 1:1 DMs: exactly two parties, canonical (user_a, user_b) unique pair,
-- per-user one-way ratchet cutoffs (left_at > 0 = user has /delete'd)
CREATE TABLE direct_messages (
    id             TEXT PRIMARY KEY,
    user_a         TEXT NOT NULL,
    user_b         TEXT NOT NULL,
    created_at     INTEGER NOT NULL,
    user_a_left_at INTEGER NOT NULL DEFAULT 0,
    user_b_left_at INTEGER NOT NULL DEFAULT 0,
    UNIQUE(user_a, user_b)
);

-- Per-user /delete sidecars — offline-device catchup for multi-device sync.
-- Rows survive last-member cleanup cascades.
CREATE TABLE deleted_groups (
    user_id TEXT NOT NULL, group_id TEXT NOT NULL,
    deleted_at INTEGER NOT NULL,
    PRIMARY KEY (user_id, group_id)
);
CREATE TABLE deleted_rooms (
    user_id TEXT NOT NULL, room_id TEXT NOT NULL,
    deleted_at INTEGER NOT NULL,
    PRIMARY KEY (user_id, room_id)
);

-- CLI -> server coordination queues. The CLI writes directly to these
-- when admin commands need to reach connected clients; a background
-- polling goroutine drains them and broadcasts within a few seconds.
CREATE TABLE pending_admin_kicks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL, group_id TEXT NOT NULL,
    reason TEXT NOT NULL DEFAULT 'admin',
    queued_at INTEGER NOT NULL
);
CREATE TABLE pending_room_retirements (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    room_id TEXT NOT NULL, retired_by TEXT NOT NULL,
    reason TEXT NOT NULL DEFAULT '',
    queued_at INTEGER NOT NULL
);

-- Read positions (per device, per room/group/dm)
CREATE TABLE read_positions (
    user TEXT, device_id TEXT,
    room TEXT NOT NULL DEFAULT '',
    group_id TEXT NOT NULL DEFAULT '',
    dm_id TEXT NOT NULL DEFAULT '',
    last_read TEXT NOT NULL, ts INTEGER NOT NULL,
    PRIMARY KEY (user, device_id, room, group_id, dm_id)
);

-- Push notification tokens, revoked devices, pending keys, profiles
CREATE TABLE push_tokens (
    user TEXT, device_id TEXT, platform TEXT NOT NULL, token TEXT NOT NULL,
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    active INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (user, device_id)
);
CREATE TABLE revoked_devices (
    user TEXT, device_id TEXT,
    revoked_at TEXT NOT NULL DEFAULT (datetime('now')),
    reason TEXT,
    PRIMARY KEY (user, device_id)
);
CREATE TABLE pending_keys (
    fingerprint TEXT PRIMARY KEY, remote_addr TEXT,
    attempts INTEGER NOT NULL DEFAULT 1,
    first_seen TEXT NOT NULL DEFAULT (datetime('now')),
    last_seen TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE profiles (
    user TEXT PRIMARY KEY, display_name TEXT, avatar_id TEXT, status_text TEXT
);

-- File content hashes (BLAKE2b-256, verified on upload/download)
CREATE TABLE file_hashes (
    file_id TEXT PRIMARY KEY, content_hash TEXT NOT NULL, size INTEGER NOT NULL
);

-- Performance indexes (per-connect query paths)
CREATE INDEX idx_epoch_keys_room_user_epoch ON epoch_keys(room, user, epoch);
CREATE INDEX idx_epoch_keys_user ON epoch_keys(user, room, epoch);
CREATE INDEX idx_group_members_user ON group_members(user, group_id);
CREATE INDEX idx_dm_user_a ON direct_messages(user_a);
CREATE INDEX idx_dm_user_b ON direct_messages(user_b);
CREATE INDEX idx_deleted_groups_user ON deleted_groups(user_id);
CREATE INDEX idx_deleted_rooms_user ON deleted_rooms(user_id);
CREATE INDEX idx_devices_last_synced ON devices(last_synced) WHERE last_synced IS NOT NULL AND last_synced != '';
CREATE INDEX idx_push_tokens_user_active ON push_tokens(user, active);
```

### Schema: room / group / dm message DBs

One file per room, per group DM, per 1:1 DM. All three use the same schema — the `wrapped_keys` column is unused for rooms (which use epoch keys from `data.db`) and populated for groups and DMs (per-message wrapped keys).

```sql
-- Messages (encrypted blobs, server cannot read content)
CREATE TABLE messages (
    id TEXT PRIMARY KEY, sender TEXT NOT NULL, ts INTEGER NOT NULL,
    epoch INTEGER,               -- set for room messages, NULL for group/DM
    payload TEXT NOT NULL, file_ids TEXT, signature TEXT,
    wrapped_keys TEXT,           -- set for group/DM messages, NULL for rooms
    deleted INTEGER NOT NULL DEFAULT 0
);

-- Reactions (encrypted, server cannot read emoji)
CREATE TABLE reactions (
    reaction_id TEXT PRIMARY KEY, message_id TEXT NOT NULL, user TEXT NOT NULL,
    ts INTEGER NOT NULL, epoch INTEGER,
    payload TEXT NOT NULL, signature TEXT, wrapped_keys TEXT,
    FOREIGN KEY (message_id) REFERENCES messages(id)
);

-- Pinned messages (only used by rooms; the table exists in all three but
-- the pin/unpin protocol verbs are scoped to rooms today)
CREATE TABLE pins (
    message_id TEXT PRIMARY KEY, pinned_by TEXT NOT NULL, ts INTEGER NOT NULL,
    FOREIGN KEY (message_id) REFERENCES messages(id)
);

-- Performance indexes
CREATE INDEX idx_messages_ts ON messages(ts);
CREATE INDEX idx_messages_sender ON messages(sender);
CREATE INDEX idx_messages_not_deleted ON messages(deleted) WHERE deleted = 0;
CREATE INDEX idx_reactions_message ON reactions(message_id);
```

## Config hot-reload

The server watches `server.toml` via fsnotify and reloads on SIGHUP.

**Hot-reloadable (no restart):** rate limits, retention, file limits, device limits, sync settings, push credentials, self-leave policy flags (`allow_self_leave_rooms`, `allow_self_leave_retired_rooms`).

**Requires restart:** port, bind address.

**Not in `server.toml` at all** (managed via `sshkey-ctl`, no reload needed): users, rooms, admin status, room membership, retirement. These live in `users.db` and `rooms.db` and the CLI writes directly to those files. Changes that need to reach connected clients (retire-user, retire-room) go through small polling queues (`pending_admin_kicks`, `pending_room_retirements`) that the running server drains every few seconds.

## Push notifications

Content-free wake pushes via APNs (iOS) and FCM (Android). The server never sends message content in push payloads -- it sends a silent wake signal, the app connects via SSH, syncs, and shows a local notification with real content.

Disabled by default. Enable by adding credentials to `server.toml`:

```toml
[push.apns]
enabled = true
key_path = "/etc/sshkey-chat/AuthKey_ABC123.p8"
key_id = "ABC123DEFG"
team_id = "TEAM123456"
bundle_id = "chat.sshkey.app"

[push.fcm]
enabled = true
credentials_path = "/etc/sshkey-chat/firebase-sa.json"
project_id = "sshkey-chat"
```

## Project structure

```
sshkey-chat/
├── cmd/
│   ├── sshkey-server/     # server entry point
│   └── sshkey-ctl/        # admin CLI tool
├── init/                  # systemd service file
├── internal/
│   ├── config/            # TOML config parsing + validation
│   ├── protocol/          # wire format message types + NDJSON codec
│   ├── push/              # APNs + FCM push notification senders
│   ├── server/            # SSH server, session handling, all protocol logic
│   └── store/             # SQLite storage (users, rooms, messages, devices, epochs, groups, DMs)
├── testdata/config/       # example config files for testing
├── go.mod
└── go.sum
```

## Related repositories

| Repo | Description |
|---|---|
| [sshkey-chat](https://github.com/brushtailmedia/sshkey-chat) | Server + admin tool + Go core library (this repo) |
| [sshkey-term](https://github.com/brushtailmedia/sshkey-term) | Terminal client (Go + Bubble Tea + rasterm) |
| [sshkey-app](https://github.com/brushtailmedia/sshkey-app) | Desktop + mobile GUI client (Rust + egui) |

## Testing

```bash
go test ./...
```

Tests cover the full handshake, room messaging with isolation, 1:1 and group DM message flow with `wrapped_keys` validation, `/leave` and `/delete` for rooms / groups / DMs, room retirement and byte-identical privacy error responses, multi-device sync via the `deleted_groups` / `deleted_rooms` sidecars, sync on reconnect, history scroll-back, and storage operations.

## Building a client

See [PROTOCOL.md](PROTOCOL.md) for the complete protocol reference -- everything you need to build a compatible client in any language. Includes wire format, all message types with JSON examples, crypto specs, key wrapping, and a minimal client checklist.

## Design

See [PROJECT.md](PROJECT.md) for the full design document including threat model, cryptographic primitives, key exchange protocols, epoch rotation, replay detection, and safety numbers.

## License

MIT
