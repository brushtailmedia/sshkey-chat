# sshkey

Private messaging server over SSH with end-to-end encryption. No accounts, no passwords -- identity is your SSH key.

The server is a blind relay. It routes, stores, and sequences encrypted blobs. It sees metadata (who, when, where, sizes) but never message content. Same trust model as Signal.

Inspired by [ssh-chat](https://github.com/shazow/ssh-chat).

## Features

- **E2E encrypted** -- server stores opaque blobs, never sees message content
- **SSH identity** -- no accounts, no passwords, your Ed25519 key is your identity
- **Rooms** with epoch-based key rotation (forward secrecy, bounded exposure)
- **DMs and group DMs** with per-message keys (Signal-level forward secrecy)
- **File sharing** via encrypted binary channel (server can't see filenames, types, or content)
- **Sync on reconnect** -- paginated catch-up with bundled epoch keys
- **Lazy scroll-back** -- on-demand history, no bulk download on connect
- **Reactions, typing indicators, read receipts, presence, pins**
- **Push notifications** -- content-free APNs/FCM wake pushes (app syncs over SSH)
- **Config hot-reload** -- add/remove users and rooms without restarting
- **Admin CLI** -- manage users, devices, pending keys from the server shell
- **Pure Go** -- no cgo, no external dependencies, single binary

## Architecture

```
Server (:2222)                           Clients
┌─────────────────────────┐
│  SSH listener            │◄──── sshkey-chat  (terminal, Go)
│  NDJSON protocol (Ch 1)  │◄──── sshkey-app   (GUI, Rust)
│  Binary file data (Ch 2) │◄──── any other client that speaks the protocol
│  SQLite WAL storage      │
└─────────────────────────┘
```

Two SSH channels per connection: Channel 1 carries NDJSON protocol messages, Channel 2 carries raw file bytes. All message content is encrypted client-side before reaching the server.

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
| `sshkey-server` | Chat server -- SSH listener, protocol handler, storage |
| `sshkey-ctl` | Local admin tool -- reads/writes config, manages users and devices |

## Quick start

### Requirements

- Go 1.25 or later

### Build

```bash
go build -o sshkey-server ./cmd/sshkey-server
go build -o sshkey-ctl ./cmd/sshkey-ctl
```

### Configure

```bash
mkdir -p /etc/sshkey-chat /var/sshkey-chat
```

Create the config files:

**`/etc/sshkey-chat/server.toml`**

```toml
[server]
port = 2222
bind = "0.0.0.0"
admins = ["alice"]

[devices]
max_per_user = 10

[rate_limits]
messages_per_second = 5
uploads_per_minute = 10
history_per_minute = 50
```

See `testdata/config/server.toml` for a complete example with all options.

**`/etc/sshkey-chat/users.toml`**

```toml
[alice]
key = "ssh-ed25519 AAAA... alice@laptop"
display_name = "Alice"
rooms = ["general", "engineering"]

[bob]
key = "ssh-ed25519 AAAA... bob@desktop"
display_name = "Bob"
rooms = ["general"]
```

**`/etc/sshkey-chat/rooms.toml`**

```toml
[general]
topic = "General chat"

[engineering]
topic = "Core platform work"
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

```bash
sshkey-ctl pending                                    # view pending key requests
sshkey-ctl approve --fingerprint FP --name NAME --rooms general  # approve a user
sshkey-ctl reject --fingerprint FP                    # reject a pending key
sshkey-ctl list-users                                 # list all users
sshkey-ctl remove-user carol                          # remove a user
sshkey-ctl revoke-device --user alice --device dev_x  # revoke a stolen device
sshkey-ctl restore-device --user alice --device dev_x # re-authorize a device
sshkey-ctl host-key                                   # print server host key fingerprint
sshkey-ctl purge --older-than 5y                      # delete old messages + vacuum
sshkey-ctl purge --older-than 1y --dry-run            # preview what would be deleted
```

## Protocol

NDJSON (newline-delimited JSON) over SSH. One JSON object per line. Capabilities are individually negotiated on connect.

### Handshake

```
Client connects via SSH with Ed25519 key
  Server -> server_hello (capabilities)
  Client -> client_hello (device_id, requested capabilities)
  Server -> welcome (user, rooms, active capabilities)
  Server -> room_list, conversation_list, profiles, epoch_keys, unread counts, pins
  Server -> sync_batch (catch-up messages) ...
  Server -> sync_complete
  -- real-time push --
```

### Message types

| Category | Client -> Server | Server -> Client |
|---|---|---|
| **Handshake** | `client_hello` | `server_hello`, `welcome` |
| **Rooms** | `send` | `message`, `room_list`, `room_event` |
| **DMs** | `create_dm`, `send_dm`, `leave_conversation` | `dm`, `dm_created`, `conversation_list`, `conversation_event` |
| **Sync** | -- | `sync_batch`, `sync_complete` |
| **History** | `history` | `history_result` |
| **Epoch keys** | `epoch_rotate` | `epoch_trigger`, `epoch_key`, `epoch_confirmed` |
| **Deletion** | `delete` | `deleted` |
| **Typing** | `typing` | `typing` |
| **Read receipts** | `read` | `read`, `unread` |
| **Reactions** | `react`, `unreact` | `reaction`, `reaction_removed` |
| **Pins** | `pin`, `unpin` | `pinned`, `unpinned`, `pins` |
| **Profiles** | `set_profile`, `set_status` | `profile`, `presence` |
| **Files** | `upload_start`, `download` | `upload_ready`, `upload_complete`, `download_start`, `download_complete` |
| **Push** | `push_register` | `push_registered` |
| **Key rotation** | `key_rotate`, `key_rotate_complete` | `key_rotate_keys` |
| **Admin** | -- | `admin_notify`, `device_revoked`, `server_shutdown` |
| **Errors** | -- | `error` |

## Storage

### Server-side

SQLite in WAL mode. The server stores encrypted blobs only -- it cannot read message content.

```
/var/sshkey-chat/data/
├── users.db              # devices, epoch keys, conversations, profiles, push tokens, read positions
├── room-general.db       # encrypted messages, reactions, pins for "general"
├── room-engineering.db   # encrypted messages for "engineering"
├── conv-xK9mQ2pR.db     # encrypted DM messages
└── files/                # encrypted file blobs
```

### Schema: users.db

```sql
-- Device registry (per user, per device)
CREATE TABLE devices (
    user TEXT, device_id TEXT, last_synced TEXT, created_at TEXT,
    PRIMARY KEY (user, device_id)
);

-- Wrapped epoch keys (rooms only, per user per epoch)
CREATE TABLE epoch_keys (
    room TEXT, epoch INTEGER, user TEXT, wrapped_key TEXT,
    PRIMARY KEY (room, epoch, user)
);

-- DM conversations
CREATE TABLE conversations (id TEXT PRIMARY KEY, created_at TEXT);
CREATE TABLE conversation_members (
    conversation_id TEXT, user TEXT, joined_at TEXT DEFAULT (datetime('now')),
    PRIMARY KEY (conversation_id, user),
    FOREIGN KEY (conversation_id) REFERENCES conversations(id)
);

-- User room join tracking (first_seen / first_epoch filtering)
CREATE TABLE user_rooms (
    user TEXT, room TEXT, first_seen INTEGER, first_epoch INTEGER,
    PRIMARY KEY (user, room)
);

-- Read positions (per device, per room/conversation)
CREATE TABLE read_positions (
    user TEXT, device_id TEXT, room TEXT, conversation_id TEXT,
    last_read TEXT, ts INTEGER,
    PRIMARY KEY (user, device_id, room, conversation_id)
);

-- Push notification tokens
CREATE TABLE push_tokens (
    user TEXT, device_id TEXT, platform TEXT, token TEXT,
    updated_at TEXT DEFAULT (datetime('now')), active INTEGER DEFAULT 1,
    PRIMARY KEY (user, device_id)
);

-- Revoked devices
CREATE TABLE revoked_devices (
    user TEXT, device_id TEXT, revoked_at TEXT, reason TEXT,
    PRIMARY KEY (user, device_id)
);

-- Pending key requests (unknown SSH keys that tried to connect)
CREATE TABLE pending_keys (
    fingerprint TEXT PRIMARY KEY, remote_addr TEXT,
    attempts INTEGER, first_seen TEXT, last_seen TEXT
);

-- User profiles
CREATE TABLE profiles (
    user TEXT PRIMARY KEY, display_name TEXT, avatar_id TEXT, status_text TEXT
);
```

### Schema: room/conversation DBs

```sql
-- Messages (encrypted blobs, server cannot read content)
CREATE TABLE messages (
    id TEXT PRIMARY KEY, sender TEXT, ts INTEGER, epoch INTEGER,
    payload TEXT, file_ids TEXT, signature TEXT, wrapped_keys TEXT,
    deleted INTEGER DEFAULT 0
);

-- Reactions (encrypted, server cannot read emoji)
CREATE TABLE reactions (
    reaction_id TEXT PRIMARY KEY, message_id TEXT, user TEXT, ts INTEGER,
    epoch INTEGER, payload TEXT, signature TEXT, wrapped_keys TEXT
);

-- Pinned messages (rooms only)
CREATE TABLE pins (
    message_id TEXT PRIMARY KEY, pinned_by TEXT, ts INTEGER
);
```

## Config hot-reload

The server watches config files via fsnotify and reloads on SIGHUP.

**Hot-reloadable (no restart):** users, rooms, admins, rate limits, retention, file limits, device limits, sync settings.

**Requires restart:** port, bind address.

On reload, the server notifies affected connected clients (updated room lists, join/leave events) and triggers epoch rotation for rooms with membership changes.

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
sshkey/
├── cmd/
│   ├── sshkey-server/     # server entry point
│   └── sshkey-ctl/        # admin CLI tool
├── init/                  # systemd service file
├── internal/
│   ├── config/            # TOML config parsing + validation
│   ├── protocol/          # wire format message types + NDJSON codec
│   ├── push/              # APNs + FCM push notification senders
│   ├── server/            # SSH server, session handling, all protocol logic
│   └── store/             # SQLite storage (messages, devices, epochs, conversations)
├── testdata/config/       # example config files for testing
├── go.mod
└── go.sum
```

## Related repositories

| Repo | Description |
|---|---|
| [sshkey](https://github.com/brushtailmedia/sshkey) | Server + admin tool + Go core library (this repo) |
| [sshkey-term](https://github.com/brushtailmedia/sshkey-term) | Terminal client (Go + Bubble Tea + libghostty) |
| [sshkey-app](https://github.com/brushtailmedia/sshkey-app) | Desktop + mobile GUI client (Rust + egui) |

## Testing

```bash
go test ./...
```

Tests cover the full handshake, room messaging with isolation, sync on reconnect, history scroll-back, DM conversations with wrapped_keys validation, and storage operations.

## Building a client

See [PROTOCOL.md](PROTOCOL.md) for the complete protocol reference -- everything you need to build a compatible client in any language. Includes wire format, all message types with JSON examples, crypto specs, key wrapping, and a minimal client checklist.

## Design

See [PROJECT.md](PROJECT.md) for the full design document including threat model, cryptographic primitives, key exchange protocols, epoch rotation, replay detection, and safety numbers.

## License

MIT
