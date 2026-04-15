# sshkey-chat

> Server architecture, design philosophy, and operational reference. For the wire protocol see [PROTOCOL.md](PROTOCOL.md). For client-specific implementation details see each client's own docs (e.g., sshkey-term's [DESIGN.md](https://github.com/brushtailmedia/sshkey-term/blob/main/DESIGN.md)).

**[sshkey.chat](https://sshkey.chat)**

A private messaging platform that uses SSH for transport, encryption, and authentication. End-to-end encrypted -- the server never sees message content. No accounts, no passwords, no OAuth. Your identity is your SSH key.

Inspired by [shazow/ssh-chat](https://github.com/shazow/ssh-chat). Credit is in README.

**Binaries:**
- `sshkey-server` -- the chat server
- `sshkey-ctl` -- local admin tool
- `sshkey-chat` -- terminal client (Go + Bubble Tea + rasterm)
- `sshkey-app` -- GUI client (Rust + egui)

---

## Architecture

**Protocol server.** The server sends structured data over SSH. Clients render it however they want. There is no built-in text/chat fallback -- a client app is required.

```
Server machine
├── sshd (:22)              -- regular OS-level SSH (admin access, server management)
├── sshkey-server (:2222)  -- chat app, own SSH listener, own key store
├── sshkey-ctl            -- local admin tool, reads/writes config + pending log
├── /etc/sshkey-chat/
│   ├── server.toml         -- server config (port, retention settings)
│   ├── users.toml          -- seed file (first-run only, then users.db is source of truth)
│   └── rooms.toml          -- seed file (first-run only, then rooms.db is source of truth)
└── /var/sshkey-chat/
    ├── pending-keys.log    -- unrecognised keys that tried to connect
    └── data/               -- SQLite DBs (encrypted blobs -- rooms, DMs, data.db)
```

**Port separation:**
- `:22` -- system sshd, untouched. Admin SSHs in for server management, config editing, running sshkey-ctl
- `:2222` -- chat app. Own SSH listener, own key store (from `users.db`), completely independent of system SSH

```
┌──────────────────────────────────────────────┐
│                   Server (:2222)              │
│                                               │
│  ┌───────────────────────────────────────┐   │
│  │     Protocol (documented, stable)      │   │
│  └──────────┬────────────────────────────┘   │
└─────────────┼────────────────────────────────┘
              │ SSH
    ┌─────────┴───────────────────────┐
    │    Any client that speaks        │
    │    the protocol                  │
    ├─────────────────────────────────┤
    │ Terminal client (ours)           │
    │ GUI client (ours)                │
    │ Third-party clients              │
    │ Bots / scripts                   │
    └─────────────────────────────────┘
```

### Server Host Key (TOFU)

The server has its own SSH host key (generated on first run, stored in `/etc/sshkey-chat/`). Clients use trust-on-first-use, same as regular SSH:

- **First connect:** client prompts the user to accept the server's host key fingerprint. On accept, stored in the client's per-server config.
- **Subsequent connects:** client verifies the server's key matches the stored fingerprint. Mismatch = hard warning, connection refused until the user explicitly re-trusts. Prevents MITM.
- **Key display:** `sshkey-ctl host-key` prints the server's public key fingerprint for out-of-band verification.

### Connection Handshake

No raw SSH fallback. Server requires a protocol-speaking client.

```
SSH connect (:2222)
    │
    ├── Key recognised (in users.db)
    │   ├── Server sends: {"protocol":"sshkey-chat","version":1}
    │   ├── Client responds with valid handshake
    │   │   └── proceed with protocol
    │   └── No valid response within 2s
    │       ├── Server sends: "This server requires the sshkey-chat client."
    │       ├── Server sends: "Install: brew install sshkey-chat"
    │       ├── Server sends: "https://sshkey.chat"
    │       └── disconnect
    │
    └── Key not recognised
        ├── Log to pending-keys.log (fingerprint, timestamp, attempt count)
        ├── Notify connected admin clients: {"type":"admin_notify","event":"pending_key",...}
        ├── Server sends: "Your key has been received. Access is awaiting approval -- an admin has been notified. Please try again soon."
        └── disconnect
```

### Message Delivery

Persistent SSH connection. Server pushes messages in real time -- no polling.

```
Alice's client ── SSH (persistent) ── Server ── SSH (persistent) ── Bob's client

Alice sends message:
    -> client sends to server
    -> server stores in room/DM DB
    -> server pushes to all connected clients in that room/conversation
    -> Bob's client receives, renders, stores in local DB
```

**Reconnect after offline (incremental sync):**
1. Client sends `last_synced_at` timestamp
2. Server sends recent messages in paginated batches (default: last 200 per room/conversation, capped at 7 days) with only the epoch keys needed to decrypt them
3. Once caught up, switch to real-time push for new messages
4. Older history available on demand via `history` request (lazy scroll-back)

**Connection keepalive:**
- SSH keepalive packets detect dropped connections fast
- Without them, a client on flaky wifi might not know the connection died for minutes
- Both Go (`x/crypto/ssh`) and Rust (`russh`) support SSH keepalive natively

### Why no raw SSH fallback

- The features that make this project worth building (encryption, sync, local DB, attachments) don't work without a client
- A text fallback is a separate client to build and maintain inside the server process
- Every protocol change means updating two things: the real client and the text renderer
- A degraded experience may be mistaken for the product
- Effort better spent making the client trivially easy to install

---

## Security Model

### Trust Model

**End-to-end encrypted. The server never sees message content.** All messages (rooms and DMs) are encrypted client-side with keys the server never possesses. The server is a blind relay -- it routes, stores, and sequences encrypted blobs. It sees metadata (who, when, where, sizes) but not content. Same model as Signal.

**Only Ed25519 SSH keys are supported.** The cryptographic model depends on Ed25519→X25519 conversion for key wrapping and Ed25519 for message signatures. The server rejects connections from non-Ed25519 keys (RSA, ECDSA, etc.) with an error message directing the user to generate an Ed25519 key.

The server operator can see who talks to whom and when, but cannot read what they say. A compromised server exposes metadata but not message content. Two encryption models:
- **Rooms:** epoch-based key rotation (≤100 messages or ≤1 hour). Amortises wrapping cost across many members.
- **DMs and group DMs:** per-message keys. Every message carries its own unique key, wrapped for each member. Signal-level forward secrecy -- compromise of one message key exposes exactly one message.

### What encryption protects

| Threat | Room messages | DM messages | Local DB |
|---|---|---|---|
| Network eavesdropping | SSH transport encryption | SSH transport encryption | N/A |
| Server disk theft / backup exposure | E2E (encrypted blobs on disk) | E2E (encrypted blobs on disk) | N/A |
| Client device theft | N/A | N/A | SQLCipher (SSH key-derived) |
| Malicious server operator | **Content protected** (metadata exposed) | **Content protected** (metadata exposed) | Protected (key never leaves client) |
| Past key compromise | Epoch-limited (≤100 msgs or ≤1 hour) | **Per-message** (1 key = 1 message) | N/A |
| Server forging messages | Message signatures (capability) | Message signatures (capability) | N/A |
| Server swapping user keys | Key pinning + safety numbers | Key pinning + safety numbers | N/A |
| Server injecting phantom members | Member list hashing (rooms) | N/A (per-message keys, sender controls wrapping) | N/A |
| Server replaying messages | Replay detection (`seq` counter in payload) | Replay detection (`seq` counter in payload) | N/A |

### What the server sees (metadata only)

The server handles routing and storage. It sees the envelope, not the content:
- Who sends messages to which room/conversation and when (from, room/conversation, timestamp)
- Message sizes and frequency (traffic analysis)
- File IDs and file sizes (not filenames, not mime types, not content)
- Online/offline times (presence data)
- Which devices each user has (device registry)
- Typing indicators and read receipt positions (metadata)

The server does **not** see: message text, attachment filenames/types, mentions, reply references, link previews, reaction emoji. All of these are inside the encrypted payload.

The server **does** see profile data: display names, avatar images, status text. These are public metadata, not E2E encrypted.

This is inherent in any client-server architecture without onion routing. Same metadata exposure as Signal.

### Defence in depth

The security features layer:
1. **SSH transport** -- encrypted, authenticated connection (baseline)
2. **End-to-end encryption** -- all messages encrypted client-side with keys the server never sees
3. **Forward secrecy** -- rooms: epoch keys rotate every 100 messages or hourly (≤100 message exposure). DMs: per-message keys (1 message exposure). Signal-level for DMs, practical for rooms.
4. **Message signatures** -- server can't forge messages (protects authenticity)
5. **Key pinning** -- server can't silently swap user keys (detects changes after first contact)
6. **Safety numbers** -- out-of-band key verification between users (verifies correctness on first contact)
7. **Member list hashing** -- detects phantom member injection during room epoch rotation
8. **Replay detection** -- monotonic counter in encrypted payload detects server replaying old messages
9. **Device revocation** -- limit blast radius of stolen devices
10. **Admin audit log** -- accountability for administrative actions
11. **Rate limiting** -- abuse prevention
12. **Client-side encrypted DB** -- protects local history from device theft

No single layer is perfect. Together they provide meaningful E2E security without the complexity of Double Ratchet.

---

## Account Lifecycle

### Identity model

**Your Ed25519 SSH key IS your account.** There is no separate account identifier, no password, no recovery mechanism on the server. The server authenticates by matching the raw key bytes against `users.db` entries — if the key matches, you are that user; if not, the connection is rejected.

**Keys are permanent.** There is no in-band key rotation protocol. A key's relationship to a username is lifelong. When that relationship needs to end, the account is **retired** — monotonic, irreversible — and a new account is created (potentially under the same username) via admin action.

This is a deliberate design choice. The alternative — supporting rotation — would:
- Require re-wrapping every room epoch key on every rotation (complex, bug-prone — see early drafts of this document)
- Introduce a **self-hijack attack**: an attacker with a stolen key could rotate to a key they control, locking out the legitimate owner
- Complicate safety-number continuity (each rotation invalidates every verified pair)
- Muddy the philosophical claim that "your key is your identity"

The cost of not supporting rotation is that legitimate key changes (hardware upgrade, good-hygiene rotation) are rare events that require admin action. For a self-hosted team-chat deployment this is acceptable.

### Three-layer defense

| Layer | Protects against | Mechanism |
|---|---|---|
| **Passphrase** | Stolen device, key at rest | Client-side SSH key passphrase — server never sees it |
| **Device revocation** | Lazy attacker reusing the stolen device as-is | `sshkey-ctl revoke-device` → `device_revoked` event, scoped to a single `device_id` |
| **Account retirement** | Key exfiltration, suspected key compromise | `retire_me` message or admin config change — ends the account |

**Key insight:** device revocation alone is NOT crypto-level protection. `device_id` is a client-generated identifier with no cryptographic binding. An attacker who extracts the raw SSH key from a stolen device can generate a new `device_id` and reconnect as a fresh device. **Device revocation only stops an attacker who uses the stolen device as-is.** For key-theft scenarios (copy the key file, exfiltrate via malware, crack the passphrase), retirement is the only answer.

### Retirement flow

On retirement (triggered by `retire_me` from the client, or `sshkey-ctl retire-user`):

1. `users.db` record is updated: `retired = 1, retired_at = <ISO8601>, retired_reason = <...>`, display name suffixed, and room memberships cleared in `rooms.db`.
2. The server's config watcher detects the change (fsnotify) and fires the retirement transition handler.
3. SSH authentication henceforth rejects the key with "account retired".
4. All active sessions for that user are terminated with `user_retired` error code.
5. `room_event` leaves broadcast for every room the user was in; affected rooms are marked for epoch rotation (next sender triggers the new key).
6. User is removed from group DM (3+ members) `conversation_members`; `conversation_event` leaves with `reason: "retirement"` broadcast to remaining members.
7. User remains in 1:1 DM `conversation_members` (for UI continuity of the remaining party) but `send_dm`/`react`/`create_dm` reject with `user_retired` error if any target is retired.
8. `user_retired` event broadcast to all connected clients so their UIs update (retired markers, read-only DMs, exclusion from completion).
9. On next client connect, `retired_users` list is sent after `welcome` so fresh clients learn about retirements that happened offline.

### Attacker-vs-victim race

If both the legitimate user and an attacker with the stolen key attempt `retire_me` simultaneously, first-to-send wins. **This is acceptable:**
- Either outcome ends with the legitimate user needing a new account.
- The attacker's "win" amounts to denial-of-service, not privilege escalation.
- This is strictly better than the hypothetical rotation model, where an attacker could rotate the key and retain exclusive access to the account while locking the legitimate user out entirely.

### Username reuse

Retired user entries remain in `users.db` (with `retired = 1`) for historical message attribution. The display name is suffixed (e.g., "Alice" → "Alice_V1St") to free the name for reuse. To create a new account, the admin runs `sshkey-ctl approve` with the new key. The legitimate user's client sees the new fingerprint via key-pinning and gets the standard "key has changed — verify" warning, which is the correct behavior (they should verify the new account's safety number out-of-band).

### Key loss

If the user loses their key entirely (no backup, no other device with the key), they cannot self-retire. They contact the admin out-of-band, who runs `sshkey-ctl retire-user --reason key_lost`. The admin then runs `sshkey-ctl approve` to create a fresh account with the new key.

**The TUI enforces key backup** at account creation (wizard backup step with explicit "I understand there is no recovery" acknowledgement) to make this failure mode as rare as possible.

---

## Protocol Specification

### Wire Format

**NDJSON (newline-delimited JSON)** on the primary SSH channel. One JSON object per line, terminated by `\n`. Human-readable, easy to debug, trivial to parse in any language.

### SSH Channel Multiplexing

Three channels over one SSH connection:

```
SSH Connection
├── Channel 1: NDJSON    (messages, commands, sync, metadata)
├── Channel 2: Downloads (server → client: raw file bytes)
└── Channel 3: Uploads   (client → server: raw file bytes)
```

Channel 1 carries all protocol messages. Channels 2 and 3 carry raw file data in one direction each. Transfers are correlated by `upload_id` / `file_id` across channels.

**Why split uploads and downloads:** a large transfer in one direction can overlap with transfers in the other. Within a direction, concurrent transfers still serialize on a mutex (frame writes must not interleave), but upload-vs-download runs fully parallel on independent SSH channels with independent flow control.

**Binary frame format (Channels 2 and 3):** each transfer is length-prefixed so the receiver knows where one file ends and the next begins. Multiple transfers can be in-flight on the same channel, and frames are self-identifying by their id prefix.

```
Binary frame:
┌──────────────────────────────────────────────────┐
│ id_len (1 byte) │ id (variable) │ data_len (8 bytes, big-endian uint64) │ data (raw bytes) │
└──────────────────────────────────────────────────┘

Example (upload on Channel 3):
  id_len: 6
  id: "up_001"
  data_len: 45000
  data: [45000 bytes of raw file data]

Example (download on Channel 2):
  id_len: 8
  id: "file_xyz"
  data_len: 45000
  data: [45000 bytes of raw file data]
```

The `id` field is the `upload_id` (Channel 3, client→server) or `file_id` (Channel 2, server→client), matching the JSON metadata on Channel 1. The 8-byte length prefix supports files up to 16 EiB (effectively unlimited). Receiver reads id_len, then id, then data_len, then exactly data_len bytes before expecting the next frame.

**Compression:** SSH supports compression natively (`zlib@openssh.com`). Enabled at the SSH layer -- NDJSON compresses well, free optimisation, no protocol changes needed.

### Capability Negotiation (IRC model)

Features are individually negotiated, not tied to a protocol version number. Server advertises capabilities, client requests what it supports, server confirms the active set for the session.

```json
// Server -> Client (first message, advertises available capabilities)
{"type":"server_hello","protocol":"sshkey-chat","version":1,"server_id":"chat.example.com","capabilities":["typing","reactions","read_receipts","file_transfer","link_previews","presence","pins","mentions","unread","status","signatures"]}

// Client -> Server (requests capabilities it supports)
{"type":"client_hello","protocol":"sshkey-chat","version":1,"client":"terminal","client_version":"0.1.0","device_id":"dev_V1StGXR8_Z5jdHi6B-myT","last_synced_at":"2026-04-01T00:00:00Z","capabilities":["typing","reactions","file_transfer"]}

// Server -> Client (confirmed active set for this session)
{"type":"welcome","user":"alice","display_name":"Alice Chen","admin":true,"rooms":["general","engineering"],"conversations":["conv_xK9mQ2pR","conv_yL0nR3qS"],"pending_sync":true,"active_capabilities":["typing","reactions","file_transfer"]}
```

**Rules:**
- Capabilities are informational -- the server does not filter outbound messages based on the client's requested set. Clients must handle all message types gracefully regardless of which capabilities they requested.
- **Clients must ignore unknown message types and unknown fields within known message types** -- forward compatible by default. A v1 client connected to a v2 server that sends a new type just skips it. A v1 client receiving a known type with an extra field it doesn't recognise just ignores that field. No errors, no crashes. Client implementations must use lenient deserialization (no strict/deny-unknown-fields mode).
- The `version` field is reserved for major protocol-breaking changes (restructuring the handshake itself). Should be rare -- maybe never.
- New features are added as new capabilities, not new protocol versions
- Capabilities are per-device, per-server (see Device Identity below)

**Why the server stays permissive (design decision):**

The server sends every message to every client regardless of negotiated capabilities. Clients filter for display based on their own capability set. This is deliberate:

- **Forward compatibility.** A server can roll out a new feature before all clients have been updated. Old clients silently ignore messages they don't understand (per the forward-compat rule above). A strict server that filtered by capability would have to be upgraded first or clients would see degraded behaviour.
- **No spoofing attack surface.** A compromised or malicious client cannot downgrade other users by claiming it lacks capabilities it actually has, because capabilities never affect what the server routes.
- **Simpler server.** No per-message capability lookups in hot paths (message broadcast, reaction fan-out, typing indicators). The server's job is routing; filtering is presentation.
- **Clients own their UX.** A client can choose to display typing indicators for some rooms but not others, mute presence events per-device, or filter by time of day -- without renegotiating with the server.

The small cost is a modest amount of wasted bandwidth sending `typing` / `presence` / `read` events to clients that don't render them. That cost is negligible relative to actual message traffic.

The `active_capabilities` field in `welcome` is informational -- it records what the client advertised in `client_hello`, so both ends agree on the UX contract, but nothing on the server side enforces it.

### Device Identity

Each device generates a Nano ID on first launch and stores it locally. Same SSH key on different devices = different `device_id`. Server tracks state per device. **Max 10 devices per user** (configurable in `server.toml`). Server rejects new device registrations past the cap with `device_limit_exceeded` error. User revokes an old device via `sshkey-ctl revoke-device` to make room. This bounds the key wrapping cost per user during epoch rotations.

```
Nano ID: V1StGXR8_Z5jdHi6B-myT  (21 chars, 126 bits entropy, same as UUID)
Prefixed: dev_V1StGXR8_Z5jdHi6B-myT

Libraries: jaevor/go-nanoid (Go), nanoid crate (Rust)
```

**Server tracks per device:**

```
Server: data.db
┌──────────────────────────────────────────────────┐
│ user    │ device_id          │ last_synced_at     │
├─────────┼───────────────────┼───────────────────┤
│ alice   │ dev_macbook_abc    │ 2026-04-03T14:00  │
│ alice   │ dev_iphone_def     │ 2026-04-03T12:30  │
│ alice   │ dev_work_ghi       │ 2026-04-02T09:00  │
│ bob     │ dev_laptop_jkl     │ 2026-04-03T13:45  │
└──────────────────────────────────────────────────┘
```

Retention keeps messages until the oldest device for any active user has synced (capped at the hard limit).

### Multi-Server Support

Clients can connect to multiple independent servers. One local DB per server.

```
~/.sshkey-chat/
├── chat.example.com/
│   ├── messages.db          (encrypted, all rooms + DMs from this server)
│   └── files/               (cached attachments)
├── work.company.com/
│   ├── messages.db
│   └── files/
└── config.toml              (global client config, server list, device ID)
```

```toml
# ~/.sshkey-chat/config.toml

[device]
id = "dev_V1StGXR8_Z5jdHi6B-myT"

[[servers]]
name = "Personal"
host = "chat.example.com"
port = 2222
key = "~/.ssh/id_ed25519"

[[servers]]
name = "Work"
host = "work.company.com"
port = 2222
key = "~/.ssh/work_key"

# Per-server capability preferences
[servers.0.capabilities]
typing = true
reactions = true
read_receipts = false
file_auto_download = true

[servers.1.capabilities]
typing = true
reactions = true
read_receipts = true
file_auto_download = true
```

Each server is independent -- different protocol version, different capabilities, different rooms, different users. Search is per-server by default, cross-server opt-in.

**Notification muting:** per-room and per-conversation mute, stored in client config. Purely client-side -- no protocol needed. Muted rooms still receive messages and sync, just no notifications. `@mentions` override mute (configurable).

### Client DB Schema

**Full schema from day one**, regardless of which capabilities are enabled. Capabilities control behaviour (what's sent, what's displayed), not storage. Tables for reactions, read receipts, typing, etc. always exist -- they're just empty if the feature is disabled.

Enabling a feature starts populating data going forward. Historical messages won't have that data retroactively. This is expected and matches how Signal/Slack handle feature additions.

No schema migrations needed for capability changes. Ever.

### Message Types

#### Handshake

```json
// Server -> Client (first message, with capabilities)
{"type":"server_hello","protocol":"sshkey-chat","version":1,"server_id":"chat.example.com","capabilities":["typing","reactions","read_receipts","file_transfer","link_previews","presence","pins","mentions","unread","status","signatures"]}

// Client -> Server (with device ID and requested capabilities)
{"type":"client_hello","protocol":"sshkey-chat","version":1,"client":"terminal","client_version":"0.1.0","device_id":"dev_V1StGXR8_Z5jdHi6B-myT","last_synced_at":"2026-04-01T00:00:00Z","capabilities":["typing","reactions","read_receipts","file_transfer"]}

// Server -> Client (handshake complete, confirmed capabilities)
{"type":"welcome","user":"alice","display_name":"Alice Chen","admin":true,"rooms":["general","engineering"],"conversations":["conv_xK9mQ2pR","conv_yL0nR3qS"],"pending_sync":true,"active_capabilities":["typing","reactions","read_receipts","file_transfer"]}
```

#### Sync (catch-up after reconnect)

```json
// Server -> Client (paginated batches -- sync window: last 200 messages or 7 days per room, whichever is smaller)
{"type":"sync_batch","messages":[...],"epoch_keys":[{"room":"general","epoch":12,"wrapped_key":"base64..."}],"page":1,"has_more":true}
{"type":"sync_batch","messages":[...],"epoch_keys":[],"page":2,"has_more":false}

// Server -> Client (catch-up complete, switching to real-time push)
{"type":"sync_complete","synced_to":"2026-04-03T14:22:00Z"}
```

Incremental sync -- client can render messages as each batch arrives. Prevents UI freezing on large catch-ups. Room sync batches include epoch keys needed to decrypt that batch's messages. DM messages carry their own wrapped keys inline (no `epoch_keys` needed). Client stores epoch keys locally for future room decryption.

**Sync is not backup.** A new device gets recent context, not the full archive. Users scroll back on demand.

#### History (lazy scroll-back)

```json
// Client -> Server (request older messages)
{"type":"history","room":"general","before":"msg_abc123","limit":100}
{"type":"history","conversation":"conv_xK9mQ2pR","before":"msg_def456","limit":100}

// Server -> Client (room page -- includes epoch keys needed to decrypt)
{"type":"history_result","room":"general","messages":[...],"epoch_keys":[{"epoch":8,"wrapped_key":"base64..."},{"epoch":7,"wrapped_key":"base64..."}],"has_more":true}

// Server -> Client (DM page -- no epoch_keys, each message carries its own wrapped_keys)
{"type":"history_result","conversation":"conv_xK9mQ2pR","messages":[...],"has_more":true}
```

On-demand pagination for older messages. Client requests a page, server responds with messages and (for rooms) the epoch keys needed to decrypt them. DM messages carry their own wrapped keys inline -- no separate key delivery needed. `has_more: false` means the client has reached the beginning of visible history (bounded by `first_seen` and server retention). Client stores fetched messages and epoch keys in local DB -- subsequent scroll-back for the same range is served locally, no network round-trip.

**Epoch key deduplication:** the server includes all epoch keys referenced by the page's messages. The client may already have some of these keys from previous pages or sync batches -- duplicates are skipped on receipt. The keys are tiny (~100 bytes each), so sending duplicates is cheaper than adding a negotiation round-trip to agree on which keys the client needs.

#### Envelope / Payload Split

All messages (rooms and DMs) are split into an **envelope** (plaintext, server-readable for routing) and a **payload** (encrypted, server-opaque). The server handles the envelope. It never sees the payload.

**Envelope (server sees):** `type`, `from`, `room`/`conversation`, `id`, `ts`, `epoch` (rooms only), `wrapped_keys` (DMs only), `file_ids` (opaque references), `signature`

**Encrypted payload (server cannot see):** `body`, `mentions`, `reply_to`, `attachments` (filenames, mime types, thumbnail IDs), `previews` (link preview data), reaction `emoji` + `target`, `seq` (replay detection counter), `device_id` (sender's device, for per-device replay tracking)

**Room messages:** payload encrypted with the current epoch key, base64-encoded into the `payload` field.

**DM messages:** payload encrypted with a per-message key (random AES-256, generated fresh per message). The per-message key is wrapped for each member and included in the envelope as `wrapped_keys`. Each message is self-contained -- no epoch state, no rotation, no server-side key management for DMs.

#### Room Messages

```json
// Client -> Server (encrypted payload, server can't read body/mentions/attachments)
{"type":"send","room":"general","epoch":3,"payload":"base64...encrypted","file_ids":["file_xyz"],"signature":"base64..."}

// Server -> Client (server adds id, from, ts -- payload passes through untouched)
{"type":"message","id":"msg_abc123","from":"alice","room":"general","ts":1712345678,"epoch":3,"payload":"base64...encrypted","file_ids":["file_xyz"],"signature":"base64..."}
```

**Decrypted payload (client-side only):**
```json
{
  "body": "@bob agreed",
  "seq": 42,
  "device_id": "dev_V1StGXR8_Z5jdHi6B-myT",
  "mentions": ["bob"],
  "reply_to": "msg_prev123",
  "attachments": [{"file_id":"file_xyz","name":"photo.jpg","size":230000,"mime":"image/jpeg"}],
  "previews": [{"url":"https://example.com","title":"Cool Thing","description":"A thing"}]
}
```

`reply_to` references the message ID being replied to. Client renders with the quoted original. `mentions` lists usernames mentioned -- client discovers mentions on decryption and generates local notifications, even if the room is muted.

#### Direct Messages & Group DMs

DM conversations have a Nano ID (`conv_` prefix). A 1:1 DM is just a group DM with two members. All DMs reference a `conversation` ID, not a recipient username.

```json
// Client -> Server (create a new DM conversation -- name is optional)
{"type":"create_dm","members":["bob","carol"],"name":"Project Alpha"}

// Server -> Client (conversation created)
{"type":"dm_created","conversation":"conv_xK9mQ2pR","members":["alice","bob","carol"],"name":"Project Alpha"}

// Client -> Server (per-message key, wrapped for each member inline)
{"type":"send_dm","conversation":"conv_xK9mQ2pR","wrapped_keys":{"alice":"base64...","bob":"base64...","carol":"base64..."},"payload":"base64...encrypted","file_ids":["file_xyz"],"signature":"base64..."}

// Server -> Client (pushed to all conversation members -- wrapped_keys pass through)
{"type":"dm","id":"msg_def456","from":"alice","conversation":"conv_xK9mQ2pR","ts":1712345678,"wrapped_keys":{"alice":"base64...","bob":"base64...","carol":"base64..."},"payload":"base64...encrypted","file_ids":["file_xyz"],"signature":"base64..."}
```

**Per-message key model:** every DM message carries its own encryption key. The sender generates a fresh AES-256 key, encrypts the payload, wraps the key for each member (including themselves for multi-device decryption), and includes all wrapped keys in the envelope. The server validates that the set of usernames in `wrapped_keys` exactly matches the conversation's current member list before relaying -- rejects with `invalid_wrapped_keys` error if there are missing or extra members. This catches client bugs early and prevents a sender from silently excluding a member. The server cannot verify the actual cryptographic content of the wrapped keys (it can't unwrap them), only that the right set of members is addressed. Each recipient unwraps their copy with their SSH private key and decrypts the payload. The message is entirely self-contained -- no epoch state, no rotation triggers, no server-side key management.

**Forward secrecy:** compromise of one per-message key exposes exactly one message. This is Signal-level forward secrecy without Double Ratchet.

**Conversation rules:**
- Server deduplicates 1:1 conversations -- creating a DM with just `["bob"]` when a 1:1 already exists returns the existing conversation
- Group DMs are distinct -- creating a new group with the same members creates a new conversation (like Slack/Signal)
- **Phase 14: group DMs are self-governed by in-group admins.** The creator becomes the first admin; admins can add, remove, promote, demote, and rename. All admins are peers (flat model — no protected tier). The "at least one admin" invariant is enforced at every mutation path. New members cannot decrypt pre-join history (per-message wrapped keys; no backfill). See `groups_admin.md` for the full design. Pre-Phase-14 groups were immutable peer DMs with no membership changes post-creation; that decision was reversed in Phase 14.
- **Max group DM size: 150 members.** Hard cap enforced by the server (`too_many_members` error). Per-message wrapped keys scale linearly: 150 members means ~12KB of key material per message and ~15ms of crypto per send. **Recommendation for client implementers:** for groups with 50+ members, surface a warning suggesting a room instead — rooms use a shared epoch key and amortise the per-member wrapping cost. The `sshkey-term` terminal client implements this as a status-bar hint on group creation. The server does not enforce the 50-member soft threshold; it is a UX guideline only.
- Conversation list sent on connect alongside room list
- **Group naming:** `create_dm` accepts an optional `name` field. **Phase 14: rename is now admin-only** (pre-Phase-14 any member could rename). Groups without a name display as the member list (e.g., "Bob, Carol"). 1:1 DMs typically don't use names — the client displays the other person's display_name.

**Moderation (Phase 14).** Group DMs are entirely self-governed. The CLI escape hatch (`sshkey-ctl remove-from-group`, the `pending_admin_kicks` queue, the `runAdminKickProcessor` polling goroutine) has been **deleted**. Server operators stay out of group membership — the server admin manages rooms and nothing else. For ToS violations that require operator intervention, the correct recourse is `sshkey-ctl retire-user` on the offending account, which triggers the retirement cascade including per-group leave + last-admin succession. The philosophical line is clean: **rooms are admin-managed, groups and DMs are self-governed by their participants.**

#### Rename Conversation

```json
// Client -> Server (any member can rename)
{"type":"rename_conversation","conversation":"conv_xK9mQ2pR","name":"New Name"}

// Server -> Client (broadcast to all members)
{"type":"conversation_renamed","conversation":"conv_xK9mQ2pR","name":"New Name","renamed_by":"alice"}
```

Rename is a system message rendered inline: "alice renamed the group to 'New Name'". Send an empty `name` to clear it (reverts to member list display).

#### Leave Conversation

```json
// Client -> Server
{"type":"leave_conversation","conversation":"conv_xK9mQ2pR"}

// Server -> Client (pushed to remaining members)
{"type":"conversation_event","conversation":"conv_xK9mQ2pR","event":"leave","user":"alice"}
```

On leave:
- User is removed from the member list
- No key rotation needed -- per-message keys mean the next message is simply wrapped for the remaining members only. The departed user is excluded automatically.
- Conversation disappears from the user's conversation list
- User loses access to future messages (not wrapped for them); local DB retains history they already synced
- 1:1 DMs: leaving effectively archives the conversation for that user. The other party still sees it.
- If only one member remains, the conversation becomes inert (still exists, no one to talk to)
- **Delete conversation on client = leave.** When a user deletes a conversation locally, the client sends `leave_conversation` to the server (same as an explicit leave), then purges the local DB data for that conversation. There is no "delete for me only" that stays silent -- every departure notifies the other members.

#### Message Deletion

Message editing is a planned feature — see the **Future: Message Editing** section below for the full design, and `message_editing.md` for the implementation plan.

```json
// Client -> Server
{"type":"delete","id":"msg_abc123"}

// Server -> Client (pushed to all in room/conversation -- includes routing)
{"type":"deleted","id":"msg_abc123","deleted_by":"alice","ts":1712345679,"room":"room_V1StGXR8_Z5jdHi6B"}
```

**Deletion permissions:**
- **Rooms:** own messages only, or any message if the user is a server admin
- **DMs / group DMs:** own messages only, no admin override -- group DMs have no admin concept

#### Typing Indicators

Capability: `typing`

Works in rooms and DM conversations. Exactly one of `room` or `conversation` is set per message.

```json
// Client -> Server (room)
{"type":"typing","room":"general"}

// Server -> Client (pushed to others in room)
{"type":"typing","room":"general","user":"alice"}

// Client -> Server (DM / group DM)
{"type":"typing","conversation":"conv_xK9mQ2pR"}

// Server -> Client (pushed to other members of conversation)
{"type":"typing","conversation":"conv_xK9mQ2pR","user":"alice"}
```

Server-side: expire after 5 seconds if no new typing message. Client-side: show "alice is typing..." with a timeout. In group DMs, show multiple: "alice and bob are typing..."

#### Read Receipts

Capability: `read_receipts`

```json
// Client -> Server (room)
{"type":"read","room":"general","last_read":"msg_abc123"}

// Server -> Client (pushed to others in room)
{"type":"read","room":"general","user":"alice","last_read":"msg_abc123"}

// Client -> Server (DM / group DM)
{"type":"read","conversation":"conv_xK9mQ2pR","last_read":"msg_def456"}

// Server -> Client (pushed to other members)
{"type":"read","conversation":"conv_xK9mQ2pR","user":"alice","last_read":"msg_def456"}
```

Disabling is a client-side toggle. Disabled = client never sends `read` messages. Other users' receipts still display unless the user also hides incoming receipts in client settings. Pure client-side -- server doesn't need to know.

#### Reactions

Capability: `reactions`

```json
// Client -> Server (room reaction -- encrypted with epoch key)
{"type":"react","id":"msg_abc123","room":"general","epoch":3,"payload":"base64...encrypted_emoji","signature":"base64..."}

// Client -> Server (DM reaction -- per-message key, wrapped for each member)
{"type":"react","id":"msg_def456","conversation":"conv_xK9mQ2pR","wrapped_keys":{"alice":"base64...","bob":"base64..."},"payload":"base64...encrypted_emoji","signature":"base64..."}

// Server -> Client (room reaction -- server assigns a reaction_id)
{"type":"reaction","reaction_id":"react_7kQ2mR","id":"msg_abc123","room":"general","user":"alice","ts":1712345680,"epoch":3,"payload":"base64...encrypted_emoji","signature":"base64..."}

// Server -> Client (DM reaction -- wrapped_keys pass through)
{"type":"reaction","reaction_id":"react_9pL4nS","id":"msg_def456","conversation":"conv_xK9mQ2pR","user":"alice","ts":1712345681,"wrapped_keys":{"alice":"base64...","bob":"base64..."},"payload":"base64...encrypted_emoji","signature":"base64..."}

// Client -> Server (remove by server-assigned reaction_id)
{"type":"unreact","reaction_id":"react_7kQ2mR"}

// Server -> Client (room)
{"type":"reaction_removed","reaction_id":"react_7kQ2mR","id":"msg_abc123","room":"general","user":"alice"}

// Server -> Client (DM)
{"type":"reaction_removed","reaction_id":"react_9pL4nS","id":"msg_def456","conversation":"conv_xK9mQ2pR","user":"alice"}
```

Reactions use the same encryption model as the conversation they belong to: epoch key for rooms, per-message key for DMs. Server assigns a `reaction_id` (Nano ID, `react_` prefix) on creation. Removal is by `reaction_id` -- this is necessary because AES-GCM produces different ciphertext each time, so the server can't match encrypted blobs. One user can have multiple reactions on the same message. Clients decrypt and aggregate locally. Synced to client local DB.

**Reaction payload includes target message ID.** The encrypted payload for a reaction is `{"emoji":"👍","target":"msg_abc123","seq":43,"device_id":"dev_V1StGXR8_Z5jdHi6B-myT"}`, not just the emoji. On decryption, the client verifies the payload's `target` matches the envelope's `id`. Mismatch = server tampering (reaction was re-targeted to a different message). This prevents a compromised server from moving reactions between messages in the same room/epoch.

#### Pinned Messages

```json
// Client -> Server (admin or permitted user)
{"type":"pin","room":"general","id":"msg_abc123"}

// Server -> Client (pushed to all in room)
{"type":"pinned","room":"general","id":"msg_abc123","pinned_by":"alice","ts":1712345681}

// Client -> Server (unpin)
{"type":"unpin","room":"general","id":"msg_abc123"}

// Server -> Client
{"type":"unpinned","room":"general","id":"msg_abc123"}

// Server -> Client (on connect, pinned messages with full envelopes for decryption)
{"type":"pins","room":"general","messages":["msg_abc123","msg_def456"],"message_data":[{"type":"message","id":"msg_abc123","from":"alice","room":"general","ts":1712345678,"epoch":3,"payload":"base64...","signature":"base64..."}]}
```

Pinning is rooms only. DMs and group DMs do not support pinned messages -- with small member counts and per-message keys, pinning adds complexity (who has pin permission in a group DM?) for little value. Users can star/bookmark messages locally in the client if needed.

**Pin filtering for new members:** the server filters pins by the user's `first_epoch` and `first_seen`. New members only see pins from messages they can decrypt -- pins from before they joined are not sent. The `message_data` field includes full encrypted message envelopes so clients can decrypt and show pin previews immediately without scrolling back through history.

#### User Profile

Users have a display name (optional, falls back to username) and an avatar (optional, small image). Profiles are set client-side and stored on the server.

```json
// Client -> Server (update profile)
{"type":"set_profile","display_name":"Alice Chen","avatar_id":"file_avatar001"}

// Server -> Client (profile broadcast to relevant users)
{"type":"profile","user":"alice","display_name":"Alice Chen","avatar_id":"file_avatar001","pubkey":"ssh-ed25519 AAAA...abc","key_fingerprint":"SHA256:abcdef123456..."}
```

**Avatar rules:**
- **Avatars are not E2E encrypted.** They are profile data, visible to everyone the user shares rooms/conversations with. Not tied to any room or conversation epoch key. Uploaded and stored in the clear. Same for display names and status text -- all profile data is public metadata the server can see. This is the same category as presence and typing indicators.
- Uploaded via a plain file upload (not epoch-encrypted), then referenced by `file_id`
- Max upload size for avatars: 256KB (enforced server-side)
- Server stores as-is -- no server-side processing
- Avatars cached in client local DB, re-fetched only on `avatar_id` change
- Terminal client: renders via sixel/kitty/iterm2 in member list, or falls back to initials

**Client-side avatar editor:**
- User picks a photo from disk
- Client shows a circular crop overlay -- user drags/zooms the photo to frame their face
- Client processes the result before upload: crop to selection, resize to 256x256 PNG, strip EXIF metadata
- If the result exceeds 256KB, re-encode at lower quality (JPEG) or smaller dimensions until it fits
- Go: `image`, `image/png`, `image/jpeg` stdlib + `golang.org/x/image/draw` for high-quality resize
- Rust: `image` crate (resize, crop, encode, EXIF strip)
- The server never touches the image -- what the client uploads is what gets stored and served

**Profile delivery:**
- On connect: server sends `profile` for each user the client shares rooms/conversations with
- On change: server pushes updated `profile` to all users who can see the changed user
- `display_name` and `avatar_id` included in `room_list` member info and `presence` messages

#### User Status

```json
// Client -> Server (set custom status)
{"type":"set_status","text":"On vacation until Monday"}

// Client -> Server (clear status)
{"type":"set_status","text":""}
```

Status is included in presence messages:

```json
{"type":"presence","user":"alice","status":"online","display_name":"Alice Chen","avatar_id":"file_avatar001","status_text":"On vacation until Monday"}
```

#### Unread Counts

Server tracks read position per device (via read receipts). On connect, server sends unread counts:

```json
// Server -> Client (on connect, per room/conversation)
{"type":"unread","room":"general","count":12,"last_read":"msg_abc100"}
{"type":"unread","conversation":"conv_xK9mQ2pR","count":3,"last_read":"msg_def400"}
```

Client shows badge counts per room/conversation. Synced across devices via read receipts.

#### File Transfer (upload)

Capability: `file_transfer`

Metadata on Channel 1 (JSON), upload bytes on Channel 3, download bytes on Channel 2. **File content is encrypted client-side** before upload. Room files are encrypted with the epoch key. DM files are encrypted with a fresh per-file key `K_file` that travels inside the encrypted message payload (Design A — see Key Exchange below). The server stores opaque encrypted blobs -- it knows the file ID and size, but not the filename, mime type, or content.

**Content integrity:** Every upload includes a `content_hash` (BLAKE2b-256 of the encrypted bytes). The server verifies the hash on receipt and rejects on mismatch. The hash is stored and echoed on `download_start` so clients can verify before decrypting. This catches truncation, bit rot, and transit corruption. Clients apply a 30-second timeout on upload/download handshake waits to prevent hangs.

```json
// Channel 1: Client -> Server (initiate -- no filename or mime, server doesn't need them)
{"type":"upload_start","upload_id":"up_001","size":45000,"content_hash":"blake2b-256:a1b2c3...","room":"general"}

// DM / group DM upload:
{"type":"upload_start","upload_id":"up_002","size":120000,"content_hash":"blake2b-256:d4e5f6...","conversation":"conv_xK9mQ2pR"}

// Channel 1: Server -> Client (ready)
{"type":"upload_ready","upload_id":"up_001"}

// Channel 3: Client -> Server (length-prefixed binary frame, see framing above)
// File bytes are already encrypted client-side (epoch key for rooms, per-file K_file for DMs)

// Channel 1: Server -> Client (complete)
{"type":"upload_complete","upload_id":"up_001","file_id":"file_xyz"}
```

If the server rejects the `upload_start` (rate limit, size limit, etc.) it replies with `upload_error` instead of `upload_ready`. The `upload_id` is echoed so clients can fail the matching pending upload instead of hanging:

```json
{"type":"upload_error","upload_id":"up_001","code":"rate_limited","message":"Upload rate limit exceeded"}
```

Then the client sends a message referencing the `file_id`. Upload first, message second. Multiple files can be uploaded before sending one message with several attachments. The attachment metadata (filename, mime type, thumbnail ID, and for DMs the `file_key`) is inside the encrypted message payload -- the server never sees it.

**Attachment thumbnails:** the **sender** generates a small thumbnail for images and videos before upload, encrypts it, and uploads as a separate file. Both the full file and thumbnail are opaque blobs to the server. Clients download the thumbnail first (tiny, instant), full file on demand.

**Decrypted payload includes attachment metadata (room):**
```json
{
  "attachments": [{"file_id":"file_xyz","name":"photo.jpg","size":230000,"mime":"image/jpeg","thumbnail_id":"file_xyz_thumb","file_epoch":3}]
}
```

**Decrypted payload includes attachment metadata (DM):**
```json
{
  "attachments": [{"file_id":"file_xyz","name":"photo.jpg","size":230000,"mime":"image/jpeg","file_key":"base64_K_file"}]
}
```

`file_epoch` is rooms only -- it records which epoch key was used to encrypt the file bytes. If the file was uploaded during a different epoch than the message, recipients use the correct key. Usually matches the message epoch; only differs during epoch transitions. `file_key` is DMs only -- the sender generates a fresh symmetric key per attachment, encrypts the file with it, and stores the base64 key inside the encrypted payload. Recipients decrypt the payload (with their wrapped `K_msg`), read `file_key` per attachment, then decrypt each file independently.

#### File Transfer (download)

```json
// Channel 1: Client -> Server
{"type":"download","file_id":"file_xyz"}

// Channel 1: Server -> Client (server only knows file_id and size)
{"type":"download_start","file_id":"file_xyz","size":45000,"content_hash":"blake2b-256:a1b2c3..."}

// Channel 2: Server -> Client (length-prefixed binary frame, see framing above)
// Encrypted bytes -- client decrypts with the appropriate key (epoch key for rooms, file_key for DMs)

// Channel 1: Server -> Client
{"type":"download_complete","file_id":"file_xyz"}
```

If the server rejects the download (file missing, no channel open, open failed) it replies with `download_error` and nothing is written to Channel 2. Clients MUST wait for either `download_start` or `download_error` on Channel 1 before attempting to read from Channel 2 — reading speculatively would block forever on a rejected download.

```json
{"type":"download_error","file_id":"file_xyz","code":"not_found","message":"File not found: file_xyz"}
```

Clients can auto-download (images under a size threshold) or prompt the user (large files). Client-side setting. The client knows the mime type and filename from the decrypted message payload, not from the server.

#### Key Exchange

Two models, one per conversation type. The server never sees unwrapped keys in either model.

**Rooms: epoch keys (shared symmetric key, rotated periodically)**

```json
// Server -> Client (current epoch key on reconnect, so the client can send immediately)
{"type":"epoch_key","room":"general","epoch":3,"wrapped_key":"base64...encrypted_with_your_pubkey"}
```

Older epoch keys for missed messages are bundled with `sync_batch` and `history_result` messages -- not sent as a separate bulk delivery. The client receives exactly the keys it needs to decrypt each batch of messages, nothing more. See [Sync](#sync-catch-up-after-reconnect) and [History](#history-lazy-scroll-back).

New member joins a room:
```json
// Server -> Client (member list with public keys -- new member generates the next epoch key)
{"type":"epoch_trigger","room":"general","new_epoch":4,"members":[{"user":"alice","pubkey":"ssh-ed25519 AAAA..."},{"user":"bob","pubkey":"ssh-ed25519 AAAA..."},{"user":"carol","pubkey":"ssh-ed25519 AAAA..."}]}

// Client -> Server (new member wraps the key for everyone)
{"type":"epoch_rotate","room":"general","epoch":4,"wrapped_keys":{"alice":"base64...","bob":"base64...","carol":"base64..."},"member_hash":"SHA256:abc123..."}
```

**DMs and group DMs: per-message keys (unique key per message, inline)**

No server-side key management. No epoch state. No rotation triggers. Every message is self-contained:

```json
// Each message carries its own key, wrapped for each member
{"type":"send_dm","conversation":"conv_xK9mQ2pR","wrapped_keys":{"alice":"base64...","bob":"base64..."},"payload":"base64...encrypted","signature":"base64..."}
```

The sender generates a fresh AES-256 key per message, encrypts the payload, wraps the key for each member (including themselves for multi-device decryption), and includes all wrapped keys in the envelope. Recipients unwrap their copy with their SSH private key and decrypt the payload. No key exchange on connect for DMs -- every message carries everything needed to decrypt it.

**No `dm_key_unwrap`.** Clients never send unwrapped keys to the server. The server only ever holds wrapped (encrypted) keys it cannot read.

**Why two models:**
- **Rooms** have many members (10-1000). Wrapping a key per-member per-message would be wasteful. Epoch keys amortise the cost across 100 messages.
- **DMs** have few members (2-20). Per-message wrapping is cheap (2-20 wraps per message, microseconds each) and gives strictly better forward secrecy -- every message has its own key.

#### Rooms

```json
// Server -> Client (on connect or room change)
{"type":"room_list","rooms":[{"name":"general","topic":"General chat","members":12},{"name":"engineering","topic":"Core platform","members":5}]}

// Server -> Client (join/leave events)
{"type":"room_event","room":"general","event":"join","user":"carol"}
{"type":"room_event","room":"general","event":"leave","user":"carol"}

// Server -> Client (conversation join/leave events -- same pattern)
{"type":"conversation_event","conversation":"conv_xK9mQ2pR","event":"leave","user":"carol"}
```

**Leave notifications:** all leave events (rooms, DMs, group DMs) produce a visible system message in the conversation: "carol has left the conversation." Clients render these inline in the message stream, not as silent metadata. This applies to:
- Room leaves (user removed from `users.toml` or reassigned)
- DM / group DM leaves (explicit `leave_conversation` or client-side delete)

#### Conversations (DMs)

```json
// Server -> Client (on connect, list of DM conversations)
{"type":"conversation_list","conversations":[{"id":"conv_xK9mQ2pR","members":["alice","bob"]},{"id":"conv_yL0nR3qS","members":["alice","bob","carol"],"name":"Project Alpha"}]}
```

Member details (display names, avatars, key fingerprints) are delivered via `profile` messages on connect -- `conversation_list` only carries IDs and member usernames.

#### Server Shutdown

```json
// Server -> Client (graceful shutdown notification)
{"type":"server_shutdown","message":"Server restarting, back shortly","reconnect_in":10}
```

#### Presence

Capability: `presence`

```json
{"type":"presence","user":"bob","status":"online","display_name":"Bob","avatar_id":"file_bob_avatar"}
{"type":"presence","user":"bob","status":"offline","display_name":"Bob","avatar_id":"file_bob_avatar","last_seen":"2026-04-03T14:00:00Z"}
```

#### Admin Notifications

```json
// Server -> Admin client (notification only, no actions over protocol)
{"type":"admin_notify","event":"pending_key","fingerprint":"xx:yy:zz","attempts":3,"first_seen":"2026-04-03T14:22:00Z"}
```

#### Mobile Push Registration

```json
// Client -> Server (register push token)
{"type":"push_register","platform":"ios","device_id":"dev_iphone_def456","token":"apns_device_token_here"}

// Server -> Client (confirmed)
{"type":"push_registered","platform":"ios"}
```

**Token rotation:** APNs/FCM tokens can expire or rotate without notice. Clients re-send `push_register` on every foreground connect. Server upserts by `device_id` -- if the token changed, it's updated; if it's the same, it's a no-op. If a push delivery fails with an invalid token error, the server marks the token as dead and stops retrying until the client re-registers.

#### Message Signatures

Capability: `signatures`

Client signs the encrypted payload with their SSH private key. The signature is part of the envelope (server can see it, can't modify it without detection). Other clients verify using the sender's public key.

**Signing scope:** the signature covers the encrypted `payload` bytes + `room`/`conversation` + `epoch` (for rooms) or `wrapped_keys` (for DMs). This prevents the server from moving a message between rooms/conversations, replaying it into a different epoch, swapping wrapped keys, or modifying the encrypted content. Signing the encrypted payload (not the plaintext) means the server can verify signature format without needing to decrypt.

**Canonical serialization for signing:** the signed byte sequence must be identical across all client implementations. For rooms: `Sign(payload_bytes || room_name_utf8 || epoch_as_big_endian_uint64)`. For DMs: `Sign(payload_bytes || conversation_id_utf8 || wrapped_keys_canonical)` where `wrapped_keys_canonical` is the wrapped key values concatenated in sorted username order (e.g., alice's wrapped bytes then bob's then carol's, sorted lexicographically by username). All fields are raw bytes (payload is the base64-decoded ciphertext, not the base64 string). This ensures Go and Rust clients produce identical signatures for the same message.

```json
// Signature is in the envelope alongside the encrypted payload
{"type":"send","room":"general","epoch":3,"payload":"base64...encrypted","signature":"base64...ed25519_signature"}
```

**Verification rules:**
- Client stores each user's public key fingerprint on first encounter (see Key Pinning below)
- Valid signature: message displayed normally
- Missing signature (sender's client doesn't support `signatures`): displayed with a subtle "unsigned" indicator, not blocked
- Invalid signature: hard warning -- "This message failed signature verification." Displayed but visually flagged. Could indicate server tampering or a key mismatch.
- Signatures apply to all message types: room messages, DMs, group DMs. Reactions are signed. Typing indicators are not (low value, high overhead).

**What this prevents:** a compromised server forging messages as a user, replaying messages across rooms/epochs, or modifying encrypted content in transit. Combined with E2E encryption, the server can neither read nor forge messages.

#### Key Pinning (Client-Side)

Not a capability -- always active on every client.

```json
// Server -> Client (included in welcome and profile messages)
{"type":"profile","user":"alice","display_name":"Alice Chen","avatar_id":"file_avatar001","pubkey":"ssh-ed25519 AAAA...abc","key_fingerprint":"SHA256:abcdef123456..."}
```

**How it works:**
- Client maintains a local key fingerprint store (per server, in the client DB)
- On first encounter with a user: store their `key_fingerprint`. This is the pinned key.
- On subsequent encounters: compare the server-provided fingerprint against the pinned value
- Match: proceed normally
- Mismatch: hard warning -- "alice's key has changed since you last communicated. This could indicate the server has been compromised or the user's key was rotated."
- User can choose to accept the new key (updates the pin) or disconnect
- Key changes are expected to be rare (user lost their key, admin re-created account). Frequent changes are suspicious.

**What this prevents:** the server silently swapping a user's public key for one the server controls, which would let it forge signatures and decrypt keys wrapped for that user (epoch keys for rooms, per-message keys for DMs). This is critical in the E2E model -- if the server swaps Bob's public key, it could intercept wrapped keys and read all of Bob's conversations.

**TOFU limitation on join:** when a new member joins and receives the member list with public keys, they're trusting the server for all keys on first contact. Key pinning only protects against swaps for users the client has seen before. For first encounters, out-of-band verification via safety numbers is the defence.

#### Safety Numbers

Not a capability -- always available as a client-side display feature. No protocol changes.

A safety number is a two-sided code derived from both users' public keys. It proves to both parties that neither key has been swapped by the server.

**Derivation:**
```
safety_number = SHA256(sort(alice_pubkey_bytes, bob_pubkey_bytes))
display as: "1234 5678 9012 3456 7890 1234"
```

Sort the raw public key bytes lexicographically so both users compute the same value regardless of who initiates. Truncate the SHA256 hash to 24 digits (80 bits), displayed as six groups of four. Easy to read aloud over a phone call or compare side by side.

**UX:**
- Client shows a "Verify" option on each user's profile
- Displays the safety number for that pair
- Users compare via phone, in person, or any trusted channel
- If it matches, the user marks that person as "verified" (stored locally in client DB, per-server)
- If the pinned key later changes, the "verified" badge is removed and the user gets a hard warning: "alice's key has changed. Your verification is no longer valid."

**Scope:** each pair has a unique safety number. Alice-Bob is different from Alice-Carol. For rooms, you verify individual members -- if you've verified Alice and Bob individually, you trust them in any room or conversation.

**What this adds beyond key pinning:** key pinning detects key *changes* (TOFU). Safety numbers verify key *correctness* -- they confirm the server provided the genuine key on first contact, not a server-controlled substitute. This closes the main gap in the TOFU model.

Same mechanism as Signal's safety numbers and WhatsApp's security codes.

#### Member List Hashing (Rooms)

Detects phantom member injection during epoch rotation. Included in `epoch_rotate` and verified by existing members.

**How it works:**
1. Generating client receives `epoch_trigger` with member list and public keys
2. Client wraps the epoch key for all listed members
3. Client computes `member_hash = SHA256(sort(member_usernames))` -- a deterministic hash of who the key was wrapped for
4. Client includes `member_hash` in the `epoch_rotate` message
5. Server distributes the new epoch key and `member_hash` to all members
6. Each existing member computes `SHA256(sort(local_member_list))` from their own locally-tracked membership (built from `room_event` join/leave messages)
7. Match → the key was wrapped for exactly who the member expects. Proceed.
8. Mismatch → hard warning: "Room membership may have been tampered with. The new epoch key was wrapped for a different set of members than expected."

**What this catches:**
- Server injects a phantom "eve" into the member list given to the generating client → existing members' local lists won't include "eve" → `member_hash` mismatch → detected
- Server omits a member from the list (denying them the key) → `member_hash` mismatch → detected

**What it doesn't catch:**
- New members (they have no prior membership state to compare against -- they trust the server for their first list, same TOFU limitation as key pinning)
- Server that consistently tampers with both `room_event` messages and `epoch_trigger` over time -- but this requires sustained active MITM of all members, not a one-off injection

#### Replay Detection

Prevents a compromised server from replaying legitimate messages with new server-generated IDs and timestamps. Without this, the server could re-deliver a valid signed message and the recipient would see a duplicate they can't distinguish from a real new message.

**How it works:**
- Each sender maintains a monotonic counter (`seq`) per device per room or conversation, starting at 1
- The sender includes both `seq` and their `device_id` inside the encrypted payload -- the server cannot see or modify either
- Each recipient tracks the highest `seq` seen per `(sender, device_id, room/conversation)` tuple in their local DB
- On decryption: if the message's `seq` ≤ the stored high-water mark for that `(sender, device_id)`, the message is a replay → flag with a warning: "Duplicate message detected (possible replay)." Display but visually flagged, same treatment as a failed signature.
- On decryption: if `seq` is higher than expected, accept and update the high-water mark. Gaps are allowed (messages can be dropped or arrive out of order during sync).
- A new device starts at `seq=1` with no false positives -- recipients have no high-water mark for that `device_id` yet, so they accept it and build from there.

**What this catches:**
- Server replays an old message verbatim with a new `msg_id` and timestamp → `seq` is stale for that `(sender, device_id)` → detected
- Server replays across rooms/conversations → signature verification fails (signature binds to room/conversation) → detected independently

**What it doesn't catch:**
- Server withholding messages entirely (no detection mechanism for dropped messages -- inherent limitation of client-server architecture)

**Counter persistence:** `seq` high-water marks are stored in the recipient's local DB. A fresh recipient (new device, wiped DB) starts with no high-water marks -- it accepts the first `seq` it sees per `(sender, device_id)` and builds from there. This is the same TOFU pattern as key pinning. A replay attack is only effective against a recipient that has never seen the original message.

**Why per-device:** a user may send from multiple devices (laptop, phone), each maintaining its own independent counter. Without per-device tracking, a new device starting at `seq=1` would trigger false replay warnings for recipients who've seen `seq=500` from the same user's other device. Per-device counters isolate this: each device has its own monotonic sequence, and recipients track them independently. The `device_id` inside the encrypted payload is tamper-proof -- the server knows it from the session but can't modify it inside the ciphertext.

#### Device Revocation

```json
// Server -> Client (device has been revoked)
{"type":"device_revoked","device_id":"dev_macbook_abc","reason":"admin_action"}
```

Revoked via `sshkey-ctl revoke-device --user alice --device dev_macbook_abc`. Server immediately disconnects the device and rejects future connections from that device ID until re-authorised. Useful when a device is lost/stolen -- revoke the device without revoking the user's key.

Re-authorise with `sshkey-ctl restore-device --user alice --device dev_macbook_abc`.

#### Errors

```json
{"type":"error","code":"not_authorized","message":"You don't have access to room: admin","ref":"msg_abc123"}
```

**Error format:** `type` is always `"error"`. `code` is a machine-readable string (see table). `message` is a human-readable description. `ref` is optional -- the ID of the client message that caused the error (for request/response correlation).

**Error codes:**

| Code | When | Client action |
|---|---|---|
| `not_authorized` | User lacks access to room/conversation, or tried to delete another user's message without admin | Display error. Do not retry. |
| `rate_limited` | Any rate limit exceeded (messages, uploads, connections, history) | Back off. Retry after a delay. Display subtle indicator to user. |
| `message_too_large` | Message body exceeds 16KB limit | Display error. User must shorten message. |
| `upload_too_large` | File exceeds `max_file_size` or avatar exceeds `max_avatar_size` | Display error with the size limit. |
| `epoch_conflict` | Client submitted `epoch_rotate` but another client's rotation for the same epoch was accepted first | Discard generated key. Use the winning epoch key when it arrives. No user-visible error. |
| `stale_member_list` | Member list changed between `epoch_trigger` and `epoch_rotate` (someone joined or left during rotation) | Discard generated key. Wait for new `epoch_trigger` with updated member list and retry automatically. |
| `invalid_wrapped_keys` | DM `wrapped_keys` usernames don't match conversation member list (missing or extra members) | Client bug -- refetch member list and rebuild wrapped keys. Log for debugging. |
| `device_limit_exceeded` | User has reached max devices per user (default 10) | Display error directing user to revoke an old device via the admin. |
| `invalid_epoch` | Message sent with an epoch older than the previous epoch (outside two-epoch grace window) | Client's epoch key is stale. Wait for the current epoch key to arrive and resend. |
| `unknown_conversation` | `send_dm` or `history` references a conversation ID the user is not a member of, or that doesn't exist | Display error. Remove conversation from local state if it was deleted. |
| `unknown_room` | Message or request references a room the user is not in or that doesn't exist | Display error. Remove room from local state if user was removed. |

### Protocol Conventions

- **Message IDs** -- server-generated, Nano ID with `msg_` prefix
- **File IDs** -- server-generated, Nano ID with `file_` prefix
- **Upload IDs** -- client-generated, Nano ID with `up_` prefix, used only during upload flow
- **Device IDs** -- client-generated on first launch, Nano ID with `dev_` prefix, persistent
- **Conversation IDs** -- server-generated, Nano ID with `conv_` prefix, for DM and group DM conversations
- **Reaction IDs** -- server-generated, Nano ID with `react_` prefix
- **Timestamps** -- Unix epoch seconds, server is the single source of truth for ordering
- **Message body limit** -- 16KB max per message body. Server rejects with `error` if exceeded. Generous for text, prevents abuse.
- **Omitted fields** -- optional fields (attachments, previews) can be omitted entirely rather than sent as null/empty
- **Message bodies are plain text** -- no markdown, no formatting markup. What you type is what everyone sees. URLs are detected client-side for link previews. Code is just text. This keeps the protocol simple, the server dumb, and clients predictable. If a client wants to optionally render markdown-like patterns locally, that's a client-side choice -- the protocol carries plain text only.
- **Ordering guarantee** -- messages within a room or conversation are delivered in server-timestamp order. The server is the single sequencer; there is no client-side reordering. During sync, batches arrive oldest-first. During real-time push, messages arrive in the order the server processed them.
- **Two-epoch grace window (rooms only)** -- server accepts room messages encrypted with the current or previous epoch. Clients can decrypt messages from adjacent epochs during transitions. Anything older than previous epoch is rejected. This handles messages in flight during rotation without blocking senders who haven't received the new key yet. DMs don't have grace windows -- every message has its own key.
- **Monotonic epoch enforcement (rooms only)** -- clients reject any `epoch_key` or `epoch_rotate` with an epoch number ≤ their current epoch for that room. Epoch numbers only go up. Prevents replay of old epoch keys. Exception: epoch keys bundled with `sync_batch` and `history_result` are for historical decryption only and do not update the client's current epoch. DMs have no epochs to enforce.
- **Unknown message types and fields** -- silently ignored by clients for forward compatibility. Applies to both unknown `type` values and unknown fields within known types. Clients must never reject or error on unrecognised data.

---

## Server Administration

All admin tasks are done via regular SSH (port 22) on the server. No admin commands over the chat protocol.

### Config Files

```toml
# /etc/sshkey-chat/server.toml
[server]
port = 2222
bind = "0.0.0.0"
# Admin status is managed via users.db (sshkey-ctl promote/demote)

[messages]
max_body_size = "16KB"

[retention]
purge_days = 0                   # 0 = keep forever. Set to e.g. 1825 (5 years) to auto-purge.

[sync]
window_messages = 200            # max messages per room/conversation on reconnect
window_days = 7                  # max age of messages in sync window
history_page_size = 100          # messages per lazy scroll-back page

[files]
max_file_size = "50MB"                # if you increase this, also increase grace_period below
max_avatar_size = "256KB"
allowed_avatar_types = ["image/png", "image/jpeg"]  # server can only filter unencrypted uploads (avatars)

[devices]
max_per_user = 10                 # max concurrent devices per user (bounds key wrapping cost)

[rate_limits]
messages_per_second = 5          # per user, across all rooms/conversations
uploads_per_minute = 60          # per user (burst 5, refill 1/sec)
connections_per_minute = 10      # per SSH key fingerprint (prevents reconnect storms)
failed_auth_per_minute = 5       # per IP (brute force protection)
typing_per_second = 1            # per user (throttle noisy typing indicators)
history_per_minute = 50          # per user (scroll-back pagination)

[shutdown]
grace_period = "10s"             # time to finish in-flight transfers on shutdown
                                 # rule of thumb: max_file_size / 10 MB/s = minimum grace
```

```toml
# /etc/sshkey-chat/users.toml (SEED FILE — processed on first server start only)
# After first start, manage users via: sshkey-ctl approve/retire-user/promote/demote
[alice]
key = "ssh-ed25519 AAAA...abc"       # one key per user, always
display_name = "Alice Chen"
rooms = ["general", "engineering", "admin"]

[bob]
key = "ssh-ed25519 AAAA...def"
display_name = "Bob"
rooms = ["general"]
```

```toml
# /etc/sshkey-chat/rooms.toml (SEED FILE — processed on first server start only)
# After first start, manage rooms via: sshkey-ctl add-room/add-to-room/remove-from-room
[general]
topic = "General chat"

[engineering]
topic = "Core platform work"

[admin]
topic = "Admin discussion"
```

Server watches config files for changes (fsnotify) or reloads on SIGHUP.

### sshkey-ctl

Local admin tool that runs on the server. Reads/writes config files and pending key log. Not a protocol client -- no network, no auth.

```bash
# View pending key requests
sshkey-ctl pending

# Approve a user and assign rooms
sshkey-ctl approve --fingerprint xx:yy:zz --name carol --rooms general,engineering

# Reject / clear from pending log
sshkey-ctl reject --fingerprint xx:yy:zz

# Purge old messages (delete + vacuum)
sshkey-ctl purge --older-than 5y

# List users
sshkey-ctl list-users

# Remove a user
sshkey-ctl remove-user carol

# Revoke a specific device (stolen laptop, etc.)
sshkey-ctl revoke-device --user alice --device dev_macbook_abc

# Re-authorise a revoked device
sshkey-ctl restore-device --user alice --device dev_macbook_abc

# Print server host key fingerprint (for out-of-band verification)
sshkey-ctl host-key
```

### Rate Limiting & Abuse Prevention

All rate limits are per-user (identified by SSH key) unless noted. Configurable in `server.toml` under `[rate_limits]`.

| Limit | Default | Scope | Action on exceed |
|---|---|---|---|
| Messages per second | 5 | per user | `error` with `rate_limited`, message dropped |
| Uploads per minute | 10 | per user | `error` with `rate_limited`, upload rejected |
| Connections per minute | 10 | per fingerprint | Connection refused with short message |
| Failed auth per minute | 5 | per IP | Connection refused, no banner |
| Typing indicators per second | 1 | per user | Silently dropped (no error) |
| History requests per minute | 50 | per user | `error` with `rate_limited`, request rejected |
| Message body size | 16KB | per message | `error` with `message_too_large` |

**Implementation:** token bucket per user, reset on the configured interval. Lightweight -- no external dependencies. Rate limit state is in-memory only, lost on restart (acceptable -- restarts are rare and the limits rebuild instantly).

**Monitoring:** rate limit violations are logged at warn level. Admin monitors via server logs (`journalctl` or `server.log`). No automated escalation -- admin decides action via `sshkey-ctl`.

### Graceful Server Shutdown

On SIGTERM or SIGINT, the server shuts down cleanly:

```
1. Stop accepting new connections
2. Broadcast to all connected clients:
   {"type":"server_shutdown","message":"Server restarting, back shortly","reconnect_in":10}
3. Wait grace_period (default 10s) for clients to finish in-flight operations
4. Flush all pending DB writes (WAL checkpoint)
5. Close all SSH connections
6. Exit
```

Clients receiving `server_shutdown` should:
- Save any unsent drafts locally
- Show the server message to the user
- Begin reconnect attempts after `reconnect_in` seconds (with exponential backoff)
- Resume via normal incremental sync on reconnect

### Config File Hot Reload

User and room data lives in SQLite databases (`users.db`, `rooms.db`). Changes via `sshkey-ctl` CLI take effect immediately — the server reads from DB on demand, no reload needed. Server watches `server.toml` via fsnotify for hot-reload of runtime settings.

**Immediate (via `sshkey-ctl`, no restart):**
- User management — `approve`, `retire-user`, `remove-user`, `promote`, `demote`
- Room management — `add-room`, `add-to-room`, `remove-from-room`

**Hot-reloadable (server.toml, no restart):**
- `[retention]`, `[files]`, `[rate_limits]`, `[messages]`, `[sync]`, `[devices]`, `[logging]`

**Requires restart:**
- `server.toml`: `port`, `bind` (can't rebind a listening socket)
- SSH host key changes

### Admin Audit Log

Append-only log of all administrative actions. Stored at `/var/sshkey-chat/audit.log`.

```
2026-04-03T14:22:00Z  sshkey-ctl  approve    user=carol fingerprint=xx:yy:zz rooms=general,engineering
2026-04-03T14:25:00Z  sshkey-ctl  reject     fingerprint=aa:bb:cc
2026-04-03T15:00:00Z  server      reload     trigger=fsnotify file=users.toml changes="+carol"
2026-04-03T15:10:00Z  sshkey-ctl  remove     user=dave
2026-04-03T16:00:00Z  sshkey-ctl  revoke-device  user=alice device=dev_macbook_abc
2026-04-03T18:00:00Z  server      shutdown   signal=SIGTERM grace=10s clients=12
```

Every `sshkey-ctl` command and every server-initiated action (config reload, shutdown) gets a timestamped entry. Not tamper-proof against root, but creates accountability and makes forensics possible after an incident.

### Admin Notifications

Admins (defined in `server.toml`) receive pending key alerts in their chat client:

```json
{"type":"admin_notify","event":"pending_key","fingerprint":"xx:yy:zz","attempts":3,"first_seen":"2026-04-03T14:22:00Z"}
```

Notification only -- no admin actions over the protocol. Admin sees the alert, SSHs into the server on port 22, runs `sshkey-ctl approve`.

### Server Operational Log

Structured JSON log for day-to-day server operations. Separate from the admin audit log (which covers administrative actions only). Stored at `/var/sshkey-chat/server.log`.

**The server never logs message content, encrypted payloads, wrapped keys, or any cryptographic material.** Only operational metadata -- the same data the server already sees for routing.

```toml
# /etc/sshkey-chat/server.toml
[logging]
level = "info"                    # debug, info, warn, error
file = "/var/sshkey-chat/server.log"
max_size_mb = 100                 # rotate at 100MB
max_files = 5                     # keep 5 rotated files
format = "json"                   # structured JSON, one object per line
```

**Log levels and what they cover:**

| Level | Events |
|---|---|
| **error** | Epoch rotation failures, DB write errors, SSH channel errors, corrupted frames on upload/download channels, key wrapping validation failures |
| **warn** | Rate limit violations, stale_member_list rejections, epoch_conflict rejections, invalid_wrapped_keys rejections, client protocol errors, push delivery failures |
| **info** | Connections, disconnections, room joins/leaves, epoch rotations (room, old_epoch, new_epoch, triggered_by, duration_ms), DM conversations created, config reloads, server start/stop |
| **debug** | Per-message routing (from, room/conversation, size_bytes -- not content), sync batches sent (user, device, pages, message_count), history requests, file uploads/downloads (file_id, size), capability negotiation |

**Example log lines:**

```json
{"ts":"2026-04-03T14:22:00.123Z","level":"info","event":"connect","user":"alice","device":"dev_macbook_abc","ip":"192.168.1.10","capabilities":["typing","reactions","file_transfer"]}
{"ts":"2026-04-03T14:22:00.456Z","level":"info","event":"sync","user":"alice","device":"dev_macbook_abc","rooms":3,"conversations":2,"messages":47,"pages":1,"duration_ms":82}
{"ts":"2026-04-03T14:25:12.789Z","level":"info","event":"epoch_rotate","room":"general","old_epoch":3,"new_epoch":4,"triggered_by":"alice","trigger":"message_count","members":12,"duration_ms":34}
{"ts":"2026-04-03T14:25:13.001Z","level":"warn","event":"epoch_conflict","room":"engineering","epoch":7,"rejected_client":"bob","accepted_client":"carol"}
{"ts":"2026-04-03T14:30:00.000Z","level":"warn","event":"rate_limited","user":"dave","limit":"messages_per_second","count":8,"threshold":5}
{"ts":"2026-04-03T14:35:00.000Z","level":"info","event":"disconnect","user":"alice","device":"dev_macbook_abc","reason":"client_closed","session_duration":"13m00s"}
{"ts":"2026-04-03T15:00:00.000Z","level":"error","event":"epoch_rotate_failed","room":"general","epoch":5,"triggered_by":"bob","error":"client_timeout","fallback":"next_sender"}
```

**What is never logged (any level):** message bodies, encrypted payloads, plaintext keys, wrapped keys, key material, signature values, decrypted content, file content, file names, mime types, emoji, reaction content, profile display names, status text. The log contains the same metadata the server handles for routing -- nothing more.

**Log rotation:** built-in size-based rotation. When `server.log` reaches `max_size_mb`, it rotates to `server.log.1`, previous `.1` becomes `.2`, etc. Oldest beyond `max_files` is deleted. No external dependency (logrotate not required, but compatible if preferred).

---

## Reference

- ssh-chat: https://github.com/shazow/ssh-chat (reference for SSH server setup, Go `x/crypto/ssh` patterns)
- Language: Go (server, terminal client), Rust (GUI client)
- License: MIT (ssh-chat), new project under own license

---

## Rooms / Channels

- **Persistent rooms** -- stored in `rooms.db`, survive server restarts. Room identity is nanoid-based (`room_` prefix), display names are mutable.
- **Room-specific permissions** -- per-user room access managed via `rooms.db` (`room_members` table), controlled by `sshkey-ctl add-to-room/remove-from-room`
- **Topic / description** -- stored per room in `rooms.db`
- **Room list on connect** -- client receives list of rooms the user has access to
- **Self-leave policy** -- off by default. `[server] allow_self_leave_rooms = false` (the default) keeps membership admin-managed. Set to `true` to let users `/leave` rooms on their own. Hot-reloadable — the server reads the flag under the cfg RLock on every `leave_room` / `delete_room`, so a config reload takes effect without client action.
- **Room retirement** -- admins can permanently archive a room via `sshkey-ctl retire-room`. Retirement is *monotonic*: once set, `retired_at` is never cleared. Retired rooms:
  - Get a 4-character base62 suffix appended to their display name (e.g. `general` → `general_A3fQ`) so admins can create a new room with the original name without collision
  - Reject all writes (`send`, `react`, `pin`, `unpin`) with `room_retired` error code
  - Freeze epoch rotation — no new keys are generated, but existing history remains decryptable with the epoch keys clients already hold
  - Are broadcast to connected members via `room_retired`; offline devices get the list via `retired_rooms` during the handshake catchup
  - Can be removed from a user's view via `/delete` (governed by `allow_self_leave_retired_rooms`, default `true`)
- **`/delete` for rooms** -- sends `delete_room`, which records a `deleted_rooms` sidecar row, runs the leave logic, and echoes `room_deleted` to the deleter's sessions. The sidecar drives offline-device catchup via `deleted_rooms` in the handshake, so a user who `/delete`'d a room from their laptop also sees it removed when their phone reconnects. The sidecar row survives any last-member cleanup cascade because `DeleteRoomRecord` deliberately does not touch `deleted_rooms`.
- **CLI is local-only** -- `sshkey-ctl retire-room` writes directly to the server DB and enqueues a `pending_room_retirements` row. A background goroutine (5s poll) drains the queue and broadcasts to connected members. This mirrors the Phase 11 `pending_admin_kicks` pattern and keeps remote admin verbs out of the chat protocol.

---

## File Sharing & Inline Media

The server stores encrypted file blobs and serves them via the upload/download channels (Channels 2 and 3). The server cannot see file content, filenames, or mime types. Display is entirely a client-side concern.

### File type handling (client-side)

| mime type | GUI client (Rust + egui) | Terminal client |
|---|---|---|
| `image/jpeg`, `image/png`, `image/gif` | inline render (egui native) | inline via sixel/kitty/iterm2 or placeholder |
| `audio/mpeg`, `audio/ogg`, `audio/flac`, `audio/wav` | inline player widget via `rodio` (play/pause/seek/progress) | filename + size, open command |
| `video/mp4`, `video/webm` | inline playback via `egui-video-rs` (pure Rust, no ffmpeg) | filename + size, open command |
| `application/pdf` | click to open in system viewer | filename + size, open command |
| `text/plain`, `text/csv` | inline preview | inline preview |
| anything else | icon + filename + size, click to open | filename + size, open command |

50MB max file size means no massive videos -- inline playback is viable for everything within the limit.

"Open" calls the system default handler (`open` on macOS, `xdg-open` on Linux).

### GUI client media libraries

- **Images:** egui native image rendering
- **Audio:** `rodio` (pure Rust decoders via Symphonia, MP3/FLAC/WAV/OGG, background thread, non-blocking)
- **Video:** `egui-video-rs` (pure Rust fork, no ffmpeg/sdl2 dependency, CPU-decoded, fine for chat-sized clips under 50MB)

Files sync to the client's local DB / file cache. Viewable offline.

### Terminal client image protocols

- **Sixel** -- xterm, foot, WezTerm, mlterm, Contour
- **iTerm2 inline image protocol** -- iTerm2, WezTerm, Mintty
- **Kitty graphics protocol** -- Kitty, expanding adoption

Handled entirely client-side. Fall back to text placeholder + download for unsupported terminals.

---

## Message History / Persistence

### Scrollback Rules

- On connect, user receives the sync window (last 200 messages or 7 days per room, configurable via `[sync]` in `server.toml`)
- **New users cannot see history from before they were added.** Server applies filters per user:
  - `first_seen` (timestamp) -- only messages where `timestamp >= first_seen` are served. Policy-enforced. Applies to rooms and DMs.
  - `first_epoch` (epoch number, rooms only) -- only room messages where `epoch >= first_epoch` are served. Crypto-enforced -- the user literally cannot decrypt messages from earlier epochs (they don't have the keys). This also filters out grace window messages sent by other members with the old epoch during the brief join transition.
  - DMs don't need `first_epoch` -- members are set at conversation creation and per-message keys are only wrapped for current members. Old DM messages from before a member existed in the conversation were never wrapped for them.
- For rooms, both filters apply. A message must pass both to be delivered.
- If a user is removed and re-added, they get a new `first_seen` and (for rooms) a new `first_epoch` -- previous history window is closed. Clean break.
- Admin override possible via `users.toml`: `history_from = "2026-01-01"` to grant access to older room history. This relaxes `first_seen` only -- the user still needs epoch keys for those older messages, which would need to be provided separately.

### Message Deletion

Same model as Signal/WhatsApp -- best-effort, no false promises. Message editing is a planned feature (see **Future: Message Editing** below and `message_editing.md`), tracked alongside delete rather than instead of it.

- User sends a delete request for a message ID via the protocol (own messages only, admins can delete any)
- Server removes message from DB (or marks as tombstone)
- Server pushes delete event to all connected clients in that room/conversation
- Connected clients remove from display immediately
- Offline clients receive the tombstone on next sync and remove from local DB. Tombstones are interleaved with regular messages in `sync_batch` and `history_result`:
  ```json
  {"type":"deleted","id":"msg_abc123","deleted_by":"alice","ts":1712345679,"room":"room_V1StGXR8_Z5jdHi6B"}
  {"type":"deleted","id":"msg_def456","deleted_by":"bob","ts":1712345700,"dm":"dm_xK9mQ2pR"}
  ```
  Client processes tombstones in order: if the original message exists in local DB, remove it; if not (message was before the client's sync window), ignore the tombstone.
- Accept that a determined user with a modified client or DB backup could retain anything they've already seen -- this is an inherent limitation of client-side storage and not worth adding complexity to fight

### Database Architecture

```
Server                              Client (per server)
┌─────────────────────┐             ┌─────────────────────┐
│ room-general.db     │             │                     │
│ room-engineering.db │  ── sync -> │ messages.db         │
│ conv-xK9mQ2pR.db   │             │ (single encrypted   │
│ conv-yL0nR3qS.db   │             │  DB, all rooms +    │
│ data.db (metadata, │             │  all DMs, one FTS5  │
│  device tracking,   │             │  index)             │
│  profiles)          │             │                     │
└─────────────────────┘             └─────────────────────┘
```

**Server: separated by access boundary. Server stores encrypted blobs only.**
- One DB per room -- encrypted message blobs, scoped to room permissions
- One DB per DM conversation (`conv-{id}.db`) -- covers both 1:1 and group DMs. Encrypted blobs. All members read/write the same DB.
- `data.db` for metadata (sync watermarks per device, first_seen, key-to-user mapping, device registry, profiles/display names/avatar references, wrapped epoch keys for rooms)
- Server maintains a mapping of `user -> [accessible conversation DBs]`
- When a user is removed: revoke access to room DBs, trigger epoch rotation for rooms (remaining members get new key). DMs need no action -- per-message keys mean the next message simply won't be wrapped for the removed user.

**E2E encryption -- two models:**

No server master key. The server never sees unwrapped keys or message content.

- **Rooms:** epoch keys -- AES-256 symmetric keys shared by all members, rotated every 100 messages or hourly. Each epoch key is wrapped per-member with SSH public keys. Server stores wrapped keys (opaque). Amortises wrapping cost for large groups.
- **DMs and group DMs:** per-message keys -- a fresh AES-256 key per message, wrapped for each member inline. No server-side key state. Signal-level forward secrecy (one key = one message).

**Cryptographic primitives:**

| Operation | Algorithm | Details |
|---|---|---|
| Room epoch key | AES-256-GCM | 256-bit random key, generated by client, shared across members for the epoch |
| DM per-message key | AES-256-GCM | 256-bit random key, generated fresh per message, used once and discarded |
| Message encryption | AES-256-GCM | Encrypt payload with the relevant key (epoch for rooms, per-message for DMs). 96-bit random nonce prepended to ciphertext. **Nonce reuse breaks GCM** -- always generate a fresh random nonce per encryption operation. |
| Key wrapping | X25519 + HKDF + AES-256-GCM | Ed25519 keys converted to X25519 for ECDH. Ephemeral X25519 keypair per wrap operation. Shared secret derived via ECDH, then HKDF-SHA256 to derive wrapping key. Symmetric key encrypted with AES-256-GCM. Wrapped output = ephemeral public key + nonce + ciphertext. Same algorithm for epoch keys and per-message keys. |
| Message signatures | Ed25519 | Rooms: Sign(payload_bytes \|\| room \|\| epoch). DMs: Sign(payload_bytes \|\| conversation \|\| wrapped_keys_canonical). See [canonical serialization](#message-signatures). |
| Local DB encryption | AES-256 (SQLCipher) | Key derived from SSH private key via HKDF-SHA256 |

**Key wrapping in detail (same for epoch keys and per-message keys):**
```
Wrapping a symmetric key for Alice:
1. Generate ephemeral X25519 keypair (eph_priv, eph_pub)
2. Convert Alice's Ed25519 public key → X25519 public key
3. ECDH: shared_secret = X25519(eph_priv, alice_x25519_pub)
4. HKDF-SHA256(shared_secret, salt=eph_pub, info="sshkey-chat key wrap") → wrapping_key
5. AES-256-GCM(wrapping_key, random_nonce, symmetric_key) → ciphertext
6. wrapped_key = eph_pub || nonce || ciphertext

Unwrapping:
1. Parse eph_pub, nonce, ciphertext from wrapped_key
2. Convert Alice's Ed25519 private key → X25519 private key
3. ECDH: shared_secret = X25519(alice_x25519_priv, eph_pub)
4. HKDF-SHA256(shared_secret, salt=eph_pub, info="sshkey-chat key wrap") → wrapping_key
5. AES-256-GCM-Open(wrapping_key, nonce, ciphertext) → symmetric_key
```

Go: `x/crypto/curve25519`, `crypto/aes`, `crypto/cipher`, `x/crypto/hkdf`. Rust: `x25519-dalek`, `aes-gcm`, `hkdf` crates.

```
Room "general" (epoch 3):
  wrapped_key_alice = wrap(epoch_key, alice_pubkey)  // X25519 + HKDF + AES-256-GCM
  wrapped_key_bob   = wrap(epoch_key, bob_pubkey)
  wrapped_key_carol = wrap(epoch_key, carol_pubkey)

  Server stores: [wrapped_key_alice, wrapped_key_bob, wrapped_key_carol]
  Server knows: nothing about the actual epoch_key

  Alice connects → server sends wrapped_key_alice → Alice unwraps locally → can encrypt/decrypt
```

**Server restart:** no self-healing needed. The server never had unwrapped keys. On restart, it sends stored wrapped epoch keys to reconnecting clients, who unwrap locally. DMs need nothing on restart -- every message carries its own keys.

**Room key rotation on member change:**

- **Member joins → new member rotates the key.** The joining client generates a new epoch key, wraps it for all members (including themselves), and sends the wrapped keys to the server. Server distributes to everyone. No waiting, no dependency on another member being online. The join itself is the rotation event. Clean epoch boundary: pre-join messages = old epoch the new member can't read, post-join messages = new epoch.

  ```
  Carol joins "general":
  1. Server sends Carol the member list with public keys (epoch_trigger)
  2. Carol generates new epoch key (epoch N+1)
  3. Carol wraps for alice, bob, carol
  4. Carol sends epoch_rotate to server
  5. Server validates, distributes → everyone switches to epoch N+1
  6. Server sends epoch_confirmed to Carol
  7. Carol can now post with the confirmed epoch key
  ```

  The server provides member public keys to the joining client. This is the same data used for key pinning -- Carol's client pins every key on first encounter and verifies on future encounters.

- **Member leaves → next sender rotates.** Server marks rotation as pending. The next member to send a message receives `epoch_trigger`, generates a new key wrapping only for remaining members. Departing member has old epoch keys but not the new one.

- **Member's SSH key revoked:** same as leave -- rotate forward, wrap with remaining valid keys.

**DM member changes are trivial.** Leave → next message simply isn't wrapped for the departed member. Join → next message includes the new member in `wrapped_keys`. No rotation, no state changes, no server involvement beyond updating the member list.

**Epoch-based forward secrecy (rooms only):**

Automatic epoch key rotation for rooms. Rotation triggers every 100 messages or every hour, whichever comes first. DMs use per-message keys and don't need rotation -- every message already has its own unique key.

**Rotation flow (server-triggered, client-executed):**
1. Server counts messages (encrypted blobs -- it doesn't need to read them)
2. At 100 messages or 1 hour, server marks the conversation as "rotation pending"
3. Server sends `epoch_trigger` to the client that sent the triggering message
4. That client generates a new AES-256 epoch key
5. Client wraps it with every member's public key (provided in the trigger)
6. Client sends `epoch_rotate` with wrapped keys to server
7. Server stores and relays wrapped keys -- never sees the unwrapped key
8. All members unwrap locally and switch to the new epoch. Pending state cleared.

```
Epoch 1 (key_a): messages 1-100     ← if key_a is compromised, only these are exposed
Epoch 2 (key_b): messages 101-200
Epoch 3 (key_c): messages 201-300   ← current epoch, key_c only exists in client memory
```

**Rotation resilience:** if the triggered client doesn't respond within 5 seconds (crash, disconnect, flaky connection), the server sends `epoch_trigger` to the next member who sends a message. Every message sent while rotation is pending is another trigger attempt. Messages continue with the old epoch key during this window -- degraded forward secrecy, but no blocked conversations, no data loss. The moment any client completes the rotation, the epoch advances and pending state clears. The time-based trigger (hourly) also re-triggers if the message-based trigger hasn't completed.

**Race conditions and edge cases (rooms only -- DMs have no race conditions because per-message keys are stateless):**

- **Two rotations collide** (e.g., member join + 100th message simultaneously): server tracks epoch numbers. First `epoch_rotate` for epoch N+1 wins, second is rejected with `epoch_conflict` error. Losing client discards their key and uses the winning one.
- **Two members join simultaneously:** server serialises. First joiner rotates, second joiner receives the first joiner's epoch key from the server and joins without rotating.
- **Member leaves during rotation:** the rotating client submits `epoch_rotate` with a member list that includes the departed member. Server validates the member list against current membership on receipt. If stale (someone left), server rejects with `stale_member_list` error and re-triggers with the updated member list. No epoch key is ever distributed to a departed member.
- **Member joins during rotation:** Alice is wrapping epoch N+1 (doesn't include Carol who just joined). Alice completes N+1. Carol triggers her own rotation on join (epoch N+2). Two back-to-back rotations. Any messages in the brief N+1 window are pre-Carol (covered by `first_seen`). Correct behaviour, not a bug.
- **Epoch transition -- messages in flight with old key:** Bob hasn't received epoch 4 yet and sends a message with epoch 3. This is valid -- Bob legitimately has epoch 3. Server accepts messages from both the current and previous epoch (two-epoch grace window). Clients must decrypt messages from adjacent epochs during transition. Client switches to the new epoch for **sending** as soon as it receives the new key. Client accepts **receiving** from current and previous epoch. Previous means exactly one epoch back -- anything older is rejected.
- **Epoch replay attack:** server replays an old `epoch_rotate` to roll a conversation back to a compromised key. Clients enforce monotonic epoch numbers -- any `epoch_key` or `epoch_rotate` with an epoch ≤ the client's current epoch for that conversation is rejected. Epoch numbers only go up. Epoch keys bundled with `sync_batch` and `history_result` are for historical decryption only and do not update the client's current epoch.
- **File upload epoch mismatch:** Alice uploads a file encrypted with epoch 3. Before sending the message, the room rotates to epoch 4. The message payload is epoch 4, the file bytes are epoch 3. Fix: the encrypted payload records `file_epoch` per attachment. Recipients use the correct epoch key to decrypt each file. Both keys exist in their local DB. (DM files don't have this problem -- each DM attachment is encrypted with its own fresh `K_file` carried in the payload's `file_key` field, independent of any epoch.)

```json
// Server -> Client (you triggered rotation, generate the new key)
// Includes member public keys so the client can wrap for everyone
{"type":"epoch_trigger","room":"general","new_epoch":4,"members":[{"user":"alice","pubkey":"ssh-ed25519 AAAA..."},{"user":"bob","pubkey":"ssh-ed25519 AAAA..."},{"user":"carol","pubkey":"ssh-ed25519 AAAA..."}]}

// Client -> Server (new key, wrapped for each member)
{"type":"epoch_rotate","room":"general","epoch":4,"wrapped_keys":{"alice":"base64...","bob":"base64...","carol":"base64..."},"member_hash":"SHA256:abc123..."}

// Server -> Client (rotation accepted and distributed)
{"type":"epoch_confirmed","room":"general","epoch":4}
```

**The generating client must not use the new epoch key for anything until `epoch_confirmed` is received.** The key is treated as pending -- not stored as the active epoch, not used to encrypt messages. If the server rejects the rotation, the client discards the key entirely. It only becomes real when the server confirms acceptance and distribution.

**Flow for a new member joining:**
1. Carol receives `epoch_trigger` with member list
2. Carol generates epoch key, wraps for all members, sends `epoch_rotate`
3. Server validates member list, accepts, distributes wrapped keys to all online members
4. Server sends `epoch_confirmed` to Carol
5. Carol's input unlocks -- she can now post with the confirmed epoch key

If the rotation is rejected (stale member list, race condition), server sends an `error` instead of `epoch_confirmed`. Carol's client receives a new `epoch_trigger` with the updated member list and retries. Input stays locked until a rotation succeeds.

**Flow for existing members (100-message rotation):**
Same rule -- must not use the new epoch key until `epoch_confirmed`. They can continue sending with the old epoch key (two-epoch grace window) during the brief wait. New members have no old key, so they wait with input locked.

**New conversations (DMs):**
DMs use per-message keys, so `create_dm` carries no encryption data. The server responds with `dm_created` containing the conversation ID. The first message to the conversation carries its own per-message key like any other DM message. No key exchange step, no waiting.

**New room members never see grace window messages.** The server tracks each user's `first_epoch` (the epoch they joined at). Carol's first epoch is N+1 (the one she generated). Server only delivers messages from epoch N+1 onward to Carol. Any epoch N messages sent by other members during the brief transition window are not delivered to her -- they're pre-join messages from her perspective. This extends the existing `first_seen` timestamp filtering to the epoch level. No undecryptable messages ever reach a new member's client.

**New group DM members never see pre-join messages or audit events.** The group-DM analogue of `first_seen` on `room_members` is `joined_at` on `group_members` (set to `datetime('now')` on every `AddGroupMember` INSERT). `syncGroup` raises `sinceTS` to `joinedAt` before querying messages and events; `handleHistory`'s group branch post-filters messages by `m.TS < joinedAt`. The wrapped-key crypto model already prevents DECRYPTION of pre-join messages (no wrapped key for the new member), but the server must also not SERVE them — pre-join timestamps, sender IDs, and `group_events` entries (past `/rename`, `/promote`, `/demote`, `/kick` audit rows) are social-graph metadata leaks even without plaintext content. Leaves + re-adds get a fresh `joined_at` so the "invisible window" while away cannot be rewound. See `groups_admin.md` "Pre-join history gate" section for the full write-up.

**Epoch key distribution ordering (rooms only):** the server must distribute epoch keys to all online members **before** relaying any messages encrypted with that epoch. If Alice receives epoch N+1 and immediately sends a message, the server must ensure Bob has received the epoch N+1 key before delivering Alice's message to Bob. SSH channel ordering guarantees this as long as the server writes the key before the message to each connection. The server queues any epoch N+1 messages for a member until their epoch key has been written to their connection. DMs don't have this problem -- every message carries its own keys.

**Offline client catch-up:**
- **Rooms:** the server stores wrapped epoch keys on disk. On reconnect, epoch keys are bundled with sync batches -- only the keys needed to decrypt messages in the sync window (last 200 messages or 7 days per room). Older epoch keys are fetched on demand with `history` pages. Client unwraps and stores keys locally as they arrive.
- **DMs:** no catch-up needed. Every DM message carries its own wrapped keys inline. The client simply unwraps each message individually as it arrives in `sync_batch` or `history_result`. No server-side key state for DMs.

**Epoch key retention on server (rooms only):** wrapped epoch keys are retained as long as the room's messages exist. Purging old messages also purges their epoch keys. DM messages store their wrapped keys inline -- they're retained and purged as part of the message itself.

Client stores epoch keys in local DB for historical room decryption. DM per-message keys are unwrapped on receipt and not stored separately -- the decrypted plaintext is stored in the local DB. Server never holds unwrapped keys -- not in memory, not on disk, not ever.

**Long-offline users:** no special handling needed. The lazy scroll-back model handles this naturally. When a user reconnects after any absence (days, months, years), they receive the sync window with bundled keys and can scroll back through everything within the server's retention window. Rooms: each `history` page bundles the epoch keys needed. DMs: each message carries its own keys. No gaps, no special reconnection flow.

**Client: single unified DB per server.**
- All rooms + all DMs in one encrypted SQLite DB
- One FTS5 index across everything -- unified search is the whole point
- Room isolation via `WHERE room_id = X`, trivial with an index
- No access control reason to separate on client side -- it's all the user's own data
- One file to encrypt, one file to back up, one schema to migrate
- Cross-room search: `SELECT * FROM messages WHERE body MATCH 'deploy' ORDER BY timestamp DESC`
- Full schema from day one -- all tables exist regardless of capabilities. No migrations for feature toggles.

### Server-Side Storage: SQLite WAL

Decision: **SQLite in WAL mode**. Flat files considered and rejected.

Why SQLite WAL:
- Concurrent reads don't block writes -- fits the "one writer, many readers" chat pattern
- Atomic writes -- no corruption on crash
- Single file per DB -- easy backup, easy reasoning
- Cleanup is simple: `DELETE WHERE timestamp < X` then `VACUUM`
- Pure Go driver available (`modernc.org/sqlite`) -- no cgo, no cross-compilation issues

Why not flat files:
- No concurrent-safe reads during writes without file locking
- Pagination requires seeking backwards from EOF or maintaining a separate index
- Cleanup means rewriting the file
- Multi-field queries (by user, date range, room) require parsing every line
- Scales poorly with large history

### Client-Side Encrypted Local DB

Each client maintains its own SQLite WAL database per server, encrypted at rest:

```
Server                          Client
┌──────────────┐                ┌──────────────────┐
│ SQLite WAL   │  ── sync ──>  │ SQLite WAL        │
│ (encrypted   │               │ (encrypted w/     │
│  blobs,      │               │  user's SSH key)  │
│  rolling     │               │ decrypted content │
│  retention)  │               │ prunable cache)   │
└──────────────┘                └──────────────────┘
```

Server stores encrypted blobs it cannot read. Client decrypts with epoch keys and stores plaintext in its own encrypted local DB.

- On connect, client sends `last_synced_at` timestamp (per device), server sends the sync window (last 200 messages or 7 days per room/conversation, whichever is smaller) with bundled epoch keys
- Older history fetched on demand via `history` requests as user scrolls back -- each page includes the epoch keys needed to decrypt it
- Local DB encrypted using key derived from user's SSH private key (HKDF -> AES-256)
- SQLCipher or go-sqlcipher / rusqlite+SQLCipher for transparent encryption -- DB file is useless without the key
- Local scrollback is instant and works offline for anything already fetched
- Fuzzy search runs against local DB -- fast, no network round-trip, only searches messages the client has fetched
- **Client-side storage is a cache, not the source of truth.** The local DB can be pruned or wiped entirely -- anything within the server's retention window can be re-fetched via `history` requests. Future mobile clients can use aggressive local retention (e.g., 30 days, 500 MB cap) and lean on lazy scroll-back. Desktop/terminal clients can keep more. The protocol is the same either way -- only the client-side defaults differ.

### Server-Side Retention / Expiry

Messages are kept indefinitely by default. The admin can purge old messages when needed via `sshkey-ctl purge --older-than 5y`. SQLite handles millions of rows efficiently -- a busy 50-user server accumulates roughly 200 MB/year, which is negligible. Purging is a manual maintenance task, not an automated process.

**Per-device sync watermarks:**
- Server records `last_synced_at` timestamp per device (updated on each client sync)

**Purge:** `sshkey-ctl purge --older-than 5y` deletes messages older than the specified duration from all room and conversation DBs, removes associated epoch keys, and runs `VACUUM` to reclaim disk space. Run manually or as a cron job.

```
Server
├── room-general.db       (all history for "general")
├── room-engineering.db
├── conv-xK9mQ2pR.db     (DM or group DM)
└── conv-yL0nR3qS.db
```

**New device sync:**
- New device connects with same SSH key, `last_synced_at` is zero (never synced)
- Server sends the default sync window: last 200 messages (or 7 days) per room/conversation, with bundled epoch keys
- This is intentionally small -- the user sees recent context immediately, not a loading screen
- Older history available on demand: as the user scrolls back, client sends `history` requests and the server responds with pages of older messages + their epoch keys
- `first_seen` still respected -- new users can't see pre-join history even via `history` requests
- Existing devices with a recent `last_synced_at` just get the delta since their last sync (usually a small batch)
- New device unwraps keys with same SSH key -- works because the key wrapping is tied to the SSH key, not the device

**SSH key changes:** Key rotation is not supported. See the **Account Lifecycle** section earlier in this document for the identity model, retirement flow, and the reasoning behind the no-rotation decision.

**Retention cleanup:**
- Via `sshkey-ctl purge --older-than 5y` (run manually or as a cron job)
- Deletes old messages, associated epoch keys, and runs VACUUM on each DB

### Search

**Client-side only.** No server-side search -- the server stores encrypted blobs it can't read. All search runs against the local encrypted DB, which only contains messages the client has already fetched (via sync window or scroll-back).

- SQLite FTS5 on the local DB for full-text search across all rooms and DMs
- Interactive fuzzy search via `go-fuzzyfinder` (ktr0731) or `sahilm/fuzzy` for the UX layer
- Search by keyword, user, date range, room -- all local, fast, no network round-trip
- Per-server search by default, cross-server search opt-in

---

## Client Apps

Two reference client apps in two languages. The server protocol is well-documented so anyone can build their own.

### Terminal Client (Go)

- Go + Bubble Tea for TUI + rasterm for inline images
- rasterm handles image protocols (sixel/kitty/iterm2) for inline image rendering
- Bubble Tea provides sidebar, room list, input bar, message stream, overlays
- Go core library: `x/crypto/ssh`, `modernc.org/sqlite`, protocol implementation

### GUI Client (Rust) -- Desktop + Mobile

- Rust + egui (`eframe` for desktop, mobile via cross-compilation)
- Traditional chat app look (Signal/Slack-like)
- Native image rendering, inline audio/video playback
- Targets macOS, Linux, Windows, iOS, Android from one codebase
- Rust core library: `russh` (SSH), `rusqlite` + SQLCipher (encrypted local DB), `ring` (crypto)

### Two Core Libraries

```
┌──────────────────────┐  ┌──────────────────────────────┐
│ Terminal client       │  │ GUI client                    │
│ (Bubble Tea + rasterm)│  │ (egui)                        │
├──────────────────────┤  ├──────────────────────────────┤
│ Go core library       │  │ Rust core library              │
│ x/crypto/ssh          │  │ russh · rusqlite · ring        │
│ modernc.org/sqlite    │  │                                │
└──────────────────────┘  └──────────────────────────────┘
         │                            │
         └────── same protocol ───────┘
```

Two independent implementations of the same protocol. This is deliberate:
- Validates the protocol design -- if both can implement it independently, anyone can
- Each language plays to its strengths: Go for terminal/server ecosystem, Rust for GUI/mobile
- No FFI bridges or gomobile bind hacks
- Server stays Go, clients use whatever makes sense

### Key Management (client-side)

On first launch or when adding a server, the client needs an SSH key. Four options:

1. **Select existing** -- scan `~/.ssh/` for key files, present a list, user picks one
2. **Import from file** -- file picker, user selects a key from anywhere on disk
3. **Generate new** -- client generates an ed25519 key pair, saves to `~/.sshkey-chat/keys/` or user-chosen location
4. **Save/export** -- export the current key to a file for backup or transfer to another device

**One key per user:** identity is the key. Each user has exactly one SSH key. Multiple keys per user are intentionally not supported -- the admin has no way to cryptographically verify that a second key belongs to the same person, and a fraudulently added key would gain access to all of that user's DM history (the symmetric key gets wrapped with each registered public key). To use the same account on a new machine, copy the existing key. To start fresh, admin removes the old user and creates a new one with the new key.

**Passphrase protection:**
- On key generation: prompt for a passphrase. Recommended by default, explicit "skip" option with a warning that the key will be stored unencrypted.
- On key selection/import: if the key has a passphrase, client prompts for it on connect.
- Passphrase caching: client caches in memory for the session (never written to disk). Integrate with system SSH agent (`ssh-agent` on Linux/macOS, Pageant on Windows) for seamless handling.
- On mobile: key stored in iOS Keychain / Android KeyStore with device-level protection (biometrics, PIN). Passphrase still applies on top if set.
- Entirely client-side. Server never sees the passphrase -- only the public key.

**Key backup:**
- On key generation: after creating the key, client prompts the user to back it up. Explain clearly: "This key is your identity. If you lose it, you lose access to your account and all encrypted message history. Back it up now."
- Offer to export/save a copy to a user-chosen location (USB drive, cloud storage, password manager)
- On mobile: additionally recommend enabling device backup that includes the keychain
- This prompt is not dismissable without the user explicitly choosing "I'll do it later" -- gentle friction to prevent regret

Key path stored per server in client config:

```toml
[[servers]]
name = "Personal"
host = "chat.example.com"
port = 2222
key = "~/.ssh/id_ed25519"

[[servers]]
name = "Work"
host = "work.company.com"
port = 2222
key = "~/.sshkey-chat/keys/work_ed25519"
```

Different servers can use different keys. The public key is what the server admin needs to approve the user via `sshkey-ctl`.

---

## Link Previews (Client-Side)

Capability: `link_previews`

Handled entirely by the sending client. Server never fetches external URLs.

**Flow:**
1. User posts a message containing a URL
2. Sender's client detects the URL before sending
3. Client fetches OG tags (title, description, image) -- one HTTP GET, parse `<head>` meta tags
4. Client bundles preview as metadata on the message and uploads OG image as an attachment if present
5. Server stores it with the message -- other clients receive the preview data ready to render, no fetching needed

Decrypted payload (inside the encrypted `payload` field, not visible to the server):
```json
{
  "body": "check this out https://example.com/thing",
  "previews": [{
    "url": "https://example.com/thing",
    "title": "Cool Thing",
    "description": "A thing that is cool",
    "image_id": "abc123"
  }]
}
```

**Why sender fetches:**
- One fetch total, not N clients hitting the same URL
- Preview arrives with the message -- instant rendering for all recipients
- No server-side HTTP client, no coordination, no caching layer
- Uses the same attachment upload path already designed for file sharing

**Safety constraints:**
- 3-second timeout on the HTTP fetch
- 1MB max download (fetch the `<head>` only, abort if response exceeds limit)
- Max 2 redirects (prevents redirect chains to internal IPs or tracking services)
- Strip known tracking parameters from the URL before fetching (`utm_*`, `fbclid`, `gclid`, etc.)
- No fetching of private/internal IPs (127.x, 10.x, 192.168.x, link-local) -- prevents SSRF from the client
- OG image fetched separately via the normal file upload path, same size limits as attachments

**Failure:** if fetch fails or times out, message sends without preview. Other clients see the raw URL. No degradation.

---

## Mobile

The GUI client (Rust + egui) targets mobile from the same codebase. egui supports iOS and Android via cross-compilation.

### Connection Lifecycle

Desktop and mobile use different connection strategies over the same protocol:

```
Desktop:  persistent SSH connection (real-time push from server)
Mobile:   connect on foreground + push-triggered background sync
```

- **Foreground:** app opens, SSH connects to server, syncs, receives real-time messages. Same as desktop.
- **Backgrounded:** SSH disconnects. Mobile OS kills background connections aggressively -- don't fight it.
- **New message for offline user:** server sends a minimal push via APNs (iOS) / FCM (Android). Push contains no message content -- just a wake signal. App wakes briefly, connects, syncs, shows notification with real content locally.

```
Phone (backgrounded):
    Server has message for offline user
        -> Server sends push: {"aps": {"content-available": 1}}
        -> No message content in push (privacy)
        -> Push wakes app briefly
        -> App connects via SSH, syncs new messages, disconnects
        -> User sees notification with actual content (rendered locally)
```

### Push Relay

Small service running alongside the chat server:
- Users register their push token (per device) with the server on first mobile connect
- Server sends lightweight wake-up pushes via APNs/FCM when messages arrive for offline users
- Push relay never sees message content -- it just signals "you have new messages"

### Platform-Specific Requirements

- **SSH key storage:** iOS Keychain / Android KeyStore. Small platform bridge needed (~50 lines Swift/Kotlin). Rust can call these via FFI.
- **Push registration:** platform-specific code for APNs/FCM token registration
- Everything else (SSH, sync, crypto, local DB, UI) is cross-platform Rust

---

## Explicitly Deferred

- **Raw SSH fallback** -- no built-in text client. Server requires a protocol-speaking client. Raw SSH connections get an install banner and disconnect.
- **Server-to-server federation** -- each server is intentionally independent. The complexity is enormous: identity resolution across servers (whose "alice" is canonical?), cross-server message routing, trust establishment, DM key distribution across server boundaries. Users who participate in multiple communities add multiple servers to their client -- the multi-server client design already handles this. Federation could theoretically be added as a future capability, but it's effectively a different project and not worth the complexity for the value it provides.

---

## Phases

1. Protocol definition + server + Go core library + terminal client
2. File sharing + inline images + link previews
3. Rust core library + GUI client (desktop)
4. GUI client (mobile) + push relay

---

## Identity Model

Two-layer identity system: **usernames** (immutable internal IDs) and **display names** (mutable, human-visible).

### Usernames (internal)

- Nanoid IDs (`usr_` prefix) generated on `sshkey-ctl approve`, stored in `users.db`
- Stored in every DB table as `sender`, `user`, primary keys
- Never changes after account creation — no bulk DB updates needed
- Retired usernames cannot be reused (prevents DM/history conflicts)
- Server rejects: new accounts with existing username, un-retiring retired accounts

### Display names (visible)

- Set by admin initially in `display_name` field, changeable by user via Settings
- Stored ONLY in the `profiles` table — name changes update one row
- Server enforces uniqueness (case-insensitive) against all active usernames and display names
- TUI renders display name everywhere; username is the hidden lookup key
- Broadcast to all clients on change — clients update their profile cache, no local DB migration

### Why this works

| Concern | How it's handled |
|---|---|
| Name changes | Only `profiles` table updates — no message/reaction/DM rewriting |
| Retirement | Username stays, display name freed for reuse by different account |
| Duplicate names | Server rejects duplicate display names on `set_profile` and `sshkey-ctl approve` |
| History attribution | Messages reference immutable username — always points to the right person |
| Client DB sync | Profile broadcast updates render cache — no local DB rows change |

### Enforcement

- `set_profile`: server checks display name against all usernames + display names (case-insensitive)
- `sshkey-ctl approve`: checks proposed username against existing + retired usernames + display names
- Config reload: rejects retired username reuse and un-retirement attempts
- Wizard: user picks preferred display name, embedded in key comment for admin

---

## Future: Push Notifications

**Status:** Feature request — blocked on sshkey-app (GUI client).

The protocol already has `push_register` / `push_registered` and the server DB has a `push_tokens` table. What's missing is provider integration.

### Required

- **APNs integration** (iOS) — server sends push via Apple Push Notification service when a device is offline
- **FCM integration** (Android) — same via Firebase Cloud Messaging
- **Privacy-preserving payload** — push content must be opaque (e.g. "New message" or encrypted notification ID). The server cannot see message content, so it cannot include a body preview. The client fetches and decrypts on wake.
- **Token lifecycle** — re-register on every foreground connect (upsert). Server prunes stale tokens after N failed deliveries.

### Design notes

- Push fires only when a device has no active SSH connection (offline)
- One push per message, not batched (avoids delay)
- Badge count = sum of unread across all rooms/conversations
- Silent push for typing/presence (iOS background refresh) — optional, battery-intensive

---

## Future: Overlay State Machine (TUI)

**Status:** Feature request — internal refactor, no user-visible change.

The TUI currently checks 18+ overlays sequentially in `Update()` to determine which one intercepts keyboard and mouse input. This works but is fragile — adding or reordering overlays can introduce priority bugs.

### Proposed

Replace the sequential `if` chain with a stack-based overlay manager:

```go
type OverlayStack struct {
    stack []Overlay
}

type Overlay interface {
    IsVisible() bool
    Update(tea.KeyMsg) (Overlay, tea.Cmd)
    HandleMouse(tea.MouseMsg) (Overlay, tea.Cmd)
    View(width, height int) string
}
```

- Push on open, pop on close
- Top of stack receives all input (keyboard + mouse)
- Focus auto-restores to FocusInput when stack empties
- No ordering to maintain — priority is implicit in stack position

---

## Future: Message Editing

**Status:** Planned feature — design complete, implementation tracked in `message_editing.md` (Phase 14).

### Constraints

- **Three context-specific verb families**, mirroring the send/receive split that shipped in Phase 11:
  - Rooms: `edit` / `edited` (uses `room` + `epoch`, no `wrapped_keys`)
  - Group DMs: `edit_group` / `group_edited` (uses `group` + `wrapped_keys` over current group members)
  - 1:1 DMs: `edit_dm` / `dm_edited` (uses `dm` + `wrapped_keys` over exactly 2 entries)
- **Only the user's most recent message in the current room/conversation** can be edited — not globally, not across contexts. Server validates per-room / per-group / per-dm. "Most recent" includes thread replies — a reply IS the user's most recent message in the parent's context if nothing followed it.
- **Room messages:** must be in the current or previous epoch (same grace window as sends). Epoch rotation naturally bounds the edit window (~100 messages or 1 hour).
- **DM / group DM messages:** no epoch restriction (per-message keys are independent), but still gated by the "most recent" rule. Editing an old message first requires scrolling past nothing else from the same user.
- **Retired rooms reject edits.** Phase 12 added `IsRoomRetired` gates to `handleSend`, `handleReact`, `handlePin`, `handleUnpin`; `handleEdit` joins that set. Retired rooms are read-only, full stop.
- **Left contexts block the edit shortcut.** A user who has `/leave`d a room or group sees the archived read-only banner. The TUI input block in `app.go` already covers `IsLeft || IsRoomRetired` — edit-mode entry routes through the same gate.
- **Original content is replaced** — no edit history retained (matches Signal behavior)
- **`edited_at` is set by the server** (authoritative, in the envelope, not the payload). Added as an `omitempty` field to the `Message`, `GroupMessage`, and `DM` protocol types.
- **Body-only edits.** Attachments are immutable — `file_ids` stay on the message. The `Edit` / `EditGroup` / `EditDM` types do NOT carry `FileIDs` fields, so there's structurally nothing to mutate. Server reads the original row's file_ids on replace and preserves them.
- **`reply_to` is immutable.** Same structural enforcement — the edit types don't carry `ReplyTo`. Thread structure stays stable.
- **No notifications on edit.** Mention extraction runs on the edited body for highlight rendering, but no push/notification fires. An edit is a correction, not a new message.
- **Cannot edit deleted messages.** Server rejects all three edit verbs if `deleted = 1`. Client does not offer the edit shortcut on deleted messages. Enforced at both layers.
- **Byte-identical privacy** — `handleEdit` / `handleEditGroup` / `handleEditDM` are new membership-gated handlers. Per the Conventions section, each needs a `TestHandleEditX_PrivacyResponsesIdentical` regression test using `bytes.Equal` on wire frames (unknown-context, non-member, and "not the original author" all return the same byte-identical response).

### Room editing

Same epoch key, new ciphertext. Simple — the key everyone already has encrypts the new payload.

```json
// Client -> Server
{"type":"edit","id":"msg_abc123","room":"room_V1StGXR8_Z5jdHi6B","epoch":3,"payload":"base64...","signature":"base64..."}

// Server -> Client (broadcast — full envelope, not a diff)
{"type":"edited","id":"msg_abc123","room":"room_V1StGXR8_Z5jdHi6B","from":"usr_alice","ts":1712345680,"epoch":3,"payload":"base64...","signature":"base64...","edited_at":1712345690}
```

Server validates: sender is original author, message is their most recent in the room, epoch is current or previous, message is not deleted, room is not retired. Replaces stored payload, sets `edited_at`. Broadcasts full envelope with `edited_at`.

### Group DM editing

Fresh per-message key for the edit, wrapped for each current group member. The original K_msg is dead — server no longer stores content encrypted with it.

```json
// Client -> Server
{"type":"edit_group","id":"msg_def456","group":"group_xK9mQ2pR",
 "wrapped_keys":{"usr_alice":"base64...","usr_bob":"base64...","usr_carol":"base64..."},
 "payload":"base64...","signature":"base64..."}

// Server -> Client (broadcast — full envelope)
{"type":"group_edited","id":"msg_def456","group":"group_xK9mQ2pR","from":"usr_alice","ts":1712345680,
 "wrapped_keys":{"usr_alice":"base64...","usr_bob":"base64...","usr_carol":"base64..."},
 "payload":"base64...","signature":"base64...","edited_at":1712345690}
```

Server validates: sender is original author, message is their most recent in the group, `wrapped_keys` matches current group member list, message is not deleted. Replaces stored payload and wrapped_keys, sets `edited_at`.

### 1:1 DM editing

Same pattern as groups but `wrapped_keys` has exactly two entries (both parties).

```json
// Client -> Server
{"type":"edit_dm","id":"msg_ghi789","dm":"dm_yL0nR3qS",
 "wrapped_keys":{"usr_alice":"base64...","usr_bob":"base64..."},
 "payload":"base64...","signature":"base64..."}

// Server -> Client (broadcast — full envelope)
{"type":"dm_edited","id":"msg_ghi789","dm":"dm_yL0nR3qS","from":"usr_alice","ts":1712345680,
 "wrapped_keys":{"usr_alice":"base64...","usr_bob":"base64..."},
 "payload":"base64...","signature":"base64...","edited_at":1712345690}
```

Server validates: sender is original author, message is their most recent in the DM, `wrapped_keys` has exactly the two DM parties, message is not deleted, neither party has `/leave`d the DM (the Phase 11 one-way ratchet cutoff). Replaces stored payload and wrapped_keys, sets `edited_at`. Message ID and original timestamp preserved — replies, reactions, and pins still reference the same ID.

### Rate limiting

Edits have their own rate limit bucket: `edits_per_minute`, default 10/min. Separate from sends — an edit is a correction, not a conversation action, and shouldn't compete with the send rate. Added as a new `EditsPerMinute` field on `config.RateLimits` with a `server.toml` documentation entry. One shared bucket across all three edit verbs (rooms, groups, DMs) — a user editing furiously in one context shouldn't get a free pass elsewhere.

### Sync and history

Server stores `edited_at` on the message row. When serializing for `sync_batch` or `history_result`, include `edited_at` in the envelope when non-zero. The `Message`, `GroupMessage`, and `DM` protocol types gain an `EditedAt int64 \`json:"edited_at,omitempty"\`` field. Clients that reconnect after an edit see the edited body with the "(edited)" marker. Old clients ignore the unknown field (forward compatibility rule).

### Client DB

Same migration pattern as `deleted`/`deleted_by`:

```sql
ALTER TABLE messages ADD COLUMN edited_at INTEGER NOT NULL DEFAULT 0;
```

On receiving `edited` / `group_edited` / `dm_edited`, update body and set `edited_at` in local DB and in-memory `DisplayMessage`. `LoadFromDB` maps it. `View()` renders "(edited)" in timestamp style when non-zero.

### TUI rendering

`Alice  3:04 PM (edited)` — the "(edited)" marker renders in the dim timestamp style. No hover/tooltip needed in terminal.

### TUI interaction

- **Up arrow on empty input, when input is focused:** populates input with the user's last editable message body in the current context, enters edit mode. Fires only when `focus == FocusInput`. Up-arrow in messages/sidebar focus keeps its existing navigation meaning. Does not fire when the context is archived (left or retired room) or when the last message is deleted.
- **Dispatch:** Enter in edit mode sends `edit` / `edit_group` / `edit_dm` depending on whether `messages.room` / `messages.group` / `messages.dm` is set. `Esc` cancels and returns to normal compose mode.
- **Visual feedback:** Input bar shows "Editing message" indicator (same style as "replying to" indicator).
- **Stale epoch:** If the epoch rotated between pressing Up and pressing Enter, server rejects with `edit_window_expired`. Client shows "Edit window expired" and returns to compose mode — user can delete the message instead.

### Signatures

Same canonical serialization as normal sends. The edit signature covers the new payload bytes + room/epoch (rooms) or group/wrapped_keys (groups) or dm/wrapped_keys (1:1 DMs). Recipients verify against the sender's key. Invalid signature = same "failed verification" warning as for normal messages.

### Multi-device

Last-write-wins. Two devices editing the same message concurrently — second edit overwrites the first. No conflict resolution, no merge, no lock. Both devices see the final result via server broadcast.

### Reactions on edit

Server clears reactions on the edited message (reactions were for the original content) by reusing the existing `store.DeleteReactionsForMessage` helper from `handleDelete`. Broadcasts `reaction_removed` for each cleared reaction so clients stay in sync.

### Why not reuse the original DM key?

AES-GCM with the same key and a new random nonce is technically safe for a single edit. But generating a fresh K_msg is cheap (one key generation + wraps per member) and preserves the security model: each encryption operation uses its own key. No reason to cut corners.

### Why not delete + re-create for DMs?

Changing the message ID breaks `reply_to`, reaction, and pin references. Other clients who already received the original would see a deletion followed by a "new" message instead of an in-place edit. Timestamp manipulation is also problematic — the server is the source of truth for `ts`.

### Why full envelope broadcast, not a diff?

A diff is fragile — if the client's local copy diverged (missed a sync, different decryption state), the patch produces garbage. A full envelope is self-contained and idempotent. A client that missed the original message can display the edited version standalone.

### New error codes

- `edit_not_authorized` — sender is not the original author (returned byte-identical to unknown/non-member per privacy convention)
- `edit_not_most_recent` — target message is no longer the user's most recent in the context
- `edit_window_expired` — room epoch rotated since send, edit window closed
- `edit_deleted_message` — target message has `deleted = 1` (returned byte-identical to not-author per privacy convention)

---

## Future: Protocol Versioning Tests

**Status:** Feature request.

A shared `protocol_test.json` file containing sample messages for every protocol type, with expected field names and values. Both sshkey-chat and sshkey-term validate against it in their test suites. Catches field name drift, missing `omitempty`, type mismatches between repos.

---

## Future: Batch Operations in sshkey-ctl

**Status:** Feature request.

### Batch approve

```bash
sshkey-ctl import --file users.csv --rooms general
```

CSV format: `key,display_name,rooms` (one user per line). Runs the same validation as single approve (duplicate key, duplicate name, Ed25519, name length) per row. Atomic: all-or-nothing write to users.toml.

### Batch room management

```bash
sshkey-ctl add-to-room --user usr_a,usr_b,usr_c --room engineering
```

Comma-separated user list. Validates each user, skips already-members with a warning.

---

## Future: Image Thumbnail Generation

**Status:** Feature request.

The `Attachment` struct has `thumbnail_id` but nothing generates thumbnails. Server-side generation is impossible (encrypted content). Client-side approach:

1. On upload: resize image to 200px wide, encode as JPEG
2. Encrypt thumbnail with the same key as the full image (room epoch key or per-file K_file)
3. Upload thumbnail as a second file, get `thumbnail_id`
4. Include `thumbnail_id` in the attachment metadata
5. Recipients download the small thumbnail first for fast preview, full image on demand

Libraries: `imaging` (Go), `image/jpeg` stdlib. Adds ~200ms to upload for typical photos.

---

## Future: Room Deletion

**Status:** Feature request.

### sshkey-ctl delete-room

Admin-only CLI command: `sshkey-ctl delete-room --name general [--purge]`

### Flow

1. Remove room from `rooms.toml` (atomic write)
2. Server detects via file watcher:
   - Removes all users from the room in memory
   - Broadcasts `room_event` leave for every member
   - Broadcasts `room_deleted` event (new message type): `{"type":"room_deleted","room":"general"}`
3. **Data handling (default):** Archive the DB file — rename `room-general.db` to `room-general.db.archived`. Admin can restore manually later.
4. **Data handling (--purge flag):** Hard-delete the DB file. Permanent, irreversible.
5. **Client side:** On `room_deleted`, remove from sidebar, clear messages if active context, show system message "Room #general was deleted."

### Design notes

- No bulk message deletion through the protocol — bulk operations are admin CLI only
- If you want to keep the room but clear history, use `sshkey-ctl purge --room general --older-than 0d`
- Room deletion is visible and auditable — cannot silently wipe a room's messages without deleting the room itself
- Archived DBs can be restored by renaming back and re-adding the room to rooms.toml

---

## Attachment Lifecycle

File blobs follow the message lifecycle — when a message is deleted, its attachments are cleaned up. No orphaned files.

### On message delete (server)

1. Soft-delete the message row (already done)
2. Query `file_ids` from the message row
3. Delete each file blob from disk (`files/<file_id>`)
4. Delete `file_hashes` entries for those file IDs
5. Delete pins referencing the deleted message (pinned tombstones are useless)
6. Delete reactions (already done)

### On message purge (sshkey-ctl)

Same cleanup — when `purge --older-than` deletes old messages, also delete the file blobs and `file_hashes` entries for those messages.

### On message delete (client)

Delete local cached files for the message's `file_id`s from the client's `files/` directory if they exist.

### Download of deleted files

Returns `download_error` with `not_found` — the file blob was deleted. Client already handles this gracefully.

### Tombstone display

"Message deleted" — no mention of attachments. The content is gone, knowing there were attachments doesn't add value.

---

## Message Deletion Model

### Rate limits

| Actor | Limit | Default |
|---|---|---|
| User (own messages) | `deletes_per_minute` | 10/min |
| Admin (any room message) | `admin_deletes_per_minute` | 50/min |

### Permissions

| Context | Who can delete | Notes |
|---|---|---|
| Room — own message | Any user | Rate limited |
| Room — other's message | Admin only | Rate limited (admin rate) |
| DM — own message | Any user | Rate limited |
| DM — other's message | Nobody | Not even admins |

### No bulk delete through the protocol

There is no `delete_all` or bulk delete endpoint. Users delete one message at a time, throttled by the rate limit. This is intentional — the rate limit prevents accidental or malicious bulk wipes and gives admins time to intervene.

Bulk operations are admin CLI only:
- `sshkey-ctl delete-room` — deletes the entire room (archive or purge)
- `sshkey-ctl purge --older-than` — time-based cleanup across all rooms

### Message deletion on retirement (optional)

When a user retires their account (via `retire_me` or `sshkey-ctl retire-user`), they may optionally request deletion of all their messages. This is **not the default** — retirement alone leaves messages intact (with a retired sender marker).

To opt in:

```json
// Client -> Server
{"type":"retire_me","reason":"self_compromise","delete_messages":true}
```

Or via CLI:

```bash
sshkey-ctl retire-user usr_abc --reason key_lost --delete-messages
```

When `delete_messages` is true:
- Server soft-deletes all messages by the retiring user across all rooms and conversations
- Broadcasts tombstones for each deleted message (rate-unlimited — this is a one-time server-side operation, not user-driven)
- Reactions on deleted messages are cleaned up
- Connected clients receive the tombstones and update their displays
- Offline clients receive tombstones in their next sync batch

This is the only path to bulk message deletion. It is permanent, tied to an irreversible account action, and fully auditable.

---

## Future: Display Room Topics in TUI

**Status:** Feature request.

Room topics are sent by the server in `room_list` but the terminal client never displays them. They should show in:

- **Info panel (`Ctrl+I`)** — under the room name, above the member list
- **Message panel header** — subtle line under `#general` showing the topic

Topic changes (if supported later) would update via `room_list` refresh.
