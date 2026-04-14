# Protocol Reference

> Complete wire protocol reference for building a compatible client. Language-agnostic — this document describes the protocol surface only. Client implementation decisions (local DB schema, caching, TUI rendering) belong in each client's own docs.

Everything you need to build a client for the sshkey-chat server.

**How to read this document:** Start with **Connection** and **Handshake** to understand the session lifecycle. Then read the message types relevant to what you're building (rooms, DMs, groups). The **Encryption** section covers the crypto primitives you'll need to implement. The **Minimal Client Checklist** at the bottom is a good starting point for a first implementation.

## Connection

Connect via SSH to the server on port 2222 (configurable). Only Ed25519 keys are supported -- the server rejects RSA, ECDSA, and other key types.

### User approval

The server does not allow anonymous access. Before a user can connect and chat, their SSH public key must be approved by a server operator via `sshkey-ctl approve`. The approval flow:

1. **Unknown key connects.** The SSH handshake succeeds (the key type is valid Ed25519) but the server does not recognize the key. The server records the key fingerprint in a `pending_keys` table and immediately disconnects with an error: `{"type":"error","code":"client_required","message":"..."}`. The client should display the user's public key and fingerprint so they can share it with the server operator for approval.
2. **Operator approves.** The server operator runs `sshkey-ctl approve --key "ssh-ed25519 AAAA..." --rooms general,support` on the server box. This creates the user in `users.db` and assigns them to the specified rooms.
3. **User reconnects.** The next SSH connection with the approved key proceeds to the normal handshake (`server_hello` → `client_hello` → `welcome`).

**Retired accounts** are also rejected at the SSH handshake level — the key is recognized but the account is marked as retired, and the server disconnects with "account retired."

**Admin notifications.** When an unknown key attempts to connect, the server broadcasts an `admin_notify` event to all connected admin clients:

```json
{"type":"admin_notify","event":"pending_key","fingerprint":"SHA256:xx...","attempts":3,"first_seen":"2026-04-03T14:22:00Z"}
```

This lets admins know someone is waiting for approval without polling.

Three SSH channels per connection:

- **Channel 1:** NDJSON protocol messages (one JSON object per line, terminated by `\n`)
- **Channel 2:** Downloads — server writes raw encrypted file bytes here (length-prefixed frames); client reads
- **Channel 3:** Uploads — client writes raw encrypted file bytes here (length-prefixed frames); server reads

Downloads and uploads are split onto separate SSH channels so a large transfer in one direction does not block the other. The client opens Channels 1, 2, and 3 in that order (each as a plain `session` channel) before sending `client_hello`.

The server's SSH host key is Ed25519, generated on first run. Clients should use trust-on-first-use (TOFU) -- store the host key fingerprint on first connect, verify on subsequent connects.

## Handshake

```
Client opens SSH connection with Ed25519 key
Client opens 3 session channels (Channel 1: protocol, Channel 2: downloads, Channel 3: uploads)

  Server -> {"type":"server_hello","protocol":"sshkey-chat","version":1,
             "server_id":"chat.example.com",
             "capabilities":["typing","reactions","read_receipts","file_transfer",
                             "link_previews","presence","pins","mentions","unread",
                             "status","signatures"]}

  Client -> {"type":"client_hello","protocol":"sshkey-chat","version":1,
             "client":"my-client","client_version":"0.1.0",
             "device_id":"dev_V1StGXR8_Z5jdHi6B-myT",
             "last_synced_at":"2026-04-01T00:00:00Z",
             "capabilities":["typing","reactions","read_receipts","file_transfer",
                             "presence","pins","mentions","unread","status","signatures"]}

  Server -> {"type":"welcome","user":"usr_alice","display_name":"Alice Chen","admin":true,
             "rooms":["room_V1StGXR8_Z5jdHi6B","room_abc123def456"],
             "groups":["group_xK9mQ2pR"],
             "pending_sync":true,
             "active_capabilities":["typing","reactions","read_receipts","file_transfer",
                                    "presence","pins","mentions","unread","status","signatures"]}
```

**Handshake rules:**

- The client must send `client_hello` within **2 seconds** of receiving `server_hello`. Timeout = the server disconnects with a `client_required` error and an install banner.
- `protocol` must be `"sshkey-chat"` and `version` must be `1`. Mismatch = disconnect with install banner.
- The `capabilities` fields exist in the handshake but **the server currently sends all message types regardless of the negotiated set**. The fields are informational and reserved for future gating. Clients must handle (or ignore) any message type the server sends, not rely on the capability list to suppress them.
- `last_synced_at` controls whether sync batches follow: empty string = no sync (first connect, or client doesn't want catchup), non-empty ISO 8601 timestamp = server sends messages newer than that timestamp.
- `pending_sync` in the welcome is `true` when `last_synced_at` was non-empty — it tells the client to expect `sync_batch` messages before `sync_complete`.

The `welcome` envelope carries room and group ID lists but NOT 1:1 DMs — those arrive separately via `dm_list` in the connect sequence below.

### Device check (between welcome and connect sequence)

After sending `welcome`, the server checks the device:

1. **Device revoked?** If the device ID has been revoked by an admin or the user, the server sends `device_revoked` and disconnects immediately. The client should show the revocation reason and exit.
2. **Too many devices?** If registering this device would exceed `max_per_user` (default 10), the server sends `device_limit_exceeded` error and disconnects. The client should tell the user to revoke an old device.
3. **Device registered.** The server upserts the device in `devices` table with a `last_synced` timestamp.

Only after these checks pass does the connect sequence begin.

### Connect sequence

After the device check, the server sends (in this exact order):

1. `deleted_rooms` -- rooms the user has `/delete`d from their view on another device; catchup for offline devices. Sent BEFORE `room_list` so the client purges before populating the active list.
2. `retired_rooms` -- rooms that were retired by an admin while this device was offline. Also sent BEFORE `room_list`.
3. `room_list` -- rooms the user is currently a member of (nanoid IDs + display names; the `room` field in all subsequent messages carries the nanoid ID, not the display name)
4. `deleted_groups` -- group DMs the user has `/delete`d on another device; catchup for offline devices. Sent BEFORE `group_list`.
5. `group_list` -- group DMs the user is currently a member of
6. `dm_list` -- 1:1 DMs (includes the per-user `left_at_for_caller` cutoff for silent multi-device `/delete` propagation)
7. `profile` -- one message per visible user (includes pubkey, fingerprint, display name, avatar, retired status)
8. `retired_users` -- list of users whose accounts have been retired and are visible to this client
9. `epoch_key` -- one message per room, carrying the current epoch key wrapped for this user
10. `unread` -- unread counts per room / group / dm
11. `pins` -- pinned message IDs + full message envelopes per room
12. `sync_batch` -- catch-up messages (only if `pending_sync` is true), may be multiple batches with `has_more` pagination
13. `sync_complete` -- sync is done, `synced_to` timestamp included. Client should store this for the next reconnect's `last_synced_at`.
14. `presence` -- online status broadcast for every currently connected user visible to this client

After `sync_complete`, the server switches to real-time push — messages, events, and broadcasts arrive as they happen.

The catchup lists (`deleted_rooms`, `retired_rooms`, `deleted_groups`) are ordered BEFORE their corresponding active-list message. This ordering is critical: a room the user `/delete`d on one device must be purged from the other device's local state BEFORE `room_list` populates it, otherwise the deleted room would briefly appear as active.

## Device Identity

Each device generates a Nano ID on first launch (21 characters, 126 bits entropy, `dev_` prefix). Store it permanently in the client's config. Same SSH key on different devices = different `device_id`.

```
dev_V1StGXR8_Z5jdHi6B-myT
```

Libraries: `jaevor/go-nanoid` (Go), `nanoid` crate (Rust), `nanoid` npm package (JS).

Max 10 devices per user (configurable via `server.toml` `[devices] max_per_user`). Server rejects with `device_limit_exceeded` if exceeded during the handshake device check.

**Forward compatibility:** Clients must ignore unknown message types and unknown fields within known message types. Never reject or error on unrecognised data.

## Wire Format

NDJSON -- one JSON object per line, UTF-8, terminated by `\n`. Every message has a `type` field.

All IDs are Nano IDs with prefixes:

| Prefix | Generated by | Example | Notes |
|---|---|---|---|
| `usr_` | Server | `usr_V1StGXR8_Z5jdHi6B-myT` | User identity (immutable, permanent) |
| `room_` | Server | `room_V1StGXR8_Z5jdHi6B` | Chat rooms — persistent, admin-managed |
| `group_` | Server | `group_xK9mQ2pR` | Group DMs (3+ party) — created via `create_group` |
| `dm_` | Server | `dm_yL0nR3qS` | 1:1 DMs — created via `create_dm` |
| `msg_` | Server | `msg_abc123def456` | Message envelopes (rooms, groups, DMs) |
| `react_` | Server | `react_7kQ2mR` | Reactions |
| `file_` | Server | `file_xyz789` | Uploaded files |
| `up_` | Client | `up_001` | Transient upload correlation IDs |
| `dev_` | Client | `dev_V1StGXR8_Z5jdHi6B-myT` | Per-device identifier, permanent on the client |

Timestamps are Unix epoch seconds (integer). The server is the single source of truth for ordering.

### Identity Model

Usernames are immutable internal IDs assigned at account creation (Nano IDs with `usr_` prefix, e.g. `usr_V1StGXR8_Z5jdHi6B-myT`). Display names are human-visible, mutable (via `set_profile`), and unique (server-enforced, case-insensitive). All protocol routing, storage, and `from`/`user` fields use the username (nanoid). Clients resolve usernames to display names at render time only, using the `profile` messages received after `welcome`.

On retirement, the display name is suffixed with 4 characters from the nanoid (e.g. "Alice" becomes "Alice_V1St") to free the name for reuse. See `PROJECT.md` section "Identity Model" for the full design.

## Encryption

The server is a blind relay. All message content is encrypted client-side. The server sees the envelope (routing metadata) but never the payload (content).

### Two Models

**Rooms -- epoch keys:**
- Shared AES-256-GCM symmetric key per room, rotated every 100 messages or 1 hour
- Key is wrapped per-member using their SSH public key
- Server stores and distributes wrapped keys (opaque blobs)

**DMs -- per-message keys:**
- Fresh AES-256 key per message
- Wrapped for each conversation member inline in the message envelope
- Every message is self-contained, no server-side key state

### Cryptographic Primitives

| Operation | Algorithm |
|---|---|
| Message encryption | AES-256-GCM, 96-bit random nonce prepended to ciphertext |
| Key wrapping | Ed25519 -> X25519 conversion, ephemeral ECDH, HKDF-SHA256, AES-256-GCM |
| Message signatures | Ed25519 |
| Local DB encryption | AES-256 via SQLCipher, key derived from SSH private key via HKDF-SHA256 |

### Key Wrapping (same for epoch keys and per-message keys)

```
Wrapping a symmetric key for Alice:
1. Generate ephemeral X25519 keypair (eph_priv, eph_pub)
2. Convert Alice's Ed25519 public key -> X25519 public key
3. ECDH: shared_secret = X25519(eph_priv, alice_x25519_pub)
4. HKDF-SHA256(shared_secret, salt=eph_pub, info="sshkey-chat key wrap") -> wrapping_key
5. AES-256-GCM(wrapping_key, random_nonce, symmetric_key) -> ciphertext
6. wrapped_key = eph_pub || nonce || ciphertext

Unwrapping:
1. Parse eph_pub, nonce, ciphertext from wrapped_key
2. Convert Alice's Ed25519 private key -> X25519 private key
3. ECDH: shared_secret = X25519(alice_x25519_priv, eph_pub)
4. HKDF-SHA256(shared_secret, salt=eph_pub, info="sshkey-chat key wrap") -> wrapping_key
5. AES-256-GCM-Open(wrapping_key, nonce, ciphertext) -> symmetric_key
```

Go: `x/crypto/curve25519`, `crypto/aes`, `crypto/cipher`, `x/crypto/hkdf`.
Rust: `x25519-dalek`, `aes-gcm`, `hkdf` crates.

### Payload Encryption / Decryption

The key wrapping above gets you the symmetric key. Here's how to use it for the actual message payload:

**Encrypting (sending):**

1. Build the payload JSON (`{"body":"...","seq":42,"device_id":"dev_...","mentions":[...],"reply_to":"...","attachments":[...]}`)
2. Get the key:
   - **Rooms:** look up the current epoch key for this room (from your local `epoch_keys` cache)
   - **Groups/DMs:** generate a random 256-bit AES key (`K_msg`), then wrap it for each member using the Key Wrapping algorithm above
3. Generate a random 96-bit (12-byte) nonce
4. AES-256-GCM encrypt the payload JSON bytes with the key and nonce
5. Prepend the nonce to the ciphertext: `encrypted = nonce (12 bytes) || ciphertext`
6. Base64-encode: `payload = base64(encrypted)`
7. Put `payload` in the envelope's `payload` field. For groups/DMs, put the per-member wrapped keys in `wrapped_keys`.

**Decrypting (receiving):**

1. Base64-decode the `payload` field
2. Split: first 12 bytes = nonce, remaining = ciphertext
3. Get the key:
   - **Rooms:** look up the epoch key for the `epoch` value in the envelope
   - **Groups/DMs:** unwrap `wrapped_keys[your_user_id]` using the Key Wrapping algorithm above to recover `K_msg`
4. AES-256-GCM decrypt with the key and nonce
5. Parse the resulting bytes as JSON to get `body`, `seq`, `device_id`, `mentions`, `reply_to`, `attachments`

**Key point:** the nonce is always prepended to the ciphertext, not sent separately. There is no `nonce` field in the envelope — it's embedded in the `payload` blob.

### Message Signatures

Client signs every message and reaction with their Ed25519 private key. The signature is in the envelope (server can see it, can't modify it without detection).

**Canonical serialization (two forms):**

- **Rooms:** `Sign(payload_bytes || room_id_utf8 || epoch_as_big_endian_uint64)`
- **Group DMs and 1:1 DMs:** `Sign(payload_bytes || context_id_utf8 || wrapped_keys_canonical)`
  - `context_id` is the group nanoid for group DMs, or the dm nanoid for 1:1 DMs
  - Same signing function for both — the context ID is the only difference

Where `wrapped_keys_canonical` is the wrapped key **values** (not keys/usernames) concatenated in sorted **user-ID order**. Implementation: sort the `wrapped_keys` map keys (user nanoids) alphabetically, then concatenate the corresponding base64-decoded wrapped-key values in that order.

All fields are raw bytes: `payload_bytes` is the base64-decoded ciphertext (not the base64 string), `room_id_utf8` / `context_id_utf8` is the UTF-8 nanoid string, `epoch` is an 8-byte big-endian uint64.

**Verification rules:**
- Valid signature: display normally
- Missing signature: show "unsigned" indicator
- Invalid signature: hard warning — "This message failed signature verification"

**Reactions use the same signing scheme** as messages in their respective context (room reactions sign with epoch, DM/group reactions sign with wrapped keys).

### Replay Detection

Each sender maintains a monotonic counter (`seq`) per device per context (room, group DM, or 1:1 DM), starting at 1. Both `seq` and `device_id` are inside the encrypted payload -- the server cannot see or modify them.

Each recipient tracks the highest `seq` seen per `(sender, device_id, context_id)` in their local DB, where `context_id` is the room / group / dm nanoid. If a message's `seq` <= the stored high-water mark, it's a replay -- flag it. The three context namespaces are independent: Alice's `seq=5` in `#general` is unrelated to Alice's `seq=5` in a group DM.

### Key Pinning

Client stores each user's public key fingerprint on first encounter. On subsequent encounters, compare the server-provided fingerprint against the pinned value. Mismatch = hard warning (key may have been swapped by a compromised server).

### Safety Numbers

```
safety_number = SHA256(sort(alice_pubkey_bytes, bob_pubkey_bytes))
display as: "1234 5678 9012 3456 7890 1234"
```

Sort raw public key bytes lexicographically. Truncate SHA256 to 24 digits, displayed as six groups of four. Users compare via phone or in person.

### Member List Hashing

During epoch rotation, the generating client includes `member_hash = SHA256(sort(member_usernames))` in `epoch_rotate`. Existing members verify this against their locally-tracked membership. Mismatch = potential phantom member injection.

## Message Types

### Envelope / Payload Split

Every room message, group DM, and 1:1 DM is split into:

- **Envelope** (plaintext, server-readable): `type`, `from`, one of `room` / `group` / `dm`, `id`, `ts`, and context-specific crypto fields (`epoch` for rooms, `wrapped_keys` for group and 1:1 DMs), plus `file_ids` and `signature`
- **Payload** (encrypted, server-opaque): `body`, `seq`, `device_id`, `mentions`, `reply_to`, `attachments`, `previews`

The server routes on the envelope but never decrypts the payload. The three context fields (`room`, `group`, `dm`) are mutually exclusive — exactly one is set per message envelope, and it selects the crypto model (epoch key vs per-message wrapped key).

**Server-set fields:** `from`, `id`, and `ts` are always set by the server, never by the client. Clients should NOT set `from` on outbound messages — the server ignores it and fills in the authenticated user ID from the SSH connection. `id` is a server-generated nanoid (`msg_` prefix). `ts` is the server's wall clock (unix seconds), the single source of truth for message ordering.

### Room Messages

```json
// Client -> Server
{"type":"send","room":"room_V1StGXR8_Z5jdHi6B","epoch":3,"payload":"base64...","file_ids":["file_xyz"],"signature":"base64..."}

// Server -> Client
{"type":"message","id":"msg_abc123","from":"usr_alice","room":"room_V1StGXR8_Z5jdHi6B","ts":1712345678,"epoch":3,"payload":"base64...","file_ids":["file_xyz"],"signature":"base64..."}
```

**Decrypted payload:**
```json
{
  "body": "@bob agreed",
  "seq": 42,
  "device_id": "dev_V1StGXR8_Z5jdHi6B-myT",
  "mentions": ["usr_bob"],
  "reply_to": "msg_prev123",
  "attachments": [{"file_id":"file_xyz","name":"photo.jpg","size":230000,"mime":"image/jpeg","thumbnail_id":"file_xyz_thumb","file_epoch":3}],
  "previews": [{"url":"https://example.com","title":"Cool Thing","description":"A thing"}]
}
```

Message body limit: 16KB. `file_epoch` records which epoch key was used to encrypt the file (rooms only). DM attachments use `file_key` instead — see File Transfer below.

**Write rejections on retired rooms.** Once a room has been retired (see **Room Retirement** below), the server rejects every write verb that targets it with `{"type":"error","code":"room_retired","message":"..."}`. This applies to `send`, `react`, `unreact`, `pin`, `unpin`, `edit` (if implemented), and `delete`. History reads (`history`, `sync_batch`) and membership queries (`room_members`) still work — retirement is read-only, not invisible. The privacy rule for non-members is unchanged: a caller who is not a member of the retired room gets the same `unknown_room` error as they would for any other room they don't have access to, so retirement state never leaks to outsiders.

### 1:1 Direct Messages

1:1 DMs are fixed two-party conversations with their own ID namespace (`dm_` prefix). Created with `create_dm` passing a single other user; the server canonicalizes the pair and deduplicates so a second `create_dm` from either party returns the existing row.

```json
// Client -> Server (create a 1:1 DM with exactly one other user)
{"type":"create_dm","other":"usr_bob"}

// Server -> Client (echo to the caller's active sessions)
{"type":"dm_created","dm":"dm_yL0nR3qS","members":["usr_alice","usr_bob"]}

// Client -> Server (send — fresh K_msg wrapped for both parties)
{"type":"send_dm","dm":"dm_yL0nR3qS",
 "wrapped_keys":{"usr_alice":"base64...","usr_bob":"base64..."},
 "payload":"base64...","signature":"base64..."}

// Server -> Client (routed to both parties' active sessions)
{"type":"dm","id":"msg_def456","from":"usr_alice","dm":"dm_yL0nR3qS","ts":1712345678,
 "wrapped_keys":{"usr_alice":"base64...","usr_bob":"base64..."},
 "payload":"base64...","signature":"base64..."}
```

- **Exactly two parties.** The `create_dm` envelope has no `members` array — it takes a single `other` user ID. The 1:1 constraint is enforced at the wire level.
- **Deduplication.** Re-issuing `create_dm` against a user you already have a DM with returns the existing `dm_` ID via `dm_created`. Safe to call idempotently.
- **`wrapped_keys` must have exactly two entries** matching the two canonical parties. Server rejects with `invalid_wrapped_keys` otherwise.
- **Include yourself in `wrapped_keys`** so your other devices can decrypt your own sends.
- **1:1 DMs have no name field.** Clients render them by resolving the other party's display name.

**`/leave` and `/delete` for 1:1 DMs:**

```json
// Client -> Server (silent leave — the other party is NOT notified)
{"type":"leave_dm","dm":"dm_yL0nR3qS"}

// Server -> Client (echo to every active session of the caller only)
{"type":"dm_left","dm":"dm_yL0nR3qS"}
```

1:1 DM `/leave` is silent by design — the other party never receives a broadcast saying you left. The server sets a per-user `left_at` cutoff on the DM row so your future reads return nothing past the cutoff, but from the other party's perspective you simply go quiet. This preserves the "did they read it?" ambiguity that's central to the DM threat model.

There is no `delete_dm` protocol verb. The client-side `/delete` flow for 1:1 DMs is:
1. Client sends `leave_dm` (same as `/leave`)
2. Server sets the per-user cutoff and echoes `dm_left`
3. Client purges all local messages for that DM on receipt of the echo
4. When BOTH parties have a non-zero `left_at` cutoff, the server runs the full cleanup cascade (drop the DM row, unlink `dm-<id>.db`, free file blobs) inside the second `leave_dm` handler — there is no dedicated delete handler

Multi-device `/delete` sync for 1:1 DMs uses the `left_at_for_caller` field on `dm_list` during the handshake rather than a sidecar table. A device that was offline when the leave happened learns about it from the non-zero cutoff value on the `DMInfo` entry.

### Group DMs

Group DMs are multi-party conversations with 2–150 members. Identified by `group_` nanoids. **Phase 14 introduced an in-group admin model** — the creator becomes the first admin; admins can add, remove, promote, demote, and rename. The pre-Phase-14 "membership is fixed at creation" model is no longer in force.

```json
// Client -> Server (create a group DM — members excludes sender, name optional)
{"type":"create_group","members":["usr_bob","usr_carol"],"name":"Project Alpha"}

// Server -> Client (echo with server-assigned group ID + full member list + admin list)
{"type":"group_created","group":"group_xK9mQ2pR","members":["usr_alice","usr_bob","usr_carol"],"admins":["usr_alice"],"name":"Project Alpha"}

// Client -> Server (send — fresh K_msg wrapped for every current member)
{"type":"send_group","group":"group_xK9mQ2pR",
 "wrapped_keys":{"usr_alice":"base64...","usr_bob":"base64...","usr_carol":"base64..."},
 "payload":"base64...","signature":"base64..."}

// Server -> Client (broadcast to all members' active sessions)
{"type":"group_message","id":"msg_ghi789","from":"usr_alice","group":"group_xK9mQ2pR","ts":1712345680,
 "wrapped_keys":{"usr_alice":"base64...","usr_bob":"base64...","usr_carol":"base64..."},
 "payload":"base64...","signature":"base64..."}
```

- **Max 150 members** (server-enforced hard cap). Per-message wrapped keys scale linearly with member count (~80 bytes per member per message on the wire). At 150 members, each message carries ~12KB of key material. **Recommended:** for groups with 50+ members, clients should suggest using a room instead — rooms use a shared epoch key and are significantly more efficient for high-traffic conversations. The server does not enforce this recommendation; it is a UX guideline for client implementers.
- **Membership is mutable by admin action** (Phase 14). The user who calls `create_group` becomes the initial admin. Admins can `add_to_group`, `remove_from_group`, `promote_group_admin`, `demote_group_admin`, and `rename_group`. New members see only post-join messages (per-message wrapped keys; no backfill).
- **`wrapped_keys` must match the current member list exactly.** Server rejects with `invalid_wrapped_keys` on mismatch. Membership is small enough that new sends re-wrapping for every recipient is cheap.
- **Include yourself in `wrapped_keys`** so your other devices can decrypt your own sends.
- **Groups have an optional display `name`.** Unnamed groups render client-side as a comma-joined member list ("Bob, Carol").
- **`GroupCreated.admins`** (Phase 14) — user IDs of the initial admin set. On a fresh create this is always just the creator. Clients use this to populate the local `is_admin` flag and in-memory admin set without an extra round-trip.

#### In-group admin verbs (Phase 14)

Four new wire verbs — `add_to_group`, `remove_from_group`, `promote_group_admin`, `demote_group_admin` — plus a related refit of `rename_group`. All five are scoped to a single group and require admin status on the caller.

**Byte-identical privacy gate.** Unknown group, non-member, and non-admin rejection responses MUST be byte-identical `ErrUnknownGroup` frames so a probing client cannot enumerate group membership or admin status. Only AFTER the caller has proven membership AND admin status does the server return distinct errors (`ErrUnknownUser`, `ErrAlreadyMember`, `ErrAlreadyAdmin`, `ErrForbidden` for last-admin rejections). Client implementations MUST pre-check the local `is_admin` flag before sending to catch the 99% case with a friendlier error than the wire-level "you are not a member of this group".

```json
// Client -> Server (admin adds a new member; quiet suppresses inline system messages)
{"type":"add_to_group","group":"group_xK9mQ2pR","user":"usr_dave","quiet":false}

// Server -> Client (echo to caller)
{"type":"add_group_result","group":"group_xK9mQ2pR","user":"usr_dave"}

// Server -> Client (broadcast to all current members including the new one)
{"type":"group_event","group":"group_xK9mQ2pR","event":"join","user":"usr_dave","by":"usr_alice"}

// Server -> Client (direct notification to the added user's sessions — inserts the group locally)
{"type":"group_added_to","group":"group_xK9mQ2pR","name":"Project Alpha",
 "members":["usr_alice","usr_bob","usr_carol","usr_dave"],
 "admins":["usr_alice"],"added_by":"usr_alice"}
```

```json
// Client -> Server (admin removes a member; kicks are always loud — no quiet flag)
{"type":"remove_from_group","group":"group_xK9mQ2pR","user":"usr_bob"}

// Server -> Client (echo to caller)
{"type":"remove_group_result","group":"group_xK9mQ2pR","user":"usr_bob"}

// Server -> Client (broadcast to remaining members; by carries the kicking admin)
{"type":"group_event","group":"group_xK9mQ2pR","event":"leave","user":"usr_bob","reason":"removed","by":"usr_alice"}

// Server -> Client (echoed to the kicked user's sessions)
{"type":"group_left","group":"group_xK9mQ2pR","reason":"removed","by":"usr_alice"}
```

```json
// Client -> Server (promote a member to admin)
{"type":"promote_group_admin","group":"group_xK9mQ2pR","user":"usr_bob","quiet":false}

// Server -> Client (echo)
{"type":"promote_admin_result","group":"group_xK9mQ2pR","user":"usr_bob"}

// Server -> Client (broadcast)
{"type":"group_event","group":"group_xK9mQ2pR","event":"promote","user":"usr_bob","by":"usr_alice"}
```

```json
// Client -> Server (demote an admin back to regular member; may be self-demote)
{"type":"demote_group_admin","group":"group_xK9mQ2pR","user":"usr_bob","quiet":false}

// Server -> Client (echo)
{"type":"demote_admin_result","group":"group_xK9mQ2pR","user":"usr_bob"}

// Server -> Client (broadcast)
{"type":"group_event","group":"group_xK9mQ2pR","event":"demote","user":"usr_bob","by":"usr_alice"}
```

**"At least one admin" invariant.** Enforced at every mutation path:

| Path | Behavior when violation would occur |
|---|---|
| Admin `/leave` | Reject with `ErrForbidden` — "Cannot leave — you are the last admin. Promote another member first, or use /delete to dissolve the group." |
| Admin `/delete` | Same rejection. |
| Admin demote-self | Same rejection. |
| Admin kicked by another admin | Allowed as long as another admin remains. |
| Admin retires their account | **Auto-promote** oldest remaining member by `joined_at`. Retirement is unilateral — server handles succession. Promoted user receives `group_event{promote, reason:"retirement_succession"}`. |

**Sole-member carve-out.** If the caller is both the only member AND the only admin, `/leave` and `/delete` proceed — there's no governance concern when nobody else is affected, and the last-member cleanup cascade runs naturally.

**Renaming a group (admin-only as of Phase 14):**

```json
// Client -> Server
{"type":"rename_group","group":"group_xK9mQ2pR","name":"New Name","quiet":false}

// Server -> Client (legacy broadcast for pre-Phase-14 clients)
{"type":"group_renamed","group":"group_xK9mQ2pR","name":"New Name","renamed_by":"usr_alice"}

// Server -> Client (Phase 14 unified broadcast; new clients dispatch on this)
{"type":"group_event","group":"group_xK9mQ2pR","event":"rename","user":"usr_alice","by":"usr_alice","name":"New Name"}
```

The server emits both `group_renamed` (legacy) and `group_event{rename}` (Phase 14) during the single-repo upgrade window. Once client repos are fully at Phase 14 the legacy broadcast can be removed. Pass an empty string to clear the name.

#### `GroupEvent` reference

`group_event` is the generic broadcast envelope for every admin-initiated group mutation and self-leave:

| Field | Semantics |
|---|---|
| `group` | Group nanoid. |
| `event` | `"leave"` \| `"join"` \| `"promote"` \| `"demote"` \| `"rename"` |
| `user` | Target user (the member this event is about). |
| `by` | Acting admin user ID. Required (non-empty) for admin-initiated events (`join`, `promote`, `demote`, `rename`, and `leave` with `reason="removed"`). Empty for self-leave, retirement, and retirement-succession promote. |
| `reason` | On `leave`: `""` (self-leave) \| `"removed"` (admin kick, `by` required) \| `"retirement"` (retiring user). On `promote`: `""` (normal promote, `by` required) \| `"retirement_succession"` (auto-promote by server, `by` empty). |
| `name` | New group name. Populated only on `rename` events. |
| `quiet` | When `true`, clients MUST still update member/admin lists and persist the event to the local `group_events` table, but MUST suppress the inline system message. Never `true` for kicks (`leave` with `reason="removed"`) — being removed is high-consequence and clients should always surface it loudly. |

**`/leave` — explicit departure:**

```json
// Client -> Server
{"type":"leave_group","group":"group_xK9mQ2pR"}

// Server -> Client (broadcast to remaining members)
{"type":"group_event","group":"group_xK9mQ2pR","event":"leave","user":"usr_alice","reason":""}

// Server -> Client (echoed to every active session of the leaver)
{"type":"group_left","group":"group_xK9mQ2pR","reason":""}
```

The leaver receives `group_left` on all of their active sessions so every device can update its local state (mark as archived, disable input, etc.). Remaining members receive `group_event{event:"leave"}`. The client flow is "send `leave_group` → wait for `group_left` echo → update local state" — never optimistically flip state on the send.

`reason` values on `group_left`:
- `""` (empty) — self-leave via `/leave`
- `"removed"` — admin removed the user via `remove_from_group`. The `by` field carries the kicking admin's user ID so the client can render "You were removed from the group by alice" instead of the generic "by an admin".
- `"retirement"` — the leaving user's account was retired
- `"admin"` — **deprecated** legacy value from the pre-Phase-14 CLI escape hatch. No new rows should emit this; clients should treat it as equivalent to `"removed"` with unknown actor for any persisted rows encountered during upgrade.

**`/delete` — silent local purge, multi-device synced:**

```json
// Client -> Server
{"type":"delete_group","group":"group_xK9mQ2pR"}

// Server -> Client (echo to every active session of the caller)
{"type":"group_deleted","group":"group_xK9mQ2pR"}
```

`delete_group` is a stronger variant of `leave_group`. The server runs the leave logic (remove from `group_members`, broadcast `group_event{leave}` to remaining members) AND records a `deleted_groups` sidecar row so the caller's offline devices can catch up on reconnect. The `group_deleted` echo goes ONLY to the caller's sessions — remaining members see a normal leave event.

On receipt of `group_deleted`, clients purge all local messages and remove the group from their active list. Offline devices catch up via the `deleted_groups` catchup list delivered BEFORE `group_list` during the handshake:

```json
// Server -> Client (handshake catchup)
{"type":"deleted_groups","groups":["group_xK9mQ2pR","group_abc123"]}
```

Clients process each entry by running the same purge path as `group_deleted`. The ordering (catchup before list) means the active group list is populated from `group_list` AFTER the purged IDs have been reconciled.

**Last-member cleanup.** If a `leave_group` or `delete_group` removes the last remaining member, the server runs the full cleanup cascade: drop the `group_conversations` row, the `group_members` rows, and unlink the per-group DB file. The `deleted_groups` sidecar rows are deliberately preserved by this cascade so the catchup path still works for the user's other devices.

### Epoch Key Management

On connect, the server sends the current epoch key for each room:

```json
{"type":"epoch_key","room":"room_V1StGXR8_Z5jdHi6B","epoch":3,"wrapped_key":"base64..."}
```

**Rotation flow (server-triggered, client-executed):**

```json
// Server -> Client (you triggered rotation -- generate the new key)
{"type":"epoch_trigger","room":"room_V1StGXR8_Z5jdHi6B","new_epoch":4,"members":[{"user":"usr_alice","pubkey":"ssh-ed25519 AAAA..."},{"user":"usr_bob","pubkey":"ssh-ed25519 AAAA..."}]}

// Client -> Server (wrap new key for all members)
{"type":"epoch_rotate","room":"room_V1StGXR8_Z5jdHi6B","epoch":4,"wrapped_keys":{"usr_alice":"base64...","usr_bob":"base64..."},"member_hash":"SHA256:abc123..."}

// Server -> Client (confirmed -- you may now use this epoch)
{"type":"epoch_confirmed","room":"room_V1StGXR8_Z5jdHi6B","epoch":4}
```

**Critical rule:** Do NOT use the new epoch key for anything until `epoch_confirmed` is received. If the server rejects the rotation, discard the key entirely.

**Two-epoch grace window:** Server accepts messages encrypted with the current or previous epoch. Anything older is rejected. Continue sending with the old epoch during rotation; switch to the new epoch after `epoch_confirmed`.

**Monotonic enforcement:** Client must reject any `epoch_key` or `epoch_rotate` with an epoch number <= the current epoch. Exception: epoch keys in `sync_batch` and `history_result` are for historical decryption only and do not update the current epoch.

### Sync (Reconnect Catch-up)

```json
// Server -> Client (paginated, oldest-first)
{"type":"sync_batch","messages":[...],"epoch_keys":[{"room":"room_V1StGXR8_Z5jdHi6B","epoch":12,"wrapped_key":"base64..."}],"reactions":[...],"events":[...],"page":1,"has_more":true}
{"type":"sync_batch","messages":[...],"epoch_keys":[],"reactions":[],"events":[],"page":2,"has_more":false}

// Server -> Client
{"type":"sync_complete","synced_to":"2026-04-03T14:22:00Z"}
```

Room sync batches include epoch keys needed to decrypt that batch and reactions for the messages in that batch. DM messages carry their own `wrapped_keys` inline. Epoch key deduplication is the client's responsibility -- skip keys you already have.

**Phase 14: `events` field.** Group DM sync batches may carry an `events` array containing recent `group_event` rows that happened while the client was offline (admin actions like join, leave, promote, demote, rename). Clients route each entry through the same dispatch path used for live `group_event` broadcasts, so persisted replay and live delivery produce identical in-memory state + local DB rows. The `sinceTS` watermark is shared between messages and events — one timestamp, both sources. Non-group sync batches (rooms, 1:1 DMs) omit the field.

### History (Scroll-back)

The `history` request carries exactly one context field (`room`, `group`, or `dm`) matching the message family the caller wants to scroll back through. The response mirrors the shape of the corresponding sync batch for that context.

```json
// Client -> Server (room)
{"type":"history","room":"room_V1StGXR8_Z5jdHi6B","before":"msg_abc123","limit":100}

// Server -> Client (rooms -- includes epoch keys for the returned messages and any reactions on them)
{"type":"history_result","room":"room_V1StGXR8_Z5jdHi6B",
 "messages":[...],
 "epoch_keys":[{"epoch":8,"wrapped_key":"base64..."}],
 "reactions":[...],
 "has_more":true}

// Client -> Server (group DM)
{"type":"history","group":"group_xK9mQ2pR","before":"msg_def456","limit":100}

// Server -> Client (group DMs -- no epoch keys, each message carries its own wrapped_keys)
{"type":"history_result","group":"group_xK9mQ2pR",
 "messages":[...],
 "reactions":[...],
 "has_more":true}

// Client -> Server (1:1 DM)
{"type":"history","dm":"dm_yL0nR3qS","before":"msg_ghi789","limit":100}

// Server -> Client (1:1 DMs -- no epoch keys, each message carries its own wrapped_keys)
{"type":"history_result","dm":"dm_yL0nR3qS",
 "messages":[...],
 "reactions":[...],
 "has_more":true}
```

Store fetched messages and epoch keys locally -- subsequent scroll-back for the same range is served from the local DB.

Privacy: callers who are not members of the requested context get the same byte-identical error as "context not found" (`unknown_room` / `unknown_group` / `unknown_dm`), so a probing client cannot enumerate existence via `history`.

### Message Deletion

```json
// Client -> Server (context-free — the server looks up the message ID to determine which room/group/dm it belongs to)
{"type":"delete","id":"msg_abc123"}

// Server -> Client (broadcast — the server fills in exactly one of room/group/dm based on the looked-up context)
{"type":"deleted","id":"msg_abc123","deleted_by":"usr_alice","ts":1712345679,"room":"room_V1StGXR8_Z5jdHi6B"}
{"type":"deleted","id":"msg_def456","deleted_by":"usr_alice","ts":1712345679,"group":"group_xK9mQ2pR"}
{"type":"deleted","id":"msg_ghi789","deleted_by":"usr_alice","ts":1712345679,"dm":"dm_yL0nR3qS"}
```

**Permissions:**
- **Rooms:** own messages only, or any message if the caller is a server admin
- **Group DMs:** own messages only, no admin override (groups have no admin concept — admins have the CLI escape hatch)
- **1:1 DMs:** own messages only

Rate limited: 10 deletes/min for regular users, 50/min for admins (rooms only).

Deletion is a **soft-delete** — the server keeps the message row with `deleted = 1` and cleared payload. Tombstones (`{"type":"deleted",...}`) are interleaved in `sync_batch` and `history_result` so clients that reconnect after a deletion receive the tombstone and update their display. Clients should render deleted messages as visible tombstones in the message stream (e.g. "message deleted") rather than removing them, to preserve conversation flow.

Retired rooms reject `delete` with `room_retired` — the history becomes permanently frozen once the room is retired.

### Typing Indicators

Capability: `typing`

Typing envelopes carry exactly one of `room`, `group`, or `dm` — the same three-context pattern as messages.

```json
// Client -> Server (set exactly one context field)
{"type":"typing","room":"room_V1StGXR8_Z5jdHi6B"}
{"type":"typing","group":"group_xK9mQ2pR"}
{"type":"typing","dm":"dm_yL0nR3qS"}

// Server -> Client (broadcast to others in that context)
{"type":"typing","room":"room_V1StGXR8_Z5jdHi6B","user":"usr_alice"}
{"type":"typing","group":"group_xK9mQ2pR","user":"usr_alice"}
{"type":"typing","dm":"dm_yL0nR3qS","user":"usr_alice"}
```

Show for 5 seconds, then expire. Re-send while the user is actively typing. The `user` field is set by the server on broadcast; clients omit it on the send.

### Read Receipts

Capability: `read_receipts`

Read receipts carry exactly one of `room`, `group`, or `dm` plus the `last_read` message ID.

```json
// Client -> Server (set exactly one context field)
{"type":"read","room":"room_V1StGXR8_Z5jdHi6B","last_read":"msg_abc123"}
{"type":"read","group":"group_xK9mQ2pR","last_read":"msg_def456"}
{"type":"read","dm":"dm_yL0nR3qS","last_read":"msg_ghi789"}

// Server -> Client (broadcast to others — or, for 1:1 DMs, to the other party)
{"type":"read","room":"room_V1StGXR8_Z5jdHi6B","user":"usr_alice","last_read":"msg_abc123"}
```

### Unread Counts

```json
// Server -> Client (on connect — one per context with unread messages)
{"type":"unread","room":"room_V1StGXR8_Z5jdHi6B","count":12,"last_read":"msg_abc100"}
{"type":"unread","group":"group_xK9mQ2pR","count":3,"last_read":"msg_def400"}
{"type":"unread","dm":"dm_yL0nR3qS","count":1,"last_read":"msg_ghi200"}
```

### Reactions

Capability: `reactions`

Reactions carry exactly one context field (`room`, `group`, or `dm`) matching the target message's context. Room reactions are encrypted with the current epoch key; group DM and 1:1 DM reactions use a fresh per-reaction wrapped key, same model as sends.

```json
// Client -> Server (room -- encrypted with epoch key)
{"type":"react","id":"msg_abc123","room":"room_V1StGXR8_Z5jdHi6B","epoch":3,
 "payload":"base64...","signature":"base64..."}

// Client -> Server (group DM -- per-reaction wrapped key, wrapped for every current group member)
{"type":"react","id":"msg_def456","group":"group_xK9mQ2pR",
 "wrapped_keys":{"usr_alice":"base64...","usr_bob":"base64...","usr_carol":"base64..."},
 "payload":"base64...","signature":"base64..."}

// Client -> Server (1:1 DM -- per-reaction wrapped key, wrapped for exactly two parties)
{"type":"react","id":"msg_ghi789","dm":"dm_yL0nR3qS",
 "wrapped_keys":{"usr_alice":"base64...","usr_bob":"base64..."},
 "payload":"base64...","signature":"base64..."}

// Server -> Client (broadcast -- context field matches the react envelope)
{"type":"reaction","reaction_id":"react_7kQ2mR","id":"msg_abc123","room":"room_V1StGXR8_Z5jdHi6B",
 "user":"usr_alice","ts":1712345680,"epoch":3,
 "payload":"base64...","signature":"base64..."}

// Client -> Server (remove — reaction_id alone is enough, the server looks up the context)
{"type":"unreact","reaction_id":"react_7kQ2mR"}

// Server -> Client (broadcast — server fills in the context field)
{"type":"reaction_removed","reaction_id":"react_7kQ2mR","id":"msg_abc123",
 "room":"room_V1StGXR8_Z5jdHi6B","user":"usr_alice"}
```

**Encrypted reaction payload:** `{"emoji":"...","target":"msg_abc123","seq":43,"device_id":"dev_..."}`. Verify `target` matches the envelope `id` on decryption.

**Emoji handling is entirely client-side.** The server cannot see the emoji content — it's encrypted inside the `payload` field, same as message bodies. This has several implications:

- **Display aggregation is a client responsibility.** The server streams reaction events; clients decrypt and aggregate by emoji. Display count should be the number of **distinct users** who reacted with a given emoji, not the number of reaction events received. A user who sends the same emoji twice should appear once in the display.
- **De-duplication is client-enforced.** The server stores each reaction as a separate record keyed by `reaction_id` (server-generated). It does not enforce uniqueness on `(message_id, user, emoji)` because it can't see the emoji. Clients are expected to skip sending a `react` when the user already has a reaction with that emoji on the target message.
- **Removal uses `reaction_id`.** Clients must track the `reaction_id` of each reaction they care about (especially the current user's own reactions) so they can send `unreact` with the right ID. The recommended client-side index is `(message_id, user, emoji) → []reaction_id`.
- **Multi-device and race drift.** Two devices for the same user can send a `react` for the same emoji before either sees the server echo. The server will store both, producing a zombie record. Clients should de-duplicate at display time (one user, one emoji → one count) and `unreact` the most recent ID first if asked to remove. Periodic server-side GC of zombie records is not required for correctness.
- **Emoji normalisation.** Clients should normalise emoji strings before comparing for de-duplication (Unicode variation selectors, skin-tone modifiers, ZWJ sequences). A simple byte-wise equality check over UTF-8 is sufficient for the common cases; clients that want exact agreement with other client implementations should NFC-normalise.
- **Multiple distinct emojis per user are allowed and expected.** A user can react to the same message with `👍` and `🎉` and `❤️` simultaneously. The model is Slack/Discord-style, not Signal-style (which replaces).
- **Removal UX.** Clients should expose an explicit "Remove my reaction" action (e.g., context menu entry) rather than relying on re-picking an emoji to toggle. Picking the same emoji twice in the emoji picker should be a no-op, not a removal.

### Pinned Messages

Rooms only. Neither group DMs nor 1:1 DMs support pins — the `pin` / `unpin` / `pinned` / `unpinned` envelopes carry a `room` field and no alternative context variants.

```json
// Client -> Server
{"type":"pin","room":"room_V1StGXR8_Z5jdHi6B","id":"msg_abc123"}

// Server -> Client
{"type":"pinned","room":"room_V1StGXR8_Z5jdHi6B","id":"msg_abc123","pinned_by":"usr_alice","ts":1712345681}

// Server -> Client (on connect -- includes full message envelopes for decryption)
{"type":"pins","room":"room_V1StGXR8_Z5jdHi6B","messages":["msg_abc123","msg_def456"],"message_data":[{"type":"message","id":"msg_abc123","from":"usr_alice","room":"room_V1StGXR8_Z5jdHi6B","ts":1712345678,"epoch":3,"payload":"base64...","signature":"base64..."}]}

// Unpin
{"type":"unpin","room":"room_V1StGXR8_Z5jdHi6B","id":"msg_abc123"}
{"type":"unpinned","room":"room_V1StGXR8_Z5jdHi6B","id":"msg_abc123"}
```

The server filters pins by the user's `first_epoch` -- new members only see pins from messages they can decrypt. `message_data` includes the full encrypted message envelopes so clients can decrypt and show pin previews without scrolling back.

### Profiles

```json
// Client -> Server
{"type":"set_profile","display_name":"Alice Chen","avatar_id":"file_avatar001"}

// Server -> Client (broadcast to visible users)
{"type":"profile","user":"usr_alice","display_name":"Alice Chen","avatar_id":"file_avatar001","pubkey":"ssh-ed25519 AAAA...","key_fingerprint":"SHA256:abcdef123456..."}
```

Profiles include the user's full public key and fingerprint. Use these for key wrapping and key pinning.

**Display name rules:**
- Min 2, max 32 characters
- No leading/trailing whitespace (server trims)
- Server-enforced uniqueness (case-insensitive) — returns `username_taken` if the name collides with another user
- Invalid names return `invalid_profile`
- Rate-limited: 5 profile changes per minute (default)

### User Status

```json
// Client -> Server
{"type":"set_status","text":"On vacation until Monday"}
{"type":"set_status","text":""}
```

Status is included in presence messages.

### Presence

Capability: `presence`

```json
{"type":"presence","user":"usr_bob","status":"online","display_name":"Bob","avatar_id":"file_bob_avatar"}
{"type":"presence","user":"usr_bob","status":"offline","display_name":"Bob","avatar_id":"file_bob_avatar","last_seen":"2026-04-03T14:00:00Z"}
```

### Room, Group, and DM Lists

Three separate list messages are delivered during the handshake, one per context family. Their ordering in the connect sequence is documented in the Handshake section.

```json
// Server -> Client (rooms the user is a member of)
{"type":"room_list","rooms":[
  {"id":"room_V1StGXR8_Z5jdHi6B","name":"general","topic":"General chat","members":12}
]}

// Server -> Client (group DMs the user is a member of — Phase 14 adds admins field)
{"type":"group_list","groups":[
  {"id":"group_xK9mQ2pR","members":["usr_alice","usr_bob","usr_carol"],"admins":["usr_alice"],"name":"Project Alpha"},
  {"id":"group_yL0nR3qS","members":["usr_alice","usr_dave"],"admins":["usr_alice","usr_dave"]}
]}

// Server -> Client (1:1 DMs the user is a party to, with per-user cutoff)
{"type":"dm_list","dms":[
  {"id":"dm_abc123","members":["usr_alice","usr_bob"]},
  {"id":"dm_def456","members":["usr_alice","usr_eve"],"left_at_for_caller":1712345600}
]}
```

`dm_list` entries may carry `left_at_for_caller > 0` to indicate the caller has previously `/delete`d this DM from another device. Clients should filter those entries out of their active DM list (the non-zero cutoff means the server has already frozen the caller's view past that timestamp).

**Room membership events:**

```json
// Server -> Client (rooms — broadcast to remaining members on join/leave)
{"type":"room_event","room":"room_V1StGXR8_Z5jdHi6B","event":"join","user":"usr_carol"}
{"type":"room_event","room":"room_V1StGXR8_Z5jdHi6B","event":"leave","user":"usr_carol","reason":""}
```

`reason` on `leave` distinguishes the trigger so clients can render distinct system messages:
- `""` (empty) — self-leave via `/leave`
- `"admin"` — admin removed via `sshkey-ctl remove-from-room`
- `"user_retired"` — the leaving user's account was retired

(Room retirement — an admin retiring the room itself — does NOT use this `reason` field. It's a separate `room_retired` broadcast; see **Room Retirement** below.)

**Group DM membership events:**

```json
// Server -> Client (groups — broadcast to remaining members on leave)
{"type":"group_event","group":"group_xK9mQ2pR","event":"leave","user":"usr_alice","reason":""}
```

`reason` values mirror `room_event`: `""` (self-leave), `"admin"` (CLI escape hatch), `"retirement"` (account retirement). Groups don't emit a `join` event because group membership is fixed at creation — there is no add path in the protocol.

**Room member query (lazy):**

```json
// Client -> Server (request room member list — must be a member of the room)
{"type":"room_members","room":"room_V1StGXR8_Z5jdHi6B"}

// Server -> Client
{"type":"room_members_list","room":"room_V1StGXR8_Z5jdHi6B","members":["usr_abc","usr_def","usr_ghi"]}
```

`room_members` is a lazy query — clients send it when they need the full member list for a room (e.g., when displaying room details), not on every room switch. The server rejects non-members with `unknown_room` (byte-identical to the response for a room that doesn't exist). Retired users are excluded from the response. Group DM and 1:1 DM members are known client-side from `group_list` / `dm_list` and don't need this request.

### Room `/leave` and `/delete`

Two client-initiated room-exit paths, both gated by server policy flags in `[server]`:

- `allow_self_leave_rooms` (default `false`) — may users self-leave active rooms? Admin-managed membership is the default.
- `allow_self_leave_retired_rooms` (default `true`) — may users self-leave rooms that an admin has already retired? Users can clean up dead rooms even when active-room leave is locked down.

```json
// Client -> Server
{"type":"leave_room","room":"room_V1StGXR8_Z5jdHi6B"}

// Server -> Client (echo to all sessions of the leaver after DB write succeeds)
{"type":"room_left","room":"room_V1StGXR8_Z5jdHi6B"}

// Server -> Client (broadcast to remaining members)
{"type":"room_event","room":"room_V1StGXR8_Z5jdHi6B","event":"leave","user":"usr_alice","reason":""}
```

`/delete` is a stronger variant that combines the leave with a local-state purge. Works on both active and retired rooms (the retired case uses the `allow_self_leave_retired_rooms` flag). The server records the deletion intent in a `deleted_rooms` sidecar table before running the leave logic, so the catchup signal survives any last-member cleanup cascade.

```json
// Client -> Server
{"type":"delete_room","room":"room_V1StGXR8_Z5jdHi6B"}

// Server -> Client (echo to all sessions of the deleter)
{"type":"room_deleted","room":"room_V1StGXR8_Z5jdHi6B"}
```

On receipt of `room_deleted`, clients purge local messages, reactions, and epoch keys for that room, then remove the room from their active list. The server's `deleted_rooms` sidecar drives offline-device catchup via the `deleted_rooms` list below.

### Room Retirement

Admins retire rooms via `sshkey-ctl retire-room` (local-only — no remote admin verb). The CLI writes directly to the server DB and queues a `pending_room_retirements` row; a background processor (5s poll) drains the queue, looks up connected members, and broadcasts `room_retired` to them.

Retiring a room:

- Sets `retired_at` on the `rooms` row
- Appends a 4-character base62 suffix to the room's display name (e.g. `general` → `general_A3fQ`) so an admin can create a new room with the original name without collision
- Freezes epoch rotation (no new keys will be generated; existing history remains decryptable with the epoch keys clients already have)
- Rejects further writes (`send`, `react`, `pin`, `unpin`) from any member with `room_retired` error code
- Does NOT remove anyone from `room_members` — retirement is orthogonal to leaving. Users can still `/delete` the retired room to remove it from their view.

```json
// Server -> Client (broadcast to connected members when retirement happens)
{"type":"room_retired","room":"room_V1StGXR8_Z5jdHi6B","name":"general_A3fQ","retired_at":1712764800}

// Server -> Client (handshake catchup — rooms retired while this device was offline)
{"type":"retired_rooms","rooms":[{"room":"room_V1StGXR8_Z5jdHi6B","name":"general_A3fQ","retired_at":1712764800}]}

// Server -> Client (handshake catchup — rooms /delete'd from another device while this one was offline)
{"type":"deleted_rooms","rooms":["room_V1StGXR8_Z5jdHi6B"]}
```

Clients should treat retired rooms as read-only — disable message input and surface the retired state to the user. Only `/delete` remains as an exit path. The `retired_rooms` and `deleted_rooms` lists are delivered during the handshake **before** `room_list`, so clients can filter out retired/deleted rooms from the active set before rendering.

### File Transfer

Capability: `file_transfer`

Metadata on Channel 1, raw bytes on Channel 2 (downloads) or Channel 3 (uploads). File content is encrypted client-side before upload.

```json
// Channel 1: Client -> Server (content_hash is required)
{"type":"upload_start","upload_id":"up_001","size":45000,"content_hash":"blake2b-256:a1b2c3...","room":"room_V1StGXR8_Z5jdHi6B"}

// Channel 1: Server -> Client
{"type":"upload_ready","upload_id":"up_001"}

// Channel 3: Client -> Server (binary frame -- see below)

// Channel 1: Server -> Client
{"type":"upload_complete","upload_id":"up_001","file_id":"file_xyz"}
```

The `content_hash` field is **required**. Format: `blake2b-256:<hex>` — a BLAKE2b-256 hash of the encrypted bytes. The server verifies the hash after receiving the file and rejects on mismatch. The hash is stored and echoed back on downloads so clients can verify integrity before decrypting.

If the server rejects an `upload_start` (rate limit, size limit, missing hash, hash mismatch, etc.), it replies with `upload_error`:

```json
// Channel 1: Server -> Client (rejection)
{"type":"upload_error","upload_id":"up_001","code":"rate_limited","message":"Upload rate limit exceeded"}
```

Upload error codes: `rate_limited`, `upload_too_large`, `missing_hash`, `hash_mismatch`, `invalid_message`.

Then send a message referencing the `file_id`. Upload first, message second.

```json
// Download (client MUST wait for download_start before reading Channel 2)
{"type":"download","file_id":"file_xyz"}
{"type":"download_start","file_id":"file_xyz","size":45000,"content_hash":"blake2b-256:a1b2c3..."}
// Channel 2: Server -> Client (binary frame)
{"type":"download_complete","file_id":"file_xyz"}
```

Clients MUST wait for `download_start` on Channel 1 before reading from Channel 2. On receipt, hash the received encrypted bytes and compare with `content_hash`. Discard without writing to disk on mismatch.

If the server rejects the download, it replies with `download_error` and nothing is written to Channel 2:

```json
// Channel 1: Server -> Client (rejection — no binary frame follows)
{"type":"download_error","file_id":"file_xyz","code":"not_found","message":"File not found: file_xyz"}
```

Download error codes: `not_found`, `no_channel`, `open_failed`.

**Timeout:** Clients should apply a 30-second timeout when waiting for `upload_ready`, `upload_complete`, and `download_start`. If the server doesn't respond within 30 seconds, abort with a timeout error.

**Binary frame format (Channels 2 and 3):**

```
id_len (1 byte) | id (variable) | data_len (8 bytes, big-endian uint64) | data (raw bytes)
```

The `id` is the `upload_id` (on Channel 3, client -> server) or `file_id` (on Channel 2, server -> client). Read `id_len`, then `id`, then `data_len`, then exactly `data_len` bytes.

Concurrent uploads share Channel 3 and so must serialize their frame writes (clients typically use a single mutex for the upload channel). Concurrent downloads share Channel 2 the same way on the client side. But an upload and a download happen on different channels and can proceed in parallel.

**Room files:** encrypt with the current epoch key. Record `file_epoch` in the attachment metadata so recipients know which epoch key decrypts the file (usually matches the message's epoch; only differs during epoch transitions).

**DM files:** encrypt each attachment with its own fresh per-file key `K_file` and store `K_file` (base64) in the attachment's `file_key` field inside the encrypted message payload. Recipients decrypt the DM payload (using their wrapped `K_msg`), read `file_key` off each attachment, then download and decrypt the file bytes independently. Design properties:

- **Per-file keys, decoupled from the message key.** `K_msg` protects the payload (including each `K_file`); each `K_file` protects only its file. An attacker who recovers `K_msg` still must separately recover each `K_file` — though in practice both live inside the same encrypted envelope.
- **Upload and send are independent operations.** You can upload a file, get back `(file_id, K_file)`, then build the message whenever you're ready (or attach the same file to a later message by re-referencing its `(file_id, K_file)` pair).
- **Each attachment is self-contained.** A recipient re-opening an attachment months later only needs the decrypted payload — no envelope key rederivation.
- **The same `Attachment` struct serves rooms and DMs.** Rooms populate `file_epoch`; DMs populate `file_key`. Both fields are `omitempty`.
- **Forward secrecy:** compromise of a single `K_file` exposes only that one file. Compromise of `K_msg` exposes the payload and every `K_file` it carries (since they live inside the payload) — so attack surfaces are equivalent for the common case, but per-file isolation means keys age independently and can be deleted piecewise.

Decrypted payload for a DM message with an attachment:

```json
{
  "body": "here's the thing",
  "seq": 17,
  "device_id": "dev_V1StGXR8_Z5jdHi6B-myT",
  "attachments": [{"file_id":"file_abc","name":"pic.jpg","size":45000,"mime":"image/jpeg","file_key":"base64_K_file"}]
}
```

For room messages with attachments, the payload includes `file_epoch` on each attachment instead of `file_key` (see Message Types → Room Messages).

### Push Registration

```json
// Client -> Server
{"type":"push_register","platform":"ios","device_id":"dev_iphone_def456","token":"apns_device_token_here"}

// Server -> Client
{"type":"push_registered","platform":"ios"}
```

Re-send on every foreground connect (token upsert). Platform is `"ios"` or `"android"`.

### Server Shutdown

```json
{"type":"server_shutdown","message":"Server restarting, back shortly","reconnect_in":10}
```

Save unsent drafts, show the message, begin reconnect after `reconnect_in` seconds with exponential backoff.

### Device Revocation

```json
{"type":"device_revoked","device_id":"dev_macbook_abc","reason":"admin_action"}
```

Server disconnects the device and rejects future connections from that device ID. Device revocation is scoped to a single client — the user's account remains active on other devices, and the SSH key continues to authenticate from new devices. For identity-level termination (key compromise), see Account Retirement.

**User-initiated device management:**

```json
// Client -> Server (request list of own devices)
{"type":"list_devices"}

// Server -> Client
{"type":"device_list","devices":[
  {"device_id":"dev_laptop","last_synced_at":"2026-04-05T12:00:00Z","created_at":"2026-01-01T00:00:00Z","current":true},
  {"device_id":"dev_phone","last_synced_at":"2026-04-01T08:00:00Z","created_at":"2026-02-01T00:00:00Z"},
  {"device_id":"dev_old","last_synced_at":"","created_at":"2025-06-01T00:00:00Z","revoked":true}
]}

// Client -> Server (revoke one of own devices — server rejects if not owned)
{"type":"revoke_device","device_id":"dev_phone"}

// Server -> Client
{"type":"device_revoke_result","device_id":"dev_phone","success":true}
```

Users can list and revoke their own devices without admin intervention. The server validates that the target `device_id` belongs to the authenticated user before revoking. Self-revocation (revoking the current device) is allowed and will disconnect the requesting session.

Admins can still revoke any user's device via `sshkey-ctl revoke-device --user --device`.

### Account Retirement

Ed25519 keys are permanent identities on this server. There is no key rotation. When an account needs to end — lost key, compromised key, retired identity — the account is **retired**: monotonic, irreversible, and client-triggered or admin-triggered.

**Client-initiated (self-service):**

```json
// Client -> Server (authenticated by the current SSH connection)
{"type":"retire_me","reason":"self_compromise"}
```

Valid reasons: `self_compromise` (suspected key theft), `switching_key` (voluntary identity change), `other`. The server authenticates the target from the SSH connection — the message has no `user` field. An attacker with the stolen key can also trigger retirement, but the outcome is the same (the legitimate user needs a new account either way).

**Admin-initiated (out-of-band):** the server operator runs `sshkey-ctl retire-user <name> --reason <reason>`. The server reads retirement status from users.db on demand, so the change takes effect immediately.

**Server broadcasts to peers:**

```json
// Server -> Client (real-time transition, broadcast to all connected clients)
{"type":"user_retired","user":"usr_alice","ts":1712345678}

// Server -> Client (on connect, after welcome, listing known retired users visible to this client)
{"type":"retired_users","users":[{"user":"usr_alice","retired_at":"2026-04-05T14:30:00Z"}]}
```

Clients use these to render `[retired]` markers on historical messages, mark 1:1 DMs with retired partners as read-only, and exclude retired users from mention completion and new-DM candidates.

**What happens when a user is retired:**
- The SSH key no longer authenticates (handshake rejected with "account retired")
- All active sessions for that user are terminated immediately
- `room_event` leaves are broadcast for every room they were in, with `reason: "user_retired"`
- Epoch rotations are marked for all those rooms (next sender triggers the new key)
- The user is removed from all group DMs (3+ members), and a `group_event` leave with `reason: "retirement"` is broadcast to remaining members
- The user is kept in the `direct_messages` row for each 1:1 DM (both parties stay in the row) so the other party retains the conversation in their UI — but sends to that DM are rejected with `user_retired` error
- Profile messages for the retired user now include `"retired": true` and `"retired_at": "..."` for clients that connect later

**Profile extensions on retirement:**

```json
{"type":"profile","user":"usr_alice","display_name":"Alice","pubkey":"ssh-ed25519 ...","key_fingerprint":"SHA256:...","retired":true,"retired_at":"2026-04-05T14:30:00Z"}
```

The key and fingerprint are still delivered so clients can verify signatures on historical messages from the retired user.

**Send-time enforcement:** `send_dm`, `send_group`, `react` (on DMs / groups), `create_dm`, and `create_group` reject with `user_retired` error code if any target member is retired. `send` (room messages) is not affected — retired users are removed from rooms synchronously at retirement time, so their exclusion from room writes is automatic via the membership check that already runs on every send.

**Username reuse rule:** retired usernames cannot be reused for new accounts. The server and `sshkey-ctl approve` reject new accounts with a username matching a retired entry. This prevents identity confusion, DM routing conflicts, and silent key overwrites. Usernames are immutable internal IDs; display names (changeable via `set_profile`) are the human-visible names with server-enforced uniqueness. See `PROJECT.md` section "Identity Model" for details.

**See `PROJECT.md` section "Account Retirement"** for the full design rationale, threat model (key compromise vs. device theft vs. rotation), username reuse handling, and the attacker-vs-victim race analysis.

### Admin Notifications

```json
{"type":"admin_notify","event":"pending_key","fingerprint":"SHA256:xx...","attempts":3,"first_seen":"2026-04-03T14:22:00Z"}
```

Delivered only to connected admin clients.

**Pending key listing (admin-only):**

```json
// Client -> Server (admin-only, non-admins get error)
{"type":"list_pending_keys"}

// Server -> Client
{"type":"pending_keys_list","keys":[
  {"fingerprint":"SHA256:xx...","attempts":3,"first_seen":"2026-04-03T14:22:00Z","last_seen":"2026-04-04T10:15:00Z"}
]}
```

Admin clients send `list_pending_keys` and present the result to the operator. Approve/reject is done via `sshkey-ctl`.

### Errors

```json
{"type":"error","code":"not_authorized","message":"You don't have access to room: admin","ref":"msg_abc123"}
```

`ref` is optional -- the ID of the client message that caused the error.

| Code | When |
|---|---|
| `not_authorized` | Caller cannot perform the action (e.g. delete another user's message without admin rights) |
| `rate_limited` | Any rate limit exceeded (messages, uploads, history, deletes, reactions, DM creation, profile changes, pins) |
| `message_too_large` | Body exceeds 16KB |
| `upload_too_large` | File exceeds server max (default 50MB) |
| `epoch_conflict` | Another client's rotation was accepted first |
| `stale_member_list` | Membership changed during rotation |
| `invalid_wrapped_keys` | DM or group DM `wrapped_keys` don't match the current member list |
| `device_limit_exceeded` | Max devices per user reached (default 10) |
| `invalid_epoch` | Epoch too old (outside grace window) or not yet confirmed |
| `unknown_room` | Caller is not a member of this room (also returned byte-identical for "room does not exist" to protect the social graph) |
| `unknown_group` | Caller is not a member of this group DM (same byte-identical privacy rule as `unknown_room`). Phase 14: also returned byte-identical for "not an admin" on admin-verb requests so non-admin status is not enumerable via error diffs. |
| `unknown_dm` | Caller is not a party to this 1:1 DM (same privacy rule) |
| `unknown_user` | **Phase 14.** `add_to_group` target does not exist or is retired. Only returned AFTER the caller has proven admin status — before that the "unknown user" case collapses into `unknown_group`. |
| `already_member` | **Phase 14.** `add_to_group` target is already a member of the group. |
| `already_admin` | **Phase 14.** `promote_group_admin` target is already an admin of the group. |
| `user_retired` | Sender or target of a DM operation has a retired account |
| `room_retired` | Room has been retired by an admin — writes (`send`, `react`, `unreact`, `pin`, `unpin`, `delete`) are rejected |
| `forbidden` | Policy gate denied the request (e.g. `allow_self_leave_rooms = false` on `leave_room` or `delete_room`) |
| `server_busy` | A cleanup mutex is held by a concurrent operation; clients should retry with short backoff (used on `create_dm` races) |
| `invalid_message` | Malformed JSON envelope, missing required fields, or invalid values (e.g. creating a DM with yourself) |
| `too_many_members` | Group DM exceeds 150-member hard cap |
| `invalid_profile` | Display name validation failed (too short, too long, invalid characters) |
| `username_taken` | Display name already in use by another user (server-enforced uniqueness, case-insensitive) |
| `internal` | Server-side failure (DB error, etc.) — client should retry or reconnect |
| `client_required` | Connection from an unknown key or non-protocol SSH session — shows install/approval instructions |

**Byte-identical privacy responses.** The three `unknown_*` codes carry byte-identical wire responses across their ambiguous failure modes — "room does not exist" and "not a member of an existing room" return exactly the same bytes, so a probing client cannot enumerate existence via error diffs. The same invariant applies to groups and DMs.

### Rate Limits

The server enforces per-user rate limits on most operations. When exceeded, the server returns `{"type":"error","code":"rate_limited","message":"..."}`. All limits are configurable via `server.toml` `[rate_limits]`. Defaults:

| Operation | Default | Scope |
|---|---|---|
| Room/group/DM messages | 5/second | Per user |
| Uploads | 60/minute | Per user |
| Connections | 20/minute | Per IP |
| Failed auth attempts | 5/minute | Per IP |
| Typing indicators | 1/second | Per user |
| History requests | 50/minute | Per user |
| Message deletes | 10/minute | Per user (regular), 50/minute (admin) |
| Reactions | 30/minute | Per user |
| DM creation | 5/minute | Per user |
| Profile changes | 5/minute | Per user |
| Pin/unpin | 10/minute | Per user |
| Group admin actions | 20/minute | Per user, per group (Phase 14) — applies to `add_to_group`, `remove_from_group`, `promote_group_admin`, `demote_group_admin`, and `rename_group`. Server-initiated paths (retirement cascade, last-member cleanup) are exempt. |

Clients should handle `rate_limited` errors gracefully — show a "Slow down" message in the status bar and retry after a brief pause. Do not retry automatically in a tight loop.

### Server Validation

The server validates every incoming message. Common rejection reasons a client builder should handle:

- **Message body size:** 16KB max. Exceeding returns `message_too_large`.
- **File upload size:** 50MB max (configurable). Exceeding returns `upload_too_large`.
- **Group DM member count:** 150 max. Exceeding returns `too_many_members`.
- **Display name:** 2-32 characters, no leading/trailing whitespace, unique (case-insensitive). Invalid returns `invalid_profile`; taken returns `username_taken`.
- **Ed25519 keys only:** RSA, ECDSA, and other key types are rejected at the SSH handshake level.
- **Malformed messages:** Missing required fields, invalid JSON, or wrong field types return `invalid_message`.
- **Epoch validation:** Messages encrypted with an epoch older than the grace window (current - 1) are rejected with `invalid_epoch`.
- **Wrapped-key validation:** `wrapped_keys` on group/DM sends must match the current member list exactly. Mismatch returns `invalid_wrapped_keys`.
- **Content hash on uploads:** `content_hash` is required on `upload_start`. Format: `blake2b-256:<hex>`. The server verifies the hash after receiving the file; mismatch returns `hash_mismatch`.

---

## Client-Side Storage

Single encrypted SQLite DB per server. Key derived from SSH private key via HKDF-SHA256. Use SQLCipher for transparent encryption. Full schema from day one — all tables exist at creation, no conditional schema.

Recommended libraries:
- Go: `modernc.org/sqlite` (pure Go) or `go-sqlcipher` (encrypted)
- Rust: `rusqlite` + SQLCipher

The local DB is a cache, not the source of truth. It can be pruned or wiped -- anything within the server's retention window can be re-fetched via `history` requests.

## Minimal Client Checklist

A minimal client that can connect and chat needs:

1. SSH connection with Ed25519 key (open Channel 1 for NDJSON; Channels 2 and 3 for files are optional if you skip `file_transfer`)
2. NDJSON codec (read/write JSON lines)
3. Handshake (send `client_hello`, process `server_hello` and `welcome`)
4. Read the connect-sequence messages and apply them to local state in order: `deleted_rooms` → `retired_rooms` → `room_list` → `deleted_groups` → `group_list` → `dm_list` → `profile` (one per user) → `retired_users` → `epoch_key` → `sync_batch` ... → `sync_complete`
5. AES-256-GCM encryption/decryption
6. X25519 key wrapping/unwrapping (for room epoch keys AND group/1:1 DM per-message wrapped keys — same algorithm, different lifecycle)
7. Send (pick the right verb per context):
   - `send` + `message` for rooms
   - `send_group` + `group_message` for group DMs
   - `send_dm` + `dm` for 1:1 DMs
8. Receive and decrypt all three message types. Each carries exactly one context field (`room`, `group`, or `dm`) on the envelope.
9. Ed25519 signature generation and verification. The server always expects signatures on sends. Canonical form differs per context — see Encryption → Message Signatures.
10. Local key storage (pinned peer fingerprints, epoch keys per room)

A minimal client that understands only rooms + 1:1 DMs is still a usable chat client — group DMs can be deferred — but the handshake sequence MUST be handled correctly (including catchup lists before active-list messages) or multi-device `/delete` will desync.

Everything else (typing, reactions, presence, file transfer, pins, read receipts, safety numbers, replay detection, `/leave`, `/delete`, room retirement) is optional and can be added incrementally. When you add `/leave` or `/delete`, wait for the server echo (`room_left`, `group_left`, `dm_left`, `room_deleted`, `group_deleted`) before touching local state — the server is authoritative.

---

## Reconnect Guidance

Clients should handle disconnects gracefully and reconnect automatically.

**SSH keepalive:** Send SSH keepalive packets every 30 seconds. If 3 consecutive keepalives receive no response, treat the connection as dead and begin reconnecting. This detects dead connections faster than TCP timeout (which can take minutes).

**Exponential backoff:** On disconnect, wait 1s before the first reconnect attempt, then double the delay on each failure: 1s → 2s → 4s → 8s → 16s → 30s → 60s cap. Reset to 1s on successful reconnect. No maximum retry count — keep trying indefinitely.

**What to send on reconnect:** Same `client_hello` as the initial connect, but with `last_synced_at` set to the `synced_to` value from the previous session's `sync_complete`. This tells the server to send only messages newer than that timestamp. If you don't have a stored `synced_to` (first connect, or local DB was wiped), send an empty `last_synced_at` — the server skips sync batches entirely and you start fresh.

**Idempotent sync:** `sync_batch` messages are safe to replay — all messages have unique IDs. If you receive a message you already have locally, skip it.

**Don't queue messages while offline.** The server doesn't accept messages without a live SSH connection. The client can't encrypt for the correct epoch without fresh keys from the server. Show the user that input is disabled during reconnect.

**Status feedback:** Show the user what's happening — "Reconnecting (attempt 3, next retry in 8s)" is better than a silent spinner. On successful reconnect, show "Connected" briefly, then clear.

---

## Connection Lifecycle

```
SSH connect (Ed25519 key)
    │
    ├── Key not approved ──────────→ "client_required" error, disconnect
    ├── Account retired ───────────→ rejected at SSH level, disconnect
    │
    ▼
server_hello → client_hello (2s timeout) → welcome
    │
    ├── Device revoked ────────────→ "device_revoked", disconnect
    ├── Too many devices ──────────→ "device_limit_exceeded", disconnect
    │
    ▼
Connect sequence (13+ messages: catchup lists → active lists → profiles → keys → sync)
    │
    ▼
sync_complete
    │
    ▼
Real-time push ←──────────────────→ Client sends messages, reactions, etc.
    │
    ├── SSH keepalive timeout ─────→ Reconnect with exponential backoff
    ├── Server shutdown ───────────→ "server_shutdown" with reconnect_in hint
    ├── Device revoked mid-session → "device_revoked", disconnect
    │
    ▼
Disconnect → Reconnect loop (client_hello with last_synced_at)
```

---

## Wire Examples (End-to-End Flows)

### Sending a room message

```
Client                                      Server
  │                                            │
  │  1. Look up epoch key for room_abc         │
  │     (from local epoch_keys cache)          │
  │                                            │
  │  2. Build payload JSON:                    │
  │     {"body":"Hello!","seq":42,             │
  │      "device_id":"dev_laptop"}             │
  │                                            │
  │  3. Encrypt payload with epoch key:        │
  │     nonce = random 12 bytes                │
  │     ciphertext = AES-256-GCM(key, nonce,   │
  │                               payload)     │
  │     payload_b64 = base64(nonce||ciphertext) │
  │                                            │
  │  4. Sign: sig = Sign(payload_bytes          │
  │           || room_id || epoch_be64)         │
  │                                            │
  ├─ {"type":"send",                          ─┤
  │   "room":"room_abc","epoch":3,             │
  │   "payload":"base64...","signature":"..."}  │
  │                                            │
  │                    5. Server validates:     │
  │                       - membership         │
  │                       - room not retired   │
  │                       - rate limit         │
  │                       - epoch in window    │
  │                       - body size ≤ 16KB   │
  │                    6. Assigns ID + TS      │
  │                    7. Stores in room DB    │
  │                    8. Broadcasts to members│
  │                                            │
  │◀─ {"type":"message","id":"msg_xyz",       ─┤
  │    "from":"usr_alice","room":"room_abc",    │
  │    "ts":1712345678,"epoch":3,              │
  │    "payload":"base64...","signature":"..."} │
  │                                            │
  │  9. Decrypt with same epoch key            │
  │  10. Verify signature against alice's key  │
  │  11. Display message                       │
```

### Sending a 1:1 DM

```
Client                                      Server
  │                                            │
  │  1. Generate random K_msg (256-bit AES)    │
  │  2. Wrap K_msg for alice + bob:            │
  │     wrapped_keys = {                       │
  │       "usr_alice": wrap(K_msg, alice_pub), │
  │       "usr_bob":   wrap(K_msg, bob_pub)    │
  │     }                                      │
  │  3. Encrypt payload with K_msg             │
  │  4. Sign with dm_id + wrapped_keys         │
  │                                            │
  ├─ {"type":"send_dm","dm":"dm_abc",         ─┤
  │   "wrapped_keys":{...},                    │
  │   "payload":"base64...","signature":"..."}  │
  │                                            │
  │◀─ {"type":"dm","id":"msg_xyz",            ─┤
  │    "from":"usr_alice","dm":"dm_abc",        │
  │    "ts":1712345678,                        │
  │    "wrapped_keys":{...},                   │
  │    "payload":"base64...","signature":"..."} │
  │                                            │
  │  5. Unwrap own key: K_msg =                │
  │     unwrap(wrapped_keys["usr_bob"],        │
  │            bob_priv)                       │
  │  6. Decrypt payload with K_msg             │
  │  7. Verify signature against alice's key   │
```

### Epoch rotation

```
Client A (triggers rotation)                Server
  │                                            │
  │  A sends a message to room_abc             │
  │  Server checks: rotation needed?           │
  │  (100 msgs or 1 hour since last rotation)  │
  │                                            │
  │◀─ {"type":"epoch_trigger",                ─┤
  │    "room":"room_abc","new_epoch":4,         │
  │    "members":[                             │
  │      {"user":"usr_alice","pubkey":"..."},   │
  │      {"user":"usr_bob","pubkey":"..."}      │
  │    ]}                                      │
  │                                            │
  │  1. Generate random 256-bit epoch key      │
  │  2. Wrap for each member in the list       │
  │  3. Hash member list for verification      │
  │                                            │
  ├─ {"type":"epoch_rotate","room":"room_abc", ─┤
  │   "epoch":4,                               │
  │   "wrapped_keys":{"usr_alice":"...","usr_bob":"..."},│
  │   "member_hash":"SHA256:abc..."}            │
  │                                            │
  │◀─ {"type":"epoch_confirmed",              ─┤
  │    "room":"room_abc","epoch":4}             │
  │                                            │
  │  *** NOW safe to use epoch 4 for sends *** │
  │                                            │
  │  All members receive epoch_key:            │
  │◀─ {"type":"epoch_key","room":"room_abc",  ─┤
  │    "epoch":4,"wrapped_key":"..."}           │
```

**Critical:** Do NOT use the new epoch key for anything until `epoch_confirmed` is received. If the server rejects the rotation (e.g., another client's rotation was accepted first — `epoch_conflict`), discard the key entirely.

### File upload

```
Client                                      Server
  │                                            │
  │  1. Encrypt file with epoch key (rooms)    │
  │     or per-file key K_file (DMs)           │
  │  2. Hash encrypted bytes:                  │
  │     content_hash = blake2b-256(encrypted)   │
  │                                            │
  ├─ Ch1: {"type":"upload_start",             ─┤
  │   "upload_id":"up_001",                    │
  │   "size":45000,                            │
  │   "content_hash":"blake2b-256:a1b2c3...",   │
  │   "room":"room_abc"}                       │
  │                                            │
  │◀─ Ch1: {"type":"upload_ready",            ─┤
  │    "upload_id":"up_001"}                    │
  │                                            │
  ├─ Ch3: binary frame (id_len|id|data_len|data)─┤
  │   id = "up_001"                            │
  │   data = encrypted file bytes              │
  │                                            │
  │  Server verifies content_hash              │
  │                                            │
  │◀─ Ch1: {"type":"upload_complete",         ─┤
  │    "upload_id":"up_001","file_id":"file_xyz"}│
  │                                            │
  │  3. Reference file_id in message:          │
  ├─ {"type":"send","room":"room_abc",        ─┤
  │   "epoch":3,"file_ids":["file_xyz"],       │
  │   "payload":"base64...","signature":"..."}  │
```

### Deleting a room from your view

```
Client                                      Server
  │                                            │
  ├─ {"type":"delete_room",                   ─┤
  │   "room":"room_abc"}                       │
  │                                            │
  │  Server:                                   │
  │  1. Records deletion in deleted_rooms      │
  │     sidecar (survives cleanup cascade)     │
  │  2. Removes user from room_members         │
  │  3. Broadcasts room_event{leave} to        │
  │     remaining members                      │
  │  4. Echoes room_deleted to caller's        │
  │     sessions (all devices)                 │
  │  5. If last member: cleanup cascade        │
  │     (drop room row, DB file, epoch keys)   │
  │                                            │
  │◀─ {"type":"room_deleted",                 ─┤
  │    "room":"room_abc"}                       │
  │                                            │
  │  Client on receipt:                        │
  │  - Purge local messages, reactions,        │
  │    epoch keys for room_abc                 │
  │  - Remove from active list                 │
  │  - Clear active context if viewing room_abc│
  │                                            │
  │  Other devices (offline):                  │
  │  - On next connect, deleted_rooms catchup  │
  │    includes room_abc → same purge path     │
```

---

## Common Pitfalls

Things every client builder hits at least once:

1. **Forgetting to include yourself in `wrapped_keys`.** On `send_group` and `send_dm`, you must wrap K_msg for your OWN user ID too, not just the other parties. Without this, your other devices can't decrypt your own messages. The server validates that `wrapped_keys` matches the full member list (including you).

2. **Using base64 strings instead of decoded bytes for signatures.** The signature canonical form operates on raw bytes: `payload_bytes` is the base64-DECODED ciphertext, not the base64 string. If you sign the base64 string, every signature verification will fail.

3. **Sending messages before `sync_complete`.** The server will accept them, but your local state may be inconsistent — you might not have the latest epoch key, or you might duplicate a message that's already in a sync batch. Wait for `sync_complete` before enabling the input.

4. **Not handling `server_busy` on `create_dm`.** The server holds a cleanup mutex briefly during DM leave operations. If a `create_dm` hits this window, it returns `server_busy`. Retry with a short backoff (1-2 seconds). Don't show an error to the user — it resolves itself.

5. **Touching local state before the server echo.** When the user runs `/leave` or `/delete`, do NOT update the local DB or UI until the server sends back `room_left`, `group_left`, `dm_left`, `room_deleted`, or `group_deleted`. If the server rejects the request (policy denied, rate limited), the user's local state would be corrupted. The echo is the confirmation.

6. **Assuming `room_list` contains all rooms you've ever been in.** It only contains rooms where the user is a CURRENT member. Rooms the user has left are absent from the list. Rooms the user has `/delete`d are absent. Retired rooms the user is still a member of ARE included (the retirement flag is delivered separately via `retired_rooms` catchup). If your client needs to show "left" rooms, that state must come from local storage.

7. **Not storing `synced_to` from `sync_complete`.** This timestamp is your reconnect bookmark. Without it, every reconnect either gets no sync (empty `last_synced_at`) or the wrong sync window. Store it in your local DB immediately on receipt.

8. **Epoch key confusion during rotation.** During the grace window (between `epoch_trigger` and `epoch_confirmed`), keep sending with the OLD epoch. The server accepts messages encrypted with the current or previous epoch. Only switch to the new epoch after receiving `epoch_confirmed`. If you receive `epoch_conflict`, another client's rotation won — discard your generated key and wait for the winning key via `epoch_key`.
