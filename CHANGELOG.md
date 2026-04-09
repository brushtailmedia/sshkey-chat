# Changelog

## [Unreleased]

### Changed
- Rooms and users migrated from TOML files to SQLite databases (`rooms.db`, `users.db`)
- Room identity switched from display names to nanoid IDs (`room_` prefix) in all protocol messages
- Admin status moved from `server.toml` to `users.db` (managed via `sshkey-ctl promote/demote`)
- `users.toml` and `rooms.toml` are now seed files only (processed on first server start)
- All user/room management via `sshkey-ctl` CLI — no runtime TOML editing
- Server reads user/room data from SQLite on demand — no in-memory caches
- Protocol signature canonical form uses `room_id` instead of `room_name`

### Added
- `users.db` — user identity, SSH key authentication, admin status, retirement
- `rooms.db` — room identity, membership, metadata (existed since v0.1.1, now sole source of truth)
- `sshkey-ctl promote/demote` commands for admin management
- Room nanoid IDs in `room_list` message (`id` field alongside `name`)
- `room_list` handled at client layer for room metadata persistence

### Removed
- `server.toml` `admins` field
- Runtime `users.toml` writes (`WriteUsers`, `persistRetirement`)
- `reloadUsers` config watcher (users.db is source of truth)
- In-memory `config.Users` and `config.Rooms` runtime caches

## v0.1.1 — 2026-04-07

- **Rate limits** — deletes (10/min user, 50/min admin), reactions (30/min), DM creation (5/min), profile changes (5/min), pin/unpin (10/min), connections (20/min)
- **Soft-delete** — message deletion is a soft-delete with tombstones sent in sync/history; reactions on deleted messages are cleaned up
- **File cleanup on delete** — file blobs, hashes, and pins cleaned up when messages are deleted or purged. No more orphaned files on disk.
- **User-friendly errors** — rate limit and conflict messages now use plain language ("Slow down — too many messages" instead of "rate_limited")
- **Room membership query** — `room_members` / `room_members_list` protocol messages with auth enforcement
- **sshkey-ctl improvements** — `approve` writes directly to users.toml (was advisory), `add-to-room`, `remove-from-room`, `status` commands, duplicate key detection, Ed25519 enforcement, display name validation
- **Module path** — changed from `github.com/brushtailmedia/sshkey` to `github.com/brushtailmedia/sshkey-chat`

## v0.1.0 — 2026-04-07

Initial release.

### Server

- 3-channel SSH architecture (NDJSON protocol, downloads, uploads)
- E2E encrypted rooms (epoch keys, AES-256-GCM) and DMs (per-message keys)
- Ed25519 key authentication — no passwords, no key rotation
- Room management with epoch key rotation on membership changes
- DM conversations (1:1 and group, max 50 members)
- File transfer with BLAKE2b-256 content hash verification
- Reactions, typing indicators, read receipts, presence, pins, mentions
- Message signatures (Ed25519) with replay detection
- Account retirement (monotonic, irreversible) with display name freeing
- Device management (multi-device, self-service revocation)
- Sync on reconnect with paginated catch-up batches
- History scroll-back with epoch keys included
- Config hot-reload via filesystem watcher
- Push token registration (APNs/FCM integration pending)
- Pending key tracking with admin notifications

### Admin CLI (sshkey-ctl)

- `approve` — add users with full validation (Ed25519, duplicate key/name, length, username collision)
- `reject` — remove pending keys (atomic write)
- `add-to-room` / `remove-from-room` — manage room membership
- `retire-user` — permanent account retirement
- `revoke-device` / `restore-device` — device management
- `list-users` / `list-retired` — user listing
- `status` — server overview (users, rooms, pending keys, DB sizes)
- `host-key` — print server fingerprint
- `purge` — delete old messages with dry-run support

### Protocol

- Full NDJSON protocol with 50+ message types
- Identity model: immutable nanoid usernames + mutable display names
- Room membership query (`room_members` / `room_members_list`)
- Admin pending key listing (`list_pending_keys` / `pending_keys_list`)
- Reactions included in sync batches and history results
- Content hash required on all file uploads
- Upload/download error messages for fast failure
