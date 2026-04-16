# Changelog

## [Unreleased]

### Added
- **Phase 20: Server-authoritative multi-device /leave catchup + room event audit trail.** Two coordinated pieces shipping together:
  - **Leave catchup (Option D queue/history split).** Replaced the client-side reconciliation walk (diff local active IDs against `room_list`/`group_list`, mark missing as left) with server-pushed `left_rooms` / `left_groups` handshake messages carrying per-leave reason codes. Server is now authoritative for "why did this room go away" — client no longer infers. Clients get distinct system messages for self-leave vs admin removal vs account retirement instead of a generic `(left)` marker.
    - **Schema restructure.** Phase 16's dual-purpose `user_left_rooms` (queue + history via `processed` flag) split into two pure-purpose tables: new `pending_remove_from_room` (queue, DELETE-on-consume — matches the other 5 Phase 16 `pending_*` queues) and `user_left_rooms` + new `user_left_groups` (pure history, no `processed` column). `ConsumePendingUserLeftRooms` deleted.
    - **Single history write point.** `performRoomLeave` / `performGroupLeave` signatures extended with `initiatedBy` parameter and now own the history write exclusively — callers (self-leave, retirement cascade, admin remove via CLI) no longer write sidecars directly.
    - **Handshake.** New `sendLeftRooms` / `sendLeftGroups` functions emit catchup BEFORE `room_list` / `group_list` so clients have reason codes before rendering sidebars. New protocol types `LeftRoomsList` / `LeftGroupsList` / `LeftRoomEntry` / `LeftGroupEntry` in both repos.
    - **Re-join cleanup.** `DeleteUserLeftRoomRows` / `DeleteUserLeftGroupRows` clear prior leave history when admin re-adds via `cmdAddToRoom` / `handleAddToGroup`.
    - **Retention.** `PruneOldUserLeftRooms` / `PruneOldUserLeftGroups` (1-year, opportunistic prune from retirement handler).
  - **Room event audit trail (parity with groups).** Phase 14 added the `group_events` schema to every per-context DB but only groups populated it. Phase 20 populates the room side via new `RecordRoomEvent` / `GetRoomEventsSince` helpers (use `RoomDB(roomID)` where group helpers use `GroupDB`). Rooms now emit inline system messages for leave/join/topic/rename/retire events, matching the group UX.
    - Event recording in 4 sites: `performRoomLeave` (leave), `cmdAddToRoom` (join — direct, no live broadcast), `processPendingRoomUpdates` (topic/rename), `processPendingRoomRetirements` (retire).
    - `pending_room_updates.new_value` column added so topic/rename audit rows capture the exact value the operator set (closes a lossy-audit race where two quick successive topic changes would both record the second value).
    - `syncRoom` extended to pack events into `SyncBatch.Events` (mirror of `syncGroup`). Pre-join privacy gate applied via existing `room_members.joined_at` — new members don't see pre-join audit events.
    - **`protocol.RoomEvent` extended** with `By` and `Name` fields (both repos). Stale Reason enum doc fixed (`"admin"` / `"retirement"` → `"removed"` / `"user_retired"`).
  - **Client changes.** New `leave_reason` column on `rooms` / `groups` tables. `MarkRoomLeft` / `MarkGroupLeft` signatures extended with reason. `MarkRoomRejoined` / `MarkGroupRejoined` clear `leave_reason`. New `room_events` client table + store helpers. Client `left_rooms` / `left_groups` / `room_event` handlers. Reconciliation walks in `room_list` / `group_list` handlers replaced with `MarkRoomRejoined` / `MarkGroupRejoined` calls. `GetActiveRoomIDs` / `GetActiveGroupIDs` + `active_ids_test.go` deleted. TUI renders inline system messages for all 5 room event types.
  - **Store helper inventory (server side):** NEW `RecordPendingRemoveFromRoom`, `ConsumePendingRemoveFromRooms`, `RecordUserLeftGroup`, `GetUserLeftRoomsCatchup`, `GetUserLeftGroupsCatchup`, `DeleteUserLeftRoomRows`, `DeleteUserLeftGroupRows`, `PruneOldUserLeftRooms`, `PruneOldUserLeftGroups`, `RecordRoomEvent`, `GetRoomEventsSince`. DELETED: `ConsumePendingUserLeftRooms`. Signature changed: `RecordPendingRoomUpdate` now takes a 4th `newValue` param.
  - Memory notes: `phase20_option_d.md` + `encryption_boundaries.md`.

- **Phase 16: Admin CLI audit + new management features.** Comprehensive overhaul of `sshkey-ctl` — 20 new commands, broadcast wiring for 9 state-changing commands, and removal of TOML-era holdovers.
  - **Gap 1 — live broadcast wiring**: `retire-user`, `unretire-user`, `promote`, `demote`, `rename-user`, `update-topic`, `rename-room`, `revoke-device`, and `remove-from-room` now propagate changes to connected clients within ~5 seconds via per-command `pending_*` queue tables + polling processor goroutines. Previously, connected clients only saw these changes on reconnect.
  - **Gap 3 — `remove-user` deleted**: TOML-era holdover that bypassed every invariant the groups/rooms admin model depends on. Use `retire-user` instead.
  - **Gap 4 — `bootstrap-admin` + `users.toml` deletion**: New `sshkey-ctl bootstrap-admin <name>` generates an Ed25519 keypair with interactive passphrase prompt (min 12 chars, zxcvbn score >= 3 required), inserts the user row with `is_admin=true`, writes audit log entry, and outputs the encrypted private key to CWD. `users.toml` support removed entirely — no migration path, no seed fallback. Existing deployments unaffected (users.db was already the source of truth since Phase 9).
  - **Default rooms**: `set-default-room` (with Variant 2 backfill of all existing users), `unset-default-room` (leaves members), `list-default-rooms`. New `is_default` column on rooms table. `approve` and `bootstrap-admin` auto-add new users to flagged rooms. `retire-room` clears the flag.
  - **Audit log reader**: `audit-log [--since DURATION] [--limit N]` and `audit-user USER` commands read the append-only `audit.log` file. Supports duration parsing with `d` suffix (e.g. `7d`), newest-first ordering, user filtering (source + details match).
  - **Inspection commands**: `show-user` (rooms, devices, fingerprint), `show-room` (members with admin badges), `list-admins`, `search-users --name` / `--fingerprint`.
  - **Operational commands**: `list-devices --user`, `room-stats` (per-room member + message counts), `check-integrity [--all]` (PRAGMA integrity_check), `prune-devices --stale-for DURATION [--dry-run]`.
  - **Security**: `block-fingerprint` / `list-blocks` / `unblock-fingerprint` with `blocked_fingerprints` table and SSH handshake enforcement (blocked keys rejected before reaching the pending queue).
  - **Destructive-action prompts**: `retire-user` and `retire-room` now show a summary and require typing "yes" to confirm (skipped when stdin is not a TTY; `--yes` flag for scripting).
  - **New protocol events**: `user_unretired` (inverse of `user_retired`), `room_updated` (carries full post-change `{Room, DisplayName, Topic}`), and live `profile` broadcasts for promote/demote/rename-user.
  - **Phase 20 sidecar built**: `user_left_rooms` table with mark-processed semantics, ready for Phase 20 to layer server-authoritative leave catchup on top.
  - **Audit log extraction**: `internal/audit` package extracted from `internal/server/audit.go` so both the server and CLI can write entries.
  - **~180 new tests** across store, server, and CLI packages.
- **Phase 15: message editing.** Three new verb families on the wire — `edit` / `edited` (rooms), `edit_group` / `group_edited` (group DMs), `edit_dm` / `dm_edited` (1:1 DMs). Each replaces the encrypted payload of an existing message row in place, preserving `id`, `sender`, `ts`, `file_ids`, and thread structure while setting a new server-authoritative `edited_at` on the broadcast echo. `Message`, `GroupMessage`, and `DM` protocol types gain an `EditedAt int64 \`json:"edited_at,omitempty"\`` field. Only the user's most recent non-deleted message in the current context is editable; non-members, non-authors, and deleted-row failure modes all collapse into byte-identical `ErrUnknownX` responses (privacy invariant). Authorship is surfaced via `ErrEditNotMostRecent`; room edits must be in the current-or-previous epoch grace window or they get `ErrEditWindowExpired`. Reactions on edited messages are cleared in the same transaction as the payload replace — clients unconditionally drop local reaction state for the edited message ID on receipt of the `edited` event (no per-reaction `reaction_removed` broadcasts). New rate limit bucket `EditsPerMinute` (default 10/min, shared across all three verbs per user). New store helpers `UpdateRoomMessageEdited` / `UpdateGroupMessageEditedWithKeys` / `UpdateDMMessageEditedWithKeys` / `GetRoomMessageByID` / `GetGroupMessageByID` / `GetDMMessageByID` / `GetUserMostRecentMessageID{Room,Group,DM}`. New `edited_at INTEGER NOT NULL DEFAULT 0` column on the per-context `messages` schema (single CREATE TABLE edit via `initMessageDB`, no ALTER per the no-live-users policy). Byte-identical privacy regression tests: `TestHandleEdit_PrivacyResponsesIdentical`, `TestHandleEditGroup_PrivacyResponsesIdentical`, `TestHandleEditDM_PrivacyResponsesIdentical`. Plus happy-path, most-recent rejection, epoch-window rejection, retired-room rejection, deleted-row collapse, and reaction-clearing tests. See `PROTOCOL.md` "Message Editing" section for the wire format and `message_editing.md` for the design write-up.

### Client-visible features (no server code change)
- **Phase 18: room topics now rendered in the sshkey-term TUI.** The server has always served `RoomInfo.Topic` in `room_list` payloads, and the client has persisted topics in its local `rooms` table since Phase 7b — but the terminal client never read them. Phase 18 wires the display-only path through to the TUI: two-line messages header (bold room name + dim italic topic) and the `Topic:` line in the info panel. Also adds a `/topic` read-only slash command that echoes the current topic in the status bar. Purely a client-side change — the server did not need updating; its `RoomInfo.Topic` wire format has been correct since v0.1.0. ~~Changing a topic via `sshkey-ctl update-topic` and broadcasting live updates via `room_updated` were deferred to Phase 16.~~ **Now shipped in Phase 16** — see the Phase 16 entry above. See sshkey-term's `CHANGELOG.md` for the client-side implementation detail. "Future: Display Room Topics in TUI" in `PROJECT.md` has been updated to "Shipped (Phase 18)".

### Fixed
- **Stale DM protocol comment.** The block comment at `internal/protocol/messages.go:125-129` claiming "1:1 DMs are NOT supported in this protocol version" has been stale since Phase 11 shipped the `CreateDM` / `SendDM` / `DM` / `LeaveDM` / `DMInfo` type family. Replaced with a one-line note pointing readers at the DM section further down the file. Cosmetic but load-bearing for first-time readers.

### Security
- **New-member pre-join history gate for group DMs** — new members added to an existing group DM no longer receive pre-join messages or pre-join `group_events` in their sync batches or history scroll-back. The wrapped-key crypto model already prevented DECRYPTION, but the server was still SERVING the rows, leaking timestamps, sender IDs, and audit-trail metadata (pre-join `/rename`, `/promote`, `/demote`, `/kick` events). `syncGroup` and `handleHistory`'s group branch now raise/post-filter by `group_members.joined_at`, mirroring the `first_seen/first_epoch` gate that has protected rooms since v0.1.0. The column existed since Phase 11 (`datetime('now')` default on `AddGroupMember`) but was never wired into the read paths — fix is pure server-side, no schema or wire change. Covered by `TestSyncGroup_FiltersPreJoinMessages`, `TestSyncGroup_FiltersPreJoinEvents`, `TestSyncGroup_ReAddResetsJoinedAt`, `TestHandleHistory_FiltersPreJoinGroupMessages`, `TestSyncGroup_ExistingMemberSeesAllPostJoin`. See `groups_admin.md` "Pre-join history gate" section for the full write-up including the pins verification (rooms-only by design) and the 1:1 DM structural safety argument.

### Changed
- **Group DMs now have an in-group admin model (Phase 14)** — reverses the "immutable peer DMs" decision from Phase 11. Group creators become the first admin; any admin can add/remove/promote/demote/rename. At-least-one-admin invariant enforced at every mutation path (`/leave`, `/delete`, demote, kick, retirement). Retirement cascade auto-promotes the oldest remaining member as successor. See `groups_admin.md` for the full design.
- **`handleRetirement` group branch restructured** — replaces the bulk `RetireUserFromGroups` store helper with per-group iteration through `performGroupLeave(reason: "retirement", by: "")`. Fixes a latent orphan-on-solo bug where retiring a sole group member never triggered `DeleteGroupConversation`, leaving the `group_conversations` row + per-group DB file orbiting forever. `RetireUserFromGroups` and its 3 store-level tests are deleted.
- **`performGroupLeave` signature extended** from `(groupID, userID, reason string)` to `(groupID, userID, reason, by string)` so admin-initiated removals can render "You were removed from X by alice" instead of the generic "by an admin". `by` is empty for self-leave and retirement paths.
- **`handleRenameGroup` now requires admin** — matches the byte-identical privacy convention (non-admin attempts collapse to `ErrUnknownGroup`). Pre-Phase-14 any member could rename.
- **`handleLeaveGroup` and `handleDeleteGroup` reject last-admin** with `ErrForbidden` when the group has other members. Sole-member carve-out: a user who is both the only member and the only admin can leave or delete freely (last-member cleanup runs).
- **Group retirement reason code** stays `"retirement"` (rooms use `"user_retired"`) — 9+ sites across both repos depend on this distinction.
- **`performGroupLeave` now records an audit row** to the per-group `group_events` table before broadcasting, best-effort. Sole recording site for `leave` events per the audit contract.
- Rooms and users migrated from TOML files to SQLite databases (`rooms.db`, `users.db`)
- Room identity switched from display names to nanoid IDs (`room_` prefix) in all protocol messages
- Admin status moved from `server.toml` to `users.db` (managed via `sshkey-ctl promote/demote`)
- `users.toml` and `rooms.toml` are now seed files only (processed on first server start)
- All user/room management via `sshkey-ctl` CLI — no runtime TOML editing
- Server reads user/room data from SQLite on demand — no in-memory caches
- Protocol signature canonical form uses `room_id` instead of `room_name`
- `handleLeaveRoom` policy gate now branches on retired state: active rooms use `allow_self_leave_rooms`, retired rooms use `allow_self_leave_retired_rooms` (Phase 12)

### Added
- **Phase 14 in-group admin verbs** — four new protocol messages: `add_to_group`, `remove_from_group`, `promote_group_admin`, `demote_group_admin`. Each has a corresponding server-to-caller echo (`add_group_result`, `remove_group_result`, `promote_admin_result`, `demote_admin_result`). All three of add/promote/demote support an optional `quiet` flag to suppress inline system messages on receiving clients; `remove_from_group` is always loud.
- **`group_added_to` direct notification** — sent to the target's active sessions when an admin adds them to an existing group. Carries the full group metadata (name, members, admins, added_by) so the client can insert the group into local state immediately.
- **`group_event` extended** — five event variants now (`leave`, `join`, `promote`, `demote`, `rename`). New fields: `by` (acting admin, required on admin-initiated events), `quiet` (suppress inline rendering), `name` (for rename events). New reasons on `leave`: `"removed"` (replaces deprecated `"admin"`) and the implicit `"retirement"`. New reason on `promote`: `"retirement_succession"` (server-initiated auto-promote).
- **`GroupCreated` and `GroupInfo` carry an `admins` field** — populated from the new `group_members.is_admin` column. Empty on pre-Phase-14 servers for graceful upgrade.
- **`GroupLeft` carries a `by` field** (non-empty only when `reason == "removed"`) so the kicked user's client can render "You were removed from the group by alice" instead of the generic fallback.
- **New `group_events` per-group audit table** — stored in each `group-{id}.db` file (`ts INTEGER` unix seconds matching `messages.ts` for shared sync watermark). Populated by `RecordGroupEvent` at each admin-action recording site. Automatic GC via `DeleteGroupConversation` — the file unlink drops the events with it.
- **`SyncBatch.Events` field** — `syncGroup` now replays recent group admin events via `GetGroupEventsSince` alongside messages and reactions. Offline clients catch up on admin history via the same sync pass (no separate catchup verb).
- **`Store.GetUserGroupJoinedAt(userID, groupID)` store helper** — reads `group_members.joined_at` as unix seconds via `strftime('%s', ...)`. Used by `syncGroup` and `handleHistory`'s group branch as the new-member pre-join history gate. Fail-open on DB error, matching `GetUserRoom` behaviour.
- **`is_admin` column on `group_members`** — CREATE TABLE edited in place (no ALTER, no live users). Only the designated admin's row starts with `is_admin = 1`; all others default `0`. Updated via the new `SetGroupMemberAdmin` store helper, read via `IsGroupAdmin` / `CountGroupAdmins` / `GetGroupAdminIDs` / `GetOldestGroupMember`.
- **`AdminActionsPerMinute` rate limit** — new config field on `RateLimitsSection`, default 20/min per user per group. Applies to all five admin verbs (the four new + `rename_group`); server-initiated paths (retirement cascade, last-member cleanup) are exempt.
- **New error codes**: `ErrUnknownUser` (add target not found), `ErrAlreadyMember` (add target already in group), `ErrAlreadyAdmin` (promote target already admin).
- **Byte-identical privacy gate** — unknown-group, non-member, and non-admin rejections on all admin verbs collapse to the same `ErrUnknownGroup` frame. `TestHandle*_PrivacyResponsesIdentical` regression tests use `bytes.Equal` on wire frames.
- **`CreateGroup` store signature** changed to `CreateGroup(id, adminID, members, name ...)` with validation that `adminID` appears in `members`. 23 call sites updated across tests.
- Deletion inventory for the Phase 11 CLI escape hatch: `admin_kicks.go` (75 lines) + `runAdminKickProcessor` goroutine + `pending_admin_kicks` table + `RecordPendingAdminKick`/`ConsumePendingAdminKicks` store fns + `cmdRemoveFromGroup` CLI command + 6 dedicated tests + stale "Phase 12 counterpart to runAdminKickProcessor" / "Mirrors PendingAdminKick" comments in `room_retirements.go` and `room_deletion.go`.
- `users.db` — user identity, SSH key authentication, admin status, retirement
- `rooms.db` — room identity, membership, metadata (existed since v0.1.1, now sole source of truth)
- `sshkey-ctl promote/demote` commands for admin management
- Room nanoid IDs in `room_list` message (`id` field alongside `name`)
- `room_list` handled at client layer for room metadata persistence
- **Room retirement (Phase 12)** — admins can retire rooms via `sshkey-ctl retire-room`; retired rooms become read-only and display-name-suffixed with a random base62 tag, users can `/delete` them to remove from view
- `sshkey-ctl retire-room` / `list-retired-rooms` CLI commands (local-only, queue + polling pattern)
- `retired_at` column on `rooms` table; `pending_room_retirements` queue; `deleted_rooms` sidecar for multi-device `/delete` catchup
- Protocol: `room_retired`, `retired_rooms` (catchup list), `delete_room`, `room_deleted`, `deleted_rooms` (catchup list) message types; new `ErrRoomRetired` and `ErrForbidden` error codes
- Write rejections on retired rooms (`send`, `react`, `pin`, `unpin`) now return `ErrRoomRetired`; missing membership gates on `react`/`pin`/`unpin` added for privacy
- `handleDeleteRoom` server handler — sidecar-first ordering so `deleted_rooms` catchup survives last-member cleanup
- `allow_self_leave_rooms` (default `false`) and `allow_self_leave_retired_rooms` (default `true`) config flags — dual policy gate for self-leave/self-delete
- `runRoomRetirementProcessor` background goroutine (5s poll) drains the `pending_room_retirements` queue and broadcasts `room_retired` to connected members

### Removed
- **CLI group-kick escape hatch (Phase 14)** — `sshkey-ctl remove-from-group` deleted. Moderation now lives in-group entirely via the admin verbs. For TOS violations, operators retire the offending user's account (`sshkey-ctl retire-user`), which triggers the retirement cascade including per-group leave + succession.
- `admin_kicks.go` file (`runAdminKickProcessor` polling goroutine, `processPendingAdminKicks` queue drain).
- `server.go`: `adminKickStop` channel, `adminKickPollInterval` constant, goroutine startup, `Close()` stopchan teardown.
- `pending_admin_kicks` table + `RecordPendingAdminKick` / `ConsumePendingAdminKicks` / `PendingAdminKick` struct store fns.
- `RetireUserFromGroups` store helper (replaced by per-group iteration in `handleRetirement`).
- 6 test functions that exercised the deleted escape-hatch paths.
- Legacy `"admin"` reason value on `group_event` / `group_left` is deprecated (still parsed defensively, but no new rows emit it in v1).

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
- DM conversations (1:1 and group, max 150 members)
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
