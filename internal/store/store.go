// Package store implements SQLite-based storage for the sshkey-chat server.
//
// Storage layout:
//   - One DB per room (room-{nanoid}.db) — encrypted message blobs
//   - One DB per group DM (group-{id}.db) — encrypted message blobs
//   - One DB per 1:1 DM (dm-{id}.db) — encrypted message blobs
//   - One data.db — metadata, device tracking, profiles, wrapped epoch keys
//
// "Group DM" refers to multi-party group conversations (3+ members, variable
// membership via group_members). "DM" or "1:1 DM" refers to a fixed
// two-party conversation via the direct_messages table with per-user
// history cutoffs.
package store

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	_ "modernc.org/sqlite"
)

// Store manages all server-side SQLite databases.
type Store struct {
	dir      string
	dataDB   *sql.DB
	roomsDB  *sql.DB // rooms.db — room identity + membership
	usersDB  *sql.DB // users.db — user identity + auth

	mu       sync.RWMutex
	roomDBs  map[string]*sql.DB // room nanoid -> message DB
	groupDBs map[string]*sql.DB // group DM ID -> message DB
	dmDBs    map[string]*sql.DB // 1:1 DM ID -> message DB
}

// Open creates or opens all databases in the given data directory.
func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(filepath.Join(dir, "data"), 0750); err != nil {
		return nil, fmt.Errorf("create data dir: %w", err)
	}

	s := &Store{
		dir:      filepath.Join(dir, "data"),
		roomDBs:  make(map[string]*sql.DB),
		groupDBs: make(map[string]*sql.DB),
		dmDBs:    make(map[string]*sql.DB),
	}

	dataDB, err := s.openDB("data.db")
	if err != nil {
		return nil, fmt.Errorf("open data.db: %w", err)
	}
	s.dataDB = dataDB

	if err := s.initDataDB(); err != nil {
		return nil, fmt.Errorf("init data.db: %w", err)
	}

	roomsDB, err := s.openDB("rooms.db")
	if err != nil {
		return nil, fmt.Errorf("open rooms.db: %w", err)
	}
	s.roomsDB = roomsDB

	if err := s.initRoomsDB(); err != nil {
		return nil, fmt.Errorf("init rooms.db: %w", err)
	}

	usersDB, err := s.openDB("users.db")
	if err != nil {
		return nil, fmt.Errorf("open users.db: %w", err)
	}
	s.usersDB = usersDB

	if err := s.initUsersDB(); err != nil {
		return nil, fmt.Errorf("init users.db: %w", err)
	}

	return s, nil
}

// Close closes all open databases.
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	var firstErr error

	// Checkpoint WAL on all databases before closing
	checkpoint := func(db *sql.DB) {
		db.Exec("PRAGMA wal_checkpoint(TRUNCATE)")
	}

	for _, db := range s.roomDBs {
		checkpoint(db)
		if err := db.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	for _, db := range s.groupDBs {
		checkpoint(db)
		if err := db.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	for _, db := range s.dmDBs {
		checkpoint(db)
		if err := db.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	checkpoint(s.dataDB)
	if err := s.dataDB.Close(); err != nil && firstErr == nil {
		firstErr = err
	}
	if s.roomsDB != nil {
		checkpoint(s.roomsDB)
		if err := s.roomsDB.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if s.usersDB != nil {
		checkpoint(s.usersDB)
		if err := s.usersDB.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// StoreFileHash saves the content hash for a file_id.
func (s *Store) StoreFileHash(fileID, contentHash string, size int64) error {
	_, err := s.dataDB.Exec(`
		INSERT OR REPLACE INTO file_hashes (file_id, content_hash, size)
		VALUES (?, ?, ?)`,
		fileID, contentHash, size)
	return err
}

// GetFileHash retrieves the content hash for a file_id. Returns ("", nil)
// if no hash row exists — used by cleanOrphanFiles to detect file blobs
// left on disk by crashed mid-upload writes (no hash row = orphan).
func (s *Store) GetFileHash(fileID string) (string, error) {
	var hash string
	err := s.dataDB.QueryRow(
		`SELECT content_hash FROM file_hashes WHERE file_id = ?`,
		fileID).Scan(&hash)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return hash, err
}

// RoomsDB returns the rooms identity database for direct queries.
func (s *Store) RoomsDB() *sql.DB {
	return s.roomsDB
}

// DeleteFileHash removes a file hash entry.
func (s *Store) DeleteFileHash(fileID string) {
	s.dataDB.Exec(`DELETE FROM file_hashes WHERE file_id = ?`, fileID)
}

// openDB opens a SQLite database in WAL mode.
func (s *Store) openDB(name string) (*sql.DB, error) {
	path := filepath.Join(s.dir, name)
	db, err := sql.Open("sqlite", path+"?_journal_mode=WAL&_busy_timeout=5000")
	if err != nil {
		return nil, err
	}
	// Enable WAL mode explicitly (some drivers need this)
	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		db.Close()
		return nil, fmt.Errorf("enable WAL: %w", err)
	}
	// Enable foreign keys
	if _, err := db.Exec("PRAGMA foreign_keys=ON"); err != nil {
		db.Close()
		return nil, fmt.Errorf("enable foreign keys: %w", err)
	}
	return db, nil
}

// RoomDB returns (or creates) the database for a room.
func (s *Store) RoomDB(room string) (*sql.DB, error) {
	s.mu.RLock()
	db, ok := s.roomDBs[room]
	s.mu.RUnlock()
	if ok {
		return db, nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Double-check after acquiring write lock
	if db, ok := s.roomDBs[room]; ok {
		return db, nil
	}

	db, err := s.openDB(fmt.Sprintf("room-%s.db", room))
	if err != nil {
		return nil, err
	}
	if err := s.initMessageDB(db); err != nil {
		db.Close()
		return nil, err
	}
	s.roomDBs[room] = db
	return db, nil
}

// GroupDB returns (or creates) the database for a group DM.
func (s *Store) GroupDB(groupID string) (*sql.DB, error) {
	s.mu.RLock()
	db, ok := s.groupDBs[groupID]
	s.mu.RUnlock()
	if ok {
		return db, nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if db, ok := s.groupDBs[groupID]; ok {
		return db, nil
	}

	db, err := s.openDB(fmt.Sprintf("group-%s.db", groupID))
	if err != nil {
		return nil, err
	}
	if err := s.initMessageDB(db); err != nil {
		db.Close()
		return nil, err
	}
	s.groupDBs[groupID] = db
	return db, nil
}

// DMDB returns (or creates) the database for a 1:1 DM.
func (s *Store) DMDB(dmID string) (*sql.DB, error) {
	s.mu.RLock()
	db, ok := s.dmDBs[dmID]
	s.mu.RUnlock()
	if ok {
		return db, nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if db, ok := s.dmDBs[dmID]; ok {
		return db, nil
	}

	db, err := s.openDB(fmt.Sprintf("dm-%s.db", dmID))
	if err != nil {
		return nil, err
	}
	if err := s.initMessageDB(db); err != nil {
		db.Close()
		return nil, err
	}
	s.dmDBs[dmID] = db
	return db, nil
}

// DataDB returns the data database for direct queries.
func (s *Store) DataDB() *sql.DB {
	return s.dataDB
}

// DataDir returns the absolute path to the directory holding all
// per-conversation database files (room-*.db, group-*.db, dm-*.db).
// Used by tests that need to verify on-disk side effects of cleanup
// operations.
func (s *Store) DataDir() string {
	return s.dir
}

// initDataDB creates the data.db schema.
func (s *Store) initDataDB() error {
	_, err := s.dataDB.Exec(`
		CREATE TABLE IF NOT EXISTS devices (
			user        TEXT NOT NULL,
			device_id   TEXT NOT NULL,
			last_synced TEXT,
			created_at  TEXT NOT NULL DEFAULT (datetime('now')),
			PRIMARY KEY (user, device_id)
		);

		CREATE TABLE IF NOT EXISTS epoch_keys (
			room        TEXT NOT NULL,
			epoch       INTEGER NOT NULL,
			user        TEXT NOT NULL,
			wrapped_key TEXT NOT NULL,
			PRIMARY KEY (room, epoch, user)
		);

		CREATE TABLE IF NOT EXISTS group_conversations (
			id          TEXT PRIMARY KEY,
			name        TEXT NOT NULL DEFAULT '',
			created_at  TEXT NOT NULL DEFAULT (datetime('now'))
		);

		CREATE TABLE IF NOT EXISTS group_members (
			group_id    TEXT NOT NULL,
			user        TEXT NOT NULL,
			is_admin    INTEGER NOT NULL DEFAULT 0,
			joined_at   TEXT NOT NULL DEFAULT (datetime('now')),
			PRIMARY KEY (group_id, user),
			FOREIGN KEY (group_id) REFERENCES group_conversations(id)
		);

		-- deleted_groups records each user's intent to remove a group DM
		-- from their view, independent of the group's actual lifetime. The
		-- row exists from the moment the user runs /delete and persists
		-- until either (a) the user is retired, or (b) the row is older
		-- than groupDeletionRetentionSeconds and the opportunistic prune
		-- in DeleteGroupConversation reclaims it. Used by sync to catch
		-- up offline devices that missed the live group_deleted echo.
		CREATE TABLE IF NOT EXISTS deleted_groups (
			user_id    TEXT NOT NULL,
			group_id   TEXT NOT NULL,
			deleted_at INTEGER NOT NULL,
			PRIMARY KEY (user_id, group_id)
		);

		CREATE INDEX IF NOT EXISTS idx_deleted_groups_user ON deleted_groups(user_id);
		CREATE INDEX IF NOT EXISTS idx_deleted_groups_age ON deleted_groups(deleted_at);

		-- deleted_rooms records each user's intent to remove a room from
		-- their view, independent of the room's actual lifetime. The row
		-- exists from the moment the user runs /delete and persists until
		-- either (a) the user is retired, or (b) the row is older than
		-- roomDeletionRetentionSeconds and the opportunistic prune in
		-- DeleteRoomRecord reclaims it. Used by sync to catch up offline
		-- devices that missed the live room_deleted echo. Parallel to
		-- deleted_groups for group DMs.
		CREATE TABLE IF NOT EXISTS deleted_rooms (
			user_id    TEXT NOT NULL,
			room_id    TEXT NOT NULL,
			deleted_at INTEGER NOT NULL,
			PRIMARY KEY (user_id, room_id)
		);

		CREATE INDEX IF NOT EXISTS idx_deleted_rooms_user ON deleted_rooms(user_id);
		CREATE INDEX IF NOT EXISTS idx_deleted_rooms_age ON deleted_rooms(deleted_at);

		-- pending_room_retirements is the queue the CLI writes to when an
		-- admin runs sshkey-ctl retire-room. The running server polls this
		-- table on a periodic ticker and, for each row, broadcasts the
		-- corresponding room_retired event to connected members of the
		-- room. This is the bridge between the CLI's direct DB mutation
		-- and the server's live broadcast surface — the only IPC mechanism
		-- between sshkey-ctl and the running sshkey-server process for
		-- retirement actions.
		--
		-- The CLI also performs the SetRoomRetired mutation directly on
		-- rooms.db, so retirement takes effect at the data layer even if
		-- the server is down. The server's processing of this queue is
		-- purely about delivering the live notifications. Rows are deleted
		-- after the server has fired the broadcasts.
		CREATE TABLE IF NOT EXISTS pending_room_retirements (
			id         INTEGER PRIMARY KEY AUTOINCREMENT,
			room_id    TEXT NOT NULL,
			retired_by TEXT NOT NULL,
			reason     TEXT NOT NULL DEFAULT '',
			queued_at  INTEGER NOT NULL
		);

		-- pending_user_retirements is the user-level analog of
		-- pending_room_retirements. Phase 16 Gap 1: when the CLI runs
		-- sshkey-ctl retire-user, it flips users.retired (so retirement
		-- takes effect at the data layer regardless of whether the
		-- server is running) and then enqueues a row here. The running
		-- server's runUserRetirementProcessor goroutine drains this
		-- queue on a periodic ticker and calls handleRetirement, which
		-- fires per-room leave events, group exits with last-admin
		-- succession, DM cutoffs, broadcasts user_retired to connected
		-- clients, and terminates active sessions.
		--
		-- Same architectural rationale as the room retirement queue:
		-- the CLI is a separate process whose only IPC with the running
		-- server is shared SQLite tables. The queue + polling pattern
		-- is the canonical bridge for CLI-initiated state changes that
		-- need live broadcasts. See Phase 12 (rooms) for the precedent.
		CREATE TABLE IF NOT EXISTS pending_user_retirements (
			id         INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id    TEXT NOT NULL,
			retired_by TEXT NOT NULL,
			reason     TEXT NOT NULL DEFAULT '',
			queued_at  INTEGER NOT NULL
		);

		-- pending_user_unretirements is the inverse of
		-- pending_user_retirements. Phase 16 Gap 1: when the CLI runs
		-- sshkey-ctl unretire-user (escape hatch for mistaken
		-- retirements), it flips users.retired back to 0 and clears
		-- retired_at / retired_reason, then enqueues a row here. The
		-- running server's runUserUnretirementProcessor goroutine
		-- drains the queue and broadcasts user_unretired to all
		-- connected clients so they can flush the [retired] marker
		-- from their profile cache.
		--
		-- Paired with the retirement queue rather than folded into a
		-- single table because the direction is one-way per row and
		-- keeping them separate matches the per-command-queue
		-- pattern the rest of Phase 16 uses. Same architectural
		-- rationale as pending_user_retirements above.
		--
		-- Note: unretirement does NOT restore room/group/DM
		-- memberships. The retirement cascade removed the user from
		-- every shared context; unretire-user only flips the flag.
		-- Operators must manually re-add via add-to-room or in-group
		-- /add. This matches the documented behavior in the Phase 16
		-- plan ("unretire-user does NOT restore memberships").
		CREATE TABLE IF NOT EXISTS pending_user_unretirements (
			id            INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id       TEXT NOT NULL,
			unretired_by  TEXT NOT NULL,
			queued_at     INTEGER NOT NULL
		);

		-- pending_admin_state_changes is the shared queue for promote,
		-- demote, and rename-user. Phase 16 Gap 1: each of these CLI
		-- verbs flips the corresponding column in users.db, then
		-- enqueues a row here so the running server can broadcast a
		-- fresh profile event to all connected clients. The clients'
		-- existing handleInternal "profile" case upserts into their
		-- in-memory profile cache, refreshing the admin badge or
		-- display name immediately.
		--
		-- Why one shared queue (3 actions) instead of three separate
		-- queues:
		--   - All three actions produce the same wire effect: a fresh
		--     protocol.Profile broadcast for the affected user
		--   - All three are operator-initiated state changes on a
		--     single users.db row (admin flag or display_name)
		--   - The processor's only branching is the audit action
		--     string (promote / demote / rename-user); the broadcast
		--     payload is uniformly built from the post-change user
		--     row
		-- A single processor with one CHECK-constrained action enum
		-- is simpler than three near-duplicate processors.
		--
		-- The action column is constrained to the three valid values
		-- so a malformed CLI insert fails at the schema layer rather
		-- than reaching the processor.
		CREATE TABLE IF NOT EXISTS pending_admin_state_changes (
			id          INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id     TEXT NOT NULL,
			action      TEXT NOT NULL CHECK (action IN ('promote', 'demote', 'rename')),
			changed_by  TEXT NOT NULL,
			queued_at   INTEGER NOT NULL
		);

		-- pending_room_updates is the shared queue for update-topic
		-- and rename-room. Phase 16 Gap 1: each of these CLI verbs
		-- mutates a column on the rooms.db row (topic or display_name)
		-- and enqueues a row here so the running server can broadcast
		-- a fresh room_updated event to connected members. The event
		-- carries the full post-change room state {Room, DisplayName,
		-- Topic} so a single client handler covers both verbs — the
		-- client just upserts its rooms table row from the event
		-- payload.
		--
		-- Why one shared queue (2 actions): same reasoning as
		-- pending_admin_state_changes. Both actions produce one
		-- room_updated broadcast per affected room; the action enum
		-- only drives the audit log entry; the wire payload is
		-- uniformly built from the post-change row.
		--
		-- Note on broadcast scope: unlike user profile updates
		-- (which broadcast wide), room updates are delivered ONLY
		-- to members of the affected room. A user who isn't in the
		-- room doesn't need to know about its topic/name changes,
		-- and the room_members lookup is cheap.
		CREATE TABLE IF NOT EXISTS pending_room_updates (
			id          INTEGER PRIMARY KEY AUTOINCREMENT,
			room_id     TEXT NOT NULL,
			action      TEXT NOT NULL CHECK (action IN ('update-topic', 'rename-room')),
			changed_by  TEXT NOT NULL,
			new_value   TEXT NOT NULL DEFAULT '',
			queued_at   INTEGER NOT NULL
		);

		-- pending_device_revocations is the queue for sshkey-ctl
		-- revoke-device. Phase 16 Gap 1: when an admin revokes a
		-- device via the CLI, the CLI calls store.RevokeDevice (which
		-- marks the device as revoked in revoked_devices, blocking
		-- future authentication attempts) and then enqueues a row
		-- here. The running server's processor drains the queue,
		-- looks up any active SSH session for the (user, device)
		-- pair, sends a device_revoked event so the client can
		-- display a notice before disconnect, and closes the SSH
		-- channel to terminate the session.
		--
		-- Different shape from the other Phase 16 Gap 1 queues:
		-- this one operates on session state (live SSH connections),
		-- not just persisted state. The data-layer effect (revoked
		-- entry in revoked_devices) is already done by the time the
		-- queue row exists; the processor's job is purely about
		-- terminating the live session, not propagating a state
		-- change to other clients. There is no "broadcast to all
		-- members" because the only party that needs to know is the
		-- revoked device itself.
		--
		-- The reason field carries the admin-supplied reason (or
		-- "admin_action" by default) so the device_revoked event
		-- can include it in the message shown to the disconnecting
		-- client.
		CREATE TABLE IF NOT EXISTS pending_device_revocations (
			id          INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id     TEXT NOT NULL,
			device_id   TEXT NOT NULL,
			reason      TEXT NOT NULL DEFAULT 'admin_action',
			revoked_by  TEXT NOT NULL,
			queued_at   INTEGER NOT NULL
		);

		-- pending_remove_from_room is the queue for sshkey-ctl
		-- remove-from-room. Phase 20 (bundled with the leave-catchup
		-- restructure): when an admin runs the CLI, the CLI inserts
		-- a row here. The server's runRemoveFromRoomProcessor drains
		-- unprocessed rows, calls performRoomLeave (which removes the
		-- user from room_members, writes a history row to
		-- user_left_rooms, broadcasts the leave event, echoes
		-- room_left to the leaver's connected sessions, and marks
		-- the room for epoch rotation), then the row is DELETEd as
		-- part of the consume-atomic transaction.
		--
		-- Same shape as the other Phase 16 pending_* queues (DELETE
		-- on consume, not mark-processed). Before Phase 20, this
		-- queue was fused with the user_left_rooms history table via
		-- a processed flag — Phase 20 split them into two
		-- pure-purpose tables for vocabulary clarity and to match
		-- the other five Phase 16 queues. See refactor_plan.md
		-- Phase 20 (Option D) for the rationale.
		CREATE TABLE IF NOT EXISTS pending_remove_from_room (
			id            INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id       TEXT NOT NULL,
			room_id       TEXT NOT NULL,
			reason        TEXT NOT NULL DEFAULT 'removed',
			initiated_by  TEXT NOT NULL,
			queued_at     INTEGER NOT NULL
		);

		-- blocked_fingerprints is the pre-approval defense against
		-- fingerprint spam. Phase 16: when an admin runs sshkey-ctl
		-- block-fingerprint, the fingerprint is inserted here.
		-- During SSH authentication, the server checks this table
		-- BEFORE writing to pending_keys; blocked fingerprints are
		-- silently rejected so they never appear in the pending
		-- queue and can't accumulate spam.
		--
		-- Different from revoked_devices (which applies to already-
		-- approved users) and from reject (which clears a single
		-- pending key). block-fingerprint is a preemptive blocklist
		-- for keys that haven't been approved yet.
		CREATE TABLE IF NOT EXISTS blocked_fingerprints (
			fingerprint  TEXT PRIMARY KEY,
			reason       TEXT NOT NULL DEFAULT '',
			blocked_at   INTEGER NOT NULL,
			blocked_by   TEXT NOT NULL
		);

		-- user_left_rooms is the pure-history sidecar for server-
		-- authoritative leave catchup (Phase 20). Every leave path
		-- (self-leave, retirement cascade, admin remove via CLI)
		-- writes a row here via performRoomLeave — single write
		-- point. GetUserLeftRoomsCatchup reads the most recent row
		-- per (user, room) on the connect handshake.
		--
		-- Rows are DELETEd on re-add (DeleteUserLeftRoomRows from
		-- cmdAddToRoom) and pruned after 1 year
		-- (PruneOldUserLeftRooms).
		--
		-- Phase 20 split the queue concern out to
		-- pending_remove_from_room above (Option D — queue is a
		-- queue, history is history). Before Phase 20 this table
		-- was dual-purpose with a processed flag; the flag and its
		-- index are gone.
		CREATE TABLE IF NOT EXISTS user_left_rooms (
			id            INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id       TEXT NOT NULL,
			room_id       TEXT NOT NULL,
			reason        TEXT NOT NULL,
			initiated_by  TEXT NOT NULL,
			left_at       INTEGER NOT NULL
		);
		CREATE INDEX IF NOT EXISTS idx_user_left_rooms_user_left_at
			ON user_left_rooms(user_id, left_at);

		-- user_left_groups is the group-side parallel of user_left_rooms.
		-- Phase 20 addition. No queue counterpart — all group leaves
		-- run inline via performGroupLeave (no CLI async path since
		-- Phase 14 deleted the escape hatch).
		CREATE TABLE IF NOT EXISTS user_left_groups (
			id            INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id       TEXT NOT NULL,
			group_id      TEXT NOT NULL,
			reason        TEXT NOT NULL,
			initiated_by  TEXT NOT NULL,
			left_at       INTEGER NOT NULL
		);
		CREATE INDEX IF NOT EXISTS idx_user_left_groups_user_left_at
			ON user_left_groups(user_id, left_at);

		-- 1:1 DMs — fixed two-party conversations with per-user history
		-- cutoffs. The user pair is canonicalized alphabetically so dedup
		-- is schema-enforced via UNIQUE(user_a, user_b). The *_left_at
		-- columns are one-way ratchets: 0 = active, >0 = user has left
		-- (server filters messages on read, not on write).
		CREATE TABLE IF NOT EXISTS direct_messages (
			id              TEXT PRIMARY KEY,
			user_a          TEXT NOT NULL,
			user_b          TEXT NOT NULL,
			created_at      INTEGER NOT NULL,
			user_a_left_at  INTEGER NOT NULL DEFAULT 0,
			user_b_left_at  INTEGER NOT NULL DEFAULT 0,
			UNIQUE(user_a, user_b)
		);

		CREATE INDEX IF NOT EXISTS idx_dm_user_a ON direct_messages(user_a);
		CREATE INDEX IF NOT EXISTS idx_dm_user_b ON direct_messages(user_b);

		CREATE TABLE IF NOT EXISTS profiles (
			user         TEXT PRIMARY KEY,
			display_name TEXT,
			avatar_id    TEXT,
			status_text  TEXT
		);

		-- user_rooms removed — first_seen/first_epoch now read from
		-- room_members in rooms.db (single source of truth).

		CREATE TABLE IF NOT EXISTS read_positions (
			user      TEXT NOT NULL,
			device_id TEXT NOT NULL,
			room      TEXT NOT NULL DEFAULT '',
			group_id  TEXT NOT NULL DEFAULT '',
			dm_id     TEXT NOT NULL DEFAULT '',
			last_read TEXT NOT NULL,
			ts        INTEGER NOT NULL,
			PRIMARY KEY (user, device_id, room, group_id, dm_id)
		);

		CREATE TABLE IF NOT EXISTS revoked_devices (
			user        TEXT NOT NULL,
			device_id   TEXT NOT NULL,
			revoked_at  TEXT NOT NULL DEFAULT (datetime('now')),
			reason      TEXT,
			PRIMARY KEY (user, device_id)
		);

		CREATE TABLE IF NOT EXISTS push_tokens (
			user        TEXT NOT NULL,
			device_id   TEXT NOT NULL,
			platform    TEXT NOT NULL,
			token       TEXT NOT NULL,
			updated_at  TEXT NOT NULL DEFAULT (datetime('now')),
			active      INTEGER NOT NULL DEFAULT 1,
			PRIMARY KEY (user, device_id)
		);

		CREATE TABLE IF NOT EXISTS pending_keys (
			fingerprint TEXT NOT NULL,
			remote_addr TEXT,
			attempts    INTEGER NOT NULL DEFAULT 1,
			first_seen  TEXT NOT NULL DEFAULT (datetime('now')),
			last_seen   TEXT NOT NULL DEFAULT (datetime('now')),
			PRIMARY KEY (fingerprint)
		);

		-- File content hashes (BLAKE2b-256 of encrypted bytes, verified on upload/download)
		CREATE TABLE IF NOT EXISTS file_hashes (
			file_id      TEXT PRIMARY KEY,
			content_hash TEXT NOT NULL,
			size         INTEGER NOT NULL
		);

		-- File-to-context bindings (Phase 17 Step 4.f). Each uploaded file is
		-- bound to exactly ONE context at upload completion: one of room /
		-- group / 1:1 DM. Used by handleDownload's ACL check to verify the
		-- caller has access to the file's owning context. Composite PK is
		-- future-proofed for multi-binding (e.g. forwards as a feature) but
		-- current usage is one row per file_id.
		--
		-- Cleanup cascades: rows for context X are deleted when context X
		-- itself is cleaned up (DeleteRoomRecord, DeleteGroupConversation,
		-- DeleteDirectMessage), when a specific file_id is tombstoned via
		-- cleanupFiles (message-delete path), or when admin CLI cmdPurge
		-- reaps old messages. The cleanOrphanFiles startup sweep catches
		-- stragglers where the file_contexts row was dropped but the
		-- file_hashes row wasn't (crash window between DELETE statements).
		-- See download_fix.md for the full cleanup site enumeration.
		CREATE TABLE IF NOT EXISTS file_contexts (
			file_id      TEXT NOT NULL,
			context_type TEXT NOT NULL,     -- 'room' | 'group' | 'dm'
			context_id   TEXT NOT NULL,
			ts           INTEGER NOT NULL,  -- unix seconds; attachment time
			PRIMARY KEY (file_id, context_type, context_id)
		);

		-- Indexes for per-connect query paths (sync, epoch keys, group DMs)
		CREATE INDEX IF NOT EXISTS idx_epoch_keys_room_user_epoch
			ON epoch_keys(room, user, epoch);
		CREATE INDEX IF NOT EXISTS idx_epoch_keys_user
			ON epoch_keys(user, room, epoch);
		CREATE INDEX IF NOT EXISTS idx_group_members_user
			ON group_members(user, group_id);
		CREATE INDEX IF NOT EXISTS idx_devices_last_synced
			ON devices(last_synced) WHERE last_synced IS NOT NULL AND last_synced != '';
		CREATE INDEX IF NOT EXISTS idx_push_tokens_user_active
			ON push_tokens(user, active);

		-- file_contexts indexes: lookup serves the download ACL (GetFileContext
		-- by file_id, O(1) with this index); cleanup serves the context-gone
		-- cascade (DELETE WHERE context_type = ? AND context_id = ?, O(rows)
		-- matching the single context being cleaned up).
		CREATE INDEX IF NOT EXISTS idx_file_contexts_lookup
			ON file_contexts(file_id);
		CREATE INDEX IF NOT EXISTS idx_file_contexts_cleanup
			ON file_contexts(context_type, context_id);
	`)
	return err
}

// initMessageDB creates the schema for room/conversation message databases.
func (s *Store) initMessageDB(db *sql.DB) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS messages (
			id        TEXT PRIMARY KEY,
			sender    TEXT NOT NULL,
			ts        INTEGER NOT NULL,
			epoch     INTEGER,
			payload   TEXT NOT NULL,
			file_ids  TEXT,
			signature TEXT,
			wrapped_keys TEXT,
			deleted   INTEGER NOT NULL DEFAULT 0,
			edited_at INTEGER NOT NULL DEFAULT 0
		);

		CREATE INDEX IF NOT EXISTS idx_messages_ts ON messages(ts);
		CREATE INDEX IF NOT EXISTS idx_messages_sender ON messages(sender);
		CREATE INDEX IF NOT EXISTS idx_messages_not_deleted ON messages(deleted) WHERE deleted = 0;

		CREATE TABLE IF NOT EXISTS reactions (
			reaction_id TEXT PRIMARY KEY,
			message_id  TEXT NOT NULL,
			user        TEXT NOT NULL,
			ts          INTEGER NOT NULL,
			epoch       INTEGER,
			payload     TEXT NOT NULL,
			signature   TEXT,
			wrapped_keys TEXT,
			FOREIGN KEY (message_id) REFERENCES messages(id)
		);

		CREATE INDEX IF NOT EXISTS idx_reactions_message ON reactions(message_id);

		CREATE TABLE IF NOT EXISTS pins (
			message_id TEXT PRIMARY KEY,
			pinned_by  TEXT NOT NULL,
			ts         INTEGER NOT NULL,
			FOREIGN KEY (message_id) REFERENCES messages(id)
		);

		-- group_events is Phase 14's audit trail for admin-initiated group
		-- mutations (join, leave, promote, demote, rename). Rooms and 1:1
		-- DMs get an empty unused copy — the cost is one schema block, the
		-- benefit is automatic GC via DeleteGroupConversation (the per-group
		-- DB file unlink drops the events with it) and alignment with the
		-- DB-per-context invariant. Populated via RecordGroupEvent by each
		-- admin-action handler, read by GetGroupEventsSince during sync_batch
		-- replay so offline clients get "alice promoted bob on Tuesday"
		-- history entries on reconnect. ts is INTEGER (unix seconds) to
		-- match messages.ts for shared sinceTS watermark in sync.
		CREATE TABLE IF NOT EXISTS group_events (
			id     INTEGER PRIMARY KEY AUTOINCREMENT,
			event  TEXT NOT NULL,
			user   TEXT NOT NULL,
			by     TEXT NOT NULL DEFAULT '',
			reason TEXT NOT NULL DEFAULT '',
			name   TEXT NOT NULL DEFAULT '',
			quiet  INTEGER NOT NULL DEFAULT 0,
			ts     INTEGER NOT NULL
		);

		CREATE INDEX IF NOT EXISTS idx_group_events_ts ON group_events(ts);
	`)
	return err
}
