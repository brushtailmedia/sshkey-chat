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
			deleted   INTEGER NOT NULL DEFAULT 0
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
