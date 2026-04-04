// Package store implements SQLite-based storage for the sshkey-chat server.
//
// Storage layout (from the design doc):
//   - One DB per room (room-{name}.db) — encrypted message blobs
//   - One DB per DM conversation (conv-{id}.db) — encrypted message blobs
//   - One users.db — metadata, device tracking, profiles, wrapped epoch keys
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
	dir     string
	usersDB *sql.DB

	mu      sync.RWMutex
	roomDBs map[string]*sql.DB // room name -> DB
	convDBs map[string]*sql.DB // conversation ID -> DB
}

// Open creates or opens all databases in the given data directory.
func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(filepath.Join(dir, "data"), 0750); err != nil {
		return nil, fmt.Errorf("create data dir: %w", err)
	}

	s := &Store{
		dir:     filepath.Join(dir, "data"),
		roomDBs: make(map[string]*sql.DB),
		convDBs: make(map[string]*sql.DB),
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
	for _, db := range s.convDBs {
		checkpoint(db)
		if err := db.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	checkpoint(s.usersDB)
	if err := s.usersDB.Close(); err != nil && firstErr == nil {
		firstErr = err
	}
	return firstErr
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

// ConvDB returns (or creates) the database for a DM conversation.
func (s *Store) ConvDB(convID string) (*sql.DB, error) {
	s.mu.RLock()
	db, ok := s.convDBs[convID]
	s.mu.RUnlock()
	if ok {
		return db, nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if db, ok := s.convDBs[convID]; ok {
		return db, nil
	}

	db, err := s.openDB(fmt.Sprintf("conv-%s.db", convID))
	if err != nil {
		return nil, err
	}
	if err := s.initMessageDB(db); err != nil {
		db.Close()
		return nil, err
	}
	s.convDBs[convID] = db
	return db, nil
}

// UsersDB returns the users database for direct queries.
func (s *Store) UsersDB() *sql.DB {
	return s.usersDB
}

// initUsersDB creates the users.db schema.
func (s *Store) initUsersDB() error {
	_, err := s.usersDB.Exec(`
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

		CREATE TABLE IF NOT EXISTS conversations (
			id          TEXT PRIMARY KEY,
			name        TEXT NOT NULL DEFAULT '',
			created_at  TEXT NOT NULL DEFAULT (datetime('now'))
		);

		CREATE TABLE IF NOT EXISTS conversation_members (
			conversation_id TEXT NOT NULL,
			user            TEXT NOT NULL,
			joined_at       TEXT NOT NULL DEFAULT (datetime('now')),
			PRIMARY KEY (conversation_id, user),
			FOREIGN KEY (conversation_id) REFERENCES conversations(id)
		);

		CREATE TABLE IF NOT EXISTS profiles (
			user         TEXT PRIMARY KEY,
			display_name TEXT,
			avatar_id    TEXT,
			status_text  TEXT
		);

		CREATE TABLE IF NOT EXISTS user_rooms (
			user        TEXT NOT NULL,
			room        TEXT NOT NULL,
			first_seen  INTEGER NOT NULL,
			first_epoch INTEGER NOT NULL DEFAULT 0,
			PRIMARY KEY (user, room)
		);

		CREATE TABLE IF NOT EXISTS read_positions (
			user            TEXT NOT NULL,
			device_id       TEXT NOT NULL,
			room            TEXT NOT NULL DEFAULT '',
			conversation_id TEXT NOT NULL DEFAULT '',
			last_read       TEXT NOT NULL,
			ts              INTEGER NOT NULL,
			PRIMARY KEY (user, device_id, room, conversation_id)
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
	`)
	return err
}
