package store

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/brushtailmedia/sshkey-chat/internal/config"
)

// UserRecord represents a user row from users.db.
type UserRecord struct {
	ID            string
	Key           string
	DisplayName   string
	Admin         bool
	Retired       bool
	RetiredAt     string
	RetiredReason string
}

func (s *Store) initUsersDB() error {
	_, err := s.usersDB.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id             TEXT PRIMARY KEY,
			key            TEXT NOT NULL,
			display_name   TEXT NOT NULL,
			admin          INTEGER NOT NULL DEFAULT 0,
			retired        INTEGER NOT NULL DEFAULT 0,
			retired_at     TEXT NOT NULL DEFAULT '',
			retired_reason TEXT NOT NULL DEFAULT ''
		);

		CREATE UNIQUE INDEX IF NOT EXISTS idx_users_key ON users(key);
	`)
	return err
}

// UsersDBEmpty returns true if the users table has no rows.
func (s *Store) UsersDBEmpty() bool {
	var count int
	s.usersDB.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&count)
	return count == 0
}

// SeedUsers populates users.db from a parsed users.toml map.
// Section keys in the TOML are the nanoid user IDs.
// Skips if users.db already has data.
func (s *Store) SeedUsers(users map[string]config.User) (int, error) {
	if !s.UsersDBEmpty() {
		return 0, nil
	}

	count := 0
	for userID, user := range users {
		// Strip the comment from the SSH key (everything after the key type + data)
		key := user.Key
		parts := strings.Fields(key)
		if len(parts) >= 2 {
			key = parts[0] + " " + parts[1] // type + key data, no comment
		}

		admin := 0
		retired := 0
		if user.Retired {
			retired = 1
		}

		_, err := s.usersDB.Exec(`
			INSERT OR IGNORE INTO users (id, key, display_name, admin, retired, retired_at, retired_reason)
			VALUES (?, ?, ?, ?, ?, ?, ?)`,
			userID, key, user.DisplayName, admin, retired, user.RetiredAt, user.RetiredReason,
		)
		if err != nil {
			return count, fmt.Errorf("seed user %s: %w", userID, err)
		}
		count++
	}
	return count, nil
}

// --- Reads ---

// GetUserByID returns a user record by nanoid. Returns nil if not found.
func (s *Store) GetUserByID(userID string) *UserRecord {
	var u UserRecord
	var admin, retired int
	err := s.usersDB.QueryRow(`
		SELECT id, key, display_name, admin, retired, retired_at, retired_reason
		FROM users WHERE id = ?`, userID,
	).Scan(&u.ID, &u.Key, &u.DisplayName, &admin, &retired, &u.RetiredAt, &u.RetiredReason)
	if err != nil {
		return nil
	}
	u.Admin = admin != 0
	u.Retired = retired != 0
	return &u
}

// GetUserByKey finds a user by their SSH public key (type + key data, no comment).
// Returns the user ID, or empty string if not found.
func (s *Store) GetUserByKey(pubKey string) string {
	// Normalize: strip comment if present
	parts := strings.Fields(pubKey)
	normalized := pubKey
	if len(parts) >= 2 {
		normalized = parts[0] + " " + parts[1]
	}

	var userID string
	s.usersDB.QueryRow(`SELECT id FROM users WHERE key = ?`, normalized).Scan(&userID)
	return userID
}

// IsAdmin returns true if the user exists and has admin privileges.
func (s *Store) IsAdmin(userID string) bool {
	var admin int
	s.usersDB.QueryRow(`SELECT admin FROM users WHERE id = ?`, userID).Scan(&admin)
	return admin != 0
}

// IsUserRetired returns true if the user exists and is retired.
func (s *Store) IsUserRetired(userID string) bool {
	var retired int
	s.usersDB.QueryRow(`SELECT retired FROM users WHERE id = ?`, userID).Scan(&retired)
	return retired != 0
}

// GetUserKey returns the SSH public key for a user. Returns empty string if not found.
func (s *Store) GetUserKey(userID string) string {
	var key string
	s.usersDB.QueryRow(`SELECT key FROM users WHERE id = ?`, userID).Scan(&key)
	return key
}

// GetUserDisplayName returns the display name for a user. Falls back to raw ID.
func (s *Store) GetUserDisplayName(userID string) string {
	var name string
	err := s.usersDB.QueryRow(`SELECT display_name FROM users WHERE id = ?`, userID).Scan(&name)
	if err != nil || name == "" {
		return userID
	}
	return name
}

// GetAllUsers returns all non-retired users.
func (s *Store) GetAllUsers() []UserRecord {
	rows, err := s.usersDB.Query(`
		SELECT id, key, display_name, admin, retired, retired_at, retired_reason
		FROM users WHERE retired = 0`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	return scanUserRows(rows)
}

// GetAllRetiredUsers returns all retired users.
func (s *Store) GetAllRetiredUsers() []UserRecord {
	rows, err := s.usersDB.Query(`
		SELECT id, key, display_name, admin, retired, retired_at, retired_reason
		FROM users WHERE retired = 1`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	return scanUserRows(rows)
}

// GetAllUsersIncludingRetired returns every user.
func (s *Store) GetAllUsersIncludingRetired() []UserRecord {
	rows, err := s.usersDB.Query(`
		SELECT id, key, display_name, admin, retired, retired_at, retired_reason
		FROM users`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	return scanUserRows(rows)
}

// IsDisplayNameTaken returns true if another user (excluding excludeUserID)
// already has this display name (case-insensitive).
func (s *Store) IsDisplayNameTaken(name, excludeUserID string) bool {
	var count int
	s.usersDB.QueryRow(`
		SELECT COUNT(*) FROM users WHERE LOWER(display_name) = LOWER(?) AND id != ?`,
		name, excludeUserID).Scan(&count)
	return count > 0
}

// --- Writes ---

// InsertUser adds a new user to users.db. Used by CLI approve.
func (s *Store) InsertUser(id, key, displayName string) error {
	// Normalize key: strip comment
	parts := strings.Fields(key)
	normalized := key
	if len(parts) >= 2 {
		normalized = parts[0] + " " + parts[1]
	}

	_, err := s.usersDB.Exec(`
		INSERT INTO users (id, key, display_name) VALUES (?, ?, ?)`,
		id, normalized, displayName,
	)
	return err
}

// SetUserRetired marks a user as retired, suffixes the display name, and records the reason.
func (s *Store) SetUserRetired(userID, reason string) error {
	now := time.Now().UTC().Format(time.RFC3339)

	// Suffix display name to free it for reuse
	suffix := ""
	if len(userID) > 8 {
		suffix = "_" + userID[4:8]
	}

	_, err := s.usersDB.Exec(`
		UPDATE users SET
			retired = 1,
			retired_at = ?,
			retired_reason = ?,
			display_name = display_name || ?
		WHERE id = ? AND retired = 0`,
		now, reason, suffix, userID,
	)
	return err
}

// SetUserDisplayName updates a user's display name.
func (s *Store) SetUserDisplayName(userID, name string) error {
	_, err := s.usersDB.Exec(`UPDATE users SET display_name = ? WHERE id = ?`, name, userID)
	return err
}

// SetAdmin sets or clears the admin flag for a user.
func (s *Store) SetAdmin(userID string, admin bool) error {
	val := 0
	if admin {
		val = 1
	}
	_, err := s.usersDB.Exec(`UPDATE users SET admin = ? WHERE id = ?`, val, userID)
	return err
}

// DeleteUser removes a user from users.db entirely.
func (s *Store) DeleteUser(userID string) error {
	_, err := s.usersDB.Exec(`DELETE FROM users WHERE id = ?`, userID)
	return err
}

// UsersDB returns the underlying users database connection.
func (s *Store) UsersDB() *sql.DB {
	return s.usersDB
}

// --- helpers ---

func scanUserRows(rows interface{ Next() bool; Scan(...any) error }) []UserRecord {
	var users []UserRecord
	for rows.Next() {
		var u UserRecord
		var admin, retired int
		if rows.Scan(&u.ID, &u.Key, &u.DisplayName, &admin, &retired, &u.RetiredAt, &u.RetiredReason) == nil {
			u.Admin = admin != 0
			u.Retired = retired != 0
			users = append(users, u)
		}
	}
	return users
}
