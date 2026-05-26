package store

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
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
	if _, err := s.usersDB.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id             TEXT PRIMARY KEY,
			key            TEXT NOT NULL,
			display_name   TEXT NOT NULL,
			admin          INTEGER NOT NULL DEFAULT 0,
			retired        INTEGER NOT NULL DEFAULT 0,
			retired_at     TEXT NOT NULL DEFAULT '',
			retired_reason TEXT NOT NULL DEFAULT '',
			quota_exempt   INTEGER NOT NULL DEFAULT 0
		);

		CREATE UNIQUE INDEX IF NOT EXISTS idx_users_key ON users(key);
	`); err != nil {
		return err
	}

	// Defensive ALTER TABLE for users.db files created before
	// quota_exempt was added (2026-04-19). No live users per the
	// pre-launch policy, so this is dev/test continuity only — but
	// failing-to-start because a column is missing on an existing
	// users.db is a worse UX than the silent migration. The IF NOT
	// EXISTS check via PRAGMA table_info avoids the "duplicate column"
	// error on already-migrated DBs.
	if !s.userColumnExists("quota_exempt") {
		if _, err := s.usersDB.Exec(`ALTER TABLE users ADD COLUMN quota_exempt INTEGER NOT NULL DEFAULT 0`); err != nil {
			return fmt.Errorf("migrate users.quota_exempt: %w", err)
		}
	}
	return nil
}

// userColumnExists returns true if the users table has a column with
// the given name. Used by initUsersDB to gate the defensive ALTER for
// columns added after the original CREATE TABLE shipped.
func (s *Store) userColumnExists(name string) bool {
	rows, err := s.usersDB.Query(`PRAGMA table_info(users)`)
	if err != nil {
		return false
	}
	defer rows.Close()
	for rows.Next() {
		var cid int
		var colName, colType string
		var notNull, pk int
		var dflt sql.NullString
		if err := rows.Scan(&cid, &colName, &colType, &notNull, &dflt, &pk); err != nil {
			return false
		}
		if colName == name {
			return true
		}
	}
	return false
}

// UsersDBEmpty returns true if the users table has no rows.
func (s *Store) UsersDBEmpty() bool {
	var count int
	s.usersDB.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&count)
	return count == 0
}

// Users are created exclusively via `sshkey-ctl approve` — every
// user supplies their own SSH public key (which arrives through the
// pending-keys queue when they first attempt a connection). The
// first admin uses `approve --admin` to flip the admin bit in the
// same transaction. There is no seed-file entry point and no
// server-side keygen path.

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

// GetUserFingerprint computes the SSH fingerprint for a user's stored
// key. Returns empty string if the user doesn't exist or the key
// can't be parsed. Phase 16 — used by cmdBlockFingerprint to check
// whether a fingerprint belongs to an already-approved user.
func (s *Store) GetUserFingerprint(userID string) string {
	key := s.GetUserKey(userID)
	if key == "" {
		return ""
	}
	parsed, _, _, _, err := ssh.ParseAuthorizedKey([]byte(key))
	if err != nil {
		return ""
	}
	return ssh.FingerprintSHA256(parsed)
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

// maxDisplayNameBytes mirrors the display-name byte cap enforced by
// config.ValidateDisplayName. Kept as a local constant so the store layer does
// not depend on the config package; if the policy cap ever changes, update both.
const maxDisplayNameBytes = 32

// truncateToBytes returns the longest prefix of s whose length in bytes does not
// exceed max, cut on a UTF-8 rune boundary so a multi-byte rune is never split.
func truncateToBytes(s string, max int) string {
	if max <= 0 {
		return ""
	}
	if len(s) <= max {
		return s
	}
	cut := 0
	for i := range s { // i is the byte offset of each rune's start
		if i > max {
			break
		}
		cut = i
	}
	return s[:cut]
}

// SetUserRetired marks a user as retired, suffixes the display name to free it
// for reuse, and records the reason.
//
// Option (b) of retirement-name-handling: the 32-byte display-name policy is
// left unchanged, and when the name plus the retirement suffix would exceed the
// byte cap the name is truncated on a UTF-8 rune boundary to make room — only on
// retire, only when necessary. (See refactor-plan.md.)
func (s *Store) SetUserRetired(userID, reason string) error {
	now := time.Now().UTC().Format(time.RFC3339)

	// Suffix display name to free it for reuse.
	suffix := ""
	if len(userID) > 8 {
		suffix = "_" + userID[4:8]
	}

	// Short userID (no suffix): preserve the original flag-only update so the
	// display name passes through untouched.
	if suffix == "" {
		_, err := s.usersDB.Exec(`
			UPDATE users SET
				retired = 1,
				retired_at = ?,
				retired_reason = ?
			WHERE id = ? AND retired = 0`,
			now, reason, userID,
		)
		return err
	}

	// Read the current name so we can rune-safe truncate it to leave room for
	// the suffix within the byte cap, then write base+suffix. (The WHERE
	// retired = 0 guard below still makes a re-retire a no-op.)
	user := s.GetUserByID(userID)
	if user == nil {
		return fmt.Errorf("user %q does not exist", userID)
	}
	base := truncateToBytes(user.DisplayName, maxDisplayNameBytes-len(suffix))
	retiredName := base + suffix

	_, err := s.usersDB.Exec(`
		UPDATE users SET
			retired = 1,
			retired_at = ?,
			retired_reason = ?,
			display_name = ?
		WHERE id = ? AND retired = 0`,
		now, reason, retiredName, userID,
	)
	return err
}

// setUserUnretiredMaxAttempts bounds placeholder-name regeneration when the
// original display name is unavailable on unretire. A random GenerateID name
// effectively never collides, so this is purely defensive (mirrors rooms'
// setRoomRetiredMaxAttempts).
const setUserUnretiredMaxAttempts = 5

// SetUserUnretired reverses a retirement. It attempts to restore the user's
// original display name (stripping the retirement suffix that SetUserRetired
// added); if that name is unavailable — empty, or already claimed by another
// account while this one was retired (retirement frees the name) — it assigns a
// unique random placeholder instead, which the user can change later via their
// client. Phase 16 Gap 1 escape hatch for mistaken retirements.
//
// Returns the assigned display name and whether the original was restored
// (false = a placeholder was assigned). The stripped original is valid by
// construction (it was a valid name before retirement, and rune-safe truncation
// preserves validity), so unretirement gates only on availability, not on
// re-validation.
//
// What this does NOT do: restore room/group/DM memberships. The retirement
// cascade in handleRetirement removed the user from every shared context, and
// SetUserUnretired only touches the users table. Operators must manually re-add
// via `sshkey-ctl add-to-room` (or in-group /add for group DMs).
//
// Returns an error if the user doesn't exist or is not currently retired (the
// CLI side surfaces these as user-facing errors).
func (s *Store) SetUserUnretired(userID string) (string, bool, error) {
	user := s.GetUserByID(userID)
	if user == nil {
		return "", false, fmt.Errorf("user %q does not exist", userID)
	}
	if !user.Retired {
		return "", false, fmt.Errorf("user %q is not retired", userID)
	}

	// Best-effort original name: strip the retirement suffix (inverse of
	// SetUserRetired's: same userID slice, same separator).
	candidate := user.DisplayName
	if len(userID) > 8 {
		candidate = strings.TrimSuffix(candidate, "_"+userID[4:8])
	}

	chosen := candidate
	restoredOriginal := true

	// If the original name is empty or has been claimed by another account,
	// fall back to a unique random placeholder. IsDisplayNameTaken excludes this
	// user's own (still-suffixed) row, so it detects a genuine third-party claim.
	if candidate == "" || s.IsDisplayNameTaken(candidate, userID) {
		restoredOriginal = false
		chosen = ""
		for attempt := 0; attempt < setUserUnretiredMaxAttempts; attempt++ {
			name := GenerateID("user_")
			if !s.IsDisplayNameTaken(name, userID) {
				chosen = name
				break
			}
		}
		if chosen == "" {
			return "", false, fmt.Errorf("unretire %q: could not generate an available placeholder display name", userID)
		}
	}

	if _, err := s.usersDB.Exec(`
		UPDATE users SET
			retired = 0,
			retired_at = '',
			retired_reason = '',
			display_name = ?
		WHERE id = ? AND retired = 1`,
		chosen, userID,
	); err != nil {
		return "", false, err
	}
	return chosen, restoredOriginal, nil
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

// UsersDB returns the underlying users database connection.
func (s *Store) UsersDB() *sql.DB {
	return s.usersDB
}

// --- helpers ---

func scanUserRows(rows interface {
	Next() bool
	Scan(...any) error
}) []UserRecord {
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
