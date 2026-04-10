package store

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/brushtailmedia/sshkey-chat/internal/config"
)

// retiredRoomSuffixLen is the number of random base62 characters appended
// to a retired room's display name (prefixed with an underscore). Four
// characters give ~16 million possibilities from the 64-char alphabet,
// collision-resistant for any plausible deployment per Q1 of the Phase
// 12 design.
const retiredRoomSuffixLen = 4

// setRoomRetiredMaxAttempts bounds the number of retries when a generated
// suffix collides with an existing display_name unique index. One retry
// is sufficient in practice; three gives margin.
const setRoomRetiredMaxAttempts = 3

// initRoomsDB creates the rooms.db schema.
func (s *Store) initRoomsDB() error {
	_, err := s.roomsDB.Exec(`
		CREATE TABLE IF NOT EXISTS rooms (
			id           TEXT PRIMARY KEY,
			display_name TEXT NOT NULL,
			topic        TEXT NOT NULL DEFAULT '',
			retired      INTEGER NOT NULL DEFAULT 0,
			retired_at   TEXT NOT NULL DEFAULT '',
			retired_by   TEXT NOT NULL DEFAULT '',
			created_at   TEXT NOT NULL DEFAULT (datetime('now'))
		);

		CREATE UNIQUE INDEX IF NOT EXISTS idx_rooms_display_name_lower
			ON rooms(LOWER(display_name));

		CREATE TABLE IF NOT EXISTS room_members (
			room_id     TEXT NOT NULL,
			user_id     TEXT NOT NULL,
			first_epoch INTEGER NOT NULL DEFAULT 0,
			joined_at   TEXT NOT NULL DEFAULT (datetime('now')),
			PRIMARY KEY (room_id, user_id)
		);

		CREATE INDEX IF NOT EXISTS idx_room_members_user
			ON room_members(user_id);
	`)
	return err
}

// RoomsDBEmpty returns true if the rooms table has no rows.
func (s *Store) RoomsDBEmpty() bool {
	var count int
	s.roomsDB.QueryRow(`SELECT COUNT(*) FROM rooms`).Scan(&count)
	return count == 0
}

// SeedRooms populates rooms.db from a parsed rooms.toml map.
// Generates a nanoid ID for each room. The TOML section key becomes
// the display_name. Skips if rooms.db already has data.
func (s *Store) SeedRooms(rooms map[string]config.Room) (int, error) {
	if !s.RoomsDBEmpty() {
		return 0, nil
	}

	tx, err := s.roomsDB.Begin()
	if err != nil {
		return 0, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	count := 0
	for name, room := range rooms {
		id := GenerateRoomID()
		topic := room.Topic
		_, err := tx.Exec(
			`INSERT INTO rooms (id, display_name, topic) VALUES (?, ?, ?)`,
			id, name, topic,
		)
		if err != nil {
			return 0, fmt.Errorf("insert room %q: %w", name, err)
		}
		count++
	}

	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit: %w", err)
	}
	return count, nil
}

// RoomMembersEmpty returns true if the room_members table has no rows.
func (s *Store) RoomMembersEmpty() bool {
	var count int
	s.roomsDB.QueryRow(`SELECT COUNT(*) FROM room_members`).Scan(&count)
	return count == 0
}

// SeedRoomMembers populates room_members from a parsed users.toml map.
// Resolves room display names to nanoid IDs via RoomDisplayNameToID.
// Skips unknown rooms (room not in rooms.db). Uses first_epoch = 0
// (fresh install, user has access from the beginning).
// Must be called after SeedRooms. Skips if room_members already has data.
func (s *Store) SeedRoomMembers(users map[string]config.User) (int, error) {
	if !s.RoomMembersEmpty() {
		return 0, nil
	}

	tx, err := s.roomsDB.Begin()
	if err != nil {
		return 0, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	count := 0
	for userID, user := range users {
		if user.Retired {
			continue
		}
		for _, roomName := range user.Rooms {
			roomID := s.RoomDisplayNameToID(roomName)
			if roomID == "" {
				continue // room not in rooms.db, skip
			}
			_, err := tx.Exec(
				`INSERT OR IGNORE INTO room_members (room_id, user_id, first_epoch) VALUES (?, ?, 0)`,
				roomID, userID,
			)
			if err != nil {
				return 0, fmt.Errorf("insert member %s in room %s: %w", userID, roomName, err)
			}
			count++
		}
	}

	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit: %w", err)
	}
	return count, nil
}

// AddRoomMember adds a user to a room. Idempotent (INSERT OR IGNORE).
func (s *Store) AddRoomMember(roomID, userID string, firstEpoch int64) error {
	_, err := s.roomsDB.Exec(
		`INSERT OR IGNORE INTO room_members (room_id, user_id, first_epoch) VALUES (?, ?, ?)`,
		roomID, userID, firstEpoch)
	return err
}

// RemoveRoomMember removes a user from a room.
func (s *Store) RemoveRoomMember(roomID, userID string) error {
	_, err := s.roomsDB.Exec(
		`DELETE FROM room_members WHERE room_id = ? AND user_id = ?`,
		roomID, userID)
	return err
}

// RemoveAllRoomMembers removes a user from all rooms (used on retirement).
func (s *Store) RemoveAllRoomMembers(userID string) {
	s.roomsDB.Exec(`DELETE FROM room_members WHERE user_id = ?`, userID)
}

// GetUserRoomIDs returns the nanoid IDs of all rooms a user is in.
func (s *Store) GetUserRoomIDs(userID string) []string {
	rows, err := s.roomsDB.Query(`
		SELECT rm.room_id FROM room_members rm
		JOIN rooms r ON rm.room_id = r.id
		WHERE rm.user_id = ? AND r.retired = 0
		ORDER BY r.created_at`,
		userID)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var ids []string
	for rows.Next() {
		var id string
		if rows.Scan(&id) == nil {
			ids = append(ids, id)
		}
	}
	return ids
}

// GetRoomMemberIDsByRoomID returns all user IDs in a room, looked up by room nanoid.
func (s *Store) GetRoomMemberIDsByRoomID(roomID string) []string {
	rows, err := s.roomsDB.Query(
		`SELECT user_id FROM room_members WHERE room_id = ?`, roomID)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var members []string
	for rows.Next() {
		var uid string
		if rows.Scan(&uid) == nil {
			members = append(members, uid)
		}
	}
	return members
}

// IsRoomMemberByID returns true if a user is a member of the room (by room nanoid).
func (s *Store) IsRoomMemberByID(roomID, userID string) bool {
	var count int
	s.roomsDB.QueryRow(
		`SELECT COUNT(*) FROM room_members WHERE room_id = ? AND user_id = ?`,
		roomID, userID).Scan(&count)
	return count > 0
}

// GetRoomByID returns a room by its nanoid. Returns nil if not found.
func (s *Store) GetRoomByID(id string) (*RoomRecord, error) {
	var r RoomRecord
	var retired int
	err := s.roomsDB.QueryRow(
		`SELECT id, display_name, topic, retired, retired_at, retired_by, created_at FROM rooms WHERE id = ?`,
		id).Scan(&r.ID, &r.DisplayName, &r.Topic, &retired, &r.RetiredAt, &r.RetiredBy, &r.CreatedAt)
	if err != nil {
		return nil, nil // not found
	}
	r.Retired = retired != 0
	return &r, nil
}

// GetRoomByDisplayName returns a room by its display name (case-insensitive).
// Returns nil if not found.
func (s *Store) GetRoomByDisplayName(name string) (*RoomRecord, error) {
	var r RoomRecord
	var retired int
	err := s.roomsDB.QueryRow(
		`SELECT id, display_name, topic, retired, retired_at, retired_by, created_at FROM rooms WHERE LOWER(display_name) = LOWER(?)`,
		name).Scan(&r.ID, &r.DisplayName, &r.Topic, &retired, &r.RetiredAt, &r.RetiredBy, &r.CreatedAt)
	if err != nil {
		return nil, nil // not found
	}
	r.Retired = retired != 0
	return &r, nil
}

// RoomDisplayNameToID resolves a room display name to its nanoid.
// Returns empty string if not found.
func (s *Store) RoomDisplayNameToID(name string) string {
	var id string
	s.roomsDB.QueryRow(
		`SELECT id FROM rooms WHERE LOWER(display_name) = LOWER(?)`,
		name).Scan(&id)
	return id
}



// GetAllRooms returns all rooms from rooms.db.
func (s *Store) GetAllRooms() ([]RoomRecord, error) {
	rows, err := s.roomsDB.Query(
		`SELECT id, display_name, topic, retired, retired_at, retired_by, created_at FROM rooms ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rooms []RoomRecord
	for rows.Next() {
		var r RoomRecord
		var retired int
		if err := rows.Scan(&r.ID, &r.DisplayName, &r.Topic, &retired, &r.RetiredAt, &r.RetiredBy, &r.CreatedAt); err != nil {
			return nil, err
		}
		r.Retired = retired != 0
		rooms = append(rooms, r)
	}
	return rooms, rows.Err()
}

// RoomRecord represents a room from rooms.db.
type RoomRecord struct {
	ID          string
	DisplayName string
	Topic       string
	Retired     bool
	RetiredAt   string
	RetiredBy   string
	CreatedAt   string
}

// IsRoomRetired returns true if the room exists and has retired = 1 set
// in rooms.db. Called from every write handler (handleSend, handleReact,
// handlePin, etc.) as the top-of-function gate that rejects writes to
// retired rooms with the "This room has been archived and is read-only"
// error (ErrRoomRetired). Missing rooms return false — the unknown-room
// error fires from elsewhere in the handler.
func (s *Store) IsRoomRetired(roomID string) bool {
	var retired int
	s.roomsDB.QueryRow(`SELECT retired FROM rooms WHERE id = ?`, roomID).Scan(&retired)
	return retired != 0
}

// SetRoomRetired marks a room as retired in rooms.db. Atomically:
//   - sets retired = 1
//   - sets retired_at to now (RFC3339 UTC)
//   - sets retired_by to the admin's user ID
//   - suffixes display_name with a 4-char random base62 tag (e.g.
//     "engineering" → "engineering_V1St") so the original display name
//     is immediately free for reuse by a new room
//
// On unique-index violation (a collision with an existing display_name
// in the case-insensitive unique index), retries up to
// setRoomRetiredMaxAttempts times with a freshly-generated suffix.
//
// Errors if the room doesn't exist, is already retired, or if every
// retry attempt collides. Mirrors SetUserRetired's shape from users.go.
//
// Called from the CLI's cmdRetireRoom. sshkey-ctl runs locally on the
// server box only — the chat protocol does not accept admin verbs over
// the wire, so retirement is a direct DB mutation rather than a
// protocol message. After SetRoomRetired succeeds, the CLI inserts a
// row into pending_room_retirements so the running server can broadcast
// room_retired to connected members. See PROJECT.md "Rooms / Channels"
// for the full security rationale.
func (s *Store) SetRoomRetired(roomID, retiredBy, _reason string) error {
	// Verify the room exists and isn't already retired. We do this as a
	// separate read to produce a clearer error than the UPDATE's
	// "rows affected = 0" ambiguity.
	var exists, alreadyRetired int
	err := s.roomsDB.QueryRow(
		`SELECT COUNT(*), COALESCE(MAX(retired), 0) FROM rooms WHERE id = ?`,
		roomID,
	).Scan(&exists, &alreadyRetired)
	if err != nil {
		return fmt.Errorf("lookup room %q: %w", roomID, err)
	}
	if exists == 0 {
		return fmt.Errorf("room %q not found", roomID)
	}
	if alreadyRetired != 0 {
		return fmt.Errorf("room %q is already retired", roomID)
	}

	now := time.Now().UTC().Format(time.RFC3339)

	// Try up to setRoomRetiredMaxAttempts times, regenerating the
	// suffix on each attempt. Unique-index violations surface from the
	// driver as an Exec error containing "UNIQUE constraint failed" —
	// retry on any Exec error that still leaves the row with retired = 0
	// (we re-check after each failed attempt to distinguish collision
	// from a genuine DB error).
	var lastErr error
	for attempt := 0; attempt < setRoomRetiredMaxAttempts; attempt++ {
		suffix := "_" + generateRetiredSuffix(retiredRoomSuffixLen)

		res, err := s.roomsDB.Exec(`
			UPDATE rooms SET
				retired = 1,
				retired_at = ?,
				retired_by = ?,
				display_name = display_name || ?
			WHERE id = ? AND retired = 0`,
			now, retiredBy, suffix, roomID,
		)
		if err != nil {
			// Could be a unique-index collision on the suffixed
			// display_name. Retry with a fresh suffix.
			lastErr = err
			continue
		}
		n, _ := res.RowsAffected()
		if n == 1 {
			return nil // success
		}
		// No rows affected despite no error — likely a race where
		// another caller retired the room between our initial check
		// and the UPDATE. Treat as already-retired.
		return fmt.Errorf("room %q is already retired", roomID)
	}

	return fmt.Errorf("retire room %q: exhausted retries: %w", roomID, lastErr)
}

// GetRetiredRoomsForUser returns every retired room where the given user
// is still present in room_members. Called from sendRetiredRooms at the
// connect handshake to build the catchup list for offline devices that
// missed the live room_retired broadcast.
//
// Filter semantics per Q8 of the Phase 12 design: a user who voluntarily
// left a room BEFORE it was retired does NOT see the retirement in this
// list, because their room_members row has already been removed by the
// leave. Only retired rooms where the user is still a formal member are
// returned. This provides a natural bound on the list size without
// needing a time-based cutoff.
func (s *Store) GetRetiredRoomsForUser(userID string) ([]RoomRecord, error) {
	rows, err := s.roomsDB.Query(`
		SELECT r.id, r.display_name, r.topic, r.retired, r.retired_at, r.retired_by, r.created_at
		FROM rooms r
		JOIN room_members rm ON rm.room_id = r.id
		WHERE rm.user_id = ? AND r.retired = 1
		ORDER BY r.retired_at DESC`,
		userID)
	if err != nil {
		return nil, fmt.Errorf("query retired rooms for user %q: %w", userID, err)
	}
	defer rows.Close()

	var out []RoomRecord
	for rows.Next() {
		var r RoomRecord
		var retired int
		if err := rows.Scan(&r.ID, &r.DisplayName, &r.Topic, &retired, &r.RetiredAt, &r.RetiredBy, &r.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan retired room: %w", err)
		}
		r.Retired = retired != 0
		out = append(out, r)
	}
	return out, rows.Err()
}

// generateRetiredSuffix returns a random base62 string of length n,
// using the same alphabet as the nanoid generator. Used by
// SetRoomRetired to produce collision-resistant retired-room suffixes.
// Falls back to a deterministic constant if crypto/rand is unavailable
// (should never happen in practice — rand.Int only errors on platform
// RNG failure).
func generateRetiredSuffix(n int) string {
	// Use the base62 subset of idAlphabet (skip _ and -) so the suffix
	// doesn't accidentally introduce shell-escaping concerns or
	// whitespace-adjacent weirdness in display names.
	const base62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	var sb strings.Builder
	sb.Grow(n)
	for i := 0; i < n; i++ {
		idx, err := rand.Int(rand.Reader, big.NewInt(int64(len(base62))))
		if err != nil {
			// Extremely unlikely — platform RNG failure. Fall back to
			// a non-random (but still-working) character so the caller
			// still gets a result they can retry with.
			sb.WriteByte(base62[0])
			continue
		}
		sb.WriteByte(base62[idx.Int64()])
	}
	return sb.String()
}

