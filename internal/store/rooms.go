package store

import (
	"fmt"

	"github.com/brushtailmedia/sshkey-chat/internal/config"
)

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

