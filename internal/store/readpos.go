package store

import (
	"database/sql"
	"time"
)

// SetReadPosition updates the read position for a user/device in a room or conversation.
func (s *Store) SetReadPosition(user, deviceID, room, convID, lastRead string) error {
	now := time.Now().Unix()
	if room == "" {
		room = ""
	}
	if convID == "" {
		convID = ""
	}
	_, err := s.usersDB.Exec(`
		INSERT INTO read_positions (user, device_id, room, conversation_id, last_read, ts)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT (user, device_id, room, conversation_id)
		DO UPDATE SET last_read = excluded.last_read, ts = excluded.ts`,
		user, deviceID, room, convID, lastRead, now,
	)
	return err
}

// GetReadPosition returns the last_read message ID for a user/device in a room or conversation.
func (s *Store) GetReadPosition(user, deviceID, room, convID string) (string, error) {
	var lastRead string
	var err error
	if room != "" {
		err = s.usersDB.QueryRow(`
			SELECT last_read FROM read_positions
			WHERE user = ? AND device_id = ? AND room = ?`,
			user, deviceID, room,
		).Scan(&lastRead)
	} else {
		err = s.usersDB.QueryRow(`
			SELECT last_read FROM read_positions
			WHERE user = ? AND device_id = ? AND conversation_id = ?`,
			user, deviceID, convID,
		).Scan(&lastRead)
	}
	if err == sql.ErrNoRows {
		return "", nil
	}
	return lastRead, err
}

// GetUnreadCount returns the count of messages after the user's read position.
func (s *Store) GetRoomUnreadCount(room, user, deviceID string) (int, string, error) {
	lastRead, err := s.GetReadPosition(user, deviceID, room, "")
	if err != nil {
		return 0, "", err
	}

	db, err := s.RoomDB(room)
	if err != nil {
		return 0, lastRead, err
	}

	var count int
	if lastRead == "" {
		// Never read — count all messages
		err = db.QueryRow(`SELECT COUNT(*) FROM messages WHERE deleted = 0`).Scan(&count)
	} else {
		err = db.QueryRow(`
			SELECT COUNT(*) FROM messages
			WHERE deleted = 0 AND rowid > (SELECT rowid FROM messages WHERE id = ?)`,
			lastRead,
		).Scan(&count)
	}
	return count, lastRead, err
}

// GetConvUnreadCount returns the count of unread DM messages.
func (s *Store) GetConvUnreadCount(convID, user, deviceID string) (int, string, error) {
	lastRead, err := s.GetReadPosition(user, deviceID, "", convID)
	if err != nil {
		return 0, "", err
	}

	db, err := s.ConvDB(convID)
	if err != nil {
		return 0, lastRead, err
	}

	var count int
	if lastRead == "" {
		err = db.QueryRow(`SELECT COUNT(*) FROM messages WHERE deleted = 0`).Scan(&count)
	} else {
		err = db.QueryRow(`
			SELECT COUNT(*) FROM messages
			WHERE deleted = 0 AND rowid > (SELECT rowid FROM messages WHERE id = ?)`,
			lastRead,
		).Scan(&count)
	}
	return count, lastRead, err
}

