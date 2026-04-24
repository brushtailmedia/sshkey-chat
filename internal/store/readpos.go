package store

import (
	"database/sql"
	"time"
)

// SetReadPosition updates the read position for a user/device in a room,
// group DM, or 1:1 DM. Exactly one of room/groupID/dmID should be non-empty.
func (s *Store) SetReadPosition(user, deviceID, room, groupID, dmID, lastRead string) error {
	now := time.Now().Unix()
	_, err := s.dataDB.Exec(`
		INSERT INTO read_positions (user, device_id, room, group_id, dm_id, last_read, ts)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (user, device_id, room, group_id, dm_id)
		DO UPDATE SET last_read = excluded.last_read, ts = excluded.ts`,
		user, deviceID, room, groupID, dmID, lastRead, now,
	)
	return err
}

// GetReadPosition returns the last_read message ID for a user/device in a
// room, group DM, or 1:1 DM. Exactly one of room/groupID/dmID should be
// non-empty.
func (s *Store) GetReadPosition(user, deviceID, room, groupID, dmID string) (string, error) {
	var lastRead string
	var err error
	if room != "" {
		err = s.dataDB.QueryRow(`
			SELECT last_read FROM read_positions
			WHERE user = ? AND device_id = ? AND room = ?`,
			user, deviceID, room,
		).Scan(&lastRead)
	} else if groupID != "" {
		err = s.dataDB.QueryRow(`
			SELECT last_read FROM read_positions
			WHERE user = ? AND device_id = ? AND group_id = ?`,
			user, deviceID, groupID,
		).Scan(&lastRead)
	} else if dmID != "" {
		err = s.dataDB.QueryRow(`
			SELECT last_read FROM read_positions
			WHERE user = ? AND device_id = ? AND dm_id = ?`,
			user, deviceID, dmID,
		).Scan(&lastRead)
	}
	if err == sql.ErrNoRows {
		return "", nil
	}
	return lastRead, err
}

// GetRoomUnreadCount returns the count of messages after the user's read position.
func (s *Store) GetRoomUnreadCount(room, user, deviceID string) (int, string, error) {
	lastRead, err := s.GetReadPosition(user, deviceID, room, "", "")
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

// GetGroupUnreadCount returns the count of unread group DM messages.
func (s *Store) GetGroupUnreadCount(groupID, user, deviceID string) (int, string, error) {
	lastRead, err := s.GetReadPosition(user, deviceID, "", groupID, "")
	if err != nil {
		return 0, "", err
	}

	db, err := s.GroupDB(groupID)
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
