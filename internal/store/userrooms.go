package store

import "time"

// GetUserRoom returns the joined_at timestamp (as unix seconds) and first_epoch
// for a user in a room. Reads from room_members in rooms.db.
// Returns 0, 0 if not found (user has no restriction).
func (s *Store) GetUserRoom(userID, roomID string) (firstSeen int64, firstEpoch int64, err error) {
	var joinedAt string
	err = s.roomsDB.QueryRow(`
		SELECT joined_at, first_epoch FROM room_members WHERE room_id = ? AND user_id = ?`,
		roomID, userID,
	).Scan(&joinedAt, &firstEpoch)
	if err != nil {
		return 0, 0, nil // not found = no restriction
	}
	if t, parseErr := time.Parse("2006-01-02 15:04:05", joinedAt); parseErr == nil {
		firstSeen = t.Unix()
	}
	return firstSeen, firstEpoch, nil
}
