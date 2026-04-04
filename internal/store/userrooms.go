package store

import "time"

// SetUserRoom records when a user was added to a room. Idempotent.
func (s *Store) SetUserRoom(user, room string, firstEpoch int64) error {
	now := time.Now().Unix()
	_, err := s.usersDB.Exec(`
		INSERT INTO user_rooms (user, room, first_seen, first_epoch)
		VALUES (?, ?, ?, ?)
		ON CONFLICT (user, room) DO NOTHING`,
		user, room, now, firstEpoch,
	)
	return err
}

// GetUserRoom returns the first_seen timestamp and first_epoch for a user in a room.
// Returns 0, 0 if not found (user has no restriction).
func (s *Store) GetUserRoom(user, room string) (firstSeen int64, firstEpoch int64, err error) {
	err = s.usersDB.QueryRow(`
		SELECT first_seen, first_epoch FROM user_rooms WHERE user = ? AND room = ?`,
		user, room,
	).Scan(&firstSeen, &firstEpoch)
	if err != nil {
		return 0, 0, nil // not found = no restriction
	}
	return firstSeen, firstEpoch, nil
}

// RemoveUserRoom removes a user's room record (on removal from room).
func (s *Store) RemoveUserRoom(user, room string) error {
	_, err := s.usersDB.Exec(`DELETE FROM user_rooms WHERE user = ? AND room = ?`, user, room)
	return err
}
