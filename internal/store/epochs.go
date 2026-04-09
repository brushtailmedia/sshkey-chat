package store

// StoreEpochKey stores a wrapped epoch key for a user in a room.
func (s *Store) StoreEpochKey(room string, epoch int64, user, wrappedKey string) error {
	_, err := s.dataDB.Exec(`
		INSERT INTO epoch_keys (room, epoch, user, wrapped_key)
		VALUES (?, ?, ?, ?)
		ON CONFLICT (room, epoch, user) DO UPDATE SET wrapped_key = excluded.wrapped_key`,
		room, epoch, user, wrappedKey,
	)
	return err
}

// GetEpochKey retrieves a wrapped epoch key for a specific user/room/epoch.
func (s *Store) GetEpochKey(room string, epoch int64, user string) (string, error) {
	var wrappedKey string
	err := s.dataDB.QueryRow(`
		SELECT wrapped_key FROM epoch_keys WHERE room = ? AND epoch = ? AND user = ?`,
		room, epoch, user,
	).Scan(&wrappedKey)
	return wrappedKey, err
}

// GetCurrentEpoch returns the highest epoch number for a room.
func (s *Store) GetCurrentEpoch(room string) (int64, error) {
	var epoch int64
	err := s.dataDB.QueryRow(`
		SELECT COALESCE(MAX(epoch), 0) FROM epoch_keys WHERE room = ?`,
		room,
	).Scan(&epoch)
	return epoch, err
}

// GetEpochKeysForUser returns all wrapped epoch keys for a user in a room,
// filtered by epoch range. Used for sync and history.
func (s *Store) GetEpochKeysForUser(room, user string, minEpoch, maxEpoch int64) (map[int64]string, error) {
	rows, err := s.dataDB.Query(`
		SELECT epoch, wrapped_key FROM epoch_keys
		WHERE room = ? AND user = ? AND epoch >= ? AND epoch <= ?
		ORDER BY epoch`,
		room, user, minEpoch, maxEpoch,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	keys := make(map[int64]string)
	for rows.Next() {
		var epoch int64
		var wrappedKey string
		if err := rows.Scan(&epoch, &wrappedKey); err != nil {
			return nil, err
		}
		keys[epoch] = wrappedKey
	}
	return keys, rows.Err()
}

