package store

// PushToken represents a registered push token for a device.
type PushToken struct {
	User     string
	DeviceID string
	Platform string // "ios" or "android"
	Token    string
	Active   bool
}

// UpsertPushToken registers or updates a push token for a device.
func (s *Store) UpsertPushToken(user, deviceID, platform, token string) error {
	_, err := s.dataDB.Exec(`
		INSERT INTO push_tokens (user, device_id, platform, token, active, updated_at)
		VALUES (?, ?, ?, ?, 1, datetime('now'))
		ON CONFLICT (user, device_id) DO UPDATE SET
			platform = excluded.platform,
			token = excluded.token,
			active = 1,
			updated_at = datetime('now')`,
		user, deviceID, platform, token,
	)
	return err
}

// GetActivePushTokens returns all active push tokens for a user.
func (s *Store) GetActivePushTokens(user string) ([]PushToken, error) {
	rows, err := s.dataDB.Query(`
		SELECT user, device_id, platform, token
		FROM push_tokens WHERE user = ? AND active = 1`,
		user,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tokens []PushToken
	for rows.Next() {
		var t PushToken
		if err := rows.Scan(&t.User, &t.DeviceID, &t.Platform, &t.Token); err != nil {
			return nil, err
		}
		t.Active = true
		tokens = append(tokens, t)
	}
	return tokens, rows.Err()
}

// DeactivatePushToken marks a push token as inactive (e.g., delivery failure).
func (s *Store) DeactivatePushToken(user, deviceID string) error {
	_, err := s.dataDB.Exec(`
		UPDATE push_tokens SET active = 0 WHERE user = ? AND device_id = ?`,
		user, deviceID,
	)
	return err
}

// RemovePushToken removes a push token entirely.
func (s *Store) RemovePushToken(user, deviceID string) error {
	_, err := s.dataDB.Exec(`DELETE FROM push_tokens WHERE user = ? AND device_id = ?`, user, deviceID)
	return err
}
