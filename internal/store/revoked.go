package store

import "database/sql"

// RevokeDevice marks a device as revoked.
func (s *Store) RevokeDevice(user, deviceID, reason string) error {
	_, err := s.dataDB.Exec(`
		INSERT INTO revoked_devices (user, device_id, reason)
		VALUES (?, ?, ?)
		ON CONFLICT (user, device_id) DO NOTHING`,
		user, deviceID, reason,
	)
	return err
}

// RestoreDevice removes a device from the revoked list.
func (s *Store) RestoreDevice(user, deviceID string) error {
	_, err := s.dataDB.Exec(`DELETE FROM revoked_devices WHERE user = ? AND device_id = ?`, user, deviceID)
	return err
}

// IsDeviceRevoked checks if a device has been revoked.
func (s *Store) IsDeviceRevoked(user, deviceID string) (bool, error) {
	var count int
	err := s.dataDB.QueryRow(`
		SELECT COUNT(*) FROM revoked_devices WHERE user = ? AND device_id = ?`,
		user, deviceID,
	).Scan(&count)
	if err == sql.ErrNoRows {
		return false, nil
	}
	return count > 0, err
}
