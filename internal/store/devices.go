package store

import (
	"database/sql"
	"time"
)

// Device represents a registered device.
type Device struct {
	User       string
	DeviceID   string
	LastSynced string
	CreatedAt  string
}

// UpsertDevice registers or updates a device. Returns the current device count for the user.
func (s *Store) UpsertDevice(user, deviceID string) (int, error) {
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := s.dataDB.Exec(`
		INSERT INTO devices (user, device_id, created_at)
		VALUES (?, ?, ?)
		ON CONFLICT (user, device_id) DO NOTHING`,
		user, deviceID, now,
	)
	if err != nil {
		return 0, err
	}

	var count int
	err = s.dataDB.QueryRow(`SELECT COUNT(*) FROM devices WHERE user = ?`, user).Scan(&count)
	return count, err
}

// UpdateDeviceSync updates the last_synced timestamp for a device.
func (s *Store) UpdateDeviceSync(user, deviceID string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := s.dataDB.Exec(`
		UPDATE devices SET last_synced = ? WHERE user = ? AND device_id = ?`,
		now, user, deviceID,
	)
	return err
}

// GetDevices returns all devices for a user.
func (s *Store) GetDevices(user string) ([]Device, error) {
	rows, err := s.dataDB.Query(`
		SELECT user, device_id, COALESCE(last_synced, ''), created_at
		FROM devices WHERE user = ? ORDER BY created_at`,
		user,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var devices []Device
	for rows.Next() {
		var d Device
		if err := rows.Scan(&d.User, &d.DeviceID, &d.LastSynced, &d.CreatedAt); err != nil {
			return nil, err
		}
		devices = append(devices, d)
	}
	return devices, rows.Err()
}

// DeviceCount returns the number of registered devices for a user.
func (s *Store) DeviceCount(user string) (int, error) {
	var count int
	err := s.dataDB.QueryRow(`SELECT COUNT(*) FROM devices WHERE user = ?`, user).Scan(&count)
	return count, err
}

// RemoveDevice removes a device registration.
func (s *Store) RemoveDevice(user, deviceID string) error {
	_, err := s.dataDB.Exec(`DELETE FROM devices WHERE user = ? AND device_id = ?`, user, deviceID)
	return err
}

// OldestSyncTime returns the oldest last_synced time across all devices for all active users.
// Returns empty string if no devices have synced.
func (s *Store) OldestSyncTime() (string, error) {
	var oldest sql.NullString
	err := s.dataDB.QueryRow(`
		SELECT MIN(last_synced) FROM devices WHERE last_synced IS NOT NULL AND last_synced != ''
	`).Scan(&oldest)
	if err != nil {
		return "", err
	}
	return oldest.String, nil
}
