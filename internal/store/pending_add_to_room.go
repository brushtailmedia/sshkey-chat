package store

import "time"

// PendingAddToRoom is one row from the pending_add_to_room queue.
type PendingAddToRoom struct {
	ID          int64
	UserID      string
	RoomID      string
	InitiatedBy string
	QueuedAt    int64
}

// RecordPendingAddToRoom queues add-to-room side effects for the
// running server processor. Membership is already written directly by
// the CLI; this queue exists for live fanout + epoch rotation.
func (s *Store) RecordPendingAddToRoom(userID, roomID, initiatedBy string) error {
	_, err := s.dataDB.Exec(
		`INSERT INTO pending_add_to_room (user_id, room_id, initiated_by, queued_at) VALUES (?, ?, ?, ?)`,
		userID, roomID, initiatedBy, time.Now().Unix(),
	)
	return err
}

// ConsumePendingAddToRooms atomically reads and deletes all queued
// rows in insertion order.
func (s *Store) ConsumePendingAddToRooms() ([]PendingAddToRoom, error) {
	tx, err := s.dataDB.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	rows, err := tx.Query(
		`SELECT id, user_id, room_id, initiated_by, queued_at FROM pending_add_to_room ORDER BY id`,
	)
	if err != nil {
		return nil, err
	}

	var pending []PendingAddToRoom
	for rows.Next() {
		var p PendingAddToRoom
		if err := rows.Scan(&p.ID, &p.UserID, &p.RoomID, &p.InitiatedBy, &p.QueuedAt); err != nil {
			rows.Close()
			return nil, err
		}
		pending = append(pending, p)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	if len(pending) > 0 {
		if _, err := tx.Exec(`DELETE FROM pending_add_to_room`); err != nil {
			return nil, err
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return pending, nil
}
