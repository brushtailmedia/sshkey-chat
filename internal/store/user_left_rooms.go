package store

// Phase 20 — user_left_rooms pure-history helpers.
//
// The queue concern moved to pending_remove_from_room (Option D).
// This file is now strictly about leave history: performRoomLeave
// writes rows, GetUserLeftRoomsCatchup reads them on handshake,
// DeleteUserLeftRoomRows clears on re-add, PruneOldUserLeftRooms
// handles retention.
//
// See refactor_plan.md Phase 20 for the rationale on the queue/history
// split.

import (
	"time"
)

// UserLeftRoom is one history row from user_left_rooms. Phase 20
// dropped the Processed field alongside the schema change.
type UserLeftRoom struct {
	ID          int64
	UserID      string
	RoomID      string
	Reason      string // '' | 'removed' | 'user_retired'
	InitiatedBy string // user_id for self-leave, 'os:<uid>' for CLI, 'system' for retirement
	LeftAt      int64
}

// RecordUserLeftRoom inserts a history row. Called exclusively from
// performRoomLeave, never from callers directly.
func (s *Store) RecordUserLeftRoom(userID, roomID, reason, initiatedBy string) (int64, error) {
	res, err := s.dataDB.Exec(
		`INSERT INTO user_left_rooms (user_id, room_id, reason, initiated_by, left_at) VALUES (?, ?, ?, ?, ?)`,
		userID, roomID, reason, initiatedBy, time.Now().Unix(),
	)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// GetUserLeftRoomsCatchup returns the most recent leave per room for
// the user. Ordered by left_at descending.
//
// Note: room_members lives in rooms.db (separate SQLite file), so the
// "exclude re-joined rooms" filter is applied by the caller
// (sendLeftRooms) via IsRoomMemberByID rather than a SQL JOIN. Under
// normal operation DeleteUserLeftRoomRows clears stale rows on
// re-add, so the Go-side filter is defensive.
func (s *Store) GetUserLeftRoomsCatchup(userID string) ([]UserLeftRoom, error) {
	rows, err := s.dataDB.Query(`
		SELECT id, user_id, room_id, reason, initiated_by, left_at
		FROM user_left_rooms
		WHERE user_id = ?
		GROUP BY room_id
		HAVING left_at = MAX(left_at)
		ORDER BY left_at DESC`,
		userID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []UserLeftRoom
	for rows.Next() {
		var u UserLeftRoom
		if err := rows.Scan(&u.ID, &u.UserID, &u.RoomID, &u.Reason, &u.InitiatedBy, &u.LeftAt); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// DeleteUserLeftRoomRows removes all user_left_rooms rows for the
// given (user, room). Called from cmdAddToRoom after a successful
// AddRoomMember so re-joining the room clears the prior leave
// history — stale rows would otherwise re-surface on next catchup.
func (s *Store) DeleteUserLeftRoomRows(userID, roomID string) error {
	_, err := s.dataDB.Exec(
		`DELETE FROM user_left_rooms WHERE user_id = ? AND room_id = ?`,
		userID, roomID,
	)
	return err
}

// PruneOldUserLeftRooms deletes rows older than maxAgeSec seconds.
// Returns the number of rows deleted. Called opportunistically from
// the retirement handler (see retirement.go) with maxAgeSec set to
// 1 year, matching the retention convention for deleted_rooms.
func (s *Store) PruneOldUserLeftRooms(maxAgeSec int64) (int64, error) {
	cutoff := time.Now().Unix() - maxAgeSec
	res, err := s.dataDB.Exec(
		`DELETE FROM user_left_rooms WHERE left_at < ?`,
		cutoff,
	)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
