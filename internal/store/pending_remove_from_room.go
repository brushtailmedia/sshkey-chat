package store

// Phase 20 — pending_remove_from_room queue helpers.
//
// Queue for sshkey-ctl remove-from-room. Follows the same shape as
// the other five Phase 16 pending_* queues (pending_admin_state_changes,
// pending_room_updates, pending_device_revocations,
// pending_user_retirements, pending_user_unretirements): DELETE on
// consume, atomic SELECT+DELETE in one transaction.
//
// The CLI (cmdRemoveFromRoom) enqueues a row. The server's
// runRemoveFromRoomProcessor drains the queue, calls performRoomLeave
// (which writes the history row to user_left_rooms inline, broadcasts
// the leave event, echoes room_left, and marks the room for epoch
// rotation), and the consumed row is deleted as part of the atomic
// consume transaction.
//
// Phase 20 split this queue out from the previously dual-purpose
// user_left_rooms table. See refactor_plan.md Phase 20 (Option D) for
// the rationale: queue is a queue, history is history.

import (
	"time"
)

// PendingRemoveFromRoom is one row from the pending_remove_from_room
// queue.
type PendingRemoveFromRoom struct {
	ID          int64
	UserID      string
	RoomID      string
	Reason      string
	InitiatedBy string
	QueuedAt    int64
}

// RecordPendingRemoveFromRoom queues a remove-from-room request so
// the running server's processor can drain it and execute the leave
// cascade. Called from cmdRemoveFromRoom AFTER the CLI has validated
// the target exists.
//
// The initiatedBy field is "os:<uid>" for CLI invocations.
// The reason field is typically "removed" for admin kicks; the column
// accepts free-form strings for forward compatibility.
func (s *Store) RecordPendingRemoveFromRoom(userID, roomID, reason, initiatedBy string) error {
	_, err := s.dataDB.Exec(
		`INSERT INTO pending_remove_from_room (user_id, room_id, reason, initiated_by, queued_at) VALUES (?, ?, ?, ?, ?)`,
		userID, roomID, reason, initiatedBy, time.Now().Unix(),
	)
	return err
}

// ConsumePendingRemoveFromRooms reads every pending row, deletes
// them all atomically, and returns the consumed list. The caller
// (processPendingRemoveFromRoom) is then responsible for running
// performRoomLeave on each row.
//
// Atomic semantics: a transaction wraps the SELECT and DELETE so a
// concurrent invocation can't double-process. Same pattern as the
// other Phase 16 pending_* queues.
func (s *Store) ConsumePendingRemoveFromRooms() ([]PendingRemoveFromRoom, error) {
	tx, err := s.dataDB.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	rows, err := tx.Query(
		`SELECT id, user_id, room_id, reason, initiated_by, queued_at FROM pending_remove_from_room ORDER BY id`,
	)
	if err != nil {
		return nil, err
	}

	var pending []PendingRemoveFromRoom
	for rows.Next() {
		var p PendingRemoveFromRoom
		if err := rows.Scan(&p.ID, &p.UserID, &p.RoomID, &p.Reason, &p.InitiatedBy, &p.QueuedAt); err != nil {
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
		if _, err := tx.Exec(`DELETE FROM pending_remove_from_room`); err != nil {
			return nil, err
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return pending, nil
}
