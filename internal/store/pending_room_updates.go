package store

// Phase 16 Gap 1 — pending_room_updates queue helpers.
//
// Shared queue for two CLI verbs that modify room properties:
//
//   update-topic  → updates rooms.topic
//   rename-room   → updates rooms.display_name
//
// The CLI side mutates rooms.db directly (via SetRoomTopic or
// SetRoomDisplayName), then calls RecordPendingRoomUpdate to queue a
// row here. The server's processPendingRoomUpdates drains the queue,
// re-reads each room's current state from rooms.db, and broadcasts a
// fresh room_updated event to connected members of the affected room.
//
// Why one shared queue + one shared processor for two actions: same
// reasoning as pending_admin_state_changes. Both produce one
// room_updated broadcast carrying the full post-change room state
// {Room, DisplayName, Topic} — the action enum is only used for the
// audit log entry. See store.go for the schema rationale.

import (
	"time"
)

// RoomUpdateAction is the type of state change carried in a
// pending_room_updates row.
type RoomUpdateAction string

const (
	RoomUpdateActionUpdateTopic RoomUpdateAction = "update-topic"
	RoomUpdateActionRenameRoom  RoomUpdateAction = "rename-room"
)

// PendingRoomUpdate is one row from the pending_room_updates queue.
type PendingRoomUpdate struct {
	ID        int64
	RoomID    string
	Action    RoomUpdateAction
	ChangedBy string
	QueuedAt  int64
}

// RecordPendingRoomUpdate queues a room update so the running server
// can broadcast a fresh room_updated event to connected members.
// Called from cmdUpdateTopic / cmdRenameRoom AFTER the CLI has
// already mutated rooms.db.
//
// The changedBy field is "os:<uid>" for CLI invocations.
func (s *Store) RecordPendingRoomUpdate(roomID string, action RoomUpdateAction, changedBy string) error {
	_, err := s.dataDB.Exec(
		`INSERT INTO pending_room_updates (room_id, action, changed_by, queued_at) VALUES (?, ?, ?, ?)`,
		roomID, string(action), changedBy, time.Now().Unix(),
	)
	return err
}

// ConsumePendingRoomUpdates reads every pending room update row,
// deletes them all atomically, and returns the consumed list. The
// caller (processPendingRoomUpdates) is responsible for broadcasting
// the corresponding room_updated events.
//
// Atomic semantics: a transaction wraps SELECT and DELETE so a
// concurrent invocation can't double-process. Same pattern as the
// other Phase 16 Gap 1 queues.
func (s *Store) ConsumePendingRoomUpdates() ([]PendingRoomUpdate, error) {
	tx, err := s.dataDB.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	rows, err := tx.Query(
		`SELECT id, room_id, action, changed_by, queued_at FROM pending_room_updates ORDER BY id`,
	)
	if err != nil {
		return nil, err
	}

	var pending []PendingRoomUpdate
	for rows.Next() {
		var p PendingRoomUpdate
		var action string
		if err := rows.Scan(&p.ID, &p.RoomID, &action, &p.ChangedBy, &p.QueuedAt); err != nil {
			rows.Close()
			return nil, err
		}
		p.Action = RoomUpdateAction(action)
		pending = append(pending, p)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	if len(pending) > 0 {
		if _, err := tx.Exec(`DELETE FROM pending_room_updates`); err != nil {
			return nil, err
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return pending, nil
}
