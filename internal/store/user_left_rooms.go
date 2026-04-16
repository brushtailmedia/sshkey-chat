package store

// Phase 16 Gap 1 — user_left_rooms helpers.
//
// Dual-purpose table: Phase 16's CLI remove-from-room queue AND the
// foundation for Phase 20's server-authoritative leave catchup.
//
// Phase 16 only uses the queue side (write 'removed' rows from the
// CLI, drain unprocessed rows from the server processor). Phase 20
// will:
//   1. Add catchup-read methods that filter by user_id + left_at
//   2. Extend the writers so self-leave, retirement cascade, etc.
//      all record rows here (currently only the CLI path writes)
//   3. Replace the client-side reconciliation walk with the
//      server-pushed catchup list on handshake
//
// See store.go for the schema rationale and Phase 16/20 interaction
// notes.

import (
	"time"
)

// UserLeftRoom is one row from the user_left_rooms table — a
// historical record that a user has left or been removed from a
// room. Phase 16 only consumes unprocessed rows; Phase 20 will add
// catchup-time queries that return all rows since a given timestamp.
type UserLeftRoom struct {
	ID          int64
	UserID      string
	RoomID      string
	Reason      string // 'removed' (Phase 16) | future Phase 20 values
	InitiatedBy string // 'os:<uid>' for CLI, user_id for self-leave, 'system' for cascade
	LeftAt      int64
	Processed   bool
}

// RecordUserLeftRoom inserts a leave record. Phase 16 Gap 1 calls
// this from cmdRemoveFromRoom with reason='removed' and initiatedBy
// set to 'os:<uid>'. Phase 20 will add additional callers from
// self-leave, retirement cascade, etc.
//
// processed defaults to 0 (false) — the row will be picked up by
// the next runRemoveFromRoomProcessor tick.
//
// Returns the new row's ID for callers that want to track it.
func (s *Store) RecordUserLeftRoom(userID, roomID, reason, initiatedBy string) (int64, error) {
	res, err := s.dataDB.Exec(
		`INSERT INTO user_left_rooms (user_id, room_id, reason, initiated_by, left_at, processed) VALUES (?, ?, ?, ?, ?, 0)`,
		userID, roomID, reason, initiatedBy, time.Now().Unix(),
	)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// ConsumePendingUserLeftRooms reads every unprocessed row, marks
// them all as processed=1 atomically, and returns the consumed list.
// The caller (runRemoveFromRoomProcessor) is then responsible for
// running the leave cascade for each row.
//
// Mark-processed semantics (rather than DELETE like the other
// Phase 16 Gap 1 queues): rows are kept after processing so Phase 20
// can read them as a leave-history catchup signal. The processed
// flag is the boundary between "queue work" and "history archive."
//
// Atomic semantics: a transaction wraps the SELECT and UPDATE so a
// concurrent invocation can't double-process. Rows are returned in
// insertion order (FIFO).
func (s *Store) ConsumePendingUserLeftRooms() ([]UserLeftRoom, error) {
	tx, err := s.dataDB.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	rows, err := tx.Query(
		`SELECT id, user_id, room_id, reason, initiated_by, left_at FROM user_left_rooms WHERE processed = 0 ORDER BY id`,
	)
	if err != nil {
		return nil, err
	}

	var pending []UserLeftRoom
	for rows.Next() {
		var p UserLeftRoom
		if err := rows.Scan(&p.ID, &p.UserID, &p.RoomID, &p.Reason, &p.InitiatedBy, &p.LeftAt); err != nil {
			rows.Close()
			return nil, err
		}
		p.Processed = false // explicit — we're about to flip it
		pending = append(pending, p)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	if len(pending) > 0 {
		if _, err := tx.Exec(`UPDATE user_left_rooms SET processed = 1 WHERE processed = 0`); err != nil {
			return nil, err
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}

	// Reflect the post-update state in the returned values so callers
	// don't get a misleading Processed=false on rows we just flipped.
	for i := range pending {
		pending[i].Processed = true
	}
	return pending, nil
}
