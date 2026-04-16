package store

// Phase 16 Gap 1 — pending_user_retirements queue helpers.
//
// User-level analog of pending_room_retirements (room_deletion.go).
// Same architecture, same atomic SELECT+DELETE pattern, same purpose:
// bridge the CLI's direct DB mutation with the running server's live
// broadcast surface.
//
// The CLI runs sshkey-ctl retire-user, which:
//   1. Calls SetUserRetired on users.db (so retirement takes effect
//      at the data layer immediately, regardless of server state)
//   2. Calls RecordPendingUserRetirement to enqueue a row here
//
// The server's runUserRetirementProcessor goroutine polls
// ConsumePendingUserRetirements on a periodic ticker, and for each row
// it calls handleRetirement which fires per-room leaves, group exits,
// DM cutoffs, the user_retired broadcast, and active session
// termination. See internal/server/user_retirements.go for the
// processor side.

import (
	"time"
)

// PendingUserRetirement is one row from the pending_user_retirements
// queue — an admin-triggered user retirement that the CLI has staged
// for the running server to broadcast. Returned by
// ConsumePendingUserRetirements.
type PendingUserRetirement struct {
	ID        int64
	UserID    string
	RetiredBy string
	Reason    string
	QueuedAt  int64
}

// RecordPendingUserRetirement queues an admin-triggered user
// retirement so the running server can fire all the downstream
// handleRetirement work (per-room leaves, group exits, DM cutoffs,
// user_retired broadcast, active session termination).
//
// Called from the CLI's retire-user command AFTER the CLI has already
// mutated the users table directly via SetUserRetired. The queue
// exists purely for live broadcast delivery; the retirement itself
// takes effect at the data layer regardless of whether the server
// processes the queue row.
//
// The retiredBy field is "os:<uid>" for CLI invocations (matching the
// audit log format) so processor-side audit entries identify the OS
// user who ran sshkey-ctl. Mirrors RecordPendingRoomRetirement.
func (s *Store) RecordPendingUserRetirement(userID, retiredBy, reason string) error {
	_, err := s.dataDB.Exec(
		`INSERT INTO pending_user_retirements (user_id, retired_by, reason, queued_at) VALUES (?, ?, ?, ?)`,
		userID, retiredBy, reason, time.Now().Unix(),
	)
	return err
}

// ConsumePendingUserRetirements reads every pending user retirement
// row, deletes them all atomically, and returns the consumed list to
// the caller. The caller (runUserRetirementProcessor) is then
// responsible for performing the handleRetirement cascade for each
// row.
//
// Atomic semantics: a transaction wraps the SELECT and DELETE so a
// concurrent invocation can't double-process a retirement. The
// transaction is short-lived (typically zero or a handful of rows) so
// contention is negligible. Mirrors ConsumePendingRoomRetirements.
func (s *Store) ConsumePendingUserRetirements() ([]PendingUserRetirement, error) {
	tx, err := s.dataDB.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	rows, err := tx.Query(
		`SELECT id, user_id, retired_by, reason, queued_at FROM pending_user_retirements ORDER BY id`,
	)
	if err != nil {
		return nil, err
	}

	var pending []PendingUserRetirement
	for rows.Next() {
		var p PendingUserRetirement
		if err := rows.Scan(&p.ID, &p.UserID, &p.RetiredBy, &p.Reason, &p.QueuedAt); err != nil {
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
		if _, err := tx.Exec(`DELETE FROM pending_user_retirements`); err != nil {
			return nil, err
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return pending, nil
}
