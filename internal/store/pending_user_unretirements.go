package store

// Phase 16 Gap 1 — pending_user_unretirements queue helpers.
//
// Inverse of pending_user_retirements (pending_user_retirements.go).
// The CLI runs sshkey-ctl unretire-user, which:
//   1. Calls SetUserUnretired on users.db (so unretirement takes
//      effect at the data layer immediately, regardless of server
//      state — flips retired=0, clears retired_at/retired_reason,
//      strips the retirement display-name suffix)
//   2. Calls RecordPendingUserUnretirement to enqueue a row here
//
// The server's runUserUnretirementProcessor goroutine polls
// ConsumePendingUserUnretirements on a periodic ticker, and for each
// row it broadcasts a user_unretired event to all connected clients
// so they can flush the [retired] marker from their profile cache.
// See internal/server/user_unretirements.go for the processor side.
//
// Note: unretirement does NOT restore room/group/DM memberships. The
// retirement cascade in handleRetirement removed the user from every
// shared context; the unretire processor only fires the broadcast so
// connected clients clear their cached retired state. Operators must
// manually re-add the user to rooms/groups via the existing CLI
// verbs.

import (
	"time"
)

// PendingUserUnretirement is one row from the pending_user_unretirements
// queue — an admin-triggered user unretirement that the CLI has staged
// for the running server to broadcast.
type PendingUserUnretirement struct {
	ID          int64
	UserID      string
	UnretiredBy string
	QueuedAt    int64
}

// RecordPendingUserUnretirement queues an admin-triggered user
// unretirement so the running server can broadcast user_unretired to
// connected clients. Called from the CLI's unretire-user command
// AFTER SetUserUnretired has already flipped the data-layer state.
//
// The unretiredBy field is "os:<uid>" for CLI invocations (matching
// the audit log format) so processor-side audit entries identify the
// OS user who ran sshkey-ctl. There is no "reason" field on the
// unretirement queue — unretirement is a singular escape-hatch
// action with no nuanced reasons (unlike retirement which has
// admin / key_lost / self_compromise / switching_key).
func (s *Store) RecordPendingUserUnretirement(userID, unretiredBy string) error {
	_, err := s.dataDB.Exec(
		`INSERT INTO pending_user_unretirements (user_id, unretired_by, queued_at) VALUES (?, ?, ?)`,
		userID, unretiredBy, time.Now().Unix(),
	)
	return err
}

// ConsumePendingUserUnretirements reads every pending unretirement
// row, deletes them all atomically, and returns the consumed list to
// the caller. The caller (runUserUnretirementProcessor) is then
// responsible for performing the user_unretired broadcasts.
//
// Atomic semantics: a transaction wraps the SELECT and DELETE so a
// concurrent invocation can't double-process. Mirrors
// ConsumePendingUserRetirements.
func (s *Store) ConsumePendingUserUnretirements() ([]PendingUserUnretirement, error) {
	tx, err := s.dataDB.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	rows, err := tx.Query(
		`SELECT id, user_id, unretired_by, queued_at FROM pending_user_unretirements ORDER BY id`,
	)
	if err != nil {
		return nil, err
	}

	var pending []PendingUserUnretirement
	for rows.Next() {
		var p PendingUserUnretirement
		if err := rows.Scan(&p.ID, &p.UserID, &p.UnretiredBy, &p.QueuedAt); err != nil {
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
		if _, err := tx.Exec(`DELETE FROM pending_user_unretirements`); err != nil {
			return nil, err
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return pending, nil
}
