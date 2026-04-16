package store

// Phase 16 Gap 1 — pending_admin_state_changes queue helpers.
//
// Shared queue for three CLI verbs that all need to propagate a
// fresh protocol.Profile broadcast to connected clients:
//
//   promote      → flips users.admin = 1
//   demote       → flips users.admin = 0
//   rename-user  → updates users.display_name
//
// The CLI side mutates users.db directly (via SetAdmin or
// SetUserDisplayName), then calls RecordPendingAdminStateChange to
// queue a row here. The server's processAdminStateChanges drains the
// queue, re-reads each user's current state from users.db, and
// broadcasts a fresh protocol.Profile event so every connected
// client's in-memory profile cache picks up the change without
// requiring a reconnect.
//
// Why one shared queue + one shared processor for three actions:
// they all produce the same wire effect (one Profile broadcast per
// affected user). The action field is only used for the audit log
// entry — the broadcast payload is uniformly built from the
// post-change user row. See store.go for the schema rationale.

import (
	"time"
)

// AdminStateChangeAction is the type of state change carried in a
// pending_admin_state_changes row. The schema enforces these via
// CHECK constraint, so any mismatch fails at INSERT time.
type AdminStateChangeAction string

const (
	AdminStateChangePromote AdminStateChangeAction = "promote"
	AdminStateChangeDemote  AdminStateChangeAction = "demote"
	AdminStateChangeRename  AdminStateChangeAction = "rename"
)

// PendingAdminStateChange is one row from the pending_admin_state_changes
// queue.
type PendingAdminStateChange struct {
	ID        int64
	UserID    string
	Action    AdminStateChangeAction
	ChangedBy string
	QueuedAt  int64
}

// RecordPendingAdminStateChange queues an admin state change so the
// running server can broadcast a fresh profile event to connected
// clients. Called from cmdPromote / cmdDemote / cmdRenameUser AFTER
// the CLI has already mutated users.db (via SetAdmin or
// SetUserDisplayName).
//
// The changedBy field is "os:<uid>" for CLI invocations.
func (s *Store) RecordPendingAdminStateChange(userID string, action AdminStateChangeAction, changedBy string) error {
	_, err := s.dataDB.Exec(
		`INSERT INTO pending_admin_state_changes (user_id, action, changed_by, queued_at) VALUES (?, ?, ?, ?)`,
		userID, string(action), changedBy, time.Now().Unix(),
	)
	return err
}

// ConsumePendingAdminStateChanges reads every pending state change
// row, deletes them all atomically, and returns the consumed list.
// The caller (processAdminStateChanges) is then responsible for
// broadcasting the corresponding protocol.Profile events.
//
// Atomic semantics: a transaction wraps the SELECT and DELETE so a
// concurrent invocation can't double-process. Same pattern as the
// other Phase 16 Gap 1 queues.
func (s *Store) ConsumePendingAdminStateChanges() ([]PendingAdminStateChange, error) {
	tx, err := s.dataDB.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	rows, err := tx.Query(
		`SELECT id, user_id, action, changed_by, queued_at FROM pending_admin_state_changes ORDER BY id`,
	)
	if err != nil {
		return nil, err
	}

	var pending []PendingAdminStateChange
	for rows.Next() {
		var p PendingAdminStateChange
		var action string
		if err := rows.Scan(&p.ID, &p.UserID, &action, &p.ChangedBy, &p.QueuedAt); err != nil {
			rows.Close()
			return nil, err
		}
		p.Action = AdminStateChangeAction(action)
		pending = append(pending, p)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	if len(pending) > 0 {
		if _, err := tx.Exec(`DELETE FROM pending_admin_state_changes`); err != nil {
			return nil, err
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return pending, nil
}
