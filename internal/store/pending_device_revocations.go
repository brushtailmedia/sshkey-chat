package store

// Phase 16 Gap 1 — pending_device_revocations queue helpers.
//
// Standalone queue for `sshkey-ctl revoke-device`. The CLI marks the
// device as revoked via RevokeDevice (which writes to
// revoked_devices, blocking future authentication attempts) and then
// enqueues a row here. The server's runDeviceRevocationProcessor
// goroutine drains the queue and, for each row, looks up any active
// SSH session matching (user, device_id) and terminates it via
// kickRevokedDeviceSession.
//
// Different shape from the other Phase 16 Gap 1 queues: this one
// operates on live session state (open SSH channels) rather than on
// persisted protocol state (broadcasts). The data-layer effect of
// revocation is already done by the CLI before enqueue; the
// processor's only job is to forcibly close any matching open
// session so the revoked device can't keep using its current
// connection until it next reconnects.

import (
	"time"
)

// PendingDeviceRevocation is one row from the pending_device_revocations
// queue.
type PendingDeviceRevocation struct {
	ID        int64
	UserID    string
	DeviceID  string
	Reason    string
	RevokedBy string
	QueuedAt  int64
}

// RecordPendingDeviceRevocation queues an admin-triggered device
// revocation so the running server can terminate any active session
// for the (user, device) pair. Called from cmdRevokeDevice AFTER the
// CLI has already written to revoked_devices via RevokeDevice.
//
// The revokedBy field is "os:<uid>" for CLI invocations (matching
// the audit log format).
func (s *Store) RecordPendingDeviceRevocation(userID, deviceID, reason, revokedBy string) error {
	if reason == "" {
		reason = "admin_action"
	}
	_, err := s.dataDB.Exec(
		`INSERT INTO pending_device_revocations (user_id, device_id, reason, revoked_by, queued_at) VALUES (?, ?, ?, ?, ?)`,
		userID, deviceID, reason, revokedBy, time.Now().Unix(),
	)
	return err
}

// ConsumePendingDeviceRevocations reads every pending revocation row,
// deletes them all atomically, and returns the consumed list. The
// caller (processPendingDeviceRevocations) is responsible for
// terminating any matching active sessions.
//
// Atomic semantics: a transaction wraps SELECT + DELETE so a
// concurrent invocation can't double-process. Same pattern as the
// other Phase 16 Gap 1 queues.
func (s *Store) ConsumePendingDeviceRevocations() ([]PendingDeviceRevocation, error) {
	tx, err := s.dataDB.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	rows, err := tx.Query(
		`SELECT id, user_id, device_id, reason, revoked_by, queued_at FROM pending_device_revocations ORDER BY id`,
	)
	if err != nil {
		return nil, err
	}

	var pending []PendingDeviceRevocation
	for rows.Next() {
		var p PendingDeviceRevocation
		if err := rows.Scan(&p.ID, &p.UserID, &p.DeviceID, &p.Reason, &p.RevokedBy, &p.QueuedAt); err != nil {
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
		if _, err := tx.Exec(`DELETE FROM pending_device_revocations`); err != nil {
			return nil, err
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return pending, nil
}
