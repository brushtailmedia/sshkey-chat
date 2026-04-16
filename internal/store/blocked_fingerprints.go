package store

// Phase 16 — blocked_fingerprints helpers.
//
// Pre-approval defense against fingerprint spam. The CLI blocks a
// fingerprint, and the server's SSH handshake checks this table
// before writing to pending_keys. Blocked fingerprints are rejected
// at the SSH layer with a generic "access denied" (no distinguishing
// message to avoid enumeration — blocked keys and bad authentication
// look identical to the client).
//
// Different from revoked_devices (which blocks already-approved
// users' specific devices) and from reject (which clears a single
// pending key from the queue). This is a preemptive blocklist.

import "time"

// BlockedFingerprint is one row from the blocked_fingerprints table.
type BlockedFingerprint struct {
	Fingerprint string
	Reason      string
	BlockedAt   int64
	BlockedBy   string
}

// BlockFingerprint adds a fingerprint to the block list. Idempotent:
// INSERT OR IGNORE so re-blocking is a no-op.
func (s *Store) BlockFingerprint(fingerprint, reason, blockedBy string) error {
	_, err := s.dataDB.Exec(
		`INSERT OR IGNORE INTO blocked_fingerprints (fingerprint, reason, blocked_at, blocked_by) VALUES (?, ?, ?, ?)`,
		fingerprint, reason, time.Now().Unix(), blockedBy,
	)
	return err
}

// UnblockFingerprint removes a fingerprint from the block list.
// No-op if the fingerprint isn't blocked.
func (s *Store) UnblockFingerprint(fingerprint string) error {
	_, err := s.dataDB.Exec(`DELETE FROM blocked_fingerprints WHERE fingerprint = ?`, fingerprint)
	return err
}

// IsFingerPrintBlocked returns true if the fingerprint is in the
// block list. Called from the SSH handshake before writing to
// pending_keys.
func (s *Store) IsFingerprintBlocked(fingerprint string) bool {
	var count int
	s.dataDB.QueryRow(`SELECT COUNT(*) FROM blocked_fingerprints WHERE fingerprint = ?`, fingerprint).Scan(&count)
	return count > 0
}

// GetBlockedFingerprints returns all blocked fingerprints.
func (s *Store) GetBlockedFingerprints() ([]BlockedFingerprint, error) {
	rows, err := s.dataDB.Query(
		`SELECT fingerprint, reason, blocked_at, blocked_by FROM blocked_fingerprints ORDER BY blocked_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []BlockedFingerprint
	for rows.Next() {
		var b BlockedFingerprint
		if err := rows.Scan(&b.Fingerprint, &b.Reason, &b.BlockedAt, &b.BlockedBy); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}
