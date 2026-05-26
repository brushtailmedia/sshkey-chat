package store

import (
	"database/sql"
	"errors"
	"fmt"
)

// PendingKey is one unknown-key contact recorded for operator triage. It is the
// DB-authoritative record behind `sshkey-ctl pending` (the flat
// pending-keys.log projection was removed once this table carried the pubkey).
type PendingKey struct {
	Fingerprint string
	RemoteAddr  string
	Attempts    int
	FirstSeen   string
	LastSeen    string
	// PubKey is the trimmed authorized-key string ("ssh-ed25519 AAAA...") the
	// server captured at first contact. May be empty on legacy rows recorded
	// before the pubkey column existed.
	PubKey string
	// RequestedUsername is the sanitized display-name hint derived from the SSH
	// username (conn.User()) at the unknown-key handshake. Empty when the client
	// sent none or it failed SanitizeRequestedNameHint; latest *non-empty* wins
	// across reconnects (DP4). Untrusted — re-gated by ValidateDisplayName
	// before it can become a real display name.
	RequestedUsername string
}

// ensurePendingKeysSchema adds columns introduced after initial launch so that
// older local/dev DBs stay usable (mirrors ensureDirectMessageSchema). The
// pubkey column holds the authorized-key string so `sshkey-ctl pending` can
// surface it for `approve --key` without a separate flat-log projection.
func (s *Store) ensurePendingKeysSchema() error {
	if !columnExists(s.dataDB, "pending_keys", "pubkey") {
		if _, err := s.dataDB.Exec(`ALTER TABLE pending_keys ADD COLUMN pubkey TEXT`); err != nil {
			return fmt.Errorf("migrate pending_keys.pubkey: %w", err)
		}
	}
	if !columnExists(s.dataDB, "pending_keys", "requested_username") {
		if _, err := s.dataDB.Exec(`ALTER TABLE pending_keys ADD COLUMN requested_username TEXT`); err != nil {
			return fmt.Errorf("migrate pending_keys.requested_username: %w", err)
		}
	}
	return nil
}

// columnExists reports whether table has a column named col. SQLite's PRAGMA
// cannot bind an identifier, so the table name is interpolated directly:
// callers MUST pass an internal, constant table name — never user input.
func columnExists(db *sql.DB, table, col string) bool {
	rows, err := db.Query(fmt.Sprintf(`PRAGMA table_info(%s)`, table))
	if err != nil {
		return false
	}
	defer rows.Close()
	for rows.Next() {
		var cid int
		var name, ctype string
		var notNull, pk int
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &ctype, &notNull, &dflt, &pk); err != nil {
			return false
		}
		if name == col {
			return true
		}
	}
	return false
}

// RecordPendingKey upserts an unknown-key contact and returns the row's
// first_seen plus whether this was the first attempt. It runs as a single
// INSERT ... ON CONFLICT DO UPDATE ... RETURNING statement: attempts defaults
// to 1 on insert and increments on conflict, so isFirstAttempt is simply
// (attempts == 1) — no separate pre-SELECT. pubkey is written on first insert
// and backfilled only when the stored value is NULL (set-once for real rows;
// heals pre-existing NULL dev/test rows on the next attempt). requestedUser is
// the sanitized display-name hint, stored via NULLIF so an empty hint becomes
// NULL; the UPDATE keeps the latest *non-empty* hint (DP4) so an empty/rejected
// reconnect never clobbers a previously captured name.
func (s *Store) RecordPendingKey(fingerprint, remoteAddr, pubkey, requestedUser string) (firstSeen string, isFirstAttempt bool, err error) {
	var attempts int
	err = s.dataDB.QueryRow(`
		INSERT INTO pending_keys (fingerprint, remote_addr, pubkey, requested_username)
		VALUES (?, ?, ?, NULLIF(?, ''))
		ON CONFLICT (fingerprint) DO UPDATE SET
			attempts           = attempts + 1,
			last_seen          = datetime('now'),
			remote_addr        = excluded.remote_addr,
			pubkey             = COALESCE(pending_keys.pubkey, excluded.pubkey),
			requested_username = COALESCE(excluded.requested_username, pending_keys.requested_username)
		RETURNING attempts, first_seen`,
		fingerprint, remoteAddr, pubkey, requestedUser,
	).Scan(&attempts, &firstSeen)
	if err != nil {
		return "", false, fmt.Errorf("record pending key: %w", err)
	}
	return firstSeen, attempts == 1, nil
}

// ListPendingKeys returns every pending-key contact, most recent activity
// first. NULL pubkey/remote_addr rows are returned with empty strings.
func (s *Store) ListPendingKeys() ([]PendingKey, error) {
	rows, err := s.dataDB.Query(`
		SELECT fingerprint, COALESCE(remote_addr, ''), attempts,
		       first_seen, last_seen, COALESCE(pubkey, ''),
		       COALESCE(requested_username, '')
		FROM pending_keys
		ORDER BY last_seen DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []PendingKey
	for rows.Next() {
		var pk PendingKey
		if err := rows.Scan(&pk.Fingerprint, &pk.RemoteAddr, &pk.Attempts,
			&pk.FirstSeen, &pk.LastSeen, &pk.PubKey, &pk.RequestedUsername); err != nil {
			return nil, err
		}
		out = append(out, pk)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// GetPendingKeyByFingerprint returns the pending-key row for a fingerprint and
// whether it exists. Used by `approve` (DP5) to prefill the requested_username
// hint as a display-name candidate.
func (s *Store) GetPendingKeyByFingerprint(fingerprint string) (PendingKey, bool, error) {
	var pk PendingKey
	err := s.dataDB.QueryRow(`
		SELECT fingerprint, COALESCE(remote_addr, ''), attempts, first_seen,
		       last_seen, COALESCE(pubkey, ''), COALESCE(requested_username, '')
		FROM pending_keys WHERE fingerprint = ?`, fingerprint,
	).Scan(&pk.Fingerprint, &pk.RemoteAddr, &pk.Attempts, &pk.FirstSeen,
		&pk.LastSeen, &pk.PubKey, &pk.RequestedUsername)
	if errors.Is(err, sql.ErrNoRows) {
		return PendingKey{}, false, nil
	}
	if err != nil {
		return PendingKey{}, false, err
	}
	return pk, true, nil
}

// DeletePendingKey removes a single pending-key row. It is not an error if the
// fingerprint is absent (approve/purge/reject all call this idempotently).
func (s *Store) DeletePendingKey(fingerprint string) error {
	_, err := s.dataDB.Exec(`DELETE FROM pending_keys WHERE fingerprint = ?`, fingerprint)
	return err
}

// ClearPendingKeys deletes all pending-key rows and returns how many existed.
func (s *Store) ClearPendingKeys() (int, error) {
	n, err := s.CountPendingKeys()
	if err != nil {
		return 0, err
	}
	if _, err := s.dataDB.Exec(`DELETE FROM pending_keys`); err != nil {
		return 0, err
	}
	return n, nil
}

// CountPendingKeys returns the number of pending-key rows.
func (s *Store) CountPendingKeys() (int, error) {
	var n int
	err := s.dataDB.QueryRow(`SELECT COUNT(*) FROM pending_keys`).Scan(&n)
	return n, err
}

// PruneOldPendingKeys deletes pending-key rows whose first_seen is older than
// maxAgeSeconds, returning how many were removed. It ages out by first_seen
// (first contact), NOT last_seen, so a key that keeps reconnecting (each
// reconnect bumps last_seen via the UPSERT) cannot keep its row alive past the
// TTL. The cutoff is computed in SQLite's own UTC datetime space and compared
// as a TEXT datetime string, matching the datetime('now')-formatted first_seen
// column — do NOT compare these TEXT timestamps against Unix seconds (the
// pending_keys schema stores TEXT, unlike e.g. deleted_rooms.deleted_at which
// is an INTEGER unix time). Storm-hardening companion to EnforcePendingKeyCap.
func (s *Store) PruneOldPendingKeys(maxAgeSeconds int64) (int, error) {
	res, err := s.dataDB.Exec(
		`DELETE FROM pending_keys WHERE first_seen < datetime('now', ?)`,
		fmt.Sprintf("-%d seconds", maxAgeSeconds),
	)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// EnforcePendingKeyCap evicts the oldest rows when pending_keys exceeds
// maxRows, returning how many were removed. "Oldest" is least-recently-active:
// ORDER BY last_seen ASC, first_seen ASC, rowid ASC, fingerprint ASC — rowid is
// the insertion-order tie-breaker for the many storm rows that share a
// second-resolution datetime('now') timestamp. Uses the portable
// `rowid IN (SELECT ... LIMIT ?)` deletion shape rather than
// `DELETE ... ORDER BY ... LIMIT` (which depends on the optional
// SQLITE_ENABLE_UPDATE_DELETE_LIMIT build flag). The hard cap bounds storage
// independent of the TTL — a distributed storm can fill the table inside the
// TTL window. Callers should enforce the cap AFTER recording the current key,
// so a fresh first-contact never leaves the table at maxRows+1.
func (s *Store) EnforcePendingKeyCap(maxRows int) (int, error) {
	count, err := s.CountPendingKeys()
	if err != nil {
		return 0, err
	}
	excess := count - maxRows
	if excess <= 0 {
		return 0, nil
	}
	res, err := s.dataDB.Exec(
		`DELETE FROM pending_keys WHERE rowid IN (
			SELECT rowid FROM pending_keys
			ORDER BY last_seen ASC, first_seen ASC, rowid ASC, fingerprint ASC
			LIMIT ?
		)`,
		excess,
	)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}
