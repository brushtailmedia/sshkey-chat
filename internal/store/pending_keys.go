package store

import (
	"database/sql"
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
// heals pre-existing NULL dev/test rows on the next attempt).
func (s *Store) RecordPendingKey(fingerprint, remoteAddr, pubkey string) (firstSeen string, isFirstAttempt bool, err error) {
	var attempts int
	err = s.dataDB.QueryRow(`
		INSERT INTO pending_keys (fingerprint, remote_addr, pubkey)
		VALUES (?, ?, ?)
		ON CONFLICT (fingerprint) DO UPDATE SET
			attempts    = attempts + 1,
			last_seen   = datetime('now'),
			remote_addr = excluded.remote_addr,
			pubkey      = COALESCE(pending_keys.pubkey, excluded.pubkey)
		RETURNING attempts, first_seen`,
		fingerprint, remoteAddr, pubkey,
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
		       first_seen, last_seen, COALESCE(pubkey, '')
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
			&pk.FirstSeen, &pk.LastSeen, &pk.PubKey); err != nil {
			return nil, err
		}
		out = append(out, pk)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
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
