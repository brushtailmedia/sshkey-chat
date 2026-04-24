package store

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// DirectMessage represents a 1:1 DM row in data.db. The two users are
// stored in alphabetical order (user_a < user_b) so the UNIQUE constraint
// enforces dedup without a secondary lookup.
type DirectMessage struct {
	ID          string
	UserA       string
	UserB       string
	CreatedAt   int64
	UserALeftAt int64
	UserBLeftAt int64
}

// CutoffFor returns the left_at timestamp for the given user, or 0 if the
// user is not on this DM row. Used to filter messages on read.
func (dm *DirectMessage) CutoffFor(userID string) int64 {
	switch userID {
	case dm.UserA:
		return dm.UserALeftAt
	case dm.UserB:
		return dm.UserBLeftAt
	}
	return 0
}

// OtherUser returns the user that is NOT userID, or "" if userID is not on
// the DM row.
func (dm *DirectMessage) OtherUser(userID string) string {
	switch userID {
	case dm.UserA:
		return dm.UserB
	case dm.UserB:
		return dm.UserA
	}
	return ""
}

// canonicalPair returns (a, b) with a < b lexicographically.
func canonicalPair(u1, u2 string) (string, string) {
	pair := []string{u1, u2}
	sort.Strings(pair)
	return pair[0], pair[1]
}

// CreateOrGetDirectMessage creates a new 1:1 DM between two users, or
// returns the existing one if the pair already has a row. Dedup is
// enforced by the UNIQUE(user_a, user_b) constraint on the canonical
// (alphabetically sorted) pair.
func (s *Store) CreateOrGetDirectMessage(id, userA, userB string) (*DirectMessage, error) {
	a, b := canonicalPair(userA, userB)
	now := time.Now().Unix()

	// Try INSERT first — most calls are creates for new pairs.
	_, err := s.dataDB.Exec(
		`INSERT OR IGNORE INTO direct_messages (id, user_a, user_b, created_at) VALUES (?, ?, ?, ?)`,
		id, a, b, now,
	)
	if err != nil {
		return nil, fmt.Errorf("create DM: %w", err)
	}

	// Always SELECT to return the canonical row (may be the one we just
	// inserted, or a pre-existing row for this pair).
	var dm DirectMessage
	err = s.dataDB.QueryRow(
		`SELECT id, user_a, user_b, created_at, user_a_left_at, user_b_left_at
		 FROM direct_messages WHERE user_a = ? AND user_b = ?`,
		a, b,
	).Scan(&dm.ID, &dm.UserA, &dm.UserB, &dm.CreatedAt, &dm.UserALeftAt, &dm.UserBLeftAt)
	if err != nil {
		return nil, fmt.Errorf("get DM: %w", err)
	}
	return &dm, nil
}

// GetDirectMessage retrieves a DM by its ID.
func (s *Store) GetDirectMessage(dmID string) (*DirectMessage, error) {
	var dm DirectMessage
	err := s.dataDB.QueryRow(
		`SELECT id, user_a, user_b, created_at, user_a_left_at, user_b_left_at
		 FROM direct_messages WHERE id = ?`,
		dmID,
	).Scan(&dm.ID, &dm.UserA, &dm.UserB, &dm.CreatedAt, &dm.UserALeftAt, &dm.UserBLeftAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &dm, nil
}

// GetDirectMessagesForUser returns every DM the user is a party to.
func (s *Store) GetDirectMessagesForUser(userID string) ([]*DirectMessage, error) {
	rows, err := s.dataDB.Query(
		`SELECT id, user_a, user_b, created_at, user_a_left_at, user_b_left_at
		 FROM direct_messages WHERE user_a = ? OR user_b = ?
		 ORDER BY id`,
		userID, userID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var dms []*DirectMessage
	for rows.Next() {
		var dm DirectMessage
		if err := rows.Scan(&dm.ID, &dm.UserA, &dm.UserB, &dm.CreatedAt, &dm.UserALeftAt, &dm.UserBLeftAt); err != nil {
			return nil, err
		}
		dms = append(dms, &dm)
	}
	return dms, rows.Err()
}

// SetDMLeftAt sets the per-user history cutoff for one party in a 1:1 DM.
// This is a one-way ratchet: if the user already has a non-zero left_at
// that is >= the new value, the write is silently skipped. If the user is
// not a party to the DM, returns an error.
//
// After this call, GetDMMessagesForUser will filter out messages with ts
// <= leftAt for the affected user. The other party is not affected.
func (s *Store) SetDMLeftAt(dmID, userID string, leftAt int64) error {
	dm, err := s.GetDirectMessage(dmID)
	if err != nil {
		return err
	}
	if dm == nil {
		return fmt.Errorf("DM %q does not exist", dmID)
	}

	var col string
	switch userID {
	case dm.UserA:
		col = "user_a_left_at"
	case dm.UserB:
		col = "user_b_left_at"
	default:
		return fmt.Errorf("user %q is not a party to DM %q", userID, dmID)
	}

	// One-way ratchet: only advance, never retreat.
	_, err = s.dataDB.Exec(
		fmt.Sprintf(`UPDATE direct_messages SET %s = ? WHERE id = ? AND %s < ?`, col, col),
		leftAt, dmID, leftAt,
	)
	return err
}

// InsertDMMessage stores a 1:1 DM message.
func (s *Store) InsertDMMessage(dmID string, msg StoredMessage) error {
	db, err := s.DMDB(dmID)
	if err != nil {
		return err
	}
	return insertMessage(db, msg)
}

// GetDMMessagesSince retrieves messages from a 1:1 DM with ts >= sinceTS,
// filtered by the caller's per-user cutoff. Used by sync.
func (s *Store) GetDMMessagesSince(dmID, userID string, sinceTS int64, limit int) ([]StoredMessage, error) {
	dm, err := s.GetDirectMessage(dmID)
	if err != nil || dm == nil {
		return nil, err
	}
	cutoff := dm.CutoffFor(userID)
	if cutoff > sinceTS {
		sinceTS = cutoff
	}
	db, err := s.DMDB(dmID)
	if err != nil {
		return nil, err
	}
	return getMessagesSince(db, sinceTS, limit)
}

// GetDMMessagesBeforeForUser retrieves messages from a 1:1 DM before a
// specific message ID, filtered by the caller's per-user cutoff. Used by
// history (scroll-back).
func (s *Store) GetDMMessagesBeforeForUser(dmID, userID, beforeID string, limit int) ([]StoredMessage, error) {
	dm, err := s.GetDirectMessage(dmID)
	if err != nil || dm == nil {
		return nil, err
	}
	cutoff := dm.CutoffFor(userID)
	db, err := s.DMDB(dmID)
	if err != nil {
		return nil, err
	}

	// If the user has a cutoff, we need to filter out messages at or before it.
	// getMessagesBefore already filters by rowid < beforeID's rowid; we add the
	// cutoff as an additional WHERE ts > cutoff.
	if cutoff > 0 {
		rows, err := db.Query(`
			SELECT id, sender, ts, epoch, payload, file_ids, signature, wrapped_keys, deleted, edited_at
			FROM messages
			WHERE rowid < (SELECT rowid FROM messages WHERE id = ?)
			  AND ts > ?
			ORDER BY rowid DESC
			LIMIT ?`,
			beforeID, cutoff, limit,
		)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		return scanMessages(rows)
	}

	return getMessagesBefore(db, beforeID, limit)
}

// DeleteDMMessage marks a 1:1 DM message as deleted. Returns file IDs for cleanup.
func (s *Store) DeleteDMMessage(dmID, msgID, deletedBy string) ([]string, error) {
	db, err := s.DMDB(dmID)
	if err != nil {
		return nil, err
	}
	return deleteMessage(db, msgID, deletedBy)
}

// GetDMReactionsForMessages returns reactions on messages in a 1:1 DM.
func (s *Store) GetDMReactionsForMessages(dmID string, messageIDs []string) ([]StoredReaction, error) {
	db, err := s.DMDB(dmID)
	if err != nil {
		return nil, err
	}
	return getReactionsForMessages(db, messageIDs)
}

// GetDMUnreadCount returns the count of unread 1:1 DM messages for a user,
// respecting the per-user cutoff.
func (s *Store) GetDMUnreadCount(dmID, user, deviceID string) (int, string, error) {
	lastRead, err := s.GetReadPosition(user, deviceID, "", "", dmID)
	if err != nil {
		return 0, "", err
	}

	db, err := s.DMDB(dmID)
	if err != nil {
		return 0, lastRead, err
	}

	// Get the user's cutoff to exclude messages they shouldn't see.
	dm, dmErr := s.GetDirectMessage(dmID)
	cutoff := int64(0)
	if dmErr == nil && dm != nil {
		cutoff = dm.CutoffFor(user)
	}

	var count int
	if lastRead == "" {
		if cutoff > 0 {
			err = db.QueryRow(`SELECT COUNT(*) FROM messages WHERE deleted = 0 AND ts > ?`, cutoff).Scan(&count)
		} else {
			err = db.QueryRow(`SELECT COUNT(*) FROM messages WHERE deleted = 0`).Scan(&count)
		}
	} else {
		if cutoff > 0 {
			err = db.QueryRow(`
				SELECT COUNT(*) FROM messages
				WHERE deleted = 0 AND ts > ? AND rowid > (SELECT rowid FROM messages WHERE id = ?)`,
				cutoff, lastRead,
			).Scan(&count)
		} else {
			err = db.QueryRow(`
				SELECT COUNT(*) FROM messages
				WHERE deleted = 0 AND rowid > (SELECT rowid FROM messages WHERE id = ?)`,
				lastRead,
			).Scan(&count)
		}
	}
	return count, lastRead, err
}

// DeleteDirectMessage permanently removes a 1:1 DM. Closes any cached
// SQLite handle for the per-DM message database, deletes the row from
// direct_messages, and unlinks the dm-<id>.db file (plus its WAL/SHM
// sidecars). Returns nil if the row does not exist (idempotent).
//
// Concurrency: this function does NOT take any application-level lock.
// The server holds dmCleanupMu around the call to serialize cleanup
// against concurrent CreateOrGetDirectMessage. The store-level mutex
// (s.mu) is acquired internally only to mutate the dmDBs cache.
func (s *Store) DeleteDirectMessage(dmID string) error {
	// Phase 17 Step 4a: path-traversal defense. See DeleteRoomRecord.
	if err := ValidateNanoID(dmID, "dm_"); err != nil {
		return fmt.Errorf("DeleteDirectMessage: %w", err)
	}

	// Close and evict any cached handle so the file is not held open
	// when we unlink it. WAL mode keeps -wal/-shm files alive while
	// the connection is open; close-then-unlink is the safe order.
	s.mu.Lock()
	if db, ok := s.dmDBs[dmID]; ok {
		db.Exec("PRAGMA wal_checkpoint(TRUNCATE)")
		_ = db.Close()
		delete(s.dmDBs, dmID)
	}
	s.mu.Unlock()

	// Delete the metadata row. This is the source of truth for
	// "does this DM exist?"; once gone, GetDirectMessage returns nil
	// and CreateOrGetDirectMessage will create a fresh row on next call.
	if _, err := s.dataDB.Exec(`DELETE FROM direct_messages WHERE id = ?`, dmID); err != nil {
		return fmt.Errorf("delete dm row: %w", err)
	}

	// Unlink the per-DM database file and its WAL sidecars.
	// Best-effort: missing files are not an error (idempotent for the
	// case where the row existed but the file was never created, e.g.
	// a freshly-leaved DM that never had any messages).
	dbPath := filepath.Join(s.dir, fmt.Sprintf("dm-%s.db", dmID))
	for _, suffix := range []string{"", "-wal", "-shm"} {
		if err := os.Remove(dbPath + suffix); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove %s: %w", dbPath+suffix, err)
		}
	}
	return nil
}
