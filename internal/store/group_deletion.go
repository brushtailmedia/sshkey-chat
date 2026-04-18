package store

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// groupDeletionRetentionSeconds is the maximum age of a deleted_groups row
// before it's eligible for opportunistic pruning. One year is generous
// enough that any reasonable offline-device catchup window has passed; a
// device that's been disconnected longer than this falls back to local
// reconciliation against group_list (mark-as-left, not purge).
const groupDeletionRetentionSeconds = 365 * 24 * 60 * 60

// RecordGroupDeletion writes a row to deleted_groups recording that the
// given user has /delete'd this group from their view. Idempotent: re-
// running for the same (user, group) pair is a no-op (the original
// deleted_at is preserved).
//
// This is the catchup signal for the user's other devices. It is INSERTed
// before any leave-side mutation in handleDeleteGroup so the intent is
// captured even if subsequent steps trigger a last-member cleanup.
func (s *Store) RecordGroupDeletion(userID, groupID string) error {
	_, err := s.dataDB.Exec(
		`INSERT OR IGNORE INTO deleted_groups (user_id, group_id, deleted_at) VALUES (?, ?, ?)`,
		userID, groupID, time.Now().Unix(),
	)
	return err
}

// GetDeletedGroupsForUser returns every group ID this user has previously
// /delete'd. Used by sendDeletedGroups during the connect handshake to
// catch up offline devices that missed the live group_deleted echo.
func (s *Store) GetDeletedGroupsForUser(userID string) ([]string, error) {
	rows, err := s.dataDB.Query(
		`SELECT group_id FROM deleted_groups WHERE user_id = ? ORDER BY deleted_at DESC`,
		userID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// ClearGroupDeletionsForUser removes every deletion record for a single
// user. Called from handleRetirement when the user's account is retired
// (the records are dead weight at that point — the user can never
// reconnect to consume them).
func (s *Store) ClearGroupDeletionsForUser(userID string) error {
	_, err := s.dataDB.Exec(`DELETE FROM deleted_groups WHERE user_id = ?`, userID)
	return err
}

// ClearGroupDeletion removes a single (user, group) deletion record.
// Reserved for a future "rejoin a group" path that doesn't exist yet — if
// admin /add re-adds a previously-deleted user to a group, the deletion
// row should be cleared so subsequent syncs don't tell the user to purge
// the group they were just re-invited to. Currently unused.
func (s *Store) ClearGroupDeletion(userID, groupID string) error {
	_, err := s.dataDB.Exec(
		`DELETE FROM deleted_groups WHERE user_id = ? AND group_id = ?`,
		userID, groupID,
	)
	return err
}

// PruneOldGroupDeletions deletes every deleted_groups row older than the
// given age in seconds. Returns the number of rows removed.
//
// This is the bounded-growth mechanism for the deleted_groups table.
// Called opportunistically from DeleteGroupConversation and
// handleRetirement so the table self-maintains without a separate GC
// goroutine. The default retention (groupDeletionRetentionSeconds) is one
// year, which is way longer than any reasonable offline-device window.
func (s *Store) PruneOldGroupDeletions(maxAgeSeconds int64) (int, error) {
	cutoff := time.Now().Unix() - maxAgeSeconds
	res, err := s.dataDB.Exec(
		`DELETE FROM deleted_groups WHERE deleted_at < ?`,
		cutoff,
	)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// DeleteGroupConversation permanently removes a group DM. Closes any
// cached SQLite handle for the per-group message database, deletes the
// rows from group_conversations and group_members, and unlinks the
// group-<id>.db file (plus its WAL/SHM sidecars). Idempotent: missing
// rows or files are not an error.
//
// Concurrency: groups have explicit IDs and no find-or-create dedup
// path, so cleanup does not race against group create. No application-
// level mutex is needed.
//
// Note: this function does NOT touch deleted_groups. Deletion records
// live independently of group lifetime — they're the catchup signal for
// offline devices, and they MUST persist across the cleanup of the group
// they reference. The opportunistic age-based prune below is the only
// thing that ever removes deleted_groups rows automatically.
func (s *Store) DeleteGroupConversation(groupID string) error {
	// Phase 17 Step 4a: path-traversal defense. See DeleteRoomRecord.
	if err := ValidateNanoID(groupID, "group_"); err != nil {
		return fmt.Errorf("DeleteGroupConversation: %w", err)
	}

	// Close and evict any cached handle so the file is not held open
	// when we unlink it. WAL mode keeps -wal/-shm files alive while the
	// connection is open; close-then-unlink is the safe order.
	s.mu.Lock()
	if db, ok := s.groupDBs[groupID]; ok {
		db.Exec("PRAGMA wal_checkpoint(TRUNCATE)")
		_ = db.Close()
		delete(s.groupDBs, groupID)
	}
	s.mu.Unlock()

	// Defensive: drop any straggler members. Last-member cleanup callers
	// should have already removed everyone, but a future caller (e.g.
	// admin force-delete) might not.
	if _, err := s.dataDB.Exec(`DELETE FROM group_members WHERE group_id = ?`, groupID); err != nil {
		return fmt.Errorf("delete group members: %w", err)
	}

	// Delete the metadata row.
	if _, err := s.dataDB.Exec(`DELETE FROM group_conversations WHERE id = ?`, groupID); err != nil {
		return fmt.Errorf("delete group row: %w", err)
	}

	// Unlink the per-group database file and its WAL sidecars.
	dbPath := filepath.Join(s.dir, fmt.Sprintf("group-%s.db", groupID))
	for _, suffix := range []string{"", "-wal", "-shm"} {
		if err := os.Remove(dbPath + suffix); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove %s: %w", dbPath+suffix, err)
		}
	}

	// Opportunistic prune: piggyback on the cleanup we just did to age
	// out very stale deletion records. Best-effort — failures here don't
	// affect the primary cleanup result. The prune only touches rows
	// older than groupDeletionRetentionSeconds, so the row we may have
	// just created in handleDeleteGroup (if alice was the last member)
	// is safe.
	_, _ = s.PruneOldGroupDeletions(groupDeletionRetentionSeconds)

	return nil
}
