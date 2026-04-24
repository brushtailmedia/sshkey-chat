package store

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// roomDeletionRetentionSeconds is the maximum age of a deleted_rooms row
// before it's eligible for opportunistic pruning. One year is generous
// enough that any reasonable offline-device catchup window has passed;
// a device that's been disconnected longer than this falls back to the
// client-side reconciliation path (mark-as-left, not purge). Mirrors
// groupDeletionRetentionSeconds.
const roomDeletionRetentionSeconds = 365 * 24 * 60 * 60

// RecordRoomDeletion writes a row to deleted_rooms recording that the
// given user has /delete'd this room from their view. Idempotent: re-
// running for the same (user, room) pair is a no-op (the original
// deleted_at is preserved).
//
// This is the catchup signal for the user's other devices. It is
// INSERTed before any leave-side mutation in handleDeleteRoom so the
// intent is captured even if subsequent steps trigger a last-member
// cleanup. Mirrors RecordGroupDeletion.
func (s *Store) RecordRoomDeletion(userID, roomID string) error {
	_, err := s.dataDB.Exec(
		`INSERT OR IGNORE INTO deleted_rooms (user_id, room_id, deleted_at) VALUES (?, ?, ?)`,
		userID, roomID, time.Now().Unix(),
	)
	return err
}

// GetDeletedRoomsForUser returns every room ID this user has previously
// /delete'd. Used by sendDeletedRooms during the connect handshake to
// catch up offline devices that missed the live room_deleted echo.
// Mirrors GetDeletedGroupsForUser.
func (s *Store) GetDeletedRoomsForUser(userID string) ([]string, error) {
	rows, err := s.dataDB.Query(
		`SELECT room_id FROM deleted_rooms WHERE user_id = ? ORDER BY deleted_at DESC`,
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

// ClearRoomDeletionsForUser removes every deletion record for a single
// user. Called from handleRetirement when the user's account is retired
// (the records are dead weight at that point — the user can never
// reconnect to consume them). Mirrors ClearGroupDeletionsForUser.
func (s *Store) ClearRoomDeletionsForUser(userID string) error {
	_, err := s.dataDB.Exec(`DELETE FROM deleted_rooms WHERE user_id = ?`, userID)
	return err
}

// ClearRoomDeletion removes a single (user, room) deletion record.
// Reserved for a future "rejoin a room" path — if an admin re-adds a
// previously-deleted user to a room, the deletion row should be cleared
// so subsequent syncs don't tell the user to purge the room they were
// just re-invited to. Mirrors ClearGroupDeletion; currently unused.
func (s *Store) ClearRoomDeletion(userID, roomID string) error {
	_, err := s.dataDB.Exec(
		`DELETE FROM deleted_rooms WHERE user_id = ? AND room_id = ?`,
		userID, roomID,
	)
	return err
}

// PruneOldRoomDeletions deletes every deleted_rooms row older than the
// given age in seconds. Returns the number of rows removed.
//
// This is the bounded-growth mechanism for the deleted_rooms table.
// Called opportunistically from DeleteRoomRecord and handleRetirement
// so the table self-maintains without a separate GC goroutine. The
// default retention (roomDeletionRetentionSeconds) is one year.
// Mirrors PruneOldGroupDeletions.
func (s *Store) PruneOldRoomDeletions(maxAgeSeconds int64) (int, error) {
	cutoff := time.Now().Unix() - maxAgeSeconds
	res, err := s.dataDB.Exec(
		`DELETE FROM deleted_rooms WHERE deleted_at < ?`,
		cutoff,
	)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// PendingRoomRetirement is one row from the pending_room_retirements
// queue — an admin-triggered room retirement that the CLI has staged
// for the running server to broadcast. Returned by
// ConsumePendingRoomRetirements.
type PendingRoomRetirement struct {
	ID        int64
	RoomID    string
	RetiredBy string
	Reason    string
	QueuedAt  int64
}

// RecordPendingRoomRetirement queues an admin-triggered room retirement
// so the running server can broadcast the room_retired event to
// connected members. Called from the CLI's retire-room command AFTER
// the CLI has already mutated the rooms table directly via
// SetRoomRetired. The queue exists purely for live broadcast delivery;
// the retirement takes effect at the data layer regardless of whether
// the server processes the queue row.
//
// The queue + polling pattern exists because sshkey-ctl runs locally
// on the server box only — it cannot send protocol messages to the
// running server, so CLI → server coordination happens via these
// shared SQLite tables. See PROJECT.md "Rooms / Channels" for the
// full security rationale.
func (s *Store) RecordPendingRoomRetirement(roomID, retiredBy, reason string) error {
	_, err := s.dataDB.Exec(
		`INSERT INTO pending_room_retirements (room_id, retired_by, reason, queued_at) VALUES (?, ?, ?, ?)`,
		roomID, retiredBy, reason, time.Now().Unix(),
	)
	return err
}

// ConsumePendingRoomRetirements reads every pending retirement row,
// deletes them all atomically, and returns the consumed list to the
// caller. The caller is then responsible for performing the
// room_retired broadcasts.
//
// Atomic semantics: a transaction wraps the SELECT and DELETE so a
// concurrent invocation can't double-process a retirement. The
// transaction is short-lived (typically zero or a handful of rows) so
// contention is negligible.
func (s *Store) ConsumePendingRoomRetirements() ([]PendingRoomRetirement, error) {
	tx, err := s.dataDB.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	rows, err := tx.Query(
		`SELECT id, room_id, retired_by, reason, queued_at FROM pending_room_retirements ORDER BY id`,
	)
	if err != nil {
		return nil, err
	}

	var pending []PendingRoomRetirement
	for rows.Next() {
		var p PendingRoomRetirement
		if err := rows.Scan(&p.ID, &p.RoomID, &p.RetiredBy, &p.Reason, &p.QueuedAt); err != nil {
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
		if _, err := tx.Exec(`DELETE FROM pending_room_retirements`); err != nil {
			return nil, err
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return pending, nil
}

// DeleteRoomRecord permanently removes a room. Closes any cached
// SQLite handle for the per-room message database, deletes the rows
// from rooms and room_members (both in rooms.db), deletes related
// epoch_keys rows (in data.db), and unlinks the room-<id>.db file
// (plus its WAL/SHM sidecars). Idempotent: missing rows or files are
// not an error.
//
// Called from handleDeleteRoom when the caller was the last remaining
// member of the room (active or retired), and from the polling
// goroutine when an admin retires a room that already has zero members
// in room_members.
//
// Note: this function does NOT touch deleted_rooms. Deletion records
// live independently of room lifetime — they're the catchup signal for
// offline devices, and they MUST persist across the cleanup of the
// room they reference. The opportunistic age-based prune below is the
// only thing that ever removes deleted_rooms rows automatically.
//
// Mirrors DeleteGroupConversation from group_deletion.go.
func (s *Store) DeleteRoomRecord(roomID string) error {
	// Phase 17 Step 4a: path-traversal defense. `roomID` flows into
	// `filepath.Join(s.dir, fmt.Sprintf("room-%s.db", roomID))` below
	// and then directly to `os.Remove`. Without this check a malformed
	// ID like "../../etc/passwd" could unlink files outside the data
	// directory. Same strict validation as RoomDB.
	if err := ValidateNanoID(roomID, "room_"); err != nil {
		return fmt.Errorf("DeleteRoomRecord: %w", err)
	}

	// Close and evict any cached handle so the file is not held open
	// when we unlink it. WAL mode keeps -wal/-shm files alive while the
	// connection is open; close-then-unlink is the safe order.
	s.mu.Lock()
	if db, ok := s.roomDBs[roomID]; ok {
		db.Exec("PRAGMA wal_checkpoint(TRUNCATE)")
		_ = db.Close()
		delete(s.roomDBs, roomID)
	}
	s.mu.Unlock()

	// Defensive: drop any straggler members. Last-member cleanup
	// callers should have already removed everyone, but a future
	// caller (e.g. admin force-delete of an occupied room) might not.
	if _, err := s.roomsDB.Exec(`DELETE FROM room_members WHERE room_id = ?`, roomID); err != nil {
		return fmt.Errorf("delete room members: %w", err)
	}

	// Delete the room metadata row.
	if _, err := s.roomsDB.Exec(`DELETE FROM rooms WHERE id = ?`, roomID); err != nil {
		return fmt.Errorf("delete room row: %w", err)
	}

	// Delete all epoch_keys rows for this room (in data.db). No
	// member can decrypt anything anyway once the room is gone, and
	// leaving stale key rows around bloats the table.
	if _, err := s.dataDB.Exec(`DELETE FROM epoch_keys WHERE room = ?`, roomID); err != nil {
		return fmt.Errorf("delete epoch keys: %w", err)
	}

	// Unlink the per-room database file and its WAL sidecars.
	dbPath := filepath.Join(s.dir, fmt.Sprintf("room-%s.db", roomID))
	for _, suffix := range []string{"", "-wal", "-shm"} {
		if err := os.Remove(dbPath + suffix); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove %s: %w", dbPath+suffix, err)
		}
	}

	// Opportunistic prune: piggyback on the cleanup we just did to
	// age out very stale deletion records. Best-effort — failures
	// here don't affect the primary cleanup result. The prune only
	// touches rows older than roomDeletionRetentionSeconds, so the
	// row we may have just created in handleDeleteRoom (if the
	// caller was the last member) is safe.
	_, _ = s.PruneOldRoomDeletions(roomDeletionRetentionSeconds)

	return nil
}
