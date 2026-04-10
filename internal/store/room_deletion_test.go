package store

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// ============================================================================
// deleted_rooms sidecar tests
// ============================================================================

// TestRecordRoomDeletion_InsertsRow verifies the basic insert path.
func TestRecordRoomDeletion_InsertsRow(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	if err := s.RecordRoomDeletion("usr_alice", "room_x"); err != nil {
		t.Fatalf("RecordRoomDeletion: %v", err)
	}

	ids, err := s.GetDeletedRoomsForUser("usr_alice")
	if err != nil {
		t.Fatalf("GetDeletedRoomsForUser: %v", err)
	}
	if len(ids) != 1 || ids[0] != "room_x" {
		t.Errorf("expected [room_x], got %v", ids)
	}
}

// TestRecordRoomDeletion_Idempotent verifies that recording the same
// (user, room) pair twice is a no-op — the first deleted_at timestamp
// is preserved (INSERT OR IGNORE semantics).
func TestRecordRoomDeletion_Idempotent(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	if err := s.RecordRoomDeletion("usr_alice", "room_x"); err != nil {
		t.Fatalf("first record: %v", err)
	}
	// Read the first deleted_at
	var firstAt int64
	s.dataDB.QueryRow(
		`SELECT deleted_at FROM deleted_rooms WHERE user_id = ? AND room_id = ?`,
		"usr_alice", "room_x",
	).Scan(&firstAt)

	// Sleep so a second INSERT with Unix-second precision would have
	// a different timestamp if it actually overwrote.
	time.Sleep(1100 * time.Millisecond)

	if err := s.RecordRoomDeletion("usr_alice", "room_x"); err != nil {
		t.Fatalf("second record: %v", err)
	}

	var secondAt int64
	s.dataDB.QueryRow(
		`SELECT deleted_at FROM deleted_rooms WHERE user_id = ? AND room_id = ?`,
		"usr_alice", "room_x",
	).Scan(&secondAt)

	if firstAt != secondAt {
		t.Errorf("deleted_at should be preserved on idempotent insert: first=%d second=%d", firstAt, secondAt)
	}
}

// TestGetDeletedRoomsForUser_ReturnsNewestFirst verifies ordering.
func TestGetDeletedRoomsForUser_ReturnsNewestFirst(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	// Insert directly with controlled timestamps to avoid sleep-based
	// test flakiness
	s.dataDB.Exec(
		`INSERT INTO deleted_rooms (user_id, room_id, deleted_at) VALUES (?, ?, ?)`,
		"usr_alice", "room_old", int64(1000),
	)
	s.dataDB.Exec(
		`INSERT INTO deleted_rooms (user_id, room_id, deleted_at) VALUES (?, ?, ?)`,
		"usr_alice", "room_new", int64(2000),
	)

	ids, err := s.GetDeletedRoomsForUser("usr_alice")
	if err != nil {
		t.Fatalf("GetDeletedRoomsForUser: %v", err)
	}
	if len(ids) != 2 {
		t.Fatalf("expected 2 rooms, got %d", len(ids))
	}
	if ids[0] != "room_new" || ids[1] != "room_old" {
		t.Errorf("expected [room_new, room_old], got %v", ids)
	}
}

// TestGetDeletedRoomsForUser_EmptyForUnknownUser verifies no-results
// case returns an empty slice (not an error).
func TestGetDeletedRoomsForUser_EmptyForUnknownUser(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	ids, err := s.GetDeletedRoomsForUser("usr_never_deleted")
	if err != nil {
		t.Fatalf("GetDeletedRoomsForUser: %v", err)
	}
	if len(ids) != 0 {
		t.Errorf("expected 0 rooms, got %d", len(ids))
	}
}

// TestGetDeletedRoomsForUser_ScopedToUser verifies that one user's
// deletion records don't leak into another user's catchup list.
func TestGetDeletedRoomsForUser_ScopedToUser(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	if err := s.RecordRoomDeletion("usr_alice", "room_x"); err != nil {
		t.Fatalf("record alice: %v", err)
	}
	if err := s.RecordRoomDeletion("usr_bob", "room_y"); err != nil {
		t.Fatalf("record bob: %v", err)
	}

	ids, _ := s.GetDeletedRoomsForUser("usr_alice")
	if len(ids) != 1 || ids[0] != "room_x" {
		t.Errorf("alice should only see room_x, got %v", ids)
	}

	ids, _ = s.GetDeletedRoomsForUser("usr_bob")
	if len(ids) != 1 || ids[0] != "room_y" {
		t.Errorf("bob should only see room_y, got %v", ids)
	}
}

// TestClearRoomDeletionsForUser_RemovesAll verifies the retirement
// cleanup path used by handleRetirement when a user is retired.
func TestClearRoomDeletionsForUser_RemovesAll(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	s.RecordRoomDeletion("usr_alice", "room_1")
	s.RecordRoomDeletion("usr_alice", "room_2")
	s.RecordRoomDeletion("usr_bob", "room_3")

	if err := s.ClearRoomDeletionsForUser("usr_alice"); err != nil {
		t.Fatalf("ClearRoomDeletionsForUser: %v", err)
	}

	ids, _ := s.GetDeletedRoomsForUser("usr_alice")
	if len(ids) != 0 {
		t.Errorf("alice should have 0 deletions after clear, got %v", ids)
	}

	ids, _ = s.GetDeletedRoomsForUser("usr_bob")
	if len(ids) != 1 {
		t.Errorf("bob's deletions should be untouched, got %v", ids)
	}
}

// TestClearRoomDeletion_RemovesSpecificRow verifies single-row removal.
func TestClearRoomDeletion_RemovesSpecificRow(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	s.RecordRoomDeletion("usr_alice", "room_1")
	s.RecordRoomDeletion("usr_alice", "room_2")

	if err := s.ClearRoomDeletion("usr_alice", "room_1"); err != nil {
		t.Fatalf("ClearRoomDeletion: %v", err)
	}

	ids, _ := s.GetDeletedRoomsForUser("usr_alice")
	if len(ids) != 1 || ids[0] != "room_2" {
		t.Errorf("expected [room_2], got %v", ids)
	}
}

// TestPruneOldRoomDeletions_RemovesStaleRows verifies that rows older
// than the cutoff are removed and the count returned.
func TestPruneOldRoomDeletions_RemovesStaleRows(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	now := time.Now().Unix()
	// Old row (10,000 seconds ago)
	s.dataDB.Exec(
		`INSERT INTO deleted_rooms (user_id, room_id, deleted_at) VALUES (?, ?, ?)`,
		"usr_alice", "room_old", now-10000,
	)
	// Fresh row (100 seconds ago)
	s.dataDB.Exec(
		`INSERT INTO deleted_rooms (user_id, room_id, deleted_at) VALUES (?, ?, ?)`,
		"usr_alice", "room_fresh", now-100,
	)

	// Prune anything older than 5000 seconds
	pruned, err := s.PruneOldRoomDeletions(5000)
	if err != nil {
		t.Fatalf("PruneOldRoomDeletions: %v", err)
	}
	if pruned != 1 {
		t.Errorf("expected 1 row pruned, got %d", pruned)
	}

	ids, _ := s.GetDeletedRoomsForUser("usr_alice")
	if len(ids) != 1 || ids[0] != "room_fresh" {
		t.Errorf("expected [room_fresh], got %v", ids)
	}
}

// ============================================================================
// pending_room_retirements queue tests
// ============================================================================

// TestRecordAndConsumePendingRoomRetirement verifies the round-trip
// for the retirement queue: CLI inserts via RecordPendingRoomRetirement,
// the server processor reads + atomically deletes via
// ConsumePendingRoomRetirements.
func TestRecordAndConsumePendingRoomRetirement(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	if err := s.RecordPendingRoomRetirement("room_1", "usr_admin", "team disbanded"); err != nil {
		t.Fatalf("record 1: %v", err)
	}
	if err := s.RecordPendingRoomRetirement("room_2", "usr_admin", ""); err != nil {
		t.Fatalf("record 2: %v", err)
	}

	pending, err := s.ConsumePendingRoomRetirements()
	if err != nil {
		t.Fatalf("consume: %v", err)
	}
	if len(pending) != 2 {
		t.Fatalf("expected 2 pending, got %d", len(pending))
	}

	// Field round-trip check
	byRoom := make(map[string]PendingRoomRetirement)
	for _, p := range pending {
		byRoom[p.RoomID] = p
	}
	if p, ok := byRoom["room_1"]; !ok {
		t.Error("room_1 missing from consumed list")
	} else {
		if p.RetiredBy != "usr_admin" {
			t.Errorf("room_1 RetiredBy = %q, want usr_admin", p.RetiredBy)
		}
		if p.Reason != "team disbanded" {
			t.Errorf("room_1 Reason = %q, want team disbanded", p.Reason)
		}
		if p.QueuedAt == 0 {
			t.Error("room_1 QueuedAt should be non-zero")
		}
	}
	if p, ok := byRoom["room_2"]; !ok {
		t.Error("room_2 missing from consumed list")
	} else {
		if p.Reason != "" {
			t.Errorf("room_2 Reason = %q, want empty", p.Reason)
		}
	}

	// After consume, queue should be empty
	pending2, err := s.ConsumePendingRoomRetirements()
	if err != nil {
		t.Fatalf("second consume: %v", err)
	}
	if len(pending2) != 0 {
		t.Errorf("queue should be empty after consume, got %d", len(pending2))
	}
}

// TestConsumePendingRoomRetirements_EmptyQueue verifies the consume
// path is a no-op (no error) when the queue is already empty.
func TestConsumePendingRoomRetirements_EmptyQueue(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	pending, err := s.ConsumePendingRoomRetirements()
	if err != nil {
		t.Fatalf("consume empty: %v", err)
	}
	if len(pending) != 0 {
		t.Errorf("expected 0, got %d", len(pending))
	}
}

// ============================================================================
// DeleteRoomRecord (last-member cleanup cascade) tests
// ============================================================================

// TestDeleteRoomRecord_RemovesRowAndFile verifies the full cascade:
// room_members rows cleared, rooms row deleted, per-room DB file
// unlinked, epoch_keys cleared.
func TestDeleteRoomRecord_RemovesRowAndFile(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	// Seed a room, a member, and a cached DB handle (which creates
	// the per-room file).
	seedTestRoom(t, s, "room_cleanup", "cleanup", "")
	seedRoomMember(t, s, "room_cleanup", "usr_alice")

	// Trigger creation of the per-room file by calling RoomDB
	if _, err := s.RoomDB("room_cleanup"); err != nil {
		t.Fatalf("RoomDB: %v", err)
	}

	// Seed an epoch key row (in data.db) referencing the room
	s.dataDB.Exec(
		`INSERT INTO epoch_keys (room, epoch, user, wrapped_key) VALUES (?, ?, ?, ?)`,
		"room_cleanup", int64(1), "usr_alice", "wrapped",
	)

	dbPath := filepath.Join(s.dir, "room-room_cleanup.db")
	if _, err := os.Stat(dbPath); err != nil {
		t.Fatalf("per-room DB file should exist before cleanup: %v", err)
	}

	// Run the cleanup cascade
	if err := s.DeleteRoomRecord("room_cleanup"); err != nil {
		t.Fatalf("DeleteRoomRecord: %v", err)
	}

	// Rooms row should be gone
	r, _ := s.GetRoomByID("room_cleanup")
	if r != nil {
		t.Error("rooms row should be deleted")
	}

	// Members should be gone
	var memberCount int
	s.roomsDB.QueryRow(
		`SELECT COUNT(*) FROM room_members WHERE room_id = ?`, "room_cleanup",
	).Scan(&memberCount)
	if memberCount != 0 {
		t.Errorf("expected 0 members, got %d", memberCount)
	}

	// Epoch keys should be gone
	var keyCount int
	s.dataDB.QueryRow(
		`SELECT COUNT(*) FROM epoch_keys WHERE room = ?`, "room_cleanup",
	).Scan(&keyCount)
	if keyCount != 0 {
		t.Errorf("expected 0 epoch_keys, got %d", keyCount)
	}

	// Per-room DB file should be gone
	if _, err := os.Stat(dbPath); !os.IsNotExist(err) {
		t.Errorf("per-room DB file should be removed, stat err: %v", err)
	}

	// Cached handle should be evicted
	s.mu.RLock()
	_, cached := s.roomDBs["room_cleanup"]
	s.mu.RUnlock()
	if cached {
		t.Error("cached DB handle should be evicted")
	}
}

// TestDeleteRoomRecord_Idempotent verifies that calling DeleteRoomRecord
// on a room that doesn't exist (or has already been deleted) is a no-op
// rather than an error. The cleanup re-check inside handleDeleteRoom's
// last-member path relies on this — two racing deleters may both call
// DeleteRoomRecord and the second one must not error.
func TestDeleteRoomRecord_Idempotent(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	// Delete a room that never existed
	if err := s.DeleteRoomRecord("room_never_existed"); err != nil {
		t.Errorf("delete of nonexistent room should be no-op, got: %v", err)
	}

	// Seed and double-delete
	seedTestRoom(t, s, "room_twice", "twice", "")
	if err := s.DeleteRoomRecord("room_twice"); err != nil {
		t.Fatalf("first delete: %v", err)
	}
	if err := s.DeleteRoomRecord("room_twice"); err != nil {
		t.Errorf("second delete should be no-op, got: %v", err)
	}
}

// TestDeleteRoomRecord_PreservesDeletedRoomsSidecar verifies the
// critical ordering constraint: the deleted_rooms sidecar row written
// by handleDeleteRoom BEFORE the leave logic must survive the
// cleanup cascade. This is what makes the multi-device catchup work.
func TestDeleteRoomRecord_PreservesDeletedRoomsSidecar(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	seedTestRoom(t, s, "room_lastmember", "lastmember", "")
	seedRoomMember(t, s, "room_lastmember", "usr_alice")

	// Simulate handleDeleteRoom ordering: sidecar FIRST, then leave
	// + cleanup cascade
	if err := s.RecordRoomDeletion("usr_alice", "room_lastmember"); err != nil {
		t.Fatalf("RecordRoomDeletion: %v", err)
	}
	if err := s.RemoveRoomMember("room_lastmember", "usr_alice"); err != nil {
		t.Fatalf("RemoveRoomMember: %v", err)
	}
	if err := s.DeleteRoomRecord("room_lastmember"); err != nil {
		t.Fatalf("DeleteRoomRecord: %v", err)
	}

	// The sidecar row MUST survive the cleanup cascade — offline
	// devices of alice need to learn about the delete on reconnect
	ids, err := s.GetDeletedRoomsForUser("usr_alice")
	if err != nil {
		t.Fatalf("GetDeletedRoomsForUser: %v", err)
	}
	found := false
	for _, id := range ids {
		if id == "room_lastmember" {
			found = true
			break
		}
	}
	if !found {
		t.Error("deleted_rooms row for room_lastmember should survive the cleanup cascade")
	}
}

// TestDeleteRoomRecord_OpportunisticPrune verifies that stale
// deleted_rooms rows from other users are cleaned up as a side
// effect of the cleanup cascade.
func TestDeleteRoomRecord_OpportunisticPrune(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	// Insert a very old deletion record (2 years ago)
	oldTime := time.Now().Unix() - (2 * 365 * 24 * 60 * 60)
	s.dataDB.Exec(
		`INSERT INTO deleted_rooms (user_id, room_id, deleted_at) VALUES (?, ?, ?)`,
		"usr_old", "room_ancient", oldTime,
	)

	// Seed and delete a different room (which triggers the
	// opportunistic prune)
	seedTestRoom(t, s, "room_trigger", "trigger", "")
	if err := s.DeleteRoomRecord("room_trigger"); err != nil {
		t.Fatalf("DeleteRoomRecord: %v", err)
	}

	// The old row should be gone
	ids, _ := s.GetDeletedRoomsForUser("usr_old")
	if len(ids) != 0 {
		t.Errorf("ancient deleted_rooms row should be pruned, got %v", ids)
	}
}
