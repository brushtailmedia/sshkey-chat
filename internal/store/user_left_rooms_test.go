package store

// Phase 20 — tests for the user_left_rooms pure-history helpers.
//
// Coverage:
//   - Record happy path
//   - GetUserLeftRoomsCatchup dedups to most-recent per (user, room)
//   - DeleteUserLeftRoomRows cleans up on re-add
//   - PruneOldUserLeftRooms respects retention
//
// The ConsumePendingUserLeftRooms + mark-processed tests from
// Phase 16 were deleted with the function in the Phase 20 queue/
// history split.

import (
	"testing"
)

func TestRecordUserLeftRoom_HappyPath(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	id, err := st.RecordUserLeftRoom("usr_alice", "rm_general", "removed", "os:1000")
	if err != nil {
		t.Fatalf("record: %v", err)
	}
	if id == 0 {
		t.Error("expected non-zero row ID")
	}
}

// TestGetUserLeftRoomsCatchup_ReturnsMostRecentPerRoom verifies the
// dedup logic. Two leaves for the same (user, room) — catchup returns
// exactly one row, the one with the highest left_at.
func TestGetUserLeftRoomsCatchup_ReturnsMostRecentPerRoom(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	if _, err := st.RecordUserLeftRoom("usr_alice", "rm_a", "", "usr_alice"); err != nil {
		t.Fatalf("first record: %v", err)
	}
	if _, err := st.RecordUserLeftRoom("usr_alice", "rm_a", "removed", "admin"); err != nil {
		t.Fatalf("second record: %v", err)
	}

	got, err := st.GetUserLeftRoomsCatchup("usr_alice")
	if err != nil {
		t.Fatalf("catchup: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 row (deduped), got %d", len(got))
	}
}

// TestDeleteUserLeftRoomRows_CleansUpOnRejoin verifies Q2 (re-join
// clears prior leave history).
func TestDeleteUserLeftRoomRows_CleansUpOnRejoin(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	if _, err := st.RecordUserLeftRoom("usr_alice", "rm_a", "removed", "admin"); err != nil {
		t.Fatalf("record: %v", err)
	}

	if err := st.DeleteUserLeftRoomRows("usr_alice", "rm_a"); err != nil {
		t.Fatalf("delete: %v", err)
	}

	got, _ := st.GetUserLeftRoomsCatchup("usr_alice")
	if len(got) != 0 {
		t.Errorf("want 0 rows after delete, got %d", len(got))
	}
}

// TestPruneOldUserLeftRooms_RespectsRetention verifies the prune
// leaves recent rows alone.
func TestPruneOldUserLeftRooms_RespectsRetention(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	if _, err := st.RecordUserLeftRoom("usr_alice", "rm_a", "", "usr_alice"); err != nil {
		t.Fatalf("record: %v", err)
	}

	deleted, err := st.PruneOldUserLeftRooms(365 * 24 * 60 * 60)
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if deleted != 0 {
		t.Errorf("want 0 rows pruned, got %d", deleted)
	}
}

// TestHasUserLeftRoom covers the delete-after-leave relationship gate:
// false for no history, true after a recorded leave, scoped to (user, room),
// and stable across duplicate leave rows. See delete-after-leave-authz-v3.md.
func TestHasUserLeftRoom(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	// No history → (false, nil), not an error.
	if left, err := st.HasUserLeftRoom("usr_alice", "rm_a"); err != nil || left {
		t.Fatalf("no history want (false,nil), got (%v,%v)", left, err)
	}

	if _, err := st.RecordUserLeftRoom("usr_alice", "rm_a", "", "usr_alice"); err != nil {
		t.Fatalf("record leave: %v", err)
	}

	// After a recorded leave → (true, nil).
	if left, err := st.HasUserLeftRoom("usr_alice", "rm_a"); err != nil || !left {
		t.Fatalf("after leave want (true,nil), got (%v,%v)", left, err)
	}

	// Scoped to (user, room).
	if left, _ := st.HasUserLeftRoom("usr_bob", "rm_a"); left {
		t.Error("should be scoped to user")
	}
	if left, _ := st.HasUserLeftRoom("usr_alice", "rm_b"); left {
		t.Error("should be scoped to room")
	}

	// Duplicate leave rows don't change the boolean.
	if _, err := st.RecordUserLeftRoom("usr_alice", "rm_a", "removed", "admin"); err != nil {
		t.Fatalf("second leave: %v", err)
	}
	if left, err := st.HasUserLeftRoom("usr_alice", "rm_a"); err != nil || !left {
		t.Fatalf("duplicate rows still (true,nil), got (%v,%v)", left, err)
	}
}
