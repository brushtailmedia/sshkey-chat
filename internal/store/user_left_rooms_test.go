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
