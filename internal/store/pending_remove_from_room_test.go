package store

// Phase 20 — tests for the pending_remove_from_room queue helpers.
// Same shape as the other Phase 16 pending_* queue tests: DELETE-on-
// consume semantics, insertion order preserved.

import (
	"testing"
)

func TestConsumePendingRemoveFromRooms_Empty(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	got, err := st.ConsumePendingRemoveFromRooms()
	if err != nil {
		t.Fatalf("consume: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected 0 rows, got %d", len(got))
	}
}

func TestRecordPendingRemoveFromRoom_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	if err := st.RecordPendingRemoveFromRoom("usr_alice", "rm_general", "removed", "os:1000"); err != nil {
		t.Fatalf("record: %v", err)
	}

	got, _ := st.ConsumePendingRemoveFromRooms()
	if len(got) != 1 {
		t.Fatalf("expected 1 row, got %d", len(got))
	}
	row := got[0]
	if row.UserID != "usr_alice" {
		t.Errorf("UserID = %q, want usr_alice", row.UserID)
	}
	if row.RoomID != "rm_general" {
		t.Errorf("RoomID = %q, want rm_general", row.RoomID)
	}
	if row.Reason != "removed" {
		t.Errorf("Reason = %q, want removed", row.Reason)
	}
	if row.InitiatedBy != "os:1000" {
		t.Errorf("InitiatedBy = %q, want os:1000", row.InitiatedBy)
	}
}

// TestConsumePendingRemoveFromRooms_DeletesRows asserts DELETE-on-consume
// (not mark-processed) — second consume returns empty, confirming the
// queue/history split from Phase 20.
func TestConsumePendingRemoveFromRooms_DeletesRows(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	st.RecordPendingRemoveFromRoom("usr_alice", "rm_a", "removed", "os:1000")
	st.RecordPendingRemoveFromRoom("usr_bob", "rm_b", "removed", "os:1000")

	first, _ := st.ConsumePendingRemoveFromRooms()
	if len(first) != 2 {
		t.Fatalf("first consume: expected 2 rows, got %d", len(first))
	}

	second, _ := st.ConsumePendingRemoveFromRooms()
	if len(second) != 0 {
		t.Errorf("second consume should be empty (DELETE-on-consume), got %d rows", len(second))
	}
}

func TestRecordPendingRemoveFromRoom_PreservesOrder(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	users := []string{"usr_a", "usr_b", "usr_c"}
	for _, u := range users {
		st.RecordPendingRemoveFromRoom(u, "rm_shared", "removed", "os:1000")
	}

	got, _ := st.ConsumePendingRemoveFromRooms()
	if len(got) != len(users) {
		t.Fatalf("expected %d rows, got %d", len(users), len(got))
	}
	for i, row := range got {
		if row.UserID != users[i] {
			t.Errorf("row %d UserID = %q, want %q", i, row.UserID, users[i])
		}
	}
}
