package store

// Phase 16 Gap 1 — tests for the user_left_rooms helpers.
//
// Coverage:
//   - Record happy path
//   - Empty consume returns no rows
//   - Round-trip: record then consume
//   - Mark-processed semantics: rows persist after consume but
//     processed=1 and second consume returns empty
//   - Insertion order preserved
//   - Multiple Record calls work correctly

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

func TestConsumePendingUserLeftRooms_Empty(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	got, err := st.ConsumePendingUserLeftRooms()
	if err != nil {
		t.Fatalf("consume: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected 0 rows, got %d", len(got))
	}
}

func TestRecordAndConsumeUserLeftRoom(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	if _, err := st.RecordUserLeftRoom("usr_alice", "rm_general", "removed", "os:1000"); err != nil {
		t.Fatalf("record: %v", err)
	}

	got, _ := st.ConsumePendingUserLeftRooms()
	if len(got) != 1 {
		t.Fatalf("expected 1 row, got %d", len(got))
	}
	row := got[0]
	if row.UserID != "usr_alice" {
		t.Errorf("UserID = %q", row.UserID)
	}
	if row.RoomID != "rm_general" {
		t.Errorf("RoomID = %q", row.RoomID)
	}
	if row.Reason != "removed" {
		t.Errorf("Reason = %q", row.Reason)
	}
	if row.InitiatedBy != "os:1000" {
		t.Errorf("InitiatedBy = %q", row.InitiatedBy)
	}
	if row.LeftAt == 0 {
		t.Error("LeftAt should be populated")
	}
	// The returned row reflects the post-update state — processed
	// should be true after consume.
	if !row.Processed {
		t.Error("returned row should have Processed=true after consume marks it")
	}
}

// TestConsumePendingUserLeftRooms_MarkProcessedSemantics verifies that
// rows persist in the table after consume (rather than being
// deleted), but a second consume returns empty because the rows are
// now marked processed=1. This is the dual-purpose pattern that
// Phase 20 will read for offline catchup.
func TestConsumePendingUserLeftRooms_MarkProcessedSemantics(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	st.RecordUserLeftRoom("usr_alice", "rm_a", "removed", "os:1000")
	st.RecordUserLeftRoom("usr_bob", "rm_b", "removed", "os:1000")

	first, _ := st.ConsumePendingUserLeftRooms()
	if len(first) != 2 {
		t.Fatalf("first consume: expected 2 rows, got %d", len(first))
	}

	// Second consume should return zero rows (the first call marked
	// them processed).
	second, _ := st.ConsumePendingUserLeftRooms()
	if len(second) != 0 {
		t.Errorf("second consume should be empty, got %d rows", len(second))
	}

	// But the rows should still be in the table — verify by counting
	// directly.
	var totalRows int
	st.dataDB.QueryRow(`SELECT COUNT(*) FROM user_left_rooms`).Scan(&totalRows)
	if totalRows != 2 {
		t.Errorf("expected 2 rows still in table after consume (mark-processed semantics), got %d", totalRows)
	}

	var processedRows int
	st.dataDB.QueryRow(`SELECT COUNT(*) FROM user_left_rooms WHERE processed = 1`).Scan(&processedRows)
	if processedRows != 2 {
		t.Errorf("expected 2 processed rows, got %d", processedRows)
	}
}

func TestRecordUserLeftRoom_PreservesOrder(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	users := []string{"usr_alpha", "usr_beta", "usr_gamma", "usr_delta"}
	for _, u := range users {
		st.RecordUserLeftRoom(u, "rm_general", "removed", "os:1000")
	}

	got, _ := st.ConsumePendingUserLeftRooms()
	if len(got) != len(users) {
		t.Fatalf("expected %d rows, got %d", len(users), len(got))
	}
	for i, row := range got {
		if row.UserID != users[i] {
			t.Errorf("row %d UserID = %q, want %q", i, row.UserID, users[i])
		}
	}
}

// TestConsumePendingUserLeftRooms_OnlyUnprocessed verifies that a
// new record AFTER an earlier consume is picked up by the next
// consume — the processor doesn't get stuck on already-processed
// rows.
func TestConsumePendingUserLeftRooms_OnlyUnprocessed(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	st.RecordUserLeftRoom("usr_alice", "rm_a", "removed", "os:1000")
	first, _ := st.ConsumePendingUserLeftRooms()
	if len(first) != 1 {
		t.Fatalf("first consume: expected 1 row, got %d", len(first))
	}

	// New row added AFTER the first consume.
	st.RecordUserLeftRoom("usr_bob", "rm_b", "removed", "os:1000")
	second, _ := st.ConsumePendingUserLeftRooms()
	if len(second) != 1 {
		t.Fatalf("second consume: expected 1 row, got %d", len(second))
	}
	if second[0].UserID != "usr_bob" {
		t.Errorf("second consume should return bob, got %q", second[0].UserID)
	}
}
