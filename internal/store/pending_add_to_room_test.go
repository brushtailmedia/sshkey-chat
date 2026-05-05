package store

import "testing"

func TestConsumePendingAddToRooms_Empty(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	got, err := st.ConsumePendingAddToRooms()
	if err != nil {
		t.Fatalf("consume: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected 0 rows, got %d", len(got))
	}
}

func TestRecordPendingAddToRoom_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	if err := st.RecordPendingAddToRoom("usr_bob", "rm_general", "os:1000"); err != nil {
		t.Fatalf("record: %v", err)
	}

	got, _ := st.ConsumePendingAddToRooms()
	if len(got) != 1 {
		t.Fatalf("expected 1 row, got %d", len(got))
	}
	row := got[0]
	if row.UserID != "usr_bob" {
		t.Errorf("UserID = %q, want usr_bob", row.UserID)
	}
	if row.RoomID != "rm_general" {
		t.Errorf("RoomID = %q, want rm_general", row.RoomID)
	}
	if row.InitiatedBy != "os:1000" {
		t.Errorf("InitiatedBy = %q, want os:1000", row.InitiatedBy)
	}
}

func TestConsumePendingAddToRooms_DeletesRows(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	st.RecordPendingAddToRoom("usr_a", "rm_a", "os:1000")
	st.RecordPendingAddToRoom("usr_b", "rm_b", "os:1000")

	first, _ := st.ConsumePendingAddToRooms()
	if len(first) != 2 {
		t.Fatalf("first consume: expected 2 rows, got %d", len(first))
	}

	second, _ := st.ConsumePendingAddToRooms()
	if len(second) != 0 {
		t.Errorf("second consume should be empty, got %d rows", len(second))
	}
}
