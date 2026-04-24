package store

// Phase 16 Gap 1 — tests for the pending_room_updates queue helpers
// AND the SetRoomTopic / SetRoomDisplayName store methods.
//
// Coverage:
//   - SetRoomTopic: happy path, missing room, retired room
//   - SetRoomDisplayName: happy path, missing room, retired room,
//     duplicate name (case-insensitive)
//   - queue: empty consume, round-trip per action, atomic delete,
//     order preservation, schema CHECK on action enum

import (
	"strings"
	"testing"
)

// helper: insert a room and return its ID.
func insertTestRoom(t *testing.T, st *Store, name, topic string) string {
	t.Helper()
	id := GenerateRoomID()
	_, err := st.RoomsDB().Exec(
		`INSERT INTO rooms (id, display_name, topic) VALUES (?, ?, ?)`,
		id, name, topic,
	)
	if err != nil {
		t.Fatalf("insert room %q: %v", name, err)
	}
	return id
}

// --- SetRoomTopic tests ---

func TestSetRoomTopic_HappyPath(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	id := insertTestRoom(t, st, "general", "old topic")

	if err := st.SetRoomTopic(id, "new topic"); err != nil {
		t.Fatalf("set topic: %v", err)
	}

	room, _ := st.GetRoomByID(id)
	if room.Topic != "new topic" {
		t.Errorf("topic = %q, want new topic", room.Topic)
	}
}

func TestSetRoomTopic_MissingRoom(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	err = st.SetRoomTopic("nonexistent", "topic")
	if err == nil {
		t.Fatal("expected error for missing room")
	}
}

func TestSetRoomTopic_RetiredRoom(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	id := insertTestRoom(t, st, "general", "topic")
	if err := st.SetRoomRetired(id, "alice", "test"); err != nil {
		t.Fatalf("retire: %v", err)
	}

	err = st.SetRoomTopic(id, "new topic")
	if err == nil {
		t.Fatal("expected error for retired room")
	}
	if !strings.Contains(err.Error(), "retired") {
		t.Errorf("error should mention 'retired', got: %v", err)
	}
}

// --- SetRoomDisplayName tests ---

func TestSetRoomDisplayName_HappyPath(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	id := insertTestRoom(t, st, "general", "topic")

	if err := st.SetRoomDisplayName(id, "engineering"); err != nil {
		t.Fatalf("rename: %v", err)
	}

	room, _ := st.GetRoomByID(id)
	if room.DisplayName != "engineering" {
		t.Errorf("display_name = %q, want engineering", room.DisplayName)
	}
}

func TestSetRoomDisplayName_MissingRoom(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	err = st.SetRoomDisplayName("nonexistent", "newname")
	if err == nil {
		t.Fatal("expected error for missing room")
	}
}

func TestSetRoomDisplayName_RetiredRoom(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	id := insertTestRoom(t, st, "general", "topic")
	st.SetRoomRetired(id, "alice", "test")

	err = st.SetRoomDisplayName(id, "engineering")
	if err == nil {
		t.Fatal("expected error for retired room")
	}
}

func TestSetRoomDisplayName_Duplicate(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	id1 := insertTestRoom(t, st, "general", "")
	insertTestRoom(t, st, "engineering", "")

	// Try to rename general → engineering (case-insensitive collision).
	err = st.SetRoomDisplayName(id1, "ENGINEERING")
	if err == nil {
		t.Fatal("expected duplicate display name error")
	}
	if !strings.Contains(err.Error(), "already in use") {
		t.Errorf("error should mention 'already in use', got: %v", err)
	}
}

// --- queue tests ---

func TestConsumePendingRoomUpdates_Empty(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	got, err := st.ConsumePendingRoomUpdates()
	if err != nil {
		t.Fatalf("consume: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected 0 rows, got %d", len(got))
	}
}

func TestRecordAndConsumePendingRoomUpdate_UpdateTopic(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	if err := st.RecordPendingRoomUpdate("rm_general", RoomUpdateActionUpdateTopic, "os:1000", "test_value"); err != nil {
		t.Fatalf("record: %v", err)
	}

	got, _ := st.ConsumePendingRoomUpdates()
	if len(got) != 1 {
		t.Fatalf("expected 1 row, got %d", len(got))
	}
	if got[0].RoomID != "rm_general" {
		t.Errorf("RoomID = %q", got[0].RoomID)
	}
	if got[0].Action != RoomUpdateActionUpdateTopic {
		t.Errorf("Action = %q, want update-topic", got[0].Action)
	}
	if got[0].ChangedBy != "os:1000" {
		t.Errorf("ChangedBy = %q", got[0].ChangedBy)
	}
}

func TestRecordAndConsumePendingRoomUpdate_RenameRoom(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	st.RecordPendingRoomUpdate("rm_general", RoomUpdateActionRenameRoom, "os:1000", "test_value")
	got, _ := st.ConsumePendingRoomUpdates()
	if len(got) != 1 || got[0].Action != RoomUpdateActionRenameRoom {
		t.Errorf("expected 1 rename-room row, got %+v", got)
	}
}

func TestConsumePendingRoomUpdates_AtomicDelete(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	st.RecordPendingRoomUpdate("rm_a", RoomUpdateActionUpdateTopic, "os:1000", "test_value")
	st.RecordPendingRoomUpdate("rm_b", RoomUpdateActionRenameRoom, "os:1000", "test_value")

	first, _ := st.ConsumePendingRoomUpdates()
	if len(first) != 2 {
		t.Fatalf("first consume: expected 2 rows, got %d", len(first))
	}

	second, _ := st.ConsumePendingRoomUpdates()
	if len(second) != 0 {
		t.Errorf("second consume should be empty, got %d rows", len(second))
	}
}

func TestRecordPendingRoomUpdate_PreservesOrder(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	rooms := []string{"rm_alpha", "rm_beta", "rm_gamma", "rm_delta"}
	for _, r := range rooms {
		st.RecordPendingRoomUpdate(r, RoomUpdateActionUpdateTopic, "os:1000", "test_value")
	}

	got, _ := st.ConsumePendingRoomUpdates()
	if len(got) != len(rooms) {
		t.Fatalf("expected %d rows, got %d", len(rooms), len(got))
	}
	for i, row := range got {
		if row.RoomID != rooms[i] {
			t.Errorf("row %d RoomID = %q, want %q", i, row.RoomID, rooms[i])
		}
	}
}

func TestRecordPendingRoomUpdate_RejectsUnknownAction(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	err = st.RecordPendingRoomUpdate("rm_general", RoomUpdateAction("bogus"), "os:1000", "test_value")
	if err == nil {
		t.Fatal("expected CHECK constraint to reject unknown action")
	}
}
