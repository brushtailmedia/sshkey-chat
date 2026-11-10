package store

// Phase 20 — tests for the per-room RecordRoomEvent / GetRoomEventsSince
// helpers. Parallel to the group-side Phase 14 tests; RoomDB creates the
// per-room DB file on demand with the shared group_events schema.

import (
	"testing"

	"github.com/brushtailmedia/sshkey-chat/internal/testutil"
)

func TestRecordRoomEvent_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	roomID := GenerateID("room_")
	if err := st.RecordRoomEvent(
		roomID, "leave", testutil.UserID("alice"), testutil.UserID("admin"), "removed", "", false, 1000,
	); err != nil {
		t.Fatalf("record: %v", err)
	}

	events, err := st.GetRoomEventsSince(roomID, 0)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	e := events[0]
	if e.Event != "leave" {
		t.Errorf("Event = %q, want leave", e.Event)
	}
	if e.User != testutil.UserID("alice") {
		t.Errorf("User = %q, want usr_alice", e.User)
	}
	if e.By != testutil.UserID("admin") {
		t.Errorf("By = %q, want usr_admin", e.By)
	}
	if e.Reason != "removed" {
		t.Errorf("Reason = %q, want removed", e.Reason)
	}
	if e.TS != 1000 {
		t.Errorf("TS = %d, want 1000", e.TS)
	}
}

// TestGetRoomEventsSince_Ordered verifies ts ASC ordering matches the
// sync replay expectation.
func TestGetRoomEventsSince_Ordered(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	roomID := GenerateID("room_")
	// Record out of order.
	st.RecordRoomEvent(roomID, "join", testutil.UserID("bob"), testutil.UserID("admin"), "", "", false, 3000)
	st.RecordRoomEvent(roomID, "leave", testutil.UserID("alice"), testutil.UserID("admin"), "removed", "", false, 1000)
	st.RecordRoomEvent(roomID, "topic", "", testutil.UserID("admin"), "", "new topic", false, 2000)

	events, err := st.GetRoomEventsSince(roomID, 0)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if len(events) != 3 {
		t.Fatalf("expected 3 events, got %d", len(events))
	}
	if events[0].TS != 1000 || events[1].TS != 2000 || events[2].TS != 3000 {
		t.Errorf("expected TS ASC order (1000, 2000, 3000), got %d, %d, %d",
			events[0].TS, events[1].TS, events[2].TS)
	}
}

// TestGetRoomEventsSince_RespectsSinceTS verifies the since filter —
// used by syncRoom's first_seen gate.
func TestGetRoomEventsSince_RespectsSinceTS(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	roomID := GenerateID("room_")
	st.RecordRoomEvent(roomID, "leave", testutil.UserID("a"), testutil.UserID("admin"), "", "", false, 500)
	st.RecordRoomEvent(roomID, "leave", testutil.UserID("b"), testutil.UserID("admin"), "", "", false, 1500)

	events, _ := st.GetRoomEventsSince(roomID, 1000)
	if len(events) != 1 {
		t.Fatalf("expected 1 event with ts >= 1000, got %d", len(events))
	}
	if events[0].User != testutil.UserID("b") {
		t.Errorf("expected usr_b (post-cutoff), got %q", events[0].User)
	}
}

// TestRecordRoomEvent_AllVocabulary verifies all 5 Phase 20 event types
// can be recorded.
func TestRecordRoomEvent_AllVocabulary(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	roomID := GenerateID("room_")
	for _, event := range []string{"leave", "join", "topic", "rename", "retire"} {
		if err := st.RecordRoomEvent(
			roomID, event, testutil.UserID("x"), testutil.UserID("admin"), "", "value", false, 1000,
		); err != nil {
			t.Errorf("RecordRoomEvent(%q): %v", event, err)
		}
	}

	events, _ := st.GetRoomEventsSince(roomID, 0)
	if len(events) != 5 {
		t.Errorf("expected 5 events (one per vocabulary type), got %d", len(events))
	}
}
