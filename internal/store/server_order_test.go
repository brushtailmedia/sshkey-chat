package store

import "testing"

// S1 (server_order foundation, history-state-model.md step 8): the server
// assigns a monotonic, per-conversation server_order on insert, returns the
// committed value, and read-back carries it. Soft-deleted tombstones keep their
// server_order so deletion changes rendering, not commit-order position.
func TestServerOrder_MonotonicPerConversationAndTombstonePreserved(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	s.SeedRooms(map[string]RoomSeed{"general": {Topic: "Chat"}, "other": {Topic: "Other"}})
	roomA := s.RoomDisplayNameToID("general")
	roomB := s.RoomDisplayNameToID("other")
	if roomA == "" || roomB == "" {
		t.Fatal("room seed failed")
	}

	// Two inserts into room A return monotonically increasing server_order.
	o1, err := s.InsertRoomMessage(roomA, StoredMessage{ID: "m1", Sender: "alice", TS: 100, Payload: "p1"})
	if err != nil {
		t.Fatalf("insert m1: %v", err)
	}
	o2, err := s.InsertRoomMessage(roomA, StoredMessage{ID: "m2", Sender: "bob", TS: 101, Payload: "p2"})
	if err != nil {
		t.Fatalf("insert m2: %v", err)
	}
	if o1 <= 0 || o2 <= o1 {
		t.Fatalf("server_order must be positive and monotonic: o1=%d o2=%d", o1, o2)
	}

	// Read-back carries the assigned server_order for each row.
	got := map[string]int64{}
	msgs, err := s.GetRoomMessages(roomA, 0, 10)
	if err != nil {
		t.Fatalf("get room A: %v", err)
	}
	for _, m := range msgs {
		got[m.ID] = m.ServerOrder
	}
	if got["m1"] != o1 || got["m2"] != o2 {
		t.Errorf("read-back server_order mismatch: m1=%d (want %d), m2=%d (want %d)", got["m1"], o1, got["m2"], o2)
	}

	// Per-conversation: room B has its own AUTOINCREMENT, so its first message
	// shares the server_order value of room A's first — proof the counter is
	// per-conversation, not global (a global counter would give roomB first=3).
	ob1, err := s.InsertRoomMessage(roomB, StoredMessage{ID: "b1", Sender: "alice", TS: 200, Payload: "pb1"})
	if err != nil {
		t.Fatalf("insert b1: %v", err)
	}
	if ob1 != o1 {
		t.Errorf("server_order should be per-conversation: roomB first=%d, roomA first=%d (want equal)", ob1, o1)
	}

	// Soft-delete m1; the tombstone keeps its original server_order and the
	// delete result exposes that order for live deleted broadcasts.
	deleted, err := s.DeleteRoomMessageWithResult(roomA, "m1", "bob")
	if err != nil {
		t.Fatalf("delete m1: %v", err)
	}
	if deleted.ServerOrder != o1 {
		t.Errorf("delete result server_order = %d, want preserved %d", deleted.ServerOrder, o1)
	}
	msgs, err = s.GetRoomMessages(roomA, 0, 10)
	if err != nil {
		t.Fatalf("get room A after delete: %v", err)
	}
	var found bool
	for _, m := range msgs {
		if m.ID == "m1" {
			found = true
			if !m.Deleted {
				t.Error("m1 should be a tombstone after delete")
			}
			if m.ServerOrder != o1 {
				t.Errorf("tombstone server_order = %d, want preserved %d", m.ServerOrder, o1)
			}
		}
	}
	if !found {
		t.Error("deleted m1 should still appear (tombstone) in read-back")
	}
}
