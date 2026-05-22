package store

// V3: AddRoomMemberIfMissing (RowsAffected source-of-truth) + the
// pending_add_to_room unique index → ErrAlreadyQueued sentinel.

import (
	"errors"
	"testing"
)

func TestAddRoomMemberIfMissing_ReportsInsert(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()
	st.SeedRooms(map[string]RoomSeed{"general": {Topic: "Chat"}})
	roomID := st.RoomDisplayNameToID("general")

	// First add: a genuinely new row → inserted == true.
	inserted, err := st.AddRoomMemberIfMissing(roomID, "usr_alice", 0)
	if err != nil {
		t.Fatalf("first add: %v", err)
	}
	if !inserted {
		t.Error("first AddRoomMemberIfMissing should report inserted=true")
	}
	if !st.IsRoomMemberByID(roomID, "usr_alice") {
		t.Error("alice should be a member after insert")
	}

	// Second add: row already exists → inserted == false (the proof the
	// helper uses to gate live side effects).
	inserted, err = st.AddRoomMemberIfMissing(roomID, "usr_alice", 0)
	if err != nil {
		t.Fatalf("second add: %v", err)
	}
	if inserted {
		t.Error("second AddRoomMemberIfMissing should report inserted=false for an existing membership")
	}
}

func TestRecordPendingAddToRoom_DuplicateReturnsErrAlreadyQueued(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	if err := st.RecordPendingAddToRoom("usr_alice", "rm_general", "os:1000"); err != nil {
		t.Fatalf("first enqueue: %v", err)
	}
	// Duplicate (user, room) trips the unique index → benign sentinel, not a
	// raw driver error.
	err = st.RecordPendingAddToRoom("usr_alice", "rm_general", "os:2000")
	if !errors.Is(err, ErrAlreadyQueued) {
		t.Fatalf("duplicate enqueue should return ErrAlreadyQueued, got %v", err)
	}

	// A different (user, room) still enqueues normally.
	if err := st.RecordPendingAddToRoom("usr_bob", "rm_general", "os:1000"); err != nil {
		t.Fatalf("distinct enqueue should succeed: %v", err)
	}

	// Exactly two rows survive (alice once, bob once).
	pending, err := st.ConsumePendingAddToRooms()
	if err != nil {
		t.Fatalf("consume: %v", err)
	}
	if len(pending) != 2 {
		t.Fatalf("want 2 queue rows (no duplicate), got %d", len(pending))
	}
}
