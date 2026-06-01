package store

import (
	"database/sql"
	"errors"
	"testing"
)

// TestDeleteMessage_ConcurrentGuard locks the F6 race guard: the destructive
// UPDATE is conditional on `deleted = 0`, so a second delete of an
// already-tombstoned message returns sql.ErrNoRows and CANNOT overwrite the
// first deleter or delete_signature — no attribution drift, no second tombstone.
func TestDeleteMessage_ConcurrentGuard(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	s.SeedRooms(map[string]RoomSeed{"general": {Topic: "Chat"}})
	room := s.RoomDisplayNameToID("general")
	if room == "" {
		t.Fatal("room seed failed")
	}
	if _, err := s.InsertRoomMessage(room, StoredMessage{ID: "m1", Sender: "alice", TS: 100, Payload: "p1"}); err != nil {
		t.Fatalf("insert: %v", err)
	}

	// First delete wins.
	if _, err := s.DeleteRoomMessageWithResult(room, "m1", "alice", "sig_alice"); err != nil {
		t.Fatalf("first delete: %v", err)
	}

	// Second delete of the now-tombstoned row must lose: ErrNoRows, no overwrite.
	if _, err := s.DeleteRoomMessageWithResult(room, "m1", "mallory", "sig_mallory"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("second delete err = %v, want sql.ErrNoRows", err)
	}

	// The first deleter + signature survive intact (sender is repurposed as
	// deleted_by on a tombstone).
	msgs, err := s.GetRoomMessages(room, 0, 10)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	var found bool
	for _, m := range msgs {
		if m.ID != "m1" {
			continue
		}
		found = true
		if !m.Deleted {
			t.Error("m1 must be a tombstone")
		}
		if m.Sender != "alice" {
			t.Errorf("first deleter overwritten: deleted_by = %q, want alice", m.Sender)
		}
		if m.DeleteSignature != "sig_alice" {
			t.Errorf("first signature overwritten: got %q, want sig_alice", m.DeleteSignature)
		}
	}
	if !found {
		t.Fatal("m1 not found after delete")
	}
}
