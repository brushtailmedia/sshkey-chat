package server

// V3: room_added_to live emission + self-join exclusion + defense-in-depth
// stale-row guards in processPendingAddToRoom. See
// fix-pending-add-to-room-bypass-v3.md.

import (
	"encoding/json"
	"testing"

	"github.com/brushtailmedia/sshkey-chat/internal/protocol"
)

// v3FrameType returns the "type" field of a captured wire frame.
func v3FrameType(t *testing.T, raw json.RawMessage) string {
	t.Helper()
	var env struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("parse envelope: %v", err)
	}
	return env.Type
}

// A CLI add to an active room emits room_added_to to EVERY session of the
// newly-added user, broadcasts room_event{join} to the REST of the room, and
// never sends the added user a self-join system message.
func TestProcessPendingAddToRoom_EmitsRoomAddedToAndExcludesSelf(t *testing.T) {
	s := newTestServer(t)
	engID := s.store.RoomDisplayNameToID("engineering")

	if err := s.store.AddRoomMember(engID, "bob", 0); err != nil {
		t.Fatalf("add member: %v", err)
	}
	if err := s.store.RecordPendingAddToRoom("bob", engID, "os:1000"); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	// Seed an epoch so the rotation-trigger path is clean.
	if err := s.store.StoreEpochKey(engID, 1, "alice", "wk_e1_alice"); err != nil {
		t.Fatalf("seed epoch: %v", err)
	}
	s.epochs.getOrCreate(engID, 1)

	alice := testClientFor("alice", "dev_alice") // existing engineering member
	bob1 := testClientFor("bob", "dev_bob1")
	bob2 := testClientFor("bob", "dev_bob2")
	s.mu.Lock()
	s.clients["dev_alice"] = alice.Client
	s.clients["dev_bob1"] = bob1.Client
	s.clients["dev_bob2"] = bob2.Client
	s.mu.Unlock()

	s.processPendingAddToRoom()

	// Every bob session: room_added_to present, self-join room_event absent.
	for name, bc := range map[string]*captureClient{"dev_bob1": bob1, "dev_bob2": bob2} {
		var sawAddedTo, sawSelfJoin bool
		var addedTo protocol.RoomAddedTo
		for _, raw := range bc.messages() {
			switch v3FrameType(t, raw) {
			case "room_added_to":
				if err := json.Unmarshal(raw, &addedTo); err != nil {
					t.Fatalf("parse room_added_to: %v", err)
				}
				sawAddedTo = true
			case "room_event":
				var ev protocol.RoomEvent
				if err := json.Unmarshal(raw, &ev); err != nil {
					t.Fatalf("parse room_event: %v", err)
				}
				if ev.Event == "join" && ev.User == "bob" {
					sawSelfJoin = true
				}
			}
		}
		if !sawAddedTo {
			t.Errorf("%s: expected room_added_to", name)
		}
		if sawSelfJoin {
			t.Errorf("%s: should NOT receive a self-join room_event", name)
		}
		if sawAddedTo {
			if addedTo.Room != engID {
				t.Errorf("%s: room_added_to.Room = %q, want %q", name, addedTo.Room, engID)
			}
			if addedTo.AddedBy != "os:1000" {
				t.Errorf("%s: room_added_to.AddedBy = %q, want os:1000", name, addedTo.AddedBy)
			}
			found := false
			for _, m := range addedTo.Members {
				if m == "bob" {
					found = true
				}
			}
			if !found {
				t.Errorf("%s: room_added_to.Members should include bob, got %v", name, addedTo.Members)
			}
		}
	}

	// alice (existing member, not the added user): join broadcast yes,
	// room_added_to no.
	var aliceSawJoin, aliceSawAddedTo bool
	for _, raw := range alice.messages() {
		switch v3FrameType(t, raw) {
		case "room_event":
			var ev protocol.RoomEvent
			if err := json.Unmarshal(raw, &ev); err == nil && ev.Event == "join" && ev.User == "bob" {
				aliceSawJoin = true
			}
		case "room_added_to":
			aliceSawAddedTo = true
		}
	}
	if !aliceSawJoin {
		t.Error("alice should receive room_event join for bob")
	}
	if aliceSawAddedTo {
		t.Error("alice (not the added user) should NOT receive room_added_to")
	}
}

// Defense-in-depth: a queued row whose room was retired after enqueue fires no
// side effects (no room_added_to, no join broadcast).
func TestProcessPendingAddToRoom_SkipsRetiredRoom(t *testing.T) {
	s := newTestServer(t)
	engID := s.store.RoomDisplayNameToID("engineering")
	if err := s.store.AddRoomMember(engID, "bob", 0); err != nil {
		t.Fatalf("add member: %v", err)
	}
	if err := s.store.RecordPendingAddToRoom("bob", engID, "os:1000"); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	if err := s.store.SetRoomRetired(engID, "os:1000", ""); err != nil {
		t.Fatalf("retire room: %v", err)
	}

	bob := testClientFor("bob", "dev_bob")
	alice := testClientFor("alice", "dev_alice")
	s.mu.Lock()
	s.clients["dev_bob"] = bob.Client
	s.clients["dev_alice"] = alice.Client
	s.mu.Unlock()

	s.processPendingAddToRoom()

	if n := len(bob.messages()); n != 0 {
		t.Errorf("retired room: bob should receive nothing, got %d", n)
	}
	if n := len(alice.messages()); n != 0 {
		t.Errorf("retired room: alice should receive nothing, got %d", n)
	}
}

// Defense-in-depth: a queued row whose user was retired after enqueue (the
// enqueue→dequeue race) fires no side effects. SetUserRetired only flips the
// flag (keeps room_members), so this exercises the retired-USER guard, not the
// non-member skip.
func TestProcessPendingAddToRoom_SkipsRetiredUser(t *testing.T) {
	s := newTestServer(t)
	engID := s.store.RoomDisplayNameToID("engineering")
	if err := s.store.AddRoomMember(engID, "bob", 0); err != nil {
		t.Fatalf("add member: %v", err)
	}
	if err := s.store.RecordPendingAddToRoom("bob", engID, "os:1000"); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	if err := s.store.SetUserRetired("bob", "test_policy"); err != nil {
		t.Fatalf("retire user: %v", err)
	}
	// Confirm bob is still a member, so the retired-user guard is what fires.
	if !s.store.IsRoomMemberByID(engID, "bob") {
		t.Fatal("precondition: bob should still be a room member after SetUserRetired")
	}

	bob := testClientFor("bob", "dev_bob")
	alice := testClientFor("alice", "dev_alice")
	s.mu.Lock()
	s.clients["dev_bob"] = bob.Client
	s.clients["dev_alice"] = alice.Client
	s.mu.Unlock()

	s.processPendingAddToRoom()

	if n := len(bob.messages()); n != 0 {
		t.Errorf("retired user: bob should receive nothing, got %d", n)
	}
	if n := len(alice.messages()); n != 0 {
		t.Errorf("retired user: alice should receive nothing, got %d", n)
	}
}
