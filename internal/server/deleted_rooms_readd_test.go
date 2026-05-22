package server

// Regression: sendDeletedRooms must not tell a client to purge a room the
// user is currently a member of. A stale deleted_rooms row can survive a
// re-add (delete writes deleted_rooms; a re-add that didn't clear it leaves
// it behind), and without this filter the handshake would purge the room the
// user just rejoined. Mirrors sendLeftRooms' defensive current-member skip.
// See stale-deleted-room-readd-fix.md.

import (
	"encoding/json"
	"testing"

	"github.com/brushtailmedia/sshkey-chat/internal/protocol"
)

func TestSendDeletedRooms_FiltersCurrentMemberRooms(t *testing.T) {
	s := newTestServer(t)
	generalID := s.store.RoomDisplayNameToID("general")
	if generalID == "" {
		t.Fatal("seed should have general room")
	}

	bob := testClientFor("bob", "dev_bob_deldrooms")

	// bob is a current member of general. Record a STALE deleted_rooms row
	// for it (simulates "deleted then re-added" where the row outlived the
	// re-add) — it must NOT be emitted, or his devices would purge a room
	// he's currently in.
	if _, err := s.store.AddRoomMemberIfMissing(generalID, "bob", 0); err != nil {
		t.Fatalf("ensure membership: %v", err)
	}
	if err := s.store.RecordRoomDeletion("bob", generalID); err != nil {
		t.Fatalf("record general deletion: %v", err)
	}

	// A genuinely-deleted room bob is NOT a member of — the offline catchup
	// must still emit this one.
	const goneRoom = "room_gone0000000000000001"
	if err := s.store.RecordRoomDeletion("bob", goneRoom); err != nil {
		t.Fatalf("record gone deletion: %v", err)
	}

	s.sendDeletedRooms(bob.Client)

	msgs := bob.messages()
	if len(msgs) != 1 {
		t.Fatalf("expected exactly 1 deleted_rooms frame, got %d", len(msgs))
	}
	var list protocol.DeletedRoomsList
	if err := json.Unmarshal(msgs[0], &list); err != nil {
		t.Fatalf("parse deleted_rooms: %v", err)
	}

	var sawGeneral, sawGone bool
	for _, r := range list.Rooms {
		if r == generalID {
			sawGeneral = true
		}
		if r == goneRoom {
			sawGone = true
		}
	}
	if sawGeneral {
		t.Errorf("deleted_rooms must not list a room the user is currently a member of (%s); got %v", generalID, list.Rooms)
	}
	if !sawGone {
		t.Errorf("deleted_rooms should still list the non-member deleted room %q; got %v", goneRoom, list.Rooms)
	}
}

// TestSendDeletedRooms_AllCurrentMemberRoomsIsNoFrame verifies that when every
// deleted_rooms row is for a room the user has since rejoined, the filter
// drops them all and no deleted_rooms frame is sent at all.
func TestSendDeletedRooms_AllCurrentMemberRoomsIsNoFrame(t *testing.T) {
	s := newTestServer(t)
	generalID := s.store.RoomDisplayNameToID("general")

	bob := testClientFor("bob", "dev_bob_deldrooms_none")
	if _, err := s.store.AddRoomMemberIfMissing(generalID, "bob", 0); err != nil {
		t.Fatalf("ensure membership: %v", err)
	}
	if err := s.store.RecordRoomDeletion("bob", generalID); err != nil {
		t.Fatalf("record deletion: %v", err)
	}

	s.sendDeletedRooms(bob.Client)

	if msgs := bob.messages(); len(msgs) != 0 {
		t.Errorf("expected no deleted_rooms frame when all rows are current-member rooms, got %d: %s", len(msgs), msgs)
	}
}
