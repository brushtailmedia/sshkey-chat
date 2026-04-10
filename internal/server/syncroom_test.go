package server

import (
	"encoding/json"
	"testing"

	"github.com/brushtailmedia/sshkey-chat/internal/protocol"
)

// Phase 12 Chunk 5 — sendRetiredRooms and sendDeletedRooms tests.

// ============================================================================
// sendRetiredRooms
// ============================================================================

// TestSendRetiredRooms_None verifies the no-op case when no retired
// rooms exist.
func TestSendRetiredRooms_None(t *testing.T) {
	s := newTestServer(t)
	cc := testClientFor("bob", "dev_bob_1")

	s.sendRetiredRooms(cc.Client)
	if msgs := cc.messages(); len(msgs) != 0 {
		t.Errorf("expected no message when no retired rooms exist, got %d", len(msgs))
	}
}

// TestSendRetiredRooms_DeliversListForMember verifies that a connected
// member of a retired room receives the retired_rooms list with the
// post-retirement (suffixed) display name.
func TestSendRetiredRooms_DeliversListForMember(t *testing.T) {
	s := newTestServer(t)
	generalID := s.store.RoomDisplayNameToID("general")
	retireRoomForTest(t, s, generalID)

	bob := testClientFor("bob", "dev_bob_1")
	s.sendRetiredRooms(bob.Client)

	msgs := bob.messages()
	if len(msgs) != 1 {
		t.Fatalf("expected 1 retired_rooms message, got %d", len(msgs))
	}
	var list protocol.RetiredRoomsList
	if err := json.Unmarshal(msgs[0], &list); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if list.Type != "retired_rooms" {
		t.Errorf("type = %q, want retired_rooms", list.Type)
	}
	if len(list.Rooms) != 1 {
		t.Fatalf("expected 1 room in list, got %d", len(list.Rooms))
	}
	if list.Rooms[0].Room != generalID {
		t.Errorf("room = %q, want %q", list.Rooms[0].Room, generalID)
	}
	if list.Rooms[0].DisplayName == "general" {
		t.Error("display name should be suffixed, not the original")
	}
}

// TestSendRetiredRooms_FiltersNonMembers verifies that a user who is
// NOT a member of any retired room receives no list (Q8 filter).
func TestSendRetiredRooms_FiltersNonMembers(t *testing.T) {
	s := newTestServer(t)

	// engineering is only alice's room in the seed. Retire it.
	engineeringID := s.store.RoomDisplayNameToID("engineering")
	retireRoomForTest(t, s, engineeringID)

	// Bob is NOT a member of engineering, so he shouldn't see it
	bob := testClientFor("bob", "dev_bob_1")
	s.sendRetiredRooms(bob.Client)

	msgs := bob.messages()
	if len(msgs) != 0 {
		t.Errorf("non-member should see 0 retired rooms, got %d messages", len(msgs))
	}

	// Alice IS a member, she should see it
	alice := testClientFor("alice", "dev_alice_1")
	s.sendRetiredRooms(alice.Client)

	aliceMsgs := alice.messages()
	if len(aliceMsgs) != 1 {
		t.Fatalf("alice should see 1 retired room, got %d messages", len(aliceMsgs))
	}
}

// TestSendRetiredRooms_FiltersUsersWhoLeftBefore verifies Q8: a user
// who voluntarily left a room before it was retired does NOT see the
// retirement in their catchup list. Membership is the filter.
func TestSendRetiredRooms_FiltersUsersWhoLeftBefore(t *testing.T) {
	s := newTestServer(t)
	generalID := s.store.RoomDisplayNameToID("general")

	// Bob leaves general BEFORE it's retired
	if err := s.store.RemoveRoomMember(generalID, "bob"); err != nil {
		t.Fatalf("RemoveRoomMember: %v", err)
	}

	// Admin later retires general
	retireRoomForTest(t, s, generalID)

	// Bob should NOT see the retirement in his catchup list — he left
	// before the retirement happened
	bob := testClientFor("bob", "dev_bob_1")
	s.sendRetiredRooms(bob.Client)

	if msgs := bob.messages(); len(msgs) != 0 {
		t.Errorf("bob left before retirement; should see 0 retired rooms, got %d messages", len(msgs))
	}

	// Carol is still a member, she should see it
	carol := testClientFor("carol", "dev_carol_1")
	s.sendRetiredRooms(carol.Client)
	if msgs := carol.messages(); len(msgs) != 1 {
		t.Errorf("carol (still member) should see 1 retired room, got %d", len(msgs))
	}
}

// ============================================================================
// sendDeletedRooms
// ============================================================================

// TestSendDeletedRooms_None verifies the no-op case when the user has
// no deletion records.
func TestSendDeletedRooms_None(t *testing.T) {
	s := newTestServer(t)
	cc := testClientFor("bob", "dev_bob_1")

	s.sendDeletedRooms(cc.Client)
	if msgs := cc.messages(); len(msgs) != 0 {
		t.Errorf("expected no message when no deletions exist, got %d", len(msgs))
	}
}

// TestSendDeletedRooms_DeliversListAfterDelete verifies that after a
// user /delete's a room, the next call to sendDeletedRooms (e.g. a
// reconnecting device) delivers the deleted_rooms catchup list.
func TestSendDeletedRooms_DeliversListAfterDelete(t *testing.T) {
	s := newTestServer(t)
	enableActiveRoomLeave(t, s)

	generalID := s.store.RoomDisplayNameToID("general")

	// Device A runs /delete
	deviceA := testClientFor("bob", "dev_bob_A")
	s.mu.Lock()
	s.clients["dev_bob_A"] = deviceA.Client
	s.mu.Unlock()
	raw, _ := json.Marshal(protocol.DeleteRoom{Type: "delete_room", Room: generalID})
	s.handleDeleteRoom(deviceA.Client, raw)

	// Device B was offline — simulate its handshake calling sendDeletedRooms
	deviceB := testClientFor("bob", "dev_bob_B")
	s.sendDeletedRooms(deviceB.Client)

	msgs := deviceB.messages()
	if len(msgs) != 1 {
		t.Fatalf("device B should have received 1 deleted_rooms message, got %d", len(msgs))
	}
	var list protocol.DeletedRoomsList
	if err := json.Unmarshal(msgs[0], &list); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if list.Type != "deleted_rooms" {
		t.Errorf("type = %q, want deleted_rooms", list.Type)
	}
	if len(list.Rooms) != 1 || list.Rooms[0] != generalID {
		t.Errorf("expected [%s] in catchup list, got %v", generalID, list.Rooms)
	}
}

// TestSendDeletedRooms_ScopedToUser verifies that one user's deletion
// records don't leak into another user's catchup list.
func TestSendDeletedRooms_ScopedToUser(t *testing.T) {
	s := newTestServer(t)

	// alice records a deletion for some room
	if err := s.store.RecordRoomDeletion("alice", "room_x"); err != nil {
		t.Fatalf("RecordRoomDeletion: %v", err)
	}

	// Bob should see nothing
	bob := testClientFor("bob", "dev_bob_1")
	s.sendDeletedRooms(bob.Client)
	if msgs := bob.messages(); len(msgs) != 0 {
		t.Errorf("bob should see 0 deletions, got %d messages", len(msgs))
	}

	// Alice should see her deletion
	alice := testClientFor("alice", "dev_alice_1")
	s.sendDeletedRooms(alice.Client)
	aliceMsgs := alice.messages()
	if len(aliceMsgs) != 1 {
		t.Fatalf("alice should see 1 deletion, got %d", len(aliceMsgs))
	}
	var list protocol.DeletedRoomsList
	json.Unmarshal(aliceMsgs[0], &list)
	if len(list.Rooms) != 1 || list.Rooms[0] != "room_x" {
		t.Errorf("expected [room_x], got %v", list.Rooms)
	}
}

// TestSendDeletedRooms_SurvivesLastMemberCleanup verifies the critical
// ordering constraint: a user who was the last member of a room and
// ran /delete (triggering the cleanup cascade) should still see the
// deletion in their catchup list from another device.
func TestSendDeletedRooms_SurvivesLastMemberCleanup(t *testing.T) {
	s := newTestServer(t)
	enableActiveRoomLeave(t, s)

	// engineering has only alice per the seed
	engineeringID := s.store.RoomDisplayNameToID("engineering")

	deviceA := testClientFor("alice", "dev_alice_A")
	s.mu.Lock()
	s.clients["dev_alice_A"] = deviceA.Client
	s.mu.Unlock()
	raw, _ := json.Marshal(protocol.DeleteRoom{Type: "delete_room", Room: engineeringID})
	s.handleDeleteRoom(deviceA.Client, raw)

	// Room should be cleaned up (last member)
	r, _ := s.store.GetRoomByID(engineeringID)
	if r != nil {
		t.Error("room should be cleaned up after last-member /delete")
	}

	// Device B reconnects and runs sendDeletedRooms — must still see
	// engineering in the list despite the cleanup
	deviceB := testClientFor("alice", "dev_alice_B")
	s.sendDeletedRooms(deviceB.Client)

	msgs := deviceB.messages()
	if len(msgs) != 1 {
		t.Fatalf("device B should receive deleted_rooms catchup, got %d messages", len(msgs))
	}
	var list protocol.DeletedRoomsList
	json.Unmarshal(msgs[0], &list)
	found := false
	for _, id := range list.Rooms {
		if id == engineeringID {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("catchup list should contain engineering despite cleanup, got %v", list.Rooms)
	}
}
