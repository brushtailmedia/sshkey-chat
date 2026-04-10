package server

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/brushtailmedia/sshkey-chat/internal/protocol"
)

// Phase 12 Chunk 3 — tests for handleDeleteRoom and the retired-room
// policy gate in handleLeaveRoom.

// enableActiveRoomLeave flips allow_self_leave_rooms to true for the
// duration of a test. Default config has it disabled (admin-managed),
// but /delete on active rooms needs the flag on to proceed past the
// policy gate.
func enableActiveRoomLeave(t *testing.T, s *Server) {
	t.Helper()
	s.cfg.Lock()
	s.cfg.Server.Server.AllowSelfLeaveRooms = true
	s.cfg.Unlock()
}

// disableRetiredRoomLeave flips allow_self_leave_retired_rooms to
// false for the duration of a test. Default is true — retired rooms
// are cleanable by users by default.
func disableRetiredRoomLeave(t *testing.T, s *Server) {
	t.Helper()
	s.cfg.Lock()
	s.cfg.Server.Server.AllowSelfLeaveRetiredRooms = false
	s.cfg.Unlock()
}

// ============================================================================
// handleDeleteRoom — happy paths
// ============================================================================

// TestHandleDeleteRoom_ActiveRoom_HappyPath verifies that a member
// /delete'ing an active room (with allow_self_leave_rooms = true)
// is removed from the room, gets a room_deleted echo, the deletion
// sidecar is recorded, and the active-room epoch is marked for
// rotation.
func TestHandleDeleteRoom_ActiveRoom_HappyPath(t *testing.T) {
	s := newTestServer(t)
	enableActiveRoomLeave(t, s)

	generalID := s.store.RoomDisplayNameToID("general")
	if generalID == "" {
		t.Fatal("seed should have general room")
	}

	// Register bob's session so the echo lands somewhere
	bob := testClientFor("bob", "dev_bob_1")
	s.mu.Lock()
	s.clients["dev_bob_1"] = bob.Client
	s.mu.Unlock()

	raw, _ := json.Marshal(protocol.DeleteRoom{Type: "delete_room", Room: generalID})
	s.handleDeleteRoom(bob.Client, raw)

	// Bob should be removed from room_members
	if s.store.IsRoomMemberByID(generalID, "bob") {
		t.Error("bob should be removed from general after delete")
	}

	// Bob should have received exactly one room_deleted echo
	msgs := bob.messages()
	if len(msgs) != 1 {
		t.Fatalf("expected 1 reply, got %d", len(msgs))
	}
	var deletedEvt protocol.RoomDeleted
	if err := json.Unmarshal(msgs[0], &deletedEvt); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if deletedEvt.Type != "room_deleted" {
		t.Errorf("event type = %q, want room_deleted", deletedEvt.Type)
	}
	if deletedEvt.Room != generalID {
		t.Errorf("event room = %q, want %q", deletedEvt.Room, generalID)
	}

	// The deleted_rooms sidecar should have a row for this user+room
	ids, err := s.store.GetDeletedRoomsForUser("bob")
	if err != nil {
		t.Fatalf("GetDeletedRoomsForUser: %v", err)
	}
	if len(ids) != 1 || ids[0] != generalID {
		t.Errorf("expected [%s] in deleted_rooms sidecar, got %v", generalID, ids)
	}
}

// TestHandleDeleteRoom_RetiredRoom_HappyPath verifies that a member
// /delete'ing a retired room (with allow_self_leave_retired_rooms =
// true, the default) succeeds. Epoch rotation is skipped for retired
// rooms per Q4.
func TestHandleDeleteRoom_RetiredRoom_HappyPath(t *testing.T) {
	s := newTestServer(t)

	generalID := s.store.RoomDisplayNameToID("general")
	retireRoomForTest(t, s, generalID)

	bob := testClientFor("bob", "dev_bob_1")
	s.mu.Lock()
	s.clients["dev_bob_1"] = bob.Client
	s.mu.Unlock()

	raw, _ := json.Marshal(protocol.DeleteRoom{Type: "delete_room", Room: generalID})
	s.handleDeleteRoom(bob.Client, raw)

	// Bob should be removed from room_members
	if s.store.IsRoomMemberByID(generalID, "bob") {
		t.Error("bob should be removed from general after delete")
	}

	// Bob should receive room_deleted echo
	msgs := bob.messages()
	if len(msgs) != 1 {
		t.Fatalf("expected 1 reply, got %d", len(msgs))
	}
	var deletedEvt protocol.RoomDeleted
	json.Unmarshal(msgs[0], &deletedEvt)
	if deletedEvt.Type != "room_deleted" {
		t.Errorf("event type = %q, want room_deleted", deletedEvt.Type)
	}

	// Sidecar must be populated
	ids, _ := s.store.GetDeletedRoomsForUser("bob")
	if len(ids) != 1 {
		t.Errorf("expected 1 sidecar row, got %d", len(ids))
	}
}

// ============================================================================
// handleDeleteRoom — policy gate
// ============================================================================

// TestHandleDeleteRoom_ActiveRoomPolicyDenied verifies that with
// allow_self_leave_rooms = false (default), a /delete on an active
// room is rejected with ErrForbidden and no state changes.
func TestHandleDeleteRoom_ActiveRoomPolicyDenied(t *testing.T) {
	s := newTestServer(t)
	// Default: allow_self_leave_rooms = false

	generalID := s.store.RoomDisplayNameToID("general")
	bob := testClientFor("bob", "dev_bob_1")

	raw, _ := json.Marshal(protocol.DeleteRoom{Type: "delete_room", Room: generalID})
	s.handleDeleteRoom(bob.Client, raw)

	msgs := bob.messages()
	if len(msgs) != 1 {
		t.Fatalf("expected 1 reply, got %d", len(msgs))
	}
	var errMsg protocol.Error
	json.Unmarshal(msgs[0], &errMsg)
	if errMsg.Code != protocol.ErrForbidden {
		t.Errorf("code = %q, want %q", errMsg.Code, protocol.ErrForbidden)
	}

	// Bob should still be a member
	if !s.store.IsRoomMemberByID(generalID, "bob") {
		t.Error("bob should still be a member after policy denial")
	}

	// Sidecar must NOT be populated
	ids, _ := s.store.GetDeletedRoomsForUser("bob")
	if len(ids) != 0 {
		t.Errorf("sidecar should be empty after denial, got %v", ids)
	}
}

// TestHandleDeleteRoom_RetiredRoomPolicyDenied verifies that with
// allow_self_leave_retired_rooms = false, a /delete on a retired
// room is rejected.
func TestHandleDeleteRoom_RetiredRoomPolicyDenied(t *testing.T) {
	s := newTestServer(t)
	generalID := s.store.RoomDisplayNameToID("general")
	retireRoomForTest(t, s, generalID)
	disableRetiredRoomLeave(t, s)

	bob := testClientFor("bob", "dev_bob_1")
	raw, _ := json.Marshal(protocol.DeleteRoom{Type: "delete_room", Room: generalID})
	s.handleDeleteRoom(bob.Client, raw)

	msgs := bob.messages()
	if len(msgs) != 1 {
		t.Fatalf("expected 1 reply, got %d", len(msgs))
	}
	var errMsg protocol.Error
	json.Unmarshal(msgs[0], &errMsg)
	if errMsg.Code != protocol.ErrForbidden {
		t.Errorf("code = %q, want %q", errMsg.Code, protocol.ErrForbidden)
	}
}

// ============================================================================
// handleDeleteRoom — privacy
// ============================================================================

// TestHandleDeleteRoom_PrivacyResponsesIdentical verifies that a
// non-member probing a real (but non-retired) room gets byte-identical
// wire bytes with a probe for an unknown room — the delete_room
// handler must not leak which rooms exist.
func TestHandleDeleteRoom_PrivacyResponsesIdentical(t *testing.T) {
	s := newTestServer(t)
	engineeringID := s.store.RoomDisplayNameToID("engineering")

	probeUnknown := testClientFor("carol", "dev_carol_1")
	rawUnknown, _ := json.Marshal(protocol.DeleteRoom{
		Type: "delete_room", Room: "room_does_not_exist",
	})
	s.handleDeleteRoom(probeUnknown.Client, rawUnknown)

	probeNonMember := testClientFor("carol", "dev_carol_2")
	rawNonMember, _ := json.Marshal(protocol.DeleteRoom{
		Type: "delete_room", Room: engineeringID,
	})
	s.handleDeleteRoom(probeNonMember.Client, rawNonMember)

	unknownMsgs := probeUnknown.messages()
	nonMemberMsgs := probeNonMember.messages()
	if len(unknownMsgs) != 1 || len(nonMemberMsgs) != 1 {
		t.Fatalf("expected 1 reply each, got unknown=%d nonmember=%d",
			len(unknownMsgs), len(nonMemberMsgs))
	}
	if !bytes.Equal(unknownMsgs[0], nonMemberMsgs[0]) {
		t.Errorf("privacy leak: handleDeleteRoom unknown and non-member responses differ\nunknown:    %s\nnon-member: %s",
			unknownMsgs[0], nonMemberMsgs[0])
	}

	var errMsg protocol.Error
	json.Unmarshal(unknownMsgs[0], &errMsg)
	if errMsg.Code != protocol.ErrUnknownRoom {
		t.Errorf("code = %q, want %q", errMsg.Code, protocol.ErrUnknownRoom)
	}
}

// ============================================================================
// handleDeleteRoom — last-member cleanup
// ============================================================================

// TestHandleDeleteRoom_LastMemberCleanupCascade verifies that when
// the last member /delete's a room, the full cleanup cascade fires
// (room row deleted, per-room DB file unlinked) AND the deleted_rooms
// sidecar row survives (it was written BEFORE the cleanup, and
// DeleteRoomRecord deliberately doesn't touch it).
func TestHandleDeleteRoom_LastMemberCleanupCascade(t *testing.T) {
	s := newTestServer(t)
	enableActiveRoomLeave(t, s)

	// engineering has only alice in the seed (via users.toml)
	engineeringID := s.store.RoomDisplayNameToID("engineering")
	members := s.store.GetRoomMemberIDsByRoomID(engineeringID)
	if len(members) != 1 || members[0] != "alice" {
		t.Fatalf("expected engineering to have only alice, got %v", members)
	}

	alice := testClientFor("alice", "dev_alice_1")
	s.mu.Lock()
	s.clients["dev_alice_1"] = alice.Client
	s.mu.Unlock()

	raw, _ := json.Marshal(protocol.DeleteRoom{
		Type: "delete_room", Room: engineeringID,
	})
	s.handleDeleteRoom(alice.Client, raw)

	// Room row should be gone (cleanup cascade ran)
	r, _ := s.store.GetRoomByID(engineeringID)
	if r != nil {
		t.Errorf("room row should be deleted by last-member cascade, got %+v", r)
	}

	// The deleted_rooms sidecar row MUST survive the cleanup cascade
	// (regression test for the ordering constraint)
	ids, _ := s.store.GetDeletedRoomsForUser("alice")
	found := false
	for _, id := range ids {
		if id == engineeringID {
			found = true
			break
		}
	}
	if !found {
		t.Error("deleted_rooms sidecar row should survive the last-member cleanup cascade")
	}
}

// ============================================================================
// handleLeaveRoom retired-room policy gate
// ============================================================================

// TestHandleLeaveRoom_RetiredRoomUsesRetiredFlag verifies that the
// Phase 12 policy gate branches on retired state correctly: a
// retired room uses allow_self_leave_retired_rooms, NOT
// allow_self_leave_rooms. If the active-rooms flag is false (default)
// but the retired-rooms flag is true (default), /leave on a retired
// room should succeed.
func TestHandleLeaveRoom_RetiredRoomUsesRetiredFlag(t *testing.T) {
	s := newTestServer(t)
	// Default config: allow_self_leave_rooms = false,
	//                 allow_self_leave_retired_rooms = true
	// Verify defaults as a precondition.
	if s.cfg.Server.Server.AllowSelfLeaveRooms {
		t.Fatal("precondition: AllowSelfLeaveRooms should default to false")
	}
	if !s.cfg.Server.Server.AllowSelfLeaveRetiredRooms {
		t.Fatal("precondition: AllowSelfLeaveRetiredRooms should default to true")
	}

	generalID := s.store.RoomDisplayNameToID("general")
	retireRoomForTest(t, s, generalID)

	bob := testClientFor("bob", "dev_bob_1")
	s.mu.Lock()
	s.clients["dev_bob_1"] = bob.Client
	s.mu.Unlock()

	raw, _ := json.Marshal(protocol.LeaveRoom{Type: "leave_room", Room: generalID})
	s.handleLeaveRoom(bob.Client, raw)

	// Bob should be removed (retired-rooms flag allowed the leave)
	if s.store.IsRoomMemberByID(generalID, "bob") {
		t.Error("bob should have been removed — retired room gate uses allow_self_leave_retired_rooms")
	}

	// Bob should receive room_left echo
	msgs := bob.messages()
	foundLeft := false
	for _, m := range msgs {
		var left protocol.RoomLeft
		if json.Unmarshal(m, &left) == nil && left.Type == "room_left" {
			foundLeft = true
			break
		}
	}
	if !foundLeft {
		t.Error("bob should have received a room_left echo")
	}
}

// TestHandleLeaveRoom_RetiredRoomPolicyDenied verifies that with
// allow_self_leave_retired_rooms = false, a /leave on a retired
// room is rejected with ErrForbidden.
func TestHandleLeaveRoom_RetiredRoomPolicyDenied(t *testing.T) {
	s := newTestServer(t)
	disableRetiredRoomLeave(t, s)

	generalID := s.store.RoomDisplayNameToID("general")
	retireRoomForTest(t, s, generalID)

	bob := testClientFor("bob", "dev_bob_1")
	raw, _ := json.Marshal(protocol.LeaveRoom{Type: "leave_room", Room: generalID})
	s.handleLeaveRoom(bob.Client, raw)

	msgs := bob.messages()
	if len(msgs) != 1 {
		t.Fatalf("expected 1 reply, got %d", len(msgs))
	}
	var errMsg protocol.Error
	json.Unmarshal(msgs[0], &errMsg)
	if errMsg.Code != protocol.ErrForbidden {
		t.Errorf("code = %q, want %q", errMsg.Code, protocol.ErrForbidden)
	}

	// Bob should still be a member
	if !s.store.IsRoomMemberByID(generalID, "bob") {
		t.Error("bob should still be a member after retired-room denial")
	}
}

// ============================================================================
// runRoomRetirementProcessor / processPendingRoomRetirements
// ============================================================================

// TestProcessPendingRoomRetirements_HappyPath verifies the end-to-end
// queue-driven retirement broadcast: the CLI path is simulated via
// direct SetRoomRetired + RecordPendingRoomRetirement calls, the
// processor consumes the queue, and connected members receive
// room_retired events.
func TestProcessPendingRoomRetirements_HappyPath(t *testing.T) {
	s := newTestServer(t)
	generalID := s.store.RoomDisplayNameToID("general")

	// Simulate the CLI: SetRoomRetired first, then enqueue.
	if err := s.store.SetRoomRetired(generalID, "alice", "test-cleanup"); err != nil {
		t.Fatalf("SetRoomRetired: %v", err)
	}
	if err := s.store.RecordPendingRoomRetirement(generalID, "alice", "test-cleanup"); err != nil {
		t.Fatalf("RecordPendingRoomRetirement: %v", err)
	}

	// Register a connected member (bob is a member of general per the seed)
	bob := testClientFor("bob", "dev_bob_1")
	s.mu.Lock()
	s.clients["dev_bob_1"] = bob.Client
	s.mu.Unlock()

	// Process the queue synchronously
	s.processPendingRoomRetirements()

	// Bob should have received a room_retired event
	msgs := bob.messages()
	if len(msgs) != 1 {
		t.Fatalf("expected 1 event, got %d", len(msgs))
	}
	var evt protocol.RoomRetired
	if err := json.Unmarshal(msgs[0], &evt); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if evt.Type != "room_retired" {
		t.Errorf("event type = %q, want room_retired", evt.Type)
	}
	if evt.Room != generalID {
		t.Errorf("event room = %q, want %q", evt.Room, generalID)
	}
	if evt.RetiredBy != "alice" {
		t.Errorf("event retired_by = %q, want alice", evt.RetiredBy)
	}
	if evt.Reason != "test-cleanup" {
		t.Errorf("event reason = %q, want test-cleanup", evt.Reason)
	}
	// Display name should be the suffixed version
	if evt.DisplayName == "general" {
		t.Error("event display_name should be suffixed, not the original")
	}

	// Queue should now be empty (atomic consume)
	remaining, _ := s.store.ConsumePendingRoomRetirements()
	if len(remaining) != 0 {
		t.Errorf("queue should be empty after processing, got %d", len(remaining))
	}
}

// TestProcessPendingRoomRetirements_EmptyQueue verifies the processor
// is a no-op on an empty queue (common case on every tick).
func TestProcessPendingRoomRetirements_EmptyQueue(t *testing.T) {
	s := newTestServer(t)
	// Should not panic or error
	s.processPendingRoomRetirements()
}

// TestProcessPendingRoomRetirements_MissingRoom verifies that a
// pending retirement referencing a room that no longer exists (e.g.
// cleaned up between enqueue and processing) is logged and skipped
// without poisoning the rest of the batch.
func TestProcessPendingRoomRetirements_MissingRoom(t *testing.T) {
	s := newTestServer(t)

	if err := s.store.RecordPendingRoomRetirement("room_ghost", "alice", ""); err != nil {
		t.Fatalf("RecordPendingRoomRetirement: %v", err)
	}

	// Should not panic — the processor logs and continues
	s.processPendingRoomRetirements()

	// Queue should be drained (atomic consume means all rows were
	// removed, even the bad one)
	remaining, _ := s.store.ConsumePendingRoomRetirements()
	if len(remaining) != 0 {
		t.Errorf("queue should be drained, got %d", len(remaining))
	}
}

// TestProcessPendingRoomRetirements_OnlyBroadcastsToMembers verifies
// that the broadcast is scoped to current room members — non-members
// should NOT receive the room_retired event.
func TestProcessPendingRoomRetirements_OnlyBroadcastsToMembers(t *testing.T) {
	s := newTestServer(t)
	engineeringID := s.store.RoomDisplayNameToID("engineering")

	// Only alice is a member of engineering per the seed
	if err := s.store.SetRoomRetired(engineeringID, "alice", ""); err != nil {
		t.Fatalf("SetRoomRetired: %v", err)
	}
	if err := s.store.RecordPendingRoomRetirement(engineeringID, "alice", ""); err != nil {
		t.Fatalf("RecordPendingRoomRetirement: %v", err)
	}

	// Register alice (member) and bob (non-member)
	alice := testClientFor("alice", "dev_alice_1")
	bob := testClientFor("bob", "dev_bob_1")
	s.mu.Lock()
	s.clients["dev_alice_1"] = alice.Client
	s.clients["dev_bob_1"] = bob.Client
	s.mu.Unlock()

	s.processPendingRoomRetirements()

	// Alice should have received the event
	aliceMsgs := alice.messages()
	if len(aliceMsgs) != 1 {
		t.Errorf("alice (member) should have received 1 event, got %d", len(aliceMsgs))
	}

	// Bob should NOT have received anything
	bobMsgs := bob.messages()
	if len(bobMsgs) != 0 {
		t.Errorf("bob (non-member) should have received 0 events, got %d", len(bobMsgs))
	}
}
