package server

// Phase 16 Gap 1 — tests for processPendingRemoveFromRoom.
//
// Coverage:
//   - happy path: queue row → user removed from members + leave
//     event broadcast to remaining members + room_left echoed to
//     leaver's own session
//   - non-member: skipped without crashing or broadcasting
//   - audit credit: operator identified by initiated_by field
//   - multiple rows in one tick

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/brushtailmedia/sshkey-chat/internal/protocol"
)

// TestProcessPendingRemoveFromRoom_HappyPath verifies the end-to-end
// flow: enqueue a removal, run the processor, check that the user
// was removed from room_members AND that remaining members received
// a room_event{leave, reason='removed'} broadcast AND that the
// kicked user received a room_left echo to its own session.
func TestProcessPendingRemoveFromRoom_HappyPath(t *testing.T) {
	s := newTestServer(t)
	generalID := s.store.RoomDisplayNameToID("general")

	// Precondition: bob is in general.
	if !s.store.IsRoomMemberByID(generalID, "bob") {
		t.Fatal("precondition: bob should be in general")
	}

	// CLI side: enqueue the removal.
	if err := s.store.RecordPendingRemoveFromRoom("bob", generalID, "removed", "os:1000"); err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	// Connect alice (remaining member) and bob (the leaver) so
	// both can observe the broadcast.
	alice := testClientFor("alice", "dev_alice_1")
	bob := testClientFor("bob", "dev_bob_1")
	s.mu.Lock()
	s.clients["dev_alice_1"] = alice.Client
	s.clients["dev_bob_1"] = bob.Client
	s.mu.Unlock()

	s.processPendingRemoveFromRoom()

	// Bob should no longer be a member.
	if s.store.IsRoomMemberByID(generalID, "bob") {
		t.Error("bob should be removed from general")
	}

	// Alice should have received room_event{leave, reason=removed}.
	aliceMsgs := alice.messages()
	if len(aliceMsgs) != 1 {
		t.Fatalf("alice should have received 1 broadcast, got %d", len(aliceMsgs))
	}
	var event protocol.RoomEvent
	if err := json.Unmarshal(aliceMsgs[0], &event); err != nil {
		t.Fatalf("parse alice event: %v", err)
	}
	if event.Type != "room_event" || event.Event != "leave" {
		t.Errorf("alice event = %+v, want room_event/leave", event)
	}
	if event.Reason != "removed" {
		t.Errorf("alice event reason = %q, want removed", event.Reason)
	}
	if event.User != "bob" {
		t.Errorf("alice event user = %q, want bob", event.User)
	}

	// Bob should have received a room_left echo to his own session.
	bobMsgs := bob.messages()
	if len(bobMsgs) != 1 {
		t.Fatalf("bob should have received 1 echo, got %d", len(bobMsgs))
	}
	var left protocol.RoomLeft
	if err := json.Unmarshal(bobMsgs[0], &left); err != nil {
		t.Fatalf("parse bob echo: %v", err)
	}
	if left.Type != "room_left" {
		t.Errorf("bob echo type = %q, want room_left", left.Type)
	}
	if left.Reason != "removed" {
		t.Errorf("bob echo reason = %q, want removed", left.Reason)
	}

	// Queue should be drained (DELETE on consume — no rows remain).
	pending, _ := s.store.ConsumePendingRemoveFromRooms()
	if len(pending) != 0 {
		t.Errorf("queue should be drained, got %d remaining rows", len(pending))
	}
}

// TestProcessPendingRemoveFromRoom_SkipsNonMember verifies that a
// queue row for a user who is no longer a member of the room (e.g.
// they left via /leave between enqueue and processing) is logged
// and skipped without broadcasting a misleading "user left" event
// to the room.
func TestProcessPendingRemoveFromRoom_SkipsNonMember(t *testing.T) {
	s := newTestServer(t)
	generalID := s.store.RoomDisplayNameToID("general")

	// Insert dave but DON'T add him to general.
	s.store.InsertUser("dave", "ssh-ed25519 AAAA fake", "dave")

	// Enqueue a removal for dave from general.
	s.store.RecordPendingRemoveFromRoom("dave", generalID, "removed", "os:1000")

	alice := testClientFor("alice", "dev_alice_1")
	s.mu.Lock()
	s.clients["dev_alice_1"] = alice.Client
	s.mu.Unlock()

	s.processPendingRemoveFromRoom()

	// Alice should NOT have received any broadcast — dave was
	// never a member, so the "skip non-member" branch fired.
	if msgs := alice.messages(); len(msgs) != 0 {
		t.Errorf("expected no broadcast for non-member removal, got %d", len(msgs))
	}
}

// TestProcessPendingRemoveFromRoom_AuditCreditsOperator verifies
// the audit log entry identifies the operator who ran the CLI.
func TestProcessPendingRemoveFromRoom_AuditCreditsOperator(t *testing.T) {
	s := newTestServer(t)
	generalID := s.store.RoomDisplayNameToID("general")

	s.store.RecordPendingRemoveFromRoom("bob", generalID, "removed", "os:5678")
	s.processPendingRemoveFromRoom()

	auditBytes, err := readAuditLog(s)
	if err != nil {
		t.Fatalf("read audit: %v", err)
	}
	auditContent := string(auditBytes)

	for _, want := range []string{
		"os:5678",
		"remove-from-room",
		"user=bob",
		"room=" + generalID,
		"reason=removed",
	} {
		if !strings.Contains(auditContent, want) {
			t.Errorf("audit log missing %q, got: %q", want, auditContent)
		}
	}
}

// TestProcessPendingRemoveFromRoom_MultipleRowsInOneTick verifies
// the processor handles multiple queued removals in a single tick.
func TestProcessPendingRemoveFromRoom_MultipleRowsInOneTick(t *testing.T) {
	s := newTestServer(t)
	generalID := s.store.RoomDisplayNameToID("general")

	// Both bob and carol are in general per the test fixtures.
	s.store.RecordPendingRemoveFromRoom("bob", generalID, "removed", "os:1000")
	s.store.RecordPendingRemoveFromRoom("carol", generalID, "removed", "os:1000")

	s.processPendingRemoveFromRoom()

	if s.store.IsRoomMemberByID(generalID, "bob") {
		t.Error("bob should be removed")
	}
	if s.store.IsRoomMemberByID(generalID, "carol") {
		t.Error("carol should be removed")
	}

	// alice (still in general) should remain.
	if !s.store.IsRoomMemberByID(generalID, "alice") {
		t.Error("alice should still be in general")
	}
}
