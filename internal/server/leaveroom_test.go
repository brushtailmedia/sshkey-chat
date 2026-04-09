package server

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/brushtailmedia/sshkey-chat/internal/protocol"
)

// TestHandleLeaveRoom_PrivacyResponsesIdentical is the byte-identity
// regression for the room privacy convention. The wire response for
// "room does not exist" and "you are not a member of an existing
// room" MUST be identical so a probing client cannot use leave_room
// to discover whether a room ID exists.
//
// Same shape as TestHandleLeaveDM_PrivacyResponsesIdentical and
// TestHandleLeaveGroup_PrivacyResponsesIdentical.
func TestHandleLeaveRoom_PrivacyResponsesIdentical(t *testing.T) {
	s := newTestServer(t)

	// "general" exists in the seed but carol is NOT a member of it
	// (she's only seeded into "general" — actually she IS a member.
	// Use a real room name that carol is NOT in. From the seed, carol
	// is in "general". Engineering only has alice. So carol probing
	// engineering = real room, non-member.)
	generalID := s.store.RoomDisplayNameToID("engineering")
	if generalID == "" {
		t.Fatal("seed should have engineering room")
	}

	// Carol probes a room ID that does NOT exist
	probe := testClientFor("carol", "dev_carol_1")
	rawProbe, _ := json.Marshal(protocol.LeaveRoom{Type: "leave_room", Room: "room_does_not_exist"})
	s.handleLeaveRoom(probe.Client, rawProbe)

	// Carol probes the real engineering room (alice is in it, carol is not)
	nonMember := testClientFor("carol", "dev_carol_2")
	rawReal, _ := json.Marshal(protocol.LeaveRoom{Type: "leave_room", Room: generalID})
	s.handleLeaveRoom(nonMember.Client, rawReal)

	probeMsgs := probe.messages()
	nonMemberMsgs := nonMember.messages()
	if len(probeMsgs) != 1 || len(nonMemberMsgs) != 1 {
		t.Fatalf("expected 1 reply each, got probe=%d nonMember=%d",
			len(probeMsgs), len(nonMemberMsgs))
	}
	if !bytes.Equal(probeMsgs[0], nonMemberMsgs[0]) {
		t.Errorf("privacy leak: unknown-room and non-member responses differ\nunknown:    %s\nnon-member: %s",
			probeMsgs[0], nonMemberMsgs[0])
	}

	// And verify the error code is ErrUnknownRoom (not ErrNotAuthorized)
	var errMsg protocol.Error
	json.Unmarshal(probeMsgs[0], &errMsg)
	if errMsg.Code != protocol.ErrUnknownRoom {
		t.Errorf("error code = %q, want %s (matches handleSend/handleLeaveGroup convention)",
			errMsg.Code, protocol.ErrUnknownRoom)
	}
}

// TestHandleSend_PrivacyResponsesIdentical is the byte-identity
// regression for the handleSend privacy alignment we just landed.
// Catches accidental regressions if anyone customises the error
// message in either branch (unknown room vs non-member).
func TestHandleSend_PrivacyResponsesIdentical(t *testing.T) {
	s := newTestServer(t)
	engineeringID := s.store.RoomDisplayNameToID("engineering")
	if engineeringID == "" {
		t.Fatal("seed should have engineering room")
	}

	probe := testClientFor("carol", "dev_carol_1")
	rawProbe, _ := json.Marshal(protocol.Send{
		Type: "send", Room: "room_does_not_exist",
		Epoch: 1, Payload: "p", Signature: "s",
	})
	s.handleSend(probe.Client, rawProbe)

	nonMember := testClientFor("carol", "dev_carol_2")
	rawReal, _ := json.Marshal(protocol.Send{
		Type: "send", Room: engineeringID,
		Epoch: 1, Payload: "p", Signature: "s",
	})
	s.handleSend(nonMember.Client, rawReal)

	probeMsgs := probe.messages()
	nonMemberMsgs := nonMember.messages()
	if len(probeMsgs) != 1 || len(nonMemberMsgs) != 1 {
		t.Fatalf("expected 1 reply each, got probe=%d nonMember=%d",
			len(probeMsgs), len(nonMemberMsgs))
	}
	if !bytes.Equal(probeMsgs[0], nonMemberMsgs[0]) {
		t.Errorf("privacy leak: handleSend unknown-room and non-member responses differ\nunknown:    %s\nnon-member: %s",
			probeMsgs[0], nonMemberMsgs[0])
	}

	var errMsg protocol.Error
	json.Unmarshal(probeMsgs[0], &errMsg)
	if errMsg.Code != protocol.ErrUnknownRoom {
		t.Errorf("send error code = %q, want %s",
			errMsg.Code, protocol.ErrUnknownRoom)
	}
}

// TestHandleLeaveRoom_PolicyGateDenial verifies that when
// allow_self_leave_rooms is false (default), a member's leave attempt
// is rejected with ErrForbidden — distinct from the unknown-room case.
// This is where the privacy convention deliberately diverges: the
// policy gate uses a different error so users understand WHY they
// can't leave (admin-managed).
func TestHandleLeaveRoom_PolicyGateDenial(t *testing.T) {
	s := newTestServer(t)
	// Default config has allow_self_leave_rooms = false
	if s.cfg.Server.Server.AllowSelfLeaveRooms {
		t.Fatal("precondition: AllowSelfLeaveRooms should default to false")
	}

	// Bob is in "general" via the seed
	generalID := s.store.RoomDisplayNameToID("general")
	bob := testClientFor("bob", "dev_bob_1")

	raw, _ := json.Marshal(protocol.LeaveRoom{Type: "leave_room", Room: generalID})
	s.handleLeaveRoom(bob.Client, raw)

	msgs := bob.messages()
	if len(msgs) != 1 {
		t.Fatalf("expected 1 reply, got %d", len(msgs))
	}
	var errMsg protocol.Error
	if err := json.Unmarshal(msgs[0], &errMsg); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if errMsg.Code != protocol.ErrForbidden {
		t.Errorf("policy denial code = %q, want %s",
			errMsg.Code, protocol.ErrForbidden)
	}

	// Bob should still be a member after denial
	if !s.store.IsRoomMemberByID(generalID, "bob") {
		t.Error("bob should still be a member after policy denial")
	}
}

// TestHandleLeaveRoom_HappyPath verifies the full self-leave flow
// when the policy gate is enabled: member is removed, broadcast fires
// to remaining members, leaver gets the echo, epoch rotation marker
// is set.
func TestHandleLeaveRoom_HappyPath(t *testing.T) {
	s := newTestServer(t)
	// Enable the policy gate for this test (default is admin-managed)
	s.cfg.Lock()
	s.cfg.Server.Server.AllowSelfLeaveRooms = true
	s.cfg.Unlock()

	generalID := s.store.RoomDisplayNameToID("general")
	bob := testClientFor("bob", "dev_bob_1")
	alice := testClientFor("alice", "dev_alice_1")

	// Register both sessions so the broadcast and echo land somewhere
	s.mu.Lock()
	s.clients["dev_bob_1"] = bob.Client
	s.clients["dev_alice_1"] = alice.Client
	s.mu.Unlock()

	raw, _ := json.Marshal(protocol.LeaveRoom{Type: "leave_room", Room: generalID})
	s.handleLeaveRoom(bob.Client, raw)

	// Bob should be removed from room_members
	if s.store.IsRoomMemberByID(generalID, "bob") {
		t.Error("bob should be removed from general after leave")
	}

	// Bob should have received exactly one room_left echo
	bobMsgs := bob.messages()
	if len(bobMsgs) != 1 {
		t.Fatalf("bob expected 1 room_left echo, got %d", len(bobMsgs))
	}
	var left protocol.RoomLeft
	if err := json.Unmarshal(bobMsgs[0], &left); err != nil {
		t.Fatalf("parse echo: %v", err)
	}
	if left.Type != "room_left" {
		t.Errorf("echo type = %q, want room_left", left.Type)
	}
	if left.Room != generalID {
		t.Errorf("echo room = %q, want %s", left.Room, generalID)
	}
	if left.Reason != "" {
		t.Errorf("self-leave should have empty reason, got %q", left.Reason)
	}

	// Alice (still a member of general) should have received the
	// room_event{leave, user: bob} broadcast
	aliceMsgs := alice.messages()
	if len(aliceMsgs) != 1 {
		t.Fatalf("alice expected 1 broadcast, got %d", len(aliceMsgs))
	}
	var ev protocol.RoomEvent
	if err := json.Unmarshal(aliceMsgs[0], &ev); err != nil {
		t.Fatalf("parse broadcast: %v", err)
	}
	if ev.Event != "leave" {
		t.Errorf("broadcast event = %q, want leave", ev.Event)
	}
	if ev.User != "bob" {
		t.Errorf("broadcast user = %q, want bob", ev.User)
	}
	if ev.Reason != "" {
		t.Errorf("self-leave broadcast should have empty reason, got %q", ev.Reason)
	}
}

// TestPerformRoomLeave_AdminReason verifies the shared performRoomLeave
// function correctly propagates a non-empty reason through both the
// echo and the broadcast. This is the path the future admin
// remove-from-room CLI and the Phase 12 retirement-driven leave will
// use, so verifying it now means those upcoming features get the
// right plumbing for free.
func TestPerformRoomLeave_AdminReason(t *testing.T) {
	s := newTestServer(t)

	generalID := s.store.RoomDisplayNameToID("general")
	bob := testClientFor("bob", "dev_bob_1")
	alice := testClientFor("alice", "dev_alice_1")

	s.mu.Lock()
	s.clients["dev_bob_1"] = bob.Client
	s.clients["dev_alice_1"] = alice.Client
	s.mu.Unlock()

	// Call performRoomLeave directly with an "admin" reason. Bypasses
	// the handler's policy gate — this is what the admin path would
	// look like internally.
	s.performRoomLeave(generalID, "bob", "admin")

	// Bob removed from members
	if s.store.IsRoomMemberByID(generalID, "bob") {
		t.Error("bob should be removed")
	}

	// Bob's echo carries Reason: "admin"
	bobMsgs := bob.messages()
	if len(bobMsgs) != 1 {
		t.Fatalf("bob expected 1 echo, got %d", len(bobMsgs))
	}
	var left protocol.RoomLeft
	json.Unmarshal(bobMsgs[0], &left)
	if left.Reason != "admin" {
		t.Errorf("echo reason = %q, want admin", left.Reason)
	}

	// Alice's broadcast also carries Reason: "admin"
	aliceMsgs := alice.messages()
	if len(aliceMsgs) != 1 {
		t.Fatalf("alice expected 1 broadcast, got %d", len(aliceMsgs))
	}
	var ev protocol.RoomEvent
	json.Unmarshal(aliceMsgs[0], &ev)
	if ev.Reason != "admin" {
		t.Errorf("broadcast reason = %q, want admin", ev.Reason)
	}
}

// TestPerformRoomLeave_RetirementReason verifies the same thing for
// the retirement reason variant. This is the Phase 12 room-retirement
// path that's not yet wired but will reuse this function.
func TestPerformRoomLeave_RetirementReason(t *testing.T) {
	s := newTestServer(t)

	generalID := s.store.RoomDisplayNameToID("general")
	bob := testClientFor("bob", "dev_bob_1")
	alice := testClientFor("alice", "dev_alice_1")

	s.mu.Lock()
	s.clients["dev_bob_1"] = bob.Client
	s.clients["dev_alice_1"] = alice.Client
	s.mu.Unlock()

	s.performRoomLeave(generalID, "bob", "retirement")

	bobMsgs := bob.messages()
	if len(bobMsgs) != 1 {
		t.Fatalf("bob expected 1 echo, got %d", len(bobMsgs))
	}
	var left protocol.RoomLeft
	json.Unmarshal(bobMsgs[0], &left)
	if left.Reason != "retirement" {
		t.Errorf("echo reason = %q, want retirement", left.Reason)
	}

	aliceMsgs := alice.messages()
	if len(aliceMsgs) != 1 {
		t.Fatalf("alice expected 1 broadcast, got %d", len(aliceMsgs))
	}
	var ev protocol.RoomEvent
	json.Unmarshal(aliceMsgs[0], &ev)
	if ev.Reason != "retirement" {
		t.Errorf("broadcast reason = %q, want retirement", ev.Reason)
	}
}
