package server

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/brushtailmedia/sshkey-chat/internal/protocol"
)

// Phase 12 Chunk 2 — write-rejection tests for retired rooms.
//
// These tests verify that every write handler (handleSend, handleReact,
// handlePin, handleUnpin) rejects writes to retired rooms with the
// informative ErrRoomRetired response, while preserving the byte-
// identical privacy convention: non-members still get ErrUnknownRoom
// regardless of whether the room is retired.
//
// handleUnreact and handleDelete are not tested here because their
// existing code paths iterate s.store.GetUserRoomIDs which already
// filters WHERE r.retired = 0 — retired rooms are naturally excluded
// from the search. See the code comments in those handlers for the
// rationale.

// retireRoomForTest is a test helper that calls SetRoomRetired on a
// room. Used by every test in this file to set up the retired state.
func retireRoomForTest(t *testing.T, s *Server, roomID string) {
	t.Helper()
	if err := s.store.SetRoomRetired(roomID, "alice", "test"); err != nil {
		t.Fatalf("SetRoomRetired(%q): %v", roomID, err)
	}
	if !s.store.IsRoomRetired(roomID) {
		t.Fatalf("IsRoomRetired(%q) = false after SetRoomRetired", roomID)
	}
}

// ============================================================================
// handleSend
// ============================================================================

// TestHandleSend_RejectsRetiredRoom verifies that a member trying to
// send a message to a retired room gets the informative ErrRoomRetired
// error (Q11: distinguishable for members, since the retirement was
// already broadcast to them).
func TestHandleSend_RejectsRetiredRoom(t *testing.T) {
	s := newTestServer(t)
	generalID := s.store.RoomDisplayNameToID("general")
	if generalID == "" {
		t.Fatal("seed should have general room")
	}
	retireRoomForTest(t, s, generalID)

	bob := testClientFor("bob", "dev_bob_1")
	raw, _ := json.Marshal(protocol.Send{
		Type: "send", Room: generalID,
		Epoch: 1, Payload: "p", Signature: "s",
	})
	s.handleSend(bob.Client, raw)

	msgs := bob.messages()
	if len(msgs) != 1 {
		t.Fatalf("expected 1 reply, got %d", len(msgs))
	}
	var errMsg protocol.Error
	if err := json.Unmarshal(msgs[0], &errMsg); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if errMsg.Code != protocol.ErrRoomRetired {
		t.Errorf("code = %q, want %q", errMsg.Code, protocol.ErrRoomRetired)
	}
	if errMsg.Message == "" {
		t.Error("expected informative message, got empty")
	}
}

// TestHandleSend_RetiredRoomPreservesPrivacy verifies that a NON-member
// probing a retired room gets the same byte-identical ErrUnknownRoom
// response they would get for a non-retired room or a genuinely
// unknown room. Retirement state must not be a probing vector for
// non-members.
func TestHandleSend_RetiredRoomPreservesPrivacy(t *testing.T) {
	s := newTestServer(t)
	engineeringID := s.store.RoomDisplayNameToID("engineering")
	if engineeringID == "" {
		t.Fatal("seed should have engineering room")
	}
	retireRoomForTest(t, s, engineeringID)

	// carol is NOT a member of engineering
	probeUnknown := testClientFor("carol", "dev_carol_1")
	rawUnknown, _ := json.Marshal(protocol.Send{
		Type: "send", Room: "room_does_not_exist",
		Epoch: 1, Payload: "p", Signature: "s",
	})
	s.handleSend(probeUnknown.Client, rawUnknown)

	probeRetired := testClientFor("carol", "dev_carol_2")
	rawRetired, _ := json.Marshal(protocol.Send{
		Type: "send", Room: engineeringID,
		Epoch: 1, Payload: "p", Signature: "s",
	})
	s.handleSend(probeRetired.Client, rawRetired)

	unknownMsgs := probeUnknown.messages()
	retiredMsgs := probeRetired.messages()
	if len(unknownMsgs) != 1 || len(retiredMsgs) != 1 {
		t.Fatalf("expected 1 reply each, got unknown=%d retired=%d",
			len(unknownMsgs), len(retiredMsgs))
	}
	if !bytes.Equal(unknownMsgs[0], retiredMsgs[0]) {
		t.Errorf("privacy leak: retired-room probe by non-member differs from unknown-room probe\nunknown: %s\nretired: %s",
			unknownMsgs[0], retiredMsgs[0])
	}
}

// ============================================================================
// handleReact
// ============================================================================

// TestHandleReact_RejectsRetiredRoom verifies that a member reacting in
// a retired room gets ErrRoomRetired.
func TestHandleReact_RejectsRetiredRoom(t *testing.T) {
	s := newTestServer(t)
	generalID := s.store.RoomDisplayNameToID("general")
	retireRoomForTest(t, s, generalID)

	bob := testClientFor("bob", "dev_bob_1")
	raw, _ := json.Marshal(protocol.React{
		Type: "react", Room: generalID, ID: "msg_target",
		Epoch: 1, Payload: "p", Signature: "s",
	})
	s.handleReact(bob.Client, raw)

	msgs := bob.messages()
	if len(msgs) != 1 {
		t.Fatalf("expected 1 reply, got %d", len(msgs))
	}
	var errMsg protocol.Error
	json.Unmarshal(msgs[0], &errMsg)
	if errMsg.Code != protocol.ErrRoomRetired {
		t.Errorf("code = %q, want %q", errMsg.Code, protocol.ErrRoomRetired)
	}
}

// TestHandleReact_RetiredRoomPreservesPrivacy verifies that a non-
// member reacting in a retired room gets the same byte-identical
// ErrUnknownRoom response as probing an unknown room.
func TestHandleReact_RetiredRoomPreservesPrivacy(t *testing.T) {
	s := newTestServer(t)
	engineeringID := s.store.RoomDisplayNameToID("engineering")
	retireRoomForTest(t, s, engineeringID)

	probeUnknown := testClientFor("carol", "dev_carol_1")
	rawUnknown, _ := json.Marshal(protocol.React{
		Type: "react", Room: "room_does_not_exist", ID: "msg_target",
		Epoch: 1, Payload: "p", Signature: "s",
	})
	s.handleReact(probeUnknown.Client, rawUnknown)

	probeRetired := testClientFor("carol", "dev_carol_2")
	rawRetired, _ := json.Marshal(protocol.React{
		Type: "react", Room: engineeringID, ID: "msg_target",
		Epoch: 1, Payload: "p", Signature: "s",
	})
	s.handleReact(probeRetired.Client, rawRetired)

	unknownMsgs := probeUnknown.messages()
	retiredMsgs := probeRetired.messages()
	if len(unknownMsgs) != 1 || len(retiredMsgs) != 1 {
		t.Fatalf("expected 1 reply each, got unknown=%d retired=%d",
			len(unknownMsgs), len(retiredMsgs))
	}
	if !bytes.Equal(unknownMsgs[0], retiredMsgs[0]) {
		t.Errorf("privacy leak: handleReact retired-room non-member response differs\nunknown: %s\nretired: %s",
			unknownMsgs[0], retiredMsgs[0])
	}
}

// ============================================================================
// handlePin
// ============================================================================

// TestHandlePin_RejectsRetiredRoom verifies that a member pinning in
// a retired room gets ErrRoomRetired.
func TestHandlePin_RejectsRetiredRoom(t *testing.T) {
	s := newTestServer(t)
	generalID := s.store.RoomDisplayNameToID("general")
	retireRoomForTest(t, s, generalID)

	bob := testClientFor("bob", "dev_bob_1")
	raw, _ := json.Marshal(protocol.Pin{
		Type: "pin", Room: generalID, ID: "msg_target",
	})
	s.handlePin(bob.Client, raw)

	msgs := bob.messages()
	if len(msgs) != 1 {
		t.Fatalf("expected 1 reply, got %d", len(msgs))
	}
	var errMsg protocol.Error
	json.Unmarshal(msgs[0], &errMsg)
	if errMsg.Code != protocol.ErrRoomRetired {
		t.Errorf("code = %q, want %q", errMsg.Code, protocol.ErrRoomRetired)
	}
}

// TestHandlePin_RetiredRoomPreservesPrivacy — non-member probing.
func TestHandlePin_RetiredRoomPreservesPrivacy(t *testing.T) {
	s := newTestServer(t)
	engineeringID := s.store.RoomDisplayNameToID("engineering")
	retireRoomForTest(t, s, engineeringID)

	probeUnknown := testClientFor("carol", "dev_carol_1")
	rawUnknown, _ := json.Marshal(protocol.Pin{
		Type: "pin", Room: "room_does_not_exist", ID: "msg_target",
	})
	s.handlePin(probeUnknown.Client, rawUnknown)

	probeRetired := testClientFor("carol", "dev_carol_2")
	rawRetired, _ := json.Marshal(protocol.Pin{
		Type: "pin", Room: engineeringID, ID: "msg_target",
	})
	s.handlePin(probeRetired.Client, rawRetired)

	unknownMsgs := probeUnknown.messages()
	retiredMsgs := probeRetired.messages()
	if len(unknownMsgs) != 1 || len(retiredMsgs) != 1 {
		t.Fatalf("expected 1 reply each, got unknown=%d retired=%d",
			len(unknownMsgs), len(retiredMsgs))
	}
	if !bytes.Equal(unknownMsgs[0], retiredMsgs[0]) {
		t.Errorf("privacy leak: handlePin retired-room non-member response differs\nunknown: %s\nretired: %s",
			unknownMsgs[0], retiredMsgs[0])
	}
}

// ============================================================================
// handleUnpin
// ============================================================================

// TestHandleUnpin_RejectsRetiredRoom verifies that a member unpinning in
// a retired room gets ErrRoomRetired.
func TestHandleUnpin_RejectsRetiredRoom(t *testing.T) {
	s := newTestServer(t)
	generalID := s.store.RoomDisplayNameToID("general")
	retireRoomForTest(t, s, generalID)

	bob := testClientFor("bob", "dev_bob_1")
	raw, _ := json.Marshal(protocol.Unpin{
		Type: "unpin", Room: generalID, ID: "msg_target",
	})
	s.handleUnpin(bob.Client, raw)

	msgs := bob.messages()
	if len(msgs) != 1 {
		t.Fatalf("expected 1 reply, got %d", len(msgs))
	}
	var errMsg protocol.Error
	json.Unmarshal(msgs[0], &errMsg)
	if errMsg.Code != protocol.ErrRoomRetired {
		t.Errorf("code = %q, want %q", errMsg.Code, protocol.ErrRoomRetired)
	}
}

// TestHandleUnpin_RetiredRoomPreservesPrivacy — non-member probing.
func TestHandleUnpin_RetiredRoomPreservesPrivacy(t *testing.T) {
	s := newTestServer(t)
	engineeringID := s.store.RoomDisplayNameToID("engineering")
	retireRoomForTest(t, s, engineeringID)

	probeUnknown := testClientFor("carol", "dev_carol_1")
	rawUnknown, _ := json.Marshal(protocol.Unpin{
		Type: "unpin", Room: "room_does_not_exist", ID: "msg_target",
	})
	s.handleUnpin(probeUnknown.Client, rawUnknown)

	probeRetired := testClientFor("carol", "dev_carol_2")
	rawRetired, _ := json.Marshal(protocol.Unpin{
		Type: "unpin", Room: engineeringID, ID: "msg_target",
	})
	s.handleUnpin(probeRetired.Client, rawRetired)

	unknownMsgs := probeUnknown.messages()
	retiredMsgs := probeRetired.messages()
	if len(unknownMsgs) != 1 || len(retiredMsgs) != 1 {
		t.Fatalf("expected 1 reply each, got unknown=%d retired=%d",
			len(unknownMsgs), len(retiredMsgs))
	}
	if !bytes.Equal(unknownMsgs[0], retiredMsgs[0]) {
		t.Errorf("privacy leak: handleUnpin retired-room non-member response differs\nunknown: %s\nretired: %s",
			unknownMsgs[0], retiredMsgs[0])
	}
}
