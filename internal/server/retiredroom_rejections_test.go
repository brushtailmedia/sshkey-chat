package server

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/brushtailmedia/sshkey-chat/internal/counters"
	"github.com/brushtailmedia/sshkey-chat/internal/protocol"
	"github.com/brushtailmedia/sshkey-chat/internal/store"
)

// validUploadHash is a well-formed blake2b-256:<hex64> content hash that
// passes the upload_start format gate (the value is irrelevant — these
// tests reject before the bytes are ever hashed).
var validUploadHash = "blake2b-256:" + strings.Repeat("a", 64)

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

// ============================================================================
// handleUploadStart  (see retired-room-upload-start-fix.md)
// ============================================================================
//
// upload_start allocates server-side pending-upload state. A retired room
// is read-only, so a custom client must not be able to allocate that state
// (or have Channel-3 bytes accepted) for an archived room — even though the
// later `send` that would reference the file is already rejected. The gate
// sits AFTER the membership check and BEFORE quota/allocation, and (like the
// write-verb rejections above) fires no counter for an authorized member.

// TestHandleUploadStart_RejectsRetiredRoom: a member uploading to a retired
// room gets the typed UploadError{code: room_retired} — NOT a generic Error
// envelope, and NOT upload_ready.
func TestHandleUploadStart_RejectsRetiredRoom(t *testing.T) {
	s := newTestServer(t)
	generalID := s.store.RoomDisplayNameToID("general")
	if generalID == "" {
		t.Fatal("seed should have general room")
	}
	retireRoomForTest(t, s, generalID)

	// bob is a member of general; membership rows survive retirement, so he
	// passes IsRoomMemberByID and reaches the new retired gate.
	bob := testClientFor("bob", "dev_bob_upl_retired")
	raw, _ := json.Marshal(protocol.UploadStart{
		Type:        "upload_start",
		UploadID:    store.GenerateID("up_"),
		Size:        100,
		ContentHash: validUploadHash,
		Room:        generalID,
	})
	s.handleUploadStart(bob.Client, raw)

	msgs := bob.messages()
	if len(msgs) != 1 {
		t.Fatalf("expected 1 reply, got %d", len(msgs))
	}
	var errResp protocol.UploadError
	if err := json.Unmarshal(msgs[0], &errResp); err != nil {
		t.Fatalf("parse upload_error: %v", err)
	}
	if errResp.Type != "upload_error" {
		t.Errorf("type = %q, want upload_error (typed UploadError, not generic Error)", errResp.Type)
	}
	if errResp.Code != protocol.ErrRoomRetired {
		t.Errorf("code = %q, want %q", errResp.Code, protocol.ErrRoomRetired)
	}
	if errResp.Message == "" {
		t.Error("expected informative message, got empty")
	}
	if got := s.counters.Get(counters.SignalNonMemberContext, "dev_bob_upl_retired"); got != 0 {
		t.Errorf("SignalNonMemberContext = %d, want 0 for authorized retired-room member", got)
	}
}

// TestHandleUploadStart_RetiredRoomAllocatesNoUpload: the rejection precedes
// pendingUpload allocation, so no upload state is created for a read-only room.
func TestHandleUploadStart_RetiredRoomAllocatesNoUpload(t *testing.T) {
	s := newTestServer(t)
	generalID := s.store.RoomDisplayNameToID("general")
	retireRoomForTest(t, s, generalID)

	bob := testClientFor("bob", "dev_bob_upl_noalloc")
	uploadID := store.GenerateID("up_")
	raw, _ := json.Marshal(protocol.UploadStart{
		Type:        "upload_start",
		UploadID:    uploadID,
		Size:        100,
		ContentHash: validUploadHash,
		Room:        generalID,
	})
	s.handleUploadStart(bob.Client, raw)

	// Read under the files mutex — the map is mutex-guarded; white-box
	// access is fine (package server) but must lock to stay -race-clean.
	s.files.mu.RLock()
	_, exists := s.files.uploads[uploadID]
	s.files.mu.RUnlock()
	if exists {
		t.Error("retired-room upload_start must not allocate a pendingUpload entry")
	}
}

// TestHandleUploadStart_RetiredRoomPreservesPrivacy: a NON-member probing a
// retired room gets the byte-identical unknown_room reply they'd get for a
// genuinely missing room — retirement is not a probing vector.
//
// NOTE: this is deliberately NOT a copy of the handleSend privacy template.
// UploadError echoes the client-chosen upload_id (and corr_id), so the two
// probes must hold those constant for byte-equality to be meaningful. Here
// corr_id is empty for both and the same upload_id is reused (safe — the
// rejection precedes allocation, so there is no pending-map collision).
func TestHandleUploadStart_RetiredRoomPreservesPrivacy(t *testing.T) {
	s := newTestServer(t)
	engineeringID := s.store.RoomDisplayNameToID("engineering")
	if engineeringID == "" {
		t.Fatal("seed should have engineering room")
	}
	retireRoomForTest(t, s, engineeringID)

	uploadID := store.GenerateID("up_") // identical across both probes
	mk := func(room string) []byte {
		raw, _ := json.Marshal(protocol.UploadStart{
			Type:        "upload_start",
			UploadID:    uploadID,
			Size:        100,
			ContentHash: validUploadHash,
			Room:        room,
		})
		return raw
	}

	// carol is not a member of engineering (nor of a missing room).
	probeUnknown := testClientFor("carol", "dev_carol_upl_1")
	s.handleUploadStart(probeUnknown.Client, mk("room_does_not_exist"))

	probeRetired := testClientFor("carol", "dev_carol_upl_2")
	s.handleUploadStart(probeRetired.Client, mk(engineeringID))

	unknownMsgs := probeUnknown.messages()
	retiredMsgs := probeRetired.messages()
	if len(unknownMsgs) != 1 || len(retiredMsgs) != 1 {
		t.Fatalf("expected 1 reply each, got unknown=%d retired=%d",
			len(unknownMsgs), len(retiredMsgs))
	}
	if !bytes.Equal(unknownMsgs[0], retiredMsgs[0]) {
		t.Errorf("privacy leak: non-member retired-room upload probe differs from unknown-room probe\nunknown: %s\nretired: %s",
			unknownMsgs[0], retiredMsgs[0])
	}
	// Both must carry the unknown-room shape — a non-member never learns the
	// room exists, let alone that it is retired.
	var errResp protocol.UploadError
	json.Unmarshal(unknownMsgs[0], &errResp)
	if errResp.Code != protocol.ErrUnknownRoom {
		t.Errorf("code = %q, want %q (non-member must get unknown-room)", errResp.Code, protocol.ErrUnknownRoom)
	}
}

// TestHandleUploadStart_ActiveRoomStillReady: the happy path is unchanged — a
// member uploading to an ACTIVE room still gets upload_ready.
func TestHandleUploadStart_ActiveRoomStillReady(t *testing.T) {
	s := newTestServer(t)
	generalID := s.store.RoomDisplayNameToID("general") // not retired

	bob := testClientFor("bob", "dev_bob_upl_active")
	uploadID := store.GenerateID("up_")
	raw, _ := json.Marshal(protocol.UploadStart{
		Type:        "upload_start",
		UploadID:    uploadID,
		Size:        100,
		ContentHash: validUploadHash,
		Room:        generalID,
	})
	s.handleUploadStart(bob.Client, raw)

	msgs := bob.messages()
	if len(msgs) != 1 {
		t.Fatalf("expected 1 reply, got %d", len(msgs))
	}
	var ready protocol.UploadReady
	if err := json.Unmarshal(msgs[0], &ready); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if ready.Type != "upload_ready" {
		t.Errorf("type = %q, want upload_ready (got %s)", ready.Type, msgs[0])
	}
	if ready.UploadID != uploadID {
		t.Errorf("upload_id = %q, want %q", ready.UploadID, uploadID)
	}
}
