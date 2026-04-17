package server

// Phase 17 Step 4.f — cross-context file_id rejection tests.
//
// validateFileIDsForContext is the server's gate against a raw-wire
// attacker who crafts a send referencing a file_id bound to a context
// they're not targeting. Every file_id has exactly one binding (single-
// binding model — forwards are not an implemented client feature), so
// a mismatch is either a client bug or an attack.
//
// Critical privacy property: the server's error response must NOT
// distinguish "the file doesn't exist" from "the file exists but isn't
// bound to this context". Both return the same `unknown_file` code and
// message. Tests lock this in directly by asserting the encoded wire
// output.
//
// These tests call validateFileIDsForContext directly (no SSH
// scaffolding) to isolate the cross-context rejection logic from
// handleSend's other plumbing.

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/brushtailmedia/sshkey-chat/internal/protocol"
	"github.com/brushtailmedia/sshkey-chat/internal/store"
)

// newCrossContextTestClient is a minimal *Client whose Encoder writes
// to the supplied buffer so tests can assert on the wire response.
func newCrossContextTestClient(deviceID string, encBuf *bytes.Buffer) *Client {
	return &Client{
		UserID:   "alice",
		DeviceID: deviceID,
		Encoder:  protocol.NewEncoder(encBuf),
	}
}

// assertUnknownFile decodes the encoder's buffer and verifies it carries
// exactly one `unknown_file` Error with the privacy-preserving message.
// Any other payload fails the test.
func assertUnknownFile(t *testing.T, encBuf *bytes.Buffer) {
	t.Helper()
	var got protocol.Error
	if err := json.Unmarshal(bytes.TrimSpace(encBuf.Bytes()), &got); err != nil {
		t.Fatalf("expected Error on wire, decode failed: %v (raw: %q)", err, encBuf.String())
	}
	if got.Type != "error" {
		t.Errorf("Type = %q, want \"error\"", got.Type)
	}
	if got.Code != "unknown_file" {
		t.Errorf("Code = %q, want \"unknown_file\"", got.Code)
	}
	// Privacy: message must NOT name a context_type or context_id —
	// just the generic "not found or not accessible" wording. If this
	// assertion fails after a future refactor, it likely means someone
	// leaked binding information into the error path. Read the comment
	// block on validateFileIDsForContext before "fixing" the test.
	if got.Message != "file not found or not accessible in this context" {
		t.Errorf("Message = %q, want generic privacy-preserving wording", got.Message)
	}
}

func TestValidateFileIDsForContext_EmptySlice_Accepts(t *testing.T) {
	s := newTestServer(t)
	var encBuf bytes.Buffer
	c := newCrossContextTestClient("dev_a", &encBuf)

	generalID := s.store.RoomDisplayNameToID("general")
	if !s.validateFileIDsForContext(c, nil, store.FileContextRoom, generalID) {
		t.Error("nil file_ids slice must accept (no-op)")
	}
	if !s.validateFileIDsForContext(c, []string{}, store.FileContextRoom, generalID) {
		t.Error("empty file_ids slice must accept (no-op)")
	}
	if encBuf.Len() != 0 {
		t.Errorf("empty slice must not write to encoder; got %q", encBuf.String())
	}
}

func TestValidateFileIDsForContext_MatchingBinding_Accepts(t *testing.T) {
	s := newTestServer(t)
	var encBuf bytes.Buffer
	c := newCrossContextTestClient("dev_a", &encBuf)

	generalID := s.store.RoomDisplayNameToID("general")
	fileID := store.GenerateID("file_")
	if err := s.store.InsertFileContext(fileID, store.FileContextRoom, generalID, 100); err != nil {
		t.Fatalf("bind file: %v", err)
	}

	if !s.validateFileIDsForContext(c, []string{fileID}, store.FileContextRoom, generalID) {
		t.Error("matching (type, id) binding must accept")
	}
	if encBuf.Len() != 0 {
		t.Errorf("accept path must not write to encoder; got %q", encBuf.String())
	}
}

func TestValidateFileIDsForContext_CrossRoomToRoom_Rejects(t *testing.T) {
	s := newTestServer(t)
	var encBuf bytes.Buffer
	c := newCrossContextTestClient("dev_a", &encBuf)

	generalID := s.store.RoomDisplayNameToID("general")
	engID := s.store.RoomDisplayNameToID("engineering")
	fileID := store.GenerateID("file_")
	// Bind the file to engineering — caller will try to reference it
	// from a send targeting general.
	if err := s.store.InsertFileContext(fileID, store.FileContextRoom, engID, 100); err != nil {
		t.Fatalf("bind file: %v", err)
	}

	if s.validateFileIDsForContext(c, []string{fileID}, store.FileContextRoom, generalID) {
		t.Error("file bound to room A must not be acceptable in send to room B")
	}
	assertUnknownFile(t, &encBuf)
}

func TestValidateFileIDsForContext_CrossRoomToGroup_Rejects(t *testing.T) {
	s := newTestServer(t)
	var encBuf bytes.Buffer
	c := newCrossContextTestClient("dev_a", &encBuf)

	generalID := s.store.RoomDisplayNameToID("general")
	fileID := store.GenerateID("file_")
	// Bind to a room; send attempt targets a group — wrong context_type
	// too, not just wrong context_id.
	if err := s.store.InsertFileContext(fileID, store.FileContextRoom, generalID, 100); err != nil {
		t.Fatalf("bind file: %v", err)
	}

	if s.validateFileIDsForContext(c, []string{fileID}, store.FileContextGroup, "group_anything") {
		t.Error("room-bound file must not be acceptable in group send")
	}
	assertUnknownFile(t, &encBuf)
}

func TestValidateFileIDsForContext_CrossGroupToDM_Rejects(t *testing.T) {
	s := newTestServer(t)
	var encBuf bytes.Buffer
	c := newCrossContextTestClient("dev_a", &encBuf)

	fileID := store.GenerateID("file_")
	if err := s.store.InsertFileContext(fileID, store.FileContextGroup, "group_xyz", 100); err != nil {
		t.Fatalf("bind file: %v", err)
	}
	dm, err := s.store.CreateOrGetDirectMessage("dm_cross", "alice", "bob")
	if err != nil {
		t.Fatalf("create dm: %v", err)
	}

	if s.validateFileIDsForContext(c, []string{fileID}, store.FileContextDM, dm.ID) {
		t.Error("group-bound file must not be acceptable in DM send")
	}
	assertUnknownFile(t, &encBuf)
}

// TestValidateFileIDsForContext_UnknownFileID_ByteIdenticalToCrossContext
// is the privacy-parity test. An attacker who fishes for "does this file
// exist?" by submitting a well-formed-but-unregistered file_id must get
// the same wire response as someone who references a real file bound to
// a different context. If these diverge, an attacker can distinguish
// "this file exists somewhere" from "nope, never uploaded" — a probe
// channel that breaks the privacy envelope.
func TestValidateFileIDsForContext_UnknownFileID_ByteIdenticalToCrossContext(t *testing.T) {
	s := newTestServer(t)
	generalID := s.store.RoomDisplayNameToID("general")
	engID := s.store.RoomDisplayNameToID("engineering")

	// Case A: cross-context reject (file exists, wrong binding).
	realFileID := store.GenerateID("file_")
	if err := s.store.InsertFileContext(realFileID, store.FileContextRoom, engID, 100); err != nil {
		t.Fatalf("bind file: %v", err)
	}
	var crossBuf bytes.Buffer
	c1 := newCrossContextTestClient("dev_a", &crossBuf)
	if s.validateFileIDsForContext(c1, []string{realFileID}, store.FileContextRoom, generalID) {
		t.Fatal("cross-context must reject")
	}

	// Case B: unknown-file reject (no binding at all).
	unknownFileID := store.GenerateID("file_")
	var unknownBuf bytes.Buffer
	c2 := newCrossContextTestClient("dev_a", &unknownBuf)
	if s.validateFileIDsForContext(c2, []string{unknownFileID}, store.FileContextRoom, generalID) {
		t.Fatal("unknown file_id must reject")
	}

	// Wire responses must be byte-identical — any divergence is a
	// privacy-envelope leak. The `\n` terminator varies in neither case
	// (NewEncoder emits each JSON value with a trailing newline), so a
	// raw byte comparison is correct.
	if !bytes.Equal(crossBuf.Bytes(), unknownBuf.Bytes()) {
		t.Errorf("wire divergence leaks file existence:\n  cross   = %q\n  unknown = %q",
			crossBuf.String(), unknownBuf.String())
	}
}

func TestValidateFileIDsForContext_MixedValidAndInvalid_RejectsAtFirstInvalid(t *testing.T) {
	s := newTestServer(t)
	var encBuf bytes.Buffer
	c := newCrossContextTestClient("dev_a", &encBuf)

	generalID := s.store.RoomDisplayNameToID("general")
	engID := s.store.RoomDisplayNameToID("engineering")

	goodID := store.GenerateID("file_")
	if err := s.store.InsertFileContext(goodID, store.FileContextRoom, generalID, 100); err != nil {
		t.Fatalf("bind good: %v", err)
	}
	// Second file is bound to a different room — must tank the whole send.
	badID := store.GenerateID("file_")
	if err := s.store.InsertFileContext(badID, store.FileContextRoom, engID, 100); err != nil {
		t.Fatalf("bind bad: %v", err)
	}

	if s.validateFileIDsForContext(c, []string{goodID, badID}, store.FileContextRoom, generalID) {
		t.Error("any cross-context file_id in the slice must reject the whole send")
	}
	assertUnknownFile(t, &encBuf)
}
