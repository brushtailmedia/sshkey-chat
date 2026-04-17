package server

// Tests for handleUploadStart context-membership authorization. The fix
// closes a gap where any authenticated user could call upload_start with
// an arbitrary room/group/dm ID and have the server allocate a fileID +
// accept bytes on Channel 3. The downstream `send` membership check would
// reject the message referencing the fileID, but the bytes persisted on
// disk as orphans (completion stores a hash record, and orphan cleanup
// only deletes files WITHOUT hash records).
//
// Each handler branch (room / group / dm) is covered twice: once where
// the caller IS a member (accept), once where they are NOT (reject with
// the matching ErrUnknown* code). Plus the envelope cases: no context set
// and multiple contexts set (both should reject with invalid_context).
//
// Privacy: non-member responses must be byte-identical whether the
// context exists or not. The final TestHandleUploadStart_PrivacyIdentical
// locks this in with bytes.Equal.

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/brushtailmedia/sshkey-chat/internal/protocol"
)

// uploadStartMsg is a small helper — the test fixture always supplies
// size/content_hash that pass the earlier validation gates so the failure
// (when it happens) is the membership check we're exercising, not a
// different rejection further up.
func uploadStartMsg(uploadID string, room, group, dm string) protocol.UploadStart {
	return protocol.UploadStart{
		Type:        "upload_start",
		UploadID:    uploadID,
		Size:        100,
		ContentHash: "blake2b-256:" + strings64("a"),
		Room:        room,
		Group:       group,
		DM:          dm,
	}
}

// strings64 returns a string of n copies of s; used to produce a 64-char
// hex-shaped content_hash body. Kept local — no need for strings.Repeat
// in the test package.
func strings64(s string) string {
	out := make([]byte, 64)
	for i := range out {
		out[i] = s[0]
	}
	return string(out)
}

// ============================================================================
// Room context
// ============================================================================

func TestHandleUploadStart_RoomMemberAccepted(t *testing.T) {
	s := newTestServer(t)
	generalID := s.store.RoomDisplayNameToID("general")

	alice := testClientFor("alice", "dev_alice_1")
	raw, _ := json.Marshal(uploadStartMsg("up_room_happy", generalID, "", ""))
	s.handleUploadStart(alice.Client, raw)

	msgs := alice.messages()
	if len(msgs) != 1 {
		t.Fatalf("expected 1 reply, got %d", len(msgs))
	}
	var ready protocol.UploadReady
	if err := json.Unmarshal(msgs[0], &ready); err != nil {
		t.Fatalf("parse reply: %v", err)
	}
	if ready.Type != "upload_ready" {
		t.Errorf("type = %q, want upload_ready", ready.Type)
	}
}

func TestHandleUploadStart_RoomNonMemberRejected(t *testing.T) {
	s := newTestServer(t)
	// alice is in engineering per the seed; bob and carol are not.
	engID := s.store.RoomDisplayNameToID("engineering")

	bob := testClientFor("bob", "dev_bob_1")
	raw, _ := json.Marshal(uploadStartMsg("up_room_reject", engID, "", ""))
	s.handleUploadStart(bob.Client, raw)

	msgs := bob.messages()
	if len(msgs) != 1 {
		t.Fatalf("expected 1 reply, got %d", len(msgs))
	}
	var errMsg protocol.UploadError
	if err := json.Unmarshal(msgs[0], &errMsg); err != nil {
		t.Fatalf("parse reply: %v", err)
	}
	if errMsg.Type != "upload_error" {
		t.Errorf("type = %q, want upload_error", errMsg.Type)
	}
	if errMsg.Code != protocol.ErrUnknownRoom {
		t.Errorf("code = %q, want %q", errMsg.Code, protocol.ErrUnknownRoom)
	}
}

// ============================================================================
// Group context
// ============================================================================

func TestHandleUploadStart_GroupMemberAccepted(t *testing.T) {
	s := newTestServer(t)
	if err := s.store.CreateGroup("group_up_happy", "alice", []string{"alice", "bob"}, "Test"); err != nil {
		t.Fatalf("create group: %v", err)
	}

	bob := testClientFor("bob", "dev_bob_1")
	raw, _ := json.Marshal(uploadStartMsg("up_group_happy", "", "group_up_happy", ""))
	s.handleUploadStart(bob.Client, raw)

	msgs := bob.messages()
	if len(msgs) != 1 {
		t.Fatalf("expected 1 reply, got %d", len(msgs))
	}
	var ready protocol.UploadReady
	if err := json.Unmarshal(msgs[0], &ready); err != nil {
		t.Fatalf("parse reply: %v", err)
	}
	if ready.Type != "upload_ready" {
		t.Errorf("type = %q, want upload_ready", ready.Type)
	}
}

func TestHandleUploadStart_GroupNonMemberRejected(t *testing.T) {
	s := newTestServer(t)
	if err := s.store.CreateGroup("group_up_reject", "alice", []string{"alice", "bob"}, "Test"); err != nil {
		t.Fatalf("create group: %v", err)
	}

	// carol is not a member.
	carol := testClientFor("carol", "dev_carol_1")
	raw, _ := json.Marshal(uploadStartMsg("up_group_reject", "", "group_up_reject", ""))
	s.handleUploadStart(carol.Client, raw)

	msgs := carol.messages()
	if len(msgs) != 1 {
		t.Fatalf("expected 1 reply, got %d", len(msgs))
	}
	var errMsg protocol.UploadError
	if err := json.Unmarshal(msgs[0], &errMsg); err != nil {
		t.Fatalf("parse reply: %v", err)
	}
	if errMsg.Code != protocol.ErrUnknownGroup {
		t.Errorf("code = %q, want %q", errMsg.Code, protocol.ErrUnknownGroup)
	}
}

// ============================================================================
// DM context
// ============================================================================

func TestHandleUploadStart_DMPartyAccepted(t *testing.T) {
	s := newTestServer(t)
	dm, err := s.store.CreateOrGetDirectMessage("dm_up_happy", "alice", "bob")
	if err != nil {
		t.Fatalf("create dm: %v", err)
	}

	bob := testClientFor("bob", "dev_bob_1")
	raw, _ := json.Marshal(uploadStartMsg("up_dm_happy", "", "", dm.ID))
	s.handleUploadStart(bob.Client, raw)

	msgs := bob.messages()
	if len(msgs) != 1 {
		t.Fatalf("expected 1 reply, got %d", len(msgs))
	}
	var ready protocol.UploadReady
	if err := json.Unmarshal(msgs[0], &ready); err != nil {
		t.Fatalf("parse reply: %v", err)
	}
	if ready.Type != "upload_ready" {
		t.Errorf("type = %q, want upload_ready", ready.Type)
	}
}

func TestHandleUploadStart_DMNonPartyRejected(t *testing.T) {
	s := newTestServer(t)
	dm, err := s.store.CreateOrGetDirectMessage("dm_up_reject", "alice", "bob")
	if err != nil {
		t.Fatalf("create dm: %v", err)
	}

	// carol is not a party.
	carol := testClientFor("carol", "dev_carol_1")
	raw, _ := json.Marshal(uploadStartMsg("up_dm_reject", "", "", dm.ID))
	s.handleUploadStart(carol.Client, raw)

	msgs := carol.messages()
	if len(msgs) != 1 {
		t.Fatalf("expected 1 reply, got %d", len(msgs))
	}
	var errMsg protocol.UploadError
	if err := json.Unmarshal(msgs[0], &errMsg); err != nil {
		t.Fatalf("parse reply: %v", err)
	}
	if errMsg.Code != protocol.ErrUnknownDM {
		t.Errorf("code = %q, want %q", errMsg.Code, protocol.ErrUnknownDM)
	}
}

// ============================================================================
// Envelope-shape rejections
// ============================================================================

func TestHandleUploadStart_NoContextRejected(t *testing.T) {
	s := newTestServer(t)
	alice := testClientFor("alice", "dev_alice_1")
	raw, _ := json.Marshal(uploadStartMsg("up_no_ctx", "", "", ""))
	s.handleUploadStart(alice.Client, raw)

	msgs := alice.messages()
	if len(msgs) != 1 {
		t.Fatalf("expected 1 reply, got %d", len(msgs))
	}
	var errMsg protocol.UploadError
	if err := json.Unmarshal(msgs[0], &errMsg); err != nil {
		t.Fatalf("parse reply: %v", err)
	}
	if errMsg.Code != "invalid_context" {
		t.Errorf("code = %q, want invalid_context", errMsg.Code)
	}
}

func TestHandleUploadStart_MultipleContextsRejected(t *testing.T) {
	s := newTestServer(t)
	generalID := s.store.RoomDisplayNameToID("general")

	alice := testClientFor("alice", "dev_alice_1")
	// Set both Room and Group — invalid_context regardless of whether alice
	// is a member of either.
	raw, _ := json.Marshal(uploadStartMsg("up_multi_ctx", generalID, "group_anything", ""))
	s.handleUploadStart(alice.Client, raw)

	msgs := alice.messages()
	if len(msgs) != 1 {
		t.Fatalf("expected 1 reply, got %d", len(msgs))
	}
	var errMsg protocol.UploadError
	if err := json.Unmarshal(msgs[0], &errMsg); err != nil {
		t.Fatalf("parse reply: %v", err)
	}
	if errMsg.Code != "invalid_context" {
		t.Errorf("code = %q, want invalid_context", errMsg.Code)
	}
}

// ============================================================================
// Privacy: non-member response must be byte-identical to "room doesn't
// exist" so a probing client cannot use upload_start to enumerate rooms.
// ============================================================================

func TestHandleUploadStart_PrivacyIdentical_Room(t *testing.T) {
	s := newTestServer(t)
	engID := s.store.RoomDisplayNameToID("engineering")

	// Case 1: bob tries to upload to engineering (exists; bob not a member).
	bob1 := testClientFor("bob", "dev_bob_1")
	raw1, _ := json.Marshal(uploadStartMsg("up_priv_1", engID, "", ""))
	s.handleUploadStart(bob1.Client, raw1)

	// Case 2: bob tries to upload to a room that doesn't exist.
	bob2 := testClientFor("bob", "dev_bob_2")
	raw2, _ := json.Marshal(uploadStartMsg("up_priv_1", "room_nonexistent", "", ""))
	s.handleUploadStart(bob2.Client, raw2)

	msgs1 := bob1.messages()
	msgs2 := bob2.messages()
	if len(msgs1) != 1 || len(msgs2) != 1 {
		t.Fatalf("expected 1 reply each, got %d / %d", len(msgs1), len(msgs2))
	}
	if !bytes.Equal(msgs1[0], msgs2[0]) {
		t.Errorf("privacy leak: upload_start non-member vs unknown-room differ\n"+
			"  non-member: %s\n  unknown:    %s",
			msgs1[0], msgs2[0])
	}
}

func TestHandleUploadStart_PrivacyIdentical_Group(t *testing.T) {
	s := newTestServer(t)
	if err := s.store.CreateGroup("group_priv_real", "alice", []string{"alice", "bob"}, "Test"); err != nil {
		t.Fatalf("create group: %v", err)
	}

	// Case 1: carol tries to upload to group_priv_real (exists; carol not a member).
	carol1 := testClientFor("carol", "dev_carol_1")
	raw1, _ := json.Marshal(uploadStartMsg("up_priv_g", "", "group_priv_real", ""))
	s.handleUploadStart(carol1.Client, raw1)

	// Case 2: carol tries to upload to a group that doesn't exist.
	carol2 := testClientFor("carol", "dev_carol_2")
	raw2, _ := json.Marshal(uploadStartMsg("up_priv_g", "", "group_does_not_exist", ""))
	s.handleUploadStart(carol2.Client, raw2)

	msgs1 := carol1.messages()
	msgs2 := carol2.messages()
	if len(msgs1) != 1 || len(msgs2) != 1 {
		t.Fatalf("expected 1 reply each, got %d / %d", len(msgs1), len(msgs2))
	}
	if !bytes.Equal(msgs1[0], msgs2[0]) {
		t.Errorf("privacy leak: upload_start non-member vs unknown-group differ\n"+
			"  non-member: %s\n  unknown:    %s",
			msgs1[0], msgs2[0])
	}
}

func TestHandleUploadStart_PrivacyIdentical_DM(t *testing.T) {
	s := newTestServer(t)
	dm, err := s.store.CreateOrGetDirectMessage("dm_priv", "alice", "bob")
	if err != nil {
		t.Fatalf("create dm: %v", err)
	}

	// Case 1: carol tries to upload to the alice-bob DM (exists; carol not a party).
	carol1 := testClientFor("carol", "dev_carol_1")
	raw1, _ := json.Marshal(uploadStartMsg("up_priv_d", "", "", dm.ID))
	s.handleUploadStart(carol1.Client, raw1)

	// Case 2: carol tries to upload to a DM that doesn't exist.
	carol2 := testClientFor("carol", "dev_carol_2")
	raw2, _ := json.Marshal(uploadStartMsg("up_priv_d", "", "", "dm_does_not_exist"))
	s.handleUploadStart(carol2.Client, raw2)

	msgs1 := carol1.messages()
	msgs2 := carol2.messages()
	if len(msgs1) != 1 || len(msgs2) != 1 {
		t.Fatalf("expected 1 reply each, got %d / %d", len(msgs1), len(msgs2))
	}
	if !bytes.Equal(msgs1[0], msgs2[0]) {
		t.Errorf("privacy leak: upload_start non-party vs unknown-dm differ\n"+
			"  non-party: %s\n  unknown:   %s",
			msgs1[0], msgs2[0])
	}
}
