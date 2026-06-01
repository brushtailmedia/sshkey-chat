package server

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/brushtailmedia/sshkey-chat/internal/actionauth"
	"github.com/brushtailmedia/sshkey-chat/internal/protocol"
	"github.com/brushtailmedia/sshkey-chat/internal/store"
	"golang.org/x/crypto/ssh"
)

// seedKeyedUser seeds a user with a freshly-generated Ed25519 keypair (so tests
// can produce delete signatures the server verifies against the stored key) and
// returns the private key. The fixed testKey* constants have no known private
// key, so F6 signature tests must mint their own.
func seedKeyedUser(t *testing.T, s *Server, userID, displayName string, admin bool, rooms []string) ed25519.PrivateKey {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("gen key for %s: %v", userID, err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("ssh pub for %s: %v", userID, err)
	}
	seedTestUser(t, s, userID, string(ssh.MarshalAuthorizedKey(sshPub)), displayName, admin, rooms)
	return priv
}

// signedDelete builds a protocol.Delete carrying the given context and a real
// Ed25519 signature over (kind, contextID, msgID).
func signedDelete(kind, contextID, msgID string, priv ed25519.PrivateKey) protocol.Delete {
	sig := ed25519.Sign(priv, actionauth.BuildDeleteCanonical(kind, contextID, msgID))
	d := protocol.Delete{Type: "delete", ID: msgID, Signature: base64.StdEncoding.EncodeToString(sig)}
	switch kind {
	case "room":
		d.Room = contextID
	case "group":
		d.Group = contextID
	case "dm":
		d.DM = contextID
	}
	return d
}

func sendDelete(s *Server, cc *captureClient, d protocol.Delete) {
	raw, _ := json.Marshal(d)
	s.handleDelete(cc.Client, raw)
}

func registerClient(s *Server, cc *captureClient) {
	s.mu.Lock()
	s.clients[cc.DeviceID] = cc.Client
	s.mu.Unlock()
}

func roomMsgDeleted(t *testing.T, s *Server, roomID, msgID string) bool {
	t.Helper()
	row, err := s.store.GetRoomMessageByID(roomID, msgID)
	if err != nil || row == nil {
		return false
	}
	return row.Deleted
}

func firstErrorCode(cc *captureClient) string {
	for _, raw := range cc.messages() {
		var e protocol.Error
		if json.Unmarshal(raw, &e) == nil && e.Type == "error" {
			return e.Code
		}
	}
	return ""
}

func hasDeletedBroadcast(cc *captureClient, msgID string) bool {
	for _, raw := range cc.messages() {
		var d protocol.Deleted
		if json.Unmarshal(raw, &d) == nil && d.Type == "deleted" && d.ID == msgID {
			return true
		}
	}
	return false
}

func seedRoomMsg(t *testing.T, s *Server, roomID, msgID, sender string) {
	t.Helper()
	if _, err := s.store.InsertRoomMessage(roomID, store.StoredMessage{
		ID: msgID, Sender: sender, TS: 100, Epoch: 1, Payload: "p", Signature: "s",
	}); err != nil {
		t.Fatalf("insert room message: %v", err)
	}
}

func signedUnreact(kind, contextID, reactionID string, priv ed25519.PrivateKey) protocol.Unreact {
	sig := ed25519.Sign(priv, actionauth.BuildUnreactCanonical(kind, contextID, reactionID))
	u := protocol.Unreact{Type: "unreact", ReactionID: reactionID, Signature: base64.StdEncoding.EncodeToString(sig)}
	switch kind {
	case "room":
		u.Room = contextID
	case "group":
		u.Group = contextID
	case "dm":
		u.DM = contextID
	}
	return u
}

func sendUnreact(s *Server, cc *captureClient, u protocol.Unreact) {
	raw, _ := json.Marshal(u)
	s.handleUnreact(cc.Client, raw)
}

func seedRoomReaction(t *testing.T, s *Server, roomID, msgID, reactionID, user string) {
	t.Helper()
	db, err := s.store.RoomDB(roomID)
	if err != nil {
		t.Fatalf("room db: %v", err)
	}
	if _, err := db.Exec(
		`INSERT INTO reactions (reaction_id, message_id, user, ts, epoch, payload, signature) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		reactionID, msgID, user, int64(101), int64(1), "payload", "sig",
	); err != nil {
		t.Fatalf("insert room reaction: %v", err)
	}
}

func roomReactionExists(t *testing.T, s *Server, roomID, reactionID string) bool {
	t.Helper()
	db, err := s.store.RoomDB(roomID)
	if err != nil {
		t.Fatalf("room db: %v", err)
	}
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM reactions WHERE reaction_id = ?`, reactionID).Scan(&n); err != nil {
		t.Fatalf("count reaction: %v", err)
	}
	return n > 0
}

func TestHandleDelete_RoomSignedAccept(t *testing.T) {
	s := newTestServer(t)
	general := s.store.RoomDisplayNameToID("general")
	priv := seedKeyedUser(t, s, "dave", "Dave", false, []string{"general"})
	seedRoomMsg(t, s, general, "m_ok", "dave")
	dave := testClientFor("dave", "dev_dave")
	registerClient(s, dave)

	sendDelete(s, dave, signedDelete("room", general, "m_ok", priv))

	if !roomMsgDeleted(t, s, general, "m_ok") {
		t.Error("valid signed delete should tombstone the message")
	}
	if !hasDeletedBroadcast(dave, "m_ok") {
		t.Error("expected a deleted broadcast")
	}
}

func TestHandleDelete_RejectsMissingSignature(t *testing.T) {
	s := newTestServer(t)
	general := s.store.RoomDisplayNameToID("general")
	seedKeyedUser(t, s, "dave", "Dave", false, []string{"general"})
	seedRoomMsg(t, s, general, "m_nosig", "dave")
	dave := testClientFor("dave", "dev_dave")
	registerClient(s, dave)

	// Context present, signature absent.
	sendDelete(s, dave, protocol.Delete{Type: "delete", ID: "m_nosig", Room: general})

	if roomMsgDeleted(t, s, general, "m_nosig") {
		t.Error("delete with no signature must not tombstone")
	}
	if code := firstErrorCode(dave); code != "invalid_message" {
		t.Errorf("error code = %q, want invalid_message", code)
	}
}

func TestHandleDelete_RejectsZeroContext(t *testing.T) {
	s := newTestServer(t)
	general := s.store.RoomDisplayNameToID("general")
	priv := seedKeyedUser(t, s, "dave", "Dave", false, []string{"general"})
	seedRoomMsg(t, s, general, "m_ctx", "dave")
	dave := testClientFor("dave", "dev_dave")
	registerClient(s, dave)

	d := signedDelete("room", general, "m_ctx", priv)
	d.Room = "" // strip the only context
	sendDelete(s, dave, d)

	if roomMsgDeleted(t, s, general, "m_ctx") {
		t.Error("zero-context delete must not tombstone")
	}
	if code := firstErrorCode(dave); code != "invalid_context" {
		t.Errorf("error = %q, want invalid_context", code)
	}
}

func TestHandleDelete_RejectsInvalidSignature(t *testing.T) {
	s := newTestServer(t)
	general := s.store.RoomDisplayNameToID("general")
	priv := seedKeyedUser(t, s, "dave", "Dave", false, []string{"general"})
	seedRoomMsg(t, s, general, "m_badsig", "dave")
	dave := testClientFor("dave", "dev_dave")
	registerClient(s, dave)

	// Valid SHAPE but signed over a different msgID — the server-verify
	// data-integrity gate must catch the mismatch.
	d := signedDelete("room", general, "some_other_msg", priv)
	d.ID = "m_badsig"
	sendDelete(s, dave, d)

	if roomMsgDeleted(t, s, general, "m_badsig") {
		t.Error("cryptographically-invalid signature must not tombstone (data-integrity gate)")
	}
}

func TestHandleDelete_NonAuthorCollapsesToUnknown(t *testing.T) {
	s := newTestServer(t)
	general := s.store.RoomDisplayNameToID("general")
	seedKeyedUser(t, s, "dave", "Dave", false, []string{"general"})
	evePriv := seedKeyedUser(t, s, "eve", "Eve", false, []string{"general"})
	seedRoomMsg(t, s, general, "m_daves", "dave")
	eve := testClientFor("eve", "dev_eve")
	registerClient(s, eve)

	// Eve is a member but not the author and not an admin: a validly-signed
	// delete of Dave's message must collapse to the room's unknown response
	// (NOT ErrNotAuthorized) and must not tombstone.
	sendDelete(s, eve, signedDelete("room", general, "m_daves", evePriv))

	if roomMsgDeleted(t, s, general, "m_daves") {
		t.Error("non-author delete must not tombstone")
	}
	if code := firstErrorCode(eve); code != protocol.ErrUnknownRoom {
		t.Errorf("non-author error = %q, want %q (privacy collapse)", code, protocol.ErrUnknownRoom)
	}
}

func TestHandleDelete_RoomAdminDeletesOther(t *testing.T) {
	s := newTestServer(t)
	general := s.store.RoomDisplayNameToID("general")
	seedKeyedUser(t, s, "dave", "Dave", false, []string{"general"})
	modPriv := seedKeyedUser(t, s, "mod", "Mod", true, []string{"general"})
	seedRoomMsg(t, s, general, "m_modtarget", "dave")
	mod := testClientFor("mod", "dev_mod")
	registerClient(s, mod)

	// Admin deletes another user's room message (own-or-admin authz), signed by
	// the admin (the session user the server verifies against).
	sendDelete(s, mod, signedDelete("room", general, "m_modtarget", modPriv))

	if !roomMsgDeleted(t, s, general, "m_modtarget") {
		t.Error("room admin should be able to delete another user's message")
	}
	if !hasDeletedBroadcast(mod, "m_modtarget") {
		t.Error("expected a deleted broadcast for the admin delete")
	}
}

func TestHandleUnreact_ContextBoundValidSignatureDeletes(t *testing.T) {
	s := newTestServer(t)
	general := s.store.RoomDisplayNameToID("general")
	priv := seedKeyedUser(t, s, "dave", "Dave", false, []string{"general"})
	seedRoomMsg(t, s, general, "m_react_ok", "dave")
	seedRoomReaction(t, s, general, "m_react_ok", "react_ok", "dave")
	dave := testClientFor("dave", "dev_dave_unreact_ok")
	registerClient(s, dave)

	sendUnreact(s, dave, signedUnreact("room", general, "react_ok", priv))

	if roomReactionExists(t, s, general, "react_ok") {
		t.Error("valid signed unreact should delete the reaction")
	}
}

func TestHandleUnreact_RejectsInvalidSignatureBeforeDelete(t *testing.T) {
	s := newTestServer(t)
	general := s.store.RoomDisplayNameToID("general")
	priv := seedKeyedUser(t, s, "dave", "Dave", false, []string{"general"})
	seedRoomMsg(t, s, general, "m_react_bad_sig", "dave")
	seedRoomReaction(t, s, general, "m_react_bad_sig", "react_bad_sig", "dave")
	dave := testClientFor("dave", "dev_dave_unreact_bad_sig")
	registerClient(s, dave)

	// Valid length/base64, but signed for a different reaction_id.
	req := signedUnreact("room", general, "some_other_react", priv)
	req.ReactionID = "react_bad_sig"
	sendUnreact(s, dave, req)

	if !roomReactionExists(t, s, general, "react_bad_sig") {
		t.Error("cryptographically-invalid unreact must not delete the reaction")
	}
	if code := firstErrorCode(dave); code != "invalid_message" {
		t.Errorf("error code = %q, want invalid_message", code)
	}
}

func TestHandleUnreact_RejectsWrongContextBeforeDelete(t *testing.T) {
	s := newTestServer(t)
	general := s.store.RoomDisplayNameToID("general")
	priv := seedKeyedUser(t, s, "dave", "Dave", false, []string{"general"})
	groupID := store.GenerateID("group_")
	if err := s.store.CreateGroup(groupID, "dave", []string{"dave", "bob"}, "Test"); err != nil {
		t.Fatalf("create group: %v", err)
	}
	seedRoomMsg(t, s, general, "m_react_wrong_ctx", "dave")
	seedRoomReaction(t, s, general, "m_react_wrong_ctx", "react_wrong_ctx", "dave")
	dave := testClientFor("dave", "dev_dave_unreact_wrong_ctx")
	registerClient(s, dave)

	// The reaction lives in the room, but the request is signed/sent for a group.
	sendUnreact(s, dave, signedUnreact("group", groupID, "react_wrong_ctx", priv))

	if !roomReactionExists(t, s, general, "react_wrong_ctx") {
		t.Error("wrong-context unreact must not delete the reaction")
	}
}

func TestHandleUnreact_RejectsZeroAndMultiContext(t *testing.T) {
	s := newTestServer(t)
	general := s.store.RoomDisplayNameToID("general")
	priv := seedKeyedUser(t, s, "dave", "Dave", false, []string{"general"})
	seedRoomMsg(t, s, general, "m_react_ctx_shape", "dave")
	seedRoomReaction(t, s, general, "m_react_ctx_shape", "react_ctx_shape", "dave")
	dave := testClientFor("dave", "dev_dave_unreact_ctx_shape")
	registerClient(s, dave)

	zero := signedUnreact("room", general, "react_ctx_shape", priv)
	zero.Room = ""
	sendUnreact(s, dave, zero)

	multi := signedUnreact("room", general, "react_ctx_shape", priv)
	multi.Group = store.GenerateID("group_")
	sendUnreact(s, dave, multi)

	if !roomReactionExists(t, s, general, "react_ctx_shape") {
		t.Error("zero/multi-context unreact must not delete the reaction")
	}
}

// onlySyncBatch returns the single sync_batch frame among emitted frames,
// ignoring any bundled actor-profile frames (F6 §5b#17 emits profiles before
// the batch). Fails unless exactly one sync_batch is present.
func onlySyncBatch(t *testing.T, frames []json.RawMessage) protocol.SyncBatch {
	t.Helper()
	var batches []protocol.SyncBatch
	for _, raw := range frames {
		var b protocol.SyncBatch
		if json.Unmarshal(raw, &b) == nil && b.Type == "sync_batch" {
			batches = append(batches, b)
		}
	}
	if len(batches) != 1 {
		t.Fatalf("expected exactly 1 sync_batch, got %d (of %d frames)", len(batches), len(frames))
	}
	return batches[0]
}

// onlyHistoryResult is onlySyncBatch's history_result analogue.
func onlyHistoryResult(t *testing.T, frames []json.RawMessage) protocol.HistoryResult {
	t.Helper()
	var results []protocol.HistoryResult
	for _, raw := range frames {
		var hr protocol.HistoryResult
		if json.Unmarshal(raw, &hr) == nil && hr.Type == "history_result" {
			results = append(results, hr)
		}
	}
	if len(results) != 1 {
		t.Fatalf("expected exactly 1 history_result, got %d (of %d frames)", len(results), len(frames))
	}
	return results[0]
}

// TestSync_BundlesActorProfiles locks F6 §5b#17: a catch-up batch carrying a
// message emits a profile frame for that message's sender (which on a tombstone
// is the deleter) BEFORE the batch, so a reconnecting client can verify it even
// for a departed/never-pinned actor.
func TestSync_BundlesActorProfiles(t *testing.T) {
	s := newTestServer(t)
	groupID := store.GenerateID("group_")
	if err := s.store.CreateGroup(groupID, "alice", []string{"alice", "bob"}, "Test"); err != nil {
		t.Fatalf("create group: %v", err)
	}
	// A post-join message from alice (a seeded user with a resolvable key) at a
	// future TS, so it is visible to bob's catch-up.
	postTS := time.Now().Unix() + 3600
	if _, err := s.store.InsertGroupMessage(groupID, store.StoredMessage{
		ID: "m_bundle", Sender: "alice", TS: postTS, Payload: "p",
		WrappedKeys: map[string]string{"alice": "wa", "bob": "wb"},
	}); err != nil {
		t.Fatalf("insert group message: %v", err)
	}

	bob := testClientFor("bob", "dev_bob_bundle")
	s.syncGroup(bob.Client, groupID, 0, 100)

	frames := bob.messages()
	profileIdx, batchIdx := -1, -1
	for i, raw := range frames {
		var p protocol.Profile
		if json.Unmarshal(raw, &p) == nil && p.Type == "profile" && p.User == "alice" {
			profileIdx = i
		}
		var b protocol.SyncBatch
		if json.Unmarshal(raw, &b) == nil && b.Type == "sync_batch" {
			batchIdx = i
		}
	}
	if profileIdx < 0 {
		t.Fatal("expected a bundled profile frame for sender 'alice'")
	}
	if batchIdx < 0 {
		t.Fatal("expected a sync_batch")
	}
	if profileIdx > batchIdx {
		t.Errorf("profile (idx %d) must precede the sync_batch (idx %d)", profileIdx, batchIdx)
	}
}
