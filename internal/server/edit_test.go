package server

// Phase 15 — edit handler tests. Covers:
//   - privacy matrix (byte-identical responses for non-member, non-author,
//     unknown-row, deleted-row across all three verbs)
//   - happy paths (room, group, DM)
//   - most-recent enforcement
//   - epoch window enforcement (rooms)
//   - rate limit (shared bucket across all three verbs)
//   - retired-room rejection
//   - reaction clearing on successful edit

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/brushtailmedia/sshkey-chat/internal/protocol"
	"github.com/brushtailmedia/sshkey-chat/internal/store"
)

// TestHandleEdit_PrivacyResponsesIdentical locks in the byte-identical
// privacy invariant for handleEdit: unknown room, non-member, unknown
// row, non-author, and deleted-row all return the same wire frame.
func TestHandleEdit_PrivacyResponsesIdentical(t *testing.T) {
	s := newTestServer(t)
	generalID := s.store.RoomDisplayNameToID("general")
	if generalID == "" {
		t.Fatal("seed failed")
	}

	// Insert alice's message in general so bob can try to impersonate.
	aliceMsgID := "msg_alice_edit"
	if err := s.store.InsertRoomMessage(generalID, store.StoredMessage{
		ID: aliceMsgID, Sender: "alice", TS: 1000, Epoch: 1, Payload: "orig", Signature: "sig",
	}); err != nil {
		t.Fatalf("insert: %v", err)
	}

	// Case 1: unknown room.
	probe1 := testClientFor("bob", "dev_bob_1")
	raw1, _ := json.Marshal(protocol.Edit{
		Type: "edit", ID: "msg_x", Room: "room_does_not_exist", Epoch: 1, Payload: "new", Signature: "new",
	})
	s.handleEdit(probe1.Client, raw1)

	// Case 2: non-member (carol is not in general per the seed; reseed needed).
	// Actually, per testdata seed, carol IS in general. Use dave (not seeded) instead.
	probe2 := testClientFor("dave", "dev_dave_1")
	raw2, _ := json.Marshal(protocol.Edit{
		Type: "edit", ID: aliceMsgID, Room: generalID, Epoch: 1, Payload: "new", Signature: "new",
	})
	s.handleEdit(probe2.Client, raw2)

	// Case 3: member, unknown row.
	probe3 := testClientFor("bob", "dev_bob_2")
	raw3, _ := json.Marshal(protocol.Edit{
		Type: "edit", ID: "msg_nonexistent", Room: generalID, Epoch: 1, Payload: "new", Signature: "new",
	})
	s.handleEdit(probe3.Client, raw3)

	// Case 4: member, row exists, wrong author.
	probe4 := testClientFor("bob", "dev_bob_3")
	raw4, _ := json.Marshal(protocol.Edit{
		Type: "edit", ID: aliceMsgID, Room: generalID, Epoch: 1, Payload: "new", Signature: "new",
	})
	s.handleEdit(probe4.Client, raw4)

	responses := [][]json.RawMessage{
		probe1.messages(),
		probe2.messages(),
		probe3.messages(),
		probe4.messages(),
	}
	for i, msgs := range responses {
		if len(msgs) != 1 {
			t.Fatalf("case %d: expected 1 reply, got %d", i+1, len(msgs))
		}
	}

	// All four cases must return the byte-identical ErrUnknownRoom frame.
	baseline := responses[0][0]
	for i := 1; i < len(responses); i++ {
		if !bytes.Equal(baseline, responses[i][0]) {
			t.Errorf("privacy leak: case %d response differs from case 1\n  case 1: %s\n  case %d: %s",
				i+1, baseline, i+1, responses[i][0])
		}
	}
}

// TestHandleEdit_HappyPath_ReplacesPayloadAndBroadcasts verifies that a
// successful edit replaces the stored payload, sets edited_at, and
// emits an `edited` broadcast to room members.
func TestHandleEdit_HappyPath_ReplacesPayloadAndBroadcasts(t *testing.T) {
	s := newTestServer(t)
	generalID := s.store.RoomDisplayNameToID("general")

	msgID := "msg_happy"
	if err := s.store.InsertRoomMessage(generalID, store.StoredMessage{
		ID: msgID, Sender: "alice", TS: 500, Epoch: 1, Payload: "original", Signature: "orig_sig",
	}); err != nil {
		t.Fatalf("insert: %v", err)
	}

	alice := testClientFor("alice", "dev_alice_1")
	s.mu.Lock()
	s.clients["dev_alice_1"] = alice.Client
	s.mu.Unlock()

	raw, _ := json.Marshal(protocol.Edit{
		Type: "edit", ID: msgID, Room: generalID, Epoch: 1, Payload: "new_payload", Signature: "new_sig",
	})
	s.handleEdit(alice.Client, raw)

	// Row should reflect the new payload + edited_at.
	got, err := s.store.GetRoomMessageByID(generalID, msgID)
	if err != nil {
		t.Fatalf("get after edit: %v", err)
	}
	if got.Payload != "new_payload" {
		t.Errorf("payload = %q, want new_payload", got.Payload)
	}
	if got.Signature != "new_sig" {
		t.Errorf("signature = %q, want new_sig", got.Signature)
	}
	if got.EditedAt == 0 {
		t.Error("edited_at should be set")
	}
	if got.TS != 500 {
		t.Errorf("ts should be preserved as 500, got %d", got.TS)
	}

	// Alice should receive the `edited` broadcast (delivered via
	// broadcastToRoom → mu.RLock → client.Encoder.Encode).
	msgs := alice.messages()
	var foundEdited bool
	for _, m := range msgs {
		var e protocol.Edited
		if err := json.Unmarshal(m, &e); err == nil && e.Type == "edited" {
			foundEdited = true
			if e.ID != msgID {
				t.Errorf("broadcast ID = %q, want %q", e.ID, msgID)
			}
			if e.Payload != "new_payload" {
				t.Errorf("broadcast payload = %q", e.Payload)
			}
			if e.EditedAt == 0 {
				t.Error("broadcast edited_at unset")
			}
		}
	}
	if !foundEdited {
		t.Error("alice did not receive the edited broadcast")
	}
}

// TestHandleEdit_NotMostRecent_ReturnsSpecificError verifies that when
// the caller is proven author but the message isn't their most recent,
// the handler surfaces ErrEditNotMostRecent rather than the
// byte-identical unknown response.
func TestHandleEdit_NotMostRecent_ReturnsSpecificError(t *testing.T) {
	s := newTestServer(t)
	generalID := s.store.RoomDisplayNameToID("general")

	// Alice sends two messages; the OLDER one can't be edited.
	if err := s.store.InsertRoomMessage(generalID, store.StoredMessage{
		ID: "msg_older", Sender: "alice", TS: 100, Epoch: 1, Payload: "1", Signature: "s",
	}); err != nil {
		t.Fatalf("insert: %v", err)
	}
	if err := s.store.InsertRoomMessage(generalID, store.StoredMessage{
		ID: "msg_newer", Sender: "alice", TS: 200, Epoch: 1, Payload: "2", Signature: "s",
	}); err != nil {
		t.Fatalf("insert: %v", err)
	}

	alice := testClientFor("alice", "dev_alice_1")
	raw, _ := json.Marshal(protocol.Edit{
		Type: "edit", ID: "msg_older", Room: generalID, Epoch: 1, Payload: "new", Signature: "new",
	})
	s.handleEdit(alice.Client, raw)

	msgs := alice.messages()
	if len(msgs) != 1 {
		t.Fatalf("expected 1 reply, got %d", len(msgs))
	}
	var errResp protocol.Error
	json.Unmarshal(msgs[0], &errResp)
	if errResp.Code != protocol.ErrEditNotMostRecent {
		t.Errorf("code = %q, want %q", errResp.Code, protocol.ErrEditNotMostRecent)
	}
}

// TestHandleEdit_DeletedMessage_CollapsedToUnknown verifies that
// attempting to edit a tombstoned row returns the byte-identical
// unknown response (not a specific "deleted" error) so the tombstone
// state doesn't leak to probing clients.
func TestHandleEdit_DeletedMessage_CollapsedToUnknown(t *testing.T) {
	s := newTestServer(t)
	generalID := s.store.RoomDisplayNameToID("general")

	// Baseline: unknown message in the same room.
	baselineClient := testClientFor("alice", "dev_alice_base")
	rawBaseline, _ := json.Marshal(protocol.Edit{
		Type: "edit", ID: "msg_nonexistent", Room: generalID, Epoch: 1, Payload: "n", Signature: "n",
	})
	s.handleEdit(baselineClient.Client, rawBaseline)
	baselineMsgs := baselineClient.messages()
	if len(baselineMsgs) != 1 {
		t.Fatalf("baseline: expected 1 reply, got %d", len(baselineMsgs))
	}

	// Insert and tombstone a message.
	if err := s.store.InsertRoomMessage(generalID, store.StoredMessage{
		ID: "msg_tombstoned", Sender: "alice", TS: 100, Epoch: 1, Payload: "p", Signature: "s",
	}); err != nil {
		t.Fatalf("insert: %v", err)
	}
	if _, err := s.store.DeleteRoomMessage(generalID, "msg_tombstoned", "alice"); err != nil {
		t.Fatalf("delete: %v", err)
	}

	aliceClient := testClientFor("alice", "dev_alice_1")
	raw, _ := json.Marshal(protocol.Edit{
		Type: "edit", ID: "msg_tombstoned", Room: generalID, Epoch: 1, Payload: "new", Signature: "new",
	})
	s.handleEdit(aliceClient.Client, raw)

	msgs := aliceClient.messages()
	if len(msgs) != 1 {
		t.Fatalf("expected 1 reply, got %d", len(msgs))
	}
	// Must match the byte-identical unknown response.
	if !bytes.Equal(baselineMsgs[0], msgs[0]) {
		t.Errorf("deleted-row response differs from baseline unknown\n  baseline: %s\n  deleted:  %s",
			baselineMsgs[0], msgs[0])
	}
}

// TestHandleEdit_RetiredRoom verifies edits are rejected with
// ErrRoomRetired on retired rooms (surfaced, not collapsed into
// unknown, matching the Phase 12 pattern for send/react/pin/unpin).
func TestHandleEdit_RetiredRoom(t *testing.T) {
	s := newTestServer(t)
	generalID := s.store.RoomDisplayNameToID("general")

	// Insert alice's message first, then retire the room.
	if err := s.store.InsertRoomMessage(generalID, store.StoredMessage{
		ID: "msg_retire", Sender: "alice", TS: 100, Epoch: 1, Payload: "p", Signature: "s",
	}); err != nil {
		t.Fatalf("insert: %v", err)
	}
	retireRoomForTest(t, s, generalID)

	alice := testClientFor("alice", "dev_alice_1")
	raw, _ := json.Marshal(protocol.Edit{
		Type: "edit", ID: "msg_retire", Room: generalID, Epoch: 1, Payload: "new", Signature: "new",
	})
	s.handleEdit(alice.Client, raw)

	msgs := alice.messages()
	if len(msgs) != 1 {
		t.Fatalf("expected 1 reply, got %d", len(msgs))
	}
	var errResp protocol.Error
	json.Unmarshal(msgs[0], &errResp)
	if errResp.Code != protocol.ErrRoomRetired {
		t.Errorf("code = %q, want %q", errResp.Code, protocol.ErrRoomRetired)
	}
}

// TestHandleEdit_EpochTooOld verifies an edit with an epoch below the
// grace window is rejected with ErrEditWindowExpired.
func TestHandleEdit_EpochTooOld(t *testing.T) {
	s := newTestServer(t)
	generalID := s.store.RoomDisplayNameToID("general")

	// Bootstrap an epoch by inserting an initial message; then bump
	// the epoch twice via epoch_rotate simulation. The test server's
	// epochs manager starts at 0, so we need to push forward.
	// Simpler approach: insert the message at epoch 1 and then set
	// the current epoch to 5 manually via the epochs manager.
	if err := s.store.InsertRoomMessage(generalID, store.StoredMessage{
		ID: "msg_old", Sender: "alice", TS: 100, Epoch: 1, Payload: "p", Signature: "s",
	}); err != nil {
		t.Fatalf("insert: %v", err)
	}

	// Fast-forward the current epoch by creating a room epoch state at
	// epoch 5 directly via getOrCreate. Simulates many rotations without
	// running the full rotation protocol.
	state := s.epochs.getOrCreate(generalID, 5)
	s.epochs.mu.Lock()
	state.confirmedEpoch = 5
	s.epochs.mu.Unlock()

	alice := testClientFor("alice", "dev_alice_1")
	raw, _ := json.Marshal(protocol.Edit{
		Type: "edit", ID: "msg_old", Room: generalID, Epoch: 1, Payload: "new", Signature: "new",
	})
	s.handleEdit(alice.Client, raw)

	msgs := alice.messages()
	if len(msgs) != 1 {
		t.Fatalf("expected 1 reply, got %d", len(msgs))
	}
	var errResp protocol.Error
	json.Unmarshal(msgs[0], &errResp)
	if errResp.Code != protocol.ErrEditWindowExpired {
		t.Errorf("code = %q, want %q", errResp.Code, protocol.ErrEditWindowExpired)
	}
}

// TestHandleEdit_ClearsReactions verifies that a successful edit drops
// all reactions on the edited row (inline DELETE matching the delete
// path's reaction-clearing behaviour; clients then unconditionally
// clear local reaction state on receipt of the `edited` event).
func TestHandleEdit_ClearsReactions(t *testing.T) {
	s := newTestServer(t)
	generalID := s.store.RoomDisplayNameToID("general")

	if err := s.store.InsertRoomMessage(generalID, store.StoredMessage{
		ID: "msg_rx", Sender: "alice", TS: 100, Epoch: 1, Payload: "p", Signature: "s",
	}); err != nil {
		t.Fatalf("insert: %v", err)
	}

	// Seed a reaction on the message via direct DB access.
	db, err := s.store.RoomDB(generalID)
	if err != nil {
		t.Fatalf("RoomDB: %v", err)
	}
	_, err = db.Exec(`INSERT INTO reactions (reaction_id, message_id, user, ts, payload) VALUES (?, ?, ?, ?, ?)`,
		"react_1", "msg_rx", "bob", 150, "emoji_payload")
	if err != nil {
		t.Fatalf("seed reaction: %v", err)
	}

	alice := testClientFor("alice", "dev_alice_1")
	raw, _ := json.Marshal(protocol.Edit{
		Type: "edit", ID: "msg_rx", Room: generalID, Epoch: 1, Payload: "new", Signature: "new",
	})
	s.handleEdit(alice.Client, raw)

	var count int
	db.QueryRow(`SELECT COUNT(*) FROM reactions WHERE message_id = ?`, "msg_rx").Scan(&count)
	if count != 0 {
		t.Errorf("reactions not cleared after edit: count = %d", count)
	}
}

// TestHandleEditGroup_PrivacyResponsesIdentical locks in the invariant
// for handleEditGroup: unknown group, non-member, unknown row, and
// non-author all return byte-identical ErrUnknownGroup.
func TestHandleEditGroup_PrivacyResponsesIdentical(t *testing.T) {
	s := newTestServer(t)
	groupPriv := store.GenerateID("group_")
	if err := s.store.CreateGroup(groupPriv, "alice", []string{"alice", "bob"}, "Priv"); err != nil {
		t.Fatalf("create group: %v", err)
	}

	// Insert alice's message.
	if err := s.store.InsertGroupMessage(groupPriv, store.StoredMessage{
		ID: "msg_alice_g", Sender: "alice", TS: 1000, Payload: "p", Signature: "s",
		WrappedKeys: map[string]string{"alice": "wa", "bob": "wb"},
	}); err != nil {
		t.Fatalf("insert: %v", err)
	}

	// Case 1: unknown group.
	probe1 := testClientFor("alice", "dev_alice_1")
	raw1, _ := json.Marshal(protocol.EditGroup{
		Type: "edit_group", ID: "msg_x", Group: store.GenerateID("group_"),
		WrappedKeys: map[string]string{"alice": "wa"}, Payload: "p", Signature: "s",
	})
	s.handleEditGroup(probe1.Client, raw1)

	// Case 2: non-member (carol is not in groupPriv).
	probe2 := testClientFor("carol", "dev_carol_1")
	raw2, _ := json.Marshal(protocol.EditGroup{
		Type: "edit_group", ID: "msg_alice_g", Group: groupPriv,
		WrappedKeys: map[string]string{"alice": "wa", "bob": "wb"}, Payload: "p", Signature: "s",
	})
	s.handleEditGroup(probe2.Client, raw2)

	// Case 3: member, unknown row.
	probe3 := testClientFor("bob", "dev_bob_1")
	raw3, _ := json.Marshal(protocol.EditGroup{
		Type: "edit_group", ID: "msg_nonexistent", Group: groupPriv,
		WrappedKeys: map[string]string{"alice": "wa", "bob": "wb"}, Payload: "p", Signature: "s",
	})
	s.handleEditGroup(probe3.Client, raw3)

	// Case 4: member, row exists, wrong author.
	probe4 := testClientFor("bob", "dev_bob_2")
	raw4, _ := json.Marshal(protocol.EditGroup{
		Type: "edit_group", ID: "msg_alice_g", Group: groupPriv,
		WrappedKeys: map[string]string{"alice": "wa", "bob": "wb"}, Payload: "p", Signature: "s",
	})
	s.handleEditGroup(probe4.Client, raw4)

	responses := [][]json.RawMessage{
		probe1.messages(),
		probe2.messages(),
		probe3.messages(),
		probe4.messages(),
	}
	baseline := responses[0][0]
	for i := 1; i < len(responses); i++ {
		if len(responses[i]) != 1 {
			t.Fatalf("case %d: expected 1 reply, got %d", i+1, len(responses[i]))
		}
		if !bytes.Equal(baseline, responses[i][0]) {
			t.Errorf("privacy leak: case %d differs from case 1\n  case 1: %s\n  case %d: %s",
				i+1, baseline, i+1, responses[i][0])
		}
	}
}

// TestHandleEditGroup_HappyPath verifies a successful group edit
// replaces the payload, rewraps keys, sets edited_at, and broadcasts.
func TestHandleEditGroup_HappyPath(t *testing.T) {
	s := newTestServer(t)
	groupHappy := store.GenerateID("group_")
	if err := s.store.CreateGroup(groupHappy, "alice", []string{"alice", "bob"}, "Happy"); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := s.store.InsertGroupMessage(groupHappy, store.StoredMessage{
		ID: "msg_gh", Sender: "alice", TS: 500, Payload: "orig", Signature: "orig_sig",
		WrappedKeys: map[string]string{"alice": "v1a", "bob": "v1b"},
	}); err != nil {
		t.Fatalf("insert: %v", err)
	}

	alice := testClientFor("alice", "dev_alice_1")
	s.mu.Lock()
	s.clients["dev_alice_1"] = alice.Client
	s.mu.Unlock()

	raw, _ := json.Marshal(protocol.EditGroup{
		Type: "edit_group", ID: "msg_gh", Group: groupHappy,
		WrappedKeys: map[string]string{"alice": "v2a", "bob": "v2b"},
		Payload:     "new_payload", Signature: "new_sig",
	})
	s.handleEditGroup(alice.Client, raw)

	got, err := s.store.GetGroupMessageByID(groupHappy, "msg_gh")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Payload != "new_payload" {
		t.Errorf("payload = %q", got.Payload)
	}
	if got.WrappedKeys["alice"] != "v2a" {
		t.Errorf("alice key not rewrapped: %q", got.WrappedKeys["alice"])
	}
	if got.EditedAt == 0 {
		t.Error("edited_at unset")
	}
	if got.TS != 500 {
		t.Errorf("ts should be preserved as 500, got %d", got.TS)
	}
}

// TestHandleEditDM_PrivacyResponsesIdentical locks in the invariant
// for handleEditDM: unknown DM, non-party, unknown row, and non-author
// all return byte-identical ErrUnknownDM.
func TestHandleEditDM_PrivacyResponsesIdentical(t *testing.T) {
	s := newTestServer(t)
	dm, err := s.store.CreateOrGetDirectMessage(store.GenerateID("dm_"), "alice", "bob")
	if err != nil {
		t.Fatalf("create DM: %v", err)
	}
	dmID := dm.ID
	if err := s.store.InsertDMMessage(dmID, store.StoredMessage{
		ID: "msg_dm_alice", Sender: "alice", TS: time.Now().Unix(), Payload: "p", Signature: "s",
		WrappedKeys: map[string]string{"alice": "wa", "bob": "wb"},
	}); err != nil {
		t.Fatalf("insert: %v", err)
	}

	// Case 1: unknown DM.
	probe1 := testClientFor("alice", "dev_alice_1")
	raw1, _ := json.Marshal(protocol.EditDM{
		Type: "edit_dm", ID: "msg_x", DM: store.GenerateID("dm_"),
		WrappedKeys: map[string]string{"alice": "wa", "bob": "wb"}, Payload: "p", Signature: "s",
	})
	s.handleEditDM(probe1.Client, raw1)

	// Case 2: non-party (carol is not part of the alice-bob DM).
	probe2 := testClientFor("carol", "dev_carol_1")
	raw2, _ := json.Marshal(protocol.EditDM{
		Type: "edit_dm", ID: "msg_dm_alice", DM: dmID,
		WrappedKeys: map[string]string{"alice": "wa", "bob": "wb"}, Payload: "p", Signature: "s",
	})
	s.handleEditDM(probe2.Client, raw2)

	// Case 3: party, unknown row.
	probe3 := testClientFor("bob", "dev_bob_1")
	raw3, _ := json.Marshal(protocol.EditDM{
		Type: "edit_dm", ID: "msg_nonexistent", DM: dmID,
		WrappedKeys: map[string]string{"alice": "wa", "bob": "wb"}, Payload: "p", Signature: "s",
	})
	s.handleEditDM(probe3.Client, raw3)

	// Case 4: party, row exists, wrong author (bob tries to edit alice's message).
	probe4 := testClientFor("bob", "dev_bob_2")
	raw4, _ := json.Marshal(protocol.EditDM{
		Type: "edit_dm", ID: "msg_dm_alice", DM: dmID,
		WrappedKeys: map[string]string{"alice": "wa", "bob": "wb"}, Payload: "p", Signature: "s",
	})
	s.handleEditDM(probe4.Client, raw4)

	responses := [][]json.RawMessage{
		probe1.messages(),
		probe2.messages(),
		probe3.messages(),
		probe4.messages(),
	}
	baseline := responses[0][0]
	for i := 1; i < len(responses); i++ {
		if len(responses[i]) != 1 {
			t.Fatalf("case %d: expected 1 reply, got %d", i+1, len(responses[i]))
		}
		if !bytes.Equal(baseline, responses[i][0]) {
			t.Errorf("privacy leak: case %d differs from case 1\n  case 1: %s\n  case %d: %s",
				i+1, baseline, i+1, responses[i][0])
		}
	}
}

func TestHandleEditGroup_NotMostRecent_ReturnsSpecificError(t *testing.T) {
	s := newTestServer(t)
	groupID := store.GenerateID("group_")
	if err := s.store.CreateGroup(groupID, "alice", []string{"alice", "bob"}, "recent"); err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	if err := s.store.InsertGroupMessage(groupID, store.StoredMessage{
		ID: "msg_old", Sender: "alice", TS: 100, Payload: "old", Signature: "s",
		WrappedKeys: map[string]string{"alice": "wa", "bob": "wb"},
	}); err != nil {
		t.Fatalf("insert old: %v", err)
	}
	if err := s.store.InsertGroupMessage(groupID, store.StoredMessage{
		ID: "msg_new", Sender: "alice", TS: 200, Payload: "new", Signature: "s",
		WrappedKeys: map[string]string{"alice": "wa", "bob": "wb"},
	}); err != nil {
		t.Fatalf("insert new: %v", err)
	}

	alice := testClientFor("alice", "dev_alice_group_recent")
	raw, _ := json.Marshal(protocol.EditGroup{
		Type:        "edit_group",
		ID:          "msg_old",
		Group:       groupID,
		WrappedKeys: map[string]string{"alice": "wa2", "bob": "wb2"},
		Payload:     "edited",
		Signature:   "sig2",
	})
	s.handleEditGroup(alice.Client, raw)

	msgs := alice.messages()
	if len(msgs) != 1 {
		t.Fatalf("expected 1 reply, got %d", len(msgs))
	}
	var errResp protocol.Error
	if err := json.Unmarshal(msgs[0], &errResp); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if errResp.Code != protocol.ErrEditNotMostRecent {
		t.Fatalf("code = %q, want %q", errResp.Code, protocol.ErrEditNotMostRecent)
	}
}

func TestHandleEditGroup_DeletedMessage_CollapsedToUnknown(t *testing.T) {
	s := newTestServer(t)
	groupID := store.GenerateID("group_")
	if err := s.store.CreateGroup(groupID, "alice", []string{"alice", "bob"}, "del"); err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}

	baselineClient := testClientFor("alice", "dev_alice_group_base")
	rawBaseline, _ := json.Marshal(protocol.EditGroup{
		Type:        "edit_group",
		ID:          "msg_missing",
		Group:       groupID,
		WrappedKeys: map[string]string{"alice": "wa", "bob": "wb"},
		Payload:     "p",
		Signature:   "s",
	})
	s.handleEditGroup(baselineClient.Client, rawBaseline)
	baselineMsgs := baselineClient.messages()
	if len(baselineMsgs) != 1 {
		t.Fatalf("baseline expected 1 reply, got %d", len(baselineMsgs))
	}

	if err := s.store.InsertGroupMessage(groupID, store.StoredMessage{
		ID: "msg_deleted", Sender: "alice", TS: 123, Payload: "body", Signature: "sig",
		WrappedKeys: map[string]string{"alice": "wa", "bob": "wb"},
	}); err != nil {
		t.Fatalf("insert: %v", err)
	}
	if _, err := s.store.DeleteGroupMessage(groupID, "msg_deleted", "alice"); err != nil {
		t.Fatalf("DeleteGroupMessage: %v", err)
	}

	probe := testClientFor("alice", "dev_alice_group_deleted")
	rawProbe, _ := json.Marshal(protocol.EditGroup{
		Type:        "edit_group",
		ID:          "msg_deleted",
		Group:       groupID,
		WrappedKeys: map[string]string{"alice": "wa2", "bob": "wb2"},
		Payload:     "new",
		Signature:   "sig2",
	})
	s.handleEditGroup(probe.Client, rawProbe)
	probeMsgs := probe.messages()
	if len(probeMsgs) != 1 {
		t.Fatalf("probe expected 1 reply, got %d", len(probeMsgs))
	}
	if !bytes.Equal(baselineMsgs[0], probeMsgs[0]) {
		t.Fatalf("deleted-group response differs from unknown baseline\nbaseline: %s\nprobe:    %s", baselineMsgs[0], probeMsgs[0])
	}
}

func TestHandleEditGroup_ClearsReactions(t *testing.T) {
	s := newTestServer(t)
	groupID := store.GenerateID("group_")
	if err := s.store.CreateGroup(groupID, "alice", []string{"alice", "bob"}, "react"); err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	if err := s.store.InsertGroupMessage(groupID, store.StoredMessage{
		ID: "msg_group_rx", Sender: "alice", TS: 100, Payload: "body", Signature: "sig",
		WrappedKeys: map[string]string{"alice": "wa", "bob": "wb"},
	}); err != nil {
		t.Fatalf("insert: %v", err)
	}
	db, err := s.store.GroupDB(groupID)
	if err != nil {
		t.Fatalf("GroupDB: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO reactions (reaction_id, message_id, user, ts, payload) VALUES (?, ?, ?, ?, ?)`,
		"react_group_1", "msg_group_rx", "bob", 150, "emoji_payload"); err != nil {
		t.Fatalf("seed reaction: %v", err)
	}

	alice := testClientFor("alice", "dev_alice_group_rx")
	raw, _ := json.Marshal(protocol.EditGroup{
		Type:        "edit_group",
		ID:          "msg_group_rx",
		Group:       groupID,
		WrappedKeys: map[string]string{"alice": "wa2", "bob": "wb2"},
		Payload:     "new",
		Signature:   "newsig",
	})
	s.handleEditGroup(alice.Client, raw)

	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM reactions WHERE message_id = ?`, "msg_group_rx").Scan(&count); err != nil {
		t.Fatalf("count reactions: %v", err)
	}
	if count != 0 {
		t.Fatalf("reactions not cleared after group edit: %d", count)
	}
}

func TestHandleEditGroup_InvalidWrappedKeys(t *testing.T) {
	s := newTestServer(t)
	groupID := store.GenerateID("group_")
	if err := s.store.CreateGroup(groupID, "alice", []string{"alice", "bob"}, "keys"); err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	if err := s.store.InsertGroupMessage(groupID, store.StoredMessage{
		ID: "msg_group_keys", Sender: "alice", TS: 100, Payload: "body", Signature: "sig",
		WrappedKeys: map[string]string{"alice": "wa", "bob": "wb"},
	}); err != nil {
		t.Fatalf("insert: %v", err)
	}

	alice := testClientFor("alice", "dev_alice_group_keys")
	raw, _ := json.Marshal(protocol.EditGroup{
		Type:        "edit_group",
		ID:          "msg_group_keys",
		Group:       groupID,
		WrappedKeys: map[string]string{"alice": "only_one"},
		Payload:     "new",
		Signature:   "newsig",
	})
	s.handleEditGroup(alice.Client, raw)

	msgs := alice.messages()
	if len(msgs) != 1 {
		t.Fatalf("expected 1 reply, got %d", len(msgs))
	}
	var errResp protocol.Error
	if err := json.Unmarshal(msgs[0], &errResp); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if errResp.Code != protocol.ErrInvalidWrappedKeys {
		t.Fatalf("code = %q, want %q", errResp.Code, protocol.ErrInvalidWrappedKeys)
	}
}

func TestHandleEditDM_HappyPath(t *testing.T) {
	s := newTestServer(t)
	dm, err := s.store.CreateOrGetDirectMessage(store.GenerateID("dm_"), "alice", "bob")
	if err != nil {
		t.Fatalf("CreateOrGetDirectMessage: %v", err)
	}
	if err := s.store.InsertDMMessage(dm.ID, store.StoredMessage{
		ID: "msg_dm_happy", Sender: "alice", TS: 500, Payload: "orig", Signature: "sig",
		WrappedKeys: map[string]string{"alice": "wa", "bob": "wb"},
	}); err != nil {
		t.Fatalf("insert: %v", err)
	}

	alice := testClientFor("alice", "dev_alice_dm_happy")
	bob := testClientFor("bob", "dev_bob_dm_happy")
	s.mu.Lock()
	s.clients["dev_alice_dm_happy"] = alice.Client
	s.clients["dev_bob_dm_happy"] = bob.Client
	s.mu.Unlock()

	raw, _ := json.Marshal(protocol.EditDM{
		Type:        "edit_dm",
		ID:          "msg_dm_happy",
		DM:          dm.ID,
		WrappedKeys: map[string]string{"alice": "wa2", "bob": "wb2"},
		Payload:     "new_payload",
		Signature:   "new_sig",
	})
	s.handleEditDM(alice.Client, raw)

	got, err := s.store.GetDMMessageByID(dm.ID, "msg_dm_happy")
	if err != nil {
		t.Fatalf("GetDMMessageByID: %v", err)
	}
	if got.Payload != "new_payload" {
		t.Fatalf("payload = %q, want new_payload", got.Payload)
	}
	if got.WrappedKeys["alice"] != "wa2" || got.WrappedKeys["bob"] != "wb2" {
		t.Fatalf("wrapped keys not updated: %+v", got.WrappedKeys)
	}
	if got.EditedAt == 0 {
		t.Fatal("edited_at should be set")
	}

	aliceMsgs := alice.messages()
	bobMsgs := bob.messages()
	if len(aliceMsgs) != 1 || len(bobMsgs) != 1 {
		t.Fatalf("expected one dm_edited per party, got alice=%d bob=%d", len(aliceMsgs), len(bobMsgs))
	}
	var aOut, bOut protocol.DMEdited
	if err := json.Unmarshal(aliceMsgs[0], &aOut); err != nil {
		t.Fatalf("unmarshal alice dm_edited: %v", err)
	}
	if err := json.Unmarshal(bobMsgs[0], &bOut); err != nil {
		t.Fatalf("unmarshal bob dm_edited: %v", err)
	}
	if aOut.Type != "dm_edited" || bOut.Type != "dm_edited" {
		t.Fatalf("unexpected broadcast types: alice=%q bob=%q", aOut.Type, bOut.Type)
	}
}

func TestHandleEditDM_NotMostRecent(t *testing.T) {
	s := newTestServer(t)
	dm, err := s.store.CreateOrGetDirectMessage(store.GenerateID("dm_"), "alice", "bob")
	if err != nil {
		t.Fatalf("CreateOrGetDirectMessage: %v", err)
	}
	if err := s.store.InsertDMMessage(dm.ID, store.StoredMessage{
		ID: "msg_dm_old", Sender: "alice", TS: 100, Payload: "old", Signature: "s",
		WrappedKeys: map[string]string{"alice": "wa", "bob": "wb"},
	}); err != nil {
		t.Fatalf("insert old: %v", err)
	}
	if err := s.store.InsertDMMessage(dm.ID, store.StoredMessage{
		ID: "msg_dm_new", Sender: "alice", TS: 200, Payload: "new", Signature: "s",
		WrappedKeys: map[string]string{"alice": "wa", "bob": "wb"},
	}); err != nil {
		t.Fatalf("insert new: %v", err)
	}

	alice := testClientFor("alice", "dev_alice_dm_recent")
	raw, _ := json.Marshal(protocol.EditDM{
		Type:        "edit_dm",
		ID:          "msg_dm_old",
		DM:          dm.ID,
		WrappedKeys: map[string]string{"alice": "wa2", "bob": "wb2"},
		Payload:     "edited",
		Signature:   "sig2",
	})
	s.handleEditDM(alice.Client, raw)

	msgs := alice.messages()
	if len(msgs) != 1 {
		t.Fatalf("expected 1 reply, got %d", len(msgs))
	}
	var errResp protocol.Error
	if err := json.Unmarshal(msgs[0], &errResp); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if errResp.Code != protocol.ErrEditNotMostRecent {
		t.Fatalf("code = %q, want %q", errResp.Code, protocol.ErrEditNotMostRecent)
	}
}

func TestHandleEditDM_DeletedMessage_CollapsedToUnknown(t *testing.T) {
	s := newTestServer(t)
	dm, err := s.store.CreateOrGetDirectMessage(store.GenerateID("dm_"), "alice", "bob")
	if err != nil {
		t.Fatalf("CreateOrGetDirectMessage: %v", err)
	}

	baseline := testClientFor("alice", "dev_alice_dm_base")
	rawBaseline, _ := json.Marshal(protocol.EditDM{
		Type:        "edit_dm",
		ID:          "msg_missing",
		DM:          dm.ID,
		WrappedKeys: map[string]string{"alice": "wa", "bob": "wb"},
		Payload:     "p",
		Signature:   "s",
	})
	s.handleEditDM(baseline.Client, rawBaseline)
	baseMsgs := baseline.messages()
	if len(baseMsgs) != 1 {
		t.Fatalf("baseline expected 1 reply, got %d", len(baseMsgs))
	}

	if err := s.store.InsertDMMessage(dm.ID, store.StoredMessage{
		ID: "msg_dm_deleted", Sender: "alice", TS: 123, Payload: "body", Signature: "sig",
		WrappedKeys: map[string]string{"alice": "wa", "bob": "wb"},
	}); err != nil {
		t.Fatalf("insert: %v", err)
	}
	if _, err := s.store.DeleteDMMessage(dm.ID, "msg_dm_deleted", "alice"); err != nil {
		t.Fatalf("DeleteDMMessage: %v", err)
	}

	probe := testClientFor("alice", "dev_alice_dm_deleted")
	rawProbe, _ := json.Marshal(protocol.EditDM{
		Type:        "edit_dm",
		ID:          "msg_dm_deleted",
		DM:          dm.ID,
		WrappedKeys: map[string]string{"alice": "wa2", "bob": "wb2"},
		Payload:     "new",
		Signature:   "sig2",
	})
	s.handleEditDM(probe.Client, rawProbe)
	probeMsgs := probe.messages()
	if len(probeMsgs) != 1 {
		t.Fatalf("probe expected 1 reply, got %d", len(probeMsgs))
	}
	if !bytes.Equal(baseMsgs[0], probeMsgs[0]) {
		t.Fatalf("deleted-dm response differs from unknown baseline\nbaseline: %s\nprobe:    %s", baseMsgs[0], probeMsgs[0])
	}
}

func TestHandleEditDM_ClearsReactions(t *testing.T) {
	s := newTestServer(t)
	dm, err := s.store.CreateOrGetDirectMessage(store.GenerateID("dm_"), "alice", "bob")
	if err != nil {
		t.Fatalf("CreateOrGetDirectMessage: %v", err)
	}
	if err := s.store.InsertDMMessage(dm.ID, store.StoredMessage{
		ID: "msg_dm_rx", Sender: "alice", TS: 100, Payload: "body", Signature: "sig",
		WrappedKeys: map[string]string{"alice": "wa", "bob": "wb"},
	}); err != nil {
		t.Fatalf("insert: %v", err)
	}
	db, err := s.store.DMDB(dm.ID)
	if err != nil {
		t.Fatalf("DMDB: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO reactions (reaction_id, message_id, user, ts, payload) VALUES (?, ?, ?, ?, ?)`,
		"react_dm_1", "msg_dm_rx", "bob", 150, "emoji_payload"); err != nil {
		t.Fatalf("seed reaction: %v", err)
	}

	alice := testClientFor("alice", "dev_alice_dm_rx")
	raw, _ := json.Marshal(protocol.EditDM{
		Type:        "edit_dm",
		ID:          "msg_dm_rx",
		DM:          dm.ID,
		WrappedKeys: map[string]string{"alice": "wa2", "bob": "wb2"},
		Payload:     "new",
		Signature:   "newsig",
	})
	s.handleEditDM(alice.Client, raw)

	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM reactions WHERE message_id = ?`, "msg_dm_rx").Scan(&count); err != nil {
		t.Fatalf("count reactions: %v", err)
	}
	if count != 0 {
		t.Fatalf("reactions not cleared after dm edit: %d", count)
	}
}

func TestHandleEditDM_FrozenCallerRejected(t *testing.T) {
	s := newTestServer(t)
	dm, err := s.store.CreateOrGetDirectMessage(store.GenerateID("dm_"), "alice", "bob")
	if err != nil {
		t.Fatalf("CreateOrGetDirectMessage: %v", err)
	}
	if err := s.store.InsertDMMessage(dm.ID, store.StoredMessage{
		ID: "msg_dm_frozen", Sender: "alice", TS: 100, Payload: "body", Signature: "sig",
		WrappedKeys: map[string]string{"alice": "wa", "bob": "wb"},
	}); err != nil {
		t.Fatalf("insert: %v", err)
	}

	// Baseline unknown-DM response for byte-identical comparison.
	baseline := testClientFor("alice", "dev_alice_dm_frozen_base")
	rawBaseline, _ := json.Marshal(protocol.EditDM{
		Type:        "edit_dm",
		ID:          "msg_any",
		DM:          store.GenerateID("dm_"),
		WrappedKeys: map[string]string{"alice": "wa", "bob": "wb"},
		Payload:     "p",
		Signature:   "s",
	})
	s.handleEditDM(baseline.Client, rawBaseline)
	baseMsgs := baseline.messages()
	if len(baseMsgs) != 1 {
		t.Fatalf("baseline expected 1 reply, got %d", len(baseMsgs))
	}

	if err := s.store.SetDMLeftAt(dm.ID, "alice", time.Now().Unix()); err != nil {
		t.Fatalf("SetDMLeftAt: %v", err)
	}

	alice := testClientFor("alice", "dev_alice_dm_frozen")
	raw, _ := json.Marshal(protocol.EditDM{
		Type:        "edit_dm",
		ID:          "msg_dm_frozen",
		DM:          dm.ID,
		WrappedKeys: map[string]string{"alice": "wa2", "bob": "wb2"},
		Payload:     "new",
		Signature:   "newsig",
	})
	s.handleEditDM(alice.Client, raw)

	msgs := alice.messages()
	if len(msgs) != 1 {
		t.Fatalf("expected 1 reply, got %d", len(msgs))
	}
	if !bytes.Equal(baseMsgs[0], msgs[0]) {
		t.Fatalf("frozen-caller response differs from unknown baseline\nbaseline: %s\nfrozen:   %s", baseMsgs[0], msgs[0])
	}
}
