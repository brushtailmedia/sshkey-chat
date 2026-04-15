package store

import (
	"database/sql"
	"testing"

	"github.com/brushtailmedia/sshkey-chat/internal/config"
)

// Phase 15: unit tests for the edit store helpers. Covers UpdateX Edited
// variants, the wrapped-keys variants, GetUserMostRecentMessageIDX, and
// GetXMessageByID. All helpers operate on the per-context message DB
// (rooms, group DMs, 1:1 DMs share the same schema via initMessageDB).

func setupEditTestStore(t *testing.T) (*Store, string) {
	t.Helper()
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	s.SeedRooms(map[string]config.Room{"general": {Topic: "Chat"}})
	generalID := s.RoomDisplayNameToID("general")
	if generalID == "" {
		t.Fatal("seed failed")
	}
	return s, generalID
}

func TestUpdateRoomMessageEdited_ReplacesPayloadAndSetsEditedAt(t *testing.T) {
	s, roomID := setupEditTestStore(t)

	err := s.InsertRoomMessage(roomID, StoredMessage{
		ID:        "msg_edit1",
		Sender:    "alice",
		TS:        1000,
		Epoch:     3,
		Payload:   "original_payload_b64",
		FileIDs:   []string{"file_abc"},
		Signature: "original_sig",
	})
	if err != nil {
		t.Fatalf("insert: %v", err)
	}

	err = s.UpdateRoomMessageEdited(roomID, "msg_edit1", "new_payload_b64", "new_sig", 2000)
	if err != nil {
		t.Fatalf("update: %v", err)
	}

	got, err := s.GetRoomMessageByID(roomID, "msg_edit1")
	if err != nil {
		t.Fatalf("get after update: %v", err)
	}
	if got.Payload != "new_payload_b64" {
		t.Errorf("payload not replaced: got %q", got.Payload)
	}
	if got.Signature != "new_sig" {
		t.Errorf("signature not replaced: got %q", got.Signature)
	}
	if got.EditedAt != 2000 {
		t.Errorf("edited_at = %d, want 2000", got.EditedAt)
	}
}

func TestUpdateRoomMessageEdited_PreservesFileIDsTSSenderEpoch(t *testing.T) {
	s, roomID := setupEditTestStore(t)

	err := s.InsertRoomMessage(roomID, StoredMessage{
		ID:        "msg_edit2",
		Sender:    "alice",
		TS:        5000,
		Epoch:     7,
		Payload:   "p",
		FileIDs:   []string{"file_x", "file_y"},
		Signature: "s",
	})
	if err != nil {
		t.Fatalf("insert: %v", err)
	}

	err = s.UpdateRoomMessageEdited(roomID, "msg_edit2", "new_p", "new_s", 9999)
	if err != nil {
		t.Fatalf("update: %v", err)
	}

	got, err := s.GetRoomMessageByID(roomID, "msg_edit2")
	if err != nil {
		t.Fatalf("get: %v", err)
	}

	// Immutability checks — everything except payload/signature/edited_at
	// must survive the edit unchanged. These are the fields the privacy
	// and signature-stability invariants depend on.
	if got.Sender != "alice" {
		t.Errorf("sender changed: %q", got.Sender)
	}
	if got.TS != 5000 {
		t.Errorf("ts changed: %d", got.TS)
	}
	if got.Epoch != 7 {
		t.Errorf("epoch changed: %d", got.Epoch)
	}
	if len(got.FileIDs) != 2 || got.FileIDs[0] != "file_x" || got.FileIDs[1] != "file_y" {
		t.Errorf("file_ids changed: %v", got.FileIDs)
	}
}

func TestUpdateRoomMessageEdited_RejectsDeletedRow(t *testing.T) {
	s, roomID := setupEditTestStore(t)

	err := s.InsertRoomMessage(roomID, StoredMessage{
		ID: "msg_del1", Sender: "alice", TS: 100, Epoch: 1, Payload: "p", Signature: "s",
	})
	if err != nil {
		t.Fatalf("insert: %v", err)
	}
	// Tombstone it via the delete path.
	_, err = s.DeleteRoomMessage(roomID, "msg_del1", "alice")
	if err != nil {
		t.Fatalf("delete: %v", err)
	}

	// Edit must now fail with sql.ErrNoRows — matches the "not found"
	// semantic the byte-identical privacy invariant depends on.
	err = s.UpdateRoomMessageEdited(roomID, "msg_del1", "new", "sig", 500)
	if err != sql.ErrNoRows {
		t.Errorf("edit on deleted row: got %v, want sql.ErrNoRows", err)
	}
}

func TestUpdateRoomMessageEdited_MissingRowReturnsErrNoRows(t *testing.T) {
	s, roomID := setupEditTestStore(t)
	err := s.UpdateRoomMessageEdited(roomID, "msg_does_not_exist", "p", "s", 500)
	if err != sql.ErrNoRows {
		t.Errorf("edit on missing row: got %v, want sql.ErrNoRows", err)
	}
}

func TestUpdateRoomMessageEdited_ClearsReactions(t *testing.T) {
	s, roomID := setupEditTestStore(t)

	err := s.InsertRoomMessage(roomID, StoredMessage{
		ID: "msg_r1", Sender: "alice", TS: 100, Epoch: 1, Payload: "p", Signature: "s",
	})
	if err != nil {
		t.Fatalf("insert: %v", err)
	}

	// Add a reaction by poking the per-context reactions table directly.
	// We don't need the full handleReact pipeline for this assertion.
	db, err := s.RoomDB(roomID)
	if err != nil {
		t.Fatalf("RoomDB: %v", err)
	}
	_, err = db.Exec(
		`INSERT INTO reactions (reaction_id, message_id, user, ts, payload) VALUES (?, ?, ?, ?, ?)`,
		"react_1", "msg_r1", "bob", 150, "emoji_payload",
	)
	if err != nil {
		t.Fatalf("seed reaction: %v", err)
	}

	// Edit should clear the reaction.
	err = s.UpdateRoomMessageEdited(roomID, "msg_r1", "new_p", "new_s", 200)
	if err != nil {
		t.Fatalf("update: %v", err)
	}

	var count int
	err = db.QueryRow(`SELECT COUNT(*) FROM reactions WHERE message_id = ?`, "msg_r1").Scan(&count)
	if err != nil {
		t.Fatalf("count reactions: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 reactions after edit, got %d", count)
	}
}

func TestGetUserMostRecentMessageIDRoom_ReturnsLatest(t *testing.T) {
	s, roomID := setupEditTestStore(t)

	// Insert three messages by alice, interleaved with one from bob.
	inserts := []StoredMessage{
		{ID: "msg_a1", Sender: "alice", TS: 100, Epoch: 1, Payload: "1", Signature: "s"},
		{ID: "msg_b1", Sender: "bob", TS: 110, Epoch: 1, Payload: "2", Signature: "s"},
		{ID: "msg_a2", Sender: "alice", TS: 120, Epoch: 1, Payload: "3", Signature: "s"},
		{ID: "msg_a3", Sender: "alice", TS: 130, Epoch: 1, Payload: "4", Signature: "s"},
	}
	for _, m := range inserts {
		if err := s.InsertRoomMessage(roomID, m); err != nil {
			t.Fatalf("insert %s: %v", m.ID, err)
		}
	}

	id, ts, err := s.GetUserMostRecentMessageIDRoom(roomID, "alice")
	if err != nil {
		t.Fatalf("get most recent: %v", err)
	}
	if id != "msg_a3" {
		t.Errorf("most recent = %q, want msg_a3", id)
	}
	if ts != 130 {
		t.Errorf("ts = %d, want 130", ts)
	}
}

func TestGetUserMostRecentMessageIDRoom_ExcludesDeleted(t *testing.T) {
	s, roomID := setupEditTestStore(t)

	s.InsertRoomMessage(roomID, StoredMessage{
		ID: "msg_a1", Sender: "alice", TS: 100, Epoch: 1, Payload: "1", Signature: "s",
	})
	s.InsertRoomMessage(roomID, StoredMessage{
		ID: "msg_a2", Sender: "alice", TS: 120, Epoch: 1, Payload: "2", Signature: "s",
	})
	// Soft-delete the most recent one.
	s.DeleteRoomMessage(roomID, "msg_a2", "alice")

	id, _, err := s.GetUserMostRecentMessageIDRoom(roomID, "alice")
	if err != nil {
		t.Fatalf("get most recent: %v", err)
	}
	// Should fall back to msg_a1 since msg_a2 is tombstoned.
	if id != "msg_a1" {
		t.Errorf("most recent (excluding deleted) = %q, want msg_a1", id)
	}
}

func TestGetUserMostRecentMessageIDRoom_EmptyReturnsBlank(t *testing.T) {
	s, roomID := setupEditTestStore(t)

	id, ts, err := s.GetUserMostRecentMessageIDRoom(roomID, "nobody")
	if err != nil {
		t.Errorf("unexpected error on empty: %v", err)
	}
	if id != "" {
		t.Errorf("id = %q, want empty string", id)
	}
	if ts != 0 {
		t.Errorf("ts = %d, want 0", ts)
	}
}

func TestGetRoomMessageByID_ReturnsMessage(t *testing.T) {
	s, roomID := setupEditTestStore(t)

	err := s.InsertRoomMessage(roomID, StoredMessage{
		ID: "msg_fetch", Sender: "alice", TS: 500, Epoch: 2,
		Payload: "pl", FileIDs: []string{"f1"}, Signature: "sg",
	})
	if err != nil {
		t.Fatalf("insert: %v", err)
	}

	got, err := s.GetRoomMessageByID(roomID, "msg_fetch")
	if err != nil {
		t.Fatalf("get by id: %v", err)
	}
	if got.ID != "msg_fetch" || got.Sender != "alice" || got.Epoch != 2 {
		t.Errorf("fetched wrong row: %+v", got)
	}
	if got.EditedAt != 0 {
		t.Errorf("unedited row should have EditedAt = 0, got %d", got.EditedAt)
	}
}

func TestGetRoomMessageByID_MissingReturnsErrNoRows(t *testing.T) {
	s, roomID := setupEditTestStore(t)
	_, err := s.GetRoomMessageByID(roomID, "msg_does_not_exist")
	if err != sql.ErrNoRows {
		t.Errorf("got %v, want sql.ErrNoRows", err)
	}
}

func TestUpdateGroupMessageEditedWithKeys_RewrapsWrappedKeys(t *testing.T) {
	s, _ := setupEditTestStore(t)

	// Insert a group message with initial wrapped_keys.
	err := s.InsertGroupMessage("group_edit_test", StoredMessage{
		ID:          "msg_g1",
		Sender:      "alice",
		TS:          1000,
		Payload:     "orig_payload",
		WrappedKeys: map[string]string{"alice": "wk_alice_v1", "bob": "wk_bob_v1"},
		Signature:   "orig_sig",
	})
	if err != nil {
		t.Fatalf("insert group msg: %v", err)
	}

	// Edit with a fresh K_msg wrapped for the current member set.
	// Fresh wrapped_keys JSON — matches encodeMap shape from the store.
	newKeysJSON := `{"alice":"wk_alice_v2","bob":"wk_bob_v2"}`
	err = s.UpdateGroupMessageEditedWithKeys("group_edit_test", "msg_g1", "new_payload", "new_sig", newKeysJSON, 5000)
	if err != nil {
		t.Fatalf("update with keys: %v", err)
	}

	got, err := s.GetGroupMessageByID("group_edit_test", "msg_g1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Payload != "new_payload" {
		t.Errorf("payload = %q, want new_payload", got.Payload)
	}
	if got.WrappedKeys["alice"] != "wk_alice_v2" {
		t.Errorf("alice wrapped key not rewrapped: %q", got.WrappedKeys["alice"])
	}
	if got.WrappedKeys["bob"] != "wk_bob_v2" {
		t.Errorf("bob wrapped key not rewrapped: %q", got.WrappedKeys["bob"])
	}
	if got.EditedAt != 5000 {
		t.Errorf("edited_at = %d, want 5000", got.EditedAt)
	}
}
