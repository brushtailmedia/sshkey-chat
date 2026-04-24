package server

// Phase 15 follow-up — regression tests for the handleReact tombstone
// guard. Before the guard, a `react` envelope could race a `delete`
// and land an orphan reaction on a tombstoned message: the FK
// constraint passed (soft-delete keeps the row) and the broadcast
// went out. After the guard (session.go `isReactableMessage`), the
// handler silently returns before INSERT and before broadcast so no
// orphan row is created and no clients see a reaction for a
// just-deleted message.
//
// These tests lock in that invariant for all three context families
// (room, group DM, 1:1 DM) plus the unknown-message case.

import (
	"encoding/json"
	"testing"

	"github.com/brushtailmedia/sshkey-chat/internal/protocol"
	"github.com/brushtailmedia/sshkey-chat/internal/store"
)

// TestHandleReact_RejectsTombstonedRoomMessage verifies that reacting
// to a soft-deleted room message produces no reaction row and no
// broadcast. Room variant.
func TestHandleReact_RejectsTombstonedRoomMessage(t *testing.T) {
	s := newTestServer(t)
	generalID := s.store.RoomDisplayNameToID("general")

	// Alice sends a message.
	if err := s.store.InsertRoomMessage(generalID, store.StoredMessage{
		ID: "msg_react_rt", Sender: "alice", TS: 100, Epoch: 1, Payload: "p", Signature: "s",
	}); err != nil {
		t.Fatalf("insert: %v", err)
	}
	// Alice deletes it. The inline reaction clear runs as part of
	// deleteMessage; after this the row has deleted=1 and there are
	// no reactions referencing it.
	if _, err := s.store.DeleteRoomMessage(generalID, "msg_react_rt", "alice"); err != nil {
		t.Fatalf("delete: %v", err)
	}

	// Bob races in and sends a react for the now-tombstoned message.
	bob := testClientFor("bob", "dev_bob_1")
	s.mu.Lock()
	s.clients["dev_bob_1"] = bob.Client
	s.mu.Unlock()

	raw, _ := json.Marshal(protocol.React{
		Type:    "react",
		ID:      "msg_react_rt",
		Room:    generalID,
		Epoch:   1,
		Payload: "encrypted_emoji",
	})
	s.handleReact(bob.Client, raw)

	// The server must NOT have inserted a reaction row.
	db, err := s.store.RoomDB(generalID)
	if err != nil {
		t.Fatalf("RoomDB: %v", err)
	}
	var count int
	err = db.QueryRow(`SELECT COUNT(*) FROM reactions WHERE message_id = ?`, "msg_react_rt").Scan(&count)
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 reaction rows after reacting to tombstone, got %d", count)
	}

	// Bob must NOT have received a reaction broadcast echo. A silent
	// no-op produces no wire output at all. Membership check passes
	// earlier, so any output means a post-check error (bug) or a
	// reaction broadcast (the exact thing we're regressing against).
	if msgs := bob.messages(); len(msgs) != 0 {
		t.Errorf("expected 0 broadcasts on tombstoned react, got %d: %v", len(msgs), msgs)
	}
}

// TestHandleReact_RejectsTombstonedGroupMessage — group DM variant.
func TestHandleReact_RejectsTombstonedGroupMessage(t *testing.T) {
	s := newTestServer(t)
	groupID := store.GenerateID("group_")
	if err := s.store.CreateGroup(groupID, "alice", []string{"alice", "bob"}, "Test"); err != nil {
		t.Fatalf("create group: %v", err)
	}

	if err := s.store.InsertGroupMessage(groupID, store.StoredMessage{
		ID:          "msg_grt",
		Sender:      "alice",
		TS:          100,
		Payload:     "p",
		Signature:   "s",
		WrappedKeys: map[string]string{"alice": "wa", "bob": "wb"},
	}); err != nil {
		t.Fatalf("insert: %v", err)
	}
	if _, err := s.store.DeleteGroupMessage(groupID, "msg_grt", "alice"); err != nil {
		t.Fatalf("delete: %v", err)
	}

	bob := testClientFor("bob", "dev_bob_1")
	s.mu.Lock()
	s.clients["dev_bob_1"] = bob.Client
	s.mu.Unlock()

	raw, _ := json.Marshal(protocol.React{
		Type:        "react",
		ID:          "msg_grt",
		Group:       groupID,
		Payload:     "enc",
		WrappedKeys: map[string]string{"alice": "wa", "bob": "wb"},
	})
	s.handleReact(bob.Client, raw)

	db, err := s.store.GroupDB(groupID)
	if err != nil {
		t.Fatalf("GroupDB: %v", err)
	}
	var count int
	db.QueryRow(`SELECT COUNT(*) FROM reactions WHERE message_id = ?`, "msg_grt").Scan(&count)
	if count != 0 {
		t.Errorf("expected 0 reaction rows, got %d", count)
	}
	if msgs := bob.messages(); len(msgs) != 0 {
		t.Errorf("expected 0 broadcasts, got %d", len(msgs))
	}
}

// TestHandleReact_RejectsTombstonedDMMessage — 1:1 DM variant.
func TestHandleReact_RejectsTombstonedDMMessage(t *testing.T) {
	s := newTestServer(t)
	dm, err := s.store.CreateOrGetDirectMessage(store.GenerateID("dm_"), "alice", "bob")
	if err != nil {
		t.Fatalf("create DM: %v", err)
	}
	dmID := dm.ID

	if err := s.store.InsertDMMessage(dmID, store.StoredMessage{
		ID:          "msg_drt",
		Sender:      "alice",
		TS:          100,
		Payload:     "p",
		Signature:   "s",
		WrappedKeys: map[string]string{"alice": "wa", "bob": "wb"},
	}); err != nil {
		t.Fatalf("insert: %v", err)
	}
	if _, err := s.store.DeleteDMMessage(dmID, "msg_drt", "alice"); err != nil {
		t.Fatalf("delete: %v", err)
	}

	bob := testClientFor("bob", "dev_bob_1")
	s.mu.Lock()
	s.clients["dev_bob_1"] = bob.Client
	s.mu.Unlock()

	raw, _ := json.Marshal(protocol.React{
		Type:        "react",
		ID:          "msg_drt",
		DM:          dmID,
		Payload:     "enc",
		WrappedKeys: map[string]string{"alice": "wa", "bob": "wb"},
	})
	s.handleReact(bob.Client, raw)

	db, err := s.store.DMDB(dmID)
	if err != nil {
		t.Fatalf("DMDB: %v", err)
	}
	var count int
	db.QueryRow(`SELECT COUNT(*) FROM reactions WHERE message_id = ?`, "msg_drt").Scan(&count)
	if count != 0 {
		t.Errorf("expected 0 reaction rows, got %d", count)
	}
	if msgs := bob.messages(); len(msgs) != 0 {
		t.Errorf("expected 0 broadcasts, got %d", len(msgs))
	}
}

// TestHandleReact_RejectsUnknownMessage verifies that reacting to a
// msgID that doesn't exist anywhere in the room also fails silently.
// FK constraint would catch this at the INSERT layer, but we want
// the explicit guard to fire earlier and skip the broadcast cleanly.
func TestHandleReact_RejectsUnknownMessage(t *testing.T) {
	s := newTestServer(t)
	generalID := s.store.RoomDisplayNameToID("general")

	bob := testClientFor("bob", "dev_bob_1")
	s.mu.Lock()
	s.clients["dev_bob_1"] = bob.Client
	s.mu.Unlock()

	raw, _ := json.Marshal(protocol.React{
		Type:    "react",
		ID:      "msg_does_not_exist",
		Room:    generalID,
		Epoch:   1,
		Payload: "enc",
	})
	s.handleReact(bob.Client, raw)

	// No reaction row, no broadcast.
	db, err := s.store.RoomDB(generalID)
	if err != nil {
		t.Fatalf("RoomDB: %v", err)
	}
	var count int
	db.QueryRow(`SELECT COUNT(*) FROM reactions WHERE message_id = ?`, "msg_does_not_exist").Scan(&count)
	if count != 0 {
		t.Errorf("expected 0 reaction rows for unknown message, got %d", count)
	}
	if msgs := bob.messages(); len(msgs) != 0 {
		t.Errorf("expected 0 broadcasts for unknown message, got %d", len(msgs))
	}
}

// TestHandleReact_HappyPath_StillWorks is a negative-regression check:
// the tombstone guard must not break the happy path. Reacting to a
// live, non-deleted message should still insert and broadcast.
func TestHandleReact_HappyPath_StillWorks(t *testing.T) {
	s := newTestServer(t)
	generalID := s.store.RoomDisplayNameToID("general")

	if err := s.store.InsertRoomMessage(generalID, store.StoredMessage{
		ID: "msg_live", Sender: "alice", TS: 100, Epoch: 1, Payload: "p", Signature: "s",
	}); err != nil {
		t.Fatalf("insert: %v", err)
	}

	bob := testClientFor("bob", "dev_bob_1")
	s.mu.Lock()
	s.clients["dev_bob_1"] = bob.Client
	s.mu.Unlock()

	raw, _ := json.Marshal(protocol.React{
		Type:    "react",
		ID:      "msg_live",
		Room:    generalID,
		Epoch:   1,
		Payload: "enc",
	})
	s.handleReact(bob.Client, raw)

	db, err := s.store.RoomDB(generalID)
	if err != nil {
		t.Fatalf("RoomDB: %v", err)
	}
	var count int
	db.QueryRow(`SELECT COUNT(*) FROM reactions WHERE message_id = ?`, "msg_live").Scan(&count)
	if count != 1 {
		t.Errorf("expected 1 reaction row on happy path, got %d", count)
	}
	// Bob should receive the reaction broadcast echo (sent as a
	// member of the room).
	msgs := bob.messages()
	if len(msgs) != 1 {
		t.Fatalf("expected 1 broadcast, got %d", len(msgs))
	}
	var reaction protocol.Reaction
	if err := json.Unmarshal(msgs[0], &reaction); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if reaction.Type != "reaction" {
		t.Errorf("broadcast type = %q, want reaction", reaction.Type)
	}
	if reaction.ID != "msg_live" {
		t.Errorf("broadcast ID = %q, want msg_live", reaction.ID)
	}
}
