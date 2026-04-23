package server

import (
	"encoding/json"
	"testing"

	"github.com/brushtailmedia/sshkey-chat/internal/protocol"
	"github.com/brushtailmedia/sshkey-chat/internal/store"
)

func TestHandleSend_DuplicatePayloadCreatesDistinctIDs(t *testing.T) {
	s := newTestServer(t)
	roomID := s.store.RoomDisplayNameToID("general")
	if roomID == "" {
		t.Fatal("seed failed: general room missing")
	}

	alice := testClientFor("alice", "dev_alice_send_dup")
	bob := testClientFor("bob", "dev_bob_send_dup")
	s.mu.Lock()
	s.clients["dev_alice_send_dup"] = alice.Client
	s.clients["dev_bob_send_dup"] = bob.Client
	s.mu.Unlock()

	raw, _ := json.Marshal(protocol.Send{
		Type:      "send",
		Room:      roomID,
		Epoch:     1,
		Payload:   "same_payload",
		Signature: "same_sig",
	})

	s.handleSend(alice.Client, raw)
	s.handleSend(alice.Client, raw)

	msgs := bob.messages()
	if len(msgs) != 2 {
		t.Fatalf("expected 2 broadcasts to bob, got %d", len(msgs))
	}

	var m1, m2 protocol.Message
	if err := json.Unmarshal(msgs[0], &m1); err != nil {
		t.Fatalf("unmarshal first message: %v", err)
	}
	if err := json.Unmarshal(msgs[1], &m2); err != nil {
		t.Fatalf("unmarshal second message: %v", err)
	}
	if m1.ID == "" || m2.ID == "" {
		t.Fatal("expected server-assigned IDs on both broadcasts")
	}
	if m1.ID == m2.ID {
		t.Fatalf("duplicate send reused msg ID %q", m1.ID)
	}

	stored, err := s.store.GetRoomMessages(roomID, 0, 10)
	if err != nil {
		t.Fatalf("GetRoomMessages: %v", err)
	}
	if len(stored) != 2 {
		t.Fatalf("expected 2 stored rows, got %d", len(stored))
	}
}

func TestHandleSendGroup_DuplicatePayloadCreatesDistinctIDs(t *testing.T) {
	s := newTestServer(t)
	groupID := store.GenerateID("group_")
	if err := s.store.CreateGroup(groupID, "alice", []string{"alice", "bob"}, "dup"); err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}

	alice := testClientFor("alice", "dev_alice_group_dup")
	bob := testClientFor("bob", "dev_bob_group_dup")
	s.mu.Lock()
	s.clients["dev_alice_group_dup"] = alice.Client
	s.clients["dev_bob_group_dup"] = bob.Client
	s.mu.Unlock()

	raw, _ := json.Marshal(protocol.SendGroup{
		Type:        "send_group",
		Group:       groupID,
		WrappedKeys: map[string]string{"alice": "ka", "bob": "kb"},
		Payload:     "same_group_payload",
		Signature:   "same_group_sig",
	})

	s.handleSendGroup(alice.Client, raw)
	s.handleSendGroup(alice.Client, raw)

	msgs := bob.messages()
	if len(msgs) != 2 {
		t.Fatalf("expected 2 group broadcasts to bob, got %d", len(msgs))
	}

	var g1, g2 protocol.GroupMessage
	if err := json.Unmarshal(msgs[0], &g1); err != nil {
		t.Fatalf("unmarshal first group message: %v", err)
	}
	if err := json.Unmarshal(msgs[1], &g2); err != nil {
		t.Fatalf("unmarshal second group message: %v", err)
	}
	if g1.ID == "" || g2.ID == "" {
		t.Fatal("expected server-assigned IDs on both group broadcasts")
	}
	if g1.ID == g2.ID {
		t.Fatalf("duplicate group send reused msg ID %q", g1.ID)
	}

	stored, err := s.store.GetGroupMessages(groupID, 0, 10)
	if err != nil {
		t.Fatalf("GetGroupMessages: %v", err)
	}
	if len(stored) != 2 {
		t.Fatalf("expected 2 stored group rows, got %d", len(stored))
	}
}

func TestHandleSendDM_DuplicatePayloadCreatesDistinctIDs(t *testing.T) {
	s := newTestServer(t)
	dm, err := s.store.CreateOrGetDirectMessage(store.GenerateID("dm_"), "alice", "bob")
	if err != nil {
		t.Fatalf("CreateOrGetDirectMessage: %v", err)
	}

	alice := testClientFor("alice", "dev_alice_dm_dup")
	bob := testClientFor("bob", "dev_bob_dm_dup")
	s.mu.Lock()
	s.clients["dev_alice_dm_dup"] = alice.Client
	s.clients["dev_bob_dm_dup"] = bob.Client
	s.mu.Unlock()

	raw, _ := json.Marshal(protocol.SendDM{
		Type:        "send_dm",
		DM:          dm.ID,
		WrappedKeys: map[string]string{"alice": "ka", "bob": "kb"},
		Payload:     "same_dm_payload",
		Signature:   "same_dm_sig",
	})

	s.handleSendDM(alice.Client, raw)
	s.handleSendDM(alice.Client, raw)

	msgs := bob.messages()
	if len(msgs) != 2 {
		t.Fatalf("expected 2 dm broadcasts to bob, got %d", len(msgs))
	}

	var d1, d2 protocol.DM
	if err := json.Unmarshal(msgs[0], &d1); err != nil {
		t.Fatalf("unmarshal first dm message: %v", err)
	}
	if err := json.Unmarshal(msgs[1], &d2); err != nil {
		t.Fatalf("unmarshal second dm message: %v", err)
	}
	if d1.ID == "" || d2.ID == "" {
		t.Fatal("expected server-assigned IDs on both dm broadcasts")
	}
	if d1.ID == d2.ID {
		t.Fatalf("duplicate dm send reused msg ID %q", d1.ID)
	}

	stored, err := s.store.GetDMMessagesSince(dm.ID, "alice", 0, 10)
	if err != nil {
		t.Fatalf("GetDMMessagesSince: %v", err)
	}
	if len(stored) != 2 {
		t.Fatalf("expected 2 stored dm rows, got %d", len(stored))
	}
}
