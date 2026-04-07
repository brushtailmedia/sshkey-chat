package store

import (
	"testing"
)

func TestStoreRoundTrip(t *testing.T) {
	dir := t.TempDir()

	s, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	// Insert a room message
	err = s.InsertRoomMessage("general", StoredMessage{
		ID:      "msg_test001",
		Sender:  "alice",
		TS:      1712345678,
		Epoch:   3,
		Payload: "base64encrypted...",
		FileIDs: []string{"file_abc"},
		Signature: "base64sig...",
	})
	if err != nil {
		t.Fatalf("insert room message: %v", err)
	}

	// Retrieve it
	msgs, err := s.GetRoomMessages("general", 0, 10)
	if err != nil {
		t.Fatalf("get room messages: %v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("expected 1 message, got %d", len(msgs))
	}
	if msgs[0].ID != "msg_test001" {
		t.Errorf("id = %q, want msg_test001", msgs[0].ID)
	}
	if msgs[0].Sender != "alice" {
		t.Errorf("sender = %q, want alice", msgs[0].Sender)
	}
	if msgs[0].Epoch != 3 {
		t.Errorf("epoch = %d, want 3", msgs[0].Epoch)
	}
	if len(msgs[0].FileIDs) != 1 || msgs[0].FileIDs[0] != "file_abc" {
		t.Errorf("file_ids = %v, want [file_abc]", msgs[0].FileIDs)
	}

	// Insert a DM message
	err = s.InsertConvMessage("conv_test001", StoredMessage{
		ID:          "msg_dm001",
		Sender:      "alice",
		TS:          1712345680,
		Payload:     "base64encrypted_dm...",
		WrappedKeys: map[string]string{"alice": "wrapped_a", "bob": "wrapped_b"},
		Signature:   "base64sig_dm...",
	})
	if err != nil {
		t.Fatalf("insert conv message: %v", err)
	}

	dmMsgs, err := s.GetConvMessages("conv_test001", 0, 10)
	if err != nil {
		t.Fatalf("get conv messages: %v", err)
	}
	if len(dmMsgs) != 1 {
		t.Fatalf("expected 1 DM, got %d", len(dmMsgs))
	}
	if dmMsgs[0].WrappedKeys["bob"] != "wrapped_b" {
		t.Errorf("wrapped_keys[bob] = %q, want wrapped_b", dmMsgs[0].WrappedKeys["bob"])
	}

	// Test device registration
	count, err := s.UpsertDevice("alice", "dev_test_001")
	if err != nil {
		t.Fatalf("upsert device: %v", err)
	}
	if count != 1 {
		t.Errorf("device count = %d, want 1", count)
	}

	count, err = s.UpsertDevice("alice", "dev_test_002")
	if err != nil {
		t.Fatalf("upsert device 2: %v", err)
	}
	if count != 2 {
		t.Errorf("device count = %d, want 2", count)
	}

	// Duplicate device shouldn't increase count
	count, err = s.UpsertDevice("alice", "dev_test_001")
	if err != nil {
		t.Fatalf("upsert device dup: %v", err)
	}
	if count != 2 {
		t.Errorf("device count after dup = %d, want 2", count)
	}

	// Test conversation creation
	err = s.CreateConversation("conv_test001", []string{"alice", "bob"})
	if err != nil {
		t.Fatalf("create conversation: %v", err)
	}

	members, err := s.GetConversationMembers("conv_test001")
	if err != nil {
		t.Fatalf("get conversation members: %v", err)
	}
	if len(members) != 2 {
		t.Fatalf("expected 2 members, got %d", len(members))
	}

	// Test 1:1 dedup
	existing, err := s.FindOneOnOneConversation("alice", "bob")
	if err != nil {
		t.Fatalf("find 1:1: %v", err)
	}
	if existing != "conv_test001" {
		t.Errorf("1:1 conversation = %q, want conv_test001", existing)
	}

	// Test epoch key storage
	err = s.StoreEpochKey("general", 3, "alice", "wrapped_epoch_key_alice")
	if err != nil {
		t.Fatalf("store epoch key: %v", err)
	}

	key, err := s.GetEpochKey("general", 3, "alice")
	if err != nil {
		t.Fatalf("get epoch key: %v", err)
	}
	if key != "wrapped_epoch_key_alice" {
		t.Errorf("epoch key = %q, want wrapped_epoch_key_alice", key)
	}

	epoch, err := s.GetCurrentEpoch("general")
	if err != nil {
		t.Fatalf("get current epoch: %v", err)
	}
	if epoch != 3 {
		t.Errorf("current epoch = %d, want 3", epoch)
	}

	// Test message deletion
	_, err = s.DeleteRoomMessage("general", "msg_test001", "alice")
	if err != nil {
		t.Fatalf("delete message: %v", err)
	}

	msgs, err = s.GetRoomMessages("general", 0, 10)
	if err != nil {
		t.Fatalf("get after delete: %v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("expected 1 message (tombstone), got %d", len(msgs))
	}
	if !msgs[0].Deleted {
		t.Error("expected message to be marked deleted")
	}

	// Test leave conversation
	err = s.RemoveConversationMember("conv_test001", "bob")
	if err != nil {
		t.Fatalf("remove member: %v", err)
	}
	members, err = s.GetConversationMembers("conv_test001")
	if err != nil {
		t.Fatalf("get members after leave: %v", err)
	}
	if len(members) != 1 || members[0] != "alice" {
		t.Errorf("members after leave = %v, want [alice]", members)
	}

	t.Log("all store operations passed")
}
