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

	// Seed a room and get its nanoid ID
	s.SeedRooms(map[string]RoomSeed{"general": {Topic: "Chat"}})
	generalID := s.RoomDisplayNameToID("general")
	if generalID == "" {
		t.Fatal("failed to get room ID after seed")
	}

	// Insert a room message
	err = s.InsertRoomMessage(generalID, StoredMessage{
		ID:        "msg_test001",
		Sender:    "alice",
		TS:        1712345678,
		Epoch:     3,
		Payload:   "base64encrypted...",
		FileIDs:   []string{"file_abc"},
		Signature: "base64sig...",
	})
	if err != nil {
		t.Fatalf("insert room message: %v", err)
	}

	// Retrieve it
	msgs, err := s.GetRoomMessages(generalID, 0, 10)
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

	// Insert a group DM message
	groupID := GenerateID("group_")
	err = s.InsertGroupMessage(groupID, StoredMessage{
		ID:          "msg_dm001",
		Sender:      "alice",
		TS:          1712345680,
		Payload:     "base64encrypted_dm...",
		WrappedKeys: map[string]string{"alice": "wrapped_a", "bob": "wrapped_b"},
		Signature:   "base64sig_dm...",
	})
	if err != nil {
		t.Fatalf("insert group message: %v", err)
	}

	dmMsgs, err := s.GetGroupMessages(groupID, 0, 10)
	if err != nil {
		t.Fatalf("get group messages: %v", err)
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

	// Test group creation
	err = s.CreateGroup(groupID, "alice", []string{"alice", "bob", "carol"})
	if err != nil {
		t.Fatalf("create group: %v", err)
	}

	members, err := s.GetGroupMembers(groupID)
	if err != nil {
		t.Fatalf("get group members: %v", err)
	}
	if len(members) != 3 {
		t.Fatalf("expected 3 members, got %d", len(members))
	}

	// Test 1:1 DM dedup
	dm1, err := s.CreateOrGetDirectMessage(GenerateID("dm_"), "alice", "bob")
	if err != nil {
		t.Fatalf("create DM: %v", err)
	}
	dm2, err := s.CreateOrGetDirectMessage(GenerateID("dm_"), "bob", "alice")
	if err != nil {
		t.Fatalf("create DM 2: %v", err)
	}
	if dm1.ID != dm2.ID {
		t.Errorf("1:1 DM dedup failed: %s != %s", dm1.ID, dm2.ID)
	}

	// Test epoch key storage
	err = s.StoreEpochKey(generalID, 3, "alice", "wrapped_epoch_key_alice")
	if err != nil {
		t.Fatalf("store epoch key: %v", err)
	}

	key, err := s.GetEpochKey(generalID, 3, "alice")
	if err != nil {
		t.Fatalf("get epoch key: %v", err)
	}
	if key != "wrapped_epoch_key_alice" {
		t.Errorf("epoch key = %q, want wrapped_epoch_key_alice", key)
	}

	epoch, err := s.GetCurrentEpoch(generalID)
	if err != nil {
		t.Fatalf("get current epoch: %v", err)
	}
	if epoch != 3 {
		t.Errorf("current epoch = %d, want 3", epoch)
	}

	// Test message deletion
	_, err = s.DeleteRoomMessage(generalID, "msg_test001", "alice")
	if err != nil {
		t.Fatalf("delete message: %v", err)
	}

	msgs, err = s.GetRoomMessages(generalID, 0, 10)
	if err != nil {
		t.Fatalf("get after delete: %v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("expected 1 message (tombstone), got %d", len(msgs))
	}
	if !msgs[0].Deleted {
		t.Error("expected message to be marked deleted")
	}

	// Test leave group
	err = s.RemoveGroupMember(groupID, "bob")
	if err != nil {
		t.Fatalf("remove member: %v", err)
	}
	members, err = s.GetGroupMembers(groupID)
	if err != nil {
		t.Fatalf("get members after leave: %v", err)
	}
	if len(members) != 2 {
		t.Fatalf("expected 2 members after leave, got %d", len(members))
	}
	// Verify bob is no longer a member
	for _, m := range members {
		if m == "bob" {
			t.Errorf("bob should have been removed from group, got %v", members)
		}
	}

	t.Log("all store operations passed")
}
