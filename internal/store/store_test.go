package store

import (
	"testing"

	"github.com/brushtailmedia/sshkey-chat/internal/testutil"
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
	_, err = s.InsertRoomMessage(generalID, StoredMessage{
		ID:        testutil.MsgID("test001"),
		Sender:    testutil.UserID("alice"),
		TS:        1712345678,
		Epoch:     3,
		Payload:   "base64encrypted...",
		FileIDs:   []string{testutil.FileID("abc")},
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
	if msgs[0].ID != testutil.MsgID("test001") {
		t.Errorf("id = %q, want msg_test001", msgs[0].ID)
	}
	if msgs[0].Sender != testutil.UserID("alice") {
		t.Errorf("sender = %q, want alice", msgs[0].Sender)
	}
	if msgs[0].Epoch != 3 {
		t.Errorf("epoch = %d, want 3", msgs[0].Epoch)
	}
	if len(msgs[0].FileIDs) != 1 || msgs[0].FileIDs[0] != testutil.FileID("abc") {
		t.Errorf("file_ids = %v, want [file_abc]", msgs[0].FileIDs)
	}

	// Insert a group DM message
	groupID := GenerateID("group_")
	_, err = s.InsertGroupMessage(groupID, StoredMessage{
		ID:          testutil.MsgID("dm001"),
		Sender:      testutil.UserID("alice"),
		TS:          1712345680,
		Payload:     "base64encrypted_dm...",
		WrappedKeys: map[string]string{testutil.UserID("alice"): "wrapped_a", testutil.UserID("bob"): "wrapped_b"},
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
	if dmMsgs[0].WrappedKeys[testutil.UserID("bob")] != "wrapped_b" {
		t.Errorf("wrapped_keys[bob] = %q, want wrapped_b", dmMsgs[0].WrappedKeys[testutil.UserID("bob")])
	}

	// Test device registration. isNew must be true for a first-seen device
	// and false for a reconnect — this drives the Tier 1 new-device
	// notification, and locks in the RowsAffected semantics it relies on.
	count, isNew, err := s.UpsertDevice(testutil.UserID("alice"), "dev_test_001")
	if err != nil {
		t.Fatalf("upsert device: %v", err)
	}
	if count != 1 {
		t.Errorf("device count = %d, want 1", count)
	}
	if !isNew {
		t.Error("first registration of dev_test_001 should report isNew=true")
	}

	count, isNew, err = s.UpsertDevice(testutil.UserID("alice"), "dev_test_002")
	if err != nil {
		t.Fatalf("upsert device 2: %v", err)
	}
	if count != 2 {
		t.Errorf("device count = %d, want 2", count)
	}
	if !isNew {
		t.Error("first registration of dev_test_002 should report isNew=true")
	}

	// Duplicate device shouldn't increase count or report isNew.
	count, isNew, err = s.UpsertDevice(testutil.UserID("alice"), "dev_test_001")
	if err != nil {
		t.Fatalf("upsert device dup: %v", err)
	}
	if count != 2 {
		t.Errorf("device count after dup = %d, want 2", count)
	}
	if isNew {
		t.Error("re-registration of dev_test_001 should report isNew=false")
	}

	// Test group creation
	err = s.CreateGroup(groupID, testutil.UserID("alice"), []string{testutil.UserID("alice"), testutil.UserID("bob"), testutil.UserID("carol")})
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
	dm1, err := s.CreateOrGetDirectMessage(GenerateID("dm_"), testutil.UserID("alice"), testutil.UserID("bob"))
	if err != nil {
		t.Fatalf("create DM: %v", err)
	}
	dm2, err := s.CreateOrGetDirectMessage(GenerateID("dm_"), testutil.UserID("bob"), testutil.UserID("alice"))
	if err != nil {
		t.Fatalf("create DM 2: %v", err)
	}
	if dm1.ID != dm2.ID {
		t.Errorf("1:1 DM dedup failed: %s != %s", dm1.ID, dm2.ID)
	}

	// Test epoch key storage
	err = s.StoreEpochKey(generalID, 3, testutil.UserID("alice"), "wrapped_epoch_key_alice")
	if err != nil {
		t.Fatalf("store epoch key: %v", err)
	}

	key, err := s.GetEpochKey(generalID, 3, testutil.UserID("alice"))
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
	_, err = s.DeleteRoomMessage(generalID, testutil.MsgID("test001"), testutil.UserID("alice"))
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
	err = s.RemoveGroupMember(groupID, testutil.UserID("bob"))
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
		if m == testutil.UserID("bob") {
			t.Errorf("bob should have been removed from group, got %v", members)
		}
	}

	t.Log("all store operations passed")
}
