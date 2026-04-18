package server

// Phase 17c Step 4 Category B — state-fix push tests.
//
// Covers:
//   - stateFixAllowed throttle: first call allows; second within TTL
//     denies; after TTL passes, allows again
//   - empty deviceID → not allowed (defensive)
//   - pushEpochKeyFix no-op when nothing to push (no epoch, no
//     wrappedKey)
//   - pushEpochKeyFix sends EpochKey when data is available
//   - integration: handleSend with bad epoch produces both error +
//     pushed epoch_key

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/brushtailmedia/sshkey-chat/internal/protocol"
)

func TestStateFixAllowed_FirstCallPermits(t *testing.T) {
	s := newTestServer(t)
	if !s.stateFixAllowed("dev_a", "send") {
		t.Error("first call denied; want allowed")
	}
}

func TestStateFixAllowed_SecondWithinTTLDenies(t *testing.T) {
	s := newTestServer(t)
	// First call stamps the timestamp.
	if !s.stateFixAllowed("dev_a", "send") {
		t.Fatal("first call denied")
	}
	// Immediately retry — should deny.
	if s.stateFixAllowed("dev_a", "send") {
		t.Error("second call within TTL permitted; want denied")
	}
}

func TestStateFixAllowed_DifferentVerbsIndependent(t *testing.T) {
	s := newTestServer(t)
	if !s.stateFixAllowed("dev_a", "send") {
		t.Fatal("send denied")
	}
	// Different verb for same device — separate key, should allow.
	if !s.stateFixAllowed("dev_a", "edit") {
		t.Error("edit denied despite independent verb key")
	}
}

func TestStateFixAllowed_DifferentDevicesIndependent(t *testing.T) {
	s := newTestServer(t)
	if !s.stateFixAllowed("dev_a", "send") {
		t.Fatal("dev_a denied")
	}
	if !s.stateFixAllowed("dev_b", "send") {
		t.Error("dev_b denied despite independent device key")
	}
}

func TestStateFixAllowed_EmptyDeviceIDDenies(t *testing.T) {
	s := newTestServer(t)
	if s.stateFixAllowed("", "send") {
		t.Error("empty deviceID permitted; want denied (defensive)")
	}
}

func TestStateFixAllowed_AfterTTLPermits(t *testing.T) {
	// Fiddle the last-push timestamp to simulate TTL elapsing without
	// actually sleeping. stateFixTTL is 1s — we set the timestamp
	// to 2s ago so the next check computes "now - last > TTL".
	s := newTestServer(t)
	s.stateFixMu.Lock()
	s.stateFixLast["dev_a:send"] = time.Now().Unix() - 2
	s.stateFixMu.Unlock()

	if !s.stateFixAllowed("dev_a", "send") {
		t.Error("call after TTL elapsed denied; want allowed")
	}
}

func TestPushEpochKeyFix_NoCurrentEpochNoOp(t *testing.T) {
	// No rotation has happened; current epoch is 0. pushEpochKeyFix
	// should short-circuit without encoding anything.
	s := newTestServer(t)
	alice := testClientFor("alice", "dev_alice_fix")
	generalID := s.store.RoomDisplayNameToID("general")
	// Throttle permits this call (first time).
	s.pushEpochKeyFix(alice.Client, "send", generalID)

	if len(alice.messages()) != 0 {
		t.Errorf("unexpected message pushed when epoch=0: %d messages", len(alice.messages()))
	}
}

func TestPushEpochKeyFix_SendsEpochKey(t *testing.T) {
	s := newTestServer(t)
	alice := testClientFor("alice", "dev_alice_fix_send")
	generalID := s.store.RoomDisplayNameToID("general")
	if err := s.store.AddRoomMember(generalID, "alice", 0); err != nil {
		t.Fatalf("AddRoomMember: %v", err)
	}
	// Seed an epoch key so the push has something to send.
	if err := s.store.StoreEpochKey(generalID, 5, "alice", "wrapped_key_for_alice"); err != nil {
		t.Fatalf("StoreEpochKey: %v", err)
	}
	s.epochs.getOrCreate(generalID, 5)

	s.pushEpochKeyFix(alice.Client, "send", generalID)

	msgs := alice.messages()
	if len(msgs) != 1 {
		t.Fatalf("expected 1 pushed epoch_key, got %d", len(msgs))
	}
	var got protocol.EpochKey
	if err := json.Unmarshal(msgs[0], &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Type != "epoch_key" {
		t.Errorf("type = %q, want epoch_key", got.Type)
	}
	if got.Room != generalID {
		t.Errorf("room = %q, want %q", got.Room, generalID)
	}
	if got.Epoch != 5 {
		t.Errorf("epoch = %d, want 5", got.Epoch)
	}
	if got.WrappedKey != "wrapped_key_for_alice" {
		t.Errorf("wrapped_key = %q, want wrapped_key_for_alice", got.WrappedKey)
	}
}

func TestPushEpochKeyFix_ThrottledAfterFirst(t *testing.T) {
	s := newTestServer(t)
	alice := testClientFor("alice", "dev_alice_fix_throttle")
	generalID := s.store.RoomDisplayNameToID("general")
	if err := s.store.AddRoomMember(generalID, "alice", 0); err != nil {
		t.Fatalf("AddRoomMember: %v", err)
	}
	if err := s.store.StoreEpochKey(generalID, 5, "alice", "wk"); err != nil {
		t.Fatalf("StoreEpochKey: %v", err)
	}
	s.epochs.getOrCreate(generalID, 5)

	// Fire twice back-to-back.
	s.pushEpochKeyFix(alice.Client, "send", generalID)
	s.pushEpochKeyFix(alice.Client, "send", generalID)

	// Throttle should prevent the second push.
	if got := len(alice.messages()); got != 1 {
		t.Errorf("pushed %d epoch_keys, want 1 (second throttled)", got)
	}
}
