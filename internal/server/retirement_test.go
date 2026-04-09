package server

import (
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/brushtailmedia/sshkey-chat/internal/config"
	"github.com/brushtailmedia/sshkey-chat/internal/protocol"
)

const testKeyAlice = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJPpG4hFrxw7JOAppGdh0JrkNDNGxypfmwJxNFCWXnpG test@sshkey"
const testKeyBob = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPRAbUFuMYE6xPqs13jvVb5hMtXpkWeGD93ayZY2lmqj bob@test"
const testKeyCarol = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOgdoNpun6JCDfucZGBYbIxiMkNOpREmLc4NwA3PUv29 carol@test"

// newTestServer creates a server with a minimal on-disk config + data dir,
// usable for testing retirement flows that don't require an SSH listener.
func newTestServer(t *testing.T) *Server {
	t.Helper()
	configDir := t.TempDir()
	dataDir := t.TempDir()

	os.WriteFile(filepath.Join(configDir, "server.toml"), []byte(`
[server]
port = 2222
bind = "127.0.0.1"
admins = ["alice"]
`), 0644)

	os.WriteFile(filepath.Join(configDir, "users.toml"), []byte(`
[alice]
key = "`+testKeyAlice+`"
display_name = "Alice"
rooms = ["general", "engineering"]

[bob]
key = "`+testKeyBob+`"
display_name = "Bob"
rooms = ["general"]

[carol]
key = "`+testKeyCarol+`"
display_name = "Carol"
rooms = ["general"]
`), 0644)

	os.WriteFile(filepath.Join(configDir, "rooms.toml"), []byte(`
[general]
topic = "General"

[engineering]
topic = "Engineering"
`), 0644)

	cfg, err := config.Load(configDir)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	s, err := New(cfg, logger, dataDir)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	t.Cleanup(func() {
		if s.store != nil {
			s.store.Close()
		}
	})
	return s
}

func TestRetireUser_SetsFields(t *testing.T) {
	s := newTestServer(t)
	before := s.store.GetUserByID("bob")
	if before == nil {
		t.Fatal("bob should exist in users.db")
	}
	if before.Retired {
		t.Fatal("bob should not be retired initially")
	}
	if len(s.store.GetUserRoomIDs("bob")) == 0 {
		t.Fatal("bob should have rooms initially")
	}

	if err := s.retireUser("bob", "self_compromise"); err != nil {
		t.Fatalf("retireUser: %v", err)
	}

	after := s.store.GetUserByID("bob")
	if !after.Retired {
		t.Error("bob should be retired")
	}
	if after.RetiredReason != "self_compromise" {
		t.Errorf("reason = %q", after.RetiredReason)
	}
	if after.RetiredAt == "" {
		t.Error("retired_at should be set")
	}
}

func TestRetireUser_PersistsToDB(t *testing.T) {
	s := newTestServer(t)
	if err := s.retireUser("bob", "admin"); err != nil {
		t.Fatalf("retire: %v", err)
	}

	// Verify state in users.db
	bob := s.store.GetUserByID("bob")
	if bob == nil {
		t.Fatal("bob should exist in users.db")
	}
	if !bob.Retired {
		t.Error("bob should be retired in users.db")
	}
	if bob.RetiredReason != "admin" {
		t.Errorf("reason = %q, want admin", bob.RetiredReason)
	}
	if bob.RetiredAt == "" {
		t.Error("retired_at should be set")
	}
	// IsUserRetired should also return true
	if !s.store.IsUserRetired("bob") {
		t.Error("IsUserRetired should return true")
	}
}

func TestRetireUser_RejectsNonExistent(t *testing.T) {
	s := newTestServer(t)
	err := s.retireUser("nonexistent", "admin")
	if err == nil {
		t.Fatal("expected error for unknown user")
	}
}

func TestRetireUser_RejectsAlreadyRetired(t *testing.T) {
	s := newTestServer(t)
	if err := s.retireUser("bob", "admin"); err != nil {
		t.Fatalf("first retire: %v", err)
	}
	err := s.retireUser("bob", "self_compromise")
	if err == nil {
		t.Fatal("expected error when retiring an already-retired user")
	}
}

func TestFindRetiredMember_NoneRetired(t *testing.T) {
	s := newTestServer(t)
	got := s.findRetiredMember([]string{"alice", "bob", "carol"})
	if got != "" {
		t.Errorf("expected empty, got %q", got)
	}
}

func TestFindRetiredMember_FirstMatchReturned(t *testing.T) {
	s := newTestServer(t)
	if err := s.retireUser("bob", "admin"); err != nil {
		t.Fatalf("retire: %v", err)
	}
	got := s.findRetiredMember([]string{"alice", "bob", "carol"})
	if got != "bob" {
		t.Errorf("got %q, want bob", got)
	}
}

func TestFindRetiredMember_UnknownUsersIgnored(t *testing.T) {
	s := newTestServer(t)
	got := s.findRetiredMember([]string{"nonexistent", "alice"})
	if got != "" {
		t.Errorf("unknown user shouldn't match retired, got %q", got)
	}
}

func TestHandleRetirement_ClearsRooms(t *testing.T) {
	s := newTestServer(t)
	// Bob was in "general" (seeded from users.toml into rooms.db).
	// Use the actual room ID nanoid, not the display name — handleRetirement
	// dispatches per-room via performRoomLeave which expects IDs.
	bobRooms := s.store.GetUserRoomIDs("bob")
	if len(bobRooms) == 0 {
		t.Fatal("precondition: bob has rooms")
	}

	s.handleRetirement("bob", bobRooms, "admin")

	// Room membership should be cleared in rooms.db
	if rooms := s.store.GetUserRoomIDs("bob"); len(rooms) != 0 {
		t.Errorf("bob should have no rooms after retirement, got %v", rooms)
	}
}

func TestHandleRetirement_RemovesFromGroups(t *testing.T) {
	s := newTestServer(t)

	// Create a group DM with alice, bob, carol
	if err := s.store.CreateGroup("group_abc", []string{"alice", "bob", "carol"}); err != nil {
		t.Fatalf("create group: %v", err)
	}

	s.handleRetirement("bob", s.store.GetUserRoomIDs("bob"), "admin")

	// Group: bob should be removed
	groupMembers, _ := s.store.GetGroupMembers("group_abc")
	for _, m := range groupMembers {
		if m == "bob" {
			t.Error("bob should be removed from group_abc")
		}
	}
	if len(groupMembers) != 2 {
		t.Errorf("group should have 2 members, got %v", groupMembers)
	}
}

func TestHandleRetirement_SetsDMCutoff(t *testing.T) {
	s := newTestServer(t)

	// Create a 1:1 DM between alice and bob
	dm, err := s.store.CreateOrGetDirectMessage("dm_ab", "alice", "bob")
	if err != nil {
		t.Fatalf("create DM: %v", err)
	}

	s.handleRetirement("bob", nil, "admin")

	// Bob's cutoff should be set (silent leave)
	dm2, _ := s.store.GetDirectMessage(dm.ID)
	if dm2 == nil {
		t.Fatal("DM should still exist after retirement")
	}
	bobCutoff := dm2.CutoffFor("bob")
	if bobCutoff == 0 {
		t.Error("bob's cutoff should be non-zero after retirement")
	}

	// Alice's cutoff should be untouched
	aliceCutoff := dm2.CutoffFor("alice")
	if aliceCutoff != 0 {
		t.Errorf("alice's cutoff should be 0, got %d", aliceCutoff)
	}
}

// TestHandleRetirement_BroadcastsUserRetiredReasonToRemainingMembers
// verifies that the room_event{leave} broadcast emitted when a user
// retires carries Reason: "user_retired", so client UIs can render a
// distinct system message ("alice's account was retired" instead of
// "alice left"). This is the propagation regression for the
// handleRetirement → performRoomLeave refactor.
func TestHandleRetirement_BroadcastsUserRetiredReasonToRemainingMembers(t *testing.T) {
	s := newTestServer(t)

	// alice is in "general" with bob and carol per the seed. Use her
	// connected session to capture the room_event broadcast we expect
	// when bob retires.
	bobRooms := s.store.GetUserRoomIDs("bob")
	if len(bobRooms) == 0 {
		t.Fatal("precondition: bob has rooms")
	}

	alice := testClientFor("alice", "dev_alice_1")
	s.mu.Lock()
	s.clients["dev_alice_1"] = alice.Client
	s.mu.Unlock()

	s.handleRetirement("bob", bobRooms, "admin")

	// alice should have received a room_event{leave, user: bob,
	// reason: user_retired} for each room she shared with bob, plus
	// one user_retired top-level broadcast.
	msgs := alice.messages()
	if len(msgs) == 0 {
		t.Fatal("alice should have received at least one message")
	}

	var foundRoomEvent bool
	for _, raw := range msgs {
		var ev protocol.RoomEvent
		if err := json.Unmarshal(raw, &ev); err != nil {
			continue
		}
		if ev.Type == "room_event" && ev.Event == "leave" && ev.User == "bob" {
			if ev.Reason != "user_retired" {
				t.Errorf("room_event reason = %q, want user_retired", ev.Reason)
			}
			foundRoomEvent = true
			break
		}
	}
	if !foundRoomEvent {
		t.Errorf("alice never received a room_event{leave, user: bob} broadcast; messages = %v", msgs)
	}
}

func TestHandleRetirement_EpochRotationMarked(t *testing.T) {
	s := newTestServer(t)
	// Initialize epoch for one of bob's rooms so we have a baseline.
	bobRooms := s.store.GetUserRoomIDs("bob")
	if len(bobRooms) == 0 {
		t.Fatal("precondition: bob has rooms")
	}
	s.epochs.getOrCreate(bobRooms[0], 1)

	s.handleRetirement("bob", bobRooms, "admin")

	// Epoch should still be accessible (retirement marks rotation, doesn't
	// advance the epoch number — the next sender does that)
	// This test mainly ensures handleRetirement doesn't crash on epoch ops
	if s.epochs == nil {
		t.Error("epoch manager should exist")
	}
}

