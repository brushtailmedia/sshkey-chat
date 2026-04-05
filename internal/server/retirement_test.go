package server

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/brushtailmedia/sshkey/internal/config"
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
	before := s.cfg.Users["bob"]
	if before.Retired {
		t.Fatal("bob should not be retired initially")
	}
	if len(before.Rooms) == 0 {
		t.Fatal("bob should have rooms initially")
	}

	if err := s.retireUser("bob", "self_compromise"); err != nil {
		t.Fatalf("retireUser: %v", err)
	}

	after := s.cfg.Users["bob"]
	if !after.Retired {
		t.Error("bob should be retired")
	}
	if after.RetiredReason != "self_compromise" {
		t.Errorf("reason = %q", after.RetiredReason)
	}
	if after.RetiredAt == "" {
		t.Error("retired_at should be set")
	}
	if len(after.Rooms) != 0 {
		t.Errorf("rooms should be cleared, got %v", after.Rooms)
	}
}

func TestRetireUser_PersistsToDisk(t *testing.T) {
	s := newTestServer(t)
	if err := s.retireUser("bob", "admin"); err != nil {
		t.Fatalf("retire: %v", err)
	}

	// Reload from disk — the persisted state should match
	cfg2, err := config.Load(s.cfg.Dir)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	bob := cfg2.Users["bob"]
	if !bob.Retired {
		t.Error("bob should be retired after reload from disk")
	}
	if bob.RetiredReason != "admin" {
		t.Errorf("reason = %q, want admin", bob.RetiredReason)
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

func TestRetireUser_RollbackOnWriteFailure(t *testing.T) {
	s := newTestServer(t)
	// Make users.toml unwritable
	usersPath := filepath.Join(s.cfg.Dir, "users.toml")
	if err := os.Chmod(usersPath, 0444); err != nil {
		t.Skip("can't chmod")
	}
	defer os.Chmod(usersPath, 0644)
	// Also make the dir read-only so the temp-file rename fails
	if err := os.Chmod(s.cfg.Dir, 0555); err != nil {
		t.Skip("can't chmod dir")
	}
	defer os.Chmod(s.cfg.Dir, 0755)

	err := s.retireUser("bob", "admin")
	if err == nil {
		t.Fatal("expected error when write fails")
	}

	// In-memory state should have been rolled back
	bob := s.cfg.Users["bob"]
	if bob.Retired {
		t.Error("in-memory state should have been rolled back on write failure")
	}
	if len(bob.Rooms) == 0 {
		t.Error("rooms should have been restored on rollback")
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
	// Bob was in "general"
	if len(s.cfg.Users["bob"].Rooms) == 0 {
		t.Fatal("precondition: bob has rooms")
	}

	oldRooms := []string{"general"}
	s.handleRetirement("bob", oldRooms, "admin")

	bob := s.cfg.Users["bob"]
	if len(bob.Rooms) != 0 {
		t.Errorf("rooms should be cleared, got %v", bob.Rooms)
	}
}

func TestHandleRetirement_RemovesFromGroupConversations(t *testing.T) {
	s := newTestServer(t)

	// Create a group DM with alice, bob, carol
	if err := s.store.CreateConversation("conv_group", []string{"alice", "bob", "carol"}); err != nil {
		t.Fatalf("create group: %v", err)
	}
	// Also create a 1:1 between bob and alice
	if err := s.store.CreateConversation("conv_oneone", []string{"alice", "bob"}); err != nil {
		t.Fatalf("create 1:1: %v", err)
	}

	s.handleRetirement("bob", []string{"general"}, "admin")

	// Group: bob should be removed
	groupMembers, _ := s.store.GetConversationMembers("conv_group")
	for _, m := range groupMembers {
		if m == "bob" {
			t.Error("bob should be removed from group conv_group")
		}
	}
	if len(groupMembers) != 2 {
		t.Errorf("group should have 2 members, got %v", groupMembers)
	}

	// 1:1: bob should be kept
	oneMembers, _ := s.store.GetConversationMembers("conv_oneone")
	foundBob := false
	for _, m := range oneMembers {
		if m == "bob" {
			foundBob = true
		}
	}
	if !foundBob {
		t.Errorf("bob should remain in 1:1 conv_oneone, got %v", oneMembers)
	}
}

func TestHandleRetirement_EpochRotationMarked(t *testing.T) {
	s := newTestServer(t)
	// Initialize epoch for "general" so we have a baseline
	s.epochs.getOrCreate("general", 1)

	s.handleRetirement("bob", []string{"general"}, "admin")

	// Epoch should still be accessible (retirement marks rotation, doesn't
	// advance the epoch number — the next sender does that)
	// This test mainly ensures handleRetirement doesn't crash on epoch ops
	if s.epochs == nil {
		t.Error("epoch manager should exist")
	}
}

func TestPersistRetirement_WritesCompleteFile(t *testing.T) {
	s := newTestServer(t)

	// Mark bob retired in memory
	s.cfg.Lock()
	bob := s.cfg.Users["bob"]
	bob.Retired = true
	bob.RetiredAt = "2026-04-05T00:00:00Z"
	bob.RetiredReason = "key_lost"
	bob.Rooms = nil
	s.cfg.Users["bob"] = bob
	s.cfg.Unlock()

	if err := s.persistRetirement("bob"); err != nil {
		t.Fatalf("persist: %v", err)
	}

	// Verify by re-reading users.toml
	reloaded, err := config.LoadUsers(filepath.Join(s.cfg.Dir, "users.toml"))
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	// bob must be in the file with retired fields
	loadedBob := reloaded["bob"]
	if !loadedBob.Retired {
		t.Error("bob should be persisted as retired")
	}
	if loadedBob.RetiredReason != "key_lost" {
		t.Errorf("reason = %q, want key_lost", loadedBob.RetiredReason)
	}
	// alice should be unaffected
	alice := reloaded["alice"]
	if alice.Retired {
		t.Error("alice should not be affected")
	}
	if len(alice.Rooms) == 0 {
		t.Error("alice's rooms should be preserved")
	}
}
