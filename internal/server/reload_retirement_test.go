package server

import (
	"os"
	"path/filepath"
	"testing"
)

// TestReloadDetectsRetirementTransition verifies that when users.toml is
// edited to add retired=true for an existing user, reloadUsers detects the
// transition and fires handleRetirement (clears rooms, removes from group
// conversations, etc.).
func TestReloadDetectsRetirementTransition(t *testing.T) {
	s := newTestServer(t)

	// Create a group DM that includes bob
	if err := s.store.CreateConversation("conv_group", []string{"alice", "bob", "carol"}); err != nil {
		t.Fatalf("create conv: %v", err)
	}

	// Edit users.toml to add retired=true for bob
	usersPath := filepath.Join(s.cfg.Dir, "users.toml")
	newContent := `[alice]
key = "` + testKeyAlice + `"
display_name = "Alice"
rooms = ["general", "engineering"]

[bob]
key = "` + testKeyBob + `"
display_name = "Bob"
retired = true
retired_at = "2026-04-05T00:00:00Z"
retired_reason = "admin"

[carol]
key = "` + testKeyCarol + `"
display_name = "Carol"
rooms = ["general"]
`
	if err := os.WriteFile(usersPath, []byte(newContent), 0644); err != nil {
		t.Fatalf("write users.toml: %v", err)
	}

	// Trigger reload
	s.reloadUsers()

	// Verify bob is now retired in memory
	bob := s.cfg.Users["bob"]
	if !bob.Retired {
		t.Error("bob should be retired after reload")
	}
	if bob.RetiredReason != "admin" {
		t.Errorf("reason = %q", bob.RetiredReason)
	}
	// Rooms should have been cleared by handleRetirement
	if len(bob.Rooms) != 0 {
		t.Errorf("rooms should be cleared, got %v", bob.Rooms)
	}

	// Group conversation should no longer contain bob
	members, _ := s.store.GetConversationMembers("conv_group")
	for _, m := range members {
		if m == "bob" {
			t.Error("bob should be removed from group on retirement transition")
		}
	}
}

func TestReloadIgnoresAlreadyRetired(t *testing.T) {
	// If bob is retired in both old and new state, no re-triggering should
	// happen — handleRetirement should NOT fire.
	s := newTestServer(t)

	// Start with bob already retired
	s.cfg.Lock()
	bob := s.cfg.Users["bob"]
	bob.Retired = true
	bob.RetiredAt = "2026-04-01T00:00:00Z"
	bob.RetiredReason = "admin"
	bob.Rooms = nil
	s.cfg.Users["bob"] = bob
	s.cfg.Unlock()

	// Create conv for alice + carol (bob is retired, not in rooms)
	s.store.CreateConversation("conv_ac", []string{"alice", "carol"})

	// Rewrite users.toml keeping bob retired
	usersPath := filepath.Join(s.cfg.Dir, "users.toml")
	newContent := `[alice]
key = "` + testKeyAlice + `"
display_name = "Alice"
rooms = ["general", "engineering"]

[bob]
key = "` + testKeyBob + `"
display_name = "Bob"
retired = true
retired_at = "2026-04-01T00:00:00Z"
retired_reason = "admin"

[carol]
key = "` + testKeyCarol + `"
display_name = "Carol"
rooms = ["general"]
`
	os.WriteFile(usersPath, []byte(newContent), 0644)

	// Reload — should be a no-op w.r.t. bob's retirement (no transition)
	s.reloadUsers()

	// Members unchanged
	members, _ := s.store.GetConversationMembers("conv_ac")
	if len(members) != 2 {
		t.Errorf("conv members should be unchanged: %v", members)
	}
}

func TestReloadDetectsMultipleRetirements(t *testing.T) {
	s := newTestServer(t)

	usersPath := filepath.Join(s.cfg.Dir, "users.toml")
	newContent := `[alice]
key = "` + testKeyAlice + `"
display_name = "Alice"
rooms = ["general", "engineering"]

[bob]
key = "` + testKeyBob + `"
display_name = "Bob"
retired = true
retired_at = "2026-04-05T00:00:00Z"
retired_reason = "admin"

[carol]
key = "` + testKeyCarol + `"
display_name = "Carol"
retired = true
retired_at = "2026-04-05T00:00:00Z"
retired_reason = "key_lost"
`
	os.WriteFile(usersPath, []byte(newContent), 0644)

	s.reloadUsers()

	if !s.cfg.Users["bob"].Retired {
		t.Error("bob should be retired")
	}
	if !s.cfg.Users["carol"].Retired {
		t.Error("carol should be retired")
	}
	if s.cfg.Users["alice"].Retired {
		t.Error("alice should NOT be retired")
	}
	// Rooms cleared for retired users
	if len(s.cfg.Users["bob"].Rooms) != 0 {
		t.Errorf("bob rooms not cleared: %v", s.cfg.Users["bob"].Rooms)
	}
	if len(s.cfg.Users["carol"].Rooms) != 0 {
		t.Errorf("carol rooms not cleared: %v", s.cfg.Users["carol"].Rooms)
	}
}

func TestReloadRejectsUnretirement(t *testing.T) {
	// v1 rule: retired accounts cannot be reactivated. The server should
	// reject the config change and preserve the retired state.
	s := newTestServer(t)

	// Start with bob retired
	s.cfg.Lock()
	bob := s.cfg.Users["bob"]
	bob.Retired = true
	bob.RetiredAt = "2026-04-01T00:00:00Z"
	bob.RetiredReason = "admin"
	bob.Rooms = nil
	s.cfg.Users["bob"] = bob
	s.cfg.Unlock()

	// Rewrite users.toml with bob un-retired (admin tries to undo retirement)
	usersPath := filepath.Join(s.cfg.Dir, "users.toml")
	newContent := `[alice]
key = "` + testKeyAlice + `"
display_name = "Alice"
rooms = ["general", "engineering"]

[bob]
key = "` + testKeyBob + `"
display_name = "Bob"
rooms = ["general"]

[carol]
key = "` + testKeyCarol + `"
display_name = "Carol"
rooms = ["general"]
`
	os.WriteFile(usersPath, []byte(newContent), 0644)

	s.reloadUsers()

	after := s.cfg.Users["bob"]
	if !after.Retired {
		t.Error("bob should still be retired — un-retirement is blocked in v1")
	}
}

func TestReloadAddingNewRetiredUser(t *testing.T) {
	// Admin adds a new user who is already retired. Should be loaded but
	// no join events fired.
	s := newTestServer(t)

	usersPath := filepath.Join(s.cfg.Dir, "users.toml")
	newContent := `[alice]
key = "` + testKeyAlice + `"
display_name = "Alice"
rooms = ["general", "engineering"]

[bob]
key = "` + testKeyBob + `"
display_name = "Bob"
rooms = ["general"]

[carol]
key = "` + testKeyCarol + `"
display_name = "Carol"
rooms = ["general"]

[dave]
key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJPpG4hFrxw7JOAppGdh0JrkNDNGxypfmwJxNFCWXnpH dave@test"
display_name = "Dave"
retired = true
retired_at = "2026-03-01T00:00:00Z"
retired_reason = "admin"
`
	os.WriteFile(usersPath, []byte(newContent), 0644)

	s.reloadUsers()

	dave, ok := s.cfg.Users["dave"]
	if !ok {
		t.Fatal("dave should have been loaded")
	}
	if !dave.Retired {
		t.Error("dave should be retired")
	}
}
