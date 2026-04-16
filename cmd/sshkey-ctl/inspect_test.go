package main

// Phase 16 — tests for the inspection commands.
//
// Coverage:
//   - show-user: found by ID, found by display name, not found,
//     includes rooms + devices
//   - show-room: found by display name, found by ID, not found,
//     includes members
//   - list-admins: empty, with admins (including retired admins)
//   - search-users: by name (case-insensitive substring), by
//     fingerprint (exact), no matches, missing args

import (
	"strings"
	"testing"

	"github.com/brushtailmedia/sshkey-chat/internal/config"
	"github.com/brushtailmedia/sshkey-chat/internal/store"
)

// --- show-user tests ---

func TestShowUser_FoundByID(t *testing.T) {
	aliceKey, _ := genTestKey(t, "Alice")
	users := map[string]testUser{
		"usr_alice": {Key: aliceKey, DisplayName: "Alice"},
	}
	dataDir := setupDataDir(t, nil, users)

	out := captureStdout(t, func() {
		if err := cmdShowUser(dataDir, []string{"usr_alice"}); err != nil {
			t.Fatalf("show-user: %v", err)
		}
	})

	for _, want := range []string{
		"usr_alice",
		"Alice",
		"SHA256:",
		"Admin:",
		"Retired:",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q, got: %q", want, out)
		}
	}
}

func TestShowUser_FoundByDisplayName(t *testing.T) {
	aliceKey, _ := genTestKey(t, "Alice")
	users := map[string]testUser{
		"usr_alice": {Key: aliceKey, DisplayName: "Alice"},
	}
	dataDir := setupDataDir(t, nil, users)

	out := captureStdout(t, func() {
		if err := cmdShowUser(dataDir, []string{"Alice"}); err != nil {
			t.Fatalf("show-user by name: %v", err)
		}
	})
	if !strings.Contains(out, "usr_alice") {
		t.Errorf("output should include user ID, got: %q", out)
	}
}

func TestShowUser_CaseInsensitiveDisplayName(t *testing.T) {
	aliceKey, _ := genTestKey(t, "Alice")
	users := map[string]testUser{
		"usr_alice": {Key: aliceKey, DisplayName: "Alice"},
	}
	dataDir := setupDataDir(t, nil, users)

	if err := cmdShowUser(dataDir, []string{"alice"}); err != nil {
		t.Fatalf("case-insensitive search should work: %v", err)
	}
}

func TestShowUser_NotFound(t *testing.T) {
	dataDir := setupDataDir(t, nil)
	err := cmdShowUser(dataDir, []string{"ghost"})
	if err == nil {
		t.Fatal("should error for unknown user")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("wrong error: %v", err)
	}
}

func TestShowUser_IncludesRooms(t *testing.T) {
	aliceKey, _ := genTestKey(t, "Alice")
	users := map[string]testUser{
		"usr_alice": {Key: aliceKey, DisplayName: "Alice", Rooms: []string{"general"}},
	}
	dataDir := setupDataDir(t, map[string]config.Room{
		"general": {Topic: "Chat"},
	}, users)

	out := captureStdout(t, func() {
		cmdShowUser(dataDir, []string{"usr_alice"})
	})
	if !strings.Contains(out, "general") {
		t.Errorf("output should include room name, got: %q", out)
	}
	if !strings.Contains(out, "Rooms (1)") {
		t.Errorf("output should include room count, got: %q", out)
	}
}

func TestShowUser_IncludesDevices(t *testing.T) {
	aliceKey, _ := genTestKey(t, "Alice")
	users := map[string]testUser{
		"usr_alice": {Key: aliceKey, DisplayName: "Alice"},
	}
	dataDir := setupDataDir(t, nil, users)

	st0, _ := store.Open(dataDir)
	st0.UpsertDevice("usr_alice", "dev_laptop")
	st0.UpsertDevice("usr_alice", "dev_phone")
	st0.Close()

	out := captureStdout(t, func() {
		cmdShowUser(dataDir, []string{"usr_alice"})
	})
	if !strings.Contains(out, "dev_laptop") {
		t.Errorf("output should include device ID, got: %q", out)
	}
	if !strings.Contains(out, "Devices (2)") {
		t.Errorf("output should show device count, got: %q", out)
	}
}

func TestShowUser_MissingArgs(t *testing.T) {
	err := cmdShowUser(t.TempDir(), nil)
	if err == nil {
		t.Fatal("should error without args")
	}
}

// --- show-room tests ---

func TestShowRoom_FoundByDisplayName(t *testing.T) {
	aliceKey, _ := genTestKey(t, "Alice")
	users := map[string]testUser{
		"usr_alice": {Key: aliceKey, DisplayName: "Alice", Rooms: []string{"general"}},
	}
	dataDir := setupDataDir(t, map[string]config.Room{
		"general": {Topic: "General chat"},
	}, users)

	out := captureStdout(t, func() {
		if err := cmdShowRoom(dataDir, []string{"general"}); err != nil {
			t.Fatalf("show-room: %v", err)
		}
	})

	for _, want := range []string{
		"general",
		"General chat",
		"Members (1)",
		"Alice",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q, got: %q", want, out)
		}
	}
}

func TestShowRoom_FoundByID(t *testing.T) {
	dataDir := setupDataDir(t, map[string]config.Room{
		"general": {Topic: "Chat"},
	})

	st0, _ := store.Open(dataDir)
	id := st0.RoomDisplayNameToID("general")
	st0.Close()

	out := captureStdout(t, func() {
		if err := cmdShowRoom(dataDir, []string{id}); err != nil {
			t.Fatalf("show-room by ID: %v", err)
		}
	})
	if !strings.Contains(out, "general") {
		t.Errorf("output should include display name: %q", out)
	}
}

func TestShowRoom_NotFound(t *testing.T) {
	dataDir := setupDataDir(t, nil)
	err := cmdShowRoom(dataDir, []string{"ghost"})
	if err == nil {
		t.Fatal("should error for unknown room")
	}
}

func TestShowRoom_MissingArgs(t *testing.T) {
	err := cmdShowRoom(t.TempDir(), nil)
	if err == nil {
		t.Fatal("should error without args")
	}
}

// --- list-admins tests ---

func TestListAdmins_Empty(t *testing.T) {
	dataDir := setupDataDir(t, nil)
	out := captureStdout(t, func() {
		cmdListAdmins(dataDir)
	})
	if !strings.Contains(out, "No admin") {
		t.Errorf("should show 'no admin' message, got: %q", out)
	}
}

func TestListAdmins_WithAdmins(t *testing.T) {
	aliceKey, _ := genTestKey(t, "Alice")
	bobKey, _ := genTestKey(t, "Bob")
	users := map[string]testUser{
		"usr_alice": {Key: aliceKey, DisplayName: "Alice"},
		"usr_bob":   {Key: bobKey, DisplayName: "Bob"},
	}
	dataDir := setupDataDir(t, nil, users)

	st0, _ := store.Open(dataDir)
	st0.SetAdmin("usr_alice", true)
	st0.Close()

	out := captureStdout(t, func() {
		cmdListAdmins(dataDir)
	})
	if !strings.Contains(out, "Alice") {
		t.Errorf("should list alice, got: %q", out)
	}
	if strings.Contains(out, "Bob") {
		t.Errorf("should not list bob (not admin), got: %q", out)
	}
}

func TestListAdmins_IncludesRetiredAdmins(t *testing.T) {
	aliceKey, _ := genTestKey(t, "Alice")
	users := map[string]testUser{
		"usr_alice12345": {Key: aliceKey, DisplayName: "Alice"},
	}
	dataDir := setupDataDir(t, nil, users)

	st0, _ := store.Open(dataDir)
	st0.SetAdmin("usr_alice12345", true)
	st0.SetUserRetired("usr_alice12345", "test")
	st0.Close()

	out := captureStdout(t, func() {
		cmdListAdmins(dataDir)
	})
	if !strings.Contains(out, "[retired]") {
		t.Errorf("should mark retired admin, got: %q", out)
	}
}

// --- search-users tests ---

func TestSearchUsers_ByName(t *testing.T) {
	aliceKey, _ := genTestKey(t, "Alice")
	bobKey, _ := genTestKey(t, "Bob")
	users := map[string]testUser{
		"usr_alice": {Key: aliceKey, DisplayName: "Alice Wonderland"},
		"usr_bob":   {Key: bobKey, DisplayName: "Bob Builder"},
	}
	dataDir := setupDataDir(t, nil, users)

	out := captureStdout(t, func() {
		if err := cmdSearchUsers(dataDir, []string{"--name", "alice"}); err != nil {
			t.Fatalf("search: %v", err)
		}
	})
	if !strings.Contains(out, "Alice Wonderland") {
		t.Errorf("should match alice, got: %q", out)
	}
	if strings.Contains(out, "Bob") {
		t.Errorf("should not match bob, got: %q", out)
	}
}

func TestSearchUsers_ByNameCaseInsensitive(t *testing.T) {
	aliceKey, _ := genTestKey(t, "Alice")
	users := map[string]testUser{
		"usr_alice": {Key: aliceKey, DisplayName: "Alice"},
	}
	dataDir := setupDataDir(t, nil, users)

	out := captureStdout(t, func() {
		cmdSearchUsers(dataDir, []string{"--name", "ALICE"})
	})
	if !strings.Contains(out, "Alice") {
		t.Errorf("case-insensitive search should match, got: %q", out)
	}
}

func TestSearchUsers_ByFingerprint(t *testing.T) {
	aliceKey, fp := genTestKey(t, "Alice")
	users := map[string]testUser{
		"usr_alice": {Key: aliceKey, DisplayName: "Alice"},
	}
	dataDir := setupDataDir(t, nil, users)

	out := captureStdout(t, func() {
		if err := cmdSearchUsers(dataDir, []string{"--fingerprint", fp}); err != nil {
			t.Fatalf("search: %v", err)
		}
	})
	if !strings.Contains(out, "Alice") {
		t.Errorf("fingerprint search should match alice, got: %q", out)
	}
}

func TestSearchUsers_NoMatches(t *testing.T) {
	dataDir := setupDataDir(t, nil)
	out := captureStdout(t, func() {
		cmdSearchUsers(dataDir, []string{"--name", "nobody"})
	})
	if !strings.Contains(out, "No users matching") {
		t.Errorf("should show no-match message, got: %q", out)
	}
}

func TestSearchUsers_MissingArgs(t *testing.T) {
	err := cmdSearchUsers(t.TempDir(), nil)
	if err == nil {
		t.Fatal("should error without --name or --fingerprint")
	}
}
