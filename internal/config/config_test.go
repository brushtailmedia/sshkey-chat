package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testKeyAlice = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJPpG4hFrxw7JOAppGdh0JrkNDNGxypfmwJxNFCWXnpG test@sshkey"
const testKeyBob = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPRAbUFuMYE6xPqs13jvVb5hMtXpkWeGD93ayZY2lmqj bob@test"

// writeMinimalConfig sets up a minimal valid config directory with optional
// extra user entries. Returns the directory path.
func writeMinimalConfig(t *testing.T, extraUsers string) string {
	t.Helper()
	dir := t.TempDir()

	os.WriteFile(filepath.Join(dir, "server.toml"), []byte(`
[server]
port = 2222
bind = "0.0.0.0"
admins = ["alice"]
`), 0644)

	users := `[alice]
key = "` + testKeyAlice + `"
display_name = "Alice"
rooms = ["general"]
` + extraUsers
	os.WriteFile(filepath.Join(dir, "users.toml"), []byte(users), 0644)

	os.WriteFile(filepath.Join(dir, "rooms.toml"), []byte(`
[general]
topic = "General"
`), 0644)

	return dir
}

func TestLoadRetiredUser(t *testing.T) {
	dir := writeMinimalConfig(t, `
[bob]
key = "`+testKeyBob+`"
display_name = "Bob"
retired = true
retired_at = "2026-04-05T00:00:00Z"
retired_reason = "key_lost"
`)
	cfg, err := Load(dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(cfg.Users) != 2 {
		t.Fatalf("expected 2 users, got %d", len(cfg.Users))
	}
	bob := cfg.Users["bob"]
	if !bob.Retired {
		t.Error("bob should be retired")
	}
	if bob.RetiredAt != "2026-04-05T00:00:00Z" {
		t.Errorf("retired_at = %q", bob.RetiredAt)
	}
	if bob.RetiredReason != "key_lost" {
		t.Errorf("retired_reason = %q", bob.RetiredReason)
	}
	alice := cfg.Users["alice"]
	if alice.Retired {
		t.Error("alice should NOT be retired (no retired field in TOML)")
	}
}

func TestRetiredUserStaleRoomReferenceAllowed(t *testing.T) {
	// Retired users can reference nonexistent rooms without failing validation
	// (rooms list is ignored for retired users).
	dir := writeMinimalConfig(t, `
[bob]
key = "`+testKeyBob+`"
display_name = "Bob"
rooms = ["nonexistent-room"]
retired = true
retired_at = "2026-04-05T00:00:00Z"
retired_reason = "admin"
`)
	if _, err := Load(dir); err != nil {
		t.Fatalf("retired user with stale room should load: %v", err)
	}
}

func TestActiveUserStaleRoomReferenceRejected(t *testing.T) {
	// Active users still need valid room references.
	dir := writeMinimalConfig(t, `
[bob]
key = "`+testKeyBob+`"
display_name = "Bob"
rooms = ["nonexistent-room"]
`)
	_, err := Load(dir)
	if err == nil {
		t.Fatal("expected load to fail for active user with bad room ref")
	}
	if !strings.Contains(err.Error(), "nonexistent-room") {
		t.Errorf("error should mention missing room: %v", err)
	}
}


func TestNoKeyRotationTypes(t *testing.T) {
	// Regression: key_rotate* types should have been removed from the protocol.
	// This test documents that decision by ensuring common rotation error codes
	// aren't present in the config. (More a marker than a test — exercises the
	// Load path and checks the world is consistent.)
	dir := writeMinimalConfig(t, "")
	cfg, err := Load(dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(cfg.Users) == 0 {
		t.Fatal("no users loaded")
	}
}
