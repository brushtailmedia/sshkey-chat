package config

// Phase 16 Gap 4: most of this file's previous tests exercised the
// users.toml load path and the cross-validation between users.toml and
// rooms.toml. That whole subsystem was removed when users.toml support
// was deleted — operators now create the first admin via
// `sshkey-ctl bootstrap-admin` and seed rooms via `sshkey-ctl add-room`
// (or via the rooms.toml seed which is still supported).
//
// The remaining tests cover what still exists: rooms.toml loading and
// the absence of the deleted Users field on Config.

import (
	"os"
	"path/filepath"
	"testing"
)

// writeMinimalConfig sets up a minimal valid config directory with
// just server.toml and rooms.toml. Returns the directory path.
func writeMinimalConfig(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()

	os.WriteFile(filepath.Join(dir, "server.toml"), []byte(`
[server]
port = 2222
bind = "0.0.0.0"
`), 0644)

	os.WriteFile(filepath.Join(dir, "rooms.toml"), []byte(`
[general]
topic = "General"
`), 0644)

	return dir
}

// TestLoadMinimal verifies the basic load path still works after the
// users.toml removal.
func TestLoadMinimal(t *testing.T) {
	dir := writeMinimalConfig(t)
	cfg, err := Load(dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Server.Server.Port != 2222 {
		t.Errorf("port = %d, want 2222", cfg.Server.Server.Port)
	}
	if len(cfg.Rooms) != 1 {
		t.Errorf("expected 1 room, got %d", len(cfg.Rooms))
	}
	if _, ok := cfg.Rooms["general"]; !ok {
		t.Error("expected 'general' room to be loaded")
	}
}

// TestLoadIgnoresUsersTomlIfPresent verifies that a stray users.toml
// file in the config directory does NOT break Load. Phase 16 Gap 4
// removed the users.toml parsing path entirely, so the file is just
// ignored — operators upgrading from a pre-Phase-16 install will see
// a warning in the server logs (from reload.go) but Load itself
// shouldn't even look at the file.
func TestLoadIgnoresUsersTomlIfPresent(t *testing.T) {
	dir := writeMinimalConfig(t)
	// Put a junk users.toml in the directory.
	os.WriteFile(filepath.Join(dir, "users.toml"), []byte(`
[alice]
key = "ssh-ed25519 AAAA-bogus"
display_name = "Alice"
`), 0644)

	cfg, err := Load(dir)
	if err != nil {
		t.Fatalf("Load should ignore stray users.toml, got error: %v", err)
	}
	if cfg == nil {
		t.Fatal("Load returned nil config")
	}
}
