package config

// Phase 17 Step 4c — FilesSection.MaxFileIDsPerMessage config tests.
//
// Verifies:
//   - Missing [files].max_file_ids_per_message → default 20 (chat-app
//     appropriate ceiling, matches Phase 17 design philosophy of
//     sensible defaults + operator override).
//   - Present value loads from TOML.
//   - Explicit 0 loads as 0 (parser doesn't coerce; handler-side
//     fallback to defaultFileIDsCap kicks in).
//   - DefaultServerConfig carries the 20.

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFilesSection_MaxFileIDsPerMessage_DefaultWhenAbsent(t *testing.T) {
	dir := writeMinimalConfig(t)
	cfg, err := Load(dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got := cfg.Server.Files.MaxFileIDsPerMessage; got != 20 {
		t.Errorf("Files.MaxFileIDsPerMessage default = %d, want 20", got)
	}
}

func TestFilesSection_MaxFileIDsPerMessage_LoadedFromTOML(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "server.toml"), []byte(`
[server]
port = 2222
bind = "0.0.0.0"

[files]
max_file_ids_per_message = 50
`), 0644)
	os.WriteFile(filepath.Join(dir, "rooms.toml"), []byte(`
[general]
topic = "General"
`), 0644)

	cfg, err := Load(dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got := cfg.Server.Files.MaxFileIDsPerMessage; got != 50 {
		t.Errorf("Files.MaxFileIDsPerMessage = %d, want 50", got)
	}
}

func TestFilesSection_MaxFileIDsPerMessage_ExplicitZeroLoadsAsZero(t *testing.T) {
	// Mirrors GroupsSection: parser does NOT coerce 0 → default. The
	// handler-side `if cap <= 0 { cap = defaultFileIDsCap }` fallback
	// is where the safety net lives.
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "server.toml"), []byte(`
[server]
port = 2222

[files]
max_file_ids_per_message = 0
`), 0644)
	os.WriteFile(filepath.Join(dir, "rooms.toml"), []byte(`
[general]
topic = "General"
`), 0644)

	cfg, err := Load(dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got := cfg.Server.Files.MaxFileIDsPerMessage; got != 0 {
		t.Errorf("Files.MaxFileIDsPerMessage = %d, want 0 (parser must not coerce)", got)
	}
}

func TestDefaultServerConfig_FilesMaxFileIDsPerMessage(t *testing.T) {
	cfg := DefaultServerConfig()
	if got := cfg.Files.MaxFileIDsPerMessage; got != 20 {
		t.Errorf("DefaultServerConfig Files.MaxFileIDsPerMessage = %d, want 20", got)
	}
}

func TestFilesSection_OtherFieldsStillLoad(t *testing.T) {
	// Regression guard: adding MaxFileIDsPerMessage shouldn't disturb
	// MaxFileSize / MaxAvatarSize / AllowedAvatarTypes parsing.
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "server.toml"), []byte(`
[server]
port = 2222

[files]
max_file_size = "25MB"
max_avatar_size = "128KB"
max_file_ids_per_message = 30
`), 0644)
	os.WriteFile(filepath.Join(dir, "rooms.toml"), []byte(`
[general]
topic = "General"
`), 0644)

	cfg, err := Load(dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Server.Files.MaxFileSize != "25MB" {
		t.Errorf("MaxFileSize = %q, want 25MB", cfg.Server.Files.MaxFileSize)
	}
	if cfg.Server.Files.MaxAvatarSize != "128KB" {
		t.Errorf("MaxAvatarSize = %q, want 128KB", cfg.Server.Files.MaxAvatarSize)
	}
	if cfg.Server.Files.MaxFileIDsPerMessage != 30 {
		t.Errorf("MaxFileIDsPerMessage = %d, want 30", cfg.Server.Files.MaxFileIDsPerMessage)
	}
}
