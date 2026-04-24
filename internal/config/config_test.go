package config

// Load parses server.toml only.

import (
	"os"
	"path/filepath"
	"testing"
)

// writeMinimalConfig sets up a minimal valid config directory with
// server.toml only. Returns the directory path.
func writeMinimalConfig(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()

	os.WriteFile(filepath.Join(dir, "server.toml"), []byte(`
[server]
port = 2222
bind = "0.0.0.0"
`), 0644)

	return dir
}

// TestLoadMinimal verifies the basic load path.
func TestLoadMinimal(t *testing.T) {
	dir := writeMinimalConfig(t)
	cfg, err := Load(dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Server.Server.Port != 2222 {
		t.Errorf("port = %d, want 2222", cfg.Server.Server.Port)
	}
}

// TestDockerReferenceServerToml_LoadsCleanly locks in that the
// operator-facing reference TOML shipped in docker/config/server.toml
// parses successfully through the full Load + Validate pipeline,
// including the [server.auto_revoke] validator. Regression guard:
// future changes to the config schema that drop or rename a documented
// key will fail this test before reaching CI.
func TestDockerReferenceServerToml_LoadsCleanly(t *testing.T) {
	// Copy the reference server.toml into a temp dir and Load.
	// Reference is at ../../docker/config/server.toml
	// relative to internal/config/.
	refPath := filepath.Join("..", "..", "docker", "config", "server.toml")
	data, err := os.ReadFile(refPath)
	if err != nil {
		t.Fatalf("read reference server.toml: %v", err)
	}

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "server.toml"), data, 0644); err != nil {
		t.Fatalf("write temp server.toml: %v", err)
	}

	cfg, err := Load(dir)
	if err != nil {
		t.Fatalf("Load(reference docker/config/server.toml): %v", err)
	}

	// Spot-check that Phase 17 + 17b knobs populated from TOML, not
	// just defaults — detects silent deletion of documented keys.
	if cfg.Server.Server.AutoRevoke.PruneAfterHours != 168 {
		t.Errorf("auto_revoke.prune_after_hours = %d, want 168 (reference TOML)", cfg.Server.Server.AutoRevoke.PruneAfterHours)
	}
	if !cfg.Server.Server.AutoRevoke.Enabled {
		t.Error("auto_revoke.enabled should be true in reference TOML")
	}
	if cfg.Server.Server.AutoRevoke.Thresholds["malformed_frame"] != "3:60" {
		t.Errorf("auto_revoke.thresholds.malformed_frame = %q, want 3:60",
			cfg.Server.Server.AutoRevoke.Thresholds["malformed_frame"])
	}
	if cfg.Server.Server.AutoRevoke.Thresholds["reconnect_flood"] == "" {
		t.Error("reference TOML should document reconnect_flood threshold")
	}
	if cfg.Server.Files.MaxFileIDsPerMessage != 20 {
		t.Errorf("files.max_file_ids_per_message = %d, want 20",
			cfg.Server.Files.MaxFileIDsPerMessage)
	}
	if cfg.Server.Groups.MaxMembers != 150 {
		t.Errorf("groups.max_members = %d, want 150", cfg.Server.Groups.MaxMembers)
	}
	if cfg.Server.RateLimits.PerClientWriteBufferSize != 256 {
		t.Errorf("rate_limits.per_client_write_buffer_size = %d, want 256",
			cfg.Server.RateLimits.PerClientWriteBufferSize)
	}
}

// TestLoadIgnoresUnknownFiles verifies Load tolerates extra files in
// the config directory and parses only server.toml.
func TestLoadIgnoresUnknownFiles(t *testing.T) {
	dir := writeMinimalConfig(t)
	// Drop an unrelated file into the config dir.
	os.WriteFile(filepath.Join(dir, "extra.toml"), []byte(`
[whatever]
unused = true
`), 0644)

	cfg, err := Load(dir)
	if err != nil {
		t.Fatalf("Load should ignore unknown files in config dir, got error: %v", err)
	}
	if cfg == nil {
		t.Fatal("Load returned nil config")
	}
}
