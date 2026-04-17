package config

import (
	"os"
	"path/filepath"
	"testing"
)

// TestDefaultDownloads verifies the per-request download channel defaults
// shipped in Phase 17 Step 4.f. These values appear in the user-visible
// wire behavior (cap rejection errors, TTL expiry timing) so regressions
// would surface as UX-level protocol breaks — hence the explicit
// assertion rather than relying on whatever zero-value ends up parsed.
func TestDefaultDownloads(t *testing.T) {
	cfg := DefaultServerConfig()
	d := cfg.Downloads

	if d.MaxConcurrentPerClient != 3 {
		t.Errorf("MaxConcurrentPerClient = %d, want 3", d.MaxConcurrentPerClient)
	}
	if d.ChannelTTLSeconds != 60 {
		t.Errorf("ChannelTTLSeconds = %d, want 60", d.ChannelTTLSeconds)
	}
}

// writeDownloadsTestConfig produces a minimal valid config directory
// with both server.toml and rooms.toml. Load requires rooms.toml to
// exist; we pass the server.toml body as a parameter so each test can
// exercise its own [downloads] shape.
func writeDownloadsTestConfig(t *testing.T, serverToml string) string {
	t.Helper()
	dir := t.TempDir()

	if err := os.WriteFile(filepath.Join(dir, "server.toml"), []byte(serverToml), 0644); err != nil {
		t.Fatalf("write server.toml: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "rooms.toml"), []byte(`
[general]
topic = "General"
`), 0644); err != nil {
		t.Fatalf("write rooms.toml: %v", err)
	}
	return dir
}

// TestDownloads_TOMLRoundTrip verifies the section parses correctly from
// on-disk server.toml. Catches toml struct-tag typos and missing-field
// regressions.
func TestDownloads_TOMLRoundTrip(t *testing.T) {
	dir := writeDownloadsTestConfig(t, `
[server]
port = 2222
bind = "127.0.0.1"

[downloads]
max_concurrent_per_client = 5
channel_ttl_seconds       = 120
`)

	cfg, err := Load(dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	if cfg.Server.Downloads.MaxConcurrentPerClient != 5 {
		t.Errorf("MaxConcurrentPerClient = %d, want 5 (toml override)",
			cfg.Server.Downloads.MaxConcurrentPerClient)
	}
	if cfg.Server.Downloads.ChannelTTLSeconds != 120 {
		t.Errorf("ChannelTTLSeconds = %d, want 120 (toml override)",
			cfg.Server.Downloads.ChannelTTLSeconds)
	}
}

// TestDownloads_DefaultsPreservedWhenOmitted verifies that when a
// server.toml has no [downloads] section at all, the DefaultServerConfig
// values survive the Load path. This matters because a typical operator
// deploying with a minimal TOML expects the defaults to apply, and a
// Load path that zero-filled the section would leave MaxConcurrentPerClient=0
// (reject every download) or ChannelTTLSeconds=0 (immediate timeout) —
// both silent-breakage scenarios.
func TestDownloads_DefaultsPreservedWhenOmitted(t *testing.T) {
	dir := writeDownloadsTestConfig(t, `
[server]
port = 2222
bind = "127.0.0.1"
`)

	cfg, err := Load(dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	if cfg.Server.Downloads.MaxConcurrentPerClient != 3 {
		t.Errorf("MaxConcurrentPerClient = %d, want 3 (default should apply when section omitted)",
			cfg.Server.Downloads.MaxConcurrentPerClient)
	}
	if cfg.Server.Downloads.ChannelTTLSeconds != 60 {
		t.Errorf("ChannelTTLSeconds = %d, want 60 (default should apply when section omitted)",
			cfg.Server.Downloads.ChannelTTLSeconds)
	}
}
