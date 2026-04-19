package config

// Phase 19 Step 1 — [backup] config loader tests.
//
// Coverage matrix:
//   - Defaults (DefaultServerConfig) — enabled=true, interval=24h, etc.
//   - TOML round-trip for a complete [backup] block
//   - Absent [backup] section falls back to defaults (including enabled=true)
//   - enabled=false skips downstream field requirement (interval still validates if set)
//   - Interval missing when enabled=true → error
//   - Interval that doesn't parse → error
//   - Interval zero or negative → error
//   - RetentionCount negative → error
//   - RetentionCount zero accepted (disables count-based retention)
//   - RetentionAge empty accepted (disables age-based retention)
//   - RetentionAge unparseable → error
//   - RetentionAge zero/negative → error
//   - DestDir with ".." rejected (path-traversal guard)
//   - DestDir absolute accepted
//   - DestDir empty accepted (caller applies default)
//   - Warning: retention fully disabled (count=0 + age empty) + enabled=true
//   - Warning: interval < 1h + enabled=true
//   - No warnings on a valid default config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDefaultServerConfig_Backup(t *testing.T) {
	cfg := DefaultServerConfig()
	b := cfg.Backup

	if !b.Enabled {
		t.Error("default Backup.Enabled = false, want true (Phase 19 decision #11: default-on)")
	}
	if b.Interval != "24h" {
		t.Errorf("default Backup.Interval = %q, want %q", b.Interval, "24h")
	}
	if b.DestDir != "backups" {
		t.Errorf("default Backup.DestDir = %q, want %q", b.DestDir, "backups")
	}
	if b.RetentionCount != 10 {
		t.Errorf("default Backup.RetentionCount = %d, want 10", b.RetentionCount)
	}
	if b.RetentionAge != "720h" {
		t.Errorf("default Backup.RetentionAge = %q, want %q", b.RetentionAge, "720h")
	}
	if !b.Compress {
		t.Error("default Backup.Compress = false, want true")
	}
	if !b.SkipIfIdle {
		t.Error("default Backup.SkipIfIdle = false, want true")
	}
	if !b.IncludeConfigFiles {
		t.Error("default Backup.IncludeConfigFiles = false, want true")
	}

	// Validate round-trips cleanly.
	parsed, warnings, err := b.ParseAndValidate()
	if err != nil {
		t.Fatalf("DefaultServerConfig().Backup.ParseAndValidate() returned error: %v", err)
	}
	if len(warnings) != 0 {
		t.Errorf("default config produced %d warnings: %v", len(warnings), warnings)
	}
	if parsed.Interval != 24*time.Hour {
		t.Errorf("parsed Interval = %s, want 24h", parsed.Interval)
	}
	if parsed.RetentionAge != 720*time.Hour {
		t.Errorf("parsed RetentionAge = %s, want 720h", parsed.RetentionAge)
	}
}

func TestBackup_LoadedFromTOML(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "server.toml"), []byte(`
[server]
port = 2222
bind = "0.0.0.0"

[backup]
enabled = true
interval = "6h"
dest_dir = "/srv/backups"
retention_count = 5
retention_age = "240h"
compress = false
skip_if_idle = false
include_config_files = false
`), 0644)

	cfg, err := LoadServerConfig(filepath.Join(dir, "server.toml"))
	if err != nil {
		t.Fatalf("LoadServerConfig: %v", err)
	}
	b := cfg.Backup
	if !b.Enabled {
		t.Error("Enabled did not round-trip")
	}
	if b.Interval != "6h" {
		t.Errorf("Interval = %q, want %q", b.Interval, "6h")
	}
	if b.DestDir != "/srv/backups" {
		t.Errorf("DestDir = %q, want /srv/backups", b.DestDir)
	}
	if b.RetentionCount != 5 {
		t.Errorf("RetentionCount = %d, want 5", b.RetentionCount)
	}
	if b.RetentionAge != "240h" {
		t.Errorf("RetentionAge = %q, want 240h", b.RetentionAge)
	}
	if b.Compress {
		t.Error("Compress did not round-trip (expected false)")
	}
	if b.SkipIfIdle {
		t.Error("SkipIfIdle did not round-trip (expected false)")
	}
	if b.IncludeConfigFiles {
		t.Error("IncludeConfigFiles did not round-trip (expected false)")
	}
}

func TestBackup_AbsentSectionUsesDefaults(t *testing.T) {
	dir := t.TempDir()
	// server.toml with no [backup] section — should get defaults including enabled=true.
	os.WriteFile(filepath.Join(dir, "server.toml"), []byte(`
[server]
port = 2222
bind = "0.0.0.0"
`), 0644)

	cfg, err := LoadServerConfig(filepath.Join(dir, "server.toml"))
	if err != nil {
		t.Fatalf("LoadServerConfig: %v", err)
	}
	if !cfg.Backup.Enabled {
		t.Error("absent [backup] section should inherit Enabled=true default")
	}
	if cfg.Backup.Interval != "24h" {
		t.Errorf("absent [backup] Interval = %q, want 24h", cfg.Backup.Interval)
	}
}

func TestBackup_ValidateRejects(t *testing.T) {
	cases := []struct {
		name    string
		section BackupSection
		wantSub string // substring expected in the error
	}{
		{
			name: "enabled but interval missing",
			section: BackupSection{
				Enabled:  true,
				Interval: "",
			},
			wantSub: "interval is required",
		},
		{
			name: "unparseable interval",
			section: BackupSection{
				Enabled:  true,
				Interval: "24 hours",
			},
			wantSub: "interval=\"24 hours\"",
		},
		{
			name: "zero interval",
			section: BackupSection{
				Enabled:  true,
				Interval: "0s",
			},
			wantSub: "must be > 0",
		},
		{
			name: "negative interval",
			section: BackupSection{
				Enabled:  true,
				Interval: "-5m",
			},
			wantSub: "must be > 0",
		},
		{
			name: "negative retention_count",
			section: BackupSection{
				Enabled:        true,
				Interval:       "24h",
				RetentionCount: -1,
			},
			wantSub: "retention_count=-1",
		},
		{
			name: "unparseable retention_age",
			section: BackupSection{
				Enabled:      true,
				Interval:     "24h",
				RetentionAge: "forever",
			},
			wantSub: "retention_age=\"forever\"",
		},
		{
			name: "zero retention_age",
			section: BackupSection{
				Enabled:      true,
				Interval:     "24h",
				RetentionAge: "0s",
			},
			wantSub: "retention_age=\"0s\"",
		},
		{
			name: "dest_dir path-traversal via leading ..",
			section: BackupSection{
				Enabled:  true,
				Interval: "24h",
				DestDir:  "../../etc",
			},
			wantSub: "path-traversal",
		},
		{
			name: "dest_dir path-traversal via embedded ..",
			section: BackupSection{
				Enabled:  true,
				Interval: "24h",
				DestDir:  "backups/../../etc",
			},
			wantSub: "path-traversal",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := tc.section.ParseAndValidate()
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantSub)
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Errorf("error = %q, want substring %q", err.Error(), tc.wantSub)
			}
		})
	}
}

func TestBackup_ValidateAccepts(t *testing.T) {
	cases := []struct {
		name    string
		section BackupSection
	}{
		{
			name: "disabled: all other fields inert",
			section: BackupSection{
				Enabled:  false,
				Interval: "", // OK when disabled
			},
		},
		{
			name: "retention_count zero (unlimited)",
			section: BackupSection{
				Enabled:        true,
				Interval:       "24h",
				RetentionCount: 0,
				RetentionAge:   "720h",
			},
		},
		{
			name: "retention_age empty (disabled)",
			section: BackupSection{
				Enabled:        true,
				Interval:       "24h",
				RetentionCount: 10,
				RetentionAge:   "",
			},
		},
		{
			name: "absolute dest_dir",
			section: BackupSection{
				Enabled:  true,
				Interval: "24h",
				DestDir:  "/srv/backups",
			},
		},
		{
			name: "empty dest_dir (caller applies default)",
			section: BackupSection{
				Enabled:  true,
				Interval: "24h",
				DestDir:  "",
			},
		},
		{
			name: "disabled but interval still set (typo catch later)",
			section: BackupSection{
				Enabled:  false,
				Interval: "24h",
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := tc.section.ParseAndValidate()
			if err != nil {
				t.Fatalf("expected no error, got: %v", err)
			}
		})
	}
}

func TestBackup_ValidateWarnings(t *testing.T) {
	// Both retention knobs disabled + enabled → warning
	section := BackupSection{
		Enabled:        true,
		Interval:       "24h",
		RetentionCount: 0,
		RetentionAge:   "",
	}
	_, warnings, err := section.ParseAndValidate()
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	found := false
	for _, w := range warnings {
		if strings.Contains(w, "retention") && strings.Contains(w, "accumulate") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected 'retention disabled' warning, got: %v", warnings)
	}

	// Sub-1h interval + enabled → warning
	section = BackupSection{
		Enabled:      true,
		Interval:     "30m",
		RetentionAge: "720h",
	}
	_, warnings, err = section.ParseAndValidate()
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	found = false
	for _, w := range warnings {
		if strings.Contains(w, "interval") && strings.Contains(w, "1h") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected 'interval < 1h' warning, got: %v", warnings)
	}

	// Sub-1h interval + DISABLED → no warning (knob is inert)
	section = BackupSection{
		Enabled:  false,
		Interval: "30m",
	}
	_, warnings, err = section.ParseAndValidate()
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	for _, w := range warnings {
		if strings.Contains(w, "interval") {
			t.Errorf("disabled config should not warn on interval, got: %v", warnings)
		}
	}
}

func TestBackup_ParsedDurations(t *testing.T) {
	section := BackupSection{
		Enabled:      true,
		Interval:     "1h30m",
		RetentionAge: "168h",
	}
	parsed, _, err := section.ParseAndValidate()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if parsed.Interval != 90*time.Minute {
		t.Errorf("parsed Interval = %s, want 1h30m", parsed.Interval)
	}
	if parsed.RetentionAge != 168*time.Hour {
		t.Errorf("parsed RetentionAge = %s, want 168h", parsed.RetentionAge)
	}
}

func TestBackup_DestDirCleaned(t *testing.T) {
	// Clean collapses redundant segments. "foo/./bar" -> "foo/bar".
	section := BackupSection{
		Enabled:  true,
		Interval: "24h",
		DestDir:  "foo/./bar",
	}
	parsed, _, err := section.ParseAndValidate()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if parsed.DestDir != filepath.Clean("foo/./bar") {
		t.Errorf("parsed DestDir = %q, want %q", parsed.DestDir, filepath.Clean("foo/./bar"))
	}
}

func TestBackup_ServerConfigValidateWiresBackup(t *testing.T) {
	// Bad [backup] should fail ServerConfig.Validate() with a clear message.
	cfg := DefaultServerConfig()
	cfg.Backup.Interval = "not-a-duration"
	_, err := cfg.Validate()
	if err == nil {
		t.Fatal("expected Validate to propagate backup error, got nil")
	}
	if !strings.Contains(err.Error(), "backup") {
		t.Errorf("error = %q, want substring 'backup'", err.Error())
	}
}
