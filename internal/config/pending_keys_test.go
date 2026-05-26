package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultServerConfig_PendingKeys(t *testing.T) {
	pk := DefaultServerConfig().Server.PendingKeys
	if pk.MaxAgeHours != 168 || pk.MaxRows != 1000 || pk.PruneIntervalSeconds != 60 ||
		pk.NotifyPerMinute != 5 || pk.NotifyBurst != 1 {
		t.Errorf("pending-keys defaults = %+v, want {168 1000 60 5 1}", pk)
	}
	// The default config must validate (LoadServerConfig decodes over these).
	if _, err := DefaultServerConfig().Validate(); err != nil {
		t.Errorf("default config should validate: %v", err)
	}
}

func TestPendingKeysSection_Validate(t *testing.T) {
	base := PendingKeysSection{MaxAgeHours: 168, MaxRows: 1000, PruneIntervalSeconds: 60, NotifyPerMinute: 5, NotifyBurst: 1}

	if err := base.Validate(); err != nil {
		t.Fatalf("valid section rejected: %v", err)
	}

	// burst == per_minute is the inclusive upper bound — valid.
	ok := base
	ok.NotifyBurst = ok.NotifyPerMinute
	if err := ok.Validate(); err != nil {
		t.Errorf("burst == per_minute should be valid: %v", err)
	}

	bad := []struct {
		name   string
		mutate func(p *PendingKeysSection)
	}{
		{"max_age_hours zero", func(p *PendingKeysSection) { p.MaxAgeHours = 0 }},
		{"max_age_hours negative", func(p *PendingKeysSection) { p.MaxAgeHours = -1 }},
		{"max_rows zero", func(p *PendingKeysSection) { p.MaxRows = 0 }},
		{"prune_interval zero", func(p *PendingKeysSection) { p.PruneIntervalSeconds = 0 }},
		{"notify_per_minute zero", func(p *PendingKeysSection) { p.NotifyPerMinute = 0 }},
		{"notify_burst zero", func(p *PendingKeysSection) { p.NotifyBurst = 0 }},
		{"notify_burst exceeds per_minute", func(p *PendingKeysSection) { p.NotifyBurst = p.NotifyPerMinute + 1 }},
	}
	for _, tc := range bad {
		p := base
		tc.mutate(&p)
		if err := p.Validate(); err == nil {
			t.Errorf("%s: expected validation error, got nil", tc.name)
		}
	}
}

// TestLoadServerConfig_OmittedPendingKeysKeepsDefaults guards the regression
// path: an existing server.toml with no [server.pending_keys] block must still
// boot (LoadServerConfig decodes over DefaultServerConfig, so the section is
// populated and passes the require-positive validation).
func TestLoadServerConfig_OmittedPendingKeysKeepsDefaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "server.toml")
	// Minimal config, no [server.pending_keys] section at all.
	if err := os.WriteFile(path, []byte("[server]\nport = 2222\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	cfg, err := LoadServerConfig(path)
	if err != nil {
		t.Fatalf("LoadServerConfig should succeed with omitted pending_keys: %v", err)
	}
	if cfg.Server.PendingKeys.MaxRows != 1000 || cfg.Server.PendingKeys.NotifyBurst != 1 {
		t.Errorf("omitted section did not keep defaults: %+v", cfg.Server.PendingKeys)
	}
}
