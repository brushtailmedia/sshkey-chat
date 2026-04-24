package config

// Phase 17b Step 1 — [server.auto_revoke] config loader tests.
//
// Coverage matrix:
//   - Defaults (DefaultServerConfig) — enabled=true, prune=168, empty map
//   - TOML round-trip for a valid [server.auto_revoke] block
//   - Unknown signal key rejected (typo) with list of valid signals
//   - Load signal key rejected with "load signal" category tag
//   - Observational signal key rejected with "observational signal" tag
//   - Malformed threshold strings — 7 variations, all rejected
//   - prune_after_hours negative rejected
//   - prune_after_hours ≤ largest window rejected
//   - prune_after_hours > largest window accepted
//   - Enabled + zero thresholds → non-fatal warning
//   - Disabled + zero thresholds → no warning (silent)
//   - Every counters.AutoRevokeSignals entry is accepted (drift guard)

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/brushtailmedia/sshkey-chat/internal/counters"
)

func TestDefaultServerConfig_AutoRevoke(t *testing.T) {
	cfg := DefaultServerConfig()
	if !cfg.Server.AutoRevoke.Enabled {
		t.Error("default AutoRevoke.Enabled = false, want true (Phase 17b default-on)")
	}
	if got := cfg.Server.AutoRevoke.PruneAfterHours; got != 168 {
		t.Errorf("default PruneAfterHours = %d, want 168", got)
	}
	if cfg.Server.AutoRevoke.Thresholds != nil {
		t.Errorf("default Thresholds = %v, want nil (operator must populate)", cfg.Server.AutoRevoke.Thresholds)
	}
}

func TestAutoRevoke_LoadedFromTOML(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "server.toml"), []byte(`
[server]
port = 2222
bind = "0.0.0.0"

[server.auto_revoke]
enabled = true
prune_after_hours = 168

[server.auto_revoke.thresholds]
malformed_frame       = "3:60"
invalid_nanoid        = "5:60"
wrapped_keys_over_cap = "2:60"
`), 0644)

	cfg, err := Load(dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	ar := cfg.Server.Server.AutoRevoke
	if !ar.Enabled {
		t.Error("Enabled = false, want true")
	}
	if ar.PruneAfterHours != 168 {
		t.Errorf("PruneAfterHours = %d, want 168", ar.PruneAfterHours)
	}
	if got, want := len(ar.Thresholds), 3; got != want {
		t.Errorf("len(Thresholds) = %d, want %d", got, want)
	}
	if ar.Thresholds["malformed_frame"] != "3:60" {
		t.Errorf("Thresholds[malformed_frame] = %q, want %q", ar.Thresholds["malformed_frame"], "3:60")
	}

	rules, warnings, err := ar.ParseAndValidate()
	if err != nil {
		t.Fatalf("ParseAndValidate: %v", err)
	}
	if len(warnings) != 0 {
		t.Errorf("warnings = %v, want none", warnings)
	}
	if len(rules) != 3 {
		t.Errorf("len(rules) = %d, want 3", len(rules))
	}
	// Verify parsed count + window are correct for one rule.
	var found bool
	for _, r := range rules {
		if r.Signal == counters.SignalMalformedFrame {
			if r.Count != 3 || r.WindowSec != 60 {
				t.Errorf("malformed_frame rule = %+v, want count=3 window=60", r)
			}
			found = true
		}
	}
	if !found {
		t.Error("malformed_frame rule not present in parsed output")
	}
}

func TestAutoRevoke_UnknownSignalRejected(t *testing.T) {
	ar := AutoRevokeSection{
		Enabled: true,
		Thresholds: map[string]string{
			"malfromed_frame": "3:60", // typo: malfromed vs malformed
		},
	}
	_, _, err := ar.ParseAndValidate()
	if err == nil {
		t.Fatal("expected error for typo signal key, got nil")
	}
	if !strings.Contains(err.Error(), "unknown signal") {
		t.Errorf("error = %q, want to contain 'unknown signal'", err.Error())
	}
	// Error should list the valid signals so the operator can fix the typo.
	if !strings.Contains(err.Error(), counters.SignalMalformedFrame) {
		t.Errorf("error = %q, want to mention valid signal name", err.Error())
	}
}

func TestAutoRevoke_LoadSignalRejected(t *testing.T) {
	ar := AutoRevokeSection{
		Enabled: true,
		Thresholds: map[string]string{
			counters.SignalRateLimited: "3:60",
		},
	}
	_, _, err := ar.ParseAndValidate()
	if err == nil {
		t.Fatal("expected error for load-signal key, got nil")
	}
	if !strings.Contains(err.Error(), "load signal") {
		t.Errorf("error = %q, want to contain 'load signal' (category tag)", err.Error())
	}
}

func TestAutoRevoke_ObservationalSignalRejected(t *testing.T) {
	ar := AutoRevokeSection{
		Enabled: true,
		Thresholds: map[string]string{
			counters.SignalBroadcastDropped: "3:60",
		},
	}
	_, _, err := ar.ParseAndValidate()
	if err == nil {
		t.Fatal("expected error for observational-signal key, got nil")
	}
	if !strings.Contains(err.Error(), "observational signal") {
		t.Errorf("error = %q, want to contain 'observational signal' (category tag)", err.Error())
	}
}

func TestAutoRevoke_MalformedThreshold(t *testing.T) {
	cases := []struct {
		name, raw string
	}{
		{"no_colon", "3"},
		{"zero_window", "3:0"},
		{"zero_count", "0:60"},
		{"nonnumeric_window", "3:x"},
		{"nonnumeric_count", "x:60"},
		{"negative_count", "-1:60"},
		{"negative_window", "3:-60"},
		{"empty_string", ""},
		{"three_parts", "3:60:extra"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ar := AutoRevokeSection{
				Enabled: true,
				Thresholds: map[string]string{
					counters.SignalMalformedFrame: tc.raw,
				},
			}
			_, _, err := ar.ParseAndValidate()
			if err == nil {
				t.Fatalf("threshold %q accepted, want rejection", tc.raw)
			}
		})
	}
}

func TestAutoRevoke_PruneAfterHours_Negative(t *testing.T) {
	ar := AutoRevokeSection{
		Enabled:         true,
		PruneAfterHours: -1,
	}
	_, _, err := ar.ParseAndValidate()
	if err == nil {
		t.Fatal("negative prune_after_hours accepted, want rejection")
	}
	if !strings.Contains(err.Error(), "prune_after_hours") {
		t.Errorf("error = %q, want to mention prune_after_hours", err.Error())
	}
}

func TestAutoRevoke_PruneAfterHours_EqualsWindow(t *testing.T) {
	// Largest window 3600s → 1h. prune_after_hours = 1 is NOT > 1h, should reject.
	ar := AutoRevokeSection{
		Enabled:         true,
		PruneAfterHours: 1,
		Thresholds: map[string]string{
			counters.SignalMalformedFrame: "3:3600",
		},
	}
	_, _, err := ar.ParseAndValidate()
	if err == nil {
		t.Fatal("prune_after_hours equal to largest window accepted, want rejection")
	}
	if !strings.Contains(err.Error(), "prune_after_hours") {
		t.Errorf("error = %q, want to mention prune_after_hours", err.Error())
	}
}

func TestAutoRevoke_PruneAfterHours_GreaterThanWindow(t *testing.T) {
	// prune_after_hours = 2, largest window = 3600s = 1h, 2 > 1, OK.
	ar := AutoRevokeSection{
		Enabled:         true,
		PruneAfterHours: 2,
		Thresholds: map[string]string{
			counters.SignalMalformedFrame: "3:3600",
		},
	}
	_, _, err := ar.ParseAndValidate()
	if err != nil {
		t.Fatalf("valid prune_after_hours rejected: %v", err)
	}
}

func TestAutoRevoke_PruneAfterHours_CeilDivide(t *testing.T) {
	// Window 3601s → ceil(3601/3600) = 2h. prune_after_hours = 2 is NOT > 2h, reject.
	// prune_after_hours = 3 IS > 2h, accept.
	ar := AutoRevokeSection{
		Enabled:         true,
		PruneAfterHours: 2,
		Thresholds: map[string]string{
			counters.SignalMalformedFrame: "3:3601",
		},
	}
	_, _, err := ar.ParseAndValidate()
	if err == nil {
		t.Error("prune_after_hours = 2 with 3601s window (ceil=2h) accepted, want rejection")
	}

	ar.PruneAfterHours = 3
	if _, _, err := ar.ParseAndValidate(); err != nil {
		t.Errorf("prune_after_hours = 3 with 3601s window rejected: %v", err)
	}
}

func TestAutoRevoke_PruneZero_DisablesCheck(t *testing.T) {
	// prune_after_hours = 0 is valid regardless of window size — TTL
	// disabled means the check doesn't fire, so no constraint.
	ar := AutoRevokeSection{
		Enabled:         true,
		PruneAfterHours: 0,
		Thresholds: map[string]string{
			counters.SignalMalformedFrame: "3:999999", // huge window
		},
	}
	if _, _, err := ar.ParseAndValidate(); err != nil {
		t.Errorf("prune_after_hours = 0 with any window rejected: %v", err)
	}
}

func TestAutoRevoke_EnabledWithZeroThresholds_Warns(t *testing.T) {
	ar := AutoRevokeSection{
		Enabled:         true,
		PruneAfterHours: 0,
		Thresholds:      nil,
	}
	_, warnings, err := ar.ParseAndValidate()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(warnings) == 0 {
		t.Error("expected warning for enabled=true + zero thresholds, got none")
	}
	if !strings.Contains(warnings[0], "enabled = true") {
		t.Errorf("warning = %q, want to mention enabled = true", warnings[0])
	}
}

func TestAutoRevoke_DisabledWithZeroThresholds_Silent(t *testing.T) {
	ar := AutoRevokeSection{
		Enabled:         false,
		PruneAfterHours: 0,
		Thresholds:      nil,
	}
	_, warnings, err := ar.ParseAndValidate()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(warnings) != 0 {
		t.Errorf("disabled config with empty thresholds produced warnings: %v", warnings)
	}
}

// TestAutoRevoke_AllAutoRevokeSignalsAccepted is a drift guard: every
// signal added to counters.AutoRevokeSignals must also be accepted by
// the config loader. This catches the scenario where someone adds a
// new misbehavior signal in the counters package but forgets to update
// the docs — the loader already accepts it (data-driven), and this
// test locks that contract in.
func TestAutoRevoke_AllAutoRevokeSignalsAccepted(t *testing.T) {
	thresholds := make(map[string]string, len(counters.AutoRevokeSignals))
	for _, sig := range counters.AutoRevokeSignals {
		thresholds[sig] = "3:60"
	}
	ar := AutoRevokeSection{
		Enabled:         true,
		PruneAfterHours: 168,
		Thresholds:      thresholds,
	}
	rules, _, err := ar.ParseAndValidate()
	if err != nil {
		t.Fatalf("all AutoRevokeSignals should be accepted: %v", err)
	}
	if len(rules) != len(counters.AutoRevokeSignals) {
		t.Errorf("parsed %d rules, want %d (one per signal)",
			len(rules), len(counters.AutoRevokeSignals))
	}
}

// TestLoadServerConfig_RejectsInvalidAutoRevoke verifies the
// LoadServerConfig → Validate wiring actually returns the error.
// Without this, a broken [server.auto_revoke] block would silently
// pass startup — the Validate call could be accidentally removed and
// the package-level tests above would still pass.
func TestLoadServerConfig_RejectsInvalidAutoRevoke(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "server.toml"), []byte(`
[server]
port = 2222

[server.auto_revoke]
enabled = true

[server.auto_revoke.thresholds]
malfromed_frame = "3:60"
`), 0644)

	_, err := Load(dir)
	if err == nil {
		t.Fatal("Load accepted invalid auto_revoke config, want error")
	}
	if !strings.Contains(err.Error(), "validate server.toml") {
		t.Errorf("error = %q, want to mention 'validate server.toml'", err.Error())
	}
}

// TestLoadServerConfig_DefaultAutoRevokeAcceptable verifies that a
// minimal server.toml (no [server.auto_revoke] block) loads cleanly
// with default Enabled=true + empty thresholds. This generates a
// startup warning via slog but does NOT return an error — breaker is
// on but has no triggers, which the operator will see in their logs.
func TestLoadServerConfig_DefaultAutoRevokeAcceptable(t *testing.T) {
	dir := writeMinimalConfig(t)
	cfg, err := Load(dir)
	if err != nil {
		t.Fatalf("minimal config with default AutoRevoke should load: %v", err)
	}
	// Verify the defaults made it through (no TOML override).
	ar := cfg.Server.Server.AutoRevoke
	if !ar.Enabled {
		t.Error("default Enabled should survive minimal load")
	}
	if ar.PruneAfterHours != 168 {
		t.Errorf("default PruneAfterHours = %d, want 168", ar.PruneAfterHours)
	}
}
