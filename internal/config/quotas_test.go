package config

// Per-user upload quota config tests.
// Out-of-phase 2026-04-19, originally Phase 25.
//
// Default-on revision: tests pivot from "section presence detection"
// (the original opt-in design) to explicit `Enabled bool` gating
// (revised same day after consistency review against Phase 17b
// auto-revoke + Phase 19 backups, both default-on).

import (
	"strings"
	"testing"
)

// -------- Enabled gate --------

func TestUserQuota_ZeroValueIsDisabled(t *testing.T) {
	// Bare struct (Enabled = false zero value) → disabled, no
	// validation runs. This is the path an operator hits if they
	// explicitly set `enabled = false` in server.toml; it's also
	// the path a unit test hits when constructing the section
	// directly without setting Enabled.
	var q UserQuotaSection
	parsed, err := q.ParseAndValidate()
	if err != nil {
		t.Fatalf("disabled section should not error, got: %v", err)
	}
	if parsed.Enabled {
		t.Error("Enabled=false should yield parsed.Enabled=false")
	}
	if parsed.WarnBytes != 0 || parsed.BlockBytes != 0 {
		t.Errorf("disabled section should yield zero parsed values, got warn=%d block=%d",
			parsed.WarnBytes, parsed.BlockBytes)
	}
}

func TestUserQuota_ExplicitDisableShortCircuitsValidation(t *testing.T) {
	// Even with garbage in the size fields, Enabled=false MUST
	// short-circuit validation — operator opt-out is a clean
	// single-flag escape hatch, not a "now go fix all the other
	// fields too" trap.
	q := UserQuotaSection{
		Enabled:               false,
		DailyUploadBytesWarn:  "not-a-size",
		DailyUploadBytesBlock: "also-garbage",
		FlagConsecutiveDays:   -99,
		RetentionDays:         -1,
	}
	parsed, err := q.ParseAndValidate()
	if err != nil {
		t.Fatalf("Enabled=false should not validate other fields, got: %v", err)
	}
	if parsed.Enabled {
		t.Error("Enabled=false should yield parsed.Enabled=false")
	}
}

// -------- Defaults (Enabled=true with empty/zero fields) --------

func TestUserQuota_EnabledMinimalUsesDefaults(t *testing.T) {
	// `enabled = true` with no other fields populated: defaults
	// kick in defensively (1GB warn / 5GB block / 2 days /
	// 30 days retention). DefaultServerConfig pre-populates these
	// in production; the defensive defaulting in ParseAndValidate
	// keeps direct-construction unit tests valid.
	q := UserQuotaSection{Enabled: true}
	parsed, err := q.ParseAndValidate()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !parsed.Enabled {
		t.Fatal("Enabled=true should yield parsed.Enabled=true")
	}
	if parsed.WarnBytes != 1<<30 {
		t.Errorf("default WarnBytes = %d, want 1GB (%d)", parsed.WarnBytes, 1<<30)
	}
	if parsed.BlockBytes != 5*1<<30 {
		t.Errorf("default BlockBytes = %d, want 5GB (%d)", parsed.BlockBytes, 5*1<<30)
	}
	if parsed.FlagConsecutiveDays != 2 {
		t.Errorf("default FlagConsecutiveDays = %d, want 2", parsed.FlagConsecutiveDays)
	}
	if parsed.RetentionDays != 30 {
		t.Errorf("default RetentionDays = %d, want 30", parsed.RetentionDays)
	}
}

func TestUserQuota_FullConfigRoundTrips(t *testing.T) {
	q := UserQuotaSection{
		Enabled:               true,
		DailyUploadBytesWarn:  "500MB",
		DailyUploadBytesBlock: "2GB",
		FlagConsecutiveDays:   3,
		RetentionDays:         60,
	}
	parsed, err := q.ParseAndValidate()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !parsed.Enabled {
		t.Fatal("expected enabled")
	}
	if parsed.WarnBytes != 500*1<<20 {
		t.Errorf("WarnBytes = %d, want 500MB (%d)", parsed.WarnBytes, 500*1<<20)
	}
	if parsed.BlockBytes != 2*1<<30 {
		t.Errorf("BlockBytes = %d, want 2GB", parsed.BlockBytes)
	}
	if parsed.FlagConsecutiveDays != 3 || parsed.RetentionDays != 60 {
		t.Errorf("days fields wrong: flag=%d ret=%d", parsed.FlagConsecutiveDays, parsed.RetentionDays)
	}
}

func TestUserQuota_PartialOverrideInheritsDefaults(t *testing.T) {
	// Operator overrides only warn — the rest fall back to
	// defaults. (DefaultServerConfig also covers this, but
	// validate the in-method defaulting too because tests and
	// callers that construct UserQuotaSection directly need it.)
	q := UserQuotaSection{
		Enabled:              true,
		DailyUploadBytesWarn: "2GB",
	}
	parsed, err := q.ParseAndValidate()
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if !parsed.Enabled {
		t.Error("Enabled=true should yield parsed.Enabled=true")
	}
	if parsed.WarnBytes != 2*1<<30 {
		t.Errorf("WarnBytes = %d, want 2GB", parsed.WarnBytes)
	}
	// BlockBytes default = 5GB, larger than 2GB → valid
	if parsed.BlockBytes != 5*1<<30 {
		t.Errorf("BlockBytes = %d, want default 5GB", parsed.BlockBytes)
	}
}

func TestUserQuota_WhitespaceFieldsTreatedAsEmpty(t *testing.T) {
	// All-whitespace size strings should be treated like empty
	// strings (defaults apply). This is the common "operator
	// typed a stray space" path; it should not break the config
	// when the section is enabled.
	q := UserQuotaSection{
		Enabled:               true,
		DailyUploadBytesWarn:  "   ",
		DailyUploadBytesBlock: "\t",
	}
	parsed, err := q.ParseAndValidate()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !parsed.Enabled {
		t.Fatal("Enabled=true should yield parsed.Enabled=true")
	}
	if parsed.WarnBytes != 1<<30 {
		t.Errorf("whitespace warn should default to 1GB, got %d", parsed.WarnBytes)
	}
	if parsed.BlockBytes != 5*1<<30 {
		t.Errorf("whitespace block should default to 5GB, got %d", parsed.BlockBytes)
	}
}

// -------- Validation rejection paths (Enabled=true) --------

func TestUserQuota_RejectsBadInput(t *testing.T) {
	cases := []struct {
		name    string
		section UserQuotaSection
		wantSub string
	}{
		{
			name: "warn unparseable",
			section: UserQuotaSection{
				Enabled:               true,
				DailyUploadBytesWarn:  "not-a-size",
				DailyUploadBytesBlock: "5GB",
			},
			wantSub: "daily_upload_bytes_warn",
		},
		{
			name: "block unparseable",
			section: UserQuotaSection{
				Enabled:               true,
				DailyUploadBytesWarn:  "1GB",
				DailyUploadBytesBlock: "huge",
			},
			wantSub: "daily_upload_bytes_block",
		},
		{
			name: "block <= warn",
			section: UserQuotaSection{
				Enabled:               true,
				DailyUploadBytesWarn:  "5GB",
				DailyUploadBytesBlock: "1GB",
			},
			wantSub: "must be greater than",
		},
		{
			name: "block == warn",
			section: UserQuotaSection{
				Enabled:               true,
				DailyUploadBytesWarn:  "1GB",
				DailyUploadBytesBlock: "1GB",
			},
			wantSub: "must be greater than",
		},
		{
			name: "zero warn rejected",
			section: UserQuotaSection{
				Enabled:               true,
				DailyUploadBytesWarn:  "0",
				DailyUploadBytesBlock: "5GB",
			},
			wantSub: "must be > 0",
		},
		{
			name: "negative flag_consecutive_days rejected",
			section: UserQuotaSection{
				Enabled:               true,
				DailyUploadBytesWarn:  "1GB",
				DailyUploadBytesBlock: "5GB",
				// FlagConsecutiveDays = 0 → defaults to 2; not a rejection.
				// To force the < 1 rejection we need a negative value.
				FlagConsecutiveDays: -1,
			},
			wantSub: "flag_consecutive_days",
		},
		{
			name: "retention < flag_consecutive_days",
			section: UserQuotaSection{
				Enabled:               true,
				DailyUploadBytesWarn:  "1GB",
				DailyUploadBytesBlock: "5GB",
				FlagConsecutiveDays:   7,
				RetentionDays:         5,
			},
			wantSub: "must be >= flag_consecutive_days",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.section.ParseAndValidate()
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantSub)
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Errorf("error = %q, want substring %q", err.Error(), tc.wantSub)
			}
		})
	}
}

// -------- ServerConfig.Validate wires the quota validation --------

func TestUserQuota_DefaultServerConfigIsValid(t *testing.T) {
	// Default-on means DefaultServerConfig must produce a config
	// that round-trips through Validate() cleanly with quotas
	// enabled (1GB warn / 5GB block / 30-day retention). If this
	// test breaks, the defaults in DefaultServerConfig and the
	// validation rules in ParseAndValidate have drifted apart.
	cfg := DefaultServerConfig()
	if !cfg.Server.Quotas.User.Enabled {
		t.Fatal("DefaultServerConfig should produce Quotas.User.Enabled=true")
	}
	if cfg.Server.Quotas.User.AllowExemptUsers {
		t.Error("DefaultServerConfig should produce Quotas.User.AllowExemptUsers=false (admin-managed-by-default)")
	}
	if _, err := cfg.Validate(); err != nil {
		t.Fatalf("default config should validate, got: %v", err)
	}
	// Confirm the parsed defaults match the documented values.
	parsed, err := cfg.Server.Quotas.User.ParseAndValidate()
	if err != nil {
		t.Fatalf("default Quotas.User should parse cleanly, got: %v", err)
	}
	if parsed.AllowExemptUsers {
		t.Error("default ParsedUserQuota.AllowExemptUsers should be false")
	}
	if parsed.WarnBytes != 1<<30 {
		t.Errorf("default WarnBytes = %d, want 1GB", parsed.WarnBytes)
	}
	if parsed.BlockBytes != 5*1<<30 {
		t.Errorf("default BlockBytes = %d, want 5GB", parsed.BlockBytes)
	}
	if parsed.FlagConsecutiveDays != 2 {
		t.Errorf("default FlagConsecutiveDays = %d, want 2", parsed.FlagConsecutiveDays)
	}
	if parsed.RetentionDays != 30 {
		t.Errorf("default RetentionDays = %d, want 30", parsed.RetentionDays)
	}
}

// -------- AllowExemptUsers gate --------

func TestUserQuota_AllowExemptUsersPropagates(t *testing.T) {
	// Setting AllowExemptUsers=true on the section must propagate
	// into ParsedUserQuota — the runtime helper isQuotaExempt
	// reads from the parsed form, so a propagation gap would mean
	// the operator's `allow_exempt_users = true` is silently
	// ignored.
	cases := []struct {
		name string
		in   bool
	}{
		{"explicit true propagates", true},
		{"explicit false propagates", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			q := UserQuotaSection{
				Enabled:          true,
				AllowExemptUsers: tc.in,
			}
			parsed, err := q.ParseAndValidate()
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if parsed.AllowExemptUsers != tc.in {
				t.Errorf("AllowExemptUsers = %v, want %v", parsed.AllowExemptUsers, tc.in)
			}
		})
	}
}

func TestUserQuota_AllowExemptUsersZeroWhenDisabled(t *testing.T) {
	// When Enabled=false, ParseAndValidate short-circuits and
	// returns the zero ParsedUserQuota — AllowExemptUsers is
	// false regardless of the input. This matches the broader
	// "disabled means zero" contract: a disabled quota config
	// can't sneak an exempt-allowance through.
	q := UserQuotaSection{
		Enabled:          false,
		AllowExemptUsers: true, // ignored because Enabled=false
	}
	parsed, err := q.ParseAndValidate()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if parsed.Enabled {
		t.Fatal("Enabled=false should yield parsed.Enabled=false")
	}
	if parsed.AllowExemptUsers {
		t.Error("Enabled=false should yield parsed.AllowExemptUsers=false (zero value)")
	}
}

func TestUserQuota_WiredIntoServerConfigValidate(t *testing.T) {
	cfg := DefaultServerConfig()
	// Inject a bad quota config — Validate must propagate the error.
	cfg.Server.Quotas.User.DailyUploadBytesWarn = "5GB"
	cfg.Server.Quotas.User.DailyUploadBytesBlock = "1GB" // reversed
	_, err := cfg.Validate()
	if err == nil {
		t.Fatal("expected Validate to propagate quota error, got nil")
	}
	if !strings.Contains(err.Error(), "quota") {
		t.Errorf("error should mention quota, got: %q", err.Error())
	}
}

func TestUserQuota_ExplicitDisableInServerConfigValidates(t *testing.T) {
	// Operator opt-out path: explicit `enabled = false`. Should
	// validate cleanly even if other fields are garbage (mirror
	// of TestUserQuota_ExplicitDisableShortCircuitsValidation but
	// at the full-config level).
	cfg := DefaultServerConfig()
	cfg.Server.Quotas.User = UserQuotaSection{Enabled: false}
	if _, err := cfg.Validate(); err != nil {
		t.Errorf("explicit opt-out should validate cleanly, got: %v", err)
	}
}
