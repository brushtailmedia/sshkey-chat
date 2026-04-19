package config

// Per-user daily upload quotas — design from upload_quota.md, originally
// scheduled as Phase 25, shipped 2026-04-19 as out-of-phase work pre-
// Phase 21 (the original intent dropped between phases 16-17 and got
// retrofitted later).
//
// **Default-on** (revised 2026-04-19 same day after consistency review
// against Phase 17b auto-revoke + Phase 19 backups, both of which ship
// default-on with the same asymmetry-of-harm argument). Operators who
// don't want quotas set `[server.quotas.user] enabled = false`.
//
// Schema:
//
//   [server.quotas.user]
//   enabled                  = true       # default; set false to disable
//   daily_upload_bytes_warn  = "1GB"
//   daily_upload_bytes_block = "5GB"
//   flag_consecutive_days    = 2
//   retention_days           = 30
//
// All fields are defaulted in DefaultServerConfig, so an operator who
// omits the section entirely gets quotas enabled with the defaults.
// To opt out, operator must explicitly add the section with
// enabled = false. Mirrors the Phase 17b + Phase 19 default-on pattern.

import (
	"fmt"
	"strings"
)

// QuotasSection is the top-level [server.quotas] table. Currently only
// [server.quotas.user] is implemented; the namespace is reserved for
// future [server.quotas.room] / [server.quotas.group] / [server.quotas.global]
// caps if the deployment shape ever needs them.
type QuotasSection struct {
	User UserQuotaSection `toml:"user"`
}

// UserQuotaSection bounds per-user daily upload bytes. Layered on top
// of the Phase 17 Step 5 UploadsPerMinute rate limit (which bounds
// bytes/minute) — quotas bound bytes/day, complementary not redundant.
//
// Default-on: DefaultServerConfig populates this with Enabled = true
// and sensible defaults. Operators who don't add the section to their
// server.toml get quotas enforcing at 1GB warn / 5GB block / 30-day
// retention. Opt-out is `enabled = false` (an explicit operator
// decision, not a silent omission).
type UserQuotaSection struct {
	// Enabled gates the whole feature. Default true (set in
	// DefaultServerConfig). When false, no DB reads on the upload
	// path, no admin_notify, no checks, no retention prune. Mirror
	// of Phase 17b auto-revoke + Phase 19 backup pattern.
	Enabled bool `toml:"enabled"`

	// AllowExemptUsers gates the per-user `quota_exempt` escape
	// hatch. Default false (admin-managed by default, mirrors the
	// AllowSelfLeaveRooms = false pattern). When false:
	//   - `sshkey-ctl user quota-exempt <user> --on` is rejected
	//     at the CLI with a pointer to this knob.
	//   - The server runtime ignores `users.quota_exempt = 1` and
	//     enforces the quota on every user, regardless of any
	//     stale exempt flag left in the DB from a prior config.
	// `--off` from the CLI is always allowed so operators can clean
	// up existing exempt flags after flipping this gate to false.
	// Set true only when an operator has a deliberate use case for
	// quota-exempt service accounts / power users.
	AllowExemptUsers bool `toml:"allow_exempt_users"`

	// DailyUploadBytesWarn fires admin_notify (event = "quota_warn")
	// the FIRST time a user crosses this threshold in a given UTC
	// day. Idempotent per-day via the warn_notified flag in the
	// daily_upload_quotas row. Default "1GB".
	DailyUploadBytesWarn string `toml:"daily_upload_bytes_warn"`

	// DailyUploadBytesBlock is the hard cap. An upload that would push
	// the user over this threshold is rejected with the
	// daily_quota_exceeded error code AND fires admin_notify
	// (event = "quota_block"). Default "5GB".
	DailyUploadBytesBlock string `toml:"daily_upload_bytes_block"`

	// FlagConsecutiveDays is N for the "user crossed warn N days in
	// a row" sustained-pattern check. Strict contiguous days. Fires
	// admin_notify (event = "quota_sustained"). Default 2.
	FlagConsecutiveDays int `toml:"flag_consecutive_days"`

	// RetentionDays prunes daily_upload_quotas rows older than this
	// at server startup. Must be >= FlagConsecutiveDays so the
	// consecutive-days check has enough history. Default 30.
	RetentionDays int `toml:"retention_days"`
}

// ParsedUserQuota is the validated, structured form. Server code reads
// this — never the raw section — so size strings parse exactly once
// at startup.
type ParsedUserQuota struct {
	Enabled              bool
	AllowExemptUsers     bool
	WarnBytes            int64
	BlockBytes           int64
	FlagConsecutiveDays  int
	RetentionDays        int
}

// ParseAndValidate parses the size strings and enforces the validation
// rules. Returns Enabled = false + nil error when the section's
// `enabled = false` (explicit opt-out). Defaults from
// DefaultServerConfig fill in any missing fields, so operator-written
// partial configs (e.g., only override warn) inherit defaults for the
// rest.
//
// Validation rules (only enforced when Enabled = true):
//   - DailyUploadBytesBlock > DailyUploadBytesWarn — reversed thresholds = bug
//   - FlagConsecutiveDays >= 1
//   - RetentionDays >= FlagConsecutiveDays — need history for the check
//   - Size strings parse to > 0 — zero rejected to catch typos
func (q UserQuotaSection) ParseAndValidate() (ParsedUserQuota, error) {
	var p ParsedUserQuota
	if !q.Enabled {
		return p, nil // disabled → all zero, no validation
	}

	// Defaults are normally pre-populated by DefaultServerConfig, but
	// be defensive: if a caller constructed a UserQuotaSection
	// directly with Enabled=true and no other fields, fall back to
	// the same defaults here so the validator doesn't reject a
	// minimal-but-valid input.
	warnStr := strings.TrimSpace(q.DailyUploadBytesWarn)
	if warnStr == "" {
		warnStr = "1GB"
	}
	blockStr := strings.TrimSpace(q.DailyUploadBytesBlock)
	if blockStr == "" {
		blockStr = "5GB"
	}
	flagDays := q.FlagConsecutiveDays
	if flagDays == 0 {
		flagDays = 2
	}
	retDays := q.RetentionDays
	if retDays == 0 {
		retDays = 30
	}

	// Parse size strings. ParseSize handles KB/MB/GB suffixes
	// (binary multiplier — consistent with MaxFileSize handling).
	warnBytes, err := ParseSize(warnStr)
	if err != nil {
		return p, fmt.Errorf("[server.quotas.user] daily_upload_bytes_warn=%q: %w", warnStr, err)
	}
	if warnBytes <= 0 {
		return p, fmt.Errorf("[server.quotas.user] daily_upload_bytes_warn=%q: must be > 0 (set enabled = false to disable quotas)", warnStr)
	}
	blockBytes, err := ParseSize(blockStr)
	if err != nil {
		return p, fmt.Errorf("[server.quotas.user] daily_upload_bytes_block=%q: %w", blockStr, err)
	}
	if blockBytes <= 0 {
		return p, fmt.Errorf("[server.quotas.user] daily_upload_bytes_block=%q: must be > 0", blockStr)
	}

	// Cross-field validation.
	if blockBytes <= warnBytes {
		return p, fmt.Errorf("[server.quotas.user] daily_upload_bytes_block (%d) must be greater than daily_upload_bytes_warn (%d)", blockBytes, warnBytes)
	}
	if flagDays < 1 {
		return p, fmt.Errorf("[server.quotas.user] flag_consecutive_days=%d: must be >= 1", flagDays)
	}
	if retDays < flagDays {
		return p, fmt.Errorf("[server.quotas.user] retention_days=%d must be >= flag_consecutive_days=%d (need enough history for the consecutive-days check)", retDays, flagDays)
	}

	p.Enabled = true
	p.AllowExemptUsers = q.AllowExemptUsers
	p.WarnBytes = warnBytes
	p.BlockBytes = blockBytes
	p.FlagConsecutiveDays = flagDays
	p.RetentionDays = retDays
	return p, nil
}
