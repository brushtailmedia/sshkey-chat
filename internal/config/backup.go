package config

// Phase 19 Step 1 — [backup] config section.
//
// Schema (see refactor_plan.md §Phase 19):
//
//   [backup]
//   enabled = true
//   interval = "24h"
//   dest_dir = "backups"
//   retention_count = 10
//   retention_age = "720h"
//   compress = true
//   skip_if_idle = true
//   include_config_files = true
//
// Default-on: data loss on a chat server is catastrophic, and
// skip_if_idle prevents noise on unused deployments. Operators who
// want to opt out set enabled = false — a conscious config edit
// rather than a silent omission.
//
// ParseAndValidate is the enforcement chokepoint. It is called from
// ServerConfig.Validate() (see config.go), which LoadServerConfig
// invokes right after TOML decode. Invalid config fails startup with
// a clear error (bad duration strings, negative counts, dest_dir
// path-traversal).

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"
)

// BackupSection configures Phase 19 backup/restore. Top-level [backup]
// in server.toml (not nested under [server], so operators who want to
// tune backup without touching [server] knobs can do so cleanly).
type BackupSection struct {
	// Enabled gates the scheduled backup goroutine. When false, the
	// scheduler doesn't run — but `sshkey-ctl backup` still works
	// (manual backups are always available regardless of this flag).
	// Default true.
	Enabled bool `toml:"enabled"`

	// Interval is the cadence between scheduled backups. Parsed as a
	// Go duration string. Must be > 0 when Enabled. Default "24h".
	Interval string `toml:"interval"`

	// DestDir is where tarballs land. Relative paths resolve against
	// the server's dataDir; absolute paths used as-is. Default
	// "backups" (relative → <dataDir>/backups/). Must not contain
	// path-traversal segments (.. components).
	DestDir string `toml:"dest_dir"`

	// RetentionCount caps the number of backup tarballs kept. After
	// each successful backup, older tarballs beyond this count are
	// deleted from DestDir. 0 disables count-based retention (keep
	// unlimited). Default 10.
	RetentionCount int `toml:"retention_count"`

	// RetentionAge deletes backup tarballs older than this duration.
	// Empty string disables age-based retention. Parsed as a Go
	// duration. Default "720h" (30 days).
	RetentionAge string `toml:"retention_age"`

	// Compress gzip-compresses the tarball. Default true — backup
	// contents are mostly compressible (SQLite pages with some
	// structure, plaintext logs, TOML). Attachment blobs are already
	// encrypted so they compress poorly, but the DB+logs gains are
	// usually worth the CPU cost.
	Compress bool `toml:"compress"`

	// SkipIfIdle skips the scheduled tick if no write activity has
	// occurred since the last successful backup. Detection: PRAGMA
	// data_version on data.db + max mtime of <dataDir>/data/files/.
	// Both must show no change since the last backup for the skip to
	// fire. Default true — saves disk on unused test/dev deployments.
	SkipIfIdle bool `toml:"skip_if_idle"`

	// IncludeConfigFiles bundles server.toml and host_key into the
	// tarball alongside the DBs. Default true — operators who manage
	// config via external systems (git, ansible) can opt out to avoid
	// duplicate sources of truth. host_key is ALWAYS included when
	// IncludeConfigFiles is true because restore-to-new-machine
	// without it breaks every client's SSH pinning. rooms.toml is
	// never included (seed file, ignored when rooms.db exists).
	IncludeConfigFiles bool `toml:"include_config_files"`
}

// ParsedBackupConfig is the validated, structured form of BackupSection.
// The scheduler and CLI consume this — not the raw BackupSection — so
// duration parsing and path resolution happen exactly once, at startup.
type ParsedBackupConfig struct {
	Enabled            bool
	Interval           time.Duration
	DestDir            string        // cleaned; still relative if operator specified relative (caller resolves against dataDir)
	RetentionCount     int
	RetentionAge       time.Duration // 0 = no age cutoff
	Compress           bool
	SkipIfIdle         bool
	IncludeConfigFiles bool
}

// ParseAndValidate walks the BackupSection, validates each field, and
// returns the parsed structured form alongside any non-fatal startup
// warnings. Errors are hard failures — they abort server startup.
//
// Validation rules:
//   - Interval must parse as a Go duration and be > 0 (when Enabled).
//   - RetentionCount must be >= 0.
//   - RetentionAge is empty (disabled) or parses as a Go duration > 0.
//   - DestDir must not contain ".." path-traversal segments after
//     filepath.Clean. Absolute paths OK; relative paths OK (caller
//     resolves against dataDir).
//
// When Enabled is false, most fields are not checked (they're inert).
// Interval and RetentionAge ARE still parsed when provided so a
// partial-typed config doesn't silently carry invalid values the
// operator will trip over when they enable the feature later.
func (b BackupSection) ParseAndValidate() (ParsedBackupConfig, []string, error) {
	var warnings []string
	parsed := ParsedBackupConfig{
		Enabled:            b.Enabled,
		RetentionCount:     b.RetentionCount,
		Compress:           b.Compress,
		SkipIfIdle:         b.SkipIfIdle,
		IncludeConfigFiles: b.IncludeConfigFiles,
	}

	// Interval — always parse if provided (catches typos early).
	if strings.TrimSpace(b.Interval) != "" {
		d, err := time.ParseDuration(b.Interval)
		if err != nil {
			return parsed, nil, fmt.Errorf("[backup] interval=%q: %w", b.Interval, err)
		}
		if d <= 0 {
			return parsed, nil, fmt.Errorf("[backup] interval=%q: must be > 0", b.Interval)
		}
		parsed.Interval = d
	} else if b.Enabled {
		return parsed, nil, fmt.Errorf("[backup] interval is required when enabled = true")
	}

	// RetentionCount — negative is always an error.
	if b.RetentionCount < 0 {
		return parsed, nil, fmt.Errorf("[backup] retention_count=%d: must be >= 0 (0 disables count-based retention)", b.RetentionCount)
	}

	// RetentionAge — empty disables; otherwise must parse as Go duration > 0.
	if strings.TrimSpace(b.RetentionAge) != "" {
		d, err := time.ParseDuration(b.RetentionAge)
		if err != nil {
			return parsed, nil, fmt.Errorf("[backup] retention_age=%q: %w", b.RetentionAge, err)
		}
		if d <= 0 {
			return parsed, nil, fmt.Errorf("[backup] retention_age=%q: must be > 0 (empty string disables age-based retention)", b.RetentionAge)
		}
		parsed.RetentionAge = d
	}

	// DestDir — reject path-traversal. Clean first, then check for
	// ".." segments. Empty is fine (caller applies default "backups").
	destClean := filepath.Clean(strings.TrimSpace(b.DestDir))
	if destClean == "." || destClean == "" {
		parsed.DestDir = ""
	} else {
		// Check every segment after Clean — Clean reduces "a/../b" to
		// "b" but "../a" stays as "../a", and "a/.." stays as ".".
		// We reject any residual ".." to prevent dest_dir escaping
		// dataDir when resolved relatively.
		if strings.HasPrefix(destClean, "..") || strings.Contains(destClean, string(filepath.Separator)+"..") {
			return parsed, nil, fmt.Errorf("[backup] dest_dir=%q: path-traversal segments not allowed", b.DestDir)
		}
		parsed.DestDir = destClean
	}

	// Soft check: retention fully disabled is unusual and worth
	// flagging. Operators can silence by setting either retention
	// knob explicitly — this fires only when BOTH are effectively off.
	if parsed.RetentionCount == 0 && parsed.RetentionAge == 0 && b.Enabled {
		warnings = append(warnings,
			"[backup] retention_count=0 and retention_age is disabled — backup tarballs will accumulate without bound")
	}

	// Soft check: interval < 1h on an enabled scheduler. Legal but
	// unusual; worth flagging since most deployments want daily.
	if b.Enabled && parsed.Interval > 0 && parsed.Interval < time.Hour {
		warnings = append(warnings,
			fmt.Sprintf("[backup] interval=%s is shorter than 1h — confirm this is intentional (most deployments use 24h)", parsed.Interval))
	}

	return parsed, warnings, nil
}
