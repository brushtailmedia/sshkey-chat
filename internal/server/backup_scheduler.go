package server

// Phase 19 Step 5 — backup scheduler goroutine + retention + concurrent-
// backup mutex + failure-counter sidecar.
//
// The scheduler runs alongside the 7 Phase 16 Gap 1 processors. It ticks
// at the configured `[backup].interval` (default 24h) and invokes
// internal/backup.Run with options derived from the [backup] config
// section. After each successful backup, retention prunes old tarballs
// per the count + age caps (OR semantics — a tarball is deleted if it
// exceeds EITHER cap; this matches operator expectations from every
// other retention system).
//
// Concurrency model:
//   - In-process scheduler vs. CLI manual backup: backupMu (TryLock —
//     loser skips with a log line, not blocking the tick).
//   - Cross-process contention (server scheduler vs. sshkey-ctl in
//     another shell): not protected. Harmless in practice — different
//     timestamps mean no filename collision, SQLite Online Backup
//     tolerates concurrent readers.
//
// State persistence:
//   - skip_if_idle baseline (PRAGMA data_version + files_dir mtime):
//     in-memory only. Reset on Server start so the first tick after
//     restart always runs.
//   - Failure counter: persisted to <dataDir>/.backup-stats.json so
//     `sshkey-ctl status` (separate process) can read it.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/brushtailmedia/sshkey-chat/internal/backup"
	"github.com/brushtailmedia/sshkey-chat/internal/config"
)

// backupStartupGracePeriod is how long after Server.Run starts the
// scheduler waits before its first backup attempt. Production default
// 60s — gives the server time to settle (process startup, signal-
// handler attach, accepting first connections). Tests override via
// SetBackupStartupGracePeriod to avoid 60s pauses.
var backupStartupGracePeriod = 60 * time.Second

// SetBackupStartupGracePeriod overrides the default 60s startup grace
// period. Test-only — production code never calls this. Returns the
// previous value so tests can restore it via t.Cleanup.
func SetBackupStartupGracePeriod(d time.Duration) time.Duration {
	prev := backupStartupGracePeriod
	backupStartupGracePeriod = d
	return prev
}

// backupStatsFile is the sidecar JSON file under dataDir that tracks
// backup outcomes for cross-process consumption (sshkey-ctl status).
// Updated after every scheduler attempt; absent file → all zeros.
const backupStatsFile = ".backup-stats.json"

// backupStats is the persisted record of scheduler outcomes. Read by
// sshkey-ctl status; written by the scheduler after each attempt.
type backupStats struct {
	FailuresTotal   int64 `json:"failures_total"`
	SuccessesTotal  int64 `json:"successes_total"`
	LastSuccessUnix int64 `json:"last_success_unix,omitempty"`
	LastFailureUnix int64 `json:"last_failure_unix,omitempty"`
	LastErrorMsg    string `json:"last_error_msg,omitempty"`
}

// runBackupScheduler is the goroutine entry point. Started by
// ListenAndServe. Sleeps for the startup grace period, runs an
// immediate backup, then enters a ticker loop on the configured
// interval.
//
// Interval changes via SIGHUP reload do NOT affect the running
// ticker — operators change interval via server restart. This
// matches every other Phase 16 processor (their poll intervals
// are constants in code).
func (s *Server) runBackupScheduler() {
	parsed, _, err := s.cfg.Server.Backup.ParseAndValidate()
	if err != nil {
		s.logger.Error("backup scheduler not started — config invalid",
			"error", err)
		return
	}
	if !parsed.Enabled {
		s.logger.Info("backup scheduler not started — [backup].enabled = false")
		return
	}
	if parsed.Interval <= 0 {
		s.logger.Error("backup scheduler not started — interval is zero",
			"interval", parsed.Interval)
		return
	}

	s.logger.Info("backup scheduler starting",
		"interval", parsed.Interval,
		"grace_period", backupStartupGracePeriod)

	// Startup grace.
	select {
	case <-time.After(backupStartupGracePeriod):
	case <-s.backupSchedulerStop:
		return
	}

	// Immediate first backup (post-grace).
	s.tryScheduledBackup()

	ticker := time.NewTicker(parsed.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			s.tryScheduledBackup()
		case <-s.backupSchedulerStop:
			return
		}
	}
}

// tryScheduledBackup is one scheduler tick. Acquires backupMu via
// TryLock — losing contention skips this tick (a manual CLI backup
// or a still-running prior tick has the lock). On success, applies
// retention to dest_dir and updates the skip-if-idle baseline.
func (s *Server) tryScheduledBackup() {
	if !s.backupMu.TryLock() {
		s.logger.Info("backup tick skipped — another backup in progress")
		return
	}
	defer s.backupMu.Unlock()

	parsed, _, err := s.cfg.Server.Backup.ParseAndValidate()
	if err != nil {
		s.logger.Error("backup config invalid at tick", "error", err)
		s.recordBackupFailure(fmt.Errorf("config: %w", err))
		return
	}
	if !parsed.Enabled {
		// enabled flipped to false via SIGHUP reload.
		return
	}

	if parsed.SkipIfIdle && s.backupSkipState.checkSkip(s.dataDir) {
		s.logger.Info("backup tick skipped — no activity since last backup")
		return
	}

	destDir := resolveBackupDestDir(parsed.DestDir, s.dataDir)

	configDir := s.cfg.Dir
	res, err := backup.Run(context.Background(), backup.Options{
		DataDir:            s.dataDir,
		ConfigDir:          configDir,
		DestDir:            destDir,
		Compress:           parsed.Compress,
		IncludeConfigFiles: parsed.IncludeConfigFiles,
	})
	if err != nil {
		s.logger.Error("scheduled backup failed", "error", err)
		s.recordBackupFailure(err)
		return
	}
	s.logger.Info("scheduled backup complete",
		"path", res.Path,
		"bytes", res.Bytes,
		"duration", res.Duration,
		"core_dbs", res.CoreDBs,
		"context_dbs", res.ContextDBs,
		"attachments", res.Attachments,
		"aux_files", res.AuxFiles)
	s.recordBackupSuccess()
	s.backupSkipState.recordPostBackup(s.dataDir)

	if err := applyRetention(destDir, parsed); err != nil {
		// Retention failure is logged but not counted as a backup
		// failure — the backup itself succeeded.
		s.logger.Warn("backup retention failed", "dest_dir", destDir, "error", err)
	}
}

// resolveBackupDestDir applies the same precedence the CLI uses:
// explicit absolute path → absolute; relative → resolved against
// dataDir. Empty falls through to "backups" relative to dataDir.
func resolveBackupDestDir(configDestDir, dataDir string) string {
	d := configDestDir
	if d == "" {
		d = "backups"
	}
	if !filepath.IsAbs(d) {
		d = filepath.Join(dataDir, d)
	}
	return d
}

// recordBackupSuccess increments the persisted success counter.
func (s *Server) recordBackupSuccess() {
	stats := s.readBackupStats()
	stats.SuccessesTotal++
	stats.LastSuccessUnix = time.Now().Unix()
	s.writeBackupStats(stats)
}

// recordBackupFailure increments the persisted failure counter and
// stores the most recent error message.
func (s *Server) recordBackupFailure(err error) {
	stats := s.readBackupStats()
	stats.FailuresTotal++
	stats.LastFailureUnix = time.Now().Unix()
	stats.LastErrorMsg = truncateErr(err.Error(), 256)
	s.writeBackupStats(stats)
}

// readBackupStats reads the sidecar file. Missing file or parse
// error returns zero-valued stats (the file is best-effort).
func (s *Server) readBackupStats() backupStats {
	if s.dataDir == "" {
		return backupStats{}
	}
	data, err := os.ReadFile(filepath.Join(s.dataDir, backupStatsFile))
	if err != nil {
		return backupStats{}
	}
	var stats backupStats
	if err := json.Unmarshal(data, &stats); err != nil {
		s.logger.Warn("backup stats file unparseable; resetting", "error", err)
		return backupStats{}
	}
	return stats
}

// writeBackupStats persists the stats sidecar. Best-effort — write
// failures log a warning but don't propagate (the scheduler must
// keep running even if the stats file becomes unwritable).
func (s *Server) writeBackupStats(stats backupStats) {
	if s.dataDir == "" {
		return
	}
	data, err := json.Marshal(stats)
	if err != nil {
		s.logger.Warn("marshal backup stats", "error", err)
		return
	}
	path := filepath.Join(s.dataDir, backupStatsFile)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		s.logger.Warn("write backup stats", "error", err)
		return
	}
	if err := os.Rename(tmp, path); err != nil {
		s.logger.Warn("rename backup stats", "error", err)
		_ = os.Remove(tmp)
	}
}

// truncateErr clips an error string to maxLen runes for the
// last_error_msg field. Long stack traces in error messages would
// bloat the sidecar file unnecessarily.
func truncateErr(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

// applyRetention prunes tarballs in destDir per the parsed retention
// rules. OR semantics: a tarball is deleted if it exceeds either the
// count cap or the age cap. Matches operator intuition (each cap is
// a hard upper bound).
//
// Filename matching: only files whose basename matches "backup-*.tar.gz"
// are considered. Other files in dest_dir (operator-placed archives,
// the sidecar stats file, etc.) are ignored.
func applyRetention(destDir string, cfg config.ParsedBackupConfig) error {
	entries, err := os.ReadDir(destDir)
	if err != nil {
		return fmt.Errorf("read dest_dir: %w", err)
	}

	type tarballInfo struct {
		path string
		mtime time.Time
	}
	var tarballs []tarballInfo
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if !isBackupTarball(e.Name()) {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		tarballs = append(tarballs, tarballInfo{
			path:  filepath.Join(destDir, e.Name()),
			mtime: info.ModTime(),
		})
	}

	// Newest first.
	sort.Slice(tarballs, func(i, j int) bool {
		return tarballs[i].mtime.After(tarballs[j].mtime)
	})

	now := time.Now()
	var firstErr error
	for i, tb := range tarballs {
		// Beyond count cap?
		beyondCount := cfg.RetentionCount > 0 && i >= cfg.RetentionCount
		// Older than age cap?
		olderThanAge := cfg.RetentionAge > 0 && now.Sub(tb.mtime) > cfg.RetentionAge
		if !beyondCount && !olderThanAge {
			continue
		}
		if err := os.Remove(tb.path); err != nil {
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}

// isBackupTarball returns true if name matches the scheduler's
// filename convention. Defensive guard against pruning operator-
// placed unrelated files.
func isBackupTarball(name string) bool {
	return strings.HasPrefix(name, "backup-") && strings.HasSuffix(name, ".tar.gz")
}

// -------- skip-if-idle implementation --------

// checkSkip returns true if the scheduler should skip the tick:
// (PRAGMA data_version unchanged) AND (data/files/ max mtime
// unchanged) since the last successful backup. On first call (no
// baseline) it always returns false — the first backup must run.
func (st *backupSkipState) checkSkip(dataDir string) bool {
	st.mu.Lock()
	defer st.mu.Unlock()
	if !st.initialized {
		return false
	}
	curVer, _ := readDataVersion(dataDir)
	curMtime, _ := scanFilesMtime(dataDir)
	if curVer != st.lastDataVersion {
		return false
	}
	if !curMtime.Equal(st.lastFilesMtime) {
		return false
	}
	return true
}

// recordPostBackup captures the current data_version + files_dir
// mtime as the new baseline for skip_if_idle comparisons.
func (st *backupSkipState) recordPostBackup(dataDir string) {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.lastDataVersion, _ = readDataVersion(dataDir)
	st.lastFilesMtime, _ = scanFilesMtime(dataDir)
	st.initialized = true
}

// readDataVersion runs `PRAGMA data_version` against data.db and
// returns the integer. SQLite increments this on every commit,
// providing a cheap "has anything changed?" probe. Returns 0 on
// open or query failure (treats as "version unknown" → tick runs).
func readDataVersion(dataDir string) (int64, error) {
	path := filepath.Join(dataDir, "data", "data.db")
	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, nil
		}
		return 0, err
	}
	db, err := sql.Open("sqlite", path+"?mode=ro")
	if err != nil {
		return 0, err
	}
	defer db.Close()
	var v int64
	if err := db.QueryRow("PRAGMA data_version").Scan(&v); err != nil {
		return 0, err
	}
	return v, nil
}

// scanFilesMtime returns the max mtime across data/files/ entries.
// Used as a second skip-if-idle signal — attachment uploads create
// new files in this directory, which data_version on data.db doesn't
// catch (file_hashes is written but the data_version increment
// happens too — actually it WOULD catch attachment activity. The
// mtime scan is a defense-in-depth signal, not a primary one).
//
// Returns zero-valued time.Time on missing dir or empty dir.
func scanFilesMtime(dataDir string) (time.Time, error) {
	dir := filepath.Join(dataDir, "data", "files")
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return time.Time{}, nil
		}
		return time.Time{}, err
	}
	var maxMtime time.Time
	for _, e := range entries {
		info, err := e.Info()
		if err != nil {
			continue
		}
		if info.ModTime().After(maxMtime) {
			maxMtime = info.ModTime()
		}
	}
	return maxMtime, nil
}

// ReadBackupStatsForCLI is exposed so cmd/sshkey-ctl can read the
// scheduler's persisted stats from a separate process. Returns
// zero-valued stats if the file is absent or unreadable (operator
// just sees zeros, not an error).
func ReadBackupStatsForCLI(dataDir string) (failures, successes int64, lastSuccess, lastFailure time.Time, lastErrMsg string) {
	if dataDir == "" {
		return
	}
	data, err := os.ReadFile(filepath.Join(dataDir, backupStatsFile))
	if err != nil {
		return
	}
	var stats backupStats
	if err := json.Unmarshal(data, &stats); err != nil {
		return
	}
	failures = stats.FailuresTotal
	successes = stats.SuccessesTotal
	if stats.LastSuccessUnix > 0 {
		lastSuccess = time.Unix(stats.LastSuccessUnix, 0)
	}
	if stats.LastFailureUnix > 0 {
		lastFailure = time.Unix(stats.LastFailureUnix, 0)
	}
	lastErrMsg = stats.LastErrorMsg
	return
}

// BackupFailuresTotal is a test-only accessor that reads the in-process
// counter via the persisted file. atomic.Int64 isn't used because the
// stats are read/written under no concurrent contention — only the
// scheduler goroutine writes, and at most every interval.
//
// Production code uses ReadBackupStatsForCLI; this is just a brief
// alias for tests that only care about the counter.
func (s *Server) BackupFailuresTotal() int64 {
	stats := s.readBackupStats()
	return stats.FailuresTotal
}

// BackupSuccessesTotal mirrors BackupFailuresTotal for the success
// counter. Test-only.
func (s *Server) BackupSuccessesTotal() int64 {
	stats := s.readBackupStats()
	return stats.SuccessesTotal
}
