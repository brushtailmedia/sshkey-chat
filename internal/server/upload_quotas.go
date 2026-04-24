package server

// Per-user daily upload quotas — server-side enforcement helpers.
// Design from upload_quota.md, shipped 2026-04-19 as out-of-phase work
// pre-Phase 21. The originally-planned implementation slipped between
// Phases 16 and 17; this is the retrofit.
//
// Module structure:
//   - quotaEnabled():          one-line cached config check used at every gate
//   - todayUTC():              date-string helper for table keys
//   - isQuotaExempt():         users.quota_exempt early-exit
//   - quotaBlockedMessage():   user-facing error text rendered from the
//                              configured block threshold
//   - notifyAdminsQuotaWarn / quota_sustained / quota_block: admin_notify dispatchers
//   - isSustainedPattern():    pure helper for the consecutive-days check
//   - pruneOldQuotaRows():     startup-time retention prune

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/brushtailmedia/sshkey-chat/internal/config"
	"github.com/brushtailmedia/sshkey-chat/internal/protocol"
	"github.com/brushtailmedia/sshkey-chat/internal/store"
)

// parsedQuota returns the validated [server.quotas.user] struct from
// the live config. Re-parses on every call (cheap — string parses + a
// few comparisons) which means SIGHUP reload picks up changes without
// a server restart. If the operator broke the config mid-flight, this
// returns Enabled=false — quotas silently disable rather than blocking
// uploads. Default-on revision (2026-04-19): DefaultServerConfig
// populates Enabled=true + the documented defaults, so operators who
// omit the section get the validated default-on config; explicit
// `enabled = false` is the opt-out path. Validation already rejected
// bad config at startup; mid-flight breakage is operator error.
func (s *Server) parsedQuota() config.ParsedUserQuota {
	s.cfg.RLock()
	q := s.cfg.Server.Server.Quotas.User
	s.cfg.RUnlock()
	parsed, err := q.ParseAndValidate()
	if err != nil {
		// Should be unreachable: startup validation already rejected
		// bad config. Defensive: log + treat as disabled.
		s.logger.Warn("quota config invalid mid-flight; disabling enforcement", "error", err)
		return config.ParsedUserQuota{}
	}
	return parsed
}

// todayUTC returns the YYYY-MM-DD date string used as the daily quota
// table key. UTC by deliberate choice — operator-friendly + immune to
// the user's local-tz quirks. Calendar-day reset cadence matches the
// spec.
func todayUTC() string {
	return time.Now().UTC().Format("2006-01-02")
}

// dateOffsetUTC returns YYYY-MM-DD for `days` days before today UTC.
// Used for the consecutive-days check (e.g. yesterday's row).
func dateOffsetUTC(days int) string {
	return time.Now().UTC().AddDate(0, 0, -days).Format("2006-01-02")
}

// isQuotaExempt reads users.quota_exempt for the given user, gated by
// the AllowExemptUsers config knob. When `[server.quotas.user]
// allow_exempt_users = false` (the default), this returns false
// unconditionally — the per-user exempt flag in the DB is ignored
// until the operator opts into the escape hatch by setting
// allow_exempt_users = true. This makes the gate effective immediately
// on flip rather than only governing future CLI calls; otherwise an
// admin staring at `false` in their config could be surprised to see
// quota bypasses driven by a stale DB flag from a prior config.
//
// Failures fail-closed (treat as not-exempt → enforce quota). Cheap
// single-row indexed query; the cost is acceptable in the upload hot
// path. Caller passes the already-parsed quota config to avoid a
// second config parse — this helper runs adjacent to a parsedQuota()
// call at every site.
func (s *Server) isQuotaExempt(quota config.ParsedUserQuota, userID string) bool {
	if !quota.AllowExemptUsers {
		return false
	}
	if s.store == nil {
		return false
	}
	exempt, err := s.store.IsUserQuotaExempt(userID)
	if err != nil {
		s.logger.Warn("isQuotaExempt failed; treating as not-exempt",
			"user", userID, "error", err)
		return false
	}
	return exempt
}

// quotaBlockedMessage renders the user-facing block message with the
// configured block threshold inline. Operators raising the block to
// 10GB get "10 GB" in the message; lowering to 2GB gets "2 GB".
// Single template, single source of truth.
func quotaBlockedMessage(blockBytes int64) string {
	return fmt.Sprintf(
		"This is a chat app, not a file server. You've reached your daily upload quota (%s). Try again after UTC midnight, or use a dedicated file-sharing service for bulk transfers.",
		formatBytesQuota(blockBytes),
	)
}

// formatBytesQuota mirrors cmd/sshkey-ctl's formatBytes — duplicated
// here to keep internal/server free of cmd/* imports. Uses binary
// (1024-base) units to match config.ParseSize's parser.
func formatBytesQuota(b int64) string {
	switch {
	case b >= 1<<30:
		return fmt.Sprintf("%.1f GB", float64(b)/float64(1<<30))
	case b >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(b)/float64(1<<20))
	case b >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(b)/float64(1<<10))
	default:
		return fmt.Sprintf("%d B", b)
	}
}

// notifyAdminsQuotaWarn fires admin_notify for the first warn-cross of
// the day. Idempotent at the call site via the prevWarned flag check;
// this function just dispatches.
func (s *Server) notifyAdminsQuotaWarn(userID string, bytesToday, threshold int64) {
	s.notifyAdmins(protocol.AdminNotifyQuota{
		Type:           "admin_notify",
		Event:          "quota_warn",
		User:           userID,
		Date:           todayUTC(),
		BytesToday:     bytesToday,
		ThresholdBytes: threshold,
	})
}

// notifyAdminsQuotaSustained fires admin_notify when the consecutive-
// days check fires alongside a warn-cross.
func (s *Server) notifyAdminsQuotaSustained(userID string, bytesToday, bytesYesterday, threshold int64, consecutiveDays int) {
	s.notifyAdmins(protocol.AdminNotifyQuota{
		Type:            "admin_notify",
		Event:           "quota_sustained",
		User:            userID,
		Date:            todayUTC(),
		BytesToday:      bytesToday,
		BytesYesterday:  bytesYesterday,
		ThresholdBytes:  threshold,
		ConsecutiveDays: consecutiveDays,
	})
}

// notifyAdminsQuotaBlock fires admin_notify when an upload is rejected
// for crossing the block threshold (either upload_start path or
// upload_complete TOCTOU path).
func (s *Server) notifyAdminsQuotaBlock(userID string, bytesToday, bytesAttempted, threshold int64) {
	s.notifyAdmins(protocol.AdminNotifyQuota{
		Type:           "admin_notify",
		Event:          "quota_block",
		User:           userID,
		Date:           todayUTC(),
		BytesToday:     bytesToday,
		BytesAttempted: bytesAttempted,
		ThresholdBytes: threshold,
	})
}

// isSustainedPattern returns true if the user crossed the warn
// threshold for `consecutiveDays` strictly contiguous days ending
// today. The recent slice is newest-first per GetRecentUploadDays;
// today is recent[0] (when present).
//
// Strict contiguity: the dates must form an unbroken sequence ending
// today. A gap day (zero rows or row missing) breaks the pattern.
func isSustainedPattern(recent []store.DailyUploadRow, warnBytes int64, consecutiveDays int) bool {
	if consecutiveDays < 2 {
		// "Sustained" implies at least 2 days; consecutive_days = 1
		// would fire on every warn-cross, which is what quota_warn
		// already does. Defensive — config validation rejects < 1.
		return false
	}
	if len(recent) < consecutiveDays {
		return false
	}
	// Build the expected date sequence (today, yesterday, ...).
	expected := make([]string, consecutiveDays)
	for i := 0; i < consecutiveDays; i++ {
		expected[i] = dateOffsetUTC(i)
	}
	// Verify the rows match exactly, AND each row crossed warn.
	for i, want := range expected {
		if recent[i].Date != want {
			return false
		}
		if recent[i].BytesTotal < warnBytes {
			return false
		}
	}
	return true
}

// pruneOldQuotaRows deletes daily_upload_quotas rows older than the
// configured retention window. Called once at server startup, right
// after cleanOrphanFiles (same family — bounded maintenance, not
// hot-path). No-op when quotas are disabled.
func (s *Server) pruneOldQuotaRows() {
	parsed := s.parsedQuota()
	if !parsed.Enabled || s.store == nil {
		return
	}
	cutoff := time.Now().UTC().AddDate(0, 0, -parsed.RetentionDays).Format("2006-01-02")
	n, err := s.store.PruneDailyUploadsBefore(cutoff)
	if err != nil {
		s.logger.Error("quota prune failed", "error", err)
		return
	}
	if n > 0 {
		s.logger.Info("pruned old quota rows", "rows", n, "before", cutoff)
	}
}

// removeUploadedFile is a tiny helper for the upload_complete TOCTOU
// path: a quota check that fails after the bytes have already landed
// on disk needs to clean up the file. Best-effort — log on failure
// but don't propagate, the orphan blob will be reaped by the next
// cleanOrphanFiles startup sweep.
func (s *Server) removeUploadedFile(fileID string) {
	if s.files == nil {
		return
	}
	path := filepath.Join(s.files.dir, fileID)
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		s.logger.Warn("quota TOCTOU rollback: failed to remove uploaded file",
			"file_id", fileID, "error", err)
	}
}
