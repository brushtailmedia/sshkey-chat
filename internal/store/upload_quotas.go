package store

// Per-user daily upload quotas — design from upload_quota.md, shipped
// 2026-04-19 as out-of-phase work pre-Phase 21.
//
// Schema lives in data.db (same database as file_hashes + file_contexts
// — keeps the per-upload accounting in one transactional domain).

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// DailyUploadRow is a single (user, date) accounting row.
type DailyUploadRow struct {
	UserID       string
	Date         string // YYYY-MM-DD, UTC
	BytesTotal   int64
	WarnNotified bool
}

// initDailyUploadQuotas creates the daily_upload_quotas table. Called
// once at store open from initDataDB-equivalent path. Idempotent via
// IF NOT EXISTS.
func (s *Store) initDailyUploadQuotas() error {
	_, err := s.dataDB.Exec(`
		CREATE TABLE IF NOT EXISTS daily_upload_quotas (
			user_id        TEXT    NOT NULL,
			date           TEXT    NOT NULL,
			bytes_total    INTEGER NOT NULL DEFAULT 0,
			warn_notified  INTEGER NOT NULL DEFAULT 0,
			PRIMARY KEY (user_id, date)
		);
		CREATE INDEX IF NOT EXISTS idx_daily_upload_user_date
			ON daily_upload_quotas(user_id, date DESC);
	`)
	return err
}

// GetDailyUploadRow returns the (bytes, warnNotified, exists) tuple for
// (user, date). Absent row is signaled by exists=false (callers treat
// as zero bytes used). Read errors propagate.
func (s *Store) GetDailyUploadRow(userID, date string) (bytes int64, warnNotified bool, exists bool, err error) {
	var n int
	err = s.dataDB.QueryRow(
		`SELECT bytes_total, warn_notified FROM daily_upload_quotas WHERE user_id = ? AND date = ?`,
		userID, date,
	).Scan(&bytes, &n)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, false, false, nil
	}
	if err != nil {
		return 0, false, false, err
	}
	return bytes, n != 0, true, nil
}

// IncrementDailyUploadBytes atomically adds bytes to the (user, date)
// row, creating it if absent. Returns the new total. If markWarned is
// true, also sets warn_notified = 1 (caller is responsible for deciding
// whether the threshold was just crossed).
//
// Atomic via SQLite UPSERT — no read-modify-write race between
// concurrent uploads from the same user.
//
// SQLITE_BUSY handling: the modernc.org/sqlite driver doesn't always
// honor the URI _busy_timeout option for concurrent writers in WAL
// mode. The retry loop below handles transient BUSY by sleeping +
// retrying with backoff, capped at ~1s total wait. Real-world
// contention on this code path is very low (per-user rate-limited at
// UploadsPerMinute, typically 60/min), so retries are rare in
// production.
func (s *Store) IncrementDailyUploadBytes(userID, date string, bytes int64, markWarned bool) (int64, error) {
	if bytes < 0 {
		return 0, fmt.Errorf("IncrementDailyUploadBytes: bytes must be >= 0, got %d", bytes)
	}
	warnVal := 0
	if markWarned {
		warnVal = 1
	}

	// INSERT path: row doesn't exist → create with bytes_total = bytes,
	//              warn_notified = warnVal.
	// CONFLICT path: row exists → bytes_total += bytes,
	//                warn_notified |= warnVal (sticky once set).
	const upsertSQL = `
		INSERT INTO daily_upload_quotas (user_id, date, bytes_total, warn_notified)
		VALUES (?, ?, ?, ?)
		ON CONFLICT (user_id, date) DO UPDATE SET
			bytes_total = bytes_total + excluded.bytes_total,
			warn_notified = MAX(warn_notified, excluded.warn_notified)`

	// Retry-on-SQLITE_BUSY loop. modernc.org/sqlite doesn't always
	// honor the URI _busy_timeout for concurrent writers in WAL mode;
	// handle it explicitly. Total wait capped at ~1s (10 attempts,
	// 5ms→200ms exponential). Real-world contention is very low
	// (per-user UploadsPerMinute rate limit), so retries are rare.
	const maxAttempts = 10
	delay := 5 * time.Millisecond
	var lastErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		_, err := s.dataDB.Exec(upsertSQL, userID, date, bytes, warnVal)
		if err == nil {
			lastErr = nil
			break
		}
		if !isSQLiteBusy(err) {
			return 0, err
		}
		lastErr = err
		time.Sleep(delay)
		delay *= 2
		if delay > 200*time.Millisecond {
			delay = 200 * time.Millisecond
		}
	}
	if lastErr != nil {
		return 0, fmt.Errorf("IncrementDailyUploadBytes: exhausted retries on SQLITE_BUSY: %w", lastErr)
	}

	// Read back the new total. SELECT is BUSY-resilient because WAL
	// readers don't block on writers, but include the same retry
	// pattern for symmetry — a still-in-flight writer mid-checkpoint
	// can briefly stall a fresh read.
	var newTotal int64
	delay = 5 * time.Millisecond
	for attempt := 0; attempt < maxAttempts; attempt++ {
		err := s.dataDB.QueryRow(
			`SELECT bytes_total FROM daily_upload_quotas WHERE user_id = ? AND date = ?`,
			userID, date,
		).Scan(&newTotal)
		if err == nil {
			return newTotal, nil
		}
		if !isSQLiteBusy(err) {
			return 0, err
		}
		time.Sleep(delay)
		delay *= 2
		if delay > 200*time.Millisecond {
			delay = 200 * time.Millisecond
		}
	}
	return 0, fmt.Errorf("IncrementDailyUploadBytes: exhausted retries on SQLITE_BUSY for read-back")
}

// isSQLiteBusy returns true if err is SQLITE_BUSY. modernc.org/sqlite
// wraps the error code in the message; substring match is the most
// portable way to detect across driver versions.
func isSQLiteBusy(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "SQLITE_BUSY") || strings.Contains(msg, "database is locked")
}

// GetRecentUploadDays returns the (date, bytes_total, warn_notified)
// rows for the last `days` days for this user, ordered newest-first.
// Used for the consecutive-days sustained-pattern check. Caller passes
// the days knob from config.
func (s *Store) GetRecentUploadDays(userID string, days int) ([]DailyUploadRow, error) {
	if days <= 0 {
		return nil, nil
	}
	rows, err := s.dataDB.Query(
		`SELECT date, bytes_total, warn_notified
		 FROM daily_upload_quotas
		 WHERE user_id = ?
		 ORDER BY date DESC
		 LIMIT ?`,
		userID, days,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DailyUploadRow
	for rows.Next() {
		var r DailyUploadRow
		var n int
		if err := rows.Scan(&r.Date, &r.BytesTotal, &n); err != nil {
			return nil, err
		}
		r.UserID = userID
		r.WarnNotified = n != 0
		out = append(out, r)
	}
	return out, rows.Err()
}

// PruneDailyUploadsBefore deletes rows with date < cutoff. Returns the
// number of rows deleted (for the startup log line).
func (s *Store) PruneDailyUploadsBefore(cutoff string) (int64, error) {
	res, err := s.dataDB.Exec(
		`DELETE FROM daily_upload_quotas WHERE date < ?`,
		cutoff,
	)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// SetUserQuotaExempt toggles the quota_exempt flag on the users row.
// Admin-only path via sshkey-ctl. Returns ErrNoRows-equivalent
// (sql.ErrNoRows wrapped) if userID doesn't exist.
func (s *Store) SetUserQuotaExempt(userID string, exempt bool) error {
	val := 0
	if exempt {
		val = 1
	}
	res, err := s.usersDB.Exec(
		`UPDATE users SET quota_exempt = ? WHERE id = ?`,
		val, userID,
	)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("user %s not found", userID)
	}
	return nil
}

// IsUserQuotaExempt reads the flag. Used as an early-exit in the
// quota-check path. Missing user returns (false, nil) — exempt-check
// failure is fail-closed (treat as not-exempt → enforce quota).
func (s *Store) IsUserQuotaExempt(userID string) (bool, error) {
	var n int
	err := s.usersDB.QueryRow(
		`SELECT quota_exempt FROM users WHERE id = ?`,
		userID,
	).Scan(&n)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return n != 0, nil
}
