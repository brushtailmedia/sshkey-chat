package store

import (
	"fmt"
	"time"
)

// retrySQLiteBusy retries a small SQLite operation when modernc/sqlite returns
// transient SQLITE_BUSY / "database is locked" under writer contention.
//
// The store now opens every connection with busy_timeout(5000) applied via the
// DSN (sqlitedsn.Writable), so the driver itself waits up to 5s for a competing
// writer — this retry is belt-and-suspenders for hot write primitives, not the
// primary timeout mechanism. (Before the DSN fix, busy_timeout was effectively 0
// because modernc silently ignores the mattn-style `_busy_timeout` param, so
// this retry was the only thing absorbing contention.)
func retrySQLiteBusy(operation string, fn func() error) error {
	const maxAttempts = 10
	delay := 5 * time.Millisecond
	var lastErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		err := fn()
		if err == nil {
			return nil
		}
		if !isSQLiteBusy(err) {
			return err
		}
		lastErr = err
		time.Sleep(delay)
		delay *= 2
		if delay > 200*time.Millisecond {
			delay = 200 * time.Millisecond
		}
	}
	return fmt.Errorf("%s: exhausted retries on SQLITE_BUSY: %w", operation, lastErr)
}
