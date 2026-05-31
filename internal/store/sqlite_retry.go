package store

import (
	"fmt"
	"time"
)

// retrySQLiteBusy retries a small SQLite operation when modernc/sqlite returns
// transient SQLITE_BUSY / "database is locked" under writer contention. The
// store opens databases with _busy_timeout, but the driver does not always wait
// reliably for concurrent writers in WAL mode, so hot write primitives need an
// explicit retry at the store boundary.
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
