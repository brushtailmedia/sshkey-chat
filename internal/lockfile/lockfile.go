// Package lockfile provides a PID-file lock for the sshkey-chat server.
//
// Phase 19 Step 2 — the lockfile is the mechanical enforcement of
// "server is stopped" for the restore command, and secondarily
// provides double-start protection on the same dataDir plus a reliable
// signal for `sshkey-ctl status` to report running-vs-not.
//
// Format: a single file at <dataDir>/sshkey-server.pid containing two
// newline-terminated lines:
//
//	<pid>
//	<start_unix_timestamp>
//
// Both lines are plain ASCII integers. No JSON, no TOML — the format
// is read from shell scripts and trivial tooling (`kill $(cat foo.pid)`
// is a supported operator workflow).
//
// Aliveness is checked via syscall.Kill(pid, 0):
//   - nil    → process exists and we can signal it (alive)
//   - EPERM  → process exists, we can't signal it (alive, different user)
//   - ESRCH  → process does not exist (stale)
//   - other  → treated as alive for safety (don't destroy unknown state)
//
// Write semantics: if an existing lockfile's PID is stale, Write
// overwrites it (crash recovery). If the PID is alive, Write refuses
// with ErrAlreadyRunning so the second server instance can report
// cleanly instead of fighting for file locks.
//
// Read semantics: returns parsed PID + start time + alive bool.
// Callers decide what to do based on alive — Server.New refuses to
// start if alive+same-dataDir; `sshkey-ctl restore` refuses to run
// if alive; `sshkey-ctl status` formats alive as "running" and
// dead-or-absent as "not running".
package lockfile

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// ErrAlreadyRunning is returned by Write when the lockfile contains a
// PID that maps to a live process. Callers should surface a clear
// error to the operator pointing at the live PID.
var ErrAlreadyRunning = errors.New("sshkey-server already running")

// Info carries the parsed contents of a lockfile plus a liveness
// check.
type Info struct {
	PID       int
	StartedAt time.Time
	Alive     bool
}

// Write atomically writes a lockfile at path containing the current
// process PID and start time.
//
// If a lockfile already exists:
//   - Stale PID (process dead) → overwrites it, returns nil
//   - Live PID → refuses with ErrAlreadyRunning
//   - Unparseable → refuses with a clear error (don't silently clobber
//     a file we don't understand — operator investigates manually)
//
// Write uses a temp-file + rename pattern so a crash mid-write can't
// leave a partial lockfile that breaks parsing.
func Write(path string) error {
	// Check for an existing lockfile first.
	if existing, err := Read(path); err == nil {
		if existing.Alive {
			return fmt.Errorf("%w: PID %d started at %s",
				ErrAlreadyRunning, existing.PID, existing.StartedAt.UTC().Format(time.RFC3339))
		}
		// Stale — fall through to overwrite.
	} else if !errors.Is(err, os.ErrNotExist) {
		// Existing file that we couldn't parse. Don't clobber it.
		return fmt.Errorf("existing lockfile at %s is unreadable: %w", path, err)
	}

	// Write to a temp file in the same directory, then rename for
	// atomicity. Same directory is required for rename to be atomic
	// on Unix (must be same filesystem).
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("create %s: %w", tmp, err)
	}

	content := fmt.Sprintf("%d\n%d\n", os.Getpid(), time.Now().Unix())
	if _, err := f.WriteString(content); err != nil {
		f.Close()
		os.Remove(tmp)
		return fmt.Errorf("write %s: %w", tmp, err)
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("close %s: %w", tmp, err)
	}

	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("rename %s to %s: %w", tmp, path, err)
	}
	return nil
}

// Read parses the lockfile at path and returns its contents plus a
// liveness check on the PID. Returns os.ErrNotExist (wrapped) if the
// file is absent — callers should use errors.Is(err, os.ErrNotExist)
// to distinguish "not running" from "can't read the file".
func Read(path string) (Info, error) {
	var info Info

	f, err := os.Open(path)
	if err != nil {
		return info, err // os.ErrNotExist wrapping is preserved
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	if !scanner.Scan() {
		return info, fmt.Errorf("lockfile %s: empty file", path)
	}
	pidStr := strings.TrimSpace(scanner.Text())
	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		return info, fmt.Errorf("lockfile %s: PID line %q is not an integer: %w", path, pidStr, err)
	}
	if pid <= 0 {
		return info, fmt.Errorf("lockfile %s: PID %d is not a positive integer", path, pid)
	}
	info.PID = pid

	if !scanner.Scan() {
		return info, fmt.Errorf("lockfile %s: missing start-timestamp line", path)
	}
	tsStr := strings.TrimSpace(scanner.Text())
	ts, err := strconv.ParseInt(tsStr, 10, 64)
	if err != nil {
		return info, fmt.Errorf("lockfile %s: timestamp line %q is not an integer: %w", path, tsStr, err)
	}
	info.StartedAt = time.Unix(ts, 0)

	info.Alive = isAlive(pid)
	return info, nil
}

// Remove deletes the lockfile. Returns nil if the file is already
// absent — remove-if-exists semantics fit the shutdown path where
// we don't want a spurious error to mask a real shutdown failure.
func Remove(path string) error {
	err := os.Remove(path)
	if err == nil || errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return fmt.Errorf("remove %s: %w", path, err)
}

// isAlive checks whether a PID refers to a running process.
// syscall.Kill(pid, 0) is the standard Unix idiom:
//   - nil         → process exists and current user can signal it
//   - syscall.EPERM → process exists, different user (still alive)
//   - syscall.ESRCH → process does not exist (stale)
//
// Any other error is treated as alive to avoid destroying state we
// don't understand. Over-reporting alive is fine (refuses to start,
// which an operator can diagnose); under-reporting alive could clobber
// a running server's state.
func isAlive(pid int) bool {
	err := syscall.Kill(pid, 0)
	if err == nil {
		return true
	}
	if errors.Is(err, syscall.ESRCH) {
		return false
	}
	// EPERM, EINVAL, anything else — treat as alive for safety.
	return true
}
