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
// Atomic acquire (Phase 21 F6 closure, 2026-04-19). Write stages the
// full payload in a per-process tempfile then calls `os.Link(tmp,
// path)` — POSIX link(2) is atomic and returns EEXIST if the target
// exists, making it the canonical exclusive-create primitive for
// file-based locks. Because the tempfile carries the complete
// payload before the Link attempt, readers who see the linked path
// always observe complete content; there is no empty-file window
// that a plain O_EXCL-on-final-path approach would expose. Prior
// implementation used a Read-then-temp-write-then-Rename sequence
// with a microsecond-level TOCTOU window where two fresh startups
// could both pass the aliveness check before either wrote, causing
// the second's rename to clobber the first's lockfile with both
// processes continuing to run. The tmpfile+Link pattern closes that
// window structurally.
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
	"path/filepath"
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

// Write atomically acquires a lockfile at path containing the current
// process PID and start time.
//
// If a lockfile already exists:
//   - Stale PID (process dead) → removes and retries, returns nil
//   - Live PID → refuses with ErrAlreadyRunning
//   - Unparseable → refuses with a clear error (don't silently clobber
//     a file we don't understand — operator investigates manually)
//
// Atomicity: acquisition stages the complete payload in a per-process
// tempfile then calls os.Link(tmp, path). POSIX link(2) is atomic and
// returns EEXIST if the target exists — exactly one of N racing
// processes wins. Because the tempfile holds the complete payload
// before Link, readers always see full content on the linked path;
// there is no zero-byte or partial-content race.
//
// The stale-retry path does one additional Link attempt after removing
// the stale file. If that retry also collides (another process beat us
// to the recovery), we return ErrAlreadyRunning against the winning
// PID rather than looping indefinitely.
func Write(path string) error {
	content := fmt.Sprintf("%d\n%d\n", os.Getpid(), time.Now().Unix())

	// Stage the full payload in a tempfile within the same directory
	// as `path`. Same-directory is required so link(2) stays within a
	// single filesystem (EXDEV otherwise). CreateTemp uses O_EXCL
	// internally so two concurrent calls get distinct tempfile names.
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".sshkey-lockfile-*.tmp")
	if err != nil {
		return fmt.Errorf("create lockfile tempfile in %s: %w", dir, err)
	}
	tmpName := tmp.Name()
	// Always remove the tempfile: on success link(2) duplicates the
	// inode so path survives; on failure the tempfile would otherwise
	// leak.
	defer os.Remove(tmpName)

	if _, err := tmp.WriteString(content); err != nil {
		tmp.Close()
		return fmt.Errorf("write lockfile tempfile %s: %w", tmpName, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close lockfile tempfile %s: %w", tmpName, err)
	}

	// First attempt: atomic exclusive-link to the final path.
	if err := os.Link(tmpName, path); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrExist) {
		return fmt.Errorf("link %s to %s: %w", tmpName, path, err)
	}

	// Lockfile already exists. Check whether it's a live server or a
	// stale post-crash artefact.
	existing, readErr := Read(path)
	if readErr != nil {
		// File exists but is unparseable (corrupted). Refuse to
		// clobber — operator investigates manually.
		return fmt.Errorf("existing lockfile at %s is unreadable: %w", path, readErr)
	}
	if existing.Alive {
		return fmt.Errorf("%w: PID %d started at %s",
			ErrAlreadyRunning, existing.PID, existing.StartedAt.UTC().Format(time.RFC3339))
	}

	// Stale. Remove and retry once. A concurrent process racing on
	// the same stale recovery could win the retry; in that case we
	// return ErrAlreadyRunning against their PID.
	if rmErr := os.Remove(path); rmErr != nil && !errors.Is(rmErr, os.ErrNotExist) {
		return fmt.Errorf("remove stale lockfile %s: %w", path, rmErr)
	}
	if err := os.Link(tmpName, path); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrExist) {
		return fmt.Errorf("retry link %s to %s: %w", tmpName, path, err)
	}
	// Another process beat us to the stale-recovery retry.
	if existing, readErr := Read(path); readErr == nil && existing.Alive {
		return fmt.Errorf("%w: PID %d started at %s (beat us to stale-lock recovery)",
			ErrAlreadyRunning, existing.PID, existing.StartedAt.UTC().Format(time.RFC3339))
	}
	return fmt.Errorf("%w: concurrent stale-lock recovery collided at %s", ErrAlreadyRunning, path)
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
