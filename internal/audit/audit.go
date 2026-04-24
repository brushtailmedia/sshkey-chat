// Package audit provides an append-only log of administrative actions.
// Both the server (for in-chat admin verbs) and the CLI (sshkey-ctl,
// for local admin operations) write to the same file so operators have
// a single place to look for "who did what when."
//
// Extracted from internal/server/audit.go in Phase 16 Gap 4 so the CLI
// could write entries for bootstrap-admin, retire-user, promote, etc.
// without needing to reach into server internals.
//
// The log file format is line-oriented plain text:
//
//	<RFC3339 timestamp>  <source>  <action>  <details>
//
// where source is one of:
//   - chat user ID (e.g. "usr_3f9a...") for in-chat admin actions
//   - "os:<uid>" for sshkey-ctl invocations (uid from os.Getuid())
//
// Format compatibility is important — the future audit-log CLI command
// will parse this format. Don't change the column widths without also
// updating the reader.
package audit

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Log is a simple wrapper around an append-only file. Concurrent writes
// from the same process are serialized via the embedded mutex.
// Cross-process concurrency (server + CLI writing simultaneously) is
// handled by the OS file lock that O_APPEND opens give us — appends
// are atomic up to PIPE_BUF size, which any single audit line easily
// fits into.
type Log struct {
	mu   sync.Mutex
	path string
}

// New constructs a Log that writes to <dataDir>/audit.log. The file is
// not opened until the first Write call; this lets callers create the
// Log lazily without worrying about errors during construction.
func New(dataDir string) *Log {
	return &Log{
		path: filepath.Join(dataDir, "audit.log"),
	}
}

// Log appends an entry with the given source, action, and details.
// All errors are silently ignored — audit logging must not break the
// caller. If the file can't be opened or the write fails, the action
// is still performed by the caller; we just lose the audit trail for
// that one entry. This matches the pre-Phase-16 behavior in
// internal/server/audit.go.
//
// The method name shadows the type name (audit.Log.Log) which reads
// as "log a log entry" — slightly awkward but keeps existing call
// sites in the server package unchanged after the extraction.
func (a *Log) Log(source, action, details string) {
	a.mu.Lock()
	defer a.mu.Unlock()

	f, err := os.OpenFile(a.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
	if err != nil {
		return
	}
	defer f.Close()

	ts := time.Now().UTC().Format(time.RFC3339)
	fmt.Fprintf(f, "%s  %-12s  %-15s  %s\n", ts, source, action, details)
}

// LogOS is a convenience wrapper for CLI callers — formats the
// source as "os:<uid>" using the current process's UID. Use this from
// sshkey-ctl command implementations so audit entries always identify
// the OS-level user who ran the command.
func (a *Log) LogOS(action, details string) {
	a.Log(fmt.Sprintf("os:%d", os.Getuid()), action, details)
}
