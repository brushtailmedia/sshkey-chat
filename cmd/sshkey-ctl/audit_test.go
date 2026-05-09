package main

// Phase 16 — tests for cmdAuditLog and cmdAuditUser.
//
// Both commands are thin wrappers around audit.Read, so most of the
// parsing/filtering coverage lives in internal/audit/reader_test.go.
// These tests verify the CLI flag parsing, the dataDir resolution
// to <dataDir>/audit.log, and the output format (newest-first
// listing of raw entries, "no entries" message on empty, error
// messages on bad flags).

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// captureStdout swaps os.Stdout for a pipe, runs fn, and returns
// what was printed. Used to verify the cmd*'s text output without
// having to refactor for an io.Writer parameter.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	done := make(chan string)
	go func() {
		var buf bytes.Buffer
		io.Copy(&buf, r)
		done <- buf.String()
	}()
	fn()
	w.Close()
	os.Stdout = orig
	return <-done
}

// writeTestAuditLog writes a known set of audit entries into a fresh
// data dir and returns the dir path. The entries cover the actions
// that Phase 16 commands write so the tests look realistic.
func writeTestAuditLog(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	content := strings.Join([]string{
		`2026-04-16T08:00:00Z  os:1000      approve          user_id=usr_alice fingerprint=SHA256:abc admin=true`,
		`2026-04-16T09:00:00Z  os:1000      promote          user=usr_bob`,
		`2026-04-16T10:00:00Z  os:1000      retire-user      user=usr_carol reason=key_lost`,
		`2026-04-16T11:00:00Z  usr_alice    rename-room      room=rm_general`,
		`2026-04-16T12:00:00Z  os:1000      revoke-device    user=usr_alice device=dev_x`,
	}, "\n") + "\n"
	if err := os.WriteFile(path, []byte(content), 0640); err != nil {
		t.Fatalf("write audit log: %v", err)
	}
	return dir
}

// --- audit-log tests ---

func TestAuditLog_NoArgsShowsAllEntries(t *testing.T) {
	dir := writeTestAuditLog(t)
	out := captureStdout(t, func() {
		if err := cmdAuditLog(dir, nil); err != nil {
			t.Fatalf("cmdAuditLog: %v", err)
		}
	})

	for _, want := range []string{
		"approve",
		"promote",
		"retire-user",
		"rename-room",
		"revoke-device",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q, got: %q", want, out)
		}
	}
}

func TestAuditLog_NewestFirst(t *testing.T) {
	dir := writeTestAuditLog(t)
	out := captureStdout(t, func() {
		cmdAuditLog(dir, nil)
	})

	// revoke-device (12:00) should appear before approve (08:00)
	revokeIdx := strings.Index(out, "revoke-device")
	approveIdx := strings.Index(out, "approve")
	if revokeIdx == -1 || approveIdx == -1 {
		t.Fatalf("output missing entries: %q", out)
	}
	if revokeIdx > approveIdx {
		t.Error("expected revoke-device to appear before approve (newest first)")
	}
}

func TestAuditLog_LimitFlag(t *testing.T) {
	dir := writeTestAuditLog(t)
	out := captureStdout(t, func() {
		cmdAuditLog(dir, []string{"--limit", "2"})
	})

	// Should only show the 2 newest entries (revoke-device, rename-room).
	if !strings.Contains(out, "revoke-device") {
		t.Error("missing revoke-device (newest)")
	}
	if !strings.Contains(out, "rename-room") {
		t.Error("missing rename-room (second-newest)")
	}
	// `approve` (08:00) is the third-newest, so --limit 2 must exclude
	// it. Match the action token at column position to avoid false
	// positives if any other entry's details mention "approve".
	if strings.Contains(out, "  approve  ") {
		t.Error("approve should be excluded by --limit 2")
	}
}

func TestAuditLog_EmptyFile(t *testing.T) {
	dir := t.TempDir()
	out := captureStdout(t, func() {
		cmdAuditLog(dir, nil)
	})
	if !strings.Contains(out, "no audit entries") {
		t.Errorf("expected 'no audit entries' message, got: %q", out)
	}
}

func TestAuditLog_BadFlag(t *testing.T) {
	dir := t.TempDir()
	err := cmdAuditLog(dir, []string{"--bogus"})
	if err == nil {
		t.Fatal("expected error on unknown flag")
	}
}

func TestAuditLog_BadSinceDuration(t *testing.T) {
	dir := t.TempDir()
	err := cmdAuditLog(dir, []string{"--since", "abc"})
	if err == nil {
		t.Fatal("expected error on bad duration")
	}
}

func TestAuditLog_NegativeLimit(t *testing.T) {
	dir := t.TempDir()
	err := cmdAuditLog(dir, []string{"--limit", "-1"})
	if err == nil {
		t.Fatal("expected error on negative limit")
	}
}

// --- audit-user tests ---

func TestAuditUser_FiltersBySource(t *testing.T) {
	dir := writeTestAuditLog(t)
	out := captureStdout(t, func() {
		cmdAuditUser(dir, []string{"usr_alice"})
	})

	// usr_alice is the SOURCE of the rename-room entry (in-chat
	// admin action), and the TARGET of approve and revoke-device
	// entries (in details). Should match all three.
	for _, want := range []string{
		"approve",       // user_id=usr_alice in details
		"rename-room",   // usr_alice as source
		"revoke-device", // user=usr_alice in details
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q, got: %q", want, out)
		}
	}
	// promote and retire-user mention different users — should be excluded.
	if strings.Contains(out, "user=usr_bob") {
		t.Error("output should not contain promote of usr_bob")
	}
	if strings.Contains(out, "user=usr_carol") {
		t.Error("output should not contain retire of usr_carol")
	}
}

func TestAuditUser_NoMatches(t *testing.T) {
	dir := writeTestAuditLog(t)
	out := captureStdout(t, func() {
		cmdAuditUser(dir, []string{"usr_ghost"})
	})
	if !strings.Contains(out, "no audit entries for user") {
		t.Errorf("expected 'no audit entries' message, got: %q", out)
	}
}

func TestAuditUser_RequiresUserArg(t *testing.T) {
	dir := t.TempDir()
	err := cmdAuditUser(dir, nil)
	if err == nil {
		t.Fatal("expected error without user argument")
	}
}

func TestAuditUser_LimitFlag(t *testing.T) {
	dir := writeTestAuditLog(t)
	out := captureStdout(t, func() {
		cmdAuditUser(dir, []string{"usr_alice", "--limit", "1"})
	})

	// Should show only the newest matching entry (revoke-device at 12:00).
	if !strings.Contains(out, "revoke-device") {
		t.Errorf("expected newest matching entry, got: %q", out)
	}
	// approve (08:00) is older than revoke-device (12:00), so --limit 1
	// must exclude it. Anchor the action token at column position to
	// avoid colliding with detail strings.
	if strings.Contains(out, "  approve  ") {
		t.Error("approve should be excluded by --limit 1")
	}
}
