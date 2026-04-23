package server

// Empty-users.db startup warning.
//
// On a fresh deployment, users.db is empty. The server runs fine but
// nothing will work — every SSH connection is rejected, every rejected
// key lands in pending-keys.log, and no admin exists to triage any of
// it. Before this warning existed, operators saw "server started"
// followed by silence, with no log signal pointing at the missing
// bootstrap step.
//
// The Server.New path fires a WARN if UsersDBEmpty() returns true at
// startup. The warning names the fix: sshkey-ctl bootstrap-admin.
//
// Tests:
//   - TestServerNew_EmptyUsersDBEmitsWarning: fresh data dir → warning.
//   - TestServerNew_NonEmptyUsersDBSuppressesWarning: admin seeded via
//     store.InsertUser → no warning.

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

func TestServerNew_EmptyUsersDBEmitsWarning(t *testing.T) {
	configDir := t.TempDir()
	dataDir := t.TempDir()
	cfg := minimalServerConfig(t, configDir)

	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelWarn}))

	s, err := New(cfg, logger, dataDir)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	t.Cleanup(func() {
		if s.store != nil {
			s.store.Close()
		}
	})

	out := logBuf.String()
	for _, want := range []string{
		"no users in users.db",
		"sshkey-ctl bootstrap-admin",
		"server will accept no logins",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("warning missing %q in log output:\n%s", want, out)
		}
	}
	// Verify the data_dir attribute is attached — operators should see
	// exactly which dataDir the warning refers to (matters when a host
	// runs multiple instances).
	if !strings.Contains(out, dataDir) {
		t.Errorf("warning missing data_dir=%q attribute in log output:\n%s", dataDir, out)
	}
}

func TestServerNew_NonEmptyUsersDBSuppressesWarning(t *testing.T) {
	configDir := t.TempDir()
	dataDir := t.TempDir()
	cfg := minimalServerConfig(t, configDir)

	// First start — creates users.db schema so we can seed.
	var firstBuf bytes.Buffer
	firstLogger := slog.New(slog.NewTextHandler(&firstBuf, &slog.HandlerOptions{Level: slog.LevelWarn}))
	first, err := New(cfg, firstLogger, dataDir)
	if err != nil {
		t.Fatalf("first server.New: %v", err)
	}
	// Seed an admin directly into the store. InsertUser takes
	// (id, key, displayName); admin flag is a separate SetAdmin call.
	if err := first.store.InsertUser("usr_admin_test", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAbcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQR admin@test", "Admin"); err != nil {
		t.Fatalf("InsertUser: %v", err)
	}
	if err := first.store.SetAdmin("usr_admin_test", true); err != nil {
		t.Fatalf("SetAdmin: %v", err)
	}
	first.Close()

	// Second start — users.db now has one admin, warning must NOT fire.
	var secondBuf bytes.Buffer
	secondLogger := slog.New(slog.NewTextHandler(&secondBuf, &slog.HandlerOptions{Level: slog.LevelWarn}))
	second, err := New(cfg, secondLogger, dataDir)
	if err != nil {
		t.Fatalf("second server.New: %v", err)
	}
	t.Cleanup(func() {
		if second.store != nil {
			second.store.Close()
		}
	})

	if strings.Contains(secondBuf.String(), "no users in users.db") {
		t.Errorf("warning fired on non-empty users.db (admin seeded between runs):\n%s", secondBuf.String())
	}
}
