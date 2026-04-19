package main

// CLI-level tests for the quota subcommand. The exempt machinery is
// gated by [server.quotas.user] allow_exempt_users in server.toml
// (default false). Tests here verify:
//   - --on is rejected when the gate is off
//   - --on succeeds when the gate is on (round-trip flips the DB flag)
//   - --off is allowed unconditionally (escape hatch)
//   - missing/unparseable server.toml on --on errors cleanly
//
// Out-of-phase 2026-04-19 (gate added same day as the original quota
// feature shipped, after a consistency review of admin-managed-by-
// default config patterns).

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/brushtailmedia/sshkey-chat/internal/store"
)

// newQuotaCLITestEnv builds a configDir + dataDir pair with an
// initialized store, a seeded user, and a server.toml with the
// allow_exempt_users line set to the given value.
func newQuotaCLITestEnv(t *testing.T, allowExempt bool) (configDir, dataDir, userID string) {
	t.Helper()
	configDir = t.TempDir()
	dataDir = t.TempDir()

	allowLine := "false"
	if allowExempt {
		allowLine = "true"
	}
	toml := `
[server]
port = 2222
bind = "127.0.0.1"

[server.quotas.user]
enabled = true
allow_exempt_users = ` + allowLine + `
`
	if err := os.WriteFile(filepath.Join(configDir, "server.toml"), []byte(toml), 0644); err != nil {
		t.Fatalf("write server.toml: %v", err)
	}
	if err := os.WriteFile(filepath.Join(configDir, "rooms.toml"), []byte{}, 0644); err != nil {
		t.Fatalf("write rooms.toml: %v", err)
	}

	st, err := store.Open(dataDir)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	userID = "usr_alice"
	if err := st.InsertUser(userID, "ssh-ed25519 AAAA fake-alice", "Alice"); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	st.Close() // cmdUserQuotaExempt opens its own handle; release the seed handle.
	return configDir, dataDir, userID
}

// readExempt reopens the store and reads the per-user exempt flag —
// used to verify that --on / --off actually wrote (or didn't write)
// to the DB.
func readExempt(t *testing.T, dataDir, userID string) bool {
	t.Helper()
	st, err := store.Open(dataDir)
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	defer st.Close()
	exempt, err := st.IsUserQuotaExempt(userID)
	if err != nil {
		t.Fatalf("read exempt: %v", err)
	}
	return exempt
}

// -------- --on rejection when gate is off --------

func TestCmdUserQuotaExempt_OnRejectedWhenGateOff(t *testing.T) {
	configDir, dataDir, userID := newQuotaCLITestEnv(t, false)

	err := cmdUserQuotaExempt(configDir, dataDir, []string{userID, "--on"})
	if err == nil {
		t.Fatal("expected error when --on is run with allow_exempt_users=false")
	}
	wantSubs := []string{"refusing", "allow_exempt_users", userID}
	for _, sub := range wantSubs {
		if !strings.Contains(err.Error(), sub) {
			t.Errorf("error %q missing expected substring %q", err.Error(), sub)
		}
	}
	// And the DB flag must NOT have been flipped.
	if readExempt(t, dataDir, userID) {
		t.Error("--on rejection should leave quota_exempt unchanged (still false)")
	}
}

// -------- --on succeeds when gate is on --------

func TestCmdUserQuotaExempt_OnSucceedsWhenGateOn(t *testing.T) {
	configDir, dataDir, userID := newQuotaCLITestEnv(t, true)

	if err := cmdUserQuotaExempt(configDir, dataDir, []string{userID, "--on"}); err != nil {
		t.Fatalf("--on with gate on should succeed, got: %v", err)
	}
	if !readExempt(t, dataDir, userID) {
		t.Error("after --on with gate on, DB flag should be set")
	}
}

// -------- --off always works (escape hatch) --------

func TestCmdUserQuotaExempt_OffWorksWhenGateOff(t *testing.T) {
	// Setup: gate on, mark user exempt, then flip gate off.
	configDir, dataDir, userID := newQuotaCLITestEnv(t, true)
	if err := cmdUserQuotaExempt(configDir, dataDir, []string{userID, "--on"}); err != nil {
		t.Fatalf("setup: --on failed: %v", err)
	}
	if !readExempt(t, dataDir, userID) {
		t.Fatal("setup: DB should report exempt=true after --on")
	}

	// Flip gate to false, leaving the existing exempt flag in place.
	tomlOff := `
[server]
port = 2222
bind = "127.0.0.1"

[server.quotas.user]
enabled = true
allow_exempt_users = false
`
	if err := os.WriteFile(filepath.Join(configDir, "server.toml"), []byte(tomlOff), 0644); err != nil {
		t.Fatalf("rewrite server.toml: %v", err)
	}

	// --off must work (escape hatch — operator needs to clean up
	// stale exempt flags after flipping the gate off).
	if err := cmdUserQuotaExempt(configDir, dataDir, []string{userID, "--off"}); err != nil {
		t.Fatalf("--off should be allowed when gate is off, got: %v", err)
	}
	if readExempt(t, dataDir, userID) {
		t.Error("after --off, DB flag should be cleared")
	}
}

// -------- error paths --------

func TestCmdUserQuotaExempt_OnErrorsOnMissingServerToml(t *testing.T) {
	// configDir without server.toml — the gate check on --on must
	// surface a clear error (don't silently bypass the gate by
	// treating "no config" as "no restriction").
	configDir := t.TempDir()
	dataDir := t.TempDir()
	st, _ := store.Open(dataDir)
	st.InsertUser("usr_alice", "ssh-ed25519 AAAA fake", "Alice")
	st.Close()

	err := cmdUserQuotaExempt(configDir, dataDir, []string{"usr_alice", "--on"})
	if err == nil {
		t.Fatal("expected error when server.toml is missing on --on")
	}
	if !strings.Contains(err.Error(), "load server.toml") {
		t.Errorf("error should mention load failure, got: %q", err.Error())
	}
}

func TestCmdUserQuotaExempt_OffSkipsConfigLoad(t *testing.T) {
	// --off doesn't need to consult the gate, so a missing
	// server.toml should not break the escape hatch. This protects
	// the recovery scenario where an operator has an unrelated
	// config breakage but still needs to clear an exempt flag.
	configDir := t.TempDir() // empty — no server.toml
	dataDir := t.TempDir()
	st, _ := store.Open(dataDir)
	st.InsertUser("usr_alice", "ssh-ed25519 AAAA fake", "Alice")
	st.SetUserQuotaExempt("usr_alice", true)
	st.Close()

	if err := cmdUserQuotaExempt(configDir, dataDir, []string{"usr_alice", "--off"}); err != nil {
		t.Fatalf("--off should not require server.toml, got: %v", err)
	}
	if readExempt(t, dataDir, "usr_alice") {
		t.Error("after --off, exempt flag should be cleared")
	}
}

// -------- usage / arg validation --------

func TestCmdUserQuotaExempt_RejectsBadFlag(t *testing.T) {
	configDir, dataDir, userID := newQuotaCLITestEnv(t, true)
	err := cmdUserQuotaExempt(configDir, dataDir, []string{userID, "--maybe"})
	if err == nil {
		t.Fatal("expected error on unknown flag")
	}
	if !strings.Contains(err.Error(), "--on or --off") {
		t.Errorf("error should mention valid flags, got: %q", err.Error())
	}
}

func TestCmdUser_DispatchesQuotaExempt(t *testing.T) {
	configDir, dataDir, userID := newQuotaCLITestEnv(t, true)
	// Routes through cmdUser to confirm the dispatch is wired.
	if err := cmdUser(configDir, dataDir, []string{"quota-exempt", userID, "--on"}); err != nil {
		t.Fatalf("cmdUser dispatch: %v", err)
	}
	if !readExempt(t, dataDir, userID) {
		t.Error("dispatched --on should have flipped the DB flag")
	}
}

func TestCmdUser_UnknownSubcommand(t *testing.T) {
	configDir := t.TempDir()
	dataDir := t.TempDir()
	err := cmdUser(configDir, dataDir, []string{"do-something-weird"})
	if err == nil {
		t.Fatal("expected error on unknown subcommand")
	}
	if !strings.Contains(err.Error(), "unknown user subcommand") {
		t.Errorf("error should mention unknown subcommand, got: %q", err.Error())
	}
}
