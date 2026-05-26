package server

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPendingNotifyLimiter_Allow(t *testing.T) {
	// burst=1: first allowed, immediate second denied (no time to refill).
	var l pendingNotifyLimiter
	if !l.allow(5, 1) {
		t.Error("first call should be allowed (starts full at burst)")
	}
	if l.allow(5, 1) {
		t.Error("second immediate call should be denied (burst=1 consumed)")
	}

	// burst=3: three immediate calls allowed, fourth denied.
	var l3 pendingNotifyLimiter
	for i := 0; i < 3; i++ {
		if !l3.allow(60, 3) {
			t.Errorf("call %d within burst=3 should be allowed", i)
		}
	}
	if l3.allow(60, 3) {
		t.Error("fourth call should be denied (burst=3 exhausted)")
	}

	// Non-positive config denies (defensive belt; callers normalize first).
	var l0 pendingNotifyLimiter
	if l0.allow(0, 1) || l0.allow(5, 0) {
		t.Error("non-positive perMinute/burst should deny")
	}
}

// newStormServer builds a server with an open store and a registered admin
// client (for admin_notify capture), mirroring the pending_keys_log test setup.
func newStormServer(t *testing.T) (*Server, *captureClient) {
	t.Helper()
	root := t.TempDir()
	configDir := filepath.Join(root, "config")
	dataDir := filepath.Join(root, "var")
	if err := os.MkdirAll(configDir, 0755); err != nil {
		t.Fatalf("mkdir config dir: %v", err)
	}
	cfg := minimalServerConfig(t, configDir)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	s, err := New(cfg, logger, dataDir)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	t.Cleanup(func() {
		if s.store != nil {
			s.store.Close()
		}
	})
	seedTestUser(t, s, "alice", testKeyAlice, "Alice", true, nil)
	admin := testClientFor("alice", "dev_alice_storm_admin")
	s.mu.Lock()
	s.clients[admin.DeviceID] = admin.Client
	s.mu.Unlock()
	return s, admin
}

func setPendingCfg(s *Server, maxAgeHours, maxRows, pruneInterval, perMin, burst int) {
	s.cfg.Lock()
	s.cfg.Server.Server.PendingKeys.MaxAgeHours = maxAgeHours
	s.cfg.Server.Server.PendingKeys.MaxRows = maxRows
	s.cfg.Server.Server.PendingKeys.PruneIntervalSeconds = pruneInterval
	s.cfg.Server.Server.PendingKeys.NotifyPerMinute = perMin
	s.cfg.Server.Server.PendingKeys.NotifyBurst = burst
	s.cfg.Unlock()
}

// TestLogPendingKey_NotifyThrottledRowsRecorded proves gap D: a fresh-key storm
// is throttled to notify_burst admin notifications, but EVERY contact's row is
// still recorded (only the push is rate-limited).
func TestLogPendingKey_NotifyThrottledRowsRecorded(t *testing.T) {
	s, admin := newStormServer(t)
	// Default config gives notify_burst=1; make it explicit for the test.
	setPendingCfg(s, 168, 1000, 60, 5, 1)

	const key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestStormKey"
	s.logPendingKey("SHA256:storm-1", "1.1.1.1:1", key, "")
	s.logPendingKey("SHA256:storm-2", "2.2.2.2:2", key, "") // burst exhausted → no notify
	s.logPendingKey("SHA256:storm-3", "3.3.3.3:3", key, "") // still throttled

	// All three contacts recorded despite the notify throttle.
	rows, err := s.store.ListPendingKeys()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(rows) != 3 {
		t.Errorf("recorded rows = %d, want 3 (throttle must not drop DB rows)", len(rows))
	}

	// Only notify_burst (=1) admin_notify pushes.
	if got := len(admin.messages()); got != 1 {
		t.Errorf("admin_notify count = %d, want 1 (notify_burst)", got)
	}
}

// TestPrunePendingKeys_CapWiring verifies the server reads max_rows from config
// and enforces the hard cap via the store.
func TestPrunePendingKeys_CapWiring(t *testing.T) {
	s, _ := newStormServer(t)
	setPendingCfg(s, 168, 2, 60, 5, 1) // max_rows = 2

	const key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestCapKey"
	for i := 0; i < 4; i++ {
		if _, _, err := s.store.RecordPendingKey(sprintfFP(i), "1:1", key, ""); err != nil {
			t.Fatalf("record %d: %v", i, err)
		}
	}

	s.prunePendingKeys()

	if n, _ := s.store.CountPendingKeys(); n != 2 {
		t.Errorf("count after prune = %d, want 2 (max_rows)", n)
	}
}

// TestLogPendingKey_EnforcesCapImmediately proves max_rows is a true row-count
// ceiling on the unknown-key path, not merely an interval-maintained cleanup: even
// when the TTL prune is inside its no-op interval, recording a new contact caps
// the table after the insert and keeps the current fresh contact.
func TestLogPendingKey_EnforcesCapImmediately(t *testing.T) {
	s, _ := newStormServer(t)
	setPendingCfg(s, 168, 2, 60, 5, 1) // max_rows = 2, interval = 60s

	const key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestImmediateCapKey"
	if _, _, err := s.store.RecordPendingKey("SHA256:old-a", "1:1", key, ""); err != nil {
		t.Fatalf("record old-a: %v", err)
	}
	if _, _, err := s.store.RecordPendingKey("SHA256:old-b", "2:2", key, ""); err != nil {
		t.Fatalf("record old-b: %v", err)
	}
	s.markPendingPruneRan() // force maybePrunePendingKeys to no-op.

	const current = "SHA256:current"
	s.logPendingKey(current, "3.3.3.3:3", key, "")

	rows, err := s.store.ListPendingKeys()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("row count after logPendingKey = %d, want 2", len(rows))
	}
	foundCurrent := false
	for _, row := range rows {
		if row.Fingerprint == current {
			foundCurrent = true
			break
		}
	}
	if !foundCurrent {
		t.Fatalf("current contact was not preserved after immediate cap; rows=%+v", rows)
	}
}

// TestMaybePrunePendingKeys_IntervalGuard proves the opportunistic TTL-prune
// helper runs at most once per prune_interval_seconds. It seeds rows directly
// through the store so it can isolate the maybe-helper; logPendingKey separately
// enforces the hard cap immediately after each unknown-key record.
func TestMaybePrunePendingKeys_IntervalGuard(t *testing.T) {
	s, _ := newStormServer(t)
	setPendingCfg(s, 168, 2, 60, 5, 1) // max_rows = 2, interval = 60s
	s.pendingPruneMu.Lock()
	s.lastPendingPrune = time.Time{}
	s.pendingPruneMu.Unlock()

	const key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestIntervalKey"
	for i := 0; i < 4; i++ {
		if _, _, err := s.store.RecordPendingKey(sprintfFP(i), "1:1", key, ""); err != nil {
			t.Fatalf("record %d: %v", i, err)
		}
	}

	s.maybePrunePendingKeys() // first run: claims the slot, caps to 2
	if n, _ := s.store.CountPendingKeys(); n != 2 {
		t.Fatalf("after first maybePrune count = %d, want 2", n)
	}

	// Add more over-cap rows, then call again immediately — within the interval
	// it must NO-OP (proving the single-flight interval guard).
	for i := 4; i < 7; i++ {
		if _, _, err := s.store.RecordPendingKey(sprintfFP(i), "1:1", key, ""); err != nil {
			t.Fatalf("record %d: %v", i, err)
		}
	}
	s.maybePrunePendingKeys() // within 60s → no-op
	if n, _ := s.store.CountPendingKeys(); n != 5 {
		t.Errorf("after second (in-interval) maybePrune count = %d, want 5 (no-op)", n)
	}
}

func TestNew_MarksStartupPendingPrune(t *testing.T) {
	s, _ := newStormServer(t)
	s.pendingPruneMu.Lock()
	defer s.pendingPruneMu.Unlock()
	if s.lastPendingPrune.IsZero() {
		t.Fatal("startup pending-key prune should seed lastPendingPrune")
	}
}

func sprintfFP(i int) string {
	return "SHA256:fp-" + string(rune('a'+i))
}
