package server

// Phase 17b Step 3 — auto-revoke processor tests.
//
// Coverage matrix:
//
//   - buildAutoRevokeReason format (D2 spec)
//   - Reason falls back to "signal X" prefix for unknown signal
//   - resolveDeviceUser: active-client fast path
//   - resolveDeviceUser: store-fallback slow path
//   - resolveDeviceUser: returns false when no mapping
//   - processAutoRevoke enqueues when device crosses threshold
//   - processAutoRevoke respects enabled=false (no enqueue; Info log)
//   - processAutoRevoke is idempotent (skips already-revoked device)
//   - processAutoRevoke handles multiple devices independently
//   - processAutoRevoke no-op when no thresholds configured
//   - processAutoRevoke handles sub-threshold devices (no enqueue)
//   - processAutoRevoke writes audit log on enqueue
//
// Tests drive counter state directly via s.counters.Inc and invoke
// processAutoRevoke() once, synchronously — no need to wait for the
// ticker goroutine. newTestServer doesn't start ListenAndServe, so
// runAutoRevokeProcessor isn't running; tests have full control of
// when evaluation fires.

import (
	"bytes"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"

	"github.com/brushtailmedia/sshkey-chat/internal/audit"
	"github.com/brushtailmedia/sshkey-chat/internal/config"
	"github.com/brushtailmedia/sshkey-chat/internal/counters"
)

func TestBuildAutoRevokeReason_Format(t *testing.T) {
	got := buildAutoRevokeReason(counters.SignalMalformedFrame, 3, 60)
	want := "Automatic revocation: too many malformed frames (3 events in 60s)"
	if got != want {
		t.Errorf("buildAutoRevokeReason = %q, want %q", got, want)
	}
}

func TestBuildAutoRevokeReason_ReconnectFlood(t *testing.T) {
	// Phase 17b Step 5c: reconnect_flood must be both an accepted
	// AutoRevokeSignals entry AND produce a clean human-readable
	// reason string. Locks in the end-to-end wiring across the
	// counters constant, AutoRevokeSignals slice, and the
	// autoRevokeDescriptions map.
	got := buildAutoRevokeReason(counters.SignalReconnectFlood, 10, 60)
	want := "Automatic revocation: reconnecting too rapidly (10 events in 60s)"
	if got != want {
		t.Errorf("buildAutoRevokeReason(reconnect_flood) = %q, want %q", got, want)
	}
}

func TestBuildAutoRevokeReason_UnknownSignalFallback(t *testing.T) {
	got := buildAutoRevokeReason("brand_new_signal", 5, 30)
	want := "Automatic revocation: signal brand_new_signal (5 events in 30s)"
	if got != want {
		t.Errorf("unknown-signal fallback = %q, want %q", got, want)
	}
}

func TestBuildAutoRevokeReason_AllMappedSignalsCovered(t *testing.T) {
	// Every signal in AutoRevokeSignals should map to a human
	// description. A signal in the slice but missing from the map
	// means the operator-facing message would fall back to the
	// generic "signal X" text, which is lower-quality UX.
	for _, sig := range counters.AutoRevokeSignals {
		if _, ok := autoRevokeDescriptions[sig]; !ok {
			t.Errorf("signal %q in AutoRevokeSignals but missing from autoRevokeDescriptions", sig)
		}
	}
}

func TestResolveDeviceUser_ActiveClient(t *testing.T) {
	s := newTestServer(t)

	// Register alice's device via the store first (so store lookup
	// would also find it — this test confirms the fast path is taken
	// rather than falling through, but either way returns alice).
	if _, err := s.store.UpsertDevice("alice", "dev_alice_active"); err != nil {
		t.Fatalf("UpsertDevice: %v", err)
	}

	// Add a fake active client entry.
	s.mu.Lock()
	s.clients["session_1"] = &Client{UserID: "alice", DeviceID: "dev_alice_active"}
	s.mu.Unlock()

	user, ok := s.resolveDeviceUser("dev_alice_active")
	if !ok {
		t.Fatal("resolveDeviceUser returned ok=false for active client")
	}
	if user != "alice" {
		t.Errorf("user = %q, want alice", user)
	}
}

func TestResolveDeviceUser_StoreFallback(t *testing.T) {
	s := newTestServer(t)

	if _, err := s.store.UpsertDevice("bob", "dev_bob_offline"); err != nil {
		t.Fatalf("UpsertDevice: %v", err)
	}

	// Device not in s.clients — must fall through to store lookup.
	user, ok := s.resolveDeviceUser("dev_bob_offline")
	if !ok {
		t.Fatal("resolveDeviceUser returned ok=false for offline-but-registered device")
	}
	if user != "bob" {
		t.Errorf("user = %q, want bob", user)
	}
}

func TestResolveDeviceUser_NoMapping(t *testing.T) {
	s := newTestServer(t)
	_, ok := s.resolveDeviceUser("dev_never_existed")
	if ok {
		t.Error("resolveDeviceUser returned ok=true for unknown device")
	}
}

// withAutoRevokeConfig is a test helper that installs a Phase 17b
// AutoRevoke config on the server. Matches the read/write dance used
// by other rate-limit-adjusting tests (see rate_limit_step5_test.go).
func withAutoRevokeConfig(t *testing.T, s *Server, enabled bool, thresholds map[string]string) {
	t.Helper()
	s.cfg.Lock()
	s.cfg.Server.Server.AutoRevoke = config.AutoRevokeSection{
		Enabled:    enabled,
		Thresholds: thresholds,
	}
	s.cfg.Unlock()
}

// captureServerLogs swaps the server's slog logger for one writing to
// the given buffer. Returns a restore func for t.Cleanup.
func captureServerLogs(s *Server, buf *bytes.Buffer, level slog.Level) {
	s.logger = slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: level}))
}

func TestProcessAutoRevoke_EnqueuesWhenThresholdCrossed(t *testing.T) {
	s := newTestServer(t)
	var logBuf bytes.Buffer
	captureServerLogs(s, &logBuf, slog.LevelWarn)

	if _, err := s.store.UpsertDevice("alice", "dev_alice_bad"); err != nil {
		t.Fatalf("UpsertDevice: %v", err)
	}

	// Cross threshold: 3 events in 60s.
	for i := 0; i < 3; i++ {
		s.counters.Inc(counters.SignalMalformedFrame, "dev_alice_bad")
	}

	withAutoRevokeConfig(t, s, true, map[string]string{
		counters.SignalMalformedFrame: "3:60",
	})

	s.processAutoRevoke()

	pending, err := s.store.ConsumePendingDeviceRevocations()
	if err != nil {
		t.Fatalf("ConsumePendingDeviceRevocations: %v", err)
	}
	if len(pending) != 1 {
		t.Fatalf("len(pending) = %d, want 1", len(pending))
	}
	p := pending[0]
	if p.UserID != "alice" {
		t.Errorf("pending.UserID = %q, want alice", p.UserID)
	}
	if p.DeviceID != "dev_alice_bad" {
		t.Errorf("pending.DeviceID = %q, want dev_alice_bad", p.DeviceID)
	}
	if p.RevokedBy != "server:auto_revoke" {
		t.Errorf("pending.RevokedBy = %q, want server:auto_revoke", p.RevokedBy)
	}
	wantReason := "Automatic revocation: too many malformed frames (3 events in 60s)"
	if p.Reason != wantReason {
		t.Errorf("pending.Reason = %q, want %q", p.Reason, wantReason)
	}

	if !strings.Contains(logBuf.String(), `level=WARN`) {
		t.Errorf("expected WARN log from enqueue path, got: %q", logBuf.String())
	}
	if !strings.Contains(logBuf.String(), `msg=auto_revoke`) {
		t.Errorf("expected auto_revoke msg in log, got: %q", logBuf.String())
	}
}

func TestProcessAutoRevoke_ObserverModeDoesNotEnqueue(t *testing.T) {
	s := newTestServer(t)
	var logBuf bytes.Buffer
	captureServerLogs(s, &logBuf, slog.LevelInfo)

	if _, err := s.store.UpsertDevice("alice", "dev_alice_observed"); err != nil {
		t.Fatalf("UpsertDevice: %v", err)
	}

	for i := 0; i < 5; i++ {
		s.counters.Inc(counters.SignalMalformedFrame, "dev_alice_observed")
	}

	withAutoRevokeConfig(t, s, false, map[string]string{
		counters.SignalMalformedFrame: "3:60",
	})

	s.processAutoRevoke()

	pending, err := s.store.ConsumePendingDeviceRevocations()
	if err != nil {
		t.Fatalf("ConsumePendingDeviceRevocations: %v", err)
	}
	if len(pending) != 0 {
		t.Errorf("observer mode enqueued %d rows, want 0", len(pending))
	}

	// Info-level "auto_revoke_would_fire" log must have fired instead.
	if !strings.Contains(logBuf.String(), `msg=auto_revoke_would_fire`) {
		t.Errorf("expected auto_revoke_would_fire log in observer mode, got: %q", logBuf.String())
	}
	if strings.Contains(logBuf.String(), `msg=auto_revoke `) {
		t.Errorf("observer mode should NOT emit auto_revoke WARN log, got: %q", logBuf.String())
	}
}

func TestProcessAutoRevoke_IdempotentSkipsAlreadyRevoked(t *testing.T) {
	s := newTestServer(t)
	captureServerLogs(s, &bytes.Buffer{}, slog.LevelWarn)

	if _, err := s.store.UpsertDevice("alice", "dev_alice_pre_revoked"); err != nil {
		t.Fatalf("UpsertDevice: %v", err)
	}
	// Pre-revoke the device (simulates admin-revoke between ticks).
	if err := s.store.RevokeDevice("alice", "dev_alice_pre_revoked", "admin_test"); err != nil {
		t.Fatalf("RevokeDevice: %v", err)
	}

	for i := 0; i < 10; i++ {
		s.counters.Inc(counters.SignalMalformedFrame, "dev_alice_pre_revoked")
	}

	withAutoRevokeConfig(t, s, true, map[string]string{
		counters.SignalMalformedFrame: "3:60",
	})

	s.processAutoRevoke()

	pending, err := s.store.ConsumePendingDeviceRevocations()
	if err != nil {
		t.Fatalf("ConsumePendingDeviceRevocations: %v", err)
	}
	if len(pending) != 0 {
		t.Errorf("already-revoked device enqueued %d rows, want 0 (idempotency)", len(pending))
	}
}

func TestProcessAutoRevoke_MultipleDevicesIndependent(t *testing.T) {
	s := newTestServer(t)
	captureServerLogs(s, &bytes.Buffer{}, slog.LevelWarn)

	devs := []struct {
		user, device string
	}{
		{"alice", "dev_alice_multi"},
		{"bob", "dev_bob_multi"},
		{"carol", "dev_carol_multi"},
	}
	for _, d := range devs {
		if _, err := s.store.UpsertDevice(d.user, d.device); err != nil {
			t.Fatalf("UpsertDevice(%s): %v", d.user, err)
		}
		for i := 0; i < 4; i++ {
			s.counters.Inc(counters.SignalMalformedFrame, d.device)
		}
	}

	withAutoRevokeConfig(t, s, true, map[string]string{
		counters.SignalMalformedFrame: "3:60",
	})

	s.processAutoRevoke()

	pending, err := s.store.ConsumePendingDeviceRevocations()
	if err != nil {
		t.Fatalf("ConsumePendingDeviceRevocations: %v", err)
	}
	if len(pending) != 3 {
		t.Fatalf("len(pending) = %d, want 3 (one per device)", len(pending))
	}

	seen := map[string]bool{}
	for _, p := range pending {
		seen[p.DeviceID] = true
	}
	for _, d := range devs {
		if !seen[d.device] {
			t.Errorf("device %s missing from enqueue result", d.device)
		}
	}
}

func TestProcessAutoRevoke_SubThresholdSkipped(t *testing.T) {
	s := newTestServer(t)
	captureServerLogs(s, &bytes.Buffer{}, slog.LevelWarn)

	if _, err := s.store.UpsertDevice("alice", "dev_alice_borderline"); err != nil {
		t.Fatalf("UpsertDevice: %v", err)
	}
	// 2 events — under threshold of 3.
	for i := 0; i < 2; i++ {
		s.counters.Inc(counters.SignalMalformedFrame, "dev_alice_borderline")
	}

	withAutoRevokeConfig(t, s, true, map[string]string{
		counters.SignalMalformedFrame: "3:60",
	})

	s.processAutoRevoke()

	pending, err := s.store.ConsumePendingDeviceRevocations()
	if err != nil {
		t.Fatalf("ConsumePendingDeviceRevocations: %v", err)
	}
	if len(pending) != 0 {
		t.Errorf("sub-threshold device enqueued %d rows, want 0", len(pending))
	}
}

func TestProcessAutoRevoke_NoThresholdsNoOp(t *testing.T) {
	s := newTestServer(t)
	captureServerLogs(s, &bytes.Buffer{}, slog.LevelWarn)

	if _, err := s.store.UpsertDevice("alice", "dev_alice_no_thresh"); err != nil {
		t.Fatalf("UpsertDevice: %v", err)
	}
	for i := 0; i < 100; i++ {
		s.counters.Inc(counters.SignalMalformedFrame, "dev_alice_no_thresh")
	}

	withAutoRevokeConfig(t, s, true, nil) // no thresholds

	s.processAutoRevoke()

	pending, err := s.store.ConsumePendingDeviceRevocations()
	if err != nil {
		t.Fatalf("ConsumePendingDeviceRevocations: %v", err)
	}
	if len(pending) != 0 {
		t.Errorf("no-thresholds config enqueued %d rows, want 0", len(pending))
	}
}

func TestProcessAutoRevoke_WritesAuditLog(t *testing.T) {
	s := newTestServer(t)
	captureServerLogs(s, &bytes.Buffer{}, slog.LevelWarn)

	if _, err := s.store.UpsertDevice("alice", "dev_alice_audit"); err != nil {
		t.Fatalf("UpsertDevice: %v", err)
	}
	for i := 0; i < 5; i++ {
		s.counters.Inc(counters.SignalInvalidNanoID, "dev_alice_audit")
	}

	withAutoRevokeConfig(t, s, true, map[string]string{
		counters.SignalInvalidNanoID: "3:60",
	})

	s.processAutoRevoke()

	// Read audit log. audit.Log writes to <dataDir>/audit.log via
	// audit.Log.Log (package-level Log type; instance at s.audit).
	// The audit package's Read function is the programmatic reader.
	entries, err := audit.Read(filepath.Join(s.dataDir, "audit.log"), audit.ReadOptions{Limit: 10})
	if err != nil {
		t.Fatalf("audit.Read: %v", err)
	}
	var found bool
	for _, e := range entries {
		if e.Action == "auto-revoke-device" &&
			strings.Contains(e.Details, "dev_alice_audit") &&
			strings.Contains(e.Details, counters.SignalInvalidNanoID) {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("audit log missing auto-revoke entry, entries: %v", entries)
	}
}
