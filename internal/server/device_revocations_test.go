package server

// Phase 16 Gap 1 — tests for processPendingDeviceRevocations and the
// kickRevokedDeviceSession helper.
//
// Coverage:
//   - happy path: queue row → audit entry + kick attempt
//   - missing connected session: queue still drained, audit still
//     written (no-op kick is OK because data-layer revocation
//     already blocked future logins)
//   - kick fires on matching (user, device) pair: DeviceRevoked
//     event encoded + Channel.Close called
//   - kick is a no-op when no matching session
//   - audit entry uses revoke-device action verb
//   - multiple rows in one tick

import (
	"encoding/json"
	"io"
	"strings"
	"sync/atomic"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/brushtailmedia/sshkey-chat/internal/protocol"
)

// noopChannel is a minimal ssh.Channel stub for testing the kick
// helper. Tracks whether Close() was called via an atomic counter so
// tests can assert it. Read/Write/etc. are no-ops; the kick helper
// only ever calls Encoder.Encode (which writes to a separate
// io.Writer) and Channel.Close.
type noopChannel struct {
	closed atomic.Int32
}

func (n *noopChannel) Read(p []byte) (int, error)  { return 0, io.EOF }
func (n *noopChannel) Write(p []byte) (int, error) { return len(p), nil }
func (n *noopChannel) Close() error {
	n.closed.Add(1)
	return nil
}
func (n *noopChannel) CloseWrite() error                                            { return nil }
func (n *noopChannel) SendRequest(name string, wantReply bool, payload []byte) (bool, error) {
	return false, nil
}
func (n *noopChannel) Stderr() io.ReadWriter { return nil }

// Compile-time assertion that noopChannel satisfies ssh.Channel.
var _ ssh.Channel = (*noopChannel)(nil)

// testClientWithChannel is testClientFor + a no-op Channel attached so
// kickRevokedDeviceSession can call Close without a nil dereference.
func testClientWithChannel(userID, deviceID string) (*captureClient, *noopChannel) {
	cc := testClientFor(userID, deviceID)
	ch := &noopChannel{}
	cc.Client.Channel = ch
	return cc, ch
}

// --- Processor tests ---

func TestProcessPendingDeviceRevocations_HappyPath(t *testing.T) {
	s := newTestServer(t)

	// Register a device for alice and revoke it via the CLI side.
	if _, err := s.store.UpsertDevice("alice", "dev_laptop"); err != nil {
		t.Fatalf("upsert device: %v", err)
	}
	if err := s.store.RevokeDevice("alice", "dev_laptop", "stolen"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if err := s.store.RecordPendingDeviceRevocation("alice", "dev_laptop", "stolen", "os:1000"); err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	// Connect alice's laptop session so we can verify the kick fires.
	cc, ch := testClientWithChannel("alice", "dev_laptop")
	s.mu.Lock()
	s.clients["dev_laptop"] = cc.Client
	s.mu.Unlock()

	s.processPendingDeviceRevocations()

	// Verify the kick fired: DeviceRevoked event written to the
	// client's encoder buffer + Channel.Close called once.
	msgs := cc.messages()
	if len(msgs) != 1 {
		t.Fatalf("expected 1 device_revoked event, got %d", len(msgs))
	}
	var event protocol.DeviceRevoked
	if err := json.Unmarshal(msgs[0], &event); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if event.Type != "device_revoked" {
		t.Errorf("type = %q, want device_revoked", event.Type)
	}
	if event.DeviceID != "dev_laptop" {
		t.Errorf("device = %q, want dev_laptop", event.DeviceID)
	}
	if event.Reason != "stolen" {
		t.Errorf("reason = %q, want stolen", event.Reason)
	}
	if got := ch.closed.Load(); got != 1 {
		t.Errorf("Channel.Close called %d times, want 1", got)
	}

	// Queue should be drained.
	pending, _ := s.store.ConsumePendingDeviceRevocations()
	if len(pending) != 0 {
		t.Errorf("queue should be drained, got %d rows", len(pending))
	}
}

// TestProcessPendingDeviceRevocations_NoActiveSessionStillSucceeds
// verifies that a queue row for a device that isn't currently
// connected is still processed (audit entry written, queue drained)
// without panicking. The data-layer revocation already blocked
// future logins, so no live kick is needed and the processor's
// no-op kick is the correct outcome.
func TestProcessPendingDeviceRevocations_NoActiveSessionStillSucceeds(t *testing.T) {
	s := newTestServer(t)

	if err := s.store.RecordPendingDeviceRevocation("alice", "dev_offline", "admin_action", "os:1000"); err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	// No client registered.
	s.processPendingDeviceRevocations()

	// Queue drained.
	pending, _ := s.store.ConsumePendingDeviceRevocations()
	if len(pending) != 0 {
		t.Errorf("queue should be drained, got %d rows", len(pending))
	}
}

// TestProcessPendingDeviceRevocations_KickIsTargeted verifies that
// only the matching (user, device) session is kicked, not other
// sessions for the same user or other devices for other users.
func TestProcessPendingDeviceRevocations_KickIsTargeted(t *testing.T) {
	s := newTestServer(t)

	// alice has two devices, bob has one. Revoke alice's dev_a.
	s.store.UpsertDevice("alice", "dev_a")
	s.store.UpsertDevice("alice", "dev_b")
	s.store.UpsertDevice("bob", "dev_b") // same device-id string, different user
	s.store.RevokeDevice("alice", "dev_a", "test")
	s.store.RecordPendingDeviceRevocation("alice", "dev_a", "test", "os:1000")

	aliceA, chA := testClientWithChannel("alice", "dev_a")
	aliceB, chB := testClientWithChannel("alice", "dev_b")
	bobB, chBobB := testClientWithChannel("bob", "dev_b")

	s.mu.Lock()
	s.clients["alice_a_session"] = aliceA.Client
	s.clients["alice_b_session"] = aliceB.Client
	s.clients["bob_b_session"] = bobB.Client
	s.mu.Unlock()

	s.processPendingDeviceRevocations()

	// alice's dev_a should be kicked.
	if got := chA.closed.Load(); got != 1 {
		t.Errorf("alice/dev_a Close called %d times, want 1", got)
	}
	if len(aliceA.messages()) != 1 {
		t.Errorf("alice/dev_a should have received 1 event, got %d", len(aliceA.messages()))
	}

	// alice's dev_b should NOT be kicked (different device).
	if got := chB.closed.Load(); got != 0 {
		t.Errorf("alice/dev_b Close called %d times, want 0", got)
	}
	if len(aliceB.messages()) != 0 {
		t.Errorf("alice/dev_b should have received 0 events, got %d", len(aliceB.messages()))
	}

	// bob's dev_b should NOT be kicked (different user, same device-id string).
	if got := chBobB.closed.Load(); got != 0 {
		t.Errorf("bob/dev_b Close called %d times, want 0", got)
	}
	if len(bobB.messages()) != 0 {
		t.Errorf("bob/dev_b should have received 0 events, got %d", len(bobB.messages()))
	}
}

func TestProcessPendingDeviceRevocations_AuditCreditsOperator(t *testing.T) {
	s := newTestServer(t)

	s.store.RecordPendingDeviceRevocation("alice", "dev_x", "stolen", "os:5678")
	s.processPendingDeviceRevocations()

	auditBytes, err := readAuditLog(s)
	if err != nil {
		t.Fatalf("read audit: %v", err)
	}
	auditContent := string(auditBytes)

	for _, want := range []string{
		"os:5678",
		"revoke-device",
		"user=alice",
		"device=dev_x",
		"reason=stolen",
	} {
		if !strings.Contains(auditContent, want) {
			t.Errorf("audit log missing %q, got: %q", want, auditContent)
		}
	}
}

func TestProcessPendingDeviceRevocations_MultipleRowsInOneTick(t *testing.T) {
	s := newTestServer(t)

	s.store.RecordPendingDeviceRevocation("alice", "dev_a", "test", "os:1000")
	s.store.RecordPendingDeviceRevocation("alice", "dev_b", "test", "os:1000")
	s.store.RecordPendingDeviceRevocation("bob", "dev_x", "test", "os:1000")

	s.processPendingDeviceRevocations()

	pending, _ := s.store.ConsumePendingDeviceRevocations()
	if len(pending) != 0 {
		t.Errorf("queue should be drained, got %d rows", len(pending))
	}

	// Three audit entries should be present.
	auditBytes, _ := readAuditLog(s)
	count := strings.Count(string(auditBytes), "revoke-device")
	if count != 3 {
		t.Errorf("expected 3 audit entries, got %d", count)
	}
}
