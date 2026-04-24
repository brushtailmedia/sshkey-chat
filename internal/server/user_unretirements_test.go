package server

// Phase 16 Gap 1 — tests for processPendingUserUnretirements.
//
// Mirrors the user_retirements_test.go suite. Coverage:
//   - happy path: queue row → user_unretired broadcast fires
//   - missing user: skip + log
//   - still-retired user (CLI bug): skip + log without broadcasting
//   - audit entry credits the operator
//   - queue is drained even on skipped rows

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/brushtailmedia/sshkey-chat/internal/protocol"
)

// TestProcessPendingUserUnretirements_HappyPath verifies the
// end-to-end flow: enqueue an unretirement, run the processor, check
// that user_unretired was broadcast to a connected client.
func TestProcessPendingUserUnretirements_HappyPath(t *testing.T) {
	s := newTestServer(t)

	// Retire bob first (the CLI side of retire-user does this; for
	// this test we just call the store helpers directly).
	if err := s.store.SetUserRetired("bob", "test"); err != nil {
		t.Fatalf("retire: %v", err)
	}
	// Then unretire — first the CLI flips the flag, then enqueues.
	if err := s.store.SetUserUnretired("bob"); err != nil {
		t.Fatalf("unretire: %v", err)
	}
	if err := s.store.RecordPendingUserUnretirement("bob", "os:1000"); err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	// Set up a fake connected client to receive the broadcast.
	carol := testClientFor("carol", "dev_carol_1")
	s.mu.Lock()
	s.clients["dev_carol_1"] = carol.Client
	s.mu.Unlock()

	// Run the processor.
	s.processPendingUserUnretirements()

	// Carol should have received a user_unretired event for bob.
	msgs := carol.messages()
	if len(msgs) != 1 {
		t.Fatalf("expected 1 broadcast, got %d", len(msgs))
	}
	var event protocol.UserUnretired
	if err := json.Unmarshal(msgs[0], &event); err != nil {
		t.Fatalf("parse event: %v", err)
	}
	if event.Type != "user_unretired" {
		t.Errorf("event type = %q, want user_unretired", event.Type)
	}
	if event.User != "bob" {
		t.Errorf("event user = %q, want bob", event.User)
	}
	if event.Ts == 0 {
		t.Error("event ts should be populated")
	}

	// Queue should be drained.
	pending, _ := s.store.ConsumePendingUserUnretirements()
	if len(pending) != 0 {
		t.Errorf("queue should be empty after processing, got %d rows", len(pending))
	}
}

// TestProcessPendingUserUnretirements_SkipsMissingUser verifies that
// a queue row referencing a nonexistent user is logged + skipped
// without crashing or broadcasting.
func TestProcessPendingUserUnretirements_SkipsMissingUser(t *testing.T) {
	s := newTestServer(t)

	if err := s.store.RecordPendingUserUnretirement("usr_ghost", "os:1000"); err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	carol := testClientFor("carol", "dev_carol_1")
	s.mu.Lock()
	s.clients["dev_carol_1"] = carol.Client
	s.mu.Unlock()

	s.processPendingUserUnretirements()

	if msgs := carol.messages(); len(msgs) != 0 {
		t.Errorf("expected no broadcasts for missing user, got %d", len(msgs))
	}

	// Queue should still be drained.
	pending, _ := s.store.ConsumePendingUserUnretirements()
	if len(pending) != 0 {
		t.Errorf("queue should be drained even on skip, got %d rows", len(pending))
	}
}

// TestProcessPendingUserUnretirements_SkipsStillRetiredUser verifies
// that a queue row pointing at a user whose retired flag is STILL
// set (CLI bug — flag should be cleared before enqueue) is skipped
// and not broadcast. The processor refuses to act on its own.
func TestProcessPendingUserUnretirements_SkipsStillRetiredUser(t *testing.T) {
	s := newTestServer(t)

	// Retire bob and leave him retired.
	if err := s.store.SetUserRetired("bob", "test"); err != nil {
		t.Fatalf("retire: %v", err)
	}
	// Enqueue an unretirement WITHOUT first calling SetUserUnretired.
	if err := s.store.RecordPendingUserUnretirement("bob", "os:1000"); err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	carol := testClientFor("carol", "dev_carol_1")
	s.mu.Lock()
	s.clients["dev_carol_1"] = carol.Client
	s.mu.Unlock()

	s.processPendingUserUnretirements()

	if msgs := carol.messages(); len(msgs) != 0 {
		t.Errorf("expected no broadcasts for still-retired user, got %d", len(msgs))
	}

	// Bob should still be retired (processor didn't touch the flag).
	bob := s.store.GetUserByID("bob")
	if bob == nil || !bob.Retired {
		t.Error("bob should still be retired — processor must not flip the flag")
	}
}

// TestProcessPendingUserUnretirements_AuditEntryCreditsOperator
// verifies the operator credit audit entry.
func TestProcessPendingUserUnretirements_AuditEntryCreditsOperator(t *testing.T) {
	s := newTestServer(t)

	if err := s.store.SetUserRetired("bob", "test"); err != nil {
		t.Fatalf("retire: %v", err)
	}
	if err := s.store.SetUserUnretired("bob"); err != nil {
		t.Fatalf("unretire: %v", err)
	}
	if err := s.store.RecordPendingUserUnretirement("bob", "os:5678"); err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	s.processPendingUserUnretirements()

	auditBytes, err := readAuditLog(s)
	if err != nil {
		t.Fatalf("read audit: %v", err)
	}
	auditContent := string(auditBytes)

	if !strings.Contains(auditContent, "os:5678") {
		t.Errorf("audit log missing operator source 'os:5678': %q", auditContent)
	}
	if !strings.Contains(auditContent, "unretire-user") {
		t.Errorf("audit log missing 'unretire-user' action: %q", auditContent)
	}
	if !strings.Contains(auditContent, "user=bob") {
		t.Errorf("audit log missing 'user=bob': %q", auditContent)
	}
}

// TestProcessPendingUserUnretirements_BroadcastsToAllClients
// verifies the wide broadcast pattern — every connected client
// receives the event, not just members of contexts the user is
// (or was) in. Matches the user_retired broadcast pattern.
func TestProcessPendingUserUnretirements_BroadcastsToAllClients(t *testing.T) {
	s := newTestServer(t)

	if err := s.store.SetUserRetired("bob", "test"); err != nil {
		t.Fatalf("retire: %v", err)
	}
	if err := s.store.SetUserUnretired("bob"); err != nil {
		t.Fatalf("unretire: %v", err)
	}
	if err := s.store.RecordPendingUserUnretirement("bob", "os:1000"); err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	// Connect three clients with different IDs.
	clients := []*captureClient{
		testClientFor("alice", "dev_alice_1"),
		testClientFor("carol", "dev_carol_1"),
		testClientFor("dave", "dev_dave_1"),
	}
	s.mu.Lock()
	for _, c := range clients {
		s.clients[c.Client.DeviceID] = c.Client
	}
	s.mu.Unlock()

	s.processPendingUserUnretirements()

	for _, c := range clients {
		msgs := c.messages()
		if len(msgs) != 1 {
			t.Errorf("client %s: expected 1 broadcast, got %d", c.Client.UserID, len(msgs))
		}
	}
}
