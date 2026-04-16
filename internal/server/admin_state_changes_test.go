package server

// Phase 16 Gap 1 — tests for processPendingAdminStateChanges, the
// shared processor for promote/demote/rename-user. Mirrors the
// retirement/unretirement processor test suites.
//
// Coverage:
//   - happy path for each action: queue row → fresh profile broadcast
//   - missing user: skip + log, no broadcast
//   - audit entry uses the correct action verb per row
//   - wide broadcast: every connected client receives the event
//   - profile carries the post-change state (admin flag, display name)
//   - multiple actions in one tick processed in order

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/brushtailmedia/sshkey-chat/internal/protocol"
	"github.com/brushtailmedia/sshkey-chat/internal/store"
)

// TestProcessPendingAdminStateChanges_Promote verifies that a promote
// row produces a profile broadcast with Admin=true.
func TestProcessPendingAdminStateChanges_Promote(t *testing.T) {
	s := newTestServer(t)

	// CLI side: flip admin flag, then enqueue.
	if err := s.store.SetAdmin("bob", true); err != nil {
		t.Fatalf("set admin: %v", err)
	}
	if err := s.store.RecordPendingAdminStateChange("bob", store.AdminStateChangePromote, "os:1000"); err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	carol := testClientFor("carol", "dev_carol_1")
	s.mu.Lock()
	s.clients["dev_carol_1"] = carol.Client
	s.mu.Unlock()

	s.processPendingAdminStateChanges()

	msgs := carol.messages()
	if len(msgs) != 1 {
		t.Fatalf("expected 1 broadcast, got %d", len(msgs))
	}
	var p protocol.Profile
	if err := json.Unmarshal(msgs[0], &p); err != nil {
		t.Fatalf("parse profile: %v", err)
	}
	if p.Type != "profile" {
		t.Errorf("type = %q, want profile", p.Type)
	}
	if p.User != "bob" {
		t.Errorf("user = %q, want bob", p.User)
	}
	if !p.Admin {
		t.Error("Admin should be true after promote")
	}
}

// TestProcessPendingAdminStateChanges_Demote verifies that a demote
// row produces a profile broadcast with Admin=false.
func TestProcessPendingAdminStateChanges_Demote(t *testing.T) {
	s := newTestServer(t)

	// alice is already an admin in newTestServer. Demote her.
	if err := s.store.SetAdmin("alice", false); err != nil {
		t.Fatalf("set admin: %v", err)
	}
	if err := s.store.RecordPendingAdminStateChange("alice", store.AdminStateChangeDemote, "os:1000"); err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	carol := testClientFor("carol", "dev_carol_1")
	s.mu.Lock()
	s.clients["dev_carol_1"] = carol.Client
	s.mu.Unlock()

	s.processPendingAdminStateChanges()

	msgs := carol.messages()
	if len(msgs) != 1 {
		t.Fatalf("expected 1 broadcast, got %d", len(msgs))
	}
	var p protocol.Profile
	json.Unmarshal(msgs[0], &p)
	if p.Admin {
		t.Error("Admin should be false after demote")
	}
}

// TestProcessPendingAdminStateChanges_Rename verifies that a rename
// row produces a profile broadcast with the new display name.
func TestProcessPendingAdminStateChanges_Rename(t *testing.T) {
	s := newTestServer(t)

	if err := s.store.SetUserDisplayName("bob", "robert"); err != nil {
		t.Fatalf("rename: %v", err)
	}
	if err := s.store.RecordPendingAdminStateChange("bob", store.AdminStateChangeRename, "os:1000"); err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	carol := testClientFor("carol", "dev_carol_1")
	s.mu.Lock()
	s.clients["dev_carol_1"] = carol.Client
	s.mu.Unlock()

	s.processPendingAdminStateChanges()

	msgs := carol.messages()
	if len(msgs) != 1 {
		t.Fatalf("expected 1 broadcast, got %d", len(msgs))
	}
	var p protocol.Profile
	json.Unmarshal(msgs[0], &p)
	if p.DisplayName != "robert" {
		t.Errorf("DisplayName = %q, want robert", p.DisplayName)
	}
}

// TestProcessPendingAdminStateChanges_SkipsMissingUser verifies that
// a queue row referencing a nonexistent user is skipped without
// crashing or broadcasting.
func TestProcessPendingAdminStateChanges_SkipsMissingUser(t *testing.T) {
	s := newTestServer(t)

	if err := s.store.RecordPendingAdminStateChange("usr_ghost", store.AdminStateChangePromote, "os:1000"); err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	carol := testClientFor("carol", "dev_carol_1")
	s.mu.Lock()
	s.clients["dev_carol_1"] = carol.Client
	s.mu.Unlock()

	s.processPendingAdminStateChanges()

	if msgs := carol.messages(); len(msgs) != 0 {
		t.Errorf("expected no broadcasts for missing user, got %d", len(msgs))
	}

	// Queue should still be drained.
	pending, _ := s.store.ConsumePendingAdminStateChanges()
	if len(pending) != 0 {
		t.Errorf("queue should be drained on skip, got %d rows", len(pending))
	}
}

// TestProcessPendingAdminStateChanges_AuditCreditsByAction verifies
// that the audit log entry uses the correct CLI verb name per
// action, not the schema enum value.
func TestProcessPendingAdminStateChanges_AuditCreditsByAction(t *testing.T) {
	s := newTestServer(t)

	// Promote bob, demote alice, rename carol — three rows, one
	// audit entry per row.
	s.store.SetAdmin("bob", true)
	s.store.RecordPendingAdminStateChange("bob", store.AdminStateChangePromote, "os:1000")
	s.store.SetAdmin("alice", false)
	s.store.RecordPendingAdminStateChange("alice", store.AdminStateChangeDemote, "os:1000")
	s.store.SetUserDisplayName("carol", "carolyn")
	s.store.RecordPendingAdminStateChange("carol", store.AdminStateChangeRename, "os:1000")

	s.processPendingAdminStateChanges()

	auditBytes, err := readAuditLog(s)
	if err != nil {
		t.Fatalf("read audit: %v", err)
	}
	auditContent := string(auditBytes)

	for _, want := range []string{
		"promote",
		"demote",
		"rename-user",
		"user=bob",
		"user=alice",
		"user=carol",
	} {
		if !strings.Contains(auditContent, want) {
			t.Errorf("audit log missing %q, got: %q", want, auditContent)
		}
	}
}

// TestProcessPendingAdminStateChanges_BroadcastsToAllClients verifies
// the wide broadcast pattern.
func TestProcessPendingAdminStateChanges_BroadcastsToAllClients(t *testing.T) {
	s := newTestServer(t)

	s.store.SetAdmin("bob", true)
	s.store.RecordPendingAdminStateChange("bob", store.AdminStateChangePromote, "os:1000")

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

	s.processPendingAdminStateChanges()

	for _, c := range clients {
		msgs := c.messages()
		if len(msgs) != 1 {
			t.Errorf("client %s: expected 1 broadcast, got %d", c.Client.UserID, len(msgs))
		}
	}
}

// TestProcessPendingAdminStateChanges_MultipleRowsInOneTick verifies
// that a single processor tick can handle multiple rows and that
// each one produces its own broadcast.
func TestProcessPendingAdminStateChanges_MultipleRowsInOneTick(t *testing.T) {
	s := newTestServer(t)

	s.store.SetAdmin("bob", true)
	s.store.RecordPendingAdminStateChange("bob", store.AdminStateChangePromote, "os:1000")
	s.store.SetUserDisplayName("carol", "carolyn")
	s.store.RecordPendingAdminStateChange("carol", store.AdminStateChangeRename, "os:1000")

	dave := testClientFor("dave", "dev_dave_1")
	s.mu.Lock()
	s.clients["dev_dave_1"] = dave.Client
	s.mu.Unlock()

	s.processPendingAdminStateChanges()

	msgs := dave.messages()
	if len(msgs) != 2 {
		t.Fatalf("expected 2 broadcasts (promote + rename), got %d", len(msgs))
	}

	// First broadcast should be bob's profile (promote).
	var p1 protocol.Profile
	json.Unmarshal(msgs[0], &p1)
	if p1.User != "bob" || !p1.Admin {
		t.Errorf("first broadcast wrong: %+v", p1)
	}

	// Second broadcast should be carol's profile (rename).
	var p2 protocol.Profile
	json.Unmarshal(msgs[1], &p2)
	if p2.User != "carol" || p2.DisplayName != "carolyn" {
		t.Errorf("second broadcast wrong: %+v", p2)
	}
}

// TestBroadcastUserProfile_PopulatesAllFields verifies that the
// profile broadcast helper populates every field the client needs to
// render the user (Admin, DisplayName, PubKey, KeyFingerprint, etc.)
// — catching the failure mode where we forget to copy a field from
// users.db into the broadcast payload.
func TestBroadcastUserProfile_PopulatesAllFields(t *testing.T) {
	s := newTestServer(t)

	carol := testClientFor("carol", "dev_carol_1")
	s.mu.Lock()
	s.clients["dev_carol_1"] = carol.Client
	s.mu.Unlock()

	user := s.store.GetUserByID("alice")
	if user == nil {
		t.Fatal("alice should exist")
	}
	s.broadcastUserProfile(user)

	msgs := carol.messages()
	if len(msgs) != 1 {
		t.Fatalf("expected 1 broadcast, got %d", len(msgs))
	}
	var p protocol.Profile
	if err := json.Unmarshal(msgs[0], &p); err != nil {
		t.Fatalf("parse: %v", err)
	}

	if p.User != "alice" {
		t.Errorf("User = %q", p.User)
	}
	if p.DisplayName == "" {
		t.Error("DisplayName empty")
	}
	if p.PubKey == "" {
		t.Error("PubKey empty")
	}
	if p.KeyFingerprint == "" {
		t.Error("KeyFingerprint empty")
	}
	if !strings.HasPrefix(p.KeyFingerprint, "SHA256:") {
		t.Errorf("KeyFingerprint should start with SHA256:, got %q", p.KeyFingerprint)
	}
	// alice is admin in newTestServer.
	if !p.Admin {
		t.Error("Admin should be true (alice is admin in test fixtures)")
	}
}
