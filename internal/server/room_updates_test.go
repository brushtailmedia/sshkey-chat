package server

// Phase 16 Gap 1 — tests for processPendingRoomUpdates.
//
// Coverage:
//   - happy path for each action (update-topic, rename-room)
//   - missing room: skip + log
//   - audit credit per action verb
//   - narrow broadcast: only members of the affected room receive
//     the event (non-members do not)
//   - multiple rooms in one tick

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/brushtailmedia/sshkey-chat/internal/protocol"
	"github.com/brushtailmedia/sshkey-chat/internal/store"
)

// TestProcessPendingRoomUpdates_UpdateTopic verifies that an
// update-topic row produces a room_updated broadcast with the new
// topic.
func TestProcessPendingRoomUpdates_UpdateTopic(t *testing.T) {
	s := newTestServer(t)
	generalID := s.store.RoomDisplayNameToID("general")
	if generalID == "" {
		t.Fatal("general room should exist in test fixtures")
	}

	// CLI side: update topic, then enqueue.
	if err := s.store.SetRoomTopic(generalID, "fresh topic"); err != nil {
		t.Fatalf("set topic: %v", err)
	}
	if err := s.store.RecordPendingRoomUpdate(generalID, store.RoomUpdateActionUpdateTopic, "os:1000"); err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	// alice is a member of general (per newTestServer fixtures).
	alice := testClientFor("alice", "dev_alice_1")
	s.mu.Lock()
	s.clients["dev_alice_1"] = alice.Client
	s.mu.Unlock()

	s.processPendingRoomUpdates()

	msgs := alice.messages()
	if len(msgs) != 1 {
		t.Fatalf("expected 1 broadcast, got %d", len(msgs))
	}
	var ru protocol.RoomUpdated
	if err := json.Unmarshal(msgs[0], &ru); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if ru.Type != "room_updated" {
		t.Errorf("type = %q, want room_updated", ru.Type)
	}
	if ru.Room != generalID {
		t.Errorf("room = %q, want %s", ru.Room, generalID)
	}
	if ru.Topic != "fresh topic" {
		t.Errorf("topic = %q, want fresh topic", ru.Topic)
	}
	if ru.DisplayName != "general" {
		t.Errorf("display_name = %q, want general", ru.DisplayName)
	}
}

// TestProcessPendingRoomUpdates_RenameRoom verifies that a
// rename-room row produces a room_updated broadcast with the new
// display name.
func TestProcessPendingRoomUpdates_RenameRoom(t *testing.T) {
	s := newTestServer(t)
	generalID := s.store.RoomDisplayNameToID("general")

	if err := s.store.SetRoomDisplayName(generalID, "main"); err != nil {
		t.Fatalf("rename: %v", err)
	}
	if err := s.store.RecordPendingRoomUpdate(generalID, store.RoomUpdateActionRenameRoom, "os:1000"); err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	alice := testClientFor("alice", "dev_alice_1")
	s.mu.Lock()
	s.clients["dev_alice_1"] = alice.Client
	s.mu.Unlock()

	s.processPendingRoomUpdates()

	msgs := alice.messages()
	if len(msgs) != 1 {
		t.Fatalf("expected 1 broadcast, got %d", len(msgs))
	}
	var ru protocol.RoomUpdated
	json.Unmarshal(msgs[0], &ru)
	if ru.DisplayName != "main" {
		t.Errorf("display_name = %q, want main", ru.DisplayName)
	}
}

// TestProcessPendingRoomUpdates_SkipsMissingRoom verifies that a
// queue row referencing a nonexistent room is skipped without
// crashing or broadcasting.
func TestProcessPendingRoomUpdates_SkipsMissingRoom(t *testing.T) {
	s := newTestServer(t)

	if err := s.store.RecordPendingRoomUpdate("rm_ghost", store.RoomUpdateActionUpdateTopic, "os:1000"); err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	alice := testClientFor("alice", "dev_alice_1")
	s.mu.Lock()
	s.clients["dev_alice_1"] = alice.Client
	s.mu.Unlock()

	s.processPendingRoomUpdates()

	if msgs := alice.messages(); len(msgs) != 0 {
		t.Errorf("expected no broadcasts for missing room, got %d", len(msgs))
	}

	pending, _ := s.store.ConsumePendingRoomUpdates()
	if len(pending) != 0 {
		t.Errorf("queue should be drained on skip, got %d rows", len(pending))
	}
}

// TestProcessPendingRoomUpdates_NarrowBroadcastMembersOnly verifies
// that the broadcast goes ONLY to members of the affected room, not
// to every connected client. dave (not a member of general) should
// receive nothing.
func TestProcessPendingRoomUpdates_NarrowBroadcastMembersOnly(t *testing.T) {
	s := newTestServer(t)
	generalID := s.store.RoomDisplayNameToID("general")

	// Insert dave but DON'T add him to general.
	if err := s.store.InsertUser("dave", "ssh-ed25519 AAAA dave-fake", "dave"); err != nil {
		t.Fatalf("insert dave: %v", err)
	}

	s.store.SetRoomTopic(generalID, "members-only test")
	s.store.RecordPendingRoomUpdate(generalID, store.RoomUpdateActionUpdateTopic, "os:1000")

	// alice IS in general; dave is NOT.
	alice := testClientFor("alice", "dev_alice_1")
	dave := testClientFor("dave", "dev_dave_1")
	s.mu.Lock()
	s.clients["dev_alice_1"] = alice.Client
	s.clients["dev_dave_1"] = dave.Client
	s.mu.Unlock()

	s.processPendingRoomUpdates()

	if msgs := alice.messages(); len(msgs) != 1 {
		t.Errorf("alice (member) should receive 1 broadcast, got %d", len(msgs))
	}
	if msgs := dave.messages(); len(msgs) != 0 {
		t.Errorf("dave (non-member) should receive 0 broadcasts, got %d", len(msgs))
	}
}

// TestProcessPendingRoomUpdates_AuditCreditsByAction verifies that
// the audit log entry uses the correct CLI verb name per action.
func TestProcessPendingRoomUpdates_AuditCreditsByAction(t *testing.T) {
	s := newTestServer(t)
	generalID := s.store.RoomDisplayNameToID("general")
	engID := s.store.RoomDisplayNameToID("engineering")

	s.store.SetRoomTopic(generalID, "topic A")
	s.store.RecordPendingRoomUpdate(generalID, store.RoomUpdateActionUpdateTopic, "os:1000")
	s.store.SetRoomDisplayName(engID, "eng")
	s.store.RecordPendingRoomUpdate(engID, store.RoomUpdateActionRenameRoom, "os:1000")

	s.processPendingRoomUpdates()

	auditBytes, err := readAuditLog(s)
	if err != nil {
		t.Fatalf("read audit: %v", err)
	}
	auditContent := string(auditBytes)

	for _, want := range []string{
		"update-topic",
		"rename-room",
		"room=" + generalID,
		"room=" + engID,
	} {
		if !strings.Contains(auditContent, want) {
			t.Errorf("audit log missing %q, got: %q", want, auditContent)
		}
	}
}

// TestProcessPendingRoomUpdates_MultipleRowsInOneTick verifies that
// multiple queue rows in a single tick all get processed.
func TestProcessPendingRoomUpdates_MultipleRowsInOneTick(t *testing.T) {
	s := newTestServer(t)
	generalID := s.store.RoomDisplayNameToID("general")
	engID := s.store.RoomDisplayNameToID("engineering")

	s.store.SetRoomTopic(generalID, "general topic")
	s.store.RecordPendingRoomUpdate(generalID, store.RoomUpdateActionUpdateTopic, "os:1000")
	s.store.SetRoomTopic(engID, "eng topic")
	s.store.RecordPendingRoomUpdate(engID, store.RoomUpdateActionUpdateTopic, "os:1000")

	// alice is a member of both rooms.
	alice := testClientFor("alice", "dev_alice_1")
	s.mu.Lock()
	s.clients["dev_alice_1"] = alice.Client
	s.mu.Unlock()

	s.processPendingRoomUpdates()

	msgs := alice.messages()
	if len(msgs) != 2 {
		t.Fatalf("expected 2 broadcasts, got %d", len(msgs))
	}
}
