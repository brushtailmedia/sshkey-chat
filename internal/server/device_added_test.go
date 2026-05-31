package server

import (
	"encoding/json"
	"testing"

	"github.com/brushtailmedia/sshkey-chat/internal/protocol"
)

// TestNotifyNewDevice_PushesToOtherSessionsOnly locks in the Tier 1
// shadow-device notification (docs/planning/open/device-identity-transparency.md):
// a freshly-registered device is announced to the user's OTHER connected
// sessions, never echoed back to the new device itself, and never leaked to a
// different user's sessions.
func TestNotifyNewDevice_PushesToOtherSessionsOnly(t *testing.T) {
	s := newTestServer(t)

	aliceOld := testClientFor("alice", "dev_alice_old")
	aliceNew := testClientFor("alice", "dev_alice_new")
	bob := testClientFor("bob", "dev_bob_1")

	s.mu.Lock()
	s.clients["dev_alice_old"] = aliceOld.Client
	s.clients["dev_alice_new"] = aliceNew.Client
	s.clients["dev_bob_1"] = bob.Client
	s.mu.Unlock()

	s.notifyNewDevice("alice", "dev_alice_new")

	// alice's OTHER device is notified about the new one.
	oldMsgs := aliceOld.messages()
	if len(oldMsgs) != 1 {
		t.Fatalf("alice's other session: expected 1 device_added, got %d", len(oldMsgs))
	}
	var added protocol.DeviceAdded
	if err := json.Unmarshal(oldMsgs[0], &added); err != nil {
		t.Fatalf("parse device_added: %v", err)
	}
	if added.Type != "device_added" {
		t.Errorf("type = %q, want device_added", added.Type)
	}
	if added.DeviceID != "dev_alice_new" {
		t.Errorf("device_id = %q, want dev_alice_new", added.DeviceID)
	}
	if added.CreatedAt == "" {
		t.Error("created_at should be set")
	}

	// The NEW device must NOT be notified about itself.
	if n := len(aliceNew.messages()); n != 0 {
		t.Errorf("new device should not be self-notified, got %d messages", n)
	}

	// A different user must NOT be notified.
	if n := len(bob.messages()); n != 0 {
		t.Errorf("bob (different user) should not be notified, got %d messages", n)
	}
}

// TestNotifyNewDevice_NoOtherSessions is a no-op when the user has no other
// connected sessions (the common case: the attacker's device is the only one
// online). Offline sessions catch it via the client's connect-time reconcile.
func TestNotifyNewDevice_NoOtherSessions(t *testing.T) {
	s := newTestServer(t)

	only := testClientFor("alice", "dev_alice_only")
	s.mu.Lock()
	s.clients["dev_alice_only"] = only.Client
	s.mu.Unlock()

	s.notifyNewDevice("alice", "dev_alice_only") // the only session IS the new device

	if n := len(only.messages()); n != 0 {
		t.Errorf("no other sessions → no push; got %d messages", n)
	}
}
