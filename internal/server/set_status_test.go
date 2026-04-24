package server

import (
	"encoding/json"
	"testing"

	"github.com/brushtailmedia/sshkey-chat/internal/protocol"
)

func TestHandleSetStatus_HappyPath(t *testing.T) {
	s := newTestServer(t)
	alice := testClientFor("alice", "dev_alice_status")

	raw, _ := json.Marshal(protocol.SetStatus{
		Type: "set_status",
		Text: "on-call today",
	})
	s.handleSetStatus(alice.Client, raw)

	// set_status is broadcast-less (no direct reply).
	if got := len(alice.messages()); got != 0 {
		t.Fatalf("expected no direct reply, got %d messages", got)
	}

	var got string
	err := s.store.DataDB().QueryRow(`SELECT status_text FROM profiles WHERE user = ?`, "alice").Scan(&got)
	if err != nil {
		t.Fatalf("query status_text: %v", err)
	}
	if got != "on-call today" {
		t.Fatalf("status_text = %q, want %q", got, "on-call today")
	}
}

func TestHandleSetStatus_SecondWriteReplacesExistingValue(t *testing.T) {
	s := newTestServer(t)
	alice := testClientFor("alice", "dev_alice_status_replace")

	first, _ := json.Marshal(protocol.SetStatus{Type: "set_status", Text: "heads down"})
	second, _ := json.Marshal(protocol.SetStatus{Type: "set_status", Text: "available"})
	s.handleSetStatus(alice.Client, first)
	s.handleSetStatus(alice.Client, second)

	var got string
	err := s.store.DataDB().QueryRow(`SELECT status_text FROM profiles WHERE user = ?`, "alice").Scan(&got)
	if err != nil {
		t.Fatalf("query status_text: %v", err)
	}
	if got != "available" {
		t.Fatalf("status_text = %q, want %q", got, "available")
	}
}
