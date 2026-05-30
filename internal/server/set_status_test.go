package server

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/brushtailmedia/sshkey-chat/internal/counters"
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

// S7: status_text is bounded (stored verbatim → storage-abuse vector). Over-long
// is silent-dropped + counted and never written; a value at exactly the cap is
// accepted.
func TestHandleSetStatus_OverLongRejected(t *testing.T) {
	s := newTestServer(t)
	alice := testClientFor("alice", "dev_alice_status_toolong")

	long := strings.Repeat("x", maxStatusTextBytes+1)
	raw, _ := json.Marshal(protocol.SetStatus{Type: "set_status", Text: long})
	s.handleSetStatus(alice.Client, raw)

	if got := s.counters.Get(counters.SignalMalformedFrame, "dev_alice_status_toolong"); got != 1 {
		t.Errorf("over-long set_status: SignalMalformedFrame = %d, want 1", got)
	}
	var stored string
	// No row written (sql.ErrNoRows → err != nil) is the pass condition.
	if err := s.store.DataDB().QueryRow(`SELECT status_text FROM profiles WHERE user = ?`, "alice").Scan(&stored); err == nil {
		t.Errorf("over-long status_text must not be stored, got %q", stored)
	}

	// A status at exactly the cap is accepted and stored.
	atCap := strings.Repeat("y", maxStatusTextBytes)
	raw2, _ := json.Marshal(protocol.SetStatus{Type: "set_status", Text: atCap})
	s.handleSetStatus(alice.Client, raw2)
	if err := s.store.DataDB().QueryRow(`SELECT status_text FROM profiles WHERE user = ?`, "alice").Scan(&stored); err != nil {
		t.Fatalf("status at cap should be stored: %v", err)
	}
	if stored != atCap {
		t.Fatalf("status_text length = %d, want %d (at-cap value)", len(stored), maxStatusTextBytes)
	}
}
