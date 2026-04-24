package server

import (
	"encoding/json"
	"testing"

	"github.com/brushtailmedia/sshkey-chat/internal/protocol"
)

func TestHandleListPendingKeys_NonAdminRejected(t *testing.T) {
	s := newTestServer(t)
	bob := testClientFor("bob", "dev_bob_pending_nonadmin")

	s.handleListPendingKeys(bob.Client)

	msgs := bob.messages()
	if len(msgs) != 1 {
		t.Fatalf("expected 1 reply, got %d", len(msgs))
	}
	var errResp protocol.Error
	if err := json.Unmarshal(msgs[0], &errResp); err != nil {
		t.Fatalf("unmarshal error reply: %v", err)
	}
	if errResp.Type != "error" {
		t.Fatalf("type = %q, want error", errResp.Type)
	}
	if errResp.Code != protocol.ErrNotAuthorized {
		t.Fatalf("code = %q, want %q", errResp.Code, protocol.ErrNotAuthorized)
	}
}

func TestHandleListPendingKeys_AdminHappyPath(t *testing.T) {
	s := newTestServer(t)
	alice := testClientFor("alice", "dev_alice_pending_admin")

	_, err := s.store.DataDB().Exec(`
		INSERT INTO pending_keys (fingerprint, attempts, first_seen, last_seen, remote_addr)
		VALUES
			('SHA256:first', 1, '2026-04-23 09:00:00', '2026-04-23 09:05:00', '10.0.0.1'),
			('SHA256:second', 2, '2026-04-23 10:00:00', '2026-04-23 10:06:00', '10.0.0.2')
	`)
	if err != nil {
		t.Fatalf("seed pending_keys: %v", err)
	}

	s.handleListPendingKeys(alice.Client)

	msgs := alice.messages()
	if len(msgs) != 1 {
		t.Fatalf("expected 1 reply, got %d", len(msgs))
	}

	var list protocol.PendingKeysList
	if err := json.Unmarshal(msgs[0], &list); err != nil {
		t.Fatalf("unmarshal pending_keys_list: %v", err)
	}
	if list.Type != "pending_keys_list" {
		t.Fatalf("type = %q, want pending_keys_list", list.Type)
	}
	if len(list.Keys) != 2 {
		t.Fatalf("keys len = %d, want 2", len(list.Keys))
	}

	// Ordered by last_seen DESC.
	if list.Keys[0].Fingerprint != "SHA256:second" {
		t.Fatalf("first fingerprint = %q, want SHA256:second", list.Keys[0].Fingerprint)
	}
	if list.Keys[1].Fingerprint != "SHA256:first" {
		t.Fatalf("second fingerprint = %q, want SHA256:first", list.Keys[1].Fingerprint)
	}
}
