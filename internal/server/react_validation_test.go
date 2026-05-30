package server

import (
	"encoding/json"
	"testing"

	"github.com/brushtailmedia/sshkey-chat/internal/protocol"
	"github.com/brushtailmedia/sshkey-chat/internal/store"
)

func reactHasErrorCode(msgs []json.RawMessage, code string) bool {
	for _, m := range msgs {
		var e protocol.Error
		if json.Unmarshal(m, &e) == nil && e.Type == "error" && e.Code == code {
			return true
		}
	}
	return false
}

// S7: a group reaction whose wrapped_keys map does not exactly match the current
// member set (here: an extra entry for a non-member) is rejected, mirroring
// send/edit. This prevents a client from stuffing wrapped_keys with entries for
// users who aren't members.
func TestHandleReact_GroupWrappedKeysMismatchRejected(t *testing.T) {
	s := newTestServer(t)
	if err := s.store.CreateGroup("grp_react", "alice", []string{"alice", "bob"}, "Test"); err != nil {
		t.Fatalf("create group: %v", err)
	}
	alice := testClientFor("alice", "dev_alice_react")

	raw, _ := json.Marshal(protocol.React{
		Type:  "react",
		ID:    "msg_x",
		Group: "grp_react",
		WrappedKeys: map[string]string{
			"alice": "k", "bob": "k", "carol": "k", // carol is NOT a member
		},
		Payload:   "p",
		Signature: "sig",
	})
	s.handleReact(alice.Client, raw)

	if !reactHasErrorCode(alice.messages(), protocol.ErrInvalidWrappedKeys) {
		t.Errorf("group react with a non-member wrapped_keys entry must be rejected with ErrInvalidWrappedKeys; got %v", alice.messages())
	}
}

// S7: a 1:1 DM reaction must carry exactly the two parties' wrapped keys.
func TestHandleReact_DMWrappedKeysMismatchRejected(t *testing.T) {
	s := newTestServer(t)
	dm, err := s.store.CreateOrGetDirectMessage(store.GenerateID("dm_"), "alice", "bob")
	if err != nil {
		t.Fatalf("create dm: %v", err)
	}
	alice := testClientFor("alice", "dev_alice_react_dm")

	// Only one party present → must be rejected.
	raw, _ := json.Marshal(protocol.React{
		Type:        "react",
		ID:          "msg_x",
		DM:          dm.ID,
		WrappedKeys: map[string]string{"alice": "k"},
		Payload:     "p",
		Signature:   "sig",
	})
	s.handleReact(alice.Client, raw)

	if !reactHasErrorCode(alice.messages(), protocol.ErrInvalidWrappedKeys) {
		t.Errorf("DM react missing a party's wrapped key must be rejected with ErrInvalidWrappedKeys; got %v", alice.messages())
	}
}

// S7: an EMPTY wrapped_keys map is tolerated (a reaction that reuses an existing
// key carries none, and an empty map is only self-inflicted undecryptability,
// never a key leak). It must NOT trip the wrapped_keys validation.
func TestHandleReact_GroupEmptyWrappedKeysTolerated(t *testing.T) {
	s := newTestServer(t)
	if err := s.store.CreateGroup("grp_react2", "alice", []string{"alice", "bob"}, "Test"); err != nil {
		t.Fatalf("create group: %v", err)
	}
	alice := testClientFor("alice", "dev_alice_react2")

	raw, _ := json.Marshal(protocol.React{
		Type:      "react",
		ID:        "msg_x",
		Group:     "grp_react2",
		Payload:   "p",
		Signature: "sig",
	}) // no wrapped_keys
	s.handleReact(alice.Client, raw)

	if reactHasErrorCode(alice.messages(), protocol.ErrInvalidWrappedKeys) {
		t.Errorf("empty wrapped_keys must be tolerated, not rejected with ErrInvalidWrappedKeys")
	}
}
