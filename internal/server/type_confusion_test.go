package server

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/brushtailmedia/sshkey-chat/internal/counters"
	"github.com/brushtailmedia/sshkey-chat/internal/protocol"
	"github.com/brushtailmedia/sshkey-chat/internal/store"
)

func TestHandleSend_RoomFieldIntegerRejectedAsMalformed(t *testing.T) {
	s := newTestServer(t)
	alice := testClientFor("alice", "dev_alice_send_int_room")

	raw := json.RawMessage(`{"type":"send","room":12345,"epoch":1,"payload":"p","signature":"s"}`)
	s.handleSend(alice.Client, raw)

	if got := s.counters.Get(counters.SignalMalformedFrame, "dev_alice_send_int_room"); got != 1 {
		t.Fatalf("SignalMalformedFrame = %d, want 1", got)
	}

	msgs := alice.messages()
	if len(msgs) != 1 {
		t.Fatalf("expected 1 error reply, got %d", len(msgs))
	}
	var errResp protocol.Error
	if err := json.Unmarshal(msgs[0], &errResp); err != nil {
		t.Fatalf("unmarshal error reply: %v", err)
	}
	if errResp.Code != "invalid_message" {
		t.Fatalf("code = %q, want invalid_message", errResp.Code)
	}
}

func TestHandleSend_RoomFieldNullCollapsesToUnknownRoom(t *testing.T) {
	s := newTestServer(t)

	// Baseline unknown-room response.
	baseline := testClientFor("alice", "dev_alice_send_null_room_base")
	rawBaseline, _ := json.Marshal(protocol.Send{
		Type:      "send",
		Room:      "room_does_not_exist",
		Epoch:     1,
		Payload:   "p",
		Signature: "s",
	})
	s.handleSend(baseline.Client, rawBaseline)
	baseMsgs := baseline.messages()
	if len(baseMsgs) != 1 {
		t.Fatalf("baseline expected 1 reply, got %d", len(baseMsgs))
	}

	// Adversarial null input: json null for string field.
	probe := testClientFor("alice", "dev_alice_send_null_room")
	raw := json.RawMessage(`{"type":"send","room":null,"epoch":1,"payload":"p","signature":"s"}`)
	s.handleSend(probe.Client, raw)

	probeMsgs := probe.messages()
	if len(probeMsgs) != 1 {
		t.Fatalf("probe expected 1 reply, got %d", len(probeMsgs))
	}
	if !bytes.Equal(baseMsgs[0], probeMsgs[0]) {
		t.Fatalf("null-room response differs from unknown-room baseline\nbaseline: %s\nprobe:    %s", baseMsgs[0], probeMsgs[0])
	}
	if got := s.counters.Get(counters.SignalMalformedFrame, "dev_alice_send_null_room"); got != 0 {
		t.Fatalf("SignalMalformedFrame for null-room = %d, want 0", got)
	}
}

func TestHandleSendGroup_WrappedKeysNonMemberKeyNamesRejected(t *testing.T) {
	s := newTestServer(t)
	groupID := store.GenerateID("group_")
	if err := s.store.CreateGroup(groupID, "alice", []string{"alice", "bob"}, "wc"); err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}

	alice := testClientFor("alice", "dev_alice_sendgroup_badkeys")
	raw := json.RawMessage(`{
		"type":"send_group",
		"group":"` + groupID + `",
		"wrapped_keys":{"☃":"abc","hello world":"def"},
		"payload":"p",
		"signature":"s"
	}`)
	s.handleSendGroup(alice.Client, raw)

	msgs := alice.messages()
	if len(msgs) != 1 {
		t.Fatalf("expected 1 error reply, got %d", len(msgs))
	}
	var errResp protocol.Error
	if err := json.Unmarshal(msgs[0], &errResp); err != nil {
		t.Fatalf("unmarshal error reply: %v", err)
	}
	if errResp.Code != protocol.ErrInvalidWrappedKeys {
		t.Fatalf("code = %q, want %q", errResp.Code, protocol.ErrInvalidWrappedKeys)
	}
}

func TestHandleSendDM_WrappedKeysInvalidBase64ValuesStillAccepted(t *testing.T) {
	// Locks in current protocol-layer behavior (Phase 21 F23 accepted scope):
	// send_dm validates wrapped_keys key set, but not per-value base64 shape.
	// Crypto layer catches malformed wrapped values at receive/decrypt time.
	s := newTestServer(t)
	dm, err := s.store.CreateOrGetDirectMessage(store.GenerateID("dm_"), "alice", "bob")
	if err != nil {
		t.Fatalf("CreateOrGetDirectMessage: %v", err)
	}

	alice := testClientFor("alice", "dev_alice_senddm_badval")
	bob := testClientFor("bob", "dev_bob_senddm_badval")
	s.mu.Lock()
	s.clients["dev_alice_senddm_badval"] = alice.Client
	s.clients["dev_bob_senddm_badval"] = bob.Client
	s.mu.Unlock()

	raw := json.RawMessage(`{
		"type":"send_dm",
		"dm":"` + dm.ID + `",
		"wrapped_keys":{"alice":"not-base64!@#","bob":"also_not_base64"},
		"payload":"p",
		"signature":"s"
	}`)
	s.handleSendDM(alice.Client, raw)

	msgs := bob.messages()
	if len(msgs) != 1 {
		t.Fatalf("expected 1 dm broadcast, got %d", len(msgs))
	}
	var out protocol.DM
	if err := json.Unmarshal(msgs[0], &out); err != nil {
		t.Fatalf("unmarshal dm broadcast: %v", err)
	}
	if out.Type != "dm" {
		t.Fatalf("type = %q, want dm", out.Type)
	}
	if out.DM != dm.ID {
		t.Fatalf("dm id = %q, want %q", out.DM, dm.ID)
	}
}
