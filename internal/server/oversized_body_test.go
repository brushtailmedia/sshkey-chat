package server

// Phase 17 Step 4c gap-closure — maxPayloadBytes sweep tests.
//
// Every Channel 1 send/edit handler now fires SignalOversizedBody on
// raw bodies exceeding the 16KB envelope cap. Previously only the
// upload_start path did. This test exercises one send handler per
// context type + one edit handler to confirm the pattern is uniformly
// wired (spot-check across the 6 sites: handleSend, handleSendGroup,
// handleSendDM, handleEdit, handleEditGroup, handleEditDM).

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/brushtailmedia/sshkey-chat/internal/counters"
	"github.com/brushtailmedia/sshkey-chat/internal/protocol"
)

// oversizedRaw returns a raw JSON blob that's guaranteed to exceed
// maxPayloadBytes, regardless of what specific verb struct it's
// intended to decode as. The handler's first check is a raw byte
// length, so we don't need a well-formed envelope — we just need
// enough bytes.
func oversizedRaw() json.RawMessage {
	var buf bytes.Buffer
	buf.WriteByte('"')
	// 17 KB of garbage, wrapped in quotes for parser sanity. The
	// handler checks len(raw) > maxPayloadBytes BEFORE any parse.
	for i := 0; i < 17*1024; i++ {
		buf.WriteByte('a')
	}
	buf.WriteByte('"')
	return json.RawMessage(buf.Bytes())
}

func TestHandleSend_OversizedBodyFiresCounter(t *testing.T) {
	s := newTestServer(t)
	alice := testClientFor("alice", "dev_alice_send_oversized")
	s.handleSend(alice.Client, oversizedRaw())

	if got := s.counters.Get(counters.SignalOversizedBody, "dev_alice_send_oversized"); got != 1 {
		t.Errorf("SignalOversizedBody on handleSend = %d, want 1", got)
	}
	// Client still gets the typed error (behavior preserved).
	msgs := alice.messages()
	if len(msgs) != 1 {
		t.Fatalf("expected 1 reply, got %d", len(msgs))
	}
	var errResp protocol.Error
	json.Unmarshal(msgs[0], &errResp)
	if errResp.Code != protocol.ErrMessageTooLarge {
		t.Errorf("code = %q, want %q", errResp.Code, protocol.ErrMessageTooLarge)
	}
}

func TestHandleSendGroup_OversizedBodyFiresCounter(t *testing.T) {
	s := newTestServer(t)
	alice := testClientFor("alice", "dev_alice_sendgroup_oversized")
	s.handleSendGroup(alice.Client, oversizedRaw())

	if got := s.counters.Get(counters.SignalOversizedBody, "dev_alice_sendgroup_oversized"); got != 1 {
		t.Errorf("SignalOversizedBody on handleSendGroup = %d, want 1", got)
	}
}

func TestHandleSendDM_OversizedBodyFiresCounter(t *testing.T) {
	s := newTestServer(t)
	alice := testClientFor("alice", "dev_alice_senddm_oversized")
	s.handleSendDM(alice.Client, oversizedRaw())

	if got := s.counters.Get(counters.SignalOversizedBody, "dev_alice_senddm_oversized"); got != 1 {
		t.Errorf("SignalOversizedBody on handleSendDM = %d, want 1", got)
	}
}

func TestHandleEdit_OversizedBodyFiresCounter(t *testing.T) {
	s := newTestServer(t)
	alice := testClientFor("alice", "dev_alice_edit_oversized")
	s.handleEdit(alice.Client, oversizedRaw())

	if got := s.counters.Get(counters.SignalOversizedBody, "dev_alice_edit_oversized"); got != 1 {
		t.Errorf("SignalOversizedBody on handleEdit = %d, want 1", got)
	}
}

func TestHandleEditGroup_OversizedBodyFiresCounter(t *testing.T) {
	s := newTestServer(t)
	alice := testClientFor("alice", "dev_alice_editgroup_oversized")
	s.handleEditGroup(alice.Client, oversizedRaw())

	if got := s.counters.Get(counters.SignalOversizedBody, "dev_alice_editgroup_oversized"); got != 1 {
		t.Errorf("SignalOversizedBody on handleEditGroup = %d, want 1", got)
	}
}

func TestHandleEditDM_OversizedBodyFiresCounter(t *testing.T) {
	s := newTestServer(t)
	alice := testClientFor("alice", "dev_alice_editdm_oversized")
	s.handleEditDM(alice.Client, oversizedRaw())

	if got := s.counters.Get(counters.SignalOversizedBody, "dev_alice_editdm_oversized"); got != 1 {
		t.Errorf("SignalOversizedBody on handleEditDM = %d, want 1", got)
	}
}
