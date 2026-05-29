package server

// Phase 17 Step 4c gap-closure — SignalMalformedFrame sweep tests.
//
// Every handler whose JSON parse failure previously emitted a generic
// `invalid_message` client error now also fires SignalMalformedFrame
// so Phase 17b sees density across the verb surface (previously only
// two sites in handleUploadStart fired this signal).
//
// Test strategy: rather than individually exercising all 22 sites,
// spot-check one handler per source file. The wiring pattern is
// mechanical (same 2-line rejectAndLog call everywhere), so covering
// representative sites per file confirms the pattern holds.
//
// Representative sites chosen:
//   - handleSend       (session.go)         — room send
//   - handleEdit       (edit.go)            — room edit
//   - handleUploadStart (filetransfer.go)   — upload path
//   - handleDownload   (filetransfer.go)    — download path
//   - handleEpochRotate (epoch.go)          — epoch rotation
//   - handleHistory    (sync.go)            — history query
//   - handleRevokeDevice (devicemgmt.go)    — device mgmt
//   - handleRetireMe   (retirement.go)      — retirement
//   - handleAddToGroup (group_admin.go)     — group admin
//   - handlePushRegister (pushhandler.go)   — push registration

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/brushtailmedia/sshkey-chat/internal/counters"
	"github.com/brushtailmedia/sshkey-chat/internal/protocol"
)

// malformedRaw returns a syntactically-broken JSON blob that every
// handler's json.Unmarshal will reject with a parse error.
func malformedRaw() json.RawMessage {
	return json.RawMessage(`{"broken:json missing_quote}`)
}

func TestHandleSend_MalformedFrameFiresSignal(t *testing.T) {
	s := newTestServer(t)
	alice := testClientFor("alice", "dev_alice_send_malformed")
	s.handleSend(alice.Client, malformedRaw())
	if got := s.counters.Get(counters.SignalMalformedFrame, "dev_alice_send_malformed"); got != 1 {
		t.Errorf("SignalMalformedFrame on handleSend = %d, want 1", got)
	}
}

func TestHandleEdit_MalformedFrameFiresSignal(t *testing.T) {
	s := newTestServer(t)
	alice := testClientFor("alice", "dev_alice_edit_malformed")
	s.handleEdit(alice.Client, malformedRaw())
	if got := s.counters.Get(counters.SignalMalformedFrame, "dev_alice_edit_malformed"); got != 1 {
		t.Errorf("SignalMalformedFrame on handleEdit = %d, want 1", got)
	}
}

func TestHandleUploadStart_MalformedFrameFiresSignal(t *testing.T) {
	s := newTestServer(t)
	alice := testClientFor("alice", "dev_alice_upload_malformed")
	s.handleUploadStart(alice.Client, malformedRaw())
	if got := s.counters.Get(counters.SignalMalformedFrame, "dev_alice_upload_malformed"); got != 1 {
		t.Errorf("SignalMalformedFrame on handleUploadStart = %d, want 1", got)
	}
}

func TestHandleDownload_MalformedFrameFiresSignal(t *testing.T) {
	s := newTestServer(t)
	alice := testClientFor("alice", "dev_alice_download_malformed")
	s.handleDownload(alice.Client, malformedRaw())
	if got := s.counters.Get(counters.SignalMalformedFrame, "dev_alice_download_malformed"); got != 1 {
		t.Errorf("SignalMalformedFrame on handleDownload = %d, want 1", got)
	}
}

func TestHandleEpochRotate_MalformedFrameFiresSignal(t *testing.T) {
	s := newTestServer(t)
	alice := testClientFor("alice", "dev_alice_epoch_malformed")
	s.handleEpochRotate(alice.Client, malformedRaw())
	if got := s.counters.Get(counters.SignalMalformedFrame, "dev_alice_epoch_malformed"); got != 1 {
		t.Errorf("SignalMalformedFrame on handleEpochRotate = %d, want 1", got)
	}
}

func TestHandleHistory_MalformedFrameFiresSignal(t *testing.T) {
	s := newTestServer(t)
	alice := testClientFor("alice", "dev_alice_history_malformed")
	s.handleHistory(alice.Client, malformedRaw())
	if got := s.counters.Get(counters.SignalMalformedFrame, "dev_alice_history_malformed"); got != 1 {
		t.Errorf("SignalMalformedFrame on handleHistory = %d, want 1", got)
	}
}

func TestHandleRevokeDevice_MalformedFrameFiresSignal(t *testing.T) {
	s := newTestServer(t)
	alice := testClientFor("alice", "dev_alice_revoke_malformed")
	s.handleRevokeDevice(alice.Client, malformedRaw())
	if got := s.counters.Get(counters.SignalMalformedFrame, "dev_alice_revoke_malformed"); got != 1 {
		t.Errorf("SignalMalformedFrame on handleRevokeDevice = %d, want 1", got)
	}
}

func TestHandleRetireMe_MalformedFrameFiresSignal(t *testing.T) {
	s := newTestServer(t)
	alice := testClientFor("alice", "dev_alice_retire_malformed")
	s.handleRetireMe(alice.Client, malformedRaw())
	if got := s.counters.Get(counters.SignalMalformedFrame, "dev_alice_retire_malformed"); got != 1 {
		t.Errorf("SignalMalformedFrame on handleRetireMe = %d, want 1", got)
	}
}

func TestHandleAddToGroup_MalformedFrameFiresSignal(t *testing.T) {
	s := newTestServer(t)
	alice := testClientFor("alice", "dev_alice_addtogroup_malformed")
	s.handleAddToGroup(alice.Client, malformedRaw())
	if got := s.counters.Get(counters.SignalMalformedFrame, "dev_alice_addtogroup_malformed"); got != 1 {
		t.Errorf("SignalMalformedFrame on handleAddToGroup = %d, want 1", got)
	}
}

func TestHandlePushRegister_MalformedFrameFiresSignal(t *testing.T) {
	s := newTestServer(t)
	alice := testClientFor("alice", "dev_alice_push_malformed")
	s.handlePushRegister(alice.Client, malformedRaw())
	if got := s.counters.Get(counters.SignalMalformedFrame, "dev_alice_push_malformed"); got != 1 {
		t.Errorf("SignalMalformedFrame on handlePushRegister = %d, want 1", got)
	}
}

func TestHandlePushRegister_BadPlatformFiresSignal(t *testing.T) {
	// Phase 17 Step 4c: not just JSON parse failures — semantic
	// validation (wrong platform value) is also a protocol-level
	// misbehavior, wires to the same signal.
	s := newTestServer(t)
	alice := testClientFor("alice", "dev_alice_push_badplat")
	raw := json.RawMessage(`{"type":"push_register","platform":"blackberry","device_id":"dev_x","token":"tok"}`)
	s.handlePushRegister(alice.Client, raw)
	if got := s.counters.Get(counters.SignalMalformedFrame, "dev_alice_push_badplat"); got != 1 {
		t.Errorf("SignalMalformedFrame on bad platform = %d, want 1", got)
	}
}

func TestHandlePushRegister_ShortTokenRejectedAndNotStored(t *testing.T) {
	s := newTestServer(t)
	alice := testClientFor("alice", "dev_alice_push_short")

	raw := json.RawMessage(`{"type":"push_register","platform":"ios","device_id":"dev_x","token":"abc"}`)
	s.handlePushRegister(alice.Client, raw)

	if got := s.counters.Get(counters.SignalMalformedFrame, "dev_alice_push_short"); got != 1 {
		t.Fatalf("SignalMalformedFrame on short token = %d, want 1", got)
	}

	msgs := alice.messages()
	if len(msgs) != 1 {
		t.Fatalf("expected 1 error message, got %d", len(msgs))
	}
	var errMsg protocol.Error
	if err := json.Unmarshal(msgs[0], &errMsg); err != nil {
		t.Fatalf("parse error reply: %v", err)
	}
	if errMsg.Code != "invalid_message" {
		t.Fatalf("error code = %q, want invalid_message", errMsg.Code)
	}
	if !strings.Contains(errMsg.Message, "at least 8") {
		t.Fatalf("error message = %q, want at-least-8 hint", errMsg.Message)
	}

	tokens, err := s.store.GetActivePushTokens("alice")
	if err != nil {
		t.Fatalf("GetActivePushTokens: %v", err)
	}
	if len(tokens) != 0 {
		t.Fatalf("short token should not be stored, got %d rows", len(tokens))
	}
}

func TestHandlePushRegister_ValidTokenStoredTrimmed(t *testing.T) {
	s := newTestServer(t)
	alice := testClientFor("alice", "dev_alice_push_ok")

	raw := json.RawMessage(`{"type":"push_register","platform":"android","device_id":"dev_x","token":"   12345678abcdef   "}`)
	s.handlePushRegister(alice.Client, raw)

	if got := s.counters.Get(counters.SignalMalformedFrame, "dev_alice_push_ok"); got != 0 {
		t.Fatalf("SignalMalformedFrame on valid token = %d, want 0", got)
	}

	msgs := alice.messages()
	if len(msgs) != 1 {
		t.Fatalf("expected 1 push_registered message, got %d", len(msgs))
	}
	var ack protocol.PushRegistered
	if err := json.Unmarshal(msgs[0], &ack); err != nil {
		t.Fatalf("parse push_registered: %v", err)
	}
	if ack.Type != "push_registered" || ack.Platform != "android" {
		t.Fatalf("unexpected ack: %+v", ack)
	}

	tokens, err := s.store.GetActivePushTokens("alice")
	if err != nil {
		t.Fatalf("GetActivePushTokens: %v", err)
	}
	if len(tokens) != 1 {
		t.Fatalf("expected 1 stored push token, got %d", len(tokens))
	}
	if tokens[0].Token != "12345678abcdef" {
		t.Fatalf("stored token = %q, want trimmed token", tokens[0].Token)
	}
	if tokens[0].DeviceID != "dev_alice_push_ok" {
		t.Fatalf("device_id = %q, want connection device id", tokens[0].DeviceID)
	}
}

func TestHandlePushRegister_OversizedTokenRejected(t *testing.T) {
	s := newTestServer(t)
	alice := testClientFor("alice", "dev_alice_push_long")

	token := strings.Repeat("a", maxPushTokenLen+1)
	rawBytes, err := json.Marshal(protocol.PushRegister{
		Type:     "push_register",
		Platform: "ios",
		DeviceID: "dev_x",
		Token:    token,
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	s.handlePushRegister(alice.Client, rawBytes)

	if got := s.counters.Get(counters.SignalMalformedFrame, "dev_alice_push_long"); got != 1 {
		t.Fatalf("SignalMalformedFrame on oversized token = %d, want 1", got)
	}
	msgs := alice.messages()
	if len(msgs) != 1 {
		t.Fatalf("expected 1 error message, got %d", len(msgs))
	}
	var errMsg protocol.Error
	if err := json.Unmarshal(msgs[0], &errMsg); err != nil {
		t.Fatalf("parse error reply: %v", err)
	}
	if errMsg.Code != "invalid_message" {
		t.Fatalf("error code = %q, want invalid_message", errMsg.Code)
	}
}

func TestHandleCreateDM_SelfFiresSignal(t *testing.T) {
	// Phase 17 Step 4c: "Cannot create a DM with yourself" is a
	// protocol-level semantic rejection, wires to SignalMalformedFrame.
	s := newTestServer(t)
	alice := testClientFor("alice", "dev_alice_dm_self")
	raw := json.RawMessage(`{"type":"create_dm","other":"alice"}`)
	s.handleCreateDM(alice.Client, raw)
	if got := s.counters.Get(counters.SignalMalformedFrame, "dev_alice_dm_self"); got != 1 {
		t.Errorf("SignalMalformedFrame on create_dm with self = %d, want 1", got)
	}
}

// TestHandleHistory_EmptyOrAmbiguousContextRejected covers the exactly-one-context
// guard: a history request with zero or more than one of room/group/dm is rejected
// with invalid_context (echoing the request corr_id) and fires SignalMalformedFrame,
// instead of hanging with no response (empty) or silently picking the first branch
// (ambiguous).
func TestHandleHistory_EmptyOrAmbiguousContextRejected(t *testing.T) {
	cases := []struct {
		name, dev string
		req       protocol.History
	}{
		{"empty", "dev_hist_ctx_empty", protocol.History{Type: "history"}},
		{"room+group", "dev_hist_ctx_rg", protocol.History{Type: "history", Room: "rm_x", Group: "grp_x"}},
		{"room+dm", "dev_hist_ctx_rd", protocol.History{Type: "history", Room: "rm_x", DM: "dm_x"}},
		{"all three", "dev_hist_ctx_all", protocol.History{Type: "history", Room: "rm_x", Group: "grp_x", DM: "dm_x"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestServer(t)
			alice := testClientFor("alice", tc.dev)
			const corrID = "corr_ABCDEFGHIJKLMNOPQRSTU" // valid shape: corr_ + 21 chars
			req := tc.req
			req.CorrID = corrID
			raw, err := json.Marshal(req)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			s.handleHistory(alice.Client, raw)

			if got := s.counters.Get(counters.SignalMalformedFrame, tc.dev); got != 1 {
				t.Errorf("SignalMalformedFrame = %d, want 1", got)
			}
			msgs := alice.messages()
			if len(msgs) != 1 {
				t.Fatalf("expected 1 error message, got %d", len(msgs))
			}
			var errMsg protocol.Error
			if err := json.Unmarshal(msgs[0], &errMsg); err != nil {
				t.Fatalf("parse error reply: %v", err)
			}
			if errMsg.Code != "invalid_context" {
				t.Errorf("error code = %q, want invalid_context", errMsg.Code)
			}
			if errMsg.CorrID != corrID {
				t.Errorf("error corr_id = %q, want echoed %q", errMsg.CorrID, corrID)
			}
		})
	}
}

// TestHandleHistory_StoreUnavailableReturnsInternalError locks in the
// owned-response guarantee (history-state-model.md step 11): an accepted
// history request (valid corr_id + exactly one context) that hits a
// storage-unavailable path returns a correlated internal_error rather than
// silently returning, which would leave the client's load stuck forever. The
// store==nil path is the defensive, testable instance of that rule.
func TestHandleHistory_StoreUnavailableReturnsInternalError(t *testing.T) {
	const corrID = "corr_ABCDEFGHIJKLMNOPQRSTU"
	s := newTestServer(t)
	alice := testClientFor("alice", "dev_alice_hist_internal")

	origStore := s.store
	s.store = nil                          // simulate storage unavailable
	defer func() { s.store = origStore }() // restore before t.Cleanup closes it

	raw, _ := json.Marshal(protocol.History{Type: "history", Room: "room_x", CorrID: corrID})
	s.handleHistory(alice.Client, raw)

	msgs := alice.messages()
	if len(msgs) != 1 {
		t.Fatalf("expected 1 reply, got %d", len(msgs))
	}
	var errMsg protocol.Error
	if json.Unmarshal(msgs[0], &errMsg) != nil {
		t.Fatalf("reply not a protocol.Error: %s", msgs[0])
	}
	if errMsg.Code != protocol.CodeInternal {
		t.Errorf("error code = %q, want internal_error", errMsg.Code)
	}
	if errMsg.CorrID != corrID {
		t.Errorf("error corr_id = %q, want echoed %q", errMsg.CorrID, corrID)
	}
}
