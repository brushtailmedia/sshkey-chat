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
	"testing"

	"github.com/brushtailmedia/sshkey-chat/internal/counters"
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
