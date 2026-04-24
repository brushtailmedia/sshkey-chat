package server

// Phase 17 Step 6 — retry_after_ms wiring tests.
//
// Every rate-limit rejection site now populates the RetryAfterMs field
// on the wire response (`protocol.Error` or `protocol.UploadError`).
// Clients implement backoff using the server-sent hint rather than a
// client-side constant.
//
// Test strategy: fire enough rapid calls at each site to exhaust its
// burst (5-token minimum + a few extra for safety → 7 calls), then
// unmarshal the rejection response and assert RetryAfterMs > 0.

import (
	"encoding/json"
	"testing"

	"github.com/brushtailmedia/sshkey-chat/internal/protocol"
)

// drainAndGetReject fires n calls and returns the last message — the
// rate-limit rejection. n >= 6 guarantees the 5-token minimum burst
// is exhausted.
func drainAndGetReject(t *testing.T, alice *captureClient, handler func(json.RawMessage), raw json.RawMessage, n int) []byte {
	t.Helper()
	for i := 0; i < n; i++ {
		handler(raw)
	}
	msgs := alice.messages()
	if len(msgs) == 0 {
		t.Fatalf("expected at least one reply, got 0")
	}
	return msgs[len(msgs)-1]
}

func assertRetryAfterMs(t *testing.T, wire []byte, site string) {
	t.Helper()
	var err protocol.Error
	if e := json.Unmarshal(wire, &err); e != nil {
		t.Fatalf("%s: unmarshal wire response: %v\nraw: %s", site, e, wire)
	}
	if err.Code != protocol.ErrRateLimited {
		t.Fatalf("%s: code = %q, want %q\nraw: %s", site, err.Code, protocol.ErrRateLimited, wire)
	}
	if err.RetryAfterMs <= 0 {
		t.Errorf("%s: retry_after_ms = %d, want > 0\nraw: %s", site, err.RetryAfterMs, wire)
	}
}

func TestRateLimit_RetryAfterMs_handleReact(t *testing.T) {
	s := newTestServer(t)
	s.cfg.Lock()
	s.cfg.Server.RateLimits.ReactionsPerMinute = 1
	s.cfg.Unlock()

	alice := testClientFor("alice", "dev_alice_rmt_react")
	raw, _ := json.Marshal(protocol.React{Type: "react", ID: "msg_xxx", Payload: "hi"})
	wire := drainAndGetReject(t, alice, func(r json.RawMessage) { s.handleReact(alice.Client, r) }, raw, 7)
	assertRetryAfterMs(t, wire, "handleReact")
}

func TestRateLimit_RetryAfterMs_handleUnreact(t *testing.T) {
	s := newTestServer(t)
	s.cfg.Lock()
	s.cfg.Server.RateLimits.ReactionsPerMinute = 1
	s.cfg.Unlock()

	alice := testClientFor("alice", "dev_alice_rmt_unreact")
	raw := json.RawMessage(`{"type":"unreact","reaction_id":"react_xxx"}`)
	wire := drainAndGetReject(t, alice, func(r json.RawMessage) { s.handleUnreact(alice.Client, r) }, raw, 7)
	assertRetryAfterMs(t, wire, "handleUnreact")
}

func TestRateLimit_RetryAfterMs_handlePin(t *testing.T) {
	s := newTestServer(t)
	s.cfg.Lock()
	s.cfg.Server.RateLimits.PinsPerMinute = 1
	s.cfg.Unlock()

	alice := testClientFor("alice", "dev_alice_rmt_pin")
	raw, _ := json.Marshal(protocol.Pin{Type: "pin", ID: "msg_xxx"})
	wire := drainAndGetReject(t, alice, func(r json.RawMessage) { s.handlePin(alice.Client, r) }, raw, 7)
	assertRetryAfterMs(t, wire, "handlePin")
}

func TestRateLimit_RetryAfterMs_handleCreateGroup(t *testing.T) {
	s := newTestServer(t)
	s.cfg.Lock()
	s.cfg.Server.RateLimits.DMCreatesPerMinute = 1
	s.cfg.Unlock()

	alice := testClientFor("alice", "dev_alice_rmt_creategroup")
	raw, _ := json.Marshal(protocol.CreateGroup{Type: "create_group", Members: []string{"bob"}})
	wire := drainAndGetReject(t, alice, func(r json.RawMessage) { s.handleCreateGroup(alice.Client, r) }, raw, 7)
	assertRetryAfterMs(t, wire, "handleCreateGroup")
}

func TestRateLimit_RetryAfterMs_handleCreateDM(t *testing.T) {
	s := newTestServer(t)
	s.cfg.Lock()
	s.cfg.Server.RateLimits.DMCreatesPerMinute = 1
	s.cfg.Unlock()

	alice := testClientFor("alice", "dev_alice_rmt_createdm")
	raw, _ := json.Marshal(protocol.CreateDM{Type: "create_dm", Other: "bob"})
	wire := drainAndGetReject(t, alice, func(r json.RawMessage) { s.handleCreateDM(alice.Client, r) }, raw, 7)
	assertRetryAfterMs(t, wire, "handleCreateDM")
}

func TestRateLimit_RetryAfterMs_handleHistory(t *testing.T) {
	s := newTestServer(t)
	s.cfg.Lock()
	s.cfg.Server.RateLimits.HistoryPerMinute = 1
	s.cfg.Unlock()

	alice := testClientFor("alice", "dev_alice_rmt_history")
	raw, _ := json.Marshal(protocol.History{Type: "history"})
	wire := drainAndGetReject(t, alice, func(r json.RawMessage) { s.handleHistory(alice.Client, r) }, raw, 7)
	assertRetryAfterMs(t, wire, "handleHistory")
}

func TestRateLimit_RetryAfterMs_handleDownload(t *testing.T) {
	s := newTestServer(t)
	s.cfg.Lock()
	s.cfg.Server.RateLimits.DownloadRequestsPerMinute = 1
	s.cfg.Unlock()

	alice := testClientFor("alice", "dev_alice_rmt_download")
	raw := json.RawMessage(`{"type":"download","file_id":"file_x"}`)
	wire := drainAndGetReject(t, alice, func(r json.RawMessage) { s.handleDownload(alice.Client, r) }, raw, 7)
	assertRetryAfterMs(t, wire, "handleDownload")
}

func TestRateLimit_RetryAfterMs_handleListDevices(t *testing.T) {
	s := newTestServer(t)
	s.cfg.Lock()
	s.cfg.Server.RateLimits.DeviceListPerMinute = 1
	s.cfg.Unlock()

	alice := testClientFor("alice", "dev_alice_rmt_listdev")
	wire := drainAndGetReject(t, alice, func(r json.RawMessage) { s.handleListDevices(alice.Client, nil) }, nil, 7)
	assertRetryAfterMs(t, wire, "handleListDevices")
}

func TestRateLimit_RetryAfterMs_handleRoomMembers(t *testing.T) {
	s := newTestServer(t)
	s.cfg.Lock()
	s.cfg.Server.RateLimits.RoomMembersPerMinute = 1
	s.cfg.Unlock()

	alice := testClientFor("alice", "dev_alice_rmt_rm")
	raw, _ := json.Marshal(protocol.RoomMembers{Type: "room_members", Room: s.store.RoomDisplayNameToID("general")})
	wire := drainAndGetReject(t, alice, func(r json.RawMessage) { s.handleRoomMembers(alice.Client, r) }, raw, 7)
	assertRetryAfterMs(t, wire, "handleRoomMembers")
}

func TestRateLimit_RetryAfterMs_handleUploadStart_UploadError(t *testing.T) {
	// Special case: handleUploadStart returns UploadError not Error.
	// UploadError has its own RetryAfterMs field.
	s := newTestServer(t)
	s.cfg.Lock()
	s.cfg.Server.RateLimits.UploadsPerMinute = 1
	s.cfg.Unlock()

	alice := testClientFor("alice", "dev_alice_rmt_upload")
	generalID := s.store.RoomDisplayNameToID("general")
	for i := 0; i < 7; i++ {
		raw, _ := json.Marshal(protocol.UploadStart{
			Type:        "upload_start",
			UploadID:    "up_XXXXXXXXXXXXXXXXXXXXX",
			Size:        100,
			ContentHash: "blake2b-256:" + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			Room:        generalID,
		})
		s.handleUploadStart(alice.Client, raw)
	}

	msgs := alice.messages()
	if len(msgs) == 0 {
		t.Fatalf("no reply from handleUploadStart")
	}
	var uerr protocol.UploadError
	if err := json.Unmarshal(msgs[len(msgs)-1], &uerr); err != nil {
		t.Fatalf("unmarshal UploadError: %v", err)
	}
	if uerr.Code != protocol.ErrRateLimited {
		t.Fatalf("code = %q, want %q", uerr.Code, protocol.ErrRateLimited)
	}
	if uerr.RetryAfterMs <= 0 {
		t.Errorf("UploadError.RetryAfterMs = %d, want > 0", uerr.RetryAfterMs)
	}
}

func TestRateLimit_RetryAfterMs_checkAdminActionRateLimit(t *testing.T) {
	// Phase 17 Step 7 polish: the checkAdminActionRateLimit wrapper is
	// the ONE site called by 4 admin verbs (add/remove/promote/demote).
	// Exercise it via handleAddToGroup to confirm the wrapper
	// propagates retry_after_ms like the direct rate-limit sites.
	s := newTestServer(t)
	s.cfg.Lock()
	s.cfg.Server.RateLimits.AdminActionsPerMinute = 1
	s.cfg.Unlock()

	// Alice needs to be an admin of a group. Use the store API.
	if err := s.store.CreateGroup("group_admin_wrap_test", "alice", []string{"alice", "bob"}, "test"); err != nil {
		t.Fatalf("create group: %v", err)
	}

	alice := testClientFor("alice", "dev_alice_rmt_adminwrap")
	raw, _ := json.Marshal(protocol.AddToGroup{
		Type:  "add_to_group",
		Group: "group_admin_wrap_test",
		User:  "carol",
	})

	// Fire 7 to exhaust burst. The wrapper is called first; later
	// calls should hit the rate-limit rejection.
	wire := drainAndGetReject(t, alice, func(r json.RawMessage) { s.handleAddToGroup(alice.Client, r) }, raw, 7)
	assertRetryAfterMs(t, wire, "checkAdminActionRateLimit (via handleAddToGroup)")
}

func TestRateLimit_RetryAfterMs_handleSend_PerSecond(t *testing.T) {
	// handleSend uses the per-SECOND `allow` variant. Verify
	// retry_after_ms is populated on that code path too.
	s := newTestServer(t)
	s.cfg.Lock()
	s.cfg.Server.RateLimits.MessagesPerSecond = 1
	s.cfg.Unlock()

	alice := testClientFor("alice", "dev_alice_rmt_send")
	raw := json.RawMessage(`{"type":"send","room":"room_xxx","payload":"hi"}`)
	wire := drainAndGetReject(t, alice, func(r json.RawMessage) { s.handleSend(alice.Client, r) }, raw, 7)
	assertRetryAfterMs(t, wire, "handleSend")
}
