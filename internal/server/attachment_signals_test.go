package server

// Phase 17 Step 4c Part 3 — attachment error-path counter wiring tests.
//
// Before Part 3, every UploadError / DownloadError response bypassed
// rejectAndLog — writing protocol errors directly without firing any
// Step 2 counter signal. Phase 17b auto-revoke had no attachment
// signal to act on. Part 3 wires the two highest-value sites:
//   - handleUploadStart rate-limit reject → SignalRateLimited
//     (load signal, not AutoRevokeSignals — counted for observability)
//   - handleBinaryChannel hash mismatch → SignalInvalidContentHash
//     (misbehavior signal, IS AutoRevokeSignals)
//
// Other rejection paths (invalid_context, not-a-member) were
// consciously left untouched — they're legitimate error states a
// probing but well-intentioned client might hit, and the plan's
// Phase 14 byte-identical-rejection invariant shapes the response
// already. Wiring them would produce noise without signal.

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/brushtailmedia/sshkey-chat/internal/counters"
	"github.com/brushtailmedia/sshkey-chat/internal/protocol"
	"github.com/brushtailmedia/sshkey-chat/internal/store"
)

func TestHandleUploadStart_RateLimitFiresCounter(t *testing.T) {
	s := newTestServer(t)
	// Squeeze the rate limit. Token bucket has a minimum burst of 5
	// regardless of per-minute rate (see ratelimit.go), so we fire 6
	// uploads in rapid succession — the 6th must trip the limit.
	s.cfg.Lock()
	s.cfg.Server.RateLimits.UploadsPerMinute = 1
	s.cfg.Unlock()

	generalID := s.store.RoomDisplayNameToID("general")
	alice := testClientFor("alice", "dev_alice_ratesig")

	validHash := "blake2b-256:" + strings.Repeat("a", 64)
	makeMsg := func() []byte {
		m := protocol.UploadStart{
			Type:        "upload_start",
			UploadID:    store.GenerateID("up_"),
			Size:        100,
			ContentHash: validHash,
			Room:        generalID,
		}
		raw, _ := json.Marshal(m)
		return raw
	}

	// Exhaust the 5-token burst, then fire a 6th that should be rejected.
	for i := 0; i < 6; i++ {
		s.handleUploadStart(alice.Client, makeMsg())
	}

	if got := s.counters.Get(counters.SignalRateLimited, "dev_alice_ratesig"); got < 1 {
		t.Errorf("SignalRateLimited = %d, want >= 1 (burst exhausted by 6 rapid uploads)", got)
	}
}

func TestHandleUploadStart_OversizedSizeFiresOversizedBody(t *testing.T) {
	// Client declares a size > MaxFileSize. Hostile or broken — no
	// legitimate client has reason to declare a 10GB chat upload. Fires
	// SignalOversizedBody (AutoRevokeSignals-eligible).
	s := newTestServer(t)

	generalID := s.store.RoomDisplayNameToID("general")
	alice := testClientFor("alice", "dev_alice_sizesig")

	// MaxFileSize default is 50MB; declare 100MB.
	msg := protocol.UploadStart{
		Type:        "upload_start",
		UploadID:    store.GenerateID("up_"),
		Size:        100 * 1024 * 1024,
		ContentHash: "blake2b-256:" + strings.Repeat("a", 64),
		Room:        generalID,
	}
	raw, _ := json.Marshal(msg)
	s.handleUploadStart(alice.Client, raw)

	if got := s.counters.Get(counters.SignalOversizedBody, "dev_alice_sizesig"); got != 1 {
		t.Errorf("SignalOversizedBody = %d, want 1", got)
	}

	// Client still receives the typed UploadError code.
	msgs := alice.messages()
	if len(msgs) != 1 {
		t.Fatalf("expected 1 reply, got %d", len(msgs))
	}
	var errResp protocol.UploadError
	json.Unmarshal(msgs[0], &errResp)
	if errResp.Code != protocol.ErrUploadTooLarge {
		t.Errorf("code = %q, want %q", errResp.Code, protocol.ErrUploadTooLarge)
	}
}

func TestHandleUploadStart_MissingContentHashFiresMalformed(t *testing.T) {
	// content_hash is a required protocol field. Omission is a
	// protocol violation. Fires SignalMalformedFrame
	// (AutoRevokeSignals-eligible).
	s := newTestServer(t)

	generalID := s.store.RoomDisplayNameToID("general")
	alice := testClientFor("alice", "dev_alice_hashless")

	msg := protocol.UploadStart{
		Type:     "upload_start",
		UploadID: store.GenerateID("up_"),
		Size:     100,
		// ContentHash intentionally omitted
		Room: generalID,
	}
	raw, _ := json.Marshal(msg)
	s.handleUploadStart(alice.Client, raw)

	if got := s.counters.Get(counters.SignalMalformedFrame, "dev_alice_hashless"); got != 1 {
		t.Errorf("SignalMalformedFrame = %d, want 1", got)
	}

	msgs := alice.messages()
	var errResp protocol.UploadError
	json.Unmarshal(msgs[0], &errResp)
	if errResp.Code != "missing_hash" {
		t.Errorf("code = %q, want missing_hash", errResp.Code)
	}
}

func TestHandleUploadStart_InvalidContextZeroFiresMalformed(t *testing.T) {
	// Zero contexts (no room, group, or dm) — protocol violation.
	s := newTestServer(t)

	alice := testClientFor("alice", "dev_alice_ctx0")
	msg := protocol.UploadStart{
		Type:        "upload_start",
		UploadID:    store.GenerateID("up_"),
		Size:        100,
		ContentHash: "blake2b-256:" + strings.Repeat("a", 64),
		// All three context fields empty
	}
	raw, _ := json.Marshal(msg)
	s.handleUploadStart(alice.Client, raw)

	if got := s.counters.Get(counters.SignalMalformedFrame, "dev_alice_ctx0"); got != 1 {
		t.Errorf("SignalMalformedFrame = %d, want 1", got)
	}

	msgs := alice.messages()
	var errResp protocol.UploadError
	json.Unmarshal(msgs[0], &errResp)
	if errResp.Code != "invalid_context" {
		t.Errorf("code = %q, want invalid_context", errResp.Code)
	}
}

func TestHandleUploadStart_InvalidContextMultipleFiresMalformed(t *testing.T) {
	// Two contexts set (room AND group) — protocol violation, same
	// category as zero contexts.
	s := newTestServer(t)

	generalID := s.store.RoomDisplayNameToID("general")
	alice := testClientFor("alice", "dev_alice_ctx2")
	msg := protocol.UploadStart{
		Type:        "upload_start",
		UploadID:    store.GenerateID("up_"),
		Size:        100,
		ContentHash: "blake2b-256:" + strings.Repeat("a", 64),
		Room:        generalID,
		Group:       store.GenerateID("group_"),
	}
	raw, _ := json.Marshal(msg)
	s.handleUploadStart(alice.Client, raw)

	if got := s.counters.Get(counters.SignalMalformedFrame, "dev_alice_ctx2"); got != 1 {
		t.Errorf("SignalMalformedFrame (dual-context) = %d, want 1", got)
	}
}

// --- Phase 17 Step 4c follow-up: non-member + download ACL/channel/IO signals ---

func TestHandleUploadStart_NonMemberRoomFiresSignal(t *testing.T) {
	s := newTestServer(t)
	engID := s.store.RoomDisplayNameToID("engineering")

	// bob is NOT a member of engineering per the seed.
	bob := testClientFor("bob", "dev_bob_nonmember_r")
	msg := protocol.UploadStart{
		Type:        "upload_start",
		UploadID:    store.GenerateID("up_"),
		Size:        100,
		ContentHash: "blake2b-256:" + strings.Repeat("a", 64),
		Room:        engID,
	}
	raw, _ := json.Marshal(msg)
	s.handleUploadStart(bob.Client, raw)

	if got := s.counters.Get(counters.SignalNonMemberContext, "dev_bob_nonmember_r"); got != 1 {
		t.Errorf("SignalNonMemberContext = %d, want 1", got)
	}
}

func TestHandleUploadStart_NonMemberGroupFiresSignal(t *testing.T) {
	s := newTestServer(t)
	if err := s.store.CreateGroup("group_nm_signal", "alice", []string{"alice"}, "Test"); err != nil {
		t.Fatalf("create group: %v", err)
	}

	bob := testClientFor("bob", "dev_bob_nonmember_g")
	msg := protocol.UploadStart{
		Type:        "upload_start",
		UploadID:    store.GenerateID("up_"),
		Size:        100,
		ContentHash: "blake2b-256:" + strings.Repeat("a", 64),
		Group:       "group_nm_signal",
	}
	raw, _ := json.Marshal(msg)
	s.handleUploadStart(bob.Client, raw)

	if got := s.counters.Get(counters.SignalNonMemberContext, "dev_bob_nonmember_g"); got != 1 {
		t.Errorf("SignalNonMemberContext = %d, want 1", got)
	}
}

func TestHandleUploadStart_NonMemberDMFiresSignal(t *testing.T) {
	s := newTestServer(t)
	dm, err := s.store.CreateOrGetDirectMessage(store.GenerateID("dm_"), "alice", "bob")
	if err != nil {
		t.Fatalf("create dm: %v", err)
	}

	carol := testClientFor("carol", "dev_carol_nonmember_d")
	msg := protocol.UploadStart{
		Type:        "upload_start",
		UploadID:    store.GenerateID("up_"),
		Size:        100,
		ContentHash: "blake2b-256:" + strings.Repeat("a", 64),
		DM:          dm.ID,
	}
	raw, _ := json.Marshal(msg)
	s.handleUploadStart(carol.Client, raw)

	if got := s.counters.Get(counters.SignalNonMemberContext, "dev_carol_nonmember_d"); got != 1 {
		t.Errorf("SignalNonMemberContext = %d, want 1", got)
	}
}

func TestHandleDownload_ACLDenyFiresNotFoundSignal(t *testing.T) {
	// Seed a file bound to engineering; bob is not a member.
	s := newTestServer(t)
	engID := s.store.RoomDisplayNameToID("engineering")
	fileID := store.GenerateID("file_")
	if err := s.store.InsertFileContext(fileID, store.FileContextRoom, engID, 100); err != nil {
		t.Fatalf("bind file: %v", err)
	}

	bob := testClientFor("bob", "dev_bob_acl_deny")
	bob.Client.DownloadChannel = &noopChannel{} // satisfy no-channel check so we reach ACL
	msg := protocol.Download{Type: "download", FileID: fileID}
	raw, _ := json.Marshal(msg)
	s.handleDownload(bob.Client, raw)

	if got := s.counters.Get(counters.SignalDownloadNotFound, "dev_bob_acl_deny"); got != 1 {
		t.Errorf("SignalDownloadNotFound (ACL deny) = %d, want 1", got)
	}
}

func TestHandleDownload_FileMissingFiresNotFoundSignal(t *testing.T) {
	// Alice has access to the file_id via file_contexts binding, but
	// the actual bytes don't exist on disk — simulates the cascade-
	// cleanup race.
	s := newTestServer(t)
	generalID := s.store.RoomDisplayNameToID("general")
	fileID := store.GenerateID("file_")
	if err := s.store.InsertFileContext(fileID, store.FileContextRoom, generalID, 100); err != nil {
		t.Fatalf("bind file: %v", err)
	}

	alice := testClientFor("alice", "dev_alice_file_missing")
	alice.Client.DownloadChannel = &noopChannel{}
	msg := protocol.Download{Type: "download", FileID: fileID}
	raw, _ := json.Marshal(msg)
	s.handleDownload(alice.Client, raw)

	if got := s.counters.Get(counters.SignalDownloadNotFound, "dev_alice_file_missing"); got != 1 {
		t.Errorf("SignalDownloadNotFound (file missing) = %d, want 1", got)
	}
}

func TestHandleDownload_NoChannelFiresSignal(t *testing.T) {
	// ACL passes (alice is in general, file bound to general post-join),
	// but DownloadChannel is nil — fires SignalDownloadNoChannel.
	s := newTestServer(t)
	generalID := s.store.RoomDisplayNameToID("general")
	fileID := store.GenerateID("file_")
	if err := s.store.InsertFileContext(fileID, store.FileContextRoom, generalID, aliceFutureTS()); err != nil {
		t.Fatalf("bind file: %v", err)
	}

	alice := testClientFor("alice", "dev_alice_nochannel")
	// alice.Client.DownloadChannel intentionally left nil
	msg := protocol.Download{Type: "download", FileID: fileID}
	raw, _ := json.Marshal(msg)
	s.handleDownload(alice.Client, raw)

	if got := s.counters.Get(counters.SignalDownloadNoChannel, "dev_alice_nochannel"); got != 1 {
		t.Errorf("SignalDownloadNoChannel = %d, want 1", got)
	}
}

func TestHandleBinaryChannel_HashMismatchFiresCounter(t *testing.T) {
	s := newTestServer(t)

	alice := testClientFor("alice", "dev_alice_hashmisS")
	s.mu.Lock()
	s.clients["dev_alice_hashmisS"] = alice.Client
	s.mu.Unlock()

	// Seed a pending upload whose content_hash doesn't match the
	// payload we're about to send — produces mismatch at commit.
	payload := []byte("hello")
	uploadID := store.GenerateID("up_")
	s.files.mu.Lock()
	s.files.uploads[uploadID] = &pendingUpload{
		uploadID:    uploadID,
		fileID:      store.GenerateID("file_"),
		size:        int64(len(payload)),
		contentHash: "blake2b-256:" + strings.Repeat("f", 64), // wrong — payload hashes to something else
		user:        "alice",
	}
	s.files.mu.Unlock()

	frame := buildUploadFrame(uploadID, uint64(len(payload)), payload)
	ch := newBufferedChannel(frame)

	s.handleBinaryChannel("alice", ch)

	// Channel 3 attribution limitation: counter fires under empty
	// deviceID per Step 2 spec. Phase 17b sees aggregate signal at the
	// empty-device bucket.
	if got := s.counters.Get(counters.SignalInvalidContentHash, ""); got != 1 {
		t.Errorf("SignalInvalidContentHash (empty device) = %d, want 1", got)
	}

	// Pending entry should be evicted by failUpload — verify the cleanup
	// composition with the counter wiring.
	s.files.mu.RLock()
	_, exists := s.files.uploads[uploadID]
	s.files.mu.RUnlock()
	if exists {
		t.Error("pending upload should have been dropped after hash-mismatch rejection")
	}
}
