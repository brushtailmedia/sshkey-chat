package server

// Phase 17 Step 4c Part 1 — shape/format validation tests.
//
// Covers:
//   - handleUploadStart rejects malformed upload_id (fires
//     SignalInvalidNanoID, response omits the echoed UploadID).
//   - handleUploadStart rejects malformed content_hash (fires
//     SignalInvalidContentHash, response has `invalid_content_hash`
//     code).
//   - handleSetProfile rejects malformed avatar_id when non-empty
//     (fires SignalInvalidNanoID, returns invalid_profile error).
//   - Happy path: empty avatar_id is accepted (no avatar).
//
// Format contract under test (from PROTOCOL.md):
//   - upload_id: `up_` + 21 nanoid-alphabet chars
//   - content_hash: `blake2b-256:[0-9a-f]{64}` — lowercase hex only
//   - avatar_id (optional): `file_` + 21 nanoid-alphabet chars

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/brushtailmedia/sshkey-chat/internal/counters"
	"github.com/brushtailmedia/sshkey-chat/internal/protocol"
	"github.com/brushtailmedia/sshkey-chat/internal/store"
)

// validHash returns a content_hash that passes the strict format check.
// Used where a test wants to isolate the upload_id / avatar_id checks
// without tripping on content_hash.
func validHash() string {
	return "blake2b-256:" + strings.Repeat("a", 64)
}

func TestHandleUploadStart_InvalidUploadID_ShortStub(t *testing.T) {
	s := newTestServer(t)
	generalID := s.store.RoomDisplayNameToID("general")

	alice := testClientFor("alice", "dev_alice_shape1")
	msg := protocol.UploadStart{
		Type:        "upload_start",
		UploadID:    "up_x", // too short — fails length check
		Size:        100,
		ContentHash: validHash(),
		Room:        generalID,
	}
	raw, _ := json.Marshal(msg)
	s.handleUploadStart(alice.Client, raw)

	msgs := alice.messages()
	if len(msgs) != 1 {
		t.Fatalf("expected 1 reply, got %d", len(msgs))
	}
	var errResp protocol.UploadError
	json.Unmarshal(msgs[0], &errResp)
	if errResp.Code != "invalid_upload_id" {
		t.Errorf("code = %q, want invalid_upload_id", errResp.Code)
	}
	// The malformed upload_id MUST NOT be echoed back — avoids log
	// injection via buggy clients shipping control characters.
	if errResp.UploadID != "" {
		t.Errorf("malformed upload_id should NOT be echoed, got %q", errResp.UploadID)
	}

	// SignalInvalidNanoID fired under the device's bucket.
	if got := s.counters.Get(counters.SignalInvalidNanoID, "dev_alice_shape1"); got != 1 {
		t.Errorf("SignalInvalidNanoID = %d, want 1", got)
	}
}

func TestHandleUploadStart_InvalidUploadID_WrongPrefix(t *testing.T) {
	s := newTestServer(t)
	generalID := s.store.RoomDisplayNameToID("general")

	alice := testClientFor("alice", "dev_alice_shape2")
	// Use a `room_` prefix to prove the prefix check rejects cross-type.
	msg := protocol.UploadStart{
		Type:        "upload_start",
		UploadID:    "room_" + strings.Repeat("a", 21), // wrong prefix but right length
		Size:        100,
		ContentHash: validHash(),
		Room:        generalID,
	}
	raw, _ := json.Marshal(msg)
	s.handleUploadStart(alice.Client, raw)

	msgs := alice.messages()
	var errResp protocol.UploadError
	json.Unmarshal(msgs[0], &errResp)
	if errResp.Code != "invalid_upload_id" {
		t.Errorf("wrong-prefix upload_id: code = %q, want invalid_upload_id", errResp.Code)
	}
}

func TestHandleUploadStart_InvalidContentHash_UppercaseHex(t *testing.T) {
	// Protocol contract is lowercase hex only. Uppercase must be
	// rejected — spec behavior, not a server-side accommodation.
	s := newTestServer(t)
	generalID := s.store.RoomDisplayNameToID("general")

	alice := testClientFor("alice", "dev_alice_hash1")
	msg := protocol.UploadStart{
		Type:        "upload_start",
		UploadID:    store.GenerateID("up_"),
		Size:        100,
		ContentHash: "blake2b-256:" + strings.Repeat("A", 64), // uppercase
		Room:        generalID,
	}
	raw, _ := json.Marshal(msg)
	s.handleUploadStart(alice.Client, raw)

	msgs := alice.messages()
	var errResp protocol.UploadError
	json.Unmarshal(msgs[0], &errResp)
	if errResp.Code != "invalid_content_hash" {
		t.Errorf("uppercase hex: code = %q, want invalid_content_hash", errResp.Code)
	}
	if got := s.counters.Get(counters.SignalInvalidContentHash, "dev_alice_hash1"); got != 1 {
		t.Errorf("SignalInvalidContentHash = %d, want 1", got)
	}
}

func TestHandleUploadStart_InvalidContentHash_WrongAlgoPrefix(t *testing.T) {
	s := newTestServer(t)
	generalID := s.store.RoomDisplayNameToID("general")

	alice := testClientFor("alice", "dev_alice_hash2")
	msg := protocol.UploadStart{
		Type:        "upload_start",
		UploadID:    store.GenerateID("up_"),
		Size:        100,
		ContentHash: "sha256:" + strings.Repeat("a", 64),
		Room:        generalID,
	}
	raw, _ := json.Marshal(msg)
	s.handleUploadStart(alice.Client, raw)

	msgs := alice.messages()
	var errResp protocol.UploadError
	json.Unmarshal(msgs[0], &errResp)
	if errResp.Code != "invalid_content_hash" {
		t.Errorf("wrong-algo prefix: code = %q, want invalid_content_hash", errResp.Code)
	}
}

func TestHandleUploadStart_InvalidContentHash_ShortBody(t *testing.T) {
	s := newTestServer(t)
	generalID := s.store.RoomDisplayNameToID("general")

	alice := testClientFor("alice", "dev_alice_hash3")
	msg := protocol.UploadStart{
		Type:        "upload_start",
		UploadID:    store.GenerateID("up_"),
		Size:        100,
		ContentHash: "blake2b-256:" + strings.Repeat("a", 32), // half length
		Room:        generalID,
	}
	raw, _ := json.Marshal(msg)
	s.handleUploadStart(alice.Client, raw)

	msgs := alice.messages()
	var errResp protocol.UploadError
	json.Unmarshal(msgs[0], &errResp)
	if errResp.Code != "invalid_content_hash" {
		t.Errorf("short-body hash: code = %q, want invalid_content_hash", errResp.Code)
	}
}

func TestHandleUploadStart_ValidContentHashAccepted(t *testing.T) {
	// Happy path — lowercase 64-char hex passes the format check.
	s := newTestServer(t)
	generalID := s.store.RoomDisplayNameToID("general")

	alice := testClientFor("alice", "dev_alice_hash_happy")
	msg := protocol.UploadStart{
		Type:        "upload_start",
		UploadID:    store.GenerateID("up_"),
		Size:        100,
		ContentHash: "blake2b-256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		Room:        generalID,
	}
	raw, _ := json.Marshal(msg)
	s.handleUploadStart(alice.Client, raw)

	msgs := alice.messages()
	if len(msgs) != 1 {
		t.Fatalf("expected 1 reply, got %d", len(msgs))
	}
	var ready protocol.UploadReady
	json.Unmarshal(msgs[0], &ready)
	if ready.Type != "upload_ready" {
		t.Errorf("type = %q, want upload_ready (valid hash should accept)", ready.Type)
	}

	// Neither malformed-hash nor invalid-nanoid counters should have fired.
	if got := s.counters.Get(counters.SignalInvalidContentHash, "dev_alice_hash_happy"); got != 0 {
		t.Errorf("SignalInvalidContentHash = %d, want 0 on happy path", got)
	}
}

func TestHandleSetProfile_InvalidAvatarID_Rejected(t *testing.T) {
	s := newTestServer(t)

	alice := testClientFor("alice", "dev_alice_avatar1")
	msg := protocol.SetProfile{
		Type:        "set_profile",
		DisplayName: "Alice Replacement",
		AvatarID:    "file_x", // too short — fails length check
	}
	raw, _ := json.Marshal(msg)
	s.handleSetProfile(alice.Client, raw)

	msgs := alice.messages()
	if len(msgs) < 1 {
		t.Fatalf("expected at least 1 reply, got %d", len(msgs))
	}
	var errResp protocol.Error
	json.Unmarshal(msgs[0], &errResp)
	if errResp.Code != "invalid_profile" {
		t.Errorf("code = %q, want invalid_profile", errResp.Code)
	}
	if got := s.counters.Get(counters.SignalInvalidNanoID, "dev_alice_avatar1"); got != 1 {
		t.Errorf("SignalInvalidNanoID = %d, want 1", got)
	}
}

func TestHandleSetProfile_EmptyAvatarIDAccepted(t *testing.T) {
	// Empty avatar_id means "no avatar" — must be allowed without
	// firing the ValidateNanoID check. Locks in the non-empty
	// precondition on the shape check.
	s := newTestServer(t)

	alice := testClientFor("alice", "dev_alice_avatar_empty")
	msg := protocol.SetProfile{
		Type:        "set_profile",
		DisplayName: "Alice No Avatar",
		AvatarID:    "",
	}
	raw, _ := json.Marshal(msg)
	s.handleSetProfile(alice.Client, raw)

	// Empty AvatarID should NOT fire the ValidateNanoID signal.
	if got := s.counters.Get(counters.SignalInvalidNanoID, "dev_alice_avatar_empty"); got != 0 {
		t.Errorf("empty avatar_id fired SignalInvalidNanoID = %d, want 0", got)
	}
}

func TestHandleSetProfile_ValidAvatarIDAccepted(t *testing.T) {
	// Happy path — a properly-shaped file_ nanoid passes validation.
	s := newTestServer(t)

	alice := testClientFor("alice", "dev_alice_avatar_ok")
	msg := protocol.SetProfile{
		Type:        "set_profile",
		DisplayName: "Alice With Avatar",
		AvatarID:    store.GenerateID("file_"),
	}
	raw, _ := json.Marshal(msg)
	s.handleSetProfile(alice.Client, raw)

	if got := s.counters.Get(counters.SignalInvalidNanoID, "dev_alice_avatar_ok"); got != 0 {
		t.Errorf("valid avatar_id fired SignalInvalidNanoID = %d, want 0", got)
	}
}

func TestValidContentHash_UnitCoverage(t *testing.T) {
	// Unit-level coverage on the validContentHash helper for the edge
	// cases that are hard to exercise via the handler path (without
	// triggering other rejections first).
	tests := []struct {
		name string
		h    string
		want bool
	}{
		{"happy lowercase", "blake2b-256:" + strings.Repeat("a", 64), true},
		{"happy mixed hex digits", "blake2b-256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", true},
		{"empty", "", false},
		{"prefix only", "blake2b-256:", false},
		{"short by one", "blake2b-256:" + strings.Repeat("a", 63), false},
		{"long by one", "blake2b-256:" + strings.Repeat("a", 65), false},
		{"uppercase hex", "blake2b-256:" + strings.Repeat("A", 64), false},
		{"wrong algo", "sha256:" + strings.Repeat("a", 64), false},
		{"leading garbage", "x" + "blake2b-256:" + strings.Repeat("a", 64), false},
		{"trailing garbage", "blake2b-256:" + strings.Repeat("a", 64) + "x", false},
		{"non-hex char g", "blake2b-256:" + strings.Repeat("g", 64), false},
		{"non-hex char space", "blake2b-256:" + strings.Repeat(" ", 64), false},
		{"null byte in body", "blake2b-256:" + strings.Repeat("\x00", 64), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := validContentHash(tc.h); got != tc.want {
				t.Errorf("validContentHash(%q) = %v, want %v", tc.h, got, tc.want)
			}
		})
	}
}
