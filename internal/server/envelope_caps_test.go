package server

// Phase 17 Step 4c Part 2 — envelope cap tests.
//
// Locks in:
//   - file_ids[] > [files].max_file_ids_per_message → SignalFileIDsOverCap,
//     file_ids_over_cap wire code. Config-driven; tests set the value
//     explicitly via s.cfg so the default doesn't leak into assertions.
//   - file_ids[] element fails ValidateNanoID → SignalInvalidNanoID, invalid_file_id wire code.
//   - wrapped_keys map > max_members → SignalWrappedKeysOverCap, wrapped_keys_over_cap wire code.
//     Applied at handleSendGroup, handleEditGroup, handleReact, handleSendDM, handleEditDM.
//   - a room's epoch_rotate is NOT under that cap: rooms have no member limit, and the
//     keys are held to the room's own member list (stale_member_list, no signal).
//
// Caps are enforced BEFORE any DB round-trip — the cheaper check
// protects the more expensive membership / context lookup from
// attacker-sized input.

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/brushtailmedia/sshkey-chat/internal/counters"
	"github.com/brushtailmedia/sshkey-chat/internal/protocol"
	"github.com/brushtailmedia/sshkey-chat/internal/store"
	"github.com/brushtailmedia/sshkey-chat/internal/testutil"
)

// genFileIDs returns n freshly-generated file_ IDs, each passing
// ValidateNanoID. Used to construct an over-cap slice whose elements
// individually are well-formed.
func genFileIDs(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = store.GenerateID("file_")
	}
	return out
}

// genWrappedKeys returns a wrapped_keys-shaped map with n entries. Only the
// count is under test here, but the values are real-size wraps all the
// same: a four-character dummy is what hid, for months, that a group at the
// member cap could not send under the 16 KB frame check (see
// TestFixtures_NoDummyWrappedKeys).
func genWrappedKeys(n int) map[string]string {
	out := make(map[string]string, n)
	for i := 0; i < n; i++ {
		// Users are just keys in this map; any string works for the cap check.
		user := "usr_filler_" + strings.Repeat("a", 11) // ~22 chars, stable length
		key := user + strings.Repeat("x", 3) + toBase26(i)
		out[key] = testutil.WrappedKey(key)
	}
	return out
}

// toBase26 turns n into a short lowercase-letter tag so each
// genWrappedKeys entry has a distinct user ID. Max n ~26^3 = 17576.
func toBase26(n int) string {
	if n == 0 {
		return "a"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('a' + n%26)}, b...)
		n /= 26
	}
	return string(b)
}

func TestHandleSend_FileIDsOverCapRejected(t *testing.T) {
	s := newTestServer(t)
	// Pin the cap at a small value so the test is self-contained —
	// doesn't depend on the default (20) and produces tight assertions.
	const testCap = 5
	s.cfg.Lock()
	s.cfg.Server.Files.MaxFileIDsPerMessage = testCap
	s.cfg.Unlock()

	generalID := s.store.RoomDisplayNameToID("general")

	alice := testClientFor(testutil.UserID("alice"), "dev_alice_fidscap1")
	msg := protocol.Send{
		Type:    "send",
		Room:    generalID,
		Payload: "hi",
		FileIDs: genFileIDs(testCap + 1), // one over cap
	}
	raw, _ := json.Marshal(msg)
	s.handleSend(alice.Client, raw)

	msgs := alice.messages()
	if len(msgs) != 1 {
		t.Fatalf("expected 1 reply, got %d", len(msgs))
	}
	var errResp protocol.Error
	json.Unmarshal(msgs[0], &errResp)
	if errResp.Code != "file_ids_over_cap" {
		t.Errorf("code = %q, want file_ids_over_cap", errResp.Code)
	}
	if got := s.counters.Get(counters.SignalFileIDsOverCap, "dev_alice_fidscap1"); got != 1 {
		t.Errorf("SignalFileIDsOverCap = %d, want 1", got)
	}
}

func TestHandleSend_FileIDsInvalidShapeRejected(t *testing.T) {
	s := newTestServer(t)
	generalID := s.store.RoomDisplayNameToID("general")

	alice := testClientFor(testutil.UserID("alice"), "dev_alice_fidshape")
	msg := protocol.Send{
		Type:    "send",
		Room:    generalID,
		Payload: "hi",
		FileIDs: []string{"file_too_short"}, // malformed: short file ID must fail the suffix length check
	}
	raw, _ := json.Marshal(msg)
	s.handleSend(alice.Client, raw)

	msgs := alice.messages()
	if len(msgs) != 1 {
		t.Fatalf("expected 1 reply, got %d", len(msgs))
	}
	var errResp protocol.Error
	json.Unmarshal(msgs[0], &errResp)
	if errResp.Code != "invalid_file_id" {
		t.Errorf("code = %q, want invalid_file_id", errResp.Code)
	}
	if got := s.counters.Get(counters.SignalInvalidNanoID, "dev_alice_fidshape"); got != 1 {
		t.Errorf("SignalInvalidNanoID = %d, want 1", got)
	}
}

func TestHandleSend_FileIDsAtCapAccepted(t *testing.T) {
	// Exactly cap entries — must pass the cap check (boundary test).
	// The send still fails for other reasons (no file_contexts
	// bindings) but the cap check itself must not fire.
	s := newTestServer(t)
	const testCap = 5
	s.cfg.Lock()
	s.cfg.Server.Files.MaxFileIDsPerMessage = testCap
	s.cfg.Unlock()

	generalID := s.store.RoomDisplayNameToID("general")

	alice := testClientFor(testutil.UserID("alice"), "dev_alice_fidsat")
	msg := protocol.Send{
		Type:    "send",
		Room:    generalID,
		Payload: "hi",
		FileIDs: genFileIDs(testCap), // exactly cap, not over
	}
	raw, _ := json.Marshal(msg)
	s.handleSend(alice.Client, raw)

	if got := s.counters.Get(counters.SignalFileIDsOverCap, "dev_alice_fidsat"); got != 0 {
		t.Errorf("SignalFileIDsOverCap = %d, want 0 at exactly-cap", got)
	}
}

func TestHandleSendGroup_WrappedKeysOverCapRejected(t *testing.T) {
	s := newTestServer(t)
	// Lower the cap so we don't need to construct a 101-entry map.
	s.cfg.Lock()
	s.cfg.Server.Groups.MaxMembers = 3
	s.cfg.Unlock()

	alice := testClientFor(testutil.UserID("alice"), "dev_alice_wkcap1")
	msg := protocol.SendGroup{
		Type:        "send_group",
		Group:       testutil.GroupID("doesnt_matter_"), // membership check would fail anyway; cap is checked first
		WrappedKeys: genWrappedKeys(4),                  // one over cap
		Payload:     "hi",
	}
	raw, _ := json.Marshal(msg)
	s.handleSendGroup(alice.Client, raw)

	msgs := alice.messages()
	var errResp protocol.Error
	json.Unmarshal(msgs[0], &errResp)
	if errResp.Code != "wrapped_keys_over_cap" {
		t.Errorf("code = %q, want wrapped_keys_over_cap", errResp.Code)
	}
	if got := s.counters.Get(counters.SignalWrappedKeysOverCap, "dev_alice_wkcap1"); got != 1 {
		t.Errorf("SignalWrappedKeysOverCap = %d, want 1", got)
	}
}

func TestHandleEditGroup_WrappedKeysOverCapRejected(t *testing.T) {
	s := newTestServer(t)
	s.cfg.Lock()
	s.cfg.Server.Groups.MaxMembers = 2
	s.cfg.Unlock()

	alice := testClientFor(testutil.UserID("alice"), "dev_alice_edit_wkcap")
	msg := protocol.EditGroup{
		Type:        "edit_group",
		ID:          store.GenerateID("msg_"),
		Group:       store.GenerateID("group_"),
		WrappedKeys: genWrappedKeys(5),
		Payload:     "hi",
	}
	raw, _ := json.Marshal(msg)
	s.handleEditGroup(alice.Client, raw)

	msgs := alice.messages()
	var errResp protocol.Error
	json.Unmarshal(msgs[0], &errResp)
	if errResp.Code != "wrapped_keys_over_cap" {
		t.Errorf("code = %q, want wrapped_keys_over_cap", errResp.Code)
	}
	if got := s.counters.Get(counters.SignalWrappedKeysOverCap, "dev_alice_edit_wkcap"); got != 1 {
		t.Errorf("SignalWrappedKeysOverCap = %d, want 1", got)
	}
}

// pendingRotationAboveGroupCap sets [groups] max_members below the size of
// the seeded room general, puts a rotation in flight for it and returns the
// room, its members and the pending epoch. Rooms have no member limit, so
// the group cap must not reach a room's epoch_rotate.
func pendingRotationAboveGroupCap(t *testing.T, s *Server) (room string, members []string, epoch int64) {
	t.Helper()
	const groupCap = 2
	s.cfg.Lock()
	s.cfg.Server.Groups.MaxMembers = groupCap
	s.cfg.Unlock()

	room = s.store.RoomDisplayNameToID("general")
	members = s.store.GetRoomMemberIDsByRoomID(room)
	if len(members) <= groupCap {
		t.Fatalf("general has %d members; this case needs more than the group cap (%d)", len(members), groupCap)
	}
	s.epochs.getOrCreate(room, 0)
	epoch = s.epochs.startRotation(room, func() {})
	if epoch == 0 {
		t.Fatal("startRotation returned 0")
	}
	return room, members, epoch
}

func TestHandleEpochRotate_RoomAboveGroupCapRotates(t *testing.T) {
	s := newTestServer(t)
	room, members, epoch := pendingRotationAboveGroupCap(t, s)

	const device = "dev_alice_room_over_cap"
	alice := testClientFor(testutil.UserID("alice"), device)
	wk := make(map[string]string, len(members))
	for _, m := range members {
		wk[m] = testutil.WrappedKey(m)
	}
	raw, _ := json.Marshal(protocol.EpochRotate{
		Type:        "epoch_rotate",
		Room:        room,
		Epoch:       epoch,
		WrappedKeys: wk,
		MemberHash:  "SHA256:deadbeef",
		MemberSig:   "c2lnbmF0dXJl", // opaque to the server
	})
	s.handleEpochRotate(alice.Client, raw)

	frames := alice.messages()
	var confirmed protocol.EpochConfirmed
	if len(frames) == 1 {
		_ = json.Unmarshal(frames[0], &confirmed)
	}
	if confirmed.Type != "epoch_confirmed" || confirmed.Room != room || confirmed.Epoch != epoch {
		t.Errorf("frames to the rotating member = %s, want exactly one epoch_confirmed for room %s epoch %d", frames, room, epoch)
	}
	if got, err := s.store.GetCurrentEpoch(room); err != nil || got != epoch {
		t.Errorf("stored current epoch = %d (err %v), want %d", got, err, epoch)
	}
	for _, m := range members {
		if got, err := s.store.GetEpochKey(room, epoch, m); err != nil || got != wk[m] {
			t.Errorf("stored key for %s: err %v, matches the key sent = %v", m, err, got == wk[m])
		}
	}
	if got := s.counters.Get(counters.SignalWrappedKeysOverCap, device); got != 0 {
		t.Errorf("SignalWrappedKeysOverCap = %d, want 0: a room's rotation is not under the group cap", got)
	}
}

func TestHandleEpochRotate_KeysBeyondTheRoomAreStaleNotASignal(t *testing.T) {
	s := newTestServer(t)
	room, members, epoch := pendingRotationAboveGroupCap(t, s)

	const device = "dev_alice_room_extra_keys"
	alice := testClientFor(testutil.UserID("alice"), device)
	wk := make(map[string]string, len(members)+2)
	for _, m := range append(members, testutil.UserID("outsider1"), testutil.UserID("outsider2")) {
		wk[m] = testutil.WrappedKey(m)
	}
	raw, _ := json.Marshal(protocol.EpochRotate{
		Type:        "epoch_rotate",
		Room:        room,
		Epoch:       epoch,
		WrappedKeys: wk,
		MemberHash:  "SHA256:deadbeef",
		MemberSig:   "c2lnbmF0dXJl", // opaque to the server
	})
	s.handleEpochRotate(alice.Client, raw)

	// The refusal is followed by a fresh epoch_trigger to the same member
	// (the existing retry); the refusal is the only error.
	frames := alice.messages()
	if codes := errorCodes(frames); len(codes) != 1 || codes[0] != protocol.ErrStaleMemberList {
		t.Errorf("error codes = %v, want only %s", codes, protocol.ErrStaleMemberList)
	}
	if n := countEnvelopeType(t, frames, "epoch_confirmed"); n != 0 {
		t.Errorf("a rotation with keys beyond the room's members was confirmed")
	}
	if got, err := s.store.GetCurrentEpoch(room); err != nil || got != 0 {
		t.Errorf("stored current epoch = %d (err %v), want 0: nothing may be stored", got, err)
	}
	if got := s.counters.Get(counters.SignalWrappedKeysOverCap, device); got != 0 {
		t.Errorf("SignalWrappedKeysOverCap = %d, want 0: a key-count mismatch in a room is not misbehaviour", got)
	}
}

func TestHandleSendDM_WrappedKeysOverCapObservability(t *testing.T) {
	// Phase 17 Step 4c gap-closure: len==2 correctness gate is the
	// tight bound in handleSendDM, but this cap check fires FIRST so
	// Phase 17b sees SignalWrappedKeysOverCap for DM abuse that would
	// otherwise only surface as ErrInvalidWrappedKeys with no counter.
	s := newTestServer(t)
	s.cfg.Lock()
	s.cfg.Server.Groups.MaxMembers = 3
	s.cfg.Unlock()

	dm, err := s.store.CreateOrGetDirectMessage(store.GenerateID("dm_"), testutil.UserID("alice"), testutil.UserID("bob"))
	if err != nil {
		t.Fatalf("create dm: %v", err)
	}

	alice := testClientFor(testutil.UserID("alice"), "dev_alice_dm_wkcap")
	msg := protocol.SendDM{
		Type:        "send_dm",
		DM:          dm.ID,
		WrappedKeys: genWrappedKeys(5), // over the 3-cap
		Payload:     "hi",
	}
	raw, _ := json.Marshal(msg)
	s.handleSendDM(alice.Client, raw)

	if got := s.counters.Get(counters.SignalWrappedKeysOverCap, "dev_alice_dm_wkcap"); got != 1 {
		t.Errorf("SignalWrappedKeysOverCap (DM send) = %d, want 1", got)
	}
}

func TestHandleEditDM_WrappedKeysOverCapObservability(t *testing.T) {
	s := newTestServer(t)
	s.cfg.Lock()
	s.cfg.Server.Groups.MaxMembers = 3
	s.cfg.Unlock()

	alice := testClientFor(testutil.UserID("alice"), "dev_alice_dm_edit_wkcap")
	msg := protocol.EditDM{
		Type:        "edit_dm",
		ID:          store.GenerateID("msg_"),
		DM:          store.GenerateID("dm_"),
		WrappedKeys: genWrappedKeys(5),
		Payload:     "hi",
	}
	raw, _ := json.Marshal(msg)
	s.handleEditDM(alice.Client, raw)

	if got := s.counters.Get(counters.SignalWrappedKeysOverCap, "dev_alice_dm_edit_wkcap"); got != 1 {
		t.Errorf("SignalWrappedKeysOverCap (DM edit) = %d, want 1", got)
	}
}

func TestHandleReact_WrappedKeysOverCapRejected(t *testing.T) {
	s := newTestServer(t)
	s.cfg.Lock()
	s.cfg.Server.Groups.MaxMembers = 2
	s.cfg.Unlock()

	alice := testClientFor(testutil.UserID("alice"), "dev_alice_react_wkcap")
	msg := protocol.React{
		Type:        "react",
		ID:          store.GenerateID("msg_"),
		Group:       store.GenerateID("group_"),
		WrappedKeys: genWrappedKeys(5),
		Payload:     "👍",
	}
	raw, _ := json.Marshal(msg)
	s.handleReact(alice.Client, raw)

	if got := s.counters.Get(counters.SignalWrappedKeysOverCap, "dev_alice_react_wkcap"); got != 1 {
		t.Errorf("SignalWrappedKeysOverCap = %d, want 1", got)
	}
}

func TestCheckWrappedKeysCap_ZeroConfigFallback(t *testing.T) {
	// Direct helper test: MaxMembers=0 triggers the defensive fallback
	// to config.DefaultMaxGroupMembers (100). A 3-entry map must be
	// accepted (100 > 3); a 101-entry map must not.
	s := newTestServer(t)
	s.cfg.Lock()
	s.cfg.Server.Groups.MaxMembers = 0
	s.cfg.Unlock()

	alice := testClientFor(testutil.UserID("alice"), "dev_alice_zero_cap")
	if !s.checkWrappedKeysCap(alice.Client, genWrappedKeys(3), "test") {
		t.Error("checkWrappedKeysCap with max_members=0 (fallback 100) should accept 3 entries")
	}
	if s.checkWrappedKeysCap(alice.Client, genWrappedKeys(101), "test") {
		t.Error("checkWrappedKeysCap with max_members=0 (fallback 100) should reject 101 entries")
	}
}

func TestCheckFileIDsCapAndShape_ConfigKnobTakesEffect(t *testing.T) {
	// Operator bumps [files].max_file_ids_per_message; the new ceiling
	// is what the check applies. Matches Phase 17's operator-tunable
	// philosophy — a photo-sharing-heavy deployment can raise the limit
	// without a code change.
	s := newTestServer(t)
	s.cfg.Lock()
	s.cfg.Server.Files.MaxFileIDsPerMessage = 50
	s.cfg.Unlock()

	alice := testClientFor(testutil.UserID("alice"), "dev_alice_knob")

	// 40 file_ids — under the bumped ceiling. Must accept.
	if !s.checkFileIDsCapAndShape(alice.Client, genFileIDs(40), "test") {
		t.Error("40 file_ids should accept when ceiling is 50")
	}

	// 51 file_ids — over the bumped ceiling. Must reject.
	if s.checkFileIDsCapAndShape(alice.Client, genFileIDs(51), "test") {
		t.Error("51 file_ids should reject when ceiling is 50")
	}
}

func TestCheckFileIDsCapAndShape_ZeroConfigFallback(t *testing.T) {
	// max_file_ids_per_message = 0 → defensive fallback to
	// defaultFileIDsCap (20). A 15-entry slice must pass, a 25-entry
	// slice must fail.
	s := newTestServer(t)
	s.cfg.Lock()
	s.cfg.Server.Files.MaxFileIDsPerMessage = 0
	s.cfg.Unlock()

	alice := testClientFor(testutil.UserID("alice"), "dev_alice_knob_zero")
	if !s.checkFileIDsCapAndShape(alice.Client, genFileIDs(15), "test") {
		t.Error("15 file_ids should accept under fallback cap (20)")
	}
	if s.checkFileIDsCapAndShape(alice.Client, genFileIDs(25), "test") {
		t.Error("25 file_ids should reject under fallback cap (20)")
	}
}

func TestCheckFileIDsCapAndShape_EmptyAccepted(t *testing.T) {
	// Empty / nil slice must be accepted without touching the ValidateNanoID
	// loop — no counter increments, no encoder writes.
	s := newTestServer(t)
	alice := testClientFor(testutil.UserID("alice"), "dev_alice_empty_fids")

	if !s.checkFileIDsCapAndShape(alice.Client, nil, "test") {
		t.Error("nil file_ids should accept")
	}
	if !s.checkFileIDsCapAndShape(alice.Client, []string{}, "test") {
		t.Error("empty file_ids should accept")
	}
	if len(alice.messages()) != 0 {
		t.Errorf("empty file_ids should not write to client; got %d messages", len(alice.messages()))
	}
}
