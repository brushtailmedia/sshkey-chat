package server

// Tests for handleRoomUpdate (room_update request handler).
//
// Spec: topic.md §7 in this repo. The 12 tests below mirror the
// spec's test plan one-for-one; the silent-drop inventory entry
// (spec item 12) lives in silent_drop_test.go as a 15th handler.
//
// "Admin" in this file means SERVER admin (users.admin flag).
// "Member" means current room member (IsRoomMemberByID). The
// fixtures construct combinations that exercise each gate
// distinctly so the two auth dimensions can't be conflated.

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/brushtailmedia/sshkey-chat/internal/counters"
	"github.com/brushtailmedia/sshkey-chat/internal/protocol"
	"github.com/brushtailmedia/sshkey-chat/internal/store"
)

func roomUpdateCountType(t *testing.T, msgs []json.RawMessage, typ string) int {
	t.Helper()
	n := 0
	for _, raw := range msgs {
		var env struct {
			Type string `json:"type"`
		}
		if err := json.Unmarshal(raw, &env); err != nil {
			t.Fatalf("parse envelope: %v", err)
		}
		if env.Type == typ {
			n++
		}
	}
	return n
}

func roomUpdateFindRoomUpdated(t *testing.T, msgs []json.RawMessage) protocol.RoomUpdated {
	t.Helper()
	for _, raw := range msgs {
		var env struct {
			Type string `json:"type"`
		}
		if err := json.Unmarshal(raw, &env); err != nil {
			t.Fatalf("parse envelope: %v", err)
		}
		if env.Type != "room_updated" {
			continue
		}
		var ru protocol.RoomUpdated
		if err := json.Unmarshal(raw, &ru); err != nil {
			t.Fatalf("parse room_updated: %v", err)
		}
		return ru
	}
	t.Fatal("missing room_updated frame")
	return protocol.RoomUpdated{}
}

// roomUpdateRaw is a small helper for marshaling a room_update
// frame in tests. Returns the raw JSON bytes ready for handler
// dispatch.
func roomUpdateRaw(t *testing.T, room, topic, corrID string) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(protocol.RoomUpdate{
		Type:   "room_update",
		Room:   room,
		Topic:  topic,
		CorrID: corrID,
	})
	if err != nil {
		t.Fatalf("marshal room_update: %v", err)
	}
	return raw
}

// Test 1 — Server-admin + room-member happy path.
//
// alice is a server admin (users.admin = true) and a member of
// "general". She updates the topic; the broadcast goes out, the
// DB reflects the change, the audit log credits "update-topic",
// and a room_event row is recorded with event = "topic".
//
// Drift guard: assert the broadcast event has NO corr_id field
// (protocol.RoomUpdated has no such field today). A future struct
// extension that started echoing it would silently break send-
// queue correlation semantics; this test would catch it.
func TestHandleRoomUpdate_HappyPath(t *testing.T) {
	s := newTestServer(t)
	generalID := s.store.RoomDisplayNameToID("general")

	alice := testClientFor("alice", "dev_alice_1")
	s.mu.Lock()
	s.clients["dev_alice_1"] = alice.Client
	s.mu.Unlock()

	s.handleRoomUpdate(alice.Client, roomUpdateRaw(t, generalID, "fresh from session", ""))

	// 1. Broadcasts went out, content correct.
	msgs := alice.messages()
	if got := roomUpdateCountType(t, msgs, "room_updated"); got != 1 {
		t.Fatalf("expected 1 room_updated broadcast, got %d (total frames=%d)", got, len(msgs))
	}
	if got := roomUpdateCountType(t, msgs, "room_event"); got != 1 {
		t.Fatalf("expected 1 room_event broadcast, got %d (total frames=%d)", got, len(msgs))
	}
	ru := roomUpdateFindRoomUpdated(t, msgs)
	if ru.Type != "room_updated" {
		t.Errorf("type = %q, want room_updated", ru.Type)
	}
	if ru.Room != generalID {
		t.Errorf("room = %q, want %s", ru.Room, generalID)
	}
	if ru.Topic != "fresh from session" {
		t.Errorf("topic = %q", ru.Topic)
	}
	if ru.DisplayName != "general" {
		t.Errorf("display_name = %q", ru.DisplayName)
	}

	// 2. Drift guard: broadcast carries NO corr_id field.
	var raw map[string]any
	foundRoomUpdatedRaw := false
	for _, frame := range msgs {
		var env struct {
			Type string `json:"type"`
		}
		if err := json.Unmarshal(frame, &env); err != nil {
			t.Fatalf("parse envelope: %v", err)
		}
		if env.Type != "room_updated" {
			continue
		}
		foundRoomUpdatedRaw = true
		if err := json.Unmarshal(frame, &raw); err != nil {
			t.Fatalf("parse raw room_updated: %v", err)
		}
		break
	}
	if !foundRoomUpdatedRaw {
		t.Fatal("missing room_updated frame while checking corr_id drift guard")
	}
	if _, present := raw["corr_id"]; present {
		t.Errorf("room_updated broadcast must not carry corr_id (current protocol.RoomUpdated has no such field); got: %v", raw["corr_id"])
	}

	// 3. DB reflects the change.
	row, err := s.store.GetRoomByID(generalID)
	if err != nil {
		t.Fatalf("get room: %v", err)
	}
	if row.Topic != "fresh from session" {
		t.Errorf("DB topic = %q, want fresh from session", row.Topic)
	}

	// 4. Audit credits update-topic for alice.
	auditBytes, err := readAuditLog(s)
	if err != nil {
		t.Fatalf("read audit: %v", err)
	}
	auditContent := string(auditBytes)
	if !strings.Contains(auditContent, "update-topic") {
		t.Errorf("audit log missing 'update-topic', got: %q", auditContent)
	}
	if !strings.Contains(auditContent, "alice") {
		t.Errorf("audit log missing 'alice' (changed_by), got: %q", auditContent)
	}
	if !strings.Contains(auditContent, "room="+generalID) {
		t.Errorf("audit log missing room=%s, got: %q", generalID, auditContent)
	}

	// 5. room_event row recorded with event = "topic".
	events, err := s.store.GetRoomEventsSince(generalID, 0)
	if err != nil {
		t.Fatalf("get room events: %v", err)
	}
	foundTopic := false
	for _, e := range events {
		if e.Event == "topic" && e.By == "alice" && e.Name == "fresh from session" {
			foundTopic = true
		}
	}
	if !foundTopic {
		t.Errorf("expected room_event(event=topic, by=alice, name='fresh from session'); got %+v", events)
	}
}

// Test 2 — Non-server-admin who IS a room member → forbidden.
//
// bob is a member of general but NOT a server admin (users.admin = false).
// He should be rejected with `forbidden`. Fixture also makes bob a
// group admin elsewhere to confirm the gate reads users.admin and
// NOT IsGroupAdmin — the two roles are independent.
func TestHandleRoomUpdate_NonAdminMemberForbidden(t *testing.T) {
	s := newTestServer(t)
	generalID := s.store.RoomDisplayNameToID("general")

	// Confirm bob is non-admin per fixture.
	if s.store.IsAdmin("bob") {
		t.Fatal("fixture mismatch: bob should be a non-admin")
	}

	// Make bob a group admin elsewhere — wrong gate must not be
	// the one fielding this request.
	if err := s.store.CreateGroup("g_bob_admin", "bob", []string{"bob"}, "Bob's group"); err != nil {
		t.Fatalf("create group: %v", err)
	}
	if isAdmin, err := s.store.IsGroupAdmin("g_bob_admin", "bob"); err != nil || !isAdmin {
		t.Fatalf("fixture mismatch: bob should be a group admin of g_bob_admin (isAdmin=%v err=%v)", isAdmin, err)
	}

	bob := testClientFor("bob", "dev_bob_1")
	s.handleRoomUpdate(bob.Client, roomUpdateRaw(t, generalID, "attempted by bob", ""))

	msgs := bob.messages()
	if len(msgs) != 1 {
		t.Fatalf("expected 1 error frame, got %d", len(msgs))
	}
	var errResp protocol.Error
	if err := json.Unmarshal(msgs[0], &errResp); err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if errResp.Code != protocol.ErrForbidden {
		t.Errorf("code = %q, want %q", errResp.Code, protocol.ErrForbidden)
	}

	// DB should be unchanged.
	row, _ := s.store.GetRoomByID(generalID)
	if row.Topic == "attempted by bob" {
		t.Errorf("DB topic should not have changed; got %q", row.Topic)
	}
}

// Test 3 — Server-admin who is NOT a room member → unknown_room.
//
// Promote bob to server admin (he's non-admin by default per the
// fixture). bob is a member of general but NOT engineering, so
// targeting engineering with an admin-bob client exercises the
// "admin but not a room member" branch. The membership gate at
// step 7 must fire before the load-row step.
//
// Note: SeedRooms can't add a fresh room after newTestServer
// because the rooms.db isn't empty at that point — SeedRooms
// early-returns 0 when there's existing data. Hence the bob-as-
// admin approach rather than seeding a new room.
func TestHandleRoomUpdate_AdminNonMemberUnknownRoom(t *testing.T) {
	s := newTestServer(t)
	engID := s.store.RoomDisplayNameToID("engineering")

	// Make bob a server admin.
	if err := s.store.SetAdmin("bob", true); err != nil {
		t.Fatalf("set bob admin: %v", err)
	}
	if !s.store.IsAdmin("bob") {
		t.Fatal("fixture: bob should be a server admin after SetAdmin")
	}
	// Sanity: bob is NOT a member of engineering.
	if s.store.IsRoomMemberByID(engID, "bob") {
		t.Fatal("fixture: bob should not be in engineering per newTestServer")
	}

	bob := testClientFor("bob", "dev_bob_admin_outsider")
	s.handleRoomUpdate(bob.Client, roomUpdateRaw(t, engID, "attempted by outsider admin", ""))

	msgs := bob.messages()
	if len(msgs) != 1 {
		t.Fatalf("expected 1 error, got %d", len(msgs))
	}
	var errResp protocol.Error
	json.Unmarshal(msgs[0], &errResp)
	if errResp.Code != protocol.ErrUnknownRoom {
		t.Errorf("code = %q, want %q", errResp.Code, protocol.ErrUnknownRoom)
	}
}

// Test 4 — Server-admin sending an unknown room ID → unknown_room.
//
// Same code as test 3 by deliberate privacy parity. Under normal
// data, step 7 (IsRoomMemberByID) catches the unknown-room case
// (no room_members row for a nonexistent room → false). Step 8's
// load-row check is the defense-in-depth second gate for the rare
// orphan-membership case.
func TestHandleRoomUpdate_AdminUnknownRoomID(t *testing.T) {
	s := newTestServer(t)

	alice := testClientFor("alice", "dev_alice_1")
	s.handleRoomUpdate(alice.Client, roomUpdateRaw(t, "rm_does_not_exist", "ghost", ""))

	msgs := alice.messages()
	if len(msgs) != 1 {
		t.Fatalf("expected 1 error, got %d", len(msgs))
	}
	var errResp protocol.Error
	json.Unmarshal(msgs[0], &errResp)
	if errResp.Code != protocol.ErrUnknownRoom {
		t.Errorf("code = %q, want %q", errResp.Code, protocol.ErrUnknownRoom)
	}
}

// Test 5 — Server-admin + member, retired room → room_retired.
func TestHandleRoomUpdate_RetiredRoom(t *testing.T) {
	s := newTestServer(t)
	generalID := s.store.RoomDisplayNameToID("general")

	// Retire general.
	if err := s.store.SetRoomRetired(generalID, "alice", "test-retirement"); err != nil {
		t.Fatalf("retire room: %v", err)
	}

	alice := testClientFor("alice", "dev_alice_1")
	s.handleRoomUpdate(alice.Client, roomUpdateRaw(t, generalID, "attempted on retired room", ""))

	msgs := alice.messages()
	if len(msgs) != 1 {
		t.Fatalf("expected 1 error, got %d", len(msgs))
	}
	var errResp protocol.Error
	json.Unmarshal(msgs[0], &errResp)
	if errResp.Code != protocol.ErrRoomRetired {
		t.Errorf("code = %q, want %q", errResp.Code, protocol.ErrRoomRetired)
	}
}

// Test 6 — Same-value topic (idempotency no-op).
//
// Pre-state: room has topic "current". alice sends a room_update
// with the same topic. Expected:
//   - alice receives a room_updated echo with the current topic
//   - no DB write
//   - no audit row for update-topic
//   - no room_event row
//   - no fanout to other members (bob's buffer stays empty)
func TestHandleRoomUpdate_IdempotencySameValue(t *testing.T) {
	s := newTestServer(t)
	generalID := s.store.RoomDisplayNameToID("general")
	if err := s.store.SetRoomTopic(generalID, "current"); err != nil {
		t.Fatalf("set initial topic: %v", err)
	}

	// Snapshot the events table BEFORE the request — comparing post
	// vs pre lets us detect any new room_event insertion regardless
	// of the timestamp.
	preEvents, _ := s.store.GetRoomEventsSince(generalID, 0)

	alice := testClientFor("alice", "dev_alice_1")
	bob := testClientFor("bob", "dev_bob_1")
	s.mu.Lock()
	s.clients["dev_alice_1"] = alice.Client
	s.clients["dev_bob_1"] = bob.Client
	s.mu.Unlock()

	s.handleRoomUpdate(alice.Client, roomUpdateRaw(t, generalID, "current", ""))

	// alice receives the echo.
	aliceMsgs := alice.messages()
	if len(aliceMsgs) != 1 {
		t.Fatalf("alice should receive 1 echo, got %d", len(aliceMsgs))
	}
	var ru protocol.RoomUpdated
	json.Unmarshal(aliceMsgs[0], &ru)
	if ru.Topic != "current" {
		t.Errorf("echo topic = %q, want current", ru.Topic)
	}

	// bob (other member) receives NOTHING.
	if msgs := bob.messages(); len(msgs) != 0 {
		t.Errorf("bob (other member) should receive nothing on idempotency path, got %d msgs", len(msgs))
	}

	// No room_event row for this action.
	postEvents, _ := s.store.GetRoomEventsSince(generalID, 0)
	if len(postEvents) != len(preEvents) {
		t.Errorf("expected no new room_event row on idempotency path; got %d (pre=%d)", len(postEvents), len(preEvents))
	}

	// Audit log: no "update-topic" entry was added (we check for the
	// changedBy=alice + verb combo — pre-test the audit log is empty
	// because nothing has been audited yet).
	auditBytes, _ := readAuditLog(s)
	if strings.Contains(string(auditBytes), "update-topic") {
		t.Errorf("audit log should not contain update-topic on idempotency path, got: %q", string(auditBytes))
	}
}

// Test 7 — Malformed JSON → invalid_message + SignalMalformedFrame
// counter increment.
//
// Pre-unmarshal: no corr_id available, so the error frame carries
// empty corr_id (mirror of every other handler's malformed-frame
// behavior).
func TestHandleRoomUpdate_MalformedJSON(t *testing.T) {
	s := newTestServer(t)

	alice := testClientFor("alice", "dev_alice_malformed")
	s.handleRoomUpdate(alice.Client, malformedRaw())

	// Counter incremented.
	if got := s.counters.Get(counters.SignalMalformedFrame, "dev_alice_malformed"); got != 1 {
		t.Errorf("SignalMalformedFrame = %d, want 1", got)
	}

	// invalid_message response.
	msgs := alice.messages()
	if len(msgs) != 1 {
		t.Fatalf("expected 1 error, got %d", len(msgs))
	}
	var errResp protocol.Error
	json.Unmarshal(msgs[0], &errResp)
	if errResp.Code != "invalid_message" {
		t.Errorf("code = %q, want invalid_message", errResp.Code)
	}
	if errResp.CorrID != "" {
		t.Errorf("malformed-frame response must carry empty corr_id (pre-unmarshal), got %q", errResp.CorrID)
	}
}

// Test 8 — Clear-topic via empty string broadcasts an empty topic
// and writes "" to the DB.
func TestHandleRoomUpdate_ClearTopic(t *testing.T) {
	s := newTestServer(t)
	generalID := s.store.RoomDisplayNameToID("general")
	if err := s.store.SetRoomTopic(generalID, "to be cleared"); err != nil {
		t.Fatalf("seed topic: %v", err)
	}

	alice := testClientFor("alice", "dev_alice_1")
	s.mu.Lock()
	s.clients["dev_alice_1"] = alice.Client
	s.mu.Unlock()

	s.handleRoomUpdate(alice.Client, roomUpdateRaw(t, generalID, "", ""))

	msgs := alice.messages()
	if got := roomUpdateCountType(t, msgs, "room_updated"); got != 1 {
		t.Fatalf("expected 1 room_updated broadcast, got %d (total frames=%d)", got, len(msgs))
	}
	if got := roomUpdateCountType(t, msgs, "room_event"); got != 1 {
		t.Fatalf("expected 1 room_event broadcast, got %d (total frames=%d)", got, len(msgs))
	}
	ru := roomUpdateFindRoomUpdated(t, msgs)
	if ru.Topic != "" {
		t.Errorf("topic = %q, want empty", ru.Topic)
	}

	row, _ := s.store.GetRoomByID(generalID)
	if row.Topic != "" {
		t.Errorf("DB topic = %q, want empty", row.Topic)
	}
}

// Test 9a — Malformed corr_id is rejected by validateCorrIDOrReject
// with silent-drop on the wire (server log + SignalMalformedFrame
// counter, but no typed response).
func TestHandleRoomUpdate_MalformedCorrID(t *testing.T) {
	s := newTestServer(t)
	generalID := s.store.RoomDisplayNameToID("general")

	// Build a frame with a malformed corr_id by hand (bypass the
	// helper, which uses an unconstrained string and wouldn't yield
	// validation failure if we asked it nicely). 100+ chars trips
	// the length cap in ValidateCorrID.
	badCorrID := strings.Repeat("x", 200)
	raw := json.RawMessage(`{"type":"room_update","room":"` + generalID + `","topic":"x","corr_id":"` + badCorrID + `"}`)

	alice := testClientFor("alice", "dev_alice_badcorr")
	s.handleRoomUpdate(alice.Client, raw)

	// Counter fires.
	if got := s.counters.Get(counters.SignalMalformedFrame, "dev_alice_badcorr"); got != 1 {
		t.Errorf("SignalMalformedFrame = %d, want 1", got)
	}

	// No typed response on the wire (silent drop convention).
	if msgs := alice.messages(); len(msgs) != 0 {
		t.Errorf("malformed corr_id must produce silent drop; got %d response frames: %s", len(msgs), msgs)
	}
}

// Test 9b — Typed errors after successful unmarshal echo corr_id.
//
// bob (non-admin) sends a room_update with a VALID-format corr_id;
// the `forbidden` response must echo it for send-queue correlation
// parity with other corr_id-carrying verbs.
//
// corr_id format is "corr_" + 21 chars from the nanoid alphabet
// (see internal/protocol/corrid.go). A 21-char filler-string keeps
// the test deterministic without pulling in a generator dependency.
func TestHandleRoomUpdate_TypedErrorEchoesCorrID(t *testing.T) {
	s := newTestServer(t)
	generalID := s.store.RoomDisplayNameToID("general")

	corrID := "corr_aaaaaaaaaaaaaaaaaaaaa" // "corr_" + 21 a's
	bob := testClientFor("bob", "dev_bob_corrid")
	s.handleRoomUpdate(bob.Client, roomUpdateRaw(t, generalID, "denied", corrID))

	msgs := bob.messages()
	if len(msgs) != 1 {
		t.Fatalf("expected 1 error, got %d", len(msgs))
	}
	var errResp protocol.Error
	json.Unmarshal(msgs[0], &errResp)
	if errResp.Code != protocol.ErrForbidden {
		t.Errorf("code = %q, want forbidden", errResp.Code)
	}
	if errResp.CorrID != corrID {
		t.Errorf("corr_id = %q, want %q", errResp.CorrID, corrID)
	}
}

// Test 10 — Rate-limit behavior.
//
// Bucket key is user-scoped for room admin actions:
//   - exhausting room_update on room A ALSO blocks room_update on room B
//     for the same user
//   - but does NOT affect group-admin buckets (different key prefix)
//
// Setup: AdminActionsPerMinute = 1. The limiter has a 5-token
// minimum burst regardless of the per-minute rate, so we fire 7
// requests on general to guarantee burst exhaustion.
func TestHandleRoomUpdate_RateLimitUserScopedAndCorrIDEcho(t *testing.T) {
	s := newTestServer(t)
	s.cfg.Lock()
	s.cfg.Server.RateLimits.AdminActionsPerMinute = 1
	s.cfg.Unlock()

	generalID := s.store.RoomDisplayNameToID("general")
	engID := s.store.RoomDisplayNameToID("engineering")

	alice := testClientFor("alice", "dev_alice_rl")
	s.mu.Lock()
	s.clients["dev_alice_rl"] = alice.Client
	s.mu.Unlock()

	corrID := "corr_aaaaaaaaaaaaaaaaaaaaa" // valid CorrID shape

	// Fire 7 room_update requests on general — exhausts the 5-token
	// burst; later responses are rate_limited.
	for i := 0; i < 7; i++ {
		s.handleRoomUpdate(alice.Client, roomUpdateRaw(t, generalID, "burst", corrID))
	}
	msgs := alice.messages()
	if len(msgs) == 0 {
		t.Fatal("expected at least one response across the 7-request burst")
	}
	// Last message must be the rate_limited rejection and echo corr_id.
	var lastErr protocol.Error
	if err := json.Unmarshal(msgs[len(msgs)-1], &lastErr); err != nil {
		t.Fatalf("parse last response: %v", err)
	}
	if lastErr.Code != protocol.ErrRateLimited {
		t.Errorf("last response code = %q, want rate_limited (burst should be exhausted)", lastErr.Code)
	}
	if lastErr.RetryAfterMs <= 0 {
		t.Errorf("retry_after_ms = %d, want > 0", lastErr.RetryAfterMs)
	}
	if lastErr.CorrID != corrID {
		t.Errorf("corr_id on rate_limited = %q, want %q", lastErr.CorrID, corrID)
	}
	// SignalRateLimited fires for at least the rejected requests.
	if got := s.counters.Get(counters.SignalRateLimited, "dev_alice_rl"); got == 0 {
		t.Errorf("SignalRateLimited = 0, want > 0")
	}
	alice.buf.Reset()

	// Probe 1: alice on engineering (different room) should STILL be
	// rate-limited because room_admin_action is user-scoped.
	s.handleRoomUpdate(alice.Client, roomUpdateRaw(t, engID, "eng update", corrID))
	msgs = alice.messages()
	if len(msgs) != 1 {
		t.Fatalf("engineering probe: expected 1 response, got %d", len(msgs))
	}
	var engErr protocol.Error
	if err := json.Unmarshal(msgs[0], &engErr); err != nil {
		t.Fatalf("parse engineering probe: %v", err)
	}
	if engErr.Code != protocol.ErrRateLimited {
		t.Errorf("engineering probe code = %q, want rate_limited", engErr.Code)
	}
	if engErr.CorrID != corrID {
		t.Errorf("engineering probe corr_id = %q, want %q", engErr.CorrID, corrID)
	}
	alice.buf.Reset()

	// Probe 2: alice via handleAddToGroup (different bucket-key
	// prefix → group_admin, separate from room_admin_action). The
	// group_admin:alice:<group> bucket is fresh.
	if err := s.store.CreateGroup("g_rl_probe", "alice", []string{"alice"}, "rl probe"); err != nil {
		t.Fatalf("create group: %v", err)
	}
	addRaw, _ := json.Marshal(protocol.AddToGroup{
		Type:  "add_to_group",
		Group: "g_rl_probe",
		User:  "bob",
	})
	s.handleAddToGroup(alice.Client, addRaw)
	// We don't assert on add_to_group's response shape — only that
	// it did NOT respond with rate_limited.
	addMsgs := alice.messages()
	for _, m := range addMsgs {
		var maybeErr protocol.Error
		if err := json.Unmarshal(m, &maybeErr); err == nil && maybeErr.Type == "error" && maybeErr.Code == protocol.ErrRateLimited {
			t.Errorf("group_admin bucket should NOT share the room_admin_action limiter; got rate_limited response from add_to_group: %s", m)
		}
	}
}

// Test 11 — Queue processor regression / shared-helper parity.
//
// Both the CLI path (processPendingRoomUpdates) and the request
// path (handleRoomUpdate) converge through emitRoomUpdate. This
// test triggers both paths with the same (action, room, by,
// value) inputs and asserts the resulting audit message, room_
// event row, and room_updated broadcast are byte-identical
// (within TS tolerance for the room_event).
func TestHandleRoomUpdate_SharedHelperParity(t *testing.T) {
	s := newTestServer(t)
	generalID := s.store.RoomDisplayNameToID("general")

	alice := testClientFor("alice", "dev_alice_parity")
	s.mu.Lock()
	s.clients["dev_alice_parity"] = alice.Client
	s.mu.Unlock()

	// === Path 1: in-session request via handleRoomUpdate ===
	if err := s.store.SetRoomTopic(generalID, "baseline"); err != nil {
		t.Fatalf("seed baseline: %v", err)
	}
	s.handleRoomUpdate(alice.Client, roomUpdateRaw(t, generalID, "shared-helper-test", ""))
	path1Msgs := alice.messages()
	if roomUpdateCountType(t, path1Msgs, "room_updated") != 1 || roomUpdateCountType(t, path1Msgs, "room_event") != 1 {
		t.Fatalf("path1: expected 1 room_updated + 1 room_event, got %d total", len(path1Msgs))
	}
	path1Audit, _ := readAuditLog(s)
	path1Events, _ := s.store.GetRoomEventsSince(generalID, 0)

	// Reset shared state for path 2.
	alice.buf.Reset()
	if err := s.store.SetRoomTopic(generalID, "baseline"); err != nil {
		t.Fatalf("reset baseline: %v", err)
	}

	// === Path 2: CLI queue via processPendingRoomUpdates ===
	if err := s.store.SetRoomTopic(generalID, "shared-helper-test"); err != nil {
		t.Fatalf("path2 set topic: %v", err)
	}
	if err := s.store.RecordPendingRoomUpdate(generalID, store.RoomUpdateActionUpdateTopic, "alice", "shared-helper-test"); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	s.processPendingRoomUpdates()
	path2Msgs := alice.messages()
	if roomUpdateCountType(t, path2Msgs, "room_updated") != 1 || roomUpdateCountType(t, path2Msgs, "room_event") != 1 {
		t.Fatalf("path2: expected 1 room_updated + 1 room_event, got %d total", len(path2Msgs))
	}
	path2Audit, _ := readAuditLog(s)
	path2Events, _ := s.store.GetRoomEventsSince(generalID, 0)

	// === Compare broadcast payloads (byte-identical via re-marshal) ===
	ru1 := roomUpdateFindRoomUpdated(t, path1Msgs)
	ru2 := roomUpdateFindRoomUpdated(t, path2Msgs)
	if ru1 != ru2 {
		t.Errorf("room_updated broadcasts differ\n  path1 (handler) = %+v\n  path2 (queue)   = %+v", ru1, ru2)
	}

	// === Compare audit credit ===
	// Both should contain the SAME audit line — same verb, same
	// changedBy, same room+state. Path 2 appends its line after
	// path 1's. Verify both lines appear.
	path1NewAudit := strings.TrimSpace(strings.TrimPrefix(string(path2Audit), string(path1Audit)))
	if path1NewAudit == "" {
		t.Fatal("path2 produced no new audit line")
	}
	// Expected audit body, byte-identical between paths:
	wantBody := "update-topic"
	if !strings.Contains(string(path1Audit), wantBody) {
		t.Errorf("path1 audit missing %q: %q", wantBody, string(path1Audit))
	}
	if !strings.Contains(path1NewAudit, wantBody) {
		t.Errorf("path2 audit missing %q: %q", wantBody, path1NewAudit)
	}

	// === Compare room_event rows ===
	if len(path2Events) != len(path1Events)+1 {
		t.Fatalf("expected exactly 1 new room_event between path1 and path2; got path1=%d path2=%d", len(path1Events), len(path2Events))
	}
	last1 := path1Events[len(path1Events)-1]
	last2 := path2Events[len(path2Events)-1]
	// All fields except TS must match.
	if last1.Event != last2.Event {
		t.Errorf("Event mismatch: %q vs %q", last1.Event, last2.Event)
	}
	if last1.By != last2.By {
		t.Errorf("By mismatch: %q vs %q", last1.By, last2.By)
	}
	if last1.Name != last2.Name {
		t.Errorf("Name mismatch: %q vs %q", last1.Name, last2.Name)
	}
	if last1.Reason != last2.Reason {
		t.Errorf("Reason mismatch: %q vs %q", last1.Reason, last2.Reason)
	}
	if last1.Quiet != last2.Quiet {
		t.Errorf("Quiet mismatch: %v vs %v", last1.Quiet, last2.Quiet)
	}
	// TS allowed to differ — the helper takes time.Now().Unix() on
	// each call. Tolerance: ≤ 2 seconds between back-to-back calls
	// in this test.
	if last2.TS-last1.TS > 2 || last1.TS-last2.TS > 2 {
		t.Errorf("TS jitter > 2s: %d vs %d", last1.TS, last2.TS)
	}
}
