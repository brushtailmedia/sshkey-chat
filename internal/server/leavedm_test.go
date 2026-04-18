package server

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/brushtailmedia/sshkey-chat/internal/protocol"
	"github.com/brushtailmedia/sshkey-chat/internal/store"
)

// TestHandleLeaveDM_RejectsUnknownDM verifies that calling /leave on a DM ID
// the server has never seen returns ErrUnknownDM and does not mutate any state.
func TestHandleLeaveDM_RejectsUnknownDM(t *testing.T) {
	s := newTestServer(t)
	cc := testClientFor("alice", "dev_alice_1")

	raw, _ := json.Marshal(protocol.LeaveDM{Type: "leave_dm", DM: "dm_does_not_exist"})
	s.handleLeaveDM(cc.Client, raw)

	msgs := cc.messages()
	if len(msgs) != 1 {
		t.Fatalf("expected 1 error reply, got %d", len(msgs))
	}
	var errMsg protocol.Error
	if err := json.Unmarshal(msgs[0], &errMsg); err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if errMsg.Type != "error" {
		t.Errorf("type = %q, want error", errMsg.Type)
	}
	if errMsg.Code != protocol.ErrUnknownDM {
		t.Errorf("code = %q, want %s", errMsg.Code, protocol.ErrUnknownDM)
	}
}

// TestHandleLeaveDM_RejectsNonMember verifies that a non-party gets the same
// generic ErrUnknownDM and that no cutoffs are touched. The error reply must
// be indistinguishable from the unknown-DM case so that probing clients
// cannot use /leave to discover whether a DM ID exists or who is in it.
func TestHandleLeaveDM_RejectsNonMember(t *testing.T) {
	s := newTestServer(t)

	dm, err := s.store.CreateOrGetDirectMessage("dm_ab", "alice", "bob")
	if err != nil {
		t.Fatalf("create DM: %v", err)
	}

	cc := testClientFor("carol", "dev_carol_1")
	raw, _ := json.Marshal(protocol.LeaveDM{Type: "leave_dm", DM: dm.ID})
	s.handleLeaveDM(cc.Client, raw)

	msgs := cc.messages()
	if len(msgs) != 1 {
		t.Fatalf("expected 1 error reply, got %d", len(msgs))
	}
	var errMsg protocol.Error
	if err := json.Unmarshal(msgs[0], &errMsg); err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if errMsg.Code != protocol.ErrUnknownDM {
		t.Errorf("code = %q, want %s", errMsg.Code, protocol.ErrUnknownDM)
	}

	// Cutoffs must remain untouched after a rejected leave.
	after, _ := s.store.GetDirectMessage(dm.ID)
	if after.CutoffFor("alice") != 0 || after.CutoffFor("bob") != 0 {
		t.Errorf("non-member leave must not advance cutoffs, got alice=%d bob=%d",
			after.CutoffFor("alice"), after.CutoffFor("bob"))
	}
}

// TestHandleLeaveDM_PrivacyResponsesIdentical is the security regression test
// for the "who is talking to whom" leak. The wire bytes returned for an
// unknown DM ID and for a non-member attempting to leave a real DM MUST be
// byte-identical so an attacker cannot use response shape to discover DM
// existence or membership.
func TestHandleLeaveDM_PrivacyResponsesIdentical(t *testing.T) {
	s := newTestServer(t)

	// Create a real DM between alice and bob.
	if _, err := s.store.CreateOrGetDirectMessage("dm_ab", "alice", "bob"); err != nil {
		t.Fatalf("create DM: %v", err)
	}

	// Carol probes a DM ID that does not exist.
	probe := testClientFor("carol", "dev_carol_1")
	rawProbe, _ := json.Marshal(protocol.LeaveDM{Type: "leave_dm", DM: "dm_does_not_exist"})
	s.handleLeaveDM(probe.Client, rawProbe)

	// Carol probes the real (alice/bob) DM that she is not a member of.
	nonMember := testClientFor("carol", "dev_carol_1")
	rawReal, _ := json.Marshal(protocol.LeaveDM{Type: "leave_dm", DM: "dm_ab"})
	s.handleLeaveDM(nonMember.Client, rawReal)

	probeMsgs := probe.messages()
	nonMemberMsgs := nonMember.messages()
	if len(probeMsgs) != 1 || len(nonMemberMsgs) != 1 {
		t.Fatalf("expected 1 reply each, got probe=%d nonMember=%d",
			len(probeMsgs), len(nonMemberMsgs))
	}
	if !bytes.Equal(probeMsgs[0], nonMemberMsgs[0]) {
		t.Errorf("privacy leak: unknown-DM and non-member responses differ\nunknown:    %s\nnon-member: %s",
			probeMsgs[0], nonMemberMsgs[0])
	}
}

// TestHandleLeaveDM_MemberSucceeds verifies the happy path: a real party can
// leave, their cutoff advances, the other party's cutoff is untouched, and
// only the leaver's session receives the dm_left echo (silent semantics).
func TestHandleLeaveDM_MemberSucceeds(t *testing.T) {
	s := newTestServer(t)

	dm, err := s.store.CreateOrGetDirectMessage("dm_ab", "alice", "bob")
	if err != nil {
		t.Fatalf("create DM: %v", err)
	}

	cc := testClientFor("bob", "dev_bob_1")
	// Register the client on the server so the dm_left echo finds it.
	s.mu.Lock()
	s.clients["dev_bob_1"] = cc.Client
	s.mu.Unlock()

	raw, _ := json.Marshal(protocol.LeaveDM{Type: "leave_dm", DM: dm.ID})
	s.handleLeaveDM(cc.Client, raw)

	msgs := cc.messages()
	if len(msgs) != 1 {
		t.Fatalf("expected 1 dm_left echo, got %d", len(msgs))
	}
	var left protocol.DMLeft
	if err := json.Unmarshal(msgs[0], &left); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if left.Type != "dm_left" {
		t.Errorf("type = %q, want dm_left", left.Type)
	}
	if left.DM != dm.ID {
		t.Errorf("dm = %q, want %s", left.DM, dm.ID)
	}

	// Bob's cutoff should now be set; alice's should be untouched.
	after, _ := s.store.GetDirectMessage(dm.ID)
	if after.CutoffFor("bob") == 0 {
		t.Error("bob's cutoff should be non-zero after leave")
	}
	if after.CutoffFor("alice") != 0 {
		t.Errorf("alice's cutoff should be 0, got %d", after.CutoffFor("alice"))
	}
}

// TestHandleLeaveDM_TriggersCleanupWhenBothLeft verifies that once both
// parties have left a DM, the row and the per-DM database file are deleted
// immediately (no grace period). The first leaver advances their cutoff
// only; the second leaver triggers cleanup.
func TestHandleLeaveDM_TriggersCleanupWhenBothLeft(t *testing.T) {
	s := newTestServer(t)

	dm, err := s.store.CreateOrGetDirectMessage(store.GenerateID("dm_"), "alice", "bob")
	if err != nil {
		t.Fatalf("create DM: %v", err)
	}

	// Insert a message so the per-DM database file exists on disk and we
	// can verify it gets unlinked. DMDB is lazy.
	if err := s.store.InsertDMMessage(dm.ID, store.StoredMessage{
		ID: "msg_1", Sender: "alice", TS: 100, Payload: "hi",
	}); err != nil {
		t.Fatalf("insert msg: %v", err)
	}

	// First leaver: alice. After this, alice has a cutoff but bob does not,
	// so cleanup should NOT fire and the row should still exist.
	aliceClient := testClientFor("alice", "dev_alice_1")
	s.handleLeaveDM(aliceClient.Client, mustJSON(t, protocol.LeaveDM{Type: "leave_dm", DM: dm.ID}))

	mid, _ := s.store.GetDirectMessage(dm.ID)
	if mid == nil {
		t.Fatal("DM row should still exist after only one party has left")
	}
	if mid.CutoffFor("alice") == 0 {
		t.Error("alice's cutoff should be set after her leave")
	}
	if mid.CutoffFor("bob") != 0 {
		t.Error("bob's cutoff should still be zero")
	}

	// Second leaver: bob. After this, both cutoffs are set, cleanup should
	// fire, and the row + dm-<id>.db file should be gone.
	bobClient := testClientFor("bob", "dev_bob_1")
	s.handleLeaveDM(bobClient.Client, mustJSON(t, protocol.LeaveDM{Type: "leave_dm", DM: dm.ID}))

	gone, _ := s.store.GetDirectMessage(dm.ID)
	if gone != nil {
		t.Errorf("DM row should be gone after both parties left, got %+v", gone)
	}

	// File on disk should be gone too.
	dbPath := filepath.Join(s.store.DataDir(), "dm-"+dm.ID+".db")
	if _, err := os.Stat(dbPath); !os.IsNotExist(err) {
		t.Errorf("dm-<id>.db should be unlinked, stat err = %v", err)
	}
}

// TestHandleLeaveDM_NoCleanupWhenOnlyOneLeft is the negative case for the
// cleanup trigger: a single leave call must NOT delete the DM. Without
// this guarantee any /delete from one party would also remove the other
// party's history.
func TestHandleLeaveDM_NoCleanupWhenOnlyOneLeft(t *testing.T) {
	s := newTestServer(t)

	dm, err := s.store.CreateOrGetDirectMessage("dm_ab", "alice", "bob")
	if err != nil {
		t.Fatalf("create DM: %v", err)
	}

	bobClient := testClientFor("bob", "dev_bob_1")
	s.handleLeaveDM(bobClient.Client, mustJSON(t, protocol.LeaveDM{Type: "leave_dm", DM: dm.ID}))

	after, _ := s.store.GetDirectMessage(dm.ID)
	if after == nil {
		t.Fatal("DM row should still exist when only one party has left")
	}
	if after.CutoffFor("bob") == 0 {
		t.Error("bob's cutoff should be set")
	}
	if after.CutoffFor("alice") != 0 {
		t.Error("alice's cutoff should still be 0")
	}
}

// TestHandleLeaveDM_CleanupIsIdempotent simulates two cleanup calls for the
// same DM (which can happen if alice and bob both call /leave at virtually
// the same instant — both observe "both > 0" inside their respective
// handlers and both invoke cleanupDormantDM). The re-check inside the
// dmCleanupMu critical section must make the second call a no-op rather
// than a double-delete error.
func TestHandleLeaveDM_CleanupIsIdempotent(t *testing.T) {
	s := newTestServer(t)

	dm, err := s.store.CreateOrGetDirectMessage(store.GenerateID("dm_"), "alice", "bob")
	if err != nil {
		t.Fatalf("create DM: %v", err)
	}

	// Manually advance both cutoffs (bypassing handleLeaveDM) to set up
	// the "both have left" precondition.
	now := time.Now().Unix()
	if err := s.store.SetDMLeftAt(dm.ID, "alice", now); err != nil {
		t.Fatalf("set alice cutoff: %v", err)
	}
	if err := s.store.SetDMLeftAt(dm.ID, "bob", now); err != nil {
		t.Fatalf("set bob cutoff: %v", err)
	}

	// First cleanup call: should delete the row + file.
	s.cleanupDormantDM(dm.ID)
	if got, _ := s.store.GetDirectMessage(dm.ID); got != nil {
		t.Fatal("first cleanup should have removed the row")
	}

	// Second cleanup call: should be a no-op, no panic, no error.
	s.cleanupDormantDM(dm.ID) // would panic if not idempotent
}

// TestHandleCreateDM_BusyDuringCleanup verifies the fail-fast contract: if
// dmCleanupMu is held (cleanup in progress), handleCreateDM returns the
// ErrServerBusy error code immediately rather than waiting. The client is
// expected to surface this and retry.
func TestHandleCreateDM_BusyDuringCleanup(t *testing.T) {
	s := newTestServer(t)

	// Simulate an in-progress cleanup by holding the mutex from the test.
	s.dmCleanupMu.Lock()

	cc := testClientFor("alice", "dev_alice_1")
	raw := mustJSON(t, protocol.CreateDM{Type: "create_dm", Other: "bob"})
	s.handleCreateDM(cc.Client, raw)

	// Release the mutex now that handleCreateDM has returned (TryLock
	// either failed and returned, or succeeded and released via defer).
	s.dmCleanupMu.Unlock()

	msgs := cc.messages()
	if len(msgs) != 1 {
		t.Fatalf("expected 1 reply, got %d", len(msgs))
	}
	var errMsg protocol.Error
	if err := json.Unmarshal(msgs[0], &errMsg); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if errMsg.Code != protocol.ErrServerBusy {
		t.Errorf("code = %q, want %s", errMsg.Code, protocol.ErrServerBusy)
	}

	// No DM should have been created while busy.
	dms, _ := s.store.GetDirectMessagesForUser("alice")
	for _, dm := range dms {
		if dm.UserA == "alice" && dm.UserB == "bob" || dm.UserA == "bob" && dm.UserB == "alice" {
			t.Errorf("create_dm should not have created a row while busy: %+v", dm)
		}
	}
}

// TestHandleCreateDM_FreshAfterCleanup verifies the full re-contact path:
// alice and bob both leave their DM (triggering cleanup), then alice runs
// /newdm @bob and gets back a NEW dm_<id> for a fresh row. The original
// dm_<id> must not be reused — it has been deleted from disk.
func TestHandleCreateDM_FreshAfterCleanup(t *testing.T) {
	s := newTestServer(t)

	// Create the original DM and have both parties leave.
	original, err := s.store.CreateOrGetDirectMessage(store.GenerateID("dm_"), "alice", "bob")
	if err != nil {
		t.Fatalf("create original DM: %v", err)
	}

	aliceClient := testClientFor("alice", "dev_alice_1")
	s.handleLeaveDM(aliceClient.Client, mustJSON(t, protocol.LeaveDM{Type: "leave_dm", DM: original.ID}))

	bobClient := testClientFor("bob", "dev_bob_1")
	s.handleLeaveDM(bobClient.Client, mustJSON(t, protocol.LeaveDM{Type: "leave_dm", DM: original.ID}))

	// Confirm the original is gone.
	if got, _ := s.store.GetDirectMessage(original.ID); got != nil {
		t.Fatal("original DM should be cleaned up after both left")
	}

	// Alice re-contacts bob. handleCreateDM broadcasts dm_created to all
	// sessions of both members via s.clients, so register alice's session
	// on the server before the call so the encode lands somewhere we can
	// observe.
	freshClient := testClientFor("alice", "dev_alice_fresh")
	s.mu.Lock()
	s.clients["dev_alice_fresh"] = freshClient.Client
	s.mu.Unlock()

	s.handleCreateDM(freshClient.Client, mustJSON(t, protocol.CreateDM{Type: "create_dm", Other: "bob"}))

	msgs := freshClient.messages()
	if len(msgs) == 0 {
		t.Fatal("expected dm_created reply, got none")
	}
	var created protocol.DMCreated
	if err := json.Unmarshal(msgs[0], &created); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if created.Type != "dm_created" {
		t.Errorf("first reply type = %q, want dm_created", created.Type)
	}
	if created.DM == "" {
		t.Fatal("dm_created has empty DM id")
	}
	if created.DM == original.ID {
		t.Errorf("re-created DM reused the deleted ID %q — must be a fresh nanoid", original.ID)
	}

	// And the new row is alive.
	fresh, _ := s.store.GetDirectMessage(created.DM)
	if fresh == nil {
		t.Fatal("fresh DM row should exist")
	}
	if fresh.UserALeftAt != 0 || fresh.UserBLeftAt != 0 {
		t.Errorf("fresh DM should have zero cutoffs, got alice=%d bob=%d",
			fresh.UserALeftAt, fresh.UserBLeftAt)
	}
}

// mustJSON marshals v or fails the test.
func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return raw
}
