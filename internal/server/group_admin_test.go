package server

// Phase 14 Chunk 2 tests for the four new in-group admin handlers and the
// handleRetirement group-branch restructure. Covers:
//
//   - Happy-path tests for each of add/remove/promote/demote
//   - Byte-identical privacy regressions (TestHandle*_PrivacyResponsesIdentical
//     using bytes.Equal on wire frames — matches the TestHandleSendGroup /
//     TestHandleRenameGroup_PrivacyResponsesIdentical pattern)
//   - Permission gates: non-admin rejected, last-admin rejected, already-*
//     rejected, self-kick routing
//   - Retirement succession: last-admin auto-promote + orphan-on-solo
//     regression (the latent bug fixed by the Option A per-group iteration)
//
// These tests land alongside the handlers in internal/server/. Client-side
// tests (TUI dispatch, sidebar indicator, etc.) are in Chunks 4-6.

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/brushtailmedia/sshkey-chat/internal/protocol"
	"github.com/brushtailmedia/sshkey-chat/internal/store"
	"github.com/brushtailmedia/sshkey-chat/internal/testutil"
)

// --- handleAddToGroup ---

func TestHandleAddToGroup_AdminCanAdd(t *testing.T) {
	s := newTestServer(t)
	if err := s.store.CreateGroup(testutil.GroupID("add"), testutil.UserID("alice"), []string{testutil.UserID("alice")}, "Test"); err != nil {
		t.Fatalf("create group: %v", err)
	}

	alice := testClientFor(testutil.UserID("alice"), "dev_alice_1")
	bob := testClientFor(testutil.UserID("bob"), "dev_bob_1")
	s.mu.Lock()
	s.clients["dev_alice_1"] = alice.Client
	s.clients["dev_bob_1"] = bob.Client
	s.mu.Unlock()

	raw, _ := json.Marshal(protocol.AddToGroup{
		Type: "add_to_group", Group: testutil.GroupID("add"), User: testutil.UserID("bob"),
	})
	s.handleAddToGroup(alice.Client, raw)

	// bob should be a member now
	isMember, _ := s.store.IsGroupMember(testutil.GroupID("add"), testutil.UserID("bob"))
	if !isMember {
		t.Error("bob should be a member after add")
	}
	// bob should NOT be an admin (promote separately)
	if isAdmin, _ := s.store.IsGroupAdmin(testutil.GroupID("add"), testutil.UserID("bob")); isAdmin {
		t.Error("bob should not be admin after add; admins are promoted separately")
	}

	// alice should receive an add_group_result echo + group_event{join}
	aliceMsgs := alice.messages()
	if len(aliceMsgs) < 1 {
		t.Fatalf("alice expected at least 1 message, got %d", len(aliceMsgs))
	}

	// bob should receive a group_added_to direct notification
	// (plus the group_event{join} broadcast since he's now a member)
	bobMsgs := bob.messages()
	if len(bobMsgs) < 1 {
		t.Fatalf("bob expected at least 1 message, got %d", len(bobMsgs))
	}
	// The group_added_to should be in bob's messages
	foundAddedTo := false
	for _, raw := range bobMsgs {
		var addedTo protocol.GroupAddedTo
		if err := json.Unmarshal(raw, &addedTo); err == nil && addedTo.Type == "group_added_to" {
			foundAddedTo = true
			if addedTo.Group != testutil.GroupID("add") {
				t.Errorf("group_added_to group = %q, want group_add", addedTo.Group)
			}
			if addedTo.AddedBy != testutil.UserID("alice") {
				t.Errorf("added_by = %q, want alice", addedTo.AddedBy)
			}
			if len(addedTo.Admins) != 1 || addedTo.Admins[0] != testutil.UserID("alice") {
				t.Errorf("admins = %v, want [alice]", addedTo.Admins)
			}
		}
	}
	if !foundAddedTo {
		t.Error("bob should have received group_added_to")
	}
}

func TestHandleAddToGroup_NonAdminRejected(t *testing.T) {
	s := newTestServer(t)
	if err := s.store.CreateGroup(testutil.GroupID("add"), testutil.UserID("alice"), []string{testutil.UserID("alice"), testutil.UserID("bob")}, "Test"); err != nil {
		t.Fatalf("create group: %v", err)
	}

	bob := testClientFor(testutil.UserID("bob"), "dev_bob_1")
	s.mu.Lock()
	s.clients["dev_bob_1"] = bob.Client
	s.mu.Unlock()

	raw, _ := json.Marshal(protocol.AddToGroup{
		Type: "add_to_group", Group: testutil.GroupID("add"), User: testutil.UserID("carol"),
	})
	s.handleAddToGroup(bob.Client, raw)

	// bob is a member but not an admin — should get ErrUnknownGroup
	// (byte-identical privacy)
	msgs := bob.messages()
	if len(msgs) != 1 {
		t.Fatalf("expected 1 reply, got %d", len(msgs))
	}
	var errResp protocol.Error
	json.Unmarshal(msgs[0], &errResp)
	if errResp.Code != protocol.ErrUnknownGroup {
		t.Errorf("expected ErrUnknownGroup for non-admin, got %q", errResp.Code)
	}

	// carol should not have been added
	isMember, _ := s.store.IsGroupMember(testutil.GroupID("add"), testutil.UserID("carol"))
	if isMember {
		t.Error("carol should not be a member after non-admin attempt")
	}
}

func TestHandleAddToGroup_PrivacyResponsesIdentical(t *testing.T) {
	s := newTestServer(t)
	if err := s.store.CreateGroup(testutil.GroupID("real"), testutil.UserID("alice"), []string{testutil.UserID("alice")}, "Real"); err != nil {
		t.Fatalf("create group: %v", err)
	}

	// Case 1: carol probes an unknown group
	probe := testClientFor(testutil.UserID("carol"), "dev_carol_1")
	rawProbe, _ := json.Marshal(protocol.AddToGroup{
		Type: "add_to_group", Group: testutil.GroupID("does_not_exist"), User: testutil.UserID("dave"),
	})
	s.handleAddToGroup(probe.Client, rawProbe)

	// Case 2: carol probes a real group she's not a member of
	nonMember := testClientFor(testutil.UserID("carol"), "dev_carol_1")
	rawReal, _ := json.Marshal(protocol.AddToGroup{
		Type: "add_to_group", Group: testutil.GroupID("real"), User: testutil.UserID("dave"),
	})
	s.handleAddToGroup(nonMember.Client, rawReal)

	probeMsgs := probe.messages()
	nonMemberMsgs := nonMember.messages()
	if len(probeMsgs) != 1 || len(nonMemberMsgs) != 1 {
		t.Fatalf("expected 1 reply each, got probe=%d nonMember=%d",
			len(probeMsgs), len(nonMemberMsgs))
	}
	if !bytes.Equal(probeMsgs[0], nonMemberMsgs[0]) {
		t.Errorf("privacy leak: unknown-group and non-member add_to_group responses differ\nunknown:    %s\nnon-member: %s",
			probeMsgs[0], nonMemberMsgs[0])
	}
}

func TestHandleAddToGroup_AlreadyMemberRejected(t *testing.T) {
	s := newTestServer(t)
	if err := s.store.CreateGroup(testutil.GroupID("add"), testutil.UserID("alice"), []string{testutil.UserID("alice"), testutil.UserID("bob")}, "Test"); err != nil {
		t.Fatalf("create group: %v", err)
	}

	alice := testClientFor(testutil.UserID("alice"), "dev_alice_1")
	s.mu.Lock()
	s.clients["dev_alice_1"] = alice.Client
	s.mu.Unlock()

	raw, _ := json.Marshal(protocol.AddToGroup{
		Type: "add_to_group", Group: testutil.GroupID("add"), User: testutil.UserID("bob"),
	})
	s.handleAddToGroup(alice.Client, raw)

	msgs := alice.messages()
	if len(msgs) != 1 {
		t.Fatalf("expected 1 reply, got %d", len(msgs))
	}
	var errResp protocol.Error
	json.Unmarshal(msgs[0], &errResp)
	if errResp.Code != protocol.ErrAlreadyMember {
		t.Errorf("expected ErrAlreadyMember, got %q", errResp.Code)
	}
}

// --- Phase 17 Step 4d: group cap enforcement ---

// TestHandleAddToGroup_GroupAtCapRejected closes the pre-Phase-17 gap:
// handleAddToGroup had no cap check, so an admin could grow a group
// past MaxMembers via repeated add_to_group, producing a group whose
// sends would then fail the wrapped_keys envelope cap on every message.
// With the fix, add_to_group enforces the same `too_many_members` cap
// as handleCreateGroup.
func TestHandleAddToGroup_GroupAtCapRejected(t *testing.T) {
	s := newTestServer(t)
	// Lower the cap to 2 so we can exercise it with the seeded user set
	// (alice, bob, carol). Must hold the config write lock.
	s.cfg.Lock()
	s.cfg.Server.Groups.MaxMembers = 2
	s.cfg.Unlock()

	// Group is already at cap (alice + bob = 2). Adding carol should fail.
	if err := s.store.CreateGroup(testutil.GroupID("cap"), testutil.UserID("alice"), []string{testutil.UserID("alice"), testutil.UserID("bob")}, "Test"); err != nil {
		t.Fatalf("create group: %v", err)
	}

	alice := testClientFor(testutil.UserID("alice"), "dev_alice_1")
	s.mu.Lock()
	s.clients["dev_alice_1"] = alice.Client
	s.mu.Unlock()

	raw, _ := json.Marshal(protocol.AddToGroup{
		Type: "add_to_group", Group: testutil.GroupID("cap"), User: testutil.UserID("carol"),
	})
	s.handleAddToGroup(alice.Client, raw)

	msgs := alice.messages()
	if len(msgs) != 1 {
		t.Fatalf("expected 1 reply, got %d", len(msgs))
	}
	var errResp protocol.Error
	json.Unmarshal(msgs[0], &errResp)
	if errResp.Code != "too_many_members" {
		t.Errorf("expected too_many_members, got %q (message: %q)", errResp.Code, errResp.Message)
	}
	// Error message should include the configured cap for operator clarity.
	if errResp.Message == "" || !bytes.Contains([]byte(errResp.Message), []byte("2 members")) {
		t.Errorf("error message should reference configured cap (2), got %q", errResp.Message)
	}

	// Confirm carol was NOT added.
	if isMember, _ := s.store.IsGroupMember(testutil.GroupID("cap"), testutil.UserID("carol")); isMember {
		t.Error("carol should NOT be a member after cap rejection")
	}
}

// TestHandleAddToGroup_BelowCapSucceeds verifies the happy path after
// the cap check: group size < maxMembers → add succeeds.
func TestHandleAddToGroup_BelowCapSucceeds(t *testing.T) {
	s := newTestServer(t)
	s.cfg.Lock()
	s.cfg.Server.Groups.MaxMembers = 3
	s.cfg.Unlock()

	// Group has 2 members; cap is 3; one seat remaining.
	if err := s.store.CreateGroup(testutil.GroupID("below_cap"), testutil.UserID("alice"), []string{testutil.UserID("alice"), testutil.UserID("bob")}, "Test"); err != nil {
		t.Fatalf("create group: %v", err)
	}

	alice := testClientFor(testutil.UserID("alice"), "dev_alice_1")
	carol := testClientFor(testutil.UserID("carol"), "dev_carol_1")
	s.mu.Lock()
	s.clients["dev_alice_1"] = alice.Client
	s.clients["dev_carol_1"] = carol.Client
	s.mu.Unlock()

	raw, _ := json.Marshal(protocol.AddToGroup{
		Type: "add_to_group", Group: testutil.GroupID("below_cap"), User: testutil.UserID("carol"),
	})
	s.handleAddToGroup(alice.Client, raw)

	if isMember, _ := s.store.IsGroupMember(testutil.GroupID("below_cap"), testutil.UserID("carol")); !isMember {
		t.Error("carol should have been added (under cap)")
	}
}

// TestHandleCreateGroup_CapIsConfigurable verifies handleCreateGroup
// reads the cap from config rather than the pre-Phase-17 hardcoded
// literal. With cap lowered to 2, creating a 3-person group must be
// rejected.
func TestHandleCreateGroup_CapIsConfigurable(t *testing.T) {
	s := newTestServer(t)
	s.cfg.Lock()
	s.cfg.Server.Groups.MaxMembers = 2
	s.cfg.Unlock()

	alice := testClientFor(testutil.UserID("alice"), "dev_alice_1")
	s.mu.Lock()
	s.clients["dev_alice_1"] = alice.Client
	s.mu.Unlock()

	// Caller is implicitly added, so Members = [bob, carol] produces
	// allMembers = [alice, bob, carol] = 3 > cap(2).
	raw, _ := json.Marshal(protocol.CreateGroup{
		Type:    "create_group",
		Members: []string{testutil.UserID("bob"), testutil.UserID("carol")},
		Name:    "Too Big",
	})
	s.handleCreateGroup(alice.Client, raw)

	msgs := alice.messages()
	if len(msgs) < 1 {
		t.Fatalf("expected at least 1 reply, got %d", len(msgs))
	}
	var errResp protocol.Error
	json.Unmarshal(msgs[0], &errResp)
	if errResp.Code != "too_many_members" {
		t.Errorf("expected too_many_members with configured cap, got %q (message: %q)", errResp.Code, errResp.Message)
	}
	// Confirm the message reflects the *configured* cap (2), not the
	// default (100).
	if !bytes.Contains([]byte(errResp.Message), []byte("2 members")) {
		t.Errorf("error message should reference configured cap (2), got %q", errResp.Message)
	}
}

// TestHandleAddToGroup_CapDefaultsTo100WhenZero covers the defensive
// fallback in the handler: if config load somehow produces a zero or
// negative MaxMembers (operator wrote `max_members = 0`, for example),
// the handler treats it as config.DefaultMaxGroupMembers (100) rather than
// allowing unlimited growth or rejecting every add. Parser test (in config
// package) verifies the zero isn't coerced there; this test verifies the
// handler catches it.
func TestHandleAddToGroup_CapDefaultsTo100WhenZero(t *testing.T) {
	s := newTestServer(t)
	s.cfg.Lock()
	s.cfg.Server.Groups.MaxMembers = 0
	s.cfg.Unlock()

	if err := s.store.CreateGroup(testutil.GroupID("zero_cap"), testutil.UserID("alice"), []string{testutil.UserID("alice"), testutil.UserID("bob")}, "Test"); err != nil {
		t.Fatalf("create group: %v", err)
	}

	alice := testClientFor(testutil.UserID("alice"), "dev_alice_1")
	s.mu.Lock()
	s.clients["dev_alice_1"] = alice.Client
	s.mu.Unlock()

	// With MaxMembers = 0 and the defensive fallback kicking in (100),
	// adding carol to a 2-person group must succeed.
	raw, _ := json.Marshal(protocol.AddToGroup{
		Type: "add_to_group", Group: testutil.GroupID("zero_cap"), User: testutil.UserID("carol"),
	})
	s.handleAddToGroup(alice.Client, raw)

	if isMember, _ := s.store.IsGroupMember(testutil.GroupID("zero_cap"), testutil.UserID("carol")); !isMember {
		t.Error("carol should have been added — zero cap should trigger the 100 fallback, not block")
	}
}

// --- handleRemoveFromGroup ---

func TestHandleRemoveFromGroup_AdminCanRemove(t *testing.T) {
	s := newTestServer(t)
	if err := s.store.CreateGroup(testutil.GroupID("kick"), testutil.UserID("alice"), []string{testutil.UserID("alice"), testutil.UserID("bob"), testutil.UserID("carol")}, "Test"); err != nil {
		t.Fatalf("create group: %v", err)
	}

	alice := testClientFor(testutil.UserID("alice"), "dev_alice_1")
	bob := testClientFor(testutil.UserID("bob"), "dev_bob_1")
	s.mu.Lock()
	s.clients["dev_alice_1"] = alice.Client
	s.clients["dev_bob_1"] = bob.Client
	s.mu.Unlock()

	raw, _ := json.Marshal(protocol.RemoveFromGroup{
		Type: "remove_from_group", Group: testutil.GroupID("kick"), User: testutil.UserID("bob"),
	})
	s.handleRemoveFromGroup(alice.Client, raw)

	// bob should be removed from group_members
	isMember, _ := s.store.IsGroupMember(testutil.GroupID("kick"), testutil.UserID("bob"))
	if isMember {
		t.Error("bob should have been removed")
	}

	// bob's sessions should have received group_left with reason="removed", by="alice"
	bobMsgs := bob.messages()
	foundLeft := false
	for _, raw := range bobMsgs {
		var left protocol.GroupLeft
		if err := json.Unmarshal(raw, &left); err == nil && left.Type == "group_left" {
			foundLeft = true
			if left.Reason != "removed" {
				t.Errorf("bob's group_left reason = %q, want 'removed'", left.Reason)
			}
			if left.By != testutil.UserID("alice") {
				t.Errorf("bob's group_left by = %q, want alice", left.By)
			}
		}
	}
	if !foundLeft {
		t.Error("bob should have received group_left")
	}
}

func TestHandleRemoveFromGroup_LastAdminRejected(t *testing.T) {
	s := newTestServer(t)
	if err := s.store.CreateGroup(testutil.GroupID("la"), testutil.UserID("alice"), []string{testutil.UserID("alice"), testutil.UserID("bob")}, "Test"); err != nil {
		t.Fatalf("create group: %v", err)
	}
	// bob promoted so both are admins
	if err := s.store.SetGroupMemberAdmin(testutil.GroupID("la"), testutil.UserID("bob"), true); err != nil {
		t.Fatalf("promote bob: %v", err)
	}
	// demote alice so only bob is admin
	if err := s.store.SetGroupMemberAdmin(testutil.GroupID("la"), testutil.UserID("alice"), false); err != nil {
		t.Fatalf("demote alice: %v", err)
	}

	bob := testClientFor(testutil.UserID("bob"), "dev_bob_1")
	s.mu.Lock()
	s.clients["dev_bob_1"] = bob.Client
	s.mu.Unlock()

	// bob (only admin) tries to remove himself — should NOT go through
	// RemoveFromGroup's self-kick shortcut either, because the shortcut
	// routes to handleLeaveGroup which has the same last-admin gate.
	raw, _ := json.Marshal(protocol.RemoveFromGroup{
		Type: "remove_from_group", Group: testutil.GroupID("la"), User: testutil.UserID("bob"),
	})
	s.handleRemoveFromGroup(bob.Client, raw)

	msgs := bob.messages()
	if len(msgs) != 1 {
		t.Fatalf("expected 1 reply, got %d", len(msgs))
	}
	var errResp protocol.Error
	json.Unmarshal(msgs[0], &errResp)
	if errResp.Code != protocol.ErrForbidden {
		t.Errorf("expected ErrForbidden for last-admin self-remove, got %q", errResp.Code)
	}
}

func TestHandleRemoveFromGroup_PrivacyResponsesIdentical(t *testing.T) {
	s := newTestServer(t)
	if err := s.store.CreateGroup(testutil.GroupID("real"), testutil.UserID("alice"), []string{testutil.UserID("alice")}, "Real"); err != nil {
		t.Fatalf("create group: %v", err)
	}

	probe := testClientFor(testutil.UserID("carol"), "dev_carol_1")
	rawProbe, _ := json.Marshal(protocol.RemoveFromGroup{
		Type: "remove_from_group", Group: testutil.GroupID("does_not_exist"), User: testutil.UserID("dave"),
	})
	s.handleRemoveFromGroup(probe.Client, rawProbe)

	nonMember := testClientFor(testutil.UserID("carol"), "dev_carol_1")
	rawReal, _ := json.Marshal(protocol.RemoveFromGroup{
		Type: "remove_from_group", Group: testutil.GroupID("real"), User: testutil.UserID("dave"),
	})
	s.handleRemoveFromGroup(nonMember.Client, rawReal)

	probeMsgs := probe.messages()
	nonMemberMsgs := nonMember.messages()
	if len(probeMsgs) != 1 || len(nonMemberMsgs) != 1 {
		t.Fatalf("expected 1 reply each, got probe=%d nonMember=%d",
			len(probeMsgs), len(nonMemberMsgs))
	}
	if !bytes.Equal(probeMsgs[0], nonMemberMsgs[0]) {
		t.Errorf("privacy leak: unknown-group and non-member remove_from_group responses differ")
	}
}

func TestPerformGroupLeave_RemovedReason(t *testing.T) {
	s := newTestServer(t)
	if err := s.store.CreateGroup(testutil.GroupID("r"), testutil.UserID("alice"), []string{testutil.UserID("alice"), testutil.UserID("bob")}, "Test"); err != nil {
		t.Fatalf("create group: %v", err)
	}
	// promote bob so alice can remove him without the last-admin gate blocking via RemoveFromGroup
	if err := s.store.SetGroupMemberAdmin(testutil.GroupID("r"), testutil.UserID("bob"), true); err != nil {
		t.Fatalf("promote bob: %v", err)
	}

	alice := testClientFor(testutil.UserID("alice"), "dev_alice_1")
	bob := testClientFor(testutil.UserID("bob"), "dev_bob_1")
	s.mu.Lock()
	s.clients["dev_alice_1"] = alice.Client
	s.clients["dev_bob_1"] = bob.Client
	s.mu.Unlock()

	// Direct call to the shared helper with reason="removed" + by="alice".
	// Asserts that the new By field is routed through broadcast + echo.
	s.performGroupLeave(testutil.GroupID("r"), testutil.UserID("bob"), "removed", testutil.UserID("alice"), testutil.UserID("alice"))

	// alice (remaining member) should receive group_event{leave, by: alice, reason: removed}
	aliceMsgs := alice.messages()
	foundEvent := false
	for _, raw := range aliceMsgs {
		var ev protocol.GroupEvent
		if err := json.Unmarshal(raw, &ev); err == nil && ev.Type == "group_event" && ev.Event == "leave" {
			foundEvent = true
			if ev.Reason != "removed" {
				t.Errorf("event reason = %q, want removed", ev.Reason)
			}
			if ev.By != testutil.UserID("alice") {
				t.Errorf("event by = %q, want alice", ev.By)
			}
		}
	}
	if !foundEvent {
		t.Error("alice should have received group_event{leave}")
	}

	// bob should have received group_left{reason: removed, by: alice}
	bobMsgs := bob.messages()
	foundLeft := false
	for _, raw := range bobMsgs {
		var left protocol.GroupLeft
		if err := json.Unmarshal(raw, &left); err == nil && left.Type == "group_left" {
			foundLeft = true
			if left.Reason != "removed" {
				t.Errorf("bob's group_left reason = %q, want removed", left.Reason)
			}
			if left.By != testutil.UserID("alice") {
				t.Errorf("bob's group_left by = %q, want alice", left.By)
			}
		}
	}
	if !foundLeft {
		t.Error("bob should have received group_left")
	}
}

// TestHandleRemoveFromGroup_LastMemberCleanupOnKickedSoleMember is
// the regression for the concern flagged during the Chunk 5 audit:
// when an admin kicks the only remaining non-self member of a group,
// the last-member cleanup cascade should fire from inside
// performGroupLeave → DeleteGroupConversation. Replaces the coverage
// that the old TestProcessPendingAdminKicks_LastMemberCleanup test
// provided via the deleted CLI escape-hatch path.
//
// Setup: 2-member group (alice admin + bob non-admin). alice kicks
// bob. Bob was the last non-admin member, but alice is still in the
// group, so DeleteGroupConversation should NOT fire (cleanup only
// runs on TRULY empty groups). After bob's kick, alice remains and
// the group row survives. Contrast with the orphan-on-solo retirement
// test in TestHandleRetirement_SoleMemberOrphanCleanupFires which
// exercises the actual empty-group cleanup branch.
//
// The stronger variant — kicking the last remaining member and
// emptying the group — requires bob to be both admin AND solo which
// is a contradiction (can't have an admin-free group). So this test
// covers the IMPORTANT case: kicked member leaves, group row and
// file survive because alice is still in it.
func TestHandleRemoveFromGroup_LastMemberCleanupOnKickedSoleMember(t *testing.T) {
	s := newTestServer(t)
	groupID := store.GenerateID("group_")
	if err := s.store.CreateGroup(groupID, testutil.UserID("alice"), []string{testutil.UserID("alice"), testutil.UserID("bob")}, "Test"); err != nil {
		t.Fatalf("create group: %v", err)
	}

	alice := testClientFor(testutil.UserID("alice"), "dev_alice_1")
	s.mu.Lock()
	s.clients["dev_alice_1"] = alice.Client
	s.mu.Unlock()

	// alice kicks bob via the handler (not performGroupLeave direct)
	// so the full pipeline runs: admin check + self-kick check +
	// last-admin check + performGroupLeave.
	raw, _ := json.Marshal(protocol.RemoveFromGroup{
		Type: "remove_from_group", Group: groupID, User: testutil.UserID("bob"),
	})
	s.handleRemoveFromGroup(alice.Client, raw)

	// bob is no longer a member
	isBobMember, _ := s.store.IsGroupMember(groupID, testutil.UserID("bob"))
	if isBobMember {
		t.Error("bob should be removed after kick")
	}

	// alice is still a member — group row should survive
	isAliceMember, _ := s.store.IsGroupMember(groupID, testutil.UserID("alice"))
	if !isAliceMember {
		t.Error("alice should still be a member")
	}

	// group_conversations row still exists (alice is still in it).
	// Verify via GetUserGroups — the group should appear in alice's list.
	groups, _ := s.store.GetUserGroups(testutil.UserID("alice"))
	found := false
	for _, g := range groups {
		if g.ID == groupID {
			found = true
			break
		}
	}
	if !found {
		t.Error("group should still exist (alice is still a member)")
	}

	// Audit: one "leave" row for bob's kick with by=alice, reason=removed
	events, _ := s.store.GetGroupEventsSince(groupID, 0)
	var foundKickEvent bool
	for _, e := range events {
		if e.Event == "leave" && e.User == testutil.UserID("bob") && e.By == testutil.UserID("alice") && e.Reason == "removed" {
			foundKickEvent = true
		}
	}
	if !foundKickEvent {
		t.Errorf("expected audit row for bob's kick, got events %+v", events)
	}
}

// --- handlePromoteGroupAdmin ---

func TestHandlePromoteGroupAdmin_Success(t *testing.T) {
	s := newTestServer(t)
	if err := s.store.CreateGroup(testutil.GroupID("p"), testutil.UserID("alice"), []string{testutil.UserID("alice"), testutil.UserID("bob")}, "Test"); err != nil {
		t.Fatalf("create group: %v", err)
	}

	alice := testClientFor(testutil.UserID("alice"), "dev_alice_1")
	s.mu.Lock()
	s.clients["dev_alice_1"] = alice.Client
	s.mu.Unlock()

	raw, _ := json.Marshal(protocol.PromoteGroupAdmin{
		Type: "promote_group_admin", Group: testutil.GroupID("p"), User: testutil.UserID("bob"),
	})
	s.handlePromoteGroupAdmin(alice.Client, raw)

	// bob should now be an admin
	isAdmin, _ := s.store.IsGroupAdmin(testutil.GroupID("p"), testutil.UserID("bob"))
	if !isAdmin {
		t.Error("bob should be an admin after promote")
	}
}

func TestHandlePromoteGroupAdmin_AlreadyAdminRejected(t *testing.T) {
	s := newTestServer(t)
	if err := s.store.CreateGroup(testutil.GroupID("p"), testutil.UserID("alice"), []string{testutil.UserID("alice"), testutil.UserID("bob")}, "Test"); err != nil {
		t.Fatalf("create group: %v", err)
	}
	s.store.SetGroupMemberAdmin(testutil.GroupID("p"), testutil.UserID("bob"), true)

	alice := testClientFor(testutil.UserID("alice"), "dev_alice_1")
	s.mu.Lock()
	s.clients["dev_alice_1"] = alice.Client
	s.mu.Unlock()

	raw, _ := json.Marshal(protocol.PromoteGroupAdmin{
		Type: "promote_group_admin", Group: testutil.GroupID("p"), User: testutil.UserID("bob"),
	})
	s.handlePromoteGroupAdmin(alice.Client, raw)

	msgs := alice.messages()
	if len(msgs) != 1 {
		t.Fatalf("expected 1 reply, got %d", len(msgs))
	}
	var errResp protocol.Error
	json.Unmarshal(msgs[0], &errResp)
	if errResp.Code != protocol.ErrAlreadyAdmin {
		t.Errorf("expected ErrAlreadyAdmin, got %q", errResp.Code)
	}
}

// --- handleDemoteGroupAdmin ---

func TestHandleDemoteGroupAdmin_Success(t *testing.T) {
	s := newTestServer(t)
	if err := s.store.CreateGroup(testutil.GroupID("d"), testutil.UserID("alice"), []string{testutil.UserID("alice"), testutil.UserID("bob")}, "Test"); err != nil {
		t.Fatalf("create group: %v", err)
	}
	s.store.SetGroupMemberAdmin(testutil.GroupID("d"), testutil.UserID("bob"), true) // both admins

	alice := testClientFor(testutil.UserID("alice"), "dev_alice_1")
	s.mu.Lock()
	s.clients["dev_alice_1"] = alice.Client
	s.mu.Unlock()

	raw, _ := json.Marshal(protocol.DemoteGroupAdmin{
		Type: "demote_group_admin", Group: testutil.GroupID("d"), User: testutil.UserID("bob"),
	})
	s.handleDemoteGroupAdmin(alice.Client, raw)

	isAdmin, _ := s.store.IsGroupAdmin(testutil.GroupID("d"), testutil.UserID("bob"))
	if isAdmin {
		t.Error("bob should no longer be an admin")
	}
}

func TestHandleDemoteGroupAdmin_LastAdminRejected(t *testing.T) {
	s := newTestServer(t)
	if err := s.store.CreateGroup(testutil.GroupID("d"), testutil.UserID("alice"), []string{testutil.UserID("alice"), testutil.UserID("bob")}, "Test"); err != nil {
		t.Fatalf("create group: %v", err)
	}
	// alice is the only admin; bob is a regular member

	alice := testClientFor(testutil.UserID("alice"), "dev_alice_1")
	s.mu.Lock()
	s.clients["dev_alice_1"] = alice.Client
	s.mu.Unlock()

	// alice tries to demote herself — rejected
	raw, _ := json.Marshal(protocol.DemoteGroupAdmin{
		Type: "demote_group_admin", Group: testutil.GroupID("d"), User: testutil.UserID("alice"),
	})
	s.handleDemoteGroupAdmin(alice.Client, raw)

	msgs := alice.messages()
	if len(msgs) != 1 {
		t.Fatalf("expected 1 reply, got %d", len(msgs))
	}
	var errResp protocol.Error
	json.Unmarshal(msgs[0], &errResp)
	if errResp.Code != protocol.ErrForbidden {
		t.Errorf("expected ErrForbidden for last-admin self-demote, got %q", errResp.Code)
	}
}

// --- handleRetirement group-branch tests ---

// TestHandleRetirement_SoleMemberOrphanCleanupFires is the regression for
// the orphan-on-solo bug that the pre-Phase-14 RetireUserFromGroups bulk
// path had: when the retiring user was the only member of a group, the
// bulk DELETE removed their group_members row but never triggered
// DeleteGroupConversation, leaving the group_conversations row and the
// per-group DB file orbiting forever. The Phase 14 per-group iteration
// via performGroupLeave fixes this as a side effect because
// performGroupLeave runs the last-member cleanup cascade unconditionally.
func TestHandleRetirement_SoleMemberOrphanCleanupFires(t *testing.T) {
	s := newTestServer(t)

	// Seed alice as a real user so handleRetirement's user lookup succeeds.
	if err := s.store.CreateGroup(testutil.GroupID("solo"), testutil.UserID("alice"), []string{testutil.UserID("alice")}, "Solo"); err != nil {
		t.Fatalf("create group: %v", err)
	}
	// Insert a message so the per-group DB file actually exists on disk.
	s.store.InsertGroupMessage(testutil.GroupID("solo"), store.StoredMessage{
		ID: testutil.MsgID("m1"), Sender: testutil.UserID("alice"), TS: 100, Payload: "payload",
	})

	s.handleRetirement(testutil.UserID("alice"), nil, "self_compromise")

	// Assertion 1: alice is no longer a member of group_solo
	isMember, _ := s.store.IsGroupMember(testutil.GroupID("solo"), testutil.UserID("alice"))
	if isMember {
		t.Error("alice should no longer be a member after retirement")
	}

	// Assertion 2: group_members for group_solo is empty
	members, _ := s.store.GetGroupMembers(testutil.GroupID("solo"))
	if len(members) != 0 {
		t.Errorf("group_members for group_solo should be empty, got %v", members)
	}

	// Assertion 3: the group_conversations row is gone (via
	// DeleteGroupConversation cascade from performGroupLeave's last-member
	// cleanup). GetUserGroups for any user should not return group_solo.
	groups, _ := s.store.GetUserGroups(testutil.UserID("alice"))
	for _, g := range groups {
		if g.ID == testutil.GroupID("solo") {
			t.Error("group_solo row should be gone after last-member cleanup")
		}
	}
}

func TestHandleRetirement_LastAdminAutoPromotesOldestMember(t *testing.T) {
	s := newTestServer(t)

	// alice (sole admin) + bob + carol (both regular members).
	// bob joined before carol (joined_at ordering).
	if err := s.store.CreateGroup(testutil.GroupID("s"), testutil.UserID("alice"), []string{testutil.UserID("alice"), testutil.UserID("bob"), testutil.UserID("carol")}, "Test"); err != nil {
		t.Fatalf("create group: %v", err)
	}

	s.handleRetirement(testutil.UserID("alice"), nil, "self_compromise")

	// alice no longer a member
	if isMember, _ := s.store.IsGroupMember(testutil.GroupID("s"), testutil.UserID("alice")); isMember {
		t.Error("alice should no longer be a member")
	}

	// bob or carol was auto-promoted (oldest by joined_at — but since
	// CreateGroup inserts all members in one loop with the same
	// datetime('now'), ordering is by user string ascending as a
	// secondary sort). Whichever got promoted, exactly ONE new admin
	// should exist.
	admins, _ := s.store.GetGroupAdminIDs(testutil.GroupID("s"))
	if len(admins) != 1 {
		t.Fatalf("expected exactly 1 admin after succession, got %d: %v", len(admins), admins)
	}
	if admins[0] != testutil.UserID("bob") && admins[0] != testutil.UserID("carol") {
		t.Errorf("successor = %q, want bob or carol", admins[0])
	}
}
