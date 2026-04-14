package server

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/brushtailmedia/sshkey-chat/internal/protocol"
)

// TestHandleDeleteGroup_MemberRemoved verifies the happy path: a member
// runs delete_group, the server runs the leave logic (RemoveGroupMember),
// records the deletion, and echoes group_deleted to the leaver's session.
//
// Phase 14: bob is promoted to co-admin so alice isn't the sole admin
// when she deletes — otherwise the inline last-admin gate would reject
// her delete (only the solo-member carve-out would let a sole-admin
// delete proceed, and this test has two members).
func TestHandleDeleteGroup_MemberRemoved(t *testing.T) {
	s := newTestServer(t)
	if err := s.store.CreateGroup("group_test", "alice", []string{"alice", "bob"}, "Test"); err != nil {
		t.Fatalf("create group: %v", err)
	}
	if err := s.store.SetGroupMemberAdmin("group_test", "bob", true); err != nil {
		t.Fatalf("promote bob: %v", err)
	}

	cc := testClientFor("alice", "dev_alice_1")
	s.mu.Lock()
	s.clients["dev_alice_1"] = cc.Client
	s.mu.Unlock()

	raw, _ := json.Marshal(protocol.DeleteGroup{Type: "delete_group", Group: "group_test"})
	s.handleDeleteGroup(cc.Client, raw)

	// alice should be removed from group_members
	members, _ := s.store.GetGroupMembers("group_test")
	for _, m := range members {
		if m == "alice" {
			t.Error("alice should have been removed from group_members")
		}
	}

	// deletion record should exist for alice
	deleted, _ := s.store.GetDeletedGroupsForUser("alice")
	if len(deleted) != 1 || deleted[0] != "group_test" {
		t.Errorf("expected deletion record for group_test, got %v", deleted)
	}

	// alice's session should have received group_deleted
	msgs := cc.messages()
	if len(msgs) != 1 {
		t.Fatalf("expected 1 echo, got %d", len(msgs))
	}
	var del protocol.GroupDeleted
	if err := json.Unmarshal(msgs[0], &del); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if del.Type != "group_deleted" || del.Group != "group_test" {
		t.Errorf("unexpected echo: %+v", del)
	}
}

// TestHandleDeleteGroup_AlreadyLeft verifies the idempotent case: alice
// is not currently a member (already /leave'd), runs /delete, the server
// records the deletion intent and echoes — no leave logic re-runs and
// no error is returned.
func TestHandleDeleteGroup_AlreadyLeft(t *testing.T) {
	s := newTestServer(t)
	if err := s.store.CreateGroup("group_test", "bob", []string{"bob"}, "Test"); err != nil {
		t.Fatalf("create group: %v", err)
	}
	// alice is NOT in the group (was never added)

	cc := testClientFor("alice", "dev_alice_1")
	s.mu.Lock()
	s.clients["dev_alice_1"] = cc.Client
	s.mu.Unlock()

	raw, _ := json.Marshal(protocol.DeleteGroup{Type: "delete_group", Group: "group_test"})
	s.handleDeleteGroup(cc.Client, raw)

	// alice should NOT have been added to group_members or anything weird
	members, _ := s.store.GetGroupMembers("group_test")
	if len(members) != 1 || members[0] != "bob" {
		t.Errorf("group_members should be unchanged [bob], got %v", members)
	}

	// deletion record SHOULD exist for alice
	deleted, _ := s.store.GetDeletedGroupsForUser("alice")
	if len(deleted) != 1 || deleted[0] != "group_test" {
		t.Errorf("expected deletion record for group_test, got %v", deleted)
	}

	// echo should still fire
	msgs := cc.messages()
	if len(msgs) != 1 {
		t.Fatalf("expected 1 echo, got %d", len(msgs))
	}
}

// TestHandleDeleteGroup_LastMemberCleanup verifies that when the deleter
// is the last remaining member, the inline leave triggers the full
// cleanup of the group_conversations row + the group-<id>.db file.
func TestHandleDeleteGroup_LastMemberCleanup(t *testing.T) {
	s := newTestServer(t)
	if err := s.store.CreateGroup("group_solo", "alice", []string{"alice"}, "Solo"); err != nil {
		t.Fatalf("create group: %v", err)
	}

	cc := testClientFor("alice", "dev_alice_1")
	s.mu.Lock()
	s.clients["dev_alice_1"] = cc.Client
	s.mu.Unlock()

	raw, _ := json.Marshal(protocol.DeleteGroup{Type: "delete_group", Group: "group_solo"})
	s.handleDeleteGroup(cc.Client, raw)

	// Group row should be gone
	groups, _ := s.store.GetUserGroups("alice")
	for _, g := range groups {
		if g.ID == "group_solo" {
			t.Error("group_solo should have been cleaned up after last member /delete")
		}
	}

	// CRITICAL: alice's deletion record must STILL exist after the cleanup.
	// This is the regression for the design decision: deleted_groups
	// rows survive group cleanup so offline devices can catch up.
	deleted, _ := s.store.GetDeletedGroupsForUser("alice")
	if len(deleted) != 1 || deleted[0] != "group_solo" {
		t.Errorf("deletion record must survive last-member cleanup, got %v", deleted)
	}
}

// TestHandleDeleteGroup_LastMemberOfflineCatchup is the end-to-end
// regression for the bug the user flagged: alice is the last member,
// runs /delete, group is cleaned up, then alice's other (previously
// offline) device connects and runs sendDeletedGroups — it must see the
// deletion record so it can purge its local copy of the group.
func TestHandleDeleteGroup_LastMemberOfflineCatchup(t *testing.T) {
	s := newTestServer(t)
	if err := s.store.CreateGroup("group_solo", "alice", []string{"alice"}, "Solo"); err != nil {
		t.Fatalf("create group: %v", err)
	}

	// Device A: runs /delete
	deviceA := testClientFor("alice", "dev_alice_A")
	s.mu.Lock()
	s.clients["dev_alice_A"] = deviceA.Client
	s.mu.Unlock()

	raw, _ := json.Marshal(protocol.DeleteGroup{Type: "delete_group", Group: "group_solo"})
	s.handleDeleteGroup(deviceA.Client, raw)

	// Device A got the live echo
	if len(deviceA.messages()) != 1 {
		t.Errorf("device A should have received group_deleted echo")
	}

	// Group is gone server-side (last member)
	if _, err := s.store.GetGroupMembers("group_solo"); err != nil {
		// table query should still work, just return empty
		t.Fatalf("get members: %v", err)
	}

	// Device B (was offline) connects and runs sendDeletedGroups manually
	// (simulating the handshake step). It should see group_solo in the list.
	deviceB := testClientFor("alice", "dev_alice_B")
	s.sendDeletedGroups(deviceB.Client)

	msgs := deviceB.messages()
	if len(msgs) != 1 {
		t.Fatalf("device B should have received deleted_groups list, got %d messages", len(msgs))
	}
	var list protocol.DeletedGroupsList
	if err := json.Unmarshal(msgs[0], &list); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if list.Type != "deleted_groups" {
		t.Errorf("type = %q, want deleted_groups", list.Type)
	}
	if len(list.Groups) != 1 || list.Groups[0] != "group_solo" {
		t.Errorf("expected [group_solo] in catchup list, got %v", list.Groups)
	}
}

// TestHandleDeleteGroup_MultiDeviceLiveEcho verifies that all of the
// user's currently-connected sessions receive the group_deleted echo,
// not just the one that initiated the delete.
//
// Phase 14: bob is promoted to co-admin so alice's delete isn't blocked
// by the last-admin gate (same rationale as TestHandleDeleteGroup_MemberRemoved).
func TestHandleDeleteGroup_MultiDeviceLiveEcho(t *testing.T) {
	s := newTestServer(t)
	if err := s.store.CreateGroup("group_test", "alice", []string{"alice", "bob"}, "Test"); err != nil {
		t.Fatalf("create group: %v", err)
	}
	if err := s.store.SetGroupMemberAdmin("group_test", "bob", true); err != nil {
		t.Fatalf("promote bob: %v", err)
	}

	deviceA := testClientFor("alice", "dev_alice_A")
	deviceB := testClientFor("alice", "dev_alice_B")
	s.mu.Lock()
	s.clients["dev_alice_A"] = deviceA.Client
	s.clients["dev_alice_B"] = deviceB.Client
	s.mu.Unlock()

	raw, _ := json.Marshal(protocol.DeleteGroup{Type: "delete_group", Group: "group_test"})
	s.handleDeleteGroup(deviceA.Client, raw)

	// Both sessions should have received group_deleted
	for _, dev := range []*captureClient{deviceA, deviceB} {
		msgs := dev.messages()
		if len(msgs) != 1 {
			t.Errorf("expected 1 echo on session, got %d", len(msgs))
			continue
		}
		var del protocol.GroupDeleted
		json.Unmarshal(msgs[0], &del)
		if del.Group != "group_test" {
			t.Errorf("wrong group in echo: %s", del.Group)
		}
	}
}

// TestSendDeletedGroups_None verifies the no-op case.
func TestSendDeletedGroups_None(t *testing.T) {
	s := newTestServer(t)
	cc := testClientFor("alice", "dev_alice_1")

	s.sendDeletedGroups(cc.Client)
	if msgs := cc.messages(); len(msgs) != 0 {
		t.Errorf("expected no message when no deletions exist, got %d", len(msgs))
	}
}

// TestHandleLeaveGroup_LastMemberCleanup verifies that the /leave path
// also triggers the cleanup (separate from /delete), so groups don't
// leak when users use the regular /leave command.
func TestHandleLeaveGroup_LastMemberCleanup(t *testing.T) {
	s := newTestServer(t)
	if err := s.store.CreateGroup("group_solo", "alice", []string{"alice"}, "Solo"); err != nil {
		t.Fatalf("create group: %v", err)
	}

	cc := testClientFor("alice", "dev_alice_1")
	s.mu.Lock()
	s.clients["dev_alice_1"] = cc.Client
	s.mu.Unlock()

	raw, _ := json.Marshal(protocol.LeaveGroup{Type: "leave_group", Group: "group_solo"})
	s.handleLeaveGroup(cc.Client, raw)

	// Group should be cleaned up
	groups, _ := s.store.GetUserGroups("alice")
	for _, g := range groups {
		if g.ID == "group_solo" {
			t.Error("group_solo should be cleaned up after last member /leave")
		}
	}
}

// TestHandleLeaveGroup_PrivacyResponsesIdentical verifies that the wire
// response for "group does not exist" and "user is not a member" are
// byte-identical, so a probing client cannot use leave_group to discover
// group existence or membership.
func TestHandleLeaveGroup_PrivacyResponsesIdentical(t *testing.T) {
	s := newTestServer(t)
	if err := s.store.CreateGroup("group_real", "alice", []string{"alice"}, "Real"); err != nil {
		t.Fatalf("create group: %v", err)
	}

	// carol probes a group that does not exist
	probe := testClientFor("carol", "dev_carol_1")
	rawProbe, _ := json.Marshal(protocol.LeaveGroup{Type: "leave_group", Group: "group_does_not_exist"})
	s.handleLeaveGroup(probe.Client, rawProbe)

	// carol probes the real group (alice is a member, carol is not)
	nonMember := testClientFor("carol", "dev_carol_1")
	rawReal, _ := json.Marshal(protocol.LeaveGroup{Type: "leave_group", Group: "group_real"})
	s.handleLeaveGroup(nonMember.Client, rawReal)

	probeMsgs := probe.messages()
	nonMemberMsgs := nonMember.messages()
	if len(probeMsgs) != 1 || len(nonMemberMsgs) != 1 {
		t.Fatalf("expected 1 reply each, got probe=%d nonMember=%d",
			len(probeMsgs), len(nonMemberMsgs))
	}
	if !bytes.Equal(probeMsgs[0], nonMemberMsgs[0]) {
		t.Errorf("privacy leak: unknown-group and non-member responses differ\nunknown:    %s\nnon-member: %s",
			probeMsgs[0], nonMemberMsgs[0])
	}
}

// TestPerformGroupLeave_EmptyReasonIsSelfLeave verifies the existing
// self-leave path still works after the refactor (regression).
func TestPerformGroupLeave_EmptyReasonIsSelfLeave(t *testing.T) {
	s := newTestServer(t)
	if err := s.store.CreateGroup("group_self", "alice", []string{"alice", "bob"}, "Self"); err != nil {
		t.Fatalf("create group: %v", err)
	}

	aliceClient := testClientFor("alice", "dev_alice_1")
	bobClient := testClientFor("bob", "dev_bob_1")
	s.mu.Lock()
	s.clients["dev_alice_1"] = aliceClient.Client
	s.clients["dev_bob_1"] = bobClient.Client
	s.mu.Unlock()

	s.performGroupLeave("group_self", "alice", "", "")

	// Alice receives group_left with empty reason
	msgs := aliceClient.messages()
	if len(msgs) != 1 {
		t.Fatalf("alice expected 1 echo, got %d", len(msgs))
	}
	var left protocol.GroupLeft
	json.Unmarshal(msgs[0], &left)
	if left.Reason != "" {
		t.Errorf("self-leave reason should be empty, got %q", left.Reason)
	}

	// Bob receives group_event{leave} with empty reason
	bobMsgs := bobClient.messages()
	if len(bobMsgs) != 1 {
		t.Fatalf("bob expected 1 broadcast, got %d", len(bobMsgs))
	}
	var ev protocol.GroupEvent
	json.Unmarshal(bobMsgs[0], &ev)
	if ev.Reason != "" {
		t.Errorf("self-leave broadcast reason should be empty, got %q", ev.Reason)
	}
}

// TestHandleRenameGroup_BroadcastsToMembers verifies the rename happy
// path: a member renames the group, the new name is persisted, and
// every connected member of the group receives a group_renamed event
// (including the renamer themselves).
func TestHandleRenameGroup_BroadcastsToMembers(t *testing.T) {
	s := newTestServer(t)
	if err := s.store.CreateGroup("group_rename", "alice", []string{"alice", "bob"}, "Old Name"); err != nil {
		t.Fatalf("create group: %v", err)
	}

	aliceClient := testClientFor("alice", "dev_alice_1")
	bobClient := testClientFor("bob", "dev_bob_1")
	s.mu.Lock()
	s.clients["dev_alice_1"] = aliceClient.Client
	s.clients["dev_bob_1"] = bobClient.Client
	s.mu.Unlock()

	raw, _ := json.Marshal(protocol.RenameGroup{
		Type: "rename_group", Group: "group_rename", Name: "New Name",
	})
	s.handleRenameGroup(aliceClient.Client, raw)

	// Phase 14: each member gets TWO broadcasts — the legacy group_renamed
	// (kept for backward compat with pre-Phase-14 clients during the
	// single-repo upgrade window) AND the new unified group_event{rename}
	// (for post-Phase-14 clients and sync replay). Both carry the same
	// new name and same renamer.
	for _, cc := range []*captureClient{aliceClient, bobClient} {
		msgs := cc.messages()
		if len(msgs) != 2 {
			t.Fatalf("expected 2 broadcasts (legacy + group_event), got %d", len(msgs))
		}

		// First: legacy group_renamed
		var renamed protocol.GroupRenamed
		if err := json.Unmarshal(msgs[0], &renamed); err != nil {
			t.Fatalf("parse legacy group_renamed: %v", err)
		}
		if renamed.Type != "group_renamed" {
			t.Errorf("type = %q, want group_renamed", renamed.Type)
		}
		if renamed.Group != "group_rename" || renamed.Name != "New Name" || renamed.RenamedBy != "alice" {
			t.Errorf("unexpected legacy broadcast: %+v", renamed)
		}

		// Second: Phase 14 group_event{rename}
		var ev protocol.GroupEvent
		if err := json.Unmarshal(msgs[1], &ev); err != nil {
			t.Fatalf("parse group_event: %v", err)
		}
		if ev.Type != "group_event" {
			t.Errorf("type = %q, want group_event", ev.Type)
		}
		if ev.Event != "rename" {
			t.Errorf("event = %q, want rename", ev.Event)
		}
		if ev.Group != "group_rename" || ev.Name != "New Name" || ev.By != "alice" {
			t.Errorf("unexpected group_event{rename}: %+v", ev)
		}
	}

	// Server-side: the group's stored name is updated. We verify by
	// inspecting via GetUserGroups (which joins on the conversation row).
	groups, _ := s.store.GetUserGroups("alice")
	for _, g := range groups {
		if g.ID == "group_rename" {
			if g.Name != "New Name" {
				t.Errorf("stored name = %q, want New Name", g.Name)
			}
			return
		}
	}
	t.Error("group_rename not found in alice's groups after rename")
}

// TestHandleRenameGroup_PrivacyResponsesIdentical verifies that the
// rename handler matches the byte-identical privacy convention used by
// the other group handlers — non-members and unknown-group probes get
// the same response.
func TestHandleRenameGroup_PrivacyResponsesIdentical(t *testing.T) {
	s := newTestServer(t)
	if err := s.store.CreateGroup("group_real", "alice", []string{"alice"}, "Real"); err != nil {
		t.Fatalf("create group: %v", err)
	}

	probe := testClientFor("carol", "dev_carol_1")
	rawProbe, _ := json.Marshal(protocol.RenameGroup{
		Type: "rename_group", Group: "group_does_not_exist", Name: "Hijack",
	})
	s.handleRenameGroup(probe.Client, rawProbe)

	nonMember := testClientFor("carol", "dev_carol_1")
	rawReal, _ := json.Marshal(protocol.RenameGroup{
		Type: "rename_group", Group: "group_real", Name: "Hijack",
	})
	s.handleRenameGroup(nonMember.Client, rawReal)

	probeMsgs := probe.messages()
	nonMemberMsgs := nonMember.messages()
	if len(probeMsgs) != 1 || len(nonMemberMsgs) != 1 {
		t.Fatalf("expected 1 reply each, got probe=%d nonMember=%d",
			len(probeMsgs), len(nonMemberMsgs))
	}
	if !bytes.Equal(probeMsgs[0], nonMemberMsgs[0]) {
		t.Errorf("privacy leak: unknown-group and non-member rename responses differ\nunknown:    %s\nnon-member: %s",
			probeMsgs[0], nonMemberMsgs[0])
	}

	// And the group_real name should NOT have been changed
	groups, _ := s.store.GetUserGroups("alice")
	for _, g := range groups {
		if g.ID == "group_real" && g.Name != "Real" {
			t.Errorf("non-member rename should not change name, got %q", g.Name)
		}
	}
}

// TestHandleSendGroup_PrivacyResponsesIdentical verifies the same
// byte-identical property for handleSendGroup.
func TestHandleSendGroup_PrivacyResponsesIdentical(t *testing.T) {
	s := newTestServer(t)
	if err := s.store.CreateGroup("group_real", "alice", []string{"alice"}, "Real"); err != nil {
		t.Fatalf("create group: %v", err)
	}

	probe := testClientFor("carol", "dev_carol_1")
	rawProbe, _ := json.Marshal(protocol.SendGroup{
		Type: "send_group", Group: "group_does_not_exist",
		WrappedKeys: map[string]string{"carol": "x"},
		Payload:     "p", Signature: "s",
	})
	s.handleSendGroup(probe.Client, rawProbe)

	nonMember := testClientFor("carol", "dev_carol_1")
	rawReal, _ := json.Marshal(protocol.SendGroup{
		Type: "send_group", Group: "group_real",
		WrappedKeys: map[string]string{"carol": "x"},
		Payload:     "p", Signature: "s",
	})
	s.handleSendGroup(nonMember.Client, rawReal)

	probeMsgs := probe.messages()
	nonMemberMsgs := nonMember.messages()
	if len(probeMsgs) != 1 || len(nonMemberMsgs) != 1 {
		t.Fatalf("expected 1 reply each, got probe=%d nonMember=%d",
			len(probeMsgs), len(nonMemberMsgs))
	}
	if !bytes.Equal(probeMsgs[0], nonMemberMsgs[0]) {
		t.Errorf("privacy leak: unknown-group and non-member send responses differ\nunknown:    %s\nnon-member: %s",
			probeMsgs[0], nonMemberMsgs[0])
	}
}
