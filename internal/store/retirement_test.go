package store

import (
	"sort"
	"testing"
)

// TestRetireUserFromConversations_OneToOneKept verifies that retiring a user
// who is in a 1:1 DM preserves their membership in conversation_members. This
// keeps the conversation visible in the remaining party's UI for history.
func TestRetireUserFromConversations_OneToOneKept(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	if err := s.CreateConversation("conv_oneone", []string{"alice", "bob"}); err != nil {
		t.Fatalf("create 1:1: %v", err)
	}

	convIDs, err := s.RetireUserFromConversations("alice")
	if err != nil {
		t.Fatalf("retire: %v", err)
	}
	if len(convIDs) != 1 || convIDs[0] != "conv_oneone" {
		t.Errorf("affected convs = %v, want [conv_oneone]", convIDs)
	}

	members, err := s.GetConversationMembers("conv_oneone")
	if err != nil {
		t.Fatalf("get members: %v", err)
	}
	sort.Strings(members)
	want := []string{"alice", "bob"}
	if len(members) != 2 || members[0] != want[0] || members[1] != want[1] {
		t.Errorf("1:1 members after retirement = %v, want %v (both preserved)", members, want)
	}
}

// TestRetireUserFromConversations_GroupRemoved verifies that retiring a user
// in a group DM (3+ members) DOES remove them from conversation_members.
func TestRetireUserFromConversations_GroupRemoved(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	if err := s.CreateConversation("conv_group", []string{"alice", "bob", "carol"}); err != nil {
		t.Fatalf("create group: %v", err)
	}

	convIDs, err := s.RetireUserFromConversations("alice")
	if err != nil {
		t.Fatalf("retire: %v", err)
	}
	if len(convIDs) != 1 || convIDs[0] != "conv_group" {
		t.Errorf("affected convs = %v, want [conv_group]", convIDs)
	}

	members, err := s.GetConversationMembers("conv_group")
	if err != nil {
		t.Fatalf("get members: %v", err)
	}
	sort.Strings(members)
	want := []string{"bob", "carol"}
	if len(members) != 2 || members[0] != want[0] || members[1] != want[1] {
		t.Errorf("group members after retirement = %v, want %v (alice removed)", members, want)
	}
}

// TestRetireUserFromConversations_Mixed verifies both types handled together.
func TestRetireUserFromConversations_Mixed(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	s.CreateConversation("conv_1on1_bob", []string{"alice", "bob"})
	s.CreateConversation("conv_1on1_carol", []string{"alice", "carol"})
	s.CreateConversation("conv_group_abc", []string{"alice", "bob", "carol"})
	s.CreateConversation("conv_group_nobob", []string{"bob", "carol"})  // 2 members but alice not in it — should be untouched

	convIDs, err := s.RetireUserFromConversations("alice")
	if err != nil {
		t.Fatalf("retire: %v", err)
	}
	sort.Strings(convIDs)
	if len(convIDs) != 3 {
		t.Errorf("affected convs = %v, want 3", convIDs)
	}

	// 1:1s still have alice
	for _, convID := range []string{"conv_1on1_bob", "conv_1on1_carol"} {
		members, _ := s.GetConversationMembers(convID)
		hasAlice := false
		for _, m := range members {
			if m == "alice" {
				hasAlice = true
			}
		}
		if !hasAlice {
			t.Errorf("1:1 %s should still contain alice: %v", convID, members)
		}
	}

	// Group should have alice removed
	groupMembers, _ := s.GetConversationMembers("conv_group_abc")
	for _, m := range groupMembers {
		if m == "alice" {
			t.Error("group should not contain alice after retirement")
		}
	}
	if len(groupMembers) != 2 {
		t.Errorf("group should have 2 remaining members, got %v", groupMembers)
	}

	// Conversation alice wasn't in should be untouched
	untouchedMembers, _ := s.GetConversationMembers("conv_group_nobob")
	if len(untouchedMembers) != 2 {
		t.Errorf("untouched conv altered: %v", untouchedMembers)
	}
}

// TestRetireUserFromConversations_NoMembership verifies a retirement for a
// user not in any conversations is a no-op.
func TestRetireUserFromConversations_NoMembership(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	// Create a conversation that doesn't include alice
	s.CreateConversation("conv_bc", []string{"bob", "carol"})

	convIDs, err := s.RetireUserFromConversations("alice")
	if err != nil {
		t.Fatalf("retire: %v", err)
	}
	if len(convIDs) != 0 {
		t.Errorf("expected empty affected list, got %v", convIDs)
	}

	// bob+carol conv untouched
	members, _ := s.GetConversationMembers("conv_bc")
	if len(members) != 2 {
		t.Errorf("bob+carol conv altered: %v", members)
	}
}

// TestRetireUserFromConversations_LargeGroup verifies a group DM with many
// members keeps the remaining members intact.
func TestRetireUserFromConversations_LargeGroup(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	members := []string{"alice", "bob", "carol", "dave", "eve", "frank"}
	if err := s.CreateConversation("conv_big", members); err != nil {
		t.Fatalf("create: %v", err)
	}

	convIDs, err := s.RetireUserFromConversations("alice")
	if err != nil {
		t.Fatalf("retire: %v", err)
	}
	if len(convIDs) != 1 {
		t.Errorf("expected 1 affected conv, got %d", len(convIDs))
	}

	got, _ := s.GetConversationMembers("conv_big")
	sort.Strings(got)
	want := []string{"bob", "carol", "dave", "eve", "frank"}
	if len(got) != 5 {
		t.Fatalf("expected 5 remaining members, got %d: %v", len(got), got)
	}
	for i, m := range want {
		if got[i] != m {
			t.Errorf("member[%d] = %q, want %q", i, got[i], m)
		}
	}
}

// TestRetireUserFromConversations_ThreeMemberGroupEdgeCase verifies the
// boundary: a 3-member group becomes 2 after retirement. It's still treated
// as a group (member removed), not a 1:1.
func TestRetireUserFromConversations_ThreeMemberGroupEdgeCase(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	s.CreateConversation("conv_abc", []string{"alice", "bob", "carol"})

	// Retire alice — this is a 3-member group at retirement time, so alice
	// should be removed even though the result is 2 members.
	convIDs, err := s.RetireUserFromConversations("alice")
	if err != nil {
		t.Fatalf("retire: %v", err)
	}
	if len(convIDs) != 1 {
		t.Errorf("affected convs: %v", convIDs)
	}

	got, _ := s.GetConversationMembers("conv_abc")
	sort.Strings(got)
	if len(got) != 2 || got[0] != "bob" || got[1] != "carol" {
		t.Errorf("members = %v, want [bob, carol]", got)
	}
}
