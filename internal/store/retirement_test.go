package store

import (
	"sort"
	"testing"
)

// TestRetireUserFromGroups_Removed verifies that retiring a user who is in a
// group DM removes them from group_members.
func TestRetireUserFromGroups_Removed(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	if err := s.CreateGroup("group_abc", "alice", []string{"alice", "bob", "carol"}); err != nil {
		t.Fatalf("create group: %v", err)
	}

	groupIDs, err := s.RetireUserFromGroups("alice")
	if err != nil {
		t.Fatalf("retire: %v", err)
	}
	if len(groupIDs) != 1 || groupIDs[0] != "group_abc" {
		t.Fatalf("expected [group_abc], got %v", groupIDs)
	}

	members, err := s.GetGroupMembers("group_abc")
	if err != nil {
		t.Fatalf("get members: %v", err)
	}
	sort.Strings(members)
	if len(members) != 2 || members[0] != "bob" || members[1] != "carol" {
		t.Fatalf("expected [bob carol], got %v", members)
	}
}

// TestRetireUserFromGroups_NoMembership verifies no-op for a user not in any group.
func TestRetireUserFromGroups_NoMembership(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	s.CreateGroup("group_bc", "bob", []string{"bob", "carol"})

	groupIDs, err := s.RetireUserFromGroups("alice")
	if err != nil {
		t.Fatalf("retire: %v", err)
	}
	if len(groupIDs) != 0 {
		t.Fatalf("expected no affected groups, got %v", groupIDs)
	}

	members, _ := s.GetGroupMembers("group_bc")
	if len(members) != 2 {
		t.Fatalf("expected 2 members unchanged, got %d", len(members))
	}
}

// TestRetireUserFromGroups_LargeGroup verifies removal from a large group.
func TestRetireUserFromGroups_LargeGroup(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	members := []string{"alice"}
	for i := 0; i < 20; i++ {
		members = append(members, "user_"+string(rune('a'+i)))
	}
	if err := s.CreateGroup("group_big", "alice", members); err != nil {
		t.Fatalf("create: %v", err)
	}

	groupIDs, err := s.RetireUserFromGroups("alice")
	if err != nil {
		t.Fatalf("retire: %v", err)
	}
	if len(groupIDs) != 1 {
		t.Fatalf("expected 1, got %d", len(groupIDs))
	}

	got, _ := s.GetGroupMembers("group_big")
	for _, m := range got {
		if m == "alice" {
			t.Fatal("alice should have been removed")
		}
	}
	if len(got) != len(members)-1 {
		t.Fatalf("expected %d members, got %d", len(members)-1, len(got))
	}
}

// TestSetDMLeftAt_OneWayRatchet verifies the per-user cutoff is a one-way ratchet.
func TestSetDMLeftAt_OneWayRatchet(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	dm, err := s.CreateOrGetDirectMessage("dm_test1", "alice", "bob")
	if err != nil {
		t.Fatalf("create DM: %v", err)
	}
	if dm.UserALeftAt != 0 || dm.UserBLeftAt != 0 {
		t.Fatal("new DM should have zero cutoffs")
	}

	// Set cutoff for alice (user_a, since alice < bob alphabetically)
	if err := s.SetDMLeftAt(dm.ID, "alice", 1000); err != nil {
		t.Fatalf("set left_at: %v", err)
	}

	dm2, _ := s.GetDirectMessage(dm.ID)
	if dm2.UserALeftAt != 1000 {
		t.Fatalf("expected user_a_left_at=1000, got %d", dm2.UserALeftAt)
	}

	// Try to set a lower value — should be rejected (ratchet)
	if err := s.SetDMLeftAt(dm.ID, "alice", 500); err != nil {
		t.Fatalf("set left_at lower: %v", err)
	}
	dm3, _ := s.GetDirectMessage(dm.ID)
	if dm3.UserALeftAt != 1000 {
		t.Fatalf("ratchet failed: expected 1000, got %d", dm3.UserALeftAt)
	}

	// Set a higher value — should succeed
	if err := s.SetDMLeftAt(dm.ID, "alice", 2000); err != nil {
		t.Fatalf("set left_at higher: %v", err)
	}
	dm4, _ := s.GetDirectMessage(dm.ID)
	if dm4.UserALeftAt != 2000 {
		t.Fatalf("expected 2000, got %d", dm4.UserALeftAt)
	}

	// Bob's cutoff should be untouched
	if dm4.UserBLeftAt != 0 {
		t.Fatalf("bob's cutoff should be 0, got %d", dm4.UserBLeftAt)
	}
}

// TestCreateOrGetDirectMessage_Dedup verifies that creating a DM twice for the
// same pair returns the same row.
func TestCreateOrGetDirectMessage_Dedup(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	dm1, err := s.CreateOrGetDirectMessage("dm_first", "bob", "alice")
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	// Create again with a different ID — should return the existing row
	dm2, err := s.CreateOrGetDirectMessage("dm_second", "alice", "bob")
	if err != nil {
		t.Fatalf("create2: %v", err)
	}

	if dm1.ID != dm2.ID {
		t.Fatalf("expected same ID (dedup), got %q and %q", dm1.ID, dm2.ID)
	}
	// Canonical order: alice < bob
	if dm1.UserA != "alice" || dm1.UserB != "bob" {
		t.Fatalf("expected canonical order [alice bob], got [%s %s]", dm1.UserA, dm1.UserB)
	}
}
