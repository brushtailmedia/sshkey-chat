package store

import (
	"testing"
)

// Phase 14 removed the TestRetireUserFromGroups_{Removed,NoMembership,LargeGroup}
// trio — they tested a store helper (RetireUserFromGroups) that was deleted
// when handleRetirement was restructured to iterate per-group through
// performGroupLeave. Coverage is subsumed by handler-level succession tests
// in the server package (TestHandleRetirement_* family, see groups_admin.md
// Test coverage section).

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
