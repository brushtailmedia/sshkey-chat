package store

import (
	"sort"
	"testing"

	"github.com/brushtailmedia/sshkey-chat/internal/testutil"
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

	dm, err := s.CreateOrGetDirectMessage(testutil.DMID("test1"), testutil.UserID("alice"), testutil.UserID("bob"))
	if err != nil {
		t.Fatalf("create DM: %v", err)
	}
	if dm.UserALeftAt != 0 || dm.UserBLeftAt != 0 {
		t.Fatal("new DM should have zero cutoffs")
	}

	// Observe cutoffs by user, independently of canonical pair ordering.
	cutoffFor := func(dm *DirectMessage, user string) int64 {
		if dm.UserA == user {
			return dm.UserALeftAt
		}
		return dm.UserBLeftAt
	}
	// Set Alice's cutoff.
	if err := s.SetDMLeftAt(dm.ID, testutil.UserID("alice"), 1000); err != nil {
		t.Fatalf("set left_at: %v", err)
	}

	dm2, _ := s.GetDirectMessage(dm.ID)
	if cutoffFor(dm2, testutil.UserID("alice")) != 1000 {
		t.Fatalf("expected user_a_left_at=1000, got %d", cutoffFor(dm2, testutil.UserID("alice")))
	}

	// Try to set a lower value — should be rejected (ratchet)
	if err := s.SetDMLeftAt(dm.ID, testutil.UserID("alice"), 500); err != nil {
		t.Fatalf("set left_at lower: %v", err)
	}
	dm3, _ := s.GetDirectMessage(dm.ID)
	if cutoffFor(dm3, testutil.UserID("alice")) != 1000 {
		t.Fatalf("ratchet failed: expected 1000, got %d", cutoffFor(dm3, testutil.UserID("alice")))
	}

	// Set a higher value — should succeed
	if err := s.SetDMLeftAt(dm.ID, testutil.UserID("alice"), 2000); err != nil {
		t.Fatalf("set left_at higher: %v", err)
	}
	dm4, _ := s.GetDirectMessage(dm.ID)
	if cutoffFor(dm4, testutil.UserID("alice")) != 2000 {
		t.Fatalf("expected 2000, got %d", cutoffFor(dm4, testutil.UserID("alice")))
	}

	// Bob's cutoff should be untouched
	if cutoffFor(dm4, testutil.UserID("bob")) != 0 {
		t.Fatalf("bob's cutoff should be 0, got %d", cutoffFor(dm4, testutil.UserID("bob")))
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

	dm1, err := s.CreateOrGetDirectMessage(testutil.DMID("first"), testutil.UserID("bob"), testutil.UserID("alice"))
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	// Create again with a different ID — should return the existing row
	dm2, err := s.CreateOrGetDirectMessage(testutil.DMID("second"), testutil.UserID("alice"), testutil.UserID("bob"))
	if err != nil {
		t.Fatalf("create2: %v", err)
	}

	if dm1.ID != dm2.ID {
		t.Fatalf("expected same ID (dedup), got %q and %q", dm1.ID, dm2.ID)
	}
	// Canonical order is lexical over actual IDs, not role labels.
	wantPair := []string{testutil.UserID("alice"), testutil.UserID("bob")}
	sort.Strings(wantPair)
	if dm1.UserA != wantPair[0] || dm1.UserB != wantPair[1] {
		t.Fatalf("expected canonical order [alice bob], got [%s %s]", dm1.UserA, dm1.UserB)
	}
}

func TestSetDMHidden_PerUser(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	dm, err := s.CreateOrGetDirectMessage(testutil.DMID("ab"), testutil.UserID("alice"), testutil.UserID("bob"))
	if err != nil {
		t.Fatalf("create DM: %v", err)
	}
	if dm.HiddenFor(testutil.UserID("alice")) || dm.HiddenFor(testutil.UserID("bob")) {
		t.Fatal("fresh DM should not be hidden")
	}

	if err := s.SetDMHidden(dm.ID, testutil.UserID("alice"), true); err != nil {
		t.Fatalf("SetDMHidden true: %v", err)
	}
	afterHide, err := s.GetDirectMessage(dm.ID)
	if err != nil {
		t.Fatalf("GetDirectMessage after hide: %v", err)
	}
	if !afterHide.HiddenFor(testutil.UserID("alice")) {
		t.Fatal("alice should be hidden after SetDMHidden(true)")
	}
	if afterHide.HiddenFor(testutil.UserID("bob")) {
		t.Fatal("bob should remain visible")
	}

	if err := s.SetDMHidden(dm.ID, testutil.UserID("alice"), false); err != nil {
		t.Fatalf("SetDMHidden false: %v", err)
	}
	afterShow, err := s.GetDirectMessage(dm.ID)
	if err != nil {
		t.Fatalf("GetDirectMessage after clear: %v", err)
	}
	if afterShow.HiddenFor(testutil.UserID("alice")) {
		t.Fatal("alice should be visible after SetDMHidden(false)")
	}
}
