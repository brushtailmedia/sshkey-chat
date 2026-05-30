package server

import (
	"encoding/json"
	"sync"
	"testing"

	"github.com/brushtailmedia/sshkey-chat/internal/protocol"
)

// TestGroupAdmin_ConcurrentDemote_NeverZeroAdmins guards the audit-S9 fix: the
// last-admin guard is a check-then-act (CountGroupAdmins → demote) that, before
// groupAdminMu, two concurrent demotes of the two distinct admins of a group
// could both pass (each reads count==2 > 1) and then both mutate, leaving the
// group with ZERO admins. groupAdminMu serializes the check+mutate so exactly
// one demote succeeds and the other is rejected as "last admin"; the group
// always retains at least one admin.
//
// Run with -race to also catch data races on the shared admin state.
func TestGroupAdmin_ConcurrentDemote_NeverZeroAdmins(t *testing.T) {
	s := newTestServer(t)
	if err := s.store.CreateGroup("grp_s9", "alice", []string{"alice", "bob"}, "S9"); err != nil {
		t.Fatalf("create group: %v", err)
	}
	if err := s.store.SetGroupMemberAdmin("grp_s9", "bob", true); err != nil {
		t.Fatalf("promote bob: %v", err)
	}
	if n, _ := s.store.CountGroupAdmins("grp_s9"); n != 2 {
		t.Fatalf("setup: admins = %d, want 2", n)
	}

	aliceC := testClientFor("alice", "dev_alice_s9")
	bobC := testClientFor("bob", "dev_bob_s9")
	demoteBob, _ := json.Marshal(protocol.DemoteGroupAdmin{Type: "demote_group_admin", Group: "grp_s9", User: "bob"})
	demoteAlice, _ := json.Marshal(protocol.DemoteGroupAdmin{Type: "demote_group_admin", Group: "grp_s9", User: "alice"})

	// Start barrier so both handlers contend on the guard simultaneously,
	// maximizing the race window (which the mutex must close).
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); <-start; s.handleDemoteGroupAdmin(aliceC.Client, demoteBob) }()
	go func() { defer wg.Done(); <-start; s.handleDemoteGroupAdmin(bobC.Client, demoteAlice) }()
	close(start)
	wg.Wait()

	if n, _ := s.store.CountGroupAdmins("grp_s9"); n < 1 {
		t.Fatalf("group left with %d admins — the last-admin guard was raced to zero (S9)", n)
	}
}
