package server

import (
	"encoding/json"
	"testing"

	"github.com/brushtailmedia/sshkey-chat/internal/protocol"
)

func TestHandleLeaveDM_SetsHiddenForLeaverOnly(t *testing.T) {
	s := newTestServer(t)
	dm, err := s.store.CreateOrGetDirectMessage("dm_ab", "alice", "bob")
	if err != nil {
		t.Fatalf("create DM: %v", err)
	}

	bob := testClientFor("bob", "dev_bob_1")
	s.mu.Lock()
	s.clients["dev_bob_1"] = bob.Client
	s.mu.Unlock()

	s.handleLeaveDM(bob.Client, mustJSON(t, protocol.LeaveDM{Type: "leave_dm", DM: dm.ID}))

	after, err := s.store.GetDirectMessage(dm.ID)
	if err != nil {
		t.Fatalf("get DM after leave: %v", err)
	}
	if after == nil {
		t.Fatal("DM should still exist after one-sided leave")
	}
	if !after.HiddenFor("bob") {
		t.Fatal("bob should be hidden after leave_dm")
	}
	if after.HiddenFor("alice") {
		t.Fatal("alice should remain visible after bob leave_dm")
	}
	if after.CutoffFor("bob") == 0 {
		t.Fatal("bob cutoff should be set after leave_dm")
	}
}

func TestHandleCreateDM_ReusesRowClearsHiddenButKeepsCutoff(t *testing.T) {
	s := newTestServer(t)
	dm, err := s.store.CreateOrGetDirectMessage("dm_ab", "alice", "bob")
	if err != nil {
		t.Fatalf("create DM: %v", err)
	}

	if err := s.store.SetDMLeftAt(dm.ID, "alice", 1234); err != nil {
		t.Fatalf("SetDMLeftAt: %v", err)
	}
	if err := s.store.SetDMHidden(dm.ID, "alice", true); err != nil {
		t.Fatalf("SetDMHidden alice: %v", err)
	}
	if err := s.store.SetDMHidden(dm.ID, "bob", true); err != nil {
		t.Fatalf("SetDMHidden bob: %v", err)
	}

	alice := testClientFor("alice", "dev_alice_1")
	s.mu.Lock()
	s.clients["dev_alice_1"] = alice.Client
	s.mu.Unlock()

	s.handleCreateDM(alice.Client, mustJSON(t, protocol.CreateDM{Type: "create_dm", Other: "bob"}))

	after, err := s.store.GetDirectMessage(dm.ID)
	if err != nil {
		t.Fatalf("get DM after create_dm: %v", err)
	}
	if after == nil {
		t.Fatal("DM should still exist")
	}
	if after.HiddenFor("alice") || after.HiddenFor("bob") {
		t.Fatalf("hidden flags should be cleared for both parties: alice=%v bob=%v",
			after.HiddenFor("alice"), after.HiddenFor("bob"))
	}
	if got := after.CutoffFor("alice"); got != 1234 {
		t.Fatalf("alice cutoff changed: got %d want 1234", got)
	}

	msgs := alice.messages()
	if len(msgs) != 1 {
		t.Fatalf("expected one dm_created, got %d", len(msgs))
	}
	var created protocol.DMCreated
	if err := json.Unmarshal(msgs[0], &created); err != nil {
		t.Fatalf("decode dm_created: %v", err)
	}
	if created.Type != "dm_created" {
		t.Fatalf("type = %q, want dm_created", created.Type)
	}
	if created.DM != dm.ID {
		t.Fatalf("expected reused dm id %q, got %q", dm.ID, created.DM)
	}
}

func TestSendDMList_IncludesHiddenForCaller(t *testing.T) {
	s := newTestServer(t)
	dm, err := s.store.CreateOrGetDirectMessage("dm_ab", "alice", "bob")
	if err != nil {
		t.Fatalf("create DM: %v", err)
	}
	if err := s.store.SetDMLeftAt(dm.ID, "alice", 4321); err != nil {
		t.Fatalf("SetDMLeftAt: %v", err)
	}
	if err := s.store.SetDMHidden(dm.ID, "alice", true); err != nil {
		t.Fatalf("SetDMHidden: %v", err)
	}

	alice := testClientFor("alice", "dev_alice_1")
	s.sendDMList(alice.Client)

	msgs := alice.messages()
	if len(msgs) != 1 {
		t.Fatalf("expected one dm_list, got %d", len(msgs))
	}
	var dl protocol.DMList
	if err := json.Unmarshal(msgs[0], &dl); err != nil {
		t.Fatalf("decode dm_list: %v", err)
	}
	if dl.Type != "dm_list" {
		t.Fatalf("type = %q, want dm_list", dl.Type)
	}
	if len(dl.DMs) != 1 {
		t.Fatalf("expected 1 DM in list, got %d", len(dl.DMs))
	}
	if !dl.DMs[0].HiddenForCaller {
		t.Fatal("hidden_for_caller should be true for alice")
	}
	if dl.DMs[0].LeftAtForCaller != 4321 {
		t.Fatalf("left_at_for_caller = %d, want 4321", dl.DMs[0].LeftAtForCaller)
	}
}
