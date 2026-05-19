package server

import (
	"encoding/json"
	"testing"

	"github.com/brushtailmedia/sshkey-chat/internal/counters"
	"github.com/brushtailmedia/sshkey-chat/internal/protocol"
	"github.com/brushtailmedia/sshkey-chat/internal/store"
)

// Typing is a membership-scoped signal: the server authorizes the
// SENDER's participation before relaying, exactly mirroring
// message-send authz (handleSend room+retired / group / DM party).
// Security is enforced server-side — the client `/typing` toggle is a
// UX affordance only and is never trusted (any client can speak the
// protocol). Unauthorized typing is silent-dropped + fires
// SignalNonMemberContext; empty/ambiguous context is silent-dropped +
// SignalMalformedFrame. See typing-relay-authz-hardening.md.

func TestHandleTyping_NonMemberRoom_SilentDropSignal(t *testing.T) {
	s := newTestServer(t)
	engID := s.store.RoomDisplayNameToID("engineering")
	bob := testClientFor("bob", "dev_bob_typing_nm_room") // bob is NOT in engineering
	raw, _ := json.Marshal(protocol.Typing{Type: "typing", Room: engID})
	s.handleTyping(bob.Client, raw)
	if got := s.counters.Get(counters.SignalNonMemberContext, "dev_bob_typing_nm_room"); got != 1 {
		t.Errorf("SignalNonMemberContext = %d, want 1", got)
	}
	if msgs := bob.messages(); len(msgs) != 0 {
		t.Errorf("non-member typing must be silent-dropped, got %d wire msg(s)", len(msgs))
	}
}

func TestHandleTyping_NonMemberGroup_SilentDropSignal(t *testing.T) {
	s := newTestServer(t)
	if err := s.store.CreateGroup("group_typing_nm", "alice", []string{"alice"}, "Test"); err != nil {
		t.Fatalf("create group: %v", err)
	}
	carol := testClientFor("carol", "dev_carol_typing_nm_grp") // not in group_typing_nm
	raw, _ := json.Marshal(protocol.Typing{Type: "typing", Group: "group_typing_nm"})
	s.handleTyping(carol.Client, raw)
	if got := s.counters.Get(counters.SignalNonMemberContext, "dev_carol_typing_nm_grp"); got != 1 {
		t.Errorf("SignalNonMemberContext = %d, want 1", got)
	}
}

func TestHandleTyping_NonPartyDM_SilentDropSignal(t *testing.T) {
	s := newTestServer(t)
	dm, err := s.store.CreateOrGetDirectMessage(store.GenerateID("dm_"), "alice", "bob")
	if err != nil {
		t.Fatalf("create dm: %v", err)
	}
	carol := testClientFor("carol", "dev_carol_typing_nm_dm") // not a party to the DM
	raw, _ := json.Marshal(protocol.Typing{Type: "typing", DM: dm.ID})
	s.handleTyping(carol.Client, raw)
	if got := s.counters.Get(counters.SignalNonMemberContext, "dev_carol_typing_nm_dm"); got != 1 {
		t.Errorf("SignalNonMemberContext = %d, want 1", got)
	}
}

// D2: full send-path mirror — a member typing into a RETIRED room is
// suppressed too (typing in a read-only room is pointless/confusing).
func TestHandleTyping_RetiredRoomMember_SilentDropSignal(t *testing.T) {
	s := newTestServer(t)
	genID := s.store.RoomDisplayNameToID("general")
	if err := s.store.SetRoomRetired(genID, "alice", "test"); err != nil {
		t.Fatalf("retire room: %v", err)
	}
	alice := testClientFor("alice", "dev_alice_typing_retired") // member, but room retired
	raw, _ := json.Marshal(protocol.Typing{Type: "typing", Room: genID})
	s.handleTyping(alice.Client, raw)
	if got := s.counters.Get(counters.SignalNonMemberContext, "dev_alice_typing_retired"); got != 1 {
		t.Errorf("retired-room typing: SignalNonMemberContext = %d, want 1 (full send-path mirror)", got)
	}
}

func TestHandleTyping_EmptyAndAmbiguousContext_MalformedSignal(t *testing.T) {
	s := newTestServer(t)
	genID := s.store.RoomDisplayNameToID("general")

	empty := testClientFor("alice", "dev_alice_typing_empty")
	raw, _ := json.Marshal(protocol.Typing{Type: "typing"}) // no context
	s.handleTyping(empty.Client, raw)
	if got := s.counters.Get(counters.SignalMalformedFrame, "dev_alice_typing_empty"); got != 1 {
		t.Errorf("empty-context typing: SignalMalformedFrame = %d, want 1", got)
	}

	ambig := testClientFor("alice", "dev_alice_typing_ambig")
	raw2, _ := json.Marshal(protocol.Typing{Type: "typing", Room: genID, DM: "dm_x"}) // two contexts
	s.handleTyping(ambig.Client, raw2)
	if got := s.counters.Get(counters.SignalMalformedFrame, "dev_alice_typing_ambig"); got != 1 {
		t.Errorf("ambiguous-context typing: SignalMalformedFrame = %d, want 1", got)
	}
}

// Negative guard: an authorized member must NOT trip either gate
// counter (the gate doesn't false-positive on legitimate typing).
func TestHandleTyping_MemberRoom_NoDropSignal(t *testing.T) {
	s := newTestServer(t)
	genID := s.store.RoomDisplayNameToID("general")
	alice := testClientFor("alice", "dev_alice_typing_member") // alice IS a member of general
	raw, _ := json.Marshal(protocol.Typing{Type: "typing", Room: genID})
	s.handleTyping(alice.Client, raw)
	if got := s.counters.Get(counters.SignalNonMemberContext, "dev_alice_typing_member"); got != 0 {
		t.Errorf("authorized member typing must NOT fire SignalNonMemberContext, got %d", got)
	}
	if got := s.counters.Get(counters.SignalMalformedFrame, "dev_alice_typing_member"); got != 0 {
		t.Errorf("authorized member typing must NOT fire SignalMalformedFrame, got %d", got)
	}
}

func TestHandleTyping_DMParty_NoDropSignal(t *testing.T) {
	s := newTestServer(t)
	dm, err := s.store.CreateOrGetDirectMessage(store.GenerateID("dm_"), "alice", "bob")
	if err != nil {
		t.Fatalf("create dm: %v", err)
	}
	alice := testClientFor("alice", "dev_alice_typing_dm_ok") // alice IS a party
	raw, _ := json.Marshal(protocol.Typing{Type: "typing", DM: dm.ID})
	s.handleTyping(alice.Client, raw)
	if got := s.counters.Get(counters.SignalNonMemberContext, "dev_alice_typing_dm_ok"); got != 0 {
		t.Errorf("authorized DM-party typing must NOT fire SignalNonMemberContext, got %d", got)
	}
}
