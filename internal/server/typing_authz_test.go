package server

import (
	"encoding/json"
	"testing"
	"time"

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

func assertTypingTimerCount(t *testing.T, s *Server, want int) {
	t.Helper()
	s.typing.mu.Lock()
	got := len(s.typing.timers)
	s.typing.mu.Unlock()
	if got != want {
		t.Fatalf("typing timer count = %d, want %d", got, want)
	}
}

func stopTypingTimers(s *Server) {
	s.typing.mu.Lock()
	defer s.typing.mu.Unlock()
	for _, timer := range s.typing.timers {
		timer.Stop()
	}
	s.typing.timers = make(map[string]*time.Timer)
}

func assertOneTypingMsg(t *testing.T, cc *captureClient, wantUser, wantRoom, wantGroup, wantDM string) {
	t.Helper()
	msgs := cc.messages()
	if len(msgs) != 1 {
		t.Fatalf("%s received %d messages, want 1", cc.DeviceID, len(msgs))
	}
	var got protocol.Typing
	if err := json.Unmarshal(msgs[0], &got); err != nil {
		t.Fatalf("parse typing message for %s: %v", cc.DeviceID, err)
	}
	if got.Type != "typing" || got.User != wantUser || got.Room != wantRoom || got.Group != wantGroup || got.DM != wantDM {
		t.Fatalf("typing message for %s = %+v, want user=%q room=%q group=%q dm=%q",
			cc.DeviceID, got, wantUser, wantRoom, wantGroup, wantDM)
	}
}

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
	assertTypingTimerCount(t, s, 0)
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
	assertTypingTimerCount(t, s, 0)
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
	assertTypingTimerCount(t, s, 0)
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
	assertTypingTimerCount(t, s, 0)
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
	assertTypingTimerCount(t, s, 0)
}

// Negative guard: an authorized member must NOT trip either gate
// counter (the gate doesn't false-positive on legitimate typing).
func TestHandleTyping_MemberRoom_NoDropSignal(t *testing.T) {
	s := newTestServer(t)
	t.Cleanup(func() { stopTypingTimers(s) })
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
	t.Cleanup(func() { stopTypingTimers(s) })
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

func TestHandleTyping_MemberRoom_RelaysToOtherRoomSessionsOnly(t *testing.T) {
	s := newTestServer(t)
	t.Cleanup(func() { stopTypingTimers(s) })
	genID := s.store.RoomDisplayNameToID("general")
	alice := testClientFor("alice", "dev_alice_typing_room_sender")
	bob := testClientFor("bob", "dev_bob_typing_room_recipient")
	carol := testClientFor("carol", "dev_carol_typing_room_recipient")
	outsider := testClientFor("mallory", "dev_mallory_typing_room_outsider")

	s.mu.Lock()
	s.clients[alice.DeviceID] = alice.Client
	s.clients[bob.DeviceID] = bob.Client
	s.clients[carol.DeviceID] = carol.Client
	s.clients[outsider.DeviceID] = outsider.Client
	s.mu.Unlock()

	raw, _ := json.Marshal(protocol.Typing{Type: "typing", Room: genID})
	s.handleTyping(alice.Client, raw)

	if msgs := alice.messages(); len(msgs) != 0 {
		t.Fatalf("sender current device received %d typing messages, want 0", len(msgs))
	}
	assertOneTypingMsg(t, bob, "alice", genID, "", "")
	assertOneTypingMsg(t, carol, "alice", genID, "", "")
	if msgs := outsider.messages(); len(msgs) != 0 {
		t.Fatalf("non-member received %d typing messages, want 0", len(msgs))
	}
	assertTypingTimerCount(t, s, 1)
}

func TestHandleTyping_GroupMember_RelaysToOtherGroupSessionsOnly(t *testing.T) {
	s := newTestServer(t)
	t.Cleanup(func() { stopTypingTimers(s) })
	if err := s.store.CreateGroup("group_typing_relay", "alice", []string{"alice", "bob"}, "Test"); err != nil {
		t.Fatalf("create group: %v", err)
	}
	alice := testClientFor("alice", "dev_alice_typing_group_sender")
	bob := testClientFor("bob", "dev_bob_typing_group_recipient")
	carol := testClientFor("carol", "dev_carol_typing_group_outsider")

	s.mu.Lock()
	s.clients[alice.DeviceID] = alice.Client
	s.clients[bob.DeviceID] = bob.Client
	s.clients[carol.DeviceID] = carol.Client
	s.mu.Unlock()

	raw, _ := json.Marshal(protocol.Typing{Type: "typing", Group: "group_typing_relay"})
	s.handleTyping(alice.Client, raw)

	if msgs := alice.messages(); len(msgs) != 0 {
		t.Fatalf("sender current device received %d typing messages, want 0", len(msgs))
	}
	assertOneTypingMsg(t, bob, "alice", "", "group_typing_relay", "")
	if msgs := carol.messages(); len(msgs) != 0 {
		t.Fatalf("non-member received %d typing messages, want 0", len(msgs))
	}
	assertTypingTimerCount(t, s, 1)
}

func TestHandleTyping_DMParty_RelaysOnlyToOtherPartySessions(t *testing.T) {
	s := newTestServer(t)
	t.Cleanup(func() { stopTypingTimers(s) })
	dm, err := s.store.CreateOrGetDirectMessage(store.GenerateID("dm_"), "alice", "bob")
	if err != nil {
		t.Fatalf("create dm: %v", err)
	}
	alice := testClientFor("alice", "dev_alice_typing_dm_sender")
	bob := testClientFor("bob", "dev_bob_typing_dm_recipient")
	carol := testClientFor("carol", "dev_carol_typing_dm_outsider")

	s.mu.Lock()
	s.clients[alice.DeviceID] = alice.Client
	s.clients[bob.DeviceID] = bob.Client
	s.clients[carol.DeviceID] = carol.Client
	s.mu.Unlock()

	raw, _ := json.Marshal(protocol.Typing{Type: "typing", DM: dm.ID})
	s.handleTyping(alice.Client, raw)

	if msgs := alice.messages(); len(msgs) != 0 {
		t.Fatalf("sender current device received %d typing messages, want 0", len(msgs))
	}
	assertOneTypingMsg(t, bob, "alice", "", "", dm.ID)
	if msgs := carol.messages(); len(msgs) != 0 {
		t.Fatalf("non-party received %d typing messages, want 0", len(msgs))
	}
	assertTypingTimerCount(t, s, 1)
}
