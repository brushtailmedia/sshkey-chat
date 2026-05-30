package server

import (
	"encoding/json"
	"testing"

	"github.com/brushtailmedia/sshkey-chat/internal/counters"
	"github.com/brushtailmedia/sshkey-chat/internal/protocol"
	"github.com/brushtailmedia/sshkey-chat/internal/store"
)

// Read receipts are membership-gated, mirroring handleTyping (audit S5). A
// non-member must neither write a read_positions row for a context it doesn't
// belong to nor have a `read` receipt fanned out to that context's real
// members. Unlike typing there is NO retired-room rejection — reading (hence
// marking read) is valid in a read-only retired room.

func assertOneReadMsg(t *testing.T, cc *captureClient, wantUser, wantRoom, wantGroup, wantDM, wantLastRead string) {
	t.Helper()
	msgs := cc.messages()
	if len(msgs) != 1 {
		t.Fatalf("%s received %d messages, want 1", cc.DeviceID, len(msgs))
	}
	var got protocol.Read
	if err := json.Unmarshal(msgs[0], &got); err != nil {
		t.Fatalf("parse read message for %s: %v", cc.DeviceID, err)
	}
	if got.Type != "read" || got.User != wantUser || got.Room != wantRoom ||
		got.Group != wantGroup || got.DM != wantDM || got.LastRead != wantLastRead {
		t.Fatalf("read message for %s = %+v, want user=%q room=%q group=%q dm=%q lastRead=%q",
			cc.DeviceID, got, wantUser, wantRoom, wantGroup, wantDM, wantLastRead)
	}
}

func TestHandleRead_NonMemberRoom_SilentDropSignal(t *testing.T) {
	s := newTestServer(t)
	engID := s.store.RoomDisplayNameToID("engineering")
	bob := testClientFor("bob", "dev_bob_read_nm_room") // bob is NOT in engineering
	raw, _ := json.Marshal(protocol.Read{Type: "read", Room: engID, LastRead: "msg_x"})
	s.handleRead(bob.Client, raw)

	if got := s.counters.Get(counters.SignalNonMemberContext, "dev_bob_read_nm_room"); got != 1 {
		t.Errorf("SignalNonMemberContext = %d, want 1", got)
	}
	if msgs := bob.messages(); len(msgs) != 0 {
		t.Errorf("non-member read must be silent-dropped, got %d wire msg(s)", len(msgs))
	}
	// Storage pollution prevented: no read_positions row written.
	if pos, _ := s.store.GetReadPosition("bob", "dev_bob_read_nm_room", engID, "", ""); pos != "" {
		t.Errorf("non-member read must not write a read position, got %q", pos)
	}
}

func TestHandleRead_NonMemberGroup_SilentDropSignal(t *testing.T) {
	s := newTestServer(t)
	if err := s.store.CreateGroup("group_read_nm", "alice", []string{"alice"}, "Test"); err != nil {
		t.Fatalf("create group: %v", err)
	}
	carol := testClientFor("carol", "dev_carol_read_nm_grp") // not in group_read_nm
	raw, _ := json.Marshal(protocol.Read{Type: "read", Group: "group_read_nm", LastRead: "msg_x"})
	s.handleRead(carol.Client, raw)

	if got := s.counters.Get(counters.SignalNonMemberContext, "dev_carol_read_nm_grp"); got != 1 {
		t.Errorf("SignalNonMemberContext = %d, want 1", got)
	}
	if msgs := carol.messages(); len(msgs) != 0 {
		t.Errorf("non-member group read must be silent-dropped, got %d wire msg(s)", len(msgs))
	}
}

func TestHandleRead_NonPartyDM_SilentDropSignal(t *testing.T) {
	s := newTestServer(t)
	dm, err := s.store.CreateOrGetDirectMessage(store.GenerateID("dm_"), "alice", "bob")
	if err != nil {
		t.Fatalf("create dm: %v", err)
	}
	carol := testClientFor("carol", "dev_carol_read_nm_dm") // not a party to the DM
	raw, _ := json.Marshal(protocol.Read{Type: "read", DM: dm.ID, LastRead: "msg_x"})
	s.handleRead(carol.Client, raw)

	if got := s.counters.Get(counters.SignalNonMemberContext, "dev_carol_read_nm_dm"); got != 1 {
		t.Errorf("SignalNonMemberContext = %d, want 1", got)
	}
	if msgs := carol.messages(); len(msgs) != 0 {
		t.Errorf("non-party DM read must be silent-dropped, got %d wire msg(s)", len(msgs))
	}
}

func TestHandleRead_EmptyAndAmbiguousContext_MalformedSignal(t *testing.T) {
	s := newTestServer(t)
	genID := s.store.RoomDisplayNameToID("general")

	empty := testClientFor("alice", "dev_alice_read_empty")
	raw, _ := json.Marshal(protocol.Read{Type: "read", LastRead: "msg_x"}) // no context
	s.handleRead(empty.Client, raw)
	if got := s.counters.Get(counters.SignalMalformedFrame, "dev_alice_read_empty"); got != 1 {
		t.Errorf("empty-context read: SignalMalformedFrame = %d, want 1", got)
	}

	ambig := testClientFor("alice", "dev_alice_read_ambig")
	raw2, _ := json.Marshal(protocol.Read{Type: "read", Room: genID, DM: "dm_x", LastRead: "msg_x"}) // two contexts
	s.handleRead(ambig.Client, raw2)
	if got := s.counters.Get(counters.SignalMalformedFrame, "dev_alice_read_ambig"); got != 1 {
		t.Errorf("ambiguous-context read: SignalMalformedFrame = %d, want 1", got)
	}
}

// Negative guard + positive relay: an authorized member trips no gate counter,
// the read position is persisted, and the receipt relays to the OTHER member's
// session only (not the sender's device, not a non-member).
func TestHandleRead_MemberRoom_WritesPositionAndRelaysToOtherSessionsOnly(t *testing.T) {
	s := newTestServer(t)
	genID := s.store.RoomDisplayNameToID("general")

	alice := testClientFor("alice", "dev_alice_read_sender")
	bob := testClientFor("bob", "dev_bob_read_recipient")             // member of general
	outsider := testClientFor("mallory", "dev_mallory_read_outsider") // not a member

	s.mu.Lock()
	s.clients[alice.DeviceID] = alice.Client
	s.clients[bob.DeviceID] = bob.Client
	s.clients[outsider.DeviceID] = outsider.Client
	s.mu.Unlock()

	raw, _ := json.Marshal(protocol.Read{Type: "read", Room: genID, LastRead: "msg_42"})
	s.handleRead(alice.Client, raw)

	if got := s.counters.Get(counters.SignalNonMemberContext, "dev_alice_read_sender"); got != 0 {
		t.Errorf("authorized member read must NOT fire SignalNonMemberContext, got %d", got)
	}
	if got := s.counters.Get(counters.SignalMalformedFrame, "dev_alice_read_sender"); got != 0 {
		t.Errorf("authorized member read must NOT fire SignalMalformedFrame, got %d", got)
	}
	if pos, _ := s.store.GetReadPosition("alice", "dev_alice_read_sender", genID, "", ""); pos != "msg_42" {
		t.Errorf("read position = %q, want msg_42", pos)
	}
	if msgs := alice.messages(); len(msgs) != 0 {
		t.Fatalf("sender device received %d read messages, want 0", len(msgs))
	}
	assertOneReadMsg(t, bob, "alice", genID, "", "", "msg_42")
	if msgs := outsider.messages(); len(msgs) != 0 {
		t.Fatalf("non-member received %d read messages, want 0", len(msgs))
	}
}

// Deliberate divergence from typing: a member may mark a RETIRED (read-only)
// room as read — reading stays allowed there, so there is no retired-room
// rejection on the read path (contrast TestHandleTyping_RetiredRoomMember).
func TestHandleRead_RetiredRoomMember_Allowed(t *testing.T) {
	s := newTestServer(t)
	genID := s.store.RoomDisplayNameToID("general")
	if err := s.store.SetRoomRetired(genID, "alice", "test"); err != nil {
		t.Fatalf("retire room: %v", err)
	}
	alice := testClientFor("alice", "dev_alice_read_retired") // member, room retired
	raw, _ := json.Marshal(protocol.Read{Type: "read", Room: genID, LastRead: "msg_99"})
	s.handleRead(alice.Client, raw)

	if got := s.counters.Get(counters.SignalNonMemberContext, "dev_alice_read_retired"); got != 0 {
		t.Errorf("member read in a retired room must be allowed (no drop), got SignalNonMemberContext=%d", got)
	}
	if pos, _ := s.store.GetReadPosition("alice", "dev_alice_read_retired", genID, "", ""); pos != "msg_99" {
		t.Errorf("read position in retired room = %q, want msg_99 (reading still allowed)", pos)
	}
}
