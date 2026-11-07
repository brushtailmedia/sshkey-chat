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
// registerClients puts capture clients into the server's routing table.
func registerClients(s *Server, ccs ...*captureClient) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, cc := range ccs {
		s.clients[cc.DeviceID] = cc.Client
	}
}

// Store-write Part 3: a room receipt is stored, then relayed to the
// sender's OWN other devices only. Three member users, one of them on two
// devices: the receipt from alice's device A reaches alice's device B and
// nobody else — not bob (a member, who used to get it), not the outsider.
func TestHandleRead_MemberRoom_WritesPositionAndRelaysToOwnOtherDevicesOnly(t *testing.T) {
	s := newTestServer(t)
	genID := s.store.RoomDisplayNameToID("general")

	aliceA := testClientFor("alice", "dev_alice_read_a")
	aliceB := testClientFor("alice", "dev_alice_read_b")
	bob := testClientFor("bob", "dev_bob_read_member")                // member of general
	outsider := testClientFor("mallory", "dev_mallory_read_outsider") // not a member
	registerClients(s, aliceA, aliceB, bob, outsider)

	raw, _ := json.Marshal(protocol.Read{Type: "read", Room: genID, LastRead: "msg_42"})
	s.handleRead(aliceA.Client, raw)

	if got := s.counters.Get(counters.SignalNonMemberContext, "dev_alice_read_a"); got != 0 {
		t.Errorf("authorized member read must NOT fire SignalNonMemberContext, got %d", got)
	}
	if got := s.counters.Get(counters.SignalMalformedFrame, "dev_alice_read_a"); got != 0 {
		t.Errorf("authorized member read must NOT fire SignalMalformedFrame, got %d", got)
	}
	if pos, _ := s.store.GetReadPosition("alice", "dev_alice_read_a", genID, "", ""); pos != "msg_42" {
		t.Errorf("read position = %q, want msg_42", pos)
	}
	if msgs := aliceA.messages(); len(msgs) != 0 {
		t.Fatalf("sender device received %d read messages, want 0", len(msgs))
	}
	assertOneReadMsg(t, aliceB, "alice", genID, "", "", "msg_42")
	if msgs := bob.messages(); len(msgs) != 0 {
		t.Fatalf("other member received %d read messages, want 0 (Part 3: own devices only)", len(msgs))
	}
	if msgs := outsider.messages(); len(msgs) != 0 {
		t.Fatalf("non-member received %d read messages, want 0", len(msgs))
	}
}

// The group variant of the test above: same recipient set.
func TestHandleRead_MemberGroup_RelaysToOwnOtherDevicesOnly(t *testing.T) {
	s := newTestServer(t)
	const groupID = "group_read_relay"
	if err := s.store.CreateGroup(groupID, "alice", []string{"alice", "bob"}, "Read relay"); err != nil {
		t.Fatalf("create group: %v", err)
	}

	aliceA := testClientFor("alice", "dev_alice_gread_a")
	aliceB := testClientFor("alice", "dev_alice_gread_b")
	bob := testClientFor("bob", "dev_bob_gread_member")
	outsider := testClientFor("mallory", "dev_mallory_gread_outsider")
	registerClients(s, aliceA, aliceB, bob, outsider)

	raw, _ := json.Marshal(protocol.Read{Type: "read", Group: groupID, LastRead: "msg_g7"})
	s.handleRead(aliceA.Client, raw)

	if pos, _ := s.store.GetReadPosition("alice", "dev_alice_gread_a", "", groupID, ""); pos != "msg_g7" {
		t.Errorf("read position = %q, want msg_g7", pos)
	}
	if msgs := aliceA.messages(); len(msgs) != 0 {
		t.Fatalf("sender device received %d read messages, want 0", len(msgs))
	}
	assertOneReadMsg(t, aliceB, "alice", "", groupID, "", "msg_g7")
	if msgs := bob.messages(); len(msgs) != 0 {
		t.Fatalf("other group member received %d read messages, want 0 (Part 3: own devices only)", len(msgs))
	}
	if msgs := outsider.messages(); len(msgs) != 0 {
		t.Fatalf("non-member received %d read messages, want 0", len(msgs))
	}
}

// The DM branch is unchanged by Part 3: a 1:1 receipt still reaches the
// sender's other devices AND the peer's devices, and nobody else.
func TestHandleRead_DM_StillReachesThePeer(t *testing.T) {
	s := newTestServer(t)
	dm, err := s.store.CreateOrGetDirectMessage("dm_read_relay", "alice", "bob")
	if err != nil {
		t.Fatalf("create DM: %v", err)
	}

	aliceA := testClientFor("alice", "dev_alice_dread_a")
	aliceB := testClientFor("alice", "dev_alice_dread_b")
	bob := testClientFor("bob", "dev_bob_dread_peer")
	outsider := testClientFor("mallory", "dev_mallory_dread_outsider")
	registerClients(s, aliceA, aliceB, bob, outsider)

	raw, _ := json.Marshal(protocol.Read{Type: "read", DM: dm.ID, LastRead: "msg_d3"})
	s.handleRead(aliceA.Client, raw)

	if pos, _ := s.store.GetReadPosition("alice", "dev_alice_dread_a", "", "", dm.ID); pos != "msg_d3" {
		t.Errorf("read position = %q, want msg_d3", pos)
	}
	if msgs := aliceA.messages(); len(msgs) != 0 {
		t.Fatalf("sender device received %d read messages, want 0", len(msgs))
	}
	assertOneReadMsg(t, aliceB, "alice", "", "", dm.ID, "msg_d3")
	assertOneReadMsg(t, bob, "alice", "", "", dm.ID, "msg_d3")
	if msgs := outsider.messages(); len(msgs) != 0 {
		t.Fatalf("non-party received %d read messages, want 0", len(msgs))
	}
}

// A user with a single device gets no relay at all — the helper sends
// nothing rather than an empty fan-out.
func TestHandleRead_SingleDevice_NoRelay(t *testing.T) {
	s := newTestServer(t)
	genID := s.store.RoomDisplayNameToID("general")
	alice := testClientFor("alice", "dev_alice_solo")
	bob := testClientFor("bob", "dev_bob_solo_member")
	registerClients(s, alice, bob)

	raw, _ := json.Marshal(protocol.Read{Type: "read", Room: genID, LastRead: "msg_1"})
	s.handleRead(alice.Client, raw)

	if msgs := alice.messages(); len(msgs) != 0 {
		t.Fatalf("sender received %d messages, want 0", len(msgs))
	}
	if msgs := bob.messages(); len(msgs) != 0 {
		t.Fatalf("other member received %d messages, want 0", len(msgs))
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
