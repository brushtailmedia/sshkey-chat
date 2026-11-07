package server

// Room typing policy — the server relays typing in a room only while the
// room has [rooms] typing_max_members members or fewer (default 100), and
// drops it silently above that: no relay, no expiry timer, an observational
// counter (never an auto-revoke input). Groups and 1:1 DMs are not gated by
// the knob. The decision is made from the member list the broadcast already
// fetches, so the policy costs no query of its own.

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/brushtailmedia/sshkey-chat/internal/counters"
	"github.com/brushtailmedia/sshkey-chat/internal/protocol"
	"github.com/brushtailmedia/sshkey-chat/internal/store"
)

// syntheticUserID returns the i-th user ID of production shape ("usr_" +
// 21 characters) under prefix, for filling a room or group past a
// threshold. Membership tables carry no foreign key to users, so no user
// rows are needed.
func syntheticUserID(prefix string, i int) string {
	return fmt.Sprintf("usr_%s%0*d", prefix, 21-len(prefix), i)
}

func syntheticUserIDs(prefix string, n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = syntheticUserID(prefix, i)
	}
	return out
}

// fillRoom adds synthetic members to roomID until it has want members.
// Repeated calls keep growing the same room: the IDs continue from the
// current size.
func fillRoom(t *testing.T, s *Server, roomID string, want int) {
	t.Helper()
	have := len(s.store.GetRoomMemberIDsByRoomID(roomID))
	if have > want {
		t.Fatalf("room %s already has %d members, cannot shrink to %d", roomID, have, want)
	}
	for i := have; i < want; i++ {
		if err := s.store.AddRoomMember(roomID, syntheticUserID("fill", i), 0); err != nil {
			t.Fatalf("add synthetic member: %v", err)
		}
	}
	if got := len(s.store.GetRoomMemberIDsByRoomID(roomID)); got != want {
		t.Fatalf("room %s has %d members after fill, want %d", roomID, got, want)
	}
}

func setRoomTypingMax(s *Server, n int) {
	s.cfg.Lock()
	s.cfg.Server.Rooms.TypingMaxMembers = n
	s.cfg.Unlock()
}

// connect registers the capture clients as live sessions.
func connect(s *Server, clients ...*captureClient) {
	s.mu.Lock()
	for _, cc := range clients {
		s.clients[cc.DeviceID] = cc.Client
	}
	s.mu.Unlock()
}

func TestRoomTypingEnabled_Rule(t *testing.T) {
	s := newTestServer(t)
	setRoomTypingMax(s, 100)
	for n, want := range map[int]bool{0: true, 1: true, 99: true, 100: true, 101: false, 1000: false} {
		if got := s.roomTypingEnabled(n); got != want {
			t.Errorf("roomTypingEnabled(%d) with limit 100 = %v, want %v", n, got, want)
		}
	}
	setRoomTypingMax(s, 0)
	for _, n := range []int{0, 1, 2, 100} {
		if s.roomTypingEnabled(n) {
			t.Errorf("roomTypingEnabled(%d) with limit 0 = true, want false (typing off)", n)
		}
	}
}

func TestHandleTyping_RoomOverThreshold_PolicySuppressed(t *testing.T) {
	s := newTestServer(t)
	t.Cleanup(func() { stopTypingTimers(s) })
	genID := s.store.RoomDisplayNameToID("general") // alice, bob, carol
	fillRoom(t, s, genID, 101)

	alice := testClientFor("alice", "dev_alice_typing_over")
	bob := testClientFor("bob", "dev_bob_typing_over")
	connect(s, alice, bob)

	raw, _ := json.Marshal(protocol.Typing{Type: "typing", Room: genID})
	s.handleTyping(alice.Client, raw)

	if msgs := bob.messages(); len(msgs) != 0 {
		t.Fatalf("member received %d typing message(s) in a 101-member room, want 0", len(msgs))
	}
	if msgs := alice.messages(); len(msgs) != 0 {
		t.Fatalf("sender received %d frame(s), want 0 (silent drop, no error oracle)", len(msgs))
	}
	assertTypingTimerCount(t, s, 0) // never reached typing.Touch
	if got := s.counters.Get(counters.SignalTypingPolicySuppressed, alice.DeviceID); got != 1 {
		t.Errorf("SignalTypingPolicySuppressed = %d, want 1", got)
	}
	if got := s.counters.Get(counters.SignalNonMemberContext, alice.DeviceID); got != 0 {
		t.Errorf("SignalNonMemberContext = %d, want 0 (policy is not misbehavior)", got)
	}
}

func TestHandleTyping_RoomAtThreshold_Relays(t *testing.T) {
	s := newTestServer(t)
	t.Cleanup(func() { stopTypingTimers(s) })
	genID := s.store.RoomDisplayNameToID("general")
	fillRoom(t, s, genID, 100)

	alice := testClientFor("alice", "dev_alice_typing_at")
	bob := testClientFor("bob", "dev_bob_typing_at")
	connect(s, alice, bob)

	raw, _ := json.Marshal(protocol.Typing{Type: "typing", Room: genID})
	s.handleTyping(alice.Client, raw)

	assertOneTypingMsg(t, bob, "alice", genID, "", "")
	assertTypingTimerCount(t, s, 1)
	if got := s.counters.Get(counters.SignalTypingPolicySuppressed, alice.DeviceID); got != 0 {
		t.Errorf("SignalTypingPolicySuppressed = %d, want 0 at exactly the limit", got)
	}
}

func TestHandleTyping_RoomKnobZero_Suppressed(t *testing.T) {
	s := newTestServer(t)
	t.Cleanup(func() { stopTypingTimers(s) })
	setRoomTypingMax(s, 0)
	genID := s.store.RoomDisplayNameToID("general") // 3 members

	alice := testClientFor("alice", "dev_alice_typing_off")
	bob := testClientFor("bob", "dev_bob_typing_off")
	connect(s, alice, bob)

	raw, _ := json.Marshal(protocol.Typing{Type: "typing", Room: genID})
	s.handleTyping(alice.Client, raw)

	if msgs := bob.messages(); len(msgs) != 0 {
		t.Fatalf("member received %d typing message(s) with typing_max_members = 0, want 0", len(msgs))
	}
	assertTypingTimerCount(t, s, 0)
	if got := s.counters.Get(counters.SignalTypingPolicySuppressed, alice.DeviceID); got != 1 {
		t.Errorf("SignalTypingPolicySuppressed = %d, want 1", got)
	}
}

func TestHandleTyping_RoomPolicyIsHotReloadable(t *testing.T) {
	// The knob is read per frame: lowering it below the room's size stops
	// relay on the next frame, raising it restores it.
	s := newTestServer(t)
	t.Cleanup(func() { stopTypingTimers(s) })
	genID := s.store.RoomDisplayNameToID("general") // 3 members

	alice := testClientFor("alice", "dev_alice_typing_reload")
	bob := testClientFor("bob", "dev_bob_typing_reload")
	connect(s, alice, bob)
	raw, _ := json.Marshal(protocol.Typing{Type: "typing", Room: genID})

	setRoomTypingMax(s, 2)
	s.handleTyping(alice.Client, raw)
	if msgs := bob.messages(); len(msgs) != 0 {
		t.Fatalf("limit 2, 3-member room: got %d relay(s), want 0", len(msgs))
	}
	setRoomTypingMax(s, 3)
	s.handleTyping(alice.Client, raw)
	assertOneTypingMsg(t, bob, "alice", genID, "", "")
}

func TestHandleTyping_GroupAt100_Relays(t *testing.T) {
	// Groups are bounded by the group cap, not the room knob: a group at
	// the cap relays typing to its connected members.
	s := newTestServer(t)
	t.Cleanup(func() { stopTypingTimers(s) })
	members := append([]string{"alice", "bob"}, syntheticUserIDs("grp", 98)...)
	groupID := store.GenerateID("group_")
	if err := s.store.CreateGroup(groupID, "alice", members, "Big"); err != nil {
		t.Fatalf("create group: %v", err)
	}
	if got, _ := s.store.GetGroupMembers(groupID); len(got) != 100 {
		t.Fatalf("group has %d members, want 100", len(got))
	}

	alice := testClientFor("alice", "dev_alice_typing_grp100")
	bob := testClientFor("bob", "dev_bob_typing_grp100")
	connect(s, alice, bob)

	raw, _ := json.Marshal(protocol.Typing{Type: "typing", Group: groupID})
	s.handleTyping(alice.Client, raw)

	assertOneTypingMsg(t, bob, "alice", "", groupID, "")
	assertTypingTimerCount(t, s, 1)
	if got := s.counters.Get(counters.SignalTypingPolicySuppressed, alice.DeviceID); got != 0 {
		t.Errorf("SignalTypingPolicySuppressed = %d, want 0 for a group", got)
	}
}

func TestHandleTyping_KnobZero_GroupAndDMUnaffected(t *testing.T) {
	// typing_max_members = 0 turns typing off in ROOMS only.
	s := newTestServer(t)
	t.Cleanup(func() { stopTypingTimers(s) })
	setRoomTypingMax(s, 0)

	groupID := store.GenerateID("group_")
	if err := s.store.CreateGroup(groupID, "alice", []string{"alice", "bob"}, "Pair"); err != nil {
		t.Fatalf("create group: %v", err)
	}
	dm, err := s.store.CreateOrGetDirectMessage(store.GenerateID("dm_"), "alice", "bob")
	if err != nil {
		t.Fatalf("create dm: %v", err)
	}

	alice := testClientFor("alice", "dev_alice_typing_knob0")
	bob := testClientFor("bob", "dev_bob_typing_knob0")
	connect(s, alice, bob)

	raw, _ := json.Marshal(protocol.Typing{Type: "typing", Group: groupID})
	s.handleTyping(alice.Client, raw)
	assertOneTypingMsg(t, bob, "alice", "", groupID, "")

	bob.buf.Reset()
	raw, _ = json.Marshal(protocol.Typing{Type: "typing", DM: dm.ID})
	s.handleTyping(alice.Client, raw)
	assertOneTypingMsg(t, bob, "alice", "", "", dm.ID)

	assertTypingTimerCount(t, s, 2)
	if got := s.counters.Get(counters.SignalTypingPolicySuppressed, alice.DeviceID); got != 0 {
		t.Errorf("SignalTypingPolicySuppressed = %d, want 0 for group and DM typing", got)
	}
}

func TestTypingPolicySuppressed_IsObservationalNotAutoRevoke(t *testing.T) {
	for _, sig := range counters.AutoRevokeSignals {
		if sig == counters.SignalTypingPolicySuppressed {
			t.Fatal("typing_policy_suppressed must never be an auto-revoke input: a client in a large room produces it legitimately")
		}
	}
}
