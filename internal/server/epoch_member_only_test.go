package server

// Who may answer a room's pending rotation, and who the server asks.
//
// Only a current member of the room may answer; any current member may,
// whoever was asked. Someone outside the room gets the same bytes whatever
// the room's state, is never sent the member list, and is counted as
// non_member_context. The server never sends a rotation request to a client
// that is not a current member.

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/brushtailmedia/sshkey-chat/internal/counters"
	"github.com/brushtailmedia/sshkey-chat/internal/protocol"
	"github.com/brushtailmedia/sshkey-chat/internal/store"
	"github.com/brushtailmedia/sshkey-chat/internal/testutil"
)

// askToRotate sends a real rotation request for room to c and returns the
// epoch it asks for. c's captured frames are cleared afterwards.
func askToRotate(t *testing.T, s *Server, room string, c *captureClient) int64 {
	t.Helper()
	s.epochs.getOrCreate(room, 0)
	s.triggerEpochRotation(c.Client, room, "message_count")
	var trigger protocol.EpochTrigger
	for _, f := range c.messages() {
		if json.Unmarshal(f, &trigger) == nil && trigger.Type == "epoch_trigger" && trigger.Room == room {
			c.buf.Reset()
			return trigger.NewEpoch
		}
	}
	t.Fatalf("no epoch_trigger for %s was sent: %s", room, c.buf.String())
	return 0
}

// rotationAnswer builds an epoch_rotate with one real-size key per user.
func rotationAnswer(room string, epoch int64, users []string) json.RawMessage {
	wk := make(map[string]string, len(users))
	for _, u := range users {
		wk[u] = testutil.WrappedKey(u)
	}
	raw, _ := json.Marshal(protocol.EpochRotate{
		Type: "epoch_rotate", Room: room, Epoch: epoch, WrappedKeys: wk,
		MemberHash: "SHA256:deadbeef", MemberSig: "c2lnbmF0dXJl",
	})
	return raw
}

// epochConflictFrame is the reply a rotation gets when nothing is pending,
// as the production encoder writes it.
func epochConflictFrame(t *testing.T) []byte {
	t.Helper()
	var wire bytes.Buffer
	if err := protocol.NewEncoder(&wire).Encode(protocol.Error{Type: "error", Code: protocol.ErrEpochConflict, Message: "Conflict detected — please try again"}); err != nil {
		t.Fatal(err)
	}
	return wire.Bytes()
}

func TestHandleEpochRotate_NonMemberAnswerRefused(t *testing.T) {
	s := newTestServer(t)
	room := s.store.RoomDisplayNameToID("engineering") // alice is its only member
	members := s.store.GetRoomMemberIDsByRoomID(room)
	alice := testClientFor(testutil.UserID("alice"), "dev_alice_rot_member")
	bob := testClientFor(testutil.UserID("bob"), "dev_bob_rot_outsider")
	if s.store.IsRoomMemberByID(room, bob.UserID) {
		t.Fatal("bob must not be a member of engineering for this case")
	}
	epoch := askToRotate(t, s, room, alice)

	// Through the dispatch, as a frame from the wire arrives.
	s.handleMessage(bob.Client, "epoch_rotate", rotationAnswer(room, epoch, members))

	if !bytes.Equal(bob.buf.Bytes(), epochConflictFrame(t)) {
		t.Errorf("non-member's answer got %s, want only the nothing-pending conflict", bob.buf.String())
	}
	if got, err := s.store.GetCurrentEpoch(room); err != nil || got != 0 {
		t.Errorf("stored current epoch = %d (err %v), want 0: a non-member's keys must not be stored", got, err)
	}
	if got := s.counters.Get(counters.SignalNonMemberContext, bob.DeviceID); got != 1 {
		t.Errorf("SignalNonMemberContext = %d, want 1", got)
	}

	// Control: the rotation is still pending and the member's answer is taken.
	s.handleMessage(alice.Client, "epoch_rotate", rotationAnswer(room, epoch, members))
	if n := countEnvelopeType(t, alice.messages(), "epoch_confirmed"); n != 1 {
		t.Errorf("member's answer after the refused one: frames %s, want one epoch_confirmed", alice.buf.String())
	}
	if gen, _, _, err := s.store.GetEpochAttestation(room, epoch); err != nil || gen != alice.UserID {
		t.Errorf("stored generator = %q (err %v), want alice", gen, err)
	}
	if got := s.counters.Get(counters.SignalNonMemberContext, alice.DeviceID); got != 0 {
		t.Errorf("SignalNonMemberContext for the member = %d, want 0", got)
	}
}

func TestHandleEpochRotate_NonMemberWrongAnswerGetsNoMemberList(t *testing.T) {
	s := newTestServer(t)
	room := s.store.RoomDisplayNameToID("engineering")
	members := s.store.GetRoomMemberIDsByRoomID(room)
	alice := testClientFor(testutil.UserID("alice"), "dev_alice_rot_member2")
	bob := testClientFor(testutil.UserID("bob"), "dev_bob_rot_outsider2")
	epoch := askToRotate(t, s, room, alice)

	s.handleMessage(bob.Client, "epoch_rotate", rotationAnswer(room, epoch, nil)) // no keys at all

	if !bytes.Equal(bob.buf.Bytes(), epochConflictFrame(t)) {
		t.Errorf("non-member's wrong answer got %s, want only the nothing-pending conflict", bob.buf.String())
	}
	if n := countEnvelopeType(t, bob.messages(), "epoch_trigger"); n != 0 {
		t.Errorf("non-member was sent %d epoch_trigger frame(s) carrying the member list", n)
	}
	// Control: the member's request was not cancelled.
	s.handleMessage(alice.Client, "epoch_rotate", rotationAnswer(room, epoch, members))
	if n := countEnvelopeType(t, alice.messages(), "epoch_confirmed"); n != 1 {
		t.Errorf("member's answer after the refused one: frames %s, want one epoch_confirmed", alice.buf.String())
	}
}

func TestHandleEpochRotate_MemberRemovedBeforeAnsweringIsNotAskedAgain(t *testing.T) {
	s := newTestServer(t)
	room := s.store.RoomDisplayNameToID("general") // alice, bob, carol
	before := s.store.GetRoomMemberIDsByRoomID(room)
	alice := testClientFor(testutil.UserID("alice"), "dev_alice_rot_removed")
	bob := testClientFor(testutil.UserID("bob"), "dev_bob_rot_remaining")
	epoch := askToRotate(t, s, room, alice)

	if err := s.store.RemoveRoomMember(room, alice.UserID); err != nil {
		t.Fatal(err)
	}
	s.handleMessage(alice.Client, "epoch_rotate", rotationAnswer(room, epoch, before)) // the list she was given

	if !bytes.Equal(alice.buf.Bytes(), epochConflictFrame(t)) {
		t.Errorf("removed member's answer got %s, want only the nothing-pending conflict", alice.buf.String())
	}
	if n := countEnvelopeType(t, alice.messages(), "epoch_trigger"); n != 0 {
		t.Errorf("removed member was asked again (%d epoch_trigger)", n)
	}
	if got := s.counters.Get(counters.SignalNonMemberContext, alice.DeviceID); got != 1 {
		t.Errorf("SignalNonMemberContext = %d, want 1", got)
	}
	// Control: the request was neither cancelled nor re-sent; a remaining
	// member's answer for the same epoch is taken.
	s.handleMessage(bob.Client, "epoch_rotate", rotationAnswer(room, epoch, s.store.GetRoomMemberIDsByRoomID(room)))
	if n := countEnvelopeType(t, bob.messages(), "epoch_confirmed"); n != 1 {
		t.Errorf("remaining member's answer: frames %s, want one epoch_confirmed", bob.buf.String())
	}
	if gen, _, _, err := s.store.GetEpochAttestation(room, epoch); err != nil || gen != bob.UserID {
		t.Errorf("stored generator = %q (err %v), want bob", gen, err)
	}
}

func TestHandleEpochRotate_MemberNotAskedIsAccepted(t *testing.T) {
	s := newTestServer(t)
	room := s.store.RoomDisplayNameToID("general")
	members := s.store.GetRoomMemberIDsByRoomID(room)
	alice := testClientFor(testutil.UserID("alice"), "dev_alice_rot_asked")
	bob := testClientFor(testutil.UserID("bob"), "dev_bob_rot_not_asked")
	epoch := askToRotate(t, s, room, alice)

	s.handleMessage(bob.Client, "epoch_rotate", rotationAnswer(room, epoch, members))

	if n := countEnvelopeType(t, bob.messages(), "epoch_confirmed"); n != 1 {
		t.Errorf("a member who was not asked: frames %s, want one epoch_confirmed", bob.buf.String())
	}
	if gen, _, _, err := s.store.GetEpochAttestation(room, epoch); err != nil || gen != bob.UserID {
		t.Errorf("stored generator = %q (err %v), want bob", gen, err)
	}
	if got := s.counters.Get(counters.SignalNonMemberContext, bob.DeviceID); got != 0 {
		t.Errorf("SignalNonMemberContext = %d, want 0", got)
	}
}

// A non-member must get the same bytes whatever the room's state, and the
// same bytes a member gets when nothing is pending.
func TestHandleEpochRotate_PrivacyResponsesIdentical(t *testing.T) {
	want := epochConflictFrame(t)
	cases := []struct {
		name       string
		member     bool // the sender is a member of the room
		pending    bool // a rotation is pending for it
		unknown    bool // the room does not exist
		wantSignal int64
	}{
		{"non-member, rotation pending", false, true, false, 1},
		{"non-member, nothing pending", false, false, false, 1},
		{"room does not exist", false, false, true, 1},
		{"member, nothing pending", true, false, false, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestServer(t)
			room := s.store.RoomDisplayNameToID("engineering")
			members := s.store.GetRoomMemberIDsByRoomID(room)
			alice := testClientFor(testutil.UserID("alice"), "dev_alice_rot_privacy")
			bob := testClientFor(testutil.UserID("bob"), "dev_bob_rot_privacy")
			epoch := int64(1)
			if tc.pending {
				epoch = askToRotate(t, s, room, alice)
			}
			sender := bob
			if tc.member {
				sender = alice
			}
			if tc.unknown {
				room = store.GenerateID("room_")
			}
			s.handleMessage(sender.Client, "epoch_rotate", rotationAnswer(room, epoch, members))
			if !bytes.Equal(sender.buf.Bytes(), want) {
				t.Errorf("reply = %s\n want %s", sender.buf.Bytes(), want)
			}
			if got := s.counters.Get(counters.SignalNonMemberContext, sender.DeviceID); got != tc.wantSignal {
				t.Errorf("SignalNonMemberContext = %d, want %d", got, tc.wantSignal)
			}
		})
	}
}

func TestTriggerEpochRotation_NeverAsksANonMember(t *testing.T) {
	s := newTestServer(t)
	room := s.store.RoomDisplayNameToID("engineering")
	alice := testClientFor(testutil.UserID("alice"), "dev_alice_rot_ask")
	bob := testClientFor(testutil.UserID("bob"), "dev_bob_rot_ask")
	s.epochs.getOrCreate(room, 0)

	s.triggerEpochRotation(bob.Client, room, "member_join")

	if len(bob.messages()) != 0 {
		t.Errorf("a non-member was sent %s", bob.buf.String())
	}
	s.epochs.mu.Lock()
	pending := s.epochs.rooms[room].pendingRotation
	s.epochs.mu.Unlock()
	if pending {
		t.Error("a request to a non-member left a rotation pending")
	}
	// Control: the same call for a member sends the request.
	if epoch := askToRotate(t, s, room, alice); epoch != 1 {
		t.Errorf("member was asked for epoch %d, want 1", epoch)
	}
}
