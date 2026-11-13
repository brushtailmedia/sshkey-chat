package server

// Who the server asks to rotate a room on three of its request paths: the
// first member of an empty room (asked at once when connected, or when they
// connect), and the sender of the message that reaches the message limit.
// Each must keep working when the rules for who may answer and who is asked
// change.

import (
	"encoding/json"
	"testing"

	"github.com/brushtailmedia/sshkey-chat/internal/protocol"
	"github.com/brushtailmedia/sshkey-chat/internal/testutil"
)

// emptyRoom returns a seeded room after removing its only member, so that it
// has no member and no key.
func emptyRoom(t *testing.T, s *Server) string {
	t.Helper()
	room := s.store.RoomDisplayNameToID("engineering")
	for _, m := range s.store.GetRoomMemberIDsByRoomID(room) {
		if err := s.store.RemoveRoomMember(room, m); err != nil {
			t.Fatal(err)
		}
	}
	if n := len(s.store.GetRoomMemberIDsByRoomID(room)); n != 0 {
		t.Fatalf("room still has %d member(s)", n)
	}
	if e, _ := s.store.GetCurrentEpoch(room); e != 0 {
		t.Fatalf("room already has epoch %d", e)
	}
	return room
}

// firstKeyRequest finds the rotation request for room among frames.
func firstKeyRequest(t *testing.T, frames []json.RawMessage, room string) protocol.EpochTrigger {
	t.Helper()
	for _, f := range frames {
		var tr protocol.EpochTrigger
		if json.Unmarshal(f, &tr) == nil && tr.Type == "epoch_trigger" && tr.Room == room {
			return tr
		}
	}
	t.Fatalf("no epoch_trigger for the room among %s", frames)
	return protocol.EpochTrigger{}
}

func answerAndExpectFirstKey(t *testing.T, s *Server, c *captureClient, tr protocol.EpochTrigger) {
	t.Helper()
	if tr.NewEpoch != 1 || len(tr.Members) != 1 || tr.Members[0].User != c.UserID {
		t.Fatalf("request = epoch %d, members %+v; want epoch 1 with the new member alone", tr.NewEpoch, tr.Members)
	}
	c.buf.Reset()
	wk := map[string]string{c.UserID: testutil.WrappedKey(c.UserID)}
	raw, _ := json.Marshal(protocol.EpochRotate{Type: "epoch_rotate", Room: tr.Room, Epoch: 1, WrappedKeys: wk, MemberHash: "SHA256:deadbeef", MemberSig: "c2lnbmF0dXJl"})
	s.handleMessage(c.Client, "epoch_rotate", raw)
	if n := countEnvelopeType(t, c.messages(), "epoch_confirmed"); n != 1 {
		t.Fatalf("the first member's answer got %s, want epoch_confirmed", c.buf.String())
	}
	if e, err := s.store.GetCurrentEpoch(tr.Room); err != nil || e != 1 {
		t.Fatalf("stored epoch = %d (err %v), want 1", e, err)
	}
	if got, err := s.store.GetEpochKey(tr.Room, 1, c.UserID); err != nil || got != wk[c.UserID] {
		t.Fatalf("the first member's key was not stored (err %v)", err)
	}
}

// Connected when the server processes the add: asked at once.
func TestProcessPendingAddToRoom_FirstMemberOfAnEmptyRoomRotates(t *testing.T) {
	s := newTestServer(t)
	room := emptyRoom(t, s)
	bob := testClientFor(testutil.UserID("bob"), "dev_bob_first_member")
	s.mu.Lock()
	s.clients[bob.DeviceID] = bob.Client
	s.mu.Unlock()

	// What sshkey-ctl add-to-room writes: the membership, then the queue row.
	if err := s.store.AddRoomMember(room, bob.UserID, 0); err != nil {
		t.Fatal(err)
	}
	if err := s.store.RecordPendingAddToRoom(bob.UserID, room, "os:1000"); err != nil {
		t.Fatal(err)
	}
	s.processPendingAddToRoom()

	if n := countEnvelopeType(t, bob.messages(), "room_added_to"); n != 1 {
		t.Errorf("room_added_to frames = %d, want 1", n)
	}
	answerAndExpectFirstKey(t, s, bob, firstKeyRequest(t, bob.messages(), room))
}

// Not connected when added: asked when they connect.
func TestTriggerPostConnectRoomRotations_FirstMemberOfARoomGetsItsFirstKey(t *testing.T) {
	s := newTestServer(t)
	room := emptyRoom(t, s)
	if err := s.store.AddRoomMember(room, testutil.UserID("bob"), 0); err != nil {
		t.Fatal(err)
	}
	if err := s.store.RecordPendingAddToRoom(testutil.UserID("bob"), room, "os:1000"); err != nil {
		t.Fatal(err)
	}
	s.processPendingAddToRoom() // nobody is connected: nothing is asked

	bob := testClientFor(testutil.UserID("bob"), "dev_bob_first_member_later")
	s.triggerPostConnectRoomRotations(bob.Client)
	answerAndExpectFirstKey(t, s, bob, firstKeyRequest(t, bob.messages(), room))
}

func TestHandleSend_MessageCountAsksTheSenderToRotate(t *testing.T) {
	s := newTestServer(t)
	room := s.store.RoomDisplayNameToID("general")
	alice := testClientFor(testutil.UserID("alice"), "dev_alice_count_rotate")
	s.epochs.getOrCreate(room, 1)
	s.epochs.mu.Lock()
	s.epochs.maxMessages = 2
	s.epochs.mu.Unlock()

	for i := 0; i < 2; i++ {
		if n := countEnvelopeType(t, alice.messages(), "epoch_trigger"); n != 0 {
			t.Fatalf("asked to rotate after %d message(s), want only at the limit", i)
		}
		raw, _ := json.Marshal(protocol.Send{Type: "send", Room: room, Epoch: 1, Payload: "aGk=", Signature: "c2ln"})
		s.handleMessage(alice.Client, "send", raw)
	}

	var trigger protocol.EpochTrigger
	for _, f := range alice.messages() {
		var candidate protocol.EpochTrigger
		if json.Unmarshal(f, &candidate) == nil && candidate.Type == "epoch_trigger" {
			trigger = candidate
		}
	}
	if trigger.Room != room || trigger.NewEpoch != 2 || len(trigger.Members) != len(s.store.GetRoomMemberIDsByRoomID(room)) {
		t.Fatalf("at the message limit the sender got %s, want an epoch_trigger for epoch 2 with every member", alice.buf.String())
	}
}
