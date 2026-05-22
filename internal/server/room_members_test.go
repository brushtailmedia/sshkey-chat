package server

// Tests for handleRoomMembers. The privacy-regression test locks in
// the Phase 14 byte-identical invariant: unknown-room and non-member
// probes must return identical wire bytes so a probing client cannot
// use room_members to enumerate room existence.
//
// Phase 21 F1 closure (2026-04-19): previously handleRoomMembers
// returned ErrNotAuthorized for the non-member path while the
// malformed/unknown-room path returned ErrUnknownRoom, leaking
// existence information. This test drift-guards the fix.

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/brushtailmedia/sshkey-chat/internal/protocol"
)

// TestHandleRoomMembers_PrivacyResponsesIdentical verifies that
// unknown-room and non-member probes produce byte-identical wire
// frames. Any divergence defeats the Phase 14 privacy invariant.
func TestHandleRoomMembers_PrivacyResponsesIdentical(t *testing.T) {
	s := newTestServer(t)
	generalID := s.store.RoomDisplayNameToID("general")
	if generalID == "" {
		t.Fatal("seed failed")
	}

	// Case 1: unknown room (room ID does not exist in rooms.db).
	probe1 := testClientFor("bob", "dev_bob_1")
	raw1, _ := json.Marshal(protocol.RoomMembers{
		Type: "room_members",
		Room: "room_does_not_exist",
	})
	s.handleRoomMembers(probe1.Client, raw1)

	// Case 2: room exists, probing client is not a member.
	// dave is not seeded as a member of general; bob and carol are.
	probe2 := testClientFor("dave", "dev_dave_1")
	raw2, _ := json.Marshal(protocol.RoomMembers{
		Type: "room_members",
		Room: generalID,
	})
	s.handleRoomMembers(probe2.Client, raw2)

	responses := [][]json.RawMessage{
		probe1.messages(),
		probe2.messages(),
	}
	for i, msgs := range responses {
		if len(msgs) != 1 {
			t.Fatalf("case %d: expected 1 reply, got %d (%q)",
				i+1, len(msgs), msgs)
		}
	}

	baseline := responses[0][0]
	for i := 1; i < len(responses); i++ {
		if !bytes.Equal(baseline, responses[i][0]) {
			t.Errorf("privacy leak: case %d response differs from case 1\n  case 1: %s\n  case %d: %s",
				i+1, baseline, i+1, responses[i][0])
		}
	}
}

// TestSendRoomList_EmitsFullMemberIDsStableOrder locks the V8 room_list
// contract: room_list carries full member user IDs, not just a count, and
// repeated handshakes over the same DB state produce byte-stable output.
func TestSendRoomList_EmitsFullMemberIDsStableOrder(t *testing.T) {
	s := newTestServer(t)
	generalID := s.store.RoomDisplayNameToID("general")
	if generalID == "" {
		t.Fatal("seed failed")
	}

	first := testClientFor("bob", "dev_bob_room_list_1")
	s.sendRoomList(first.Client)
	firstMsgs := first.messages()
	if len(firstMsgs) != 1 {
		t.Fatalf("first sendRoomList: expected 1 message, got %d", len(firstMsgs))
	}

	var list protocol.RoomList
	if err := json.Unmarshal(firstMsgs[0], &list); err != nil {
		t.Fatalf("unmarshal room_list: %v", err)
	}
	if list.Type != "room_list" {
		t.Fatalf("Type = %q, want room_list", list.Type)
	}
	if len(list.Rooms) != 1 {
		t.Fatalf("bob should receive exactly general, got %d rooms: %+v", len(list.Rooms), list.Rooms)
	}
	room := list.Rooms[0]
	if room.ID != generalID {
		t.Fatalf("room ID = %q, want %q", room.ID, generalID)
	}
	wantMembers := []string{"alice", "bob", "carol"}
	if !reflect.DeepEqual(room.Members, wantMembers) {
		t.Fatalf("room_list members = %v, want %v", room.Members, wantMembers)
	}

	second := testClientFor("bob", "dev_bob_room_list_2")
	s.sendRoomList(second.Client)
	secondMsgs := second.messages()
	if len(secondMsgs) != 1 {
		t.Fatalf("second sendRoomList: expected 1 message, got %d", len(secondMsgs))
	}
	if !bytes.Equal(firstMsgs[0], secondMsgs[0]) {
		t.Fatalf("room_list output is not byte-stable\nfirst:  %s\nsecond: %s", firstMsgs[0], secondMsgs[0])
	}
}

// TestHandleRoomMembers_MemberHappyPath verifies the happy-path
// response shape for a legitimate member — regression guard so the
// privacy fix doesn't accidentally break the normal flow.
func TestHandleRoomMembers_MemberHappyPath(t *testing.T) {
	s := newTestServer(t)
	generalID := s.store.RoomDisplayNameToID("general")
	if generalID == "" {
		t.Fatal("seed failed")
	}

	// Valid corrID: "corr_" + 21 nanoid chars (see protocol/corrid.go).
	const validCorrID = "corr_abcdefghijklmnopqrstu"

	probe := testClientFor("bob", "dev_bob_member")
	raw, _ := json.Marshal(protocol.RoomMembers{
		Type:   "room_members",
		Room:   generalID,
		CorrID: validCorrID,
	})
	s.handleRoomMembers(probe.Client, raw)

	msgs := probe.messages()
	if len(msgs) != 1 {
		t.Fatalf("expected 1 reply, got %d", len(msgs))
	}

	var resp protocol.RoomMembersList
	if err := json.Unmarshal(msgs[0], &resp); err != nil {
		t.Fatalf("unmarshal reply: %v", err)
	}
	if resp.Type != "room_members_list" {
		t.Errorf("Type = %q, want %q", resp.Type, "room_members_list")
	}
	if resp.Room != generalID {
		t.Errorf("Room = %q, want %q", resp.Room, generalID)
	}
	if resp.CorrID != validCorrID {
		t.Errorf("CorrID = %q, want %q (echoed)", resp.CorrID, validCorrID)
	}
	if len(resp.Members) == 0 {
		t.Error("Members empty; expected at least bob + carol")
	}
}
