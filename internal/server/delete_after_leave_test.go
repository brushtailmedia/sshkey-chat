package server

// Delete-after-leave (rooms only) — see delete-after-leave-authz-v3.md.
//
// /delete is "leave-if-needed + purge": a current member's delete reuses
// performRoomLeave (covered by the happy-path tests in deleteroom_test.go),
// while an already-LEFT member may purge their retained copy without a
// second leave. A re-delete is rejected (already deleted ⇒ error + abuse
// signal), and a never-member is rejected with the same byte-identical
// ErrUnknownRoom. sendLeftRooms suppresses rooms that are also in
// deleted_rooms (delete supersedes leave on catchup).

import (
	"bytes"
	"encoding/json"
	"sync"
	"testing"

	"github.com/brushtailmedia/sshkey-chat/internal/counters"
	"github.com/brushtailmedia/sshkey-chat/internal/protocol"
)

// A previously-left member (user_left_rooms row, not a current member) can
// /delete to purge their retained copy. This is the bug fix. It is purge-only
// — no second leave broadcast, no room_left echo — and it succeeds even with
// allow_self_leave_rooms = false (default), because the policy gate is skipped
// for the already-left path (there is no leave to authorize).
func TestHandleDeleteRoom_AlreadyLeftMember_PurgesNoSecondLeave(t *testing.T) {
	s := newTestServer(t)
	// Default config: allow_self_leave_rooms = false — must NOT block this.
	// engineering has only alice (bob is NOT a current member per the seed).
	engineeringID := s.store.RoomDisplayNameToID("engineering")

	// bob has a recorded leave for engineering (left earlier / admin-removed)
	// but is not a current member.
	if _, err := s.store.RecordUserLeftRoom("bob", engineeringID, "removed", "admin"); err != nil {
		t.Fatalf("seed leave: %v", err)
	}

	bob := testClientFor("bob", "dev_bob_1")
	s.mu.Lock()
	s.clients["dev_bob_1"] = bob.Client
	s.mu.Unlock()

	raw, _ := json.Marshal(protocol.DeleteRoom{Type: "delete_room", Room: engineeringID})
	s.handleDeleteRoom(bob.Client, raw)

	// Purge-only: exactly one frame, a room_deleted (no room_left), even
	// though allow_self_leave_rooms is false — the policy gate is skipped on
	// the already-left path.
	msgs := bob.messages()
	if len(msgs) != 1 {
		t.Fatalf("already-left delete should produce exactly 1 reply (room_deleted), got %d", len(msgs))
	}
	var probe struct {
		Type string `json:"type"`
	}
	json.Unmarshal(msgs[0], &probe)
	if probe.Type != "room_deleted" {
		t.Errorf("type = %q, want room_deleted (no room_left for an already-left purge)", probe.Type)
	}
	if ids, _ := s.store.GetDeletedRoomsForUser("bob"); len(ids) != 1 || ids[0] != engineeringID {
		t.Errorf("deleted_rooms should record [%s], got %v", engineeringID, ids)
	}
	// alice (still a member) is untouched — an already-left purge changes no
	// membership.
	if !s.store.IsRoomMemberByID(engineeringID, "alice") {
		t.Error("alice should remain a member; an already-left purge changes no membership")
	}
}

// A re-delete (a deleted_rooms row already exists) is rejected with
// ErrUnknownRoom and fires the abuse counter — "can't delete twice".
func TestHandleDeleteRoom_ReDeleteRejected(t *testing.T) {
	s := newTestServer(t)
	enableActiveRoomLeave(t, s)
	generalID := s.store.RoomDisplayNameToID("general")
	raw, _ := json.Marshal(protocol.DeleteRoom{Type: "delete_room", Room: generalID})

	// First delete by device A (current member).
	deviceA := testClientFor("bob", "dev_bob_A")
	s.mu.Lock()
	s.clients["dev_bob_A"] = deviceA.Client
	s.mu.Unlock()
	s.handleDeleteRoom(deviceA.Client, raw)

	// Re-delete from a fresh device (same user) — hits the already-deleted
	// guard. Fresh, unregistered client → its buffer holds only the reject
	// (it never received device A's room_left/room_deleted fan-out).
	deviceB := testClientFor("bob", "dev_bob_B")
	s.handleDeleteRoom(deviceB.Client, raw)

	msgs := deviceB.messages()
	if len(msgs) != 1 {
		t.Fatalf("re-delete should produce exactly 1 reply (the reject), got %d", len(msgs))
	}
	var errMsg protocol.Error
	json.Unmarshal(msgs[0], &errMsg)
	if errMsg.Code != protocol.ErrUnknownRoom {
		t.Errorf("re-delete code = %q, want %q", errMsg.Code, protocol.ErrUnknownRoom)
	}
	if got := s.counters.Get(counters.SignalNonMemberContext, "dev_bob_B"); got != 1 {
		t.Errorf("re-delete should fire SignalNonMemberContext once, got %d", got)
	}
}

// Two devices racing the same /delete must produce one durable purge intent
// and one logical delete. The loser gets the same non-member-shaped reject as
// a re-delete; it must not produce a second leave/delete fan-out.
func TestHandleDeleteRoom_ConcurrentDoubleDeleteSinglePurge(t *testing.T) {
	s := newTestServer(t)
	enableActiveRoomLeave(t, s)
	generalID := s.store.RoomDisplayNameToID("general")
	raw, _ := json.Marshal(protocol.DeleteRoom{Type: "delete_room", Room: generalID})

	deviceA := testClientFor("bob", "dev_bob_concurrent_A")
	deviceB := testClientFor("bob", "dev_bob_concurrent_B")
	s.mu.Lock()
	s.clients[deviceA.DeviceID] = deviceA.Client
	s.clients[deviceB.DeviceID] = deviceB.Client
	s.mu.Unlock()

	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2)
	for _, cc := range []*captureClient{deviceA, deviceB} {
		go func(cc *captureClient) {
			defer wg.Done()
			<-start
			s.handleDeleteRoom(cc.Client, raw)
		}(cc)
	}
	close(start)
	wg.Wait()

	ids, err := s.store.GetDeletedRoomsForUser("bob")
	if err != nil {
		t.Fatalf("GetDeletedRoomsForUser: %v", err)
	}
	if len(ids) != 1 || ids[0] != generalID {
		t.Fatalf("concurrent delete should create exactly one deleted_rooms row, got %v", ids)
	}
	if s.store.IsRoomMemberByID(generalID, "bob") {
		t.Fatal("bob should be removed by the winning delete")
	}

	var leftFrames, deletedFrames, unknownRoomErrors int
	for _, raw := range append(deviceA.messages(), deviceB.messages()...) {
		var kind struct {
			Type string `json:"type"`
			Code string `json:"code,omitempty"`
		}
		if err := json.Unmarshal(raw, &kind); err != nil {
			t.Fatalf("unmarshal frame %s: %v", raw, err)
		}
		switch kind.Type {
		case "room_left":
			leftFrames++
		case "room_deleted":
			deletedFrames++
		case "error":
			if kind.Code == protocol.ErrUnknownRoom {
				unknownRoomErrors++
			}
		}
	}
	// One successful delete fan-outs room_left + room_deleted to both of
	// bob's connected devices. A second successful delete would double these.
	if leftFrames != 2 || deletedFrames != 2 {
		t.Fatalf("want one fan-out to two devices (left=2 deleted=2), got left=%d deleted=%d",
			leftFrames, deletedFrames)
	}
	if unknownRoomErrors != 1 {
		t.Fatalf("losing delete should get exactly one unknown_room-shaped reject, got %d", unknownRoomErrors)
	}
}

// If the purge intent cannot be durably recorded, current-member /delete must
// fail closed: no membership removal, no user_left_rooms history, no room_left,
// and no room_deleted. Otherwise offline devices could miss the purge catchup
// and later resurrect the room as read-only from left_rooms.
func TestHandleDeleteRoom_RecordPurgeIntentFailureFailsClosed(t *testing.T) {
	s := newTestServer(t)
	enableActiveRoomLeave(t, s)
	generalID := s.store.RoomDisplayNameToID("general")
	bob := testClientFor("bob", "dev_bob_record_fail")

	dropDataTable(t, s, "deleted_rooms")

	raw, _ := json.Marshal(protocol.DeleteRoom{Type: "delete_room", Room: generalID})
	s.handleDeleteRoom(bob.Client, raw)

	msgs := bob.messages()
	if len(msgs) != 1 {
		t.Fatalf("record failure should produce exactly 1 error reply, got %d", len(msgs))
	}
	var got protocol.Error
	if err := json.Unmarshal(msgs[0], &got); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if got.Code != protocol.CodeInternal {
		t.Fatalf("code = %q, want %q", got.Code, protocol.CodeInternal)
	}
	if !s.store.IsRoomMemberByID(generalID, "bob") {
		t.Error("bob should remain a member when purge intent recording fails")
	}
	if left, err := s.store.HasUserLeftRoom("bob", generalID); err != nil || left {
		t.Errorf("delete should not write user_left_rooms on purge-record failure, got left=%v err=%v", left, err)
	}
}

// delete → re-add → delete again must SUCCEED. This locks the step-4
// dependency on the prerequisite: the re-add path clears deleted_rooms, so a
// rejoined member carries no stale row and the atomic guard inserts fresh
// rather than wrongly rejecting their legitimate new delete.
func TestHandleDeleteRoom_DeleteReAddDeleteAgain(t *testing.T) {
	s := newTestServer(t)
	enableActiveRoomLeave(t, s)
	generalID := s.store.RoomDisplayNameToID("general")

	bob := testClientFor("bob", "dev_bob_1")
	s.mu.Lock()
	s.clients["dev_bob_1"] = bob.Client
	s.mu.Unlock()
	raw, _ := json.Marshal(protocol.DeleteRoom{Type: "delete_room", Room: generalID})

	// First delete.
	s.handleDeleteRoom(bob.Client, raw)
	_ = bob.messages()

	// Simulate the operator re-add path, which clears BOTH sidecars
	// (DeleteUserLeftRoomRows + ClearRoomDeletion — stale-deleted-room-readd-fix).
	if _, err := s.store.AddRoomMemberIfMissing(generalID, "bob", 0); err != nil {
		t.Fatalf("re-add: %v", err)
	}
	if err := s.store.DeleteUserLeftRoomRows("bob", generalID); err != nil {
		t.Fatalf("clear left history: %v", err)
	}
	if err := s.store.ClearRoomDeletion("bob", generalID); err != nil {
		t.Fatalf("clear deletion: %v", err)
	}

	// Delete again — must not be rejected by the already-deleted guard.
	s.handleDeleteRoom(bob.Client, raw)

	if s.store.IsRoomMemberByID(generalID, "bob") {
		t.Error("second delete (after re-add) should remove bob again — must not be rejected")
	}
	var sawDeleted bool
	for _, m := range bob.messages() {
		var probe struct {
			Type string `json:"type"`
		}
		json.Unmarshal(m, &probe)
		if probe.Type == "room_deleted" {
			sawDeleted = true
		}
	}
	if !sawDeleted {
		t.Error("second delete (after re-add) should echo room_deleted, not be rejected")
	}
}

// A never-member /delete is rejected with ErrUnknownRoom, fires
// SignalNonMemberContext, and records no deleted_rooms row.
func TestHandleDeleteRoom_NeverMemberFiresSignal(t *testing.T) {
	s := newTestServer(t)
	engineeringID := s.store.RoomDisplayNameToID("engineering") // bob is not a member

	bob := testClientFor("bob", "dev_bob_nm")
	raw, _ := json.Marshal(protocol.DeleteRoom{Type: "delete_room", Room: engineeringID})
	s.handleDeleteRoom(bob.Client, raw)

	msgs := bob.messages()
	if len(msgs) != 1 {
		t.Fatalf("expected 1 reply, got %d", len(msgs))
	}
	var errMsg protocol.Error
	json.Unmarshal(msgs[0], &errMsg)
	if errMsg.Code != protocol.ErrUnknownRoom {
		t.Errorf("code = %q, want %q", errMsg.Code, protocol.ErrUnknownRoom)
	}
	if got := s.counters.Get(counters.SignalNonMemberContext, "dev_bob_nm"); got != 1 {
		t.Errorf("never-member delete should fire SignalNonMemberContext once, got %d", got)
	}
	if ids, _ := s.store.GetDeletedRoomsForUser("bob"); len(ids) != 0 {
		t.Errorf("never-member delete must not record deleted_rooms, got %v", ids)
	}
}

// The already-deleted reject and the never-member reject must be
// byte-identical (no oracle distinguishing "you once had this" from "never
// existed"). Privacy parity, extended to the already-deleted case.
func TestHandleDeleteRoom_RejectsByteIdentical(t *testing.T) {
	s := newTestServer(t)
	enableActiveRoomLeave(t, s)
	generalID := s.store.RoomDisplayNameToID("general")
	engineeringID := s.store.RoomDisplayNameToID("engineering")

	// Already-deleted: device A (bob) deletes general; device B (bob, fresh)
	// re-deletes → already-deleted reject in B's buffer only.
	deviceA := testClientFor("bob", "dev_bob_A")
	s.mu.Lock()
	s.clients["dev_bob_A"] = deviceA.Client
	s.mu.Unlock()
	rawGeneral, _ := json.Marshal(protocol.DeleteRoom{Type: "delete_room", Room: generalID})
	s.handleDeleteRoom(deviceA.Client, rawGeneral)

	deviceB := testClientFor("bob", "dev_bob_B")
	s.handleDeleteRoom(deviceB.Client, rawGeneral) // already-deleted reject
	reDeleteMsgs := deviceB.messages()

	// Never-member: carol deletes engineering (carol is not a member of it).
	carol := testClientFor("carol", "dev_carol_nm")
	rawEng, _ := json.Marshal(protocol.DeleteRoom{Type: "delete_room", Room: engineeringID})
	s.handleDeleteRoom(carol.Client, rawEng)
	neverMemberMsgs := carol.messages()

	if len(reDeleteMsgs) != 1 || len(neverMemberMsgs) != 1 {
		t.Fatalf("expected 1 reply each, got redelete=%d nevermember=%d",
			len(reDeleteMsgs), len(neverMemberMsgs))
	}
	if !bytes.Equal(reDeleteMsgs[0], neverMemberMsgs[0]) {
		t.Errorf("already-deleted and never-member rejects must be byte-identical\nredelete:    %s\nnevermember: %s",
			reDeleteMsgs[0], neverMemberMsgs[0])
	}
}

// sendLeftRooms suppresses a room that also has a deleted_rooms row (delete
// supersedes leave), but still emits a left-only room. Without this, the
// reconnect handshake (deleted_rooms before left_rooms) would purge the room
// then resurrect it read-only.
func TestSendLeftRooms_SuppressesDeletedRooms(t *testing.T) {
	s := newTestServer(t)

	// Two rooms bob is NOT a current member of (so the current-member filter
	// is not what's being exercised): one he left AND deleted, one left-only.
	const deletedAndLeft = "rm_delandleft00000000001"
	const leftOnly = "rm_leftonly000000000001"
	if _, err := s.store.RecordUserLeftRoom("bob", deletedAndLeft, "removed", "admin"); err != nil {
		t.Fatalf("seed leave (deleted): %v", err)
	}
	if _, err := s.store.RecordUserLeftRoom("bob", leftOnly, "", "bob"); err != nil {
		t.Fatalf("seed leave (leftonly): %v", err)
	}
	if err := s.store.RecordRoomDeletion("bob", deletedAndLeft); err != nil {
		t.Fatalf("seed deletion: %v", err)
	}

	bob := testClientFor("bob", "dev_bob_1")
	s.sendLeftRooms(bob.Client)

	msgs := bob.messages()
	if len(msgs) != 1 {
		t.Fatalf("expected 1 left_rooms message, got %d", len(msgs))
	}
	var list protocol.LeftRoomsList
	if err := json.Unmarshal(msgs[0], &list); err != nil {
		t.Fatalf("parse left_rooms: %v", err)
	}
	var sawDeleted, sawLeftOnly bool
	for _, e := range list.Rooms {
		if e.Room == deletedAndLeft {
			sawDeleted = true
		}
		if e.Room == leftOnly {
			sawLeftOnly = true
		}
	}
	if sawDeleted {
		t.Errorf("sendLeftRooms must suppress a room that also has a deleted_rooms row (%s)", deletedAndLeft)
	}
	if !sawLeftOnly {
		t.Errorf("sendLeftRooms should still emit a left-only room (%s); got %v", leftOnly, list.Rooms)
	}
}

// If the deleted_rooms lookup fails while building left_rooms, fail closed and
// emit no left_rooms frame. Without this, a deleted+left room could be
// resurrected read-only on reconnect because delete precedence could not be
// proven.
func TestSendLeftRooms_DeletedRoomsLookupFailureEmitsNoLeftRooms(t *testing.T) {
	s := newTestServer(t)
	const leftOnly = "rm_leftonly000000000001"
	if _, err := s.store.RecordUserLeftRoom("bob", leftOnly, "", "bob"); err != nil {
		t.Fatalf("seed leave: %v", err)
	}

	dropDataTable(t, s, "deleted_rooms")

	bob := testClientFor("bob", "dev_bob_left_failclosed")
	s.sendLeftRooms(bob.Client)

	if msgs := bob.messages(); len(msgs) != 0 {
		t.Fatalf("deleted_rooms lookup failure should emit no left_rooms frame, got %d: %s", len(msgs), msgs)
	}
}
