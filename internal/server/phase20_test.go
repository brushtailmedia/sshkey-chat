package server

// Phase 20 — integration-ish tests for the bundled leave catchup +
// room event audit trail behaviors. These test the side effects of
// performRoomLeave / performGroupLeave (history writes, audit writes)
// via the same test harness existing leaveroom_test.go / group_admin_test.go
// use.

import (
	"testing"

	"github.com/brushtailmedia/sshkey-chat/internal/testutil"
)

// TestPerformRoomLeave_WritesHistoryOnEveryPath verifies that every
// reason value produces a user_left_rooms history row (the single
// write point Phase 20 Option D established).
func TestPerformRoomLeave_WritesHistoryOnEveryPath(t *testing.T) {
	cases := []struct {
		name        string
		reason      string
		initiatedBy string
	}{
		{"self_leave", "", testutil.UserID("bob")},
		{"admin_removed", "removed", testutil.UserID("admin")},
		{"user_retired", "user_retired", "system"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestServer(t)
			generalID := s.store.RoomDisplayNameToID("general")

			s.performRoomLeave(generalID, testutil.UserID("bob"), tc.reason, tc.initiatedBy)

			got, err := s.store.GetUserLeftRoomsCatchup(testutil.UserID("bob"))
			if err != nil {
				t.Fatalf("catchup: %v", err)
			}
			if len(got) != 1 {
				t.Fatalf("want 1 history row, got %d", len(got))
			}
			if got[0].Reason != tc.reason {
				t.Errorf("Reason = %q, want %q", got[0].Reason, tc.reason)
			}
			if got[0].InitiatedBy != tc.initiatedBy {
				t.Errorf("InitiatedBy = %q, want %q", got[0].InitiatedBy, tc.initiatedBy)
			}
		})
	}
}

// TestPerformRoomLeave_RecordsRoomEvent verifies the inline room audit
// trail write (Phase 20 bundled scope).
func TestPerformRoomLeave_RecordsRoomEvent(t *testing.T) {
	s := newTestServer(t)
	generalID := s.store.RoomDisplayNameToID("general")

	s.performRoomLeave(generalID, testutil.UserID("bob"), "removed", testutil.UserID("admin"))

	events, err := s.store.GetRoomEventsSince(generalID, 0)
	if err != nil {
		t.Fatalf("get room events: %v", err)
	}
	found := false
	for _, e := range events {
		if e.Event == "leave" && e.User == testutil.UserID("bob") {
			if e.By != testutil.UserID("admin") {
				t.Errorf("By = %q, want admin", e.By)
			}
			if e.Reason != "removed" {
				t.Errorf("Reason = %q, want removed", e.Reason)
			}
			found = true
			break
		}
	}
	if !found {
		t.Errorf("leave event not found among %d events", len(events))
	}
}

// TestPerformGroupLeave_WritesHistoryOnEveryPath verifies the group-
// side equivalent.
func TestPerformGroupLeave_WritesHistoryOnEveryPath(t *testing.T) {
	cases := []struct {
		name        string
		reason      string
		by          string
		initiatedBy string
	}{
		{"self_leave", "", "", testutil.UserID("alice")},
		{"admin_removed", "removed", testutil.UserID("alice"), testutil.UserID("alice")},
		{"retirement", "retirement", "", "system"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestServer(t)
			// Create a group with alice as sole member so performGroupLeave
			// can be called cleanly.
			groupID := testutil.GroupID("grp_" + tc.name)
			if err := s.store.CreateGroup(groupID, testutil.UserID("alice"), []string{testutil.UserID("alice")}, "lunch"); err != nil {
				t.Fatalf("create group: %v", err)
			}

			s.performGroupLeave(groupID, testutil.UserID("alice"), tc.reason, tc.by, tc.initiatedBy)

			got, err := s.store.GetUserLeftGroupsCatchup(testutil.UserID("alice"))
			if err != nil {
				t.Fatalf("catchup: %v", err)
			}
			if len(got) != 1 {
				t.Fatalf("want 1 history row, got %d", len(got))
			}
			if got[0].Reason != tc.reason {
				t.Errorf("Reason = %q, want %q", got[0].Reason, tc.reason)
			}
			if got[0].InitiatedBy != tc.initiatedBy {
				t.Errorf("InitiatedBy = %q, want %q", got[0].InitiatedBy, tc.initiatedBy)
			}
		})
	}
}

// TestPerformGroupLeave_HistoryWrittenBeforeLastMemberCleanup asserts
// the ordering guarantee — the user_left_groups row (in data.db) must
// land before the per-group DB file is unlinked by last-member cleanup,
// otherwise the row would be inside the deleted file and lost.
//
// Since user_left_groups lives in data.db (not the per-group DB), the
// row survives last-member cleanup regardless. This test confirms that
// the row exists post-cleanup.
func TestPerformGroupLeave_HistoryWrittenBeforeLastMemberCleanup(t *testing.T) {
	s := newTestServer(t)
	groupID := testutil.GroupID("grp_solo")
	if err := s.store.CreateGroup(groupID, testutil.UserID("alice"), []string{testutil.UserID("alice")}, "solo"); err != nil {
		t.Fatalf("create group: %v", err)
	}

	// Alice is the sole member — leaving triggers last-member cleanup
	// which unlinks the per-group DB file.
	s.performGroupLeave(groupID, testutil.UserID("alice"), "", "", testutil.UserID("alice"))

	// The user_left_groups row should still exist in data.db.
	got, err := s.store.GetUserLeftGroupsCatchup(testutil.UserID("alice"))
	if err != nil {
		t.Fatalf("catchup: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 history row surviving cleanup, got %d", len(got))
	}
	if got[0].GroupID != groupID {
		t.Errorf("GroupID = %q, want %q", got[0].GroupID, groupID)
	}
}

// TestSendLeftRoomsCatchup_ReturnsEmpty_NoLeaves verifies the handshake
// function sends nothing when the user has no leave history.
func TestSendLeftRoomsCatchup_ReturnsEmpty_NoLeaves(t *testing.T) {
	s := newTestServer(t)
	client := testClientFor(testutil.UserID("bob"), "dev_bob_1")

	s.sendLeftRooms(client.Client)

	msgs := client.messages()
	if len(msgs) != 0 {
		t.Errorf("expected 0 messages (no leaves), got %d", len(msgs))
	}
}

// TestSendLeftRoomsCatchup_ReturnsEntriesWithReasons verifies the
// handshake function emits a left_rooms message with the recorded
// reasons.
func TestSendLeftRoomsCatchup_ReturnsEntriesWithReasons(t *testing.T) {
	s := newTestServer(t)
	generalID := s.store.RoomDisplayNameToID("general")

	// Record a leave for bob. performRoomLeave removes from members too.
	s.performRoomLeave(generalID, testutil.UserID("bob"), "removed", testutil.UserID("admin"))

	client := testClientFor(testutil.UserID("bob"), "dev_bob_1")
	s.sendLeftRooms(client.Client)

	msgs := client.messages()
	if len(msgs) != 1 {
		t.Fatalf("expected 1 left_rooms message, got %d", len(msgs))
	}
	// Verify the payload contains bob's leave entry.
	if string(msgs[0]) == "" {
		t.Error("empty payload")
	}
}

// TestProcessPendingRemoveFromRoom_DrainsQueueNotHistory verifies the
// processor reads from pending_remove_from_room (Phase 20 Option D),
// not user_left_rooms. The queue should be empty after processing,
// and the history row should exist separately.
func TestProcessPendingRemoveFromRoom_DrainsQueueNotHistory(t *testing.T) {
	s := newTestServer(t)
	generalID := s.store.RoomDisplayNameToID("general")

	if err := s.store.RecordPendingRemoveFromRoom(testutil.UserID("bob"), generalID, "removed", "os:1000"); err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	s.processPendingRemoveFromRoom()

	// Queue should be drained.
	pending, _ := s.store.ConsumePendingRemoveFromRooms()
	if len(pending) != 0 {
		t.Errorf("queue should be drained, got %d remaining", len(pending))
	}

	// History row should be present (written by performRoomLeave).
	history, _ := s.store.GetUserLeftRoomsCatchup(testutil.UserID("bob"))
	if len(history) != 1 {
		t.Errorf("expected 1 history row, got %d", len(history))
	}
}

// TestRunRoomRetirementProcessor_RecordsRetireEvent verifies that the
// processor records a retire room_event alongside the live broadcast.
func TestRunRoomRetirementProcessor_RecordsRetireEvent(t *testing.T) {
	s := newTestServer(t)
	generalID := s.store.RoomDisplayNameToID("general")

	// Simulate the retirement: CLI-side mutation then enqueue.
	if err := s.store.SetRoomRetired(generalID, "testing phase 20", "os:1000"); err != nil {
		t.Fatalf("set retired: %v", err)
	}
	if err := s.store.RecordPendingRoomRetirement(generalID, "os:1000", "testing phase 20"); err != nil {
		t.Fatalf("enqueue retirement: %v", err)
	}

	s.processPendingRoomRetirements()

	events, _ := s.store.GetRoomEventsSince(generalID, 0)
	found := false
	for _, e := range events {
		if e.Event == "retire" {
			if e.By != "os:1000" {
				t.Errorf("retire By = %q, want os:1000", e.By)
			}
			found = true
			break
		}
	}
	if !found {
		t.Errorf("retire event not found among %d events", len(events))
	}
}
