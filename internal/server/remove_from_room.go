package server

// Phase 16 Gap 1 — runRemoveFromRoomProcessor and
// processPendingRemoveFromRoom. Standalone processor for
// `sshkey-ctl remove-from-room`.
//
// Different shape from the per-command queues used by the other
// Phase 16 Gap 1 commands: this one drains the dual-purpose
// user_left_rooms table that Phase 20 will also use for
// server-authoritative leave catchup. Phase 16's CLI write path is
// the only producer for now; Phase 20 will extend it with self-leave
// and retirement-cascade writers.
//
// The processor's actual work is small: for each unprocessed row,
// call performRoomLeave, which already handles:
//   - removing the user from room_members
//   - broadcasting room_event{leave, reason} to remaining members
//   - echoing room_left to the leaver's own connected sessions
//   - marking the room for epoch rotation (forward secrecy)
//
// Phase 16 just bridges the CLI write to the existing leave cascade.

import (
	"time"
)

// removeFromRoomPollInterval matches the other Phase 16 Gap 1
// processor cadences.
const removeFromRoomPollInterval = 5 * time.Second

// runRemoveFromRoomProcessor polls user_left_rooms for unprocessed
// rows and runs performRoomLeave for each one.
func (s *Server) runRemoveFromRoomProcessor() {
	ticker := time.NewTicker(removeFromRoomPollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-s.removeFromRoomStop:
			return
		case <-ticker.C:
			s.processPendingRemoveFromRoom()
		}
	}
}

// processPendingRemoveFromRoom consumes unprocessed user_left_rooms
// rows and dispatches each one through performRoomLeave. Each call:
//   - Atomically reads + marks-processed the pending rows
//   - For each row, verifies the user is still a member of the
//     room (defensive — handles the race where the user already
//     left via another path between enqueue and processing)
//   - Writes an audit log entry crediting the operator
//   - Calls performRoomLeave which performs the full leave cascade
//
// Errors are logged but don't stop processing.
//
// Idempotency: if the user isn't a member at processing time, we
// log and skip. The mark-processed already happened atomically with
// the SELECT, so the row won't be picked up again on the next tick.
// Phase 20's catchup readers will see the row as "left at this
// time" regardless of whether the actual cascade ran (the row's
// presence is the source of truth, not the processed flag).
func (s *Server) processPendingRemoveFromRoom() {
	if s.store == nil {
		return
	}

	pending, err := s.store.ConsumePendingUserLeftRooms()
	if err != nil {
		s.logger.Error("failed to consume user_left_rooms queue", "error", err)
		return
	}
	if len(pending) == 0 {
		return
	}

	for _, p := range pending {
		s.logger.Info("processing remove-from-room",
			"user", p.UserID,
			"room", p.RoomID,
			"reason", p.Reason,
			"initiated_by", p.InitiatedBy,
			"left_at", p.LeftAt,
		)

		// Defensive: skip if the user isn't a member at processing
		// time. This handles a race where the user already left via
		// /leave or was retired between enqueue and processing.
		// Calling performRoomLeave on a non-member would still
		// broadcast a misleading "user left" event to everyone in
		// the room.
		if !s.store.IsRoomMemberByID(p.RoomID, p.UserID) {
			s.logger.Warn("queued remove-from-room references non-member",
				"user", p.UserID, "room", p.RoomID)
			continue
		}

		// Audit credit. The CLI verb ("remove-from-room") is used
		// as the action label so operators reading the log see what
		// they typed.
		if s.audit != nil {
			s.audit.Log(p.InitiatedBy, "remove-from-room",
				"user="+p.UserID+" room="+p.RoomID+" reason="+p.Reason)
		}

		// performRoomLeave does the full cascade: RemoveRoomMember,
		// broadcast room_event{leave, reason}, echo room_left to
		// the leaver's sessions, mark for epoch rotation. The
		// reason="removed" carried in p.Reason gets passed through
		// to the broadcast so client UIs can render an appropriate
		// system message ("alice was removed by an admin" instead
		// of "alice left").
		s.performRoomLeave(p.RoomID, p.UserID, p.Reason)
	}
}
