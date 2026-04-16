package server

// Phase 20 — runRemoveFromRoomProcessor and
// processPendingRemoveFromRoom. Standalone processor for
// `sshkey-ctl remove-from-room`.
//
// Same shape as the other five Phase 16 pending_* processors
// (pending_admin_state_changes, pending_room_updates,
// pending_device_revocations, pending_user_retirements,
// pending_user_unretirements): atomic SELECT + DELETE consume
// every tick, then run the side-effect (here, performRoomLeave)
// for each consumed row.
//
// The processor's actual work is small: for each consumed row,
// call performRoomLeave, which already handles:
//   - removing the user from room_members
//   - writing the user_left_rooms history row (Phase 20)
//   - writing a room_event audit row (Phase 20)
//   - broadcasting room_event{leave, reason} to remaining members
//   - echoing room_left to the leaver's own connected sessions
//   - marking the room for epoch rotation (forward secrecy)
//
// The processor just bridges the CLI enqueue to the existing leave
// cascade; the side effects live in performRoomLeave and its helpers.

import (
	"time"
)

// removeFromRoomPollInterval matches the other Phase 16 processor cadences.
const removeFromRoomPollInterval = 5 * time.Second

// runRemoveFromRoomProcessor polls pending_remove_from_room for
// enqueued rows and runs performRoomLeave for each one.
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

// processPendingRemoveFromRoom consumes pending_remove_from_room
// rows and dispatches each one through performRoomLeave. Each call:
//   - Atomically reads + DELETEs the pending rows
//   - For each row, verifies the user is still a member of the
//     room (defensive — handles the race where the user already
//     left via self-leave / retirement between enqueue and processing)
//   - Writes an audit log entry crediting the operator
//   - Calls performRoomLeave which performs the full leave cascade
//
// Errors are logged but don't stop processing.
//
// Idempotency: if the user isn't a member at processing time, we log
// and skip. The DELETE on consume means the row is already gone, so
// it won't be retried on the next tick.
func (s *Server) processPendingRemoveFromRoom() {
	if s.store == nil {
		return
	}

	pending, err := s.store.ConsumePendingRemoveFromRooms()
	if err != nil {
		s.logger.Error("failed to consume pending_remove_from_room queue", "error", err)
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
			"queued_at", p.QueuedAt,
		)

		// Defensive: skip if the user isn't a member at processing
		// time. This handles a race where the user already left via
		// /leave or was retired between enqueue and processing.
		// Calling performRoomLeave on a non-member would still
		// broadcast a misleading "user left" event to everyone in
		// the room, and would write a spurious user_left_rooms row.
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
		// RecordUserLeftRoom (Phase 20 history), RecordRoomEvent
		// (Phase 20 audit), broadcast room_event{leave, reason},
		// echo room_left to the leaver's sessions, mark for epoch
		// rotation. The reason="removed" and initiatedBy="os:<uid>"
		// carried in the queue row flow through to all five sinks.
		s.performRoomLeave(p.RoomID, p.UserID, p.Reason, p.InitiatedBy)
	}
}
