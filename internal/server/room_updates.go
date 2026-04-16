package server

// Phase 16 Gap 1 — runRoomUpdatesProcessor and
// processPendingRoomUpdates. Shared processor for update-topic and
// rename-room — both CLI verbs mutate a column on a single rooms.db
// row and need to broadcast a fresh room_updated event to connected
// members of the affected room.
//
// Architecturally identical to admin_state_changes.go but for room
// properties instead of user properties, and with a NARROW broadcast
// scope (members of the room only) instead of wide. Same shape as
// the existing room_retirements processor.

import (
	"time"

	"github.com/brushtailmedia/sshkey-chat/internal/protocol"
	"github.com/brushtailmedia/sshkey-chat/internal/store"
)

// roomUpdatePollInterval is how often the room update processor
// checks the pending_room_updates queue. Five seconds matches the
// other Phase 16 Gap 1 processors.
const roomUpdatePollInterval = 5 * time.Second

// runRoomUpdatesProcessor is the polling loop that bridges the CLI's
// pending_room_updates queue with the running server's broadcast
// surface. Started by Server.Run alongside the other Phase 16 Gap 1
// processors.
func (s *Server) runRoomUpdatesProcessor() {
	ticker := time.NewTicker(roomUpdatePollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-s.roomUpdateStop:
			return
		case <-ticker.C:
			s.processPendingRoomUpdates()
		}
	}
}

// processPendingRoomUpdates consumes the queue and broadcasts a
// fresh room_updated event for each row. Each call:
//   - Atomically reads + deletes the queue rows
//   - For each row, re-reads the room from rooms.db (so the
//     broadcast carries the post-change state)
//   - Writes an audit log entry with the action-specific verb
//     (update-topic / rename-room)
//   - Looks up current room members and broadcasts to every
//     connected session whose UserID is in the member set
//
// Errors are logged but don't stop processing.
func (s *Server) processPendingRoomUpdates() {
	if s.store == nil {
		return
	}

	pending, err := s.store.ConsumePendingRoomUpdates()
	if err != nil {
		s.logger.Error("failed to consume room update queue", "error", err)
		return
	}
	if len(pending) == 0 {
		return
	}

	for _, p := range pending {
		s.logger.Info("processing room update",
			"room", p.RoomID,
			"action", string(p.Action),
			"changed_by", p.ChangedBy,
			"queued_at", p.QueuedAt,
		)

		// Re-fetch the room row to capture the post-change state.
		room, err := s.store.GetRoomByID(p.RoomID)
		if err != nil {
			s.logger.Error("failed to lookup room during update processing",
				"room", p.RoomID, "error", err)
			continue
		}
		if room == nil {
			s.logger.Warn("queued room update references missing room",
				"room", p.RoomID, "action", string(p.Action))
			continue
		}

		// Audit credit. The action-to-verb mapping uses the CLI verb
		// names so operators reading the log see what they typed.
		var auditAction string
		switch p.Action {
		case store.RoomUpdateActionUpdateTopic:
			auditAction = "update-topic"
		case store.RoomUpdateActionRenameRoom:
			auditAction = "rename-room"
		default:
			s.logger.Warn("unknown room update action",
				"action", string(p.Action))
			continue
		}
		if s.audit != nil {
			s.audit.Log(p.ChangedBy, auditAction,
				"room="+p.RoomID+" display_name="+room.DisplayName+" topic="+room.Topic)
		}

		// Build the broadcast event with the full post-change room
		// state — both fields populated even if only one changed,
		// so the client can apply the event with a single upsert.
		event := protocol.RoomUpdated{
			Type:        "room_updated",
			Room:        p.RoomID,
			DisplayName: room.DisplayName,
			Topic:       room.Topic,
		}

		// Narrow broadcast: members of the affected room only.
		// Mirrors the room_retired pattern. Members who aren't
		// currently connected pick up the update on their next
		// reconnect via the existing room_list catchup.
		members := s.store.GetRoomMemberIDsByRoomID(p.RoomID)
		memberSet := make(map[string]bool, len(members))
		for _, m := range members {
			memberSet[m] = true
		}

		s.mu.RLock()
		for _, client := range s.clients {
			if memberSet[client.UserID] {
				client.Encoder.Encode(event)
			}
		}
		s.mu.RUnlock()
	}
}
