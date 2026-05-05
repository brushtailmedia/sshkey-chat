package server

import (
	"time"

	"github.com/brushtailmedia/sshkey-chat/internal/protocol"
)

const addToRoomPollInterval = 5 * time.Second

// runAddToRoomProcessor polls pending_add_to_room and applies live
// side effects for CLI add-to-room operations.
func (s *Server) runAddToRoomProcessor() {
	ticker := time.NewTicker(addToRoomPollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-s.addToRoomStop:
			return
		case <-ticker.C:
			s.processPendingAddToRoom()
		}
	}
}

// processPendingAddToRoom consumes pending_add_to_room rows and, for
// each still-valid membership:
//   - writes a room_event join audit row
//   - broadcasts room_event{join} to current room members
//   - triggers epoch rotation when an online room member is available
func (s *Server) processPendingAddToRoom() {
	if s.store == nil {
		return
	}

	pending, err := s.store.ConsumePendingAddToRooms()
	if err != nil {
		s.logger.Error("failed to consume pending_add_to_room queue", "error", err)
		return
	}
	if len(pending) == 0 {
		return
	}

	for _, p := range pending {
		s.logger.Info("processing add-to-room",
			"user", p.UserID,
			"room", p.RoomID,
			"initiated_by", p.InitiatedBy,
			"queued_at", p.QueuedAt,
		)

		// Skip stale rows where membership no longer exists.
		if !s.store.IsRoomMemberByID(p.RoomID, p.UserID) {
			s.logger.Warn("queued add-to-room references non-member",
				"user", p.UserID, "room", p.RoomID)
			continue
		}

		if s.audit != nil {
			s.audit.Log(p.InitiatedBy, "add-to-room",
				"user="+p.UserID+" room="+p.RoomID)
		}

		if err := s.store.RecordRoomEvent(
			p.RoomID, "join", p.UserID, p.InitiatedBy, "", "", false, time.Now().Unix(),
		); err != nil {
			s.logger.Error("failed to record room event",
				"room", p.RoomID, "event", "join", "user", p.UserID, "error", err)
		}

		s.broadcastToRoom(p.RoomID, protocol.RoomEvent{
			Type:  "room_event",
			Room:  p.RoomID,
			Event: "join",
			User:  p.UserID,
			By:    p.InitiatedBy,
		})

		epoch := s.epochs.currentEpochNum(p.RoomID)
		if epoch == 0 {
			if dbEpoch, err := s.store.GetCurrentEpoch(p.RoomID); err == nil && dbEpoch > 0 {
				epoch = dbEpoch
			}
		}
		s.epochs.getOrCreate(p.RoomID, epoch)

		rotator := s.pickConnectedRoomMember(p.RoomID)
		if rotator == nil {
			s.logger.Info("add-to-room has no online room member for immediate rotation",
				"room", p.RoomID, "user", p.UserID)
			continue
		}
		s.triggerEpochRotation(rotator, p.RoomID, "member_join")
	}
}

func (s *Server) pickConnectedRoomMember(roomID string) *Client {
	if s.store == nil {
		return nil
	}

	memberSet := make(map[string]bool)
	for _, uid := range s.store.GetRoomMemberIDsByRoomID(roomID) {
		memberSet[uid] = true
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, client := range s.clients {
		if memberSet[client.UserID] {
			return client
		}
	}
	return nil
}
