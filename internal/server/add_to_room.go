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

		// Stale-row guards (defense-in-depth, server-authoritative). A queued
		// row can outlive its preconditions in the ~5s between enqueue and
		// dequeue: the room may have been retired/deleted, or the user
		// retired. Never broadcast a join, rotate, or notify for those —
		// retirement is read-only, and a retired user must not be surfaced as
		// a live room member. Both are in addition to the IsRoomMemberByID
		// skip above.
		room, err := s.store.GetRoomByID(p.RoomID)
		if err != nil || room == nil || room.Retired {
			s.logger.Warn("queued add-to-room references a missing or retired room — skipping side effects",
				"user", p.UserID, "room", p.RoomID)
			continue
		}
		u := s.store.GetUserByID(p.UserID)
		if u == nil || u.Retired {
			s.logger.Warn("queued add-to-room references a missing or retired user — skipping side effects",
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

		// Live "you were added" notification to EVERY connected session of the
		// newly-added user. Live-only — never replayed in sync_batch; offline
		// correctness comes from room_list on next connect. Member ordering is
		// deterministic (GetRoomMemberIDsByRoomID orders by joined_at,user_id).
		members := s.store.GetRoomMemberIDsByRoomID(p.RoomID)
		addedTo := protocol.RoomAddedTo{
			Type:    "room_added_to",
			Room:    p.RoomID,
			Name:    room.DisplayName,
			Topic:   room.Topic,
			Members: members,
			AddedBy: p.InitiatedBy,
		}
		s.mu.RLock()
		var targets []*Client
		for _, client := range s.clients {
			if client.UserID == p.UserID {
				targets = append(targets, client)
			}
		}
		s.mu.RUnlock()
		s.fanOut("room_added_to", addedTo, targets)

		// Join broadcast to the REST of the room — exclude the newly-added
		// user, who gets room_added_to instead of a self-join system message.
		s.broadcastToRoomExceptUser(p.RoomID, p.UserID, protocol.RoomEvent{
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
