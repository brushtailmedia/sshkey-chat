package server

import (
	"database/sql"
	"encoding/json"
	"strings"
	"time"

	"github.com/brushtailmedia/sshkey-chat/internal/protocol"
)

// broadcastPresence sends presence updates when a user connects or disconnects.
func (s *Server) broadcastPresence(userID, status string) {
	if s.store == nil {
		return
	}

	presence := protocol.Presence{
		Type:        "presence",
		User:        userID,
		Status:      status,
		DisplayName: s.store.GetUserDisplayName(userID),
	}

	if status == "offline" {
		presence.LastSeen = time.Now().UTC().Format(time.RFC3339)
	}

	// Build set of users who share a room with this user
	visibleTo := make(map[string]bool)
	for _, roomID := range s.store.GetUserRoomIDs(userID) {
		for _, uid := range s.store.GetRoomMemberIDsByRoomID(roomID) {
			visibleTo[uid] = true
		}
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, client := range s.clients {
		if client.UserID == userID {
			continue
		}
		if visibleTo[client.UserID] {
			client.Encoder.Encode(presence)
		}
	}
}

// sendUnreadCounts sends unread counts for each room and conversation on connect.
func (s *Server) sendUnreadCounts(c *Client) {
	if s.store == nil {
		return
	}

	rooms := s.store.GetUserRoomIDs(c.UserID)

	for _, roomID := range rooms {
		count, lastRead, err := s.store.GetRoomUnreadCount(roomID, c.UserID, c.DeviceID)
		if err != nil || count == 0 {
			continue
		}
		c.Encoder.Encode(protocol.Unread{
			Type:     "unread",
			Room:     roomID,
			Count:    count,
			LastRead: lastRead,
		})
	}

	groups, err := s.store.GetUserGroups(c.UserID)
	if err != nil {
		return
	}
	for _, g := range groups {
		count, lastRead, err := s.store.GetGroupUnreadCount(g.ID, c.UserID, c.DeviceID)
		if err != nil || count == 0 {
			continue
		}
		c.Encoder.Encode(protocol.Unread{
			Type:     "unread",
			Group:    g.ID,
			Count:    count,
			LastRead: lastRead,
		})
	}

	// 1:1 DMs
	dms, dmErr := s.store.GetDirectMessagesForUser(c.UserID)
	if dmErr != nil {
		return
	}
	for _, dm := range dms {
		count, lastRead, err := s.store.GetDMUnreadCount(dm.ID, c.UserID, c.DeviceID)
		if err != nil || count == 0 {
			continue
		}
		c.Encoder.Encode(protocol.Unread{
			Type:     "unread",
			DM:       dm.ID,
			Count:    count,
			LastRead: lastRead,
		})
	}
}

// sendPins sends pinned message lists for each room on connect.
func (s *Server) sendPins(c *Client) {
	if s.store == nil {
		return
	}

	rooms := s.store.GetUserRoomIDs(c.UserID)

	for _, roomID := range rooms {
		db, err := s.store.RoomDB(roomID)
		if err != nil {
			continue
		}

		// Get user's first_epoch for this room — filter out pins from before they joined
		firstSeen, firstEpoch, _ := s.store.GetUserRoom(c.UserID, roomID)

		// Join pins with messages to get the epoch and timestamp of each pinned message
		rows, err := db.Query(`
			SELECT p.message_id, COALESCE(m.epoch, 0), COALESCE(m.ts, 0)
			FROM pins p
			LEFT JOIN messages m ON p.message_id = m.id
			ORDER BY p.ts`)
		if err != nil {
			continue
		}

		var pinned []string
		var pinnedMsgIDs []string
		for rows.Next() {
			var msgID string
			var epoch int64
			var ts int64
			if err := rows.Scan(&msgID, &epoch, &ts); err != nil {
				break
			}
			if firstEpoch > 0 && epoch > 0 && epoch < firstEpoch {
				continue
			}
			if firstSeen > 0 && ts > 0 && ts < firstSeen {
				continue
			}
			pinned = append(pinned, msgID)
			pinnedMsgIDs = append(pinnedMsgIDs, msgID)
		}
		rows.Close()

		if len(pinned) > 0 {
			// Fetch full message envelopes for pinned messages
			var messageData []json.RawMessage
			for _, msgID := range pinnedMsgIDs {
				var id, sender, payload, signature string
				var msgTS, msgEpoch int64
				var fileIDs sql.NullString
				err := db.QueryRow(`
					SELECT id, sender, ts, epoch, payload, signature, file_ids
					FROM messages WHERE id = ? AND deleted = 0`, msgID,
				).Scan(&id, &sender, &msgTS, &msgEpoch, &payload, &signature, &fileIDs)
				if err != nil {
					continue
				}
				msg := protocol.Message{
					Type:      "message",
					ID:        id,
					From:      sender,
					Room:      roomID,
					TS:        msgTS,
					Epoch:     msgEpoch,
					Payload:   payload,
					Signature: signature,
				}
				if fileIDs.Valid && fileIDs.String != "" {
					msg.FileIDs = strings.Split(fileIDs.String, ",")
				}
				data, _ := json.Marshal(msg)
				messageData = append(messageData, data)
			}

			c.Encoder.Encode(protocol.Pins{
				Type:        "pins",
				Room:        roomID,
				Messages:    pinned,
				MessageData: messageData,
			})
		}
	}
}
