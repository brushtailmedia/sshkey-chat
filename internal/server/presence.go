package server

import (
	"database/sql"
	"encoding/json"
	"strings"
	"time"

	"github.com/brushtailmedia/sshkey/internal/protocol"
)

// broadcastPresence sends presence updates when a user connects or disconnects.
func (s *Server) broadcastPresence(username, status string) {
	s.cfg.RLock()
	user := s.cfg.Users[username]
	s.cfg.RUnlock()

	presence := protocol.Presence{
		Type:        "presence",
		User:        username,
		Status:      status,
		DisplayName: user.DisplayName,
	}

	if status == "offline" {
		presence.LastSeen = time.Now().UTC().Format(time.RFC3339)
	}

	// Broadcast to all connected clients who can see this user
	s.mu.RLock()
	defer s.mu.RUnlock()

	s.cfg.RLock()
	defer s.cfg.RUnlock()

	// Find rooms the user is in
	userRooms := make(map[string]bool)
	for _, r := range user.Rooms {
		userRooms[r] = true
	}

	for _, client := range s.clients {
		if client.Username == username {
			continue
		}
		// Check if this client shares a room
		clientUser := s.cfg.Users[client.Username]
		for _, r := range clientUser.Rooms {
			if userRooms[r] {
				client.Encoder.Encode(presence)
				break
			}
		}
	}
}

// sendUnreadCounts sends unread counts for each room and conversation on connect.
func (s *Server) sendUnreadCounts(c *Client) {
	if s.store == nil {
		return
	}

	s.cfg.RLock()
	rooms := s.cfg.Users[c.Username].Rooms
	s.cfg.RUnlock()

	for _, room := range rooms {
		count, lastRead, err := s.store.GetRoomUnreadCount(room, c.Username, c.DeviceID)
		if err != nil || count == 0 {
			continue
		}
		c.Encoder.Encode(protocol.Unread{
			Type:     "unread",
			Room:     room,
			Count:    count,
			LastRead: lastRead,
		})
	}

	convs, err := s.store.GetUserConversations(c.Username)
	if err != nil {
		return
	}
	for _, conv := range convs {
		count, lastRead, err := s.store.GetConvUnreadCount(conv.ID, c.Username, c.DeviceID)
		if err != nil || count == 0 {
			continue
		}
		c.Encoder.Encode(protocol.Unread{
			Type:         "unread",
			Conversation: conv.ID,
			Count:        count,
			LastRead:     lastRead,
		})
	}
}

// sendPins sends pinned message lists for each room on connect.
func (s *Server) sendPins(c *Client) {
	if s.store == nil {
		return
	}

	s.cfg.RLock()
	rooms := s.cfg.Users[c.Username].Rooms
	s.cfg.RUnlock()

	for _, room := range rooms {
		db, err := s.store.RoomDB(room)
		if err != nil {
			continue
		}

		// Get user's first_epoch for this room — filter out pins from before they joined
		firstSeen, firstEpoch, _ := s.store.GetUserRoom(c.Username, room)

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
					Room:      room,
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
				Room:        room,
				Messages:    pinned,
				MessageData: messageData,
			})
		}
	}
}
