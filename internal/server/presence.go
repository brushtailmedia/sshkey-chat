package server

import (
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

		rows, err := db.Query(`SELECT message_id FROM pins ORDER BY ts`)
		if err != nil {
			continue
		}

		var pinned []string
		for rows.Next() {
			var msgID string
			if err := rows.Scan(&msgID); err != nil {
				break
			}
			pinned = append(pinned, msgID)
		}
		rows.Close()

		if len(pinned) > 0 {
			c.Encoder.Encode(protocol.Pins{
				Type:     "pins",
				Room:     room,
				Messages: pinned,
			})
		}
	}
}
