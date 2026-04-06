package server

import (
	"encoding/json"

	"github.com/brushtailmedia/sshkey-chat/internal/protocol"
)

// handlePushRegister processes a push token registration.
func (s *Server) handlePushRegister(c *Client, raw json.RawMessage) {
	var msg protocol.PushRegister
	if err := json.Unmarshal(raw, &msg); err != nil {
		c.Encoder.Encode(protocol.Error{Type: "error", Code: "invalid_message", Message: "malformed push_register"})
		return
	}

	if msg.Platform != "ios" && msg.Platform != "android" {
		c.Encoder.Encode(protocol.Error{Type: "error", Code: "invalid_message", Message: "platform must be ios or android"})
		return
	}

	if s.store != nil {
		if err := s.store.UpsertPushToken(c.Username, c.DeviceID, msg.Platform, msg.Token); err != nil {
			s.logger.Error("failed to store push token", "user", c.Username, "error", err)
			return
		}
	}

	c.Encoder.Encode(protocol.PushRegistered{
		Type:     "push_registered",
		Platform: msg.Platform,
	})

	s.logger.Info("push token registered",
		"user", c.Username,
		"device", c.DeviceID,
		"platform", msg.Platform,
	)
}

// notifyOfflineUsers sends push notifications to offline users who should
// receive a message. Called after storing and broadcasting a room or DM message.
func (s *Server) notifyOfflineUsers(recipients []string) {
	if s.push == nil || s.store == nil {
		return
	}

	for _, username := range recipients {
		// Check if user has any connected device
		if s.isUserOnline(username) {
			continue
		}

		// Get push tokens for this user
		tokens, err := s.store.GetActivePushTokens(username)
		if err != nil || len(tokens) == 0 {
			continue
		}

		// Send wake push to each device
		for _, tok := range tokens {
			valid, err := s.push.SendWake(tok.Platform, tok.Token)
			if err != nil {
				s.logger.Warn("push send failed",
					"user", username,
					"device", tok.DeviceID,
					"platform", tok.Platform,
					"error", err,
				)
			}
			if !valid {
				// Token is dead — deactivate it
				s.store.DeactivatePushToken(username, tok.DeviceID)
			}
		}
	}
}

// isUserOnline checks if any device for a user is currently connected.
func (s *Server) isUserOnline(username string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, client := range s.clients {
		if client.Username == username {
			return true
		}
	}
	return false
}

// getRoomMembers returns all usernames in a room.
func (s *Server) getRoomMembers(room string) []string {
	s.cfg.RLock()
	defer s.cfg.RUnlock()

	var members []string
	for username, user := range s.cfg.Users {
		for _, r := range user.Rooms {
			if r == room {
				members = append(members, username)
				break
			}
		}
	}
	return members
}
