package server

import (
	"encoding/json"
	"strings"

	"github.com/brushtailmedia/sshkey-chat/internal/counters"
	"github.com/brushtailmedia/sshkey-chat/internal/protocol"
)

const (
	minPushTokenLen = 8
	maxPushTokenLen = 4096
)

// handlePushRegister processes a push token registration.
func (s *Server) handlePushRegister(c *Client, raw json.RawMessage) {
	var msg protocol.PushRegister
	if err := json.Unmarshal(raw, &msg); err != nil {
		s.rejectAndLog(c, counters.SignalMalformedFrame, "push_register", "malformed push_register frame",
			&protocol.Error{Type: "error", Code: "invalid_message", Message: "malformed push_register"})
		return
	}

	if msg.Platform != "ios" && msg.Platform != "android" {
		s.rejectAndLog(c, counters.SignalMalformedFrame, "push_register", "platform must be ios or android",
			&protocol.Error{Type: "error", Code: "invalid_message", Message: "platform must be ios or android"})
		return
	}

	token := strings.TrimSpace(msg.Token)
	if len(token) < minPushTokenLen {
		s.rejectAndLog(c, counters.SignalMalformedFrame, "push_register", "push token too short",
			&protocol.Error{Type: "error", Code: "invalid_message", Message: "push token must be at least 8 characters"})
		return
	}
	if len(token) > maxPushTokenLen {
		s.rejectAndLog(c, counters.SignalMalformedFrame, "push_register", "push token too long",
			&protocol.Error{Type: "error", Code: "invalid_message", Message: "push token too long"})
		return
	}

	if s.store != nil {
		if err := s.store.UpsertPushToken(c.UserID, c.DeviceID, msg.Platform, token); err != nil {
			s.logger.Error("failed to store push token", "user", c.UserID, "error", err)
			return
		}
	}

	c.Encoder.Encode(protocol.PushRegistered{
		Type:     "push_registered",
		Platform: msg.Platform,
	})

	s.logger.Info("push token registered",
		"user", c.UserID,
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

	for _, userID := range recipients {
		// Check if user has any connected device
		if s.isUserOnline(userID) {
			continue
		}

		// Get push tokens for this user
		tokens, err := s.store.GetActivePushTokens(userID)
		if err != nil || len(tokens) == 0 {
			continue
		}

		// Send wake push to each device
		for _, tok := range tokens {
			valid, err := s.push.SendWake(tok.Platform, tok.Token)
			if err != nil {
				s.logger.Warn("push send failed",
					"user", userID,
					"device", tok.DeviceID,
					"platform", tok.Platform,
					"error", err,
				)
			}
			if !valid {
				// Token is dead — deactivate it
				s.store.DeactivatePushToken(userID, tok.DeviceID)
			}
		}
	}
}

// isUserOnline checks if any device for a user is currently connected.
func (s *Server) isUserOnline(userID string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, client := range s.clients {
		if client.UserID == userID {
			return true
		}
	}
	return false
}

// getRoomMembers returns all user IDs in a room.
func (s *Server) getRoomMembers(roomID string) []string {
	if s.store == nil {
		return nil
	}
	return s.store.GetRoomMemberIDsByRoomID(roomID)
}
