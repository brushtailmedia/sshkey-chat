package server

import (
	"encoding/json"
	"time"

	"github.com/brushtailmedia/sshkey/internal/protocol"
	"github.com/brushtailmedia/sshkey/internal/store"
)

// sendSync sends sync batches to a reconnecting client.
// lastSyncedAt is the ISO 8601 timestamp from client_hello (empty for first connect).
func (s *Server) sendSync(c *Client, lastSyncedAt string) {
	if s.store == nil {
		c.Encoder.Encode(protocol.SyncComplete{
			Type:     "sync_complete",
			SyncedTo: time.Now().UTC().Format(time.RFC3339),
		})
		return
	}

	// Determine sync window
	windowMessages := s.cfg.Server.Sync.WindowMessages
	if windowMessages == 0 {
		windowMessages = 200
	}
	windowDays := s.cfg.Server.Sync.WindowDays
	if windowDays == 0 {
		windowDays = 7
	}

	var sinceTS int64
	if lastSyncedAt != "" {
		t, err := time.Parse(time.RFC3339, lastSyncedAt)
		if err == nil {
			sinceTS = t.Unix()
		}
	}

	// Apply window_days cap
	windowCutoff := time.Now().Add(-time.Duration(windowDays) * 24 * time.Hour).Unix()
	if sinceTS < windowCutoff {
		sinceTS = windowCutoff
	}

	s.cfg.RLock()
	rooms := s.cfg.Users[c.Username].Rooms
	s.cfg.RUnlock()

	// Sync room messages
	for _, room := range rooms {
		s.syncRoom(c, room, sinceTS, windowMessages)
	}

	// Sync DM conversations
	convs, err := s.store.GetUserConversations(c.Username)
	if err == nil {
		for _, conv := range convs {
			s.syncConversation(c, conv.ID, sinceTS, windowMessages)
		}
	}

	// Update device sync watermark
	s.store.UpdateDeviceSync(c.Username, c.DeviceID)

	c.Encoder.Encode(protocol.SyncComplete{
		Type:     "sync_complete",
		SyncedTo: time.Now().UTC().Format(time.RFC3339),
	})
}

// syncRoom sends a sync batch for a single room.
func (s *Server) syncRoom(c *Client, room string, sinceTS int64, limit int) {
	// Apply first_seen filter — new users only see post-join messages
	firstSeen, firstEpoch, _ := s.store.GetUserRoom(c.Username, room)
	if firstSeen > 0 && firstSeen > sinceTS {
		sinceTS = firstSeen
	}

	msgs, err := s.store.GetRoomMessagesSince(room, sinceTS, limit)
	if err != nil {
		s.logger.Error("sync room failed", "room", room, "error", err)
		return
	}

	// Filter out messages from epochs before the user's first_epoch
	if firstEpoch > 0 {
		filtered := msgs[:0]
		for _, m := range msgs {
			if m.Epoch >= firstEpoch || m.Deleted {
				filtered = append(filtered, m)
			}
		}
		msgs = filtered
	}

	if len(msgs) == 0 {
		return
	}

	// Collect epoch keys needed for this batch
	minEpoch, maxEpoch := store.GetEpochRange(msgs)
	var epochKeys []protocol.SyncEpochKey

	if minEpoch > 0 || maxEpoch > 0 {
		keys, err := s.store.GetEpochKeysForUser(room, c.Username, minEpoch, maxEpoch)
		if err == nil {
			for epoch, wrappedKey := range keys {
				epochKeys = append(epochKeys, protocol.SyncEpochKey{
					Room:       room,
					Epoch:      epoch,
					WrappedKey: wrappedKey,
				})
			}
		}
	}

	// Convert to protocol messages
	protoMsgs := storedToRawMessages(msgs, room, "")

	// Fetch reactions for these messages
	var protoReactions []json.RawMessage
	if msgIDs := collectMessageIDs(msgs); len(msgIDs) > 0 {
		if reactions, err := s.store.GetRoomReactionsForMessages(room, msgIDs); err == nil && len(reactions) > 0 {
			protoReactions = storedReactionsToRaw(reactions, room, "")
		}
	}

	c.Encoder.Encode(protocol.SyncBatch{
		Type:      "sync_batch",
		Messages:  protoMsgs,
		Reactions: protoReactions,
		EpochKeys: epochKeys,
		Page:      1,
		HasMore:   false,
	})
}

// syncConversation sends a sync batch for a single DM conversation.
func (s *Server) syncConversation(c *Client, convID string, sinceTS int64, limit int) {
	msgs, err := s.store.GetConvMessagesSince(convID, sinceTS, limit)
	if err != nil {
		s.logger.Error("sync conversation failed", "conversation", convID, "error", err)
		return
	}

	if len(msgs) == 0 {
		return
	}

	// DMs carry their own wrapped keys -- no epoch_keys needed
	protoMsgs := storedToRawMessages(msgs, "", convID)

	var protoReactions []json.RawMessage
	if msgIDs := collectMessageIDs(msgs); len(msgIDs) > 0 {
		if reactions, err := s.store.GetConvReactionsForMessages(convID, msgIDs); err == nil && len(reactions) > 0 {
			protoReactions = storedReactionsToRaw(reactions, "", convID)
		}
	}

	c.Encoder.Encode(protocol.SyncBatch{
		Type:      "sync_batch",
		Messages:  protoMsgs,
		Reactions: protoReactions,
		EpochKeys: nil,
		Page:      1,
		HasMore:   false,
	})
}

// handleHistory processes a history (scroll-back) request.
func (s *Server) handleHistory(c *Client, raw json.RawMessage) {
	if !s.limiter.allowPerMinute("history:"+c.Username, s.cfg.Server.RateLimits.HistoryPerMinute) {
		c.Encoder.Encode(protocol.Error{Type: "error", Code: protocol.ErrRateLimited, Message: "History rate limit exceeded"})
		return
	}

	var req protocol.History
	if err := json.Unmarshal(raw, &req); err != nil {
		c.Encoder.Encode(protocol.Error{Type: "error", Code: "invalid_message", Message: "malformed history"})
		return
	}

	if s.store == nil {
		return
	}

	limit := req.Limit
	if limit <= 0 || limit > s.cfg.Server.Sync.HistoryPageSize {
		limit = s.cfg.Server.Sync.HistoryPageSize
		if limit == 0 {
			limit = 100
		}
	}

	if req.Room != "" {
		// Verify access
		s.cfg.RLock()
		user := s.cfg.Users[c.Username]
		s.cfg.RUnlock()
		inRoom := false
		for _, r := range user.Rooms {
			if r == req.Room {
				inRoom = true
				break
			}
		}
		if !inRoom {
			c.Encoder.Encode(protocol.Error{
				Type: "error", Code: protocol.ErrNotAuthorized,
				Message: "You don't have access to room: " + req.Room,
			})
			return
		}

		msgs, err := s.store.GetRoomMessagesBefore(req.Room, req.Before, limit+1)
		if err != nil {
			s.logger.Error("history failed", "room", req.Room, "error", err)
			return
		}

		// Apply first_seen/first_epoch filter
		firstSeen, firstEpoch, _ := s.store.GetUserRoom(c.Username, req.Room)
		if firstSeen > 0 || firstEpoch > 0 {
			filtered := msgs[:0]
			for _, m := range msgs {
				if firstSeen > 0 && m.TS < firstSeen {
					continue
				}
				if firstEpoch > 0 && m.Epoch < firstEpoch && !m.Deleted {
					continue
				}
				filtered = append(filtered, m)
			}
			msgs = filtered
		}

		hasMore := len(msgs) > limit
		if hasMore {
			msgs = msgs[:limit]
		}

		// Collect epoch keys
		var epochKeys []protocol.SyncEpochKey
		if len(msgs) > 0 {
			minEpoch, maxEpoch := store.GetEpochRange(msgs)
			keys, err := s.store.GetEpochKeysForUser(req.Room, c.Username, minEpoch, maxEpoch)
			if err == nil {
				for epoch, wrappedKey := range keys {
					epochKeys = append(epochKeys, protocol.SyncEpochKey{
						Room:       req.Room,
						Epoch:      epoch,
						WrappedKey: wrappedKey,
					})
				}
			}
		}

		var roomReactions []json.RawMessage
		if msgIDs := collectMessageIDs(msgs); len(msgIDs) > 0 {
			if reactions, err := s.store.GetRoomReactionsForMessages(req.Room, msgIDs); err == nil && len(reactions) > 0 {
				roomReactions = storedReactionsToRaw(reactions, req.Room, "")
			}
		}

		c.Encoder.Encode(protocol.HistoryResult{
			Type:      "history_result",
			Room:      req.Room,
			Messages:  storedToRawMessages(msgs, req.Room, ""),
			Reactions: roomReactions,
			EpochKeys: epochKeys,
			HasMore:   hasMore,
		})

	} else if req.Conversation != "" {
		// Verify membership
		isMember, err := s.store.IsConversationMember(req.Conversation, c.Username)
		if err != nil || !isMember {
			c.Encoder.Encode(protocol.Error{
				Type: "error", Code: protocol.ErrUnknownConversation,
				Message: "You are not a member of this conversation",
			})
			return
		}

		msgs, err := s.store.GetConvMessagesBefore(req.Conversation, req.Before, limit+1)
		if err != nil {
			s.logger.Error("history failed", "conversation", req.Conversation, "error", err)
			return
		}

		hasMore := len(msgs) > limit
		if hasMore {
			msgs = msgs[:limit]
		}

		var convReactions []json.RawMessage
		if msgIDs := collectMessageIDs(msgs); len(msgIDs) > 0 {
			if reactions, err := s.store.GetConvReactionsForMessages(req.Conversation, msgIDs); err == nil && len(reactions) > 0 {
				convReactions = storedReactionsToRaw(reactions, "", req.Conversation)
			}
		}

		c.Encoder.Encode(protocol.HistoryResult{
			Type:         "history_result",
			Conversation: req.Conversation,
			Messages:     storedToRawMessages(msgs, "", req.Conversation),
			Reactions:    convReactions,
			HasMore:      hasMore,
		})
	}
}

// storedToRawMessages converts stored messages to JSON raw messages for sync/history.
// Tombstoned messages become "deleted" type messages.
// collectMessageIDs extracts non-deleted message IDs from a set of stored messages.
func collectMessageIDs(msgs []store.StoredMessage) []string {
	ids := make([]string, 0, len(msgs))
	for _, m := range msgs {
		if !m.Deleted {
			ids = append(ids, m.ID)
		}
	}
	return ids
}

// storedReactionsToRaw converts stored reactions to protocol Reaction raw messages.
func storedReactionsToRaw(reactions []store.StoredReaction, room, conversation string) []json.RawMessage {
	result := make([]json.RawMessage, 0, len(reactions))
	for _, r := range reactions {
		msg := protocol.Reaction{
			Type:        "reaction",
			ReactionID:  r.ReactionID,
			ID:          r.MessageID,
			Room:        room,
			Conversation: conversation,
			User:        r.User,
			TS:          r.TS,
			Epoch:       r.Epoch,
			WrappedKeys: r.WrappedKeys,
			Payload:     r.Payload,
			Signature:   r.Signature,
		}
		data, _ := json.Marshal(msg)
		result = append(result, json.RawMessage(data))
	}
	return result
}

func storedToRawMessages(msgs []store.StoredMessage, room, conversation string) []json.RawMessage {
	result := make([]json.RawMessage, 0, len(msgs))

	for _, m := range msgs {
		var data []byte

		if m.Deleted {
			tombstone := protocol.Deleted{
				Type:         "deleted",
				ID:           m.ID,
				DeletedBy:    m.Sender, // sender field repurposed for deleted_by on tombstones
				TS:           m.TS,
				Room:         room,
				Conversation: conversation,
			}
			data, _ = json.Marshal(tombstone)
		} else if room != "" {
			msg := protocol.Message{
				Type:      "message",
				ID:        m.ID,
				From:      m.Sender,
				Room:      room,
				TS:        m.TS,
				Epoch:     m.Epoch,
				Payload:   m.Payload,
				FileIDs:   m.FileIDs,
				Signature: m.Signature,
			}
			data, _ = json.Marshal(msg)
		} else {
			msg := protocol.DM{
				Type:         "dm",
				ID:           m.ID,
				From:         m.Sender,
				Conversation: conversation,
				TS:           m.TS,
				WrappedKeys:  m.WrappedKeys,
				Payload:      m.Payload,
				FileIDs:      m.FileIDs,
				Signature:    m.Signature,
			}
			data, _ = json.Marshal(msg)
		}

		result = append(result, json.RawMessage(data))
	}

	return result
}
