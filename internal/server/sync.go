package server

import (
	"encoding/json"
	"time"

	"github.com/brushtailmedia/sshkey-chat/internal/protocol"
	"github.com/brushtailmedia/sshkey-chat/internal/store"
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

	rooms := s.store.GetUserRoomIDs(c.UserID)

	// Sync room messages
	for _, roomID := range rooms {
		s.syncRoom(c, roomID, sinceTS, windowMessages)
	}

	// Sync group DMs
	groups, err := s.store.GetUserGroups(c.UserID)
	if err == nil {
		for _, g := range groups {
			s.syncGroup(c, g.ID, sinceTS, windowMessages)
		}
	}

	// Sync 1:1 DMs
	dms, dmErr := s.store.GetDirectMessagesForUser(c.UserID)
	if dmErr == nil {
		for _, dm := range dms {
			s.syncDM(c, dm.ID, sinceTS, windowMessages)
		}
	}

	// Update device sync watermark
	s.store.UpdateDeviceSync(c.UserID, c.DeviceID)

	c.Encoder.Encode(protocol.SyncComplete{
		Type:     "sync_complete",
		SyncedTo: time.Now().UTC().Format(time.RFC3339),
	})
}

// syncRoom sends a sync batch for a single room. Phase 20 extended
// this to pack room_events (leave / join / topic / rename / retire)
// alongside messages, mirroring syncGroup's event packing. Both use
// the same first_seen gate so pre-join audit is never served.
func (s *Server) syncRoom(c *Client, roomID string, sinceTS int64, limit int) {
	// Apply first_seen filter — new users only see post-join messages
	// AND post-join audit events (Phase 20). Same gate covers both.
	firstSeen, firstEpoch, _ := s.store.GetUserRoom(c.UserID, roomID)
	if firstSeen > 0 && firstSeen > sinceTS {
		sinceTS = firstSeen
	}

	msgs, err := s.store.GetRoomMessagesSince(roomID, sinceTS, limit)
	if err != nil {
		s.logger.Error("sync room failed", "room", roomID, "error", err)
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

	// Phase 20: fetch room_events for replay. Events are unencrypted
	// metadata (server-authored audit — see encryption_boundaries
	// memory note) so there's no first_epoch filter; the first_seen
	// gate above is sufficient.
	events, eventsErr := s.store.GetRoomEventsSince(roomID, sinceTS)
	if eventsErr != nil {
		s.logger.Error("sync room events failed", "room", roomID, "error", eventsErr)
		events = nil
	}

	if len(msgs) == 0 && len(events) == 0 {
		return
	}

	// Collect epoch keys needed for this batch
	minEpoch, maxEpoch := store.GetEpochRange(msgs)
	var epochKeys []protocol.SyncEpochKey

	if minEpoch > 0 || maxEpoch > 0 {
		keys, err := s.store.GetEpochKeysForUser(roomID, c.UserID, minEpoch, maxEpoch)
		if err == nil {
			for epoch, wrappedKey := range keys {
				epochKeys = append(epochKeys, protocol.SyncEpochKey{
					Room:       roomID,
					Epoch:      epoch,
					WrappedKey: wrappedKey,
				})
			}
		}
	}

	// Convert to protocol messages
	protoMsgs := storedToRawMessages(msgs, roomID, "")

	// Fetch reactions for these messages
	var protoReactions []json.RawMessage
	if msgIDs := collectMessageIDs(msgs); len(msgIDs) > 0 {
		if reactions, err := s.store.GetRoomReactionsForMessages(roomID, msgIDs); err == nil && len(reactions) > 0 {
			protoReactions = storedReactionsToRaw(reactions, roomID, "")
		}
	}

	// Phase 20: pack room_events into SyncBatch.Events so the client
	// replays audit entries through the same dispatch path used for
	// live room_event broadcasts.
	var protoEvents []json.RawMessage
	if len(events) > 0 {
		protoEvents = roomEventsToRaw(events, roomID)
	}

	c.Encoder.Encode(protocol.SyncBatch{
		Type:      "sync_batch",
		Messages:  protoMsgs,
		Reactions: protoReactions,
		Events:    protoEvents,
		EpochKeys: epochKeys,
		Page:      1,
		HasMore:   false,
	})
}

// roomEventsToRaw converts per-room group_events rows to protocol
// RoomEvent raw messages for inclusion in SyncBatch.Events. Mirror of
// groupEventsToRaw for rooms. Phase 20.
func roomEventsToRaw(events []store.GroupEventRow, roomID string) []json.RawMessage {
	result := make([]json.RawMessage, 0, len(events))
	for _, e := range events {
		msg := protocol.RoomEvent{
			Type:   "room_event",
			Room:   roomID,
			Event:  e.Event,
			User:   e.User,
			By:     e.By,
			Reason: e.Reason,
			Name:   e.Name,
		}
		data, err := json.Marshal(msg)
		if err != nil {
			continue
		}
		result = append(result, data)
	}
	return result
}

// syncGroup sends a sync batch for a single group DM. Phase 14 extended
// this to also pack group_events (admin actions) alongside messages and
// reactions so clients that were offline during admin changes catch up
// on the event stream via sync_batch. The events table and messages
// table both live inside the per-group DB file, both use INTEGER unix
// second timestamps, and both are queried by the same sinceTS — one
// watermark, two data sources.
//
// A group may have new events even when no new messages exist (e.g. an
// admin /rename'd the group but nobody sent anything since), so the
// early return is gated on BOTH message count AND event count.
func (s *Server) syncGroup(c *Client, groupID string, sinceTS int64, limit int) {
	// Apply joined_at filter — new members only see post-join messages
	// and events. Mirrors syncRoom's first_seen gate. The wrapped-key
	// crypto model already prevents a new member from DECRYPTING pre-join
	// messages, but the server must also not SERVE them: timestamps,
	// sender IDs, and event replay (pre-join /promote, /rename, /kick
	// audit entries) are social-graph metadata leaks even without
	// plaintext. One raise here covers both branches of the sync batch
	// (GetGroupMessagesSince and GetGroupEventsSince) — both use the same
	// sinceTS watermark, so the filter is free on the events side.
	joinedAt, _ := s.store.GetUserGroupJoinedAt(c.UserID, groupID)
	if joinedAt > 0 && joinedAt > sinceTS {
		sinceTS = joinedAt
	}

	msgs, err := s.store.GetGroupMessagesSince(groupID, sinceTS, limit)
	if err != nil {
		s.logger.Error("sync group failed", "group", groupID, "error", err)
		return
	}

	// Phase 14: fetch recent group_events for replay. Best-effort — event
	// replay failures do not block the message sync path.
	events, eventsErr := s.store.GetGroupEventsSince(groupID, sinceTS)
	if eventsErr != nil {
		s.logger.Error("sync group events failed", "group", groupID, "error", eventsErr)
		// Fall through — we still want to deliver messages even if events
		// couldn't be fetched.
		events = nil
	}

	if len(msgs) == 0 && len(events) == 0 {
		return
	}

	// Group DMs carry their own wrapped keys -- no epoch_keys needed
	protoMsgs := storedToRawMessages(msgs, "", groupID)

	var protoReactions []json.RawMessage
	if msgIDs := collectMessageIDs(msgs); len(msgIDs) > 0 {
		if reactions, err := s.store.GetGroupReactionsForMessages(groupID, msgIDs); err == nil && len(reactions) > 0 {
			protoReactions = storedReactionsToRaw(reactions, "", groupID)
		}
	}

	var protoEvents []json.RawMessage
	if len(events) > 0 {
		protoEvents = groupEventsToRaw(events, groupID)
	}

	c.Encoder.Encode(protocol.SyncBatch{
		Type:      "sync_batch",
		Messages:  protoMsgs,
		Reactions: protoReactions,
		Events:    protoEvents,
		EpochKeys: nil,
		Page:      1,
		HasMore:   false,
	})
}

// groupEventsToRaw converts per-group group_events rows to protocol
// GroupEvent raw messages for inclusion in SyncBatch.Events. Clients
// route each entry through the same dispatch path used for live
// group_event broadcasts, so persisted replay and live delivery produce
// identical local state.
func groupEventsToRaw(events []store.GroupEventRow, groupID string) []json.RawMessage {
	result := make([]json.RawMessage, 0, len(events))
	for _, e := range events {
		msg := protocol.GroupEvent{
			Type:   "group_event",
			Group:  groupID,
			Event:  e.Event,
			User:   e.User,
			By:     e.By,
			Reason: e.Reason,
			Name:   e.Name,
			Quiet:  e.Quiet,
		}
		data, _ := json.Marshal(msg)
		result = append(result, json.RawMessage(data))
	}
	return result
}

// syncDM sends a sync batch for a single 1:1 DM, respecting the per-user
// history cutoff. After the cutoff, the leaver sees nothing.
func (s *Server) syncDM(c *Client, dmID string, sinceTS int64, limit int) {
	msgs, err := s.store.GetDMMessagesSince(dmID, c.UserID, sinceTS, limit)
	if err != nil {
		s.logger.Error("sync DM failed", "dm", dmID, "error", err)
		return
	}

	if len(msgs) == 0 {
		return
	}

	// 1:1 DMs carry their own wrapped keys -- no epoch_keys needed
	protoMsgs := storedToRawDMMessages(msgs, dmID)

	var protoReactions []json.RawMessage
	if msgIDs := collectMessageIDs(msgs); len(msgIDs) > 0 {
		if reactions, err := s.store.GetDMReactionsForMessages(dmID, msgIDs); err == nil && len(reactions) > 0 {
			protoReactions = storedReactionsToRaw(reactions, "", "")
			// Patch DM field onto each reaction (storedReactionsToRaw takes room/group)
			for i := range protoReactions {
				var r protocol.Reaction
				if json.Unmarshal(protoReactions[i], &r) == nil {
					r.DM = dmID
					data, _ := json.Marshal(r)
					protoReactions[i] = data
				}
			}
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

// storedToRawDMMessages converts stored messages to protocol DM raw messages.
func storedToRawDMMessages(msgs []store.StoredMessage, dmID string) []json.RawMessage {
	result := make([]json.RawMessage, 0, len(msgs))
	for _, m := range msgs {
		var data []byte
		if m.Deleted {
			tombstone := protocol.Deleted{
				Type:      "deleted",
				ID:        m.ID,
				DeletedBy: m.Sender,
				TS:        m.TS,
				DM:        dmID,
			}
			data, _ = json.Marshal(tombstone)
		} else {
			msg := protocol.DM{
				Type:        "dm",
				ID:          m.ID,
				From:        m.Sender,
				DM:          dmID,
				TS:          m.TS,
				WrappedKeys: m.WrappedKeys,
				Payload:     m.Payload,
				FileIDs:     m.FileIDs,
				Signature:   m.Signature,
				EditedAt:    m.EditedAt, // Phase 15
			}
			data, _ = json.Marshal(msg)
		}
		result = append(result, json.RawMessage(data))
	}
	return result
}

// handleHistory processes a history (scroll-back) request.
func (s *Server) handleHistory(c *Client, raw json.RawMessage) {
	if !s.limiter.allowPerMinute("history:"+c.UserID, s.cfg.Server.RateLimits.HistoryPerMinute) {
		c.Encoder.Encode(protocol.Error{Type: "error", Code: protocol.ErrRateLimited, Message: "Too many requests — wait a moment"})
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
		inRoom := s.store != nil && s.store.IsRoomMemberByID(req.Room, c.UserID)
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
		firstSeen, firstEpoch, _ := s.store.GetUserRoom(c.UserID, req.Room)
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
			keys, err := s.store.GetEpochKeysForUser(req.Room, c.UserID, minEpoch, maxEpoch)
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

	} else if req.Group != "" {
		// Verify membership
		isMember, err := s.store.IsGroupMember(req.Group, c.UserID)
		if err != nil || !isMember {
			c.Encoder.Encode(protocol.Error{
				Type: "error", Code: protocol.ErrUnknownGroup,
				Message: "You are not a member of this group",
			})
			return
		}

		msgs, err := s.store.GetGroupMessagesBefore(req.Group, req.Before, limit+1)
		if err != nil {
			s.logger.Error("history failed", "group", req.Group, "error", err)
			return
		}

		// Apply joined_at filter — post-query filter (not sinceTS raise)
		// because GetGroupMessagesBefore is id+limit shaped, not
		// timestamp-shaped. Mirrors the rooms history branch which does
		// the same post-filter on first_seen/first_epoch. Messages at
		// exactly joined_at are kept (strict less-than).
		joinedAt, _ := s.store.GetUserGroupJoinedAt(c.UserID, req.Group)
		if joinedAt > 0 {
			filtered := msgs[:0]
			for _, m := range msgs {
				if m.TS < joinedAt {
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

		var groupReactions []json.RawMessage
		if msgIDs := collectMessageIDs(msgs); len(msgIDs) > 0 {
			if reactions, err := s.store.GetGroupReactionsForMessages(req.Group, msgIDs); err == nil && len(reactions) > 0 {
				groupReactions = storedReactionsToRaw(reactions, "", req.Group)
			}
		}

		c.Encoder.Encode(protocol.HistoryResult{
			Type:      "history_result",
			Group:     req.Group,
			Messages:  storedToRawMessages(msgs, "", req.Group),
			Reactions: groupReactions,
			HasMore:   hasMore,
		})

	} else if req.DM != "" {
		// Verify caller is a party to this DM
		dm, err := s.store.GetDirectMessage(req.DM)
		if err != nil || dm == nil || (dm.UserA != c.UserID && dm.UserB != c.UserID) {
			c.Encoder.Encode(protocol.Error{
				Type: "error", Code: protocol.ErrUnknownDM,
				Message: "You are not a party to this DM",
			})
			return
		}

		msgs, err := s.store.GetDMMessagesBeforeForUser(req.DM, c.UserID, req.Before, limit+1)
		if err != nil {
			s.logger.Error("history failed", "dm", req.DM, "error", err)
			return
		}

		hasMore := len(msgs) > limit
		if hasMore {
			msgs = msgs[:limit]
		}

		var dmReactions []json.RawMessage
		if msgIDs := collectMessageIDs(msgs); len(msgIDs) > 0 {
			if reactions, err := s.store.GetDMReactionsForMessages(req.DM, msgIDs); err == nil && len(reactions) > 0 {
				dmReactions = storedReactionsToRaw(reactions, "", "")
				// Patch DM field
				for i := range dmReactions {
					var r protocol.Reaction
					if json.Unmarshal(dmReactions[i], &r) == nil {
						r.DM = req.DM
						data, _ := json.Marshal(r)
						dmReactions[i] = data
					}
				}
			}
		}

		c.Encoder.Encode(protocol.HistoryResult{
			Type:      "history_result",
			DM:        req.DM,
			Messages:  storedToRawDMMessages(msgs, req.DM),
			Reactions: dmReactions,
			HasMore:   hasMore,
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
func storedReactionsToRaw(reactions []store.StoredReaction, roomID, groupID string) []json.RawMessage {
	result := make([]json.RawMessage, 0, len(reactions))
	for _, r := range reactions {
		msg := protocol.Reaction{
			Type:        "reaction",
			ReactionID:  r.ReactionID,
			ID:          r.MessageID,
			Room:        roomID,
			Group:       groupID,
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

func storedToRawMessages(msgs []store.StoredMessage, roomID, groupID string) []json.RawMessage {
	result := make([]json.RawMessage, 0, len(msgs))

	for _, m := range msgs {
		var data []byte

		if m.Deleted {
			tombstone := protocol.Deleted{
				Type:      "deleted",
				ID:        m.ID,
				DeletedBy: m.Sender, // sender field repurposed for deleted_by on tombstones
				TS:        m.TS,
				Room:      roomID,
				Group:     groupID,
			}
			data, _ = json.Marshal(tombstone)
		} else if roomID != "" {
			msg := protocol.Message{
				Type:      "message",
				ID:        m.ID,
				From:      m.Sender,
				Room:      roomID,
				TS:        m.TS,
				Epoch:     m.Epoch,
				Payload:   m.Payload,
				FileIDs:   m.FileIDs,
				Signature: m.Signature,
				EditedAt:  m.EditedAt, // Phase 15: 0 on unedited rows (omitempty)
			}
			data, _ = json.Marshal(msg)
		} else {
			msg := protocol.GroupMessage{
				Type:        "group_message",
				ID:          m.ID,
				From:        m.Sender,
				Group:       groupID,
				TS:          m.TS,
				WrappedKeys: m.WrappedKeys,
				Payload:     m.Payload,
				FileIDs:     m.FileIDs,
				Signature:   m.Signature,
				EditedAt:    m.EditedAt, // Phase 15
			}
			data, _ = json.Marshal(msg)
		}

		result = append(result, json.RawMessage(data))
	}

	return result
}
