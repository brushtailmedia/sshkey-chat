package server

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/brushtailmedia/sshkey/internal/protocol"
	"github.com/brushtailmedia/sshkey/internal/store"
)

const maxPayloadBytes = 16 * 1024 // 16KB max message body

// allCapabilities is the full set of capabilities the server supports.
var allCapabilities = []string{
	"typing",
	"reactions",
	"read_receipts",
	"file_transfer",
	"link_previews",
	"presence",
	"pins",
	"mentions",
	"unread",
	"status",
	"signatures",
}

// handleSession runs the protocol session on an accepted SSH channel.
// dlChanCh delivers the download channel (Channel 2) once the client opens
// it; may remain empty if the client never opens it.
func (s *Server) handleSession(username string, conn *ssh.ServerConn, ch ssh.Channel, dlChanCh <-chan ssh.Channel) {
	defer ch.Close()

	enc := protocol.NewEncoder(ch)
	dec := protocol.NewDecoder(ch)

	// Step 1: Send server_hello
	err := enc.Encode(protocol.ServerHello{
		Type:         "server_hello",
		Protocol:     "sshkey-chat",
		Version:      1,
		ServerID:     s.cfg.Server.Server.Bind,
		Capabilities: allCapabilities,
	})
	if err != nil {
		s.logger.Error("failed to send server_hello", "user", username, "error", err)
		return
	}

	// Step 2: Wait for client_hello (2 second timeout)
	type helloResult struct {
		hello protocol.ClientHello
		err   error
	}
	helloCh := make(chan helloResult, 1)
	go func() {
		var raw json.RawMessage
		raw, err := dec.DecodeRaw()
		if err != nil {
			helloCh <- helloResult{err: err}
			return
		}
		msgType, err := protocol.TypeOf(raw)
		if err != nil || msgType != "client_hello" {
			helloCh <- helloResult{err: io.ErrUnexpectedEOF}
			return
		}
		var hello protocol.ClientHello
		if err := json.Unmarshal(raw, &hello); err != nil {
			helloCh <- helloResult{err: err}
			return
		}
		helloCh <- helloResult{hello: hello}
	}()

	var clientHello protocol.ClientHello
	select {
	case result := <-helloCh:
		if result.err != nil {
			// Not a protocol client -- send install banner
			s.sendInstallBanner(enc)
			return
		}
		clientHello = result.hello
	case <-time.After(2 * time.Second):
		// Timeout -- not a protocol client
		s.sendInstallBanner(enc)
		return
	}

	// Validate client_hello
	if clientHello.Protocol != "sshkey-chat" || clientHello.Version != 1 {
		s.logger.Warn("invalid client_hello",
			"user", username,
			"protocol", clientHello.Protocol,
			"version", clientHello.Version,
		)
		s.sendInstallBanner(enc)
		return
	}

	// Negotiate capabilities
	active := negotiateCapabilities(clientHello.Capabilities)

	// Build room and conversation lists for this user
	s.cfg.RLock()
	user := s.cfg.Users[username]
	rooms := user.Rooms
	isAdmin := false
	for _, a := range s.cfg.Server.Server.Admins {
		if a == username {
			isAdmin = true
			break
		}
	}
	s.cfg.RUnlock()

	// Conversation IDs for the welcome envelope. Rich info (members, names)
	// arrives separately via the conversation_list message sent just after
	// welcome in the connect sequence.
	var conversations []string
	if s.store != nil {
		if convs, err := s.store.GetUserConversations(username); err == nil {
			for _, c := range convs {
				conversations = append(conversations, c.ID)
			}
		}
	}

	// Step 3: Send welcome
	pendingSync := clientHello.LastSyncedAt != "" // sync follows if client has a last_synced_at
	err = enc.Encode(protocol.Welcome{
		Type:               "welcome",
		User:               username,
		DisplayName:        user.DisplayName,
		Admin:              isAdmin,
		Rooms:              rooms,
		Conversations:      conversations,
		PendingSync:        pendingSync,
		ActiveCapabilities: active,
	})
	if err != nil {
		s.logger.Error("failed to send welcome", "user", username, "error", err)
		return
	}

	s.logger.Info("handshake complete",
		"user", username,
		"device", clientHello.DeviceID,
		"capabilities", active,
	)

	// Check device revocation and register
	if s.store != nil {
		revoked, err := s.store.IsDeviceRevoked(username, clientHello.DeviceID)
		if err == nil && revoked {
			enc.Encode(protocol.DeviceRevoked{
				Type:     "device_revoked",
				DeviceID: clientHello.DeviceID,
				Reason:   "admin_action",
			})
			return
		}

		deviceCount, err := s.store.UpsertDevice(username, clientHello.DeviceID)
		if err != nil {
			s.logger.Error("device registration failed", "user", username, "error", err)
		} else if deviceCount > s.cfg.Server.Devices.MaxPerUser {
			enc.Encode(protocol.Error{
				Type:    "error",
				Code:    protocol.ErrDeviceLimitExceeded,
				Message: "Too many devices registered. Revoke an old device to continue.",
			})
			return
		}
	}

	// Register client
	client := &Client{
		Username:     username,
		DeviceID:     clientHello.DeviceID,
		Encoder:      enc,
		Decoder:      dec,
		Channel:      ch,
		Conn:         conn,
		Capabilities: active,
	}

	s.mu.Lock()
	s.clients[clientHello.DeviceID] = client
	s.mu.Unlock()

	// Attach the download channel if the client opened Channel 2. The
	// client opens Channels 1-3 before sending client_hello, so by now the
	// download channel should already be on dlChanCh. Wait briefly to
	// tolerate any reordering, then proceed without it (downloads will
	// fail, uploads still work via Channel 3).
	select {
	case dlCh := <-dlChanCh:
		s.mu.Lock()
		client.DownloadChannel = dlCh
		s.mu.Unlock()
	case <-time.After(500 * time.Millisecond):
		s.logger.Debug("no download channel", "user", username, "device", clientHello.DeviceID)
	}

	defer func() {
		s.mu.Lock()
		delete(s.clients, clientHello.DeviceID)
		s.mu.Unlock()

		// Clean up any pending uploads for this user. If the client
		// disconnected mid-upload, these entries would leak in the map
		// and the associated files (if partially written) are cleaned
		// up by handleBinaryChannel's error path.
		s.files.mu.Lock()
		for id, p := range s.files.uploads {
			if p.user == client.Username {
				delete(s.files.uploads, id)
			}
		}
		s.files.mu.Unlock()
	}()

	// Send room list
	s.sendRoomList(client)

	// Send conversation list (DMs)
	s.sendConversationList(client)

	// Send profiles for visible users
	s.sendProfiles(client)

	// Send retired users list so client can mark historical messages correctly
	s.sendRetiredUsers(client)

	// Send current epoch keys for rooms
	s.sendEpochKeys(client)

	// Send unread counts
	s.sendUnreadCounts(client)

	// Send pinned messages per room
	s.sendPins(client)

	// Send sync batches (catch-up after reconnect)
	s.sendSync(client, clientHello.LastSyncedAt)

	// Broadcast online presence
	s.broadcastPresence(username, "online")
	defer s.broadcastPresence(username, "offline")

	// Trigger initial epoch rotation for fresh rooms (after message loop can handle responses)
	go func() {
		s.cfg.RLock()
		rooms := s.cfg.Users[username].Rooms
		s.cfg.RUnlock()

		for _, room := range rooms {
			if s.epochs.currentEpochNum(room) == 0 {
				s.triggerEpochRotation(client, room, "initial")
			}
		}
	}()

	// Main message loop
	s.messageLoop(client)
}

// sendInstallBanner sends the install instructions and closes.
func (s *Server) sendInstallBanner(enc *protocol.Encoder) {
	enc.Encode(map[string]string{"type": "error", "code": "client_required", "message": "This server requires the sshkey-chat client. Install: https://sshkey.chat"})
}

// negotiateCapabilities returns the intersection of server and client capabilities.
func negotiateCapabilities(requested []string) []string {
	serverSet := make(map[string]bool, len(allCapabilities))
	for _, c := range allCapabilities {
		serverSet[c] = true
	}

	var active []string
	for _, c := range requested {
		if serverSet[c] {
			active = append(active, c)
		}
	}
	return active
}

// sendRoomList sends the room_list message to the client.
func (s *Server) sendRoomList(c *Client) {
	s.cfg.RLock()
	defer s.cfg.RUnlock()

	var rooms []protocol.RoomInfo
	for _, roomName := range s.cfg.Users[c.Username].Rooms {
		room := s.cfg.Rooms[roomName]
		// Count members in this room
		memberCount := 0
		for _, u := range s.cfg.Users {
			for _, r := range u.Rooms {
				if r == roomName {
					memberCount++
					break
				}
			}
		}
		rooms = append(rooms, protocol.RoomInfo{
			Name:    roomName,
			Topic:   room.Topic,
			Members: memberCount,
		})
	}

	c.Encoder.Encode(protocol.RoomList{
		Type:  "room_list",
		Rooms: rooms,
	})
}

// sendConversationList sends the conversation_list message to the client.
func (s *Server) sendConversationList(c *Client) {
	if s.store == nil {
		return
	}

	convs, err := s.store.GetUserConversations(c.Username)
	if err != nil {
		s.logger.Error("failed to get conversations", "user", c.Username, "error", err)
		return
	}

	if len(convs) == 0 {
		return
	}

	var convInfos []protocol.ConversationInfo
	for _, conv := range convs {
		convInfos = append(convInfos, protocol.ConversationInfo{
			ID:      conv.ID,
			Members: conv.Members,
			Name:    conv.Name,
		})
	}

	c.Encoder.Encode(protocol.ConversationList{
		Type:          "conversation_list",
		Conversations: convInfos,
	})
}

// sendProfiles sends profile messages for all users visible to this client
// (shared rooms + shared DM conversations).
func (s *Server) sendProfiles(c *Client) {
	// Collect all visible usernames
	visible := make(map[string]bool)

	s.cfg.RLock()
	clientRooms := make(map[string]bool)
	for _, r := range s.cfg.Users[c.Username].Rooms {
		clientRooms[r] = true
	}
	for username, user := range s.cfg.Users {
		for _, r := range user.Rooms {
			if clientRooms[r] {
				visible[username] = true
				break
			}
		}
	}
	s.cfg.RUnlock()

	// Also include DM conversation members
	if s.store != nil {
		convs, err := s.store.GetUserConversations(c.Username)
		if err == nil {
			for _, conv := range convs {
				for _, m := range conv.Members {
					visible[m] = true
				}
			}
		}
	}

	// Send profiles
	s.cfg.RLock()
	defer s.cfg.RUnlock()

	adminSet := make(map[string]bool, len(s.cfg.Server.Server.Admins))
	for _, a := range s.cfg.Server.Server.Admins {
		adminSet[a] = true
	}

	for username := range visible {
		user, ok := s.cfg.Users[username]
		if !ok {
			continue
		}
		parsed, _, _, _, err := ssh.ParseAuthorizedKey([]byte(user.Key))
		if err != nil {
			continue
		}

		displayName := user.DisplayName
		avatarID := ""
		// Merge stored profile data (avatar, display_name overrides from
		// set_profile) with config-based defaults. DB values take precedence
		// for fields users can customize at runtime.
		if s.store != nil {
			var dbDisplayName, dbAvatarID sql.NullString
			s.store.UsersDB().QueryRow(
				`SELECT display_name, avatar_id FROM profiles WHERE user = ?`,
				username).Scan(&dbDisplayName, &dbAvatarID)
			if dbDisplayName.Valid && dbDisplayName.String != "" {
				displayName = dbDisplayName.String
			}
			if dbAvatarID.Valid {
				avatarID = dbAvatarID.String
			}
		}

		c.Encoder.Encode(protocol.Profile{
			Type:           "profile",
			User:           username,
			DisplayName:    displayName,
			AvatarID:       avatarID,
			PubKey:         user.Key,
			KeyFingerprint: ssh.FingerprintSHA256(parsed),
			Admin:          adminSet[username],
			Retired:        user.Retired,
			RetiredAt:      user.RetiredAt,
		})
	}
}

// messageLoop reads and dispatches messages from the client.
func (s *Server) messageLoop(c *Client) {
	for {
		raw, err := c.Decoder.DecodeRaw()
		if err != nil {
			if err != io.EOF {
				s.logger.Error("read error", "user", c.Username, "error", err)
			}
			return
		}

		msgType, err := protocol.TypeOf(raw)
		if err != nil {
			s.logger.Warn("invalid message", "user", c.Username, "error", err)
			continue
		}

		s.handleMessage(c, msgType, raw)
	}
}

// handleMessage dispatches a decoded message by type.
func (s *Server) handleMessage(c *Client, msgType string, raw json.RawMessage) {
	switch msgType {
	case "send":
		s.handleSend(c, raw)
	case "send_dm":
		s.handleSendDM(c, raw)
	case "create_dm":
		s.handleCreateDM(c, raw)
	case "epoch_rotate":
		s.handleEpochRotate(c, raw)
	case "delete":
		s.handleDelete(c, raw)
	case "leave_conversation":
		s.handleLeaveConversation(c, raw)
	case "rename_conversation":
		s.handleRenameConversation(c, raw)
	case "history":
		s.handleHistory(c, raw)
	case "react":
		s.handleReact(c, raw)
	case "unreact":
		s.handleUnreact(c, raw)
	case "pin":
		s.handlePin(c, raw)
	case "unpin":
		s.handleUnpin(c, raw)
	case "set_profile":
		s.handleSetProfile(c, raw)
	case "set_status":
		s.handleSetStatus(c, raw)
	case "retire_me":
		s.handleRetireMe(c, raw)
	case "list_devices":
		s.handleListDevices(c, raw)
	case "revoke_device":
		s.handleRevokeDevice(c, raw)
	case "list_pending_keys":
		s.handleListPendingKeys(c)
	case "upload_start":
		s.handleUploadStart(c, raw)
	case "download":
		s.handleDownload(c, raw)
	case "push_register":
		s.handlePushRegister(c, raw)
	case "typing":
		s.handleTyping(c, raw)
	case "read":
		s.handleRead(c, raw)
	default:
		s.logger.Debug("unhandled message type", "user", c.Username, "type", msgType)
	}
}

// handleSend processes a room message.
func (s *Server) handleSend(c *Client, raw json.RawMessage) {
	// Rate limit
	if !s.limiter.allow("msg:"+c.Username, float64(s.cfg.Server.RateLimits.MessagesPerSecond)) {
		c.Encoder.Encode(protocol.Error{Type: "error", Code: protocol.ErrRateLimited, Message: "Message rate limit exceeded"})
		return
	}

	// Check payload size (raw JSON includes overhead, but payload is the bulk)
	if len(raw) > maxPayloadBytes {
		c.Encoder.Encode(protocol.Error{Type: "error", Code: protocol.ErrMessageTooLarge, Message: "Message exceeds 16KB limit"})
		return
	}

	var msg protocol.Send
	if err := json.Unmarshal(raw, &msg); err != nil {
		c.Encoder.Encode(protocol.Error{Type: "error", Code: "invalid_message", Message: "malformed send"})
		return
	}

	// Verify user is in this room
	s.cfg.RLock()
	user := s.cfg.Users[c.Username]
	s.cfg.RUnlock()

	inRoom := false
	for _, r := range user.Rooms {
		if r == msg.Room {
			inRoom = true
			break
		}
	}
	if !inRoom {
		c.Encoder.Encode(protocol.Error{
			Type:    "error",
			Code:    protocol.ErrNotAuthorized,
			Message: "You don't have access to room: " + msg.Room,
		})
		return
	}

	// Validate epoch
	currentEpoch := s.epochs.currentEpochNum(msg.Room)
	confirmedEpoch := s.epochs.confirmedEpochNum(msg.Room)

	if currentEpoch > 0 {
		// Reject epochs older than the grace window (current - 1)
		if msg.Epoch < currentEpoch-1 {
			c.Encoder.Encode(protocol.Error{
				Type:    "error",
				Code:    protocol.ErrInvalidEpoch,
				Message: "Epoch too old (outside two-epoch grace window)",
			})
			return
		}
		// Reject epochs beyond what's been confirmed and distributed.
		// Prevents a client from sending with a pending key that might get rejected.
		if confirmedEpoch > 0 && msg.Epoch > confirmedEpoch {
			c.Encoder.Encode(protocol.Error{
				Type:    "error",
				Code:    protocol.ErrInvalidEpoch,
				Message: "Epoch not yet confirmed. Wait for epoch_confirmed before sending.",
			})
			return
		}
	}

	// Assign server-generated ID and timestamp
	outMsg := protocol.Message{
		Type:      "message",
		ID:        generateID("msg_"),
		From:      c.Username,
		Room:      msg.Room,
		TS:        time.Now().Unix(),
		Epoch:     msg.Epoch,
		Payload:   msg.Payload,
		FileIDs:   msg.FileIDs,
		Signature: msg.Signature,
	}

	// Store in room DB
	if s.store != nil {
		err := s.store.InsertRoomMessage(msg.Room, store.StoredMessage{
			ID:        outMsg.ID,
			Sender:    outMsg.From,
			TS:        outMsg.TS,
			Epoch:     outMsg.Epoch,
			Payload:   outMsg.Payload,
			FileIDs:   outMsg.FileIDs,
			Signature: outMsg.Signature,
		})
		if err != nil {
			s.logger.Error("failed to store message", "room", msg.Room, "error", err)
		}
	}

	// Broadcast to all connected clients in this room
	s.broadcastToRoom(msg.Room, outMsg)

	// Check if rotation is needed
	s.checkRotationNeeded(c, msg.Room)

	// Notify offline room members via push
	go s.notifyOfflineUsers(s.getRoomMembers(msg.Room))
}

// handleSendDM processes a direct message.
func (s *Server) handleSendDM(c *Client, raw json.RawMessage) {
	if len(raw) > maxPayloadBytes {
		c.Encoder.Encode(protocol.Error{Type: "error", Code: protocol.ErrMessageTooLarge, Message: "Message exceeds 16KB limit"})
		return
	}

	var msg protocol.SendDM
	if err := json.Unmarshal(raw, &msg); err != nil {
		c.Encoder.Encode(protocol.Error{Type: "error", Code: "invalid_message", Message: "malformed send_dm"})
		return
	}

	// Validate conversation exists and user is a member
	if s.store != nil {
		isMember, err := s.store.IsConversationMember(msg.Conversation, c.Username)
		if err != nil || !isMember {
			c.Encoder.Encode(protocol.Error{
				Type:    "error",
				Code:    protocol.ErrUnknownConversation,
				Message: "You are not a member of this conversation",
			})
			return
		}

		// Validate wrapped_keys match conversation member list
		members, err := s.store.GetConversationMembers(msg.Conversation)
		if err == nil {
			// Reject if any member is retired (applies to 1:1 DMs where the
			// retired user is preserved in conversation_members). Group DMs
			// have retired members removed at retirement time, so this check
			// is effectively a 1:1-only safeguard.
			if retired := s.findRetiredMember(members); retired != "" {
				c.Encoder.Encode(protocol.Error{
					Type:    "error",
					Code:    protocol.ErrUserRetired,
					Message: fmt.Sprintf("Cannot send — %s's account has been retired", retired),
				})
				return
			}

			memberSet := make(map[string]bool, len(members))
			for _, m := range members {
				memberSet[m] = true
			}
			wrappedSet := make(map[string]bool, len(msg.WrappedKeys))
			for k := range msg.WrappedKeys {
				wrappedSet[k] = true
			}
			if len(memberSet) != len(wrappedSet) {
				c.Encoder.Encode(protocol.Error{
					Type:    "error",
					Code:    protocol.ErrInvalidWrappedKeys,
					Message: "wrapped_keys must match conversation member list",
				})
				return
			}
			for m := range memberSet {
				if !wrappedSet[m] {
					c.Encoder.Encode(protocol.Error{
						Type:    "error",
						Code:    protocol.ErrInvalidWrappedKeys,
						Message: "wrapped_keys must match conversation member list",
					})
					return
				}
			}
		}
	}

	outMsg := protocol.DM{
		Type:         "dm",
		ID:           generateID("msg_"),
		From:         c.Username,
		Conversation: msg.Conversation,
		TS:           time.Now().Unix(),
		WrappedKeys:  msg.WrappedKeys,
		Payload:      msg.Payload,
		FileIDs:      msg.FileIDs,
		Signature:    msg.Signature,
	}

	// Store in conversation DB
	if s.store != nil {
		err := s.store.InsertConvMessage(msg.Conversation, store.StoredMessage{
			ID:          outMsg.ID,
			Sender:      outMsg.From,
			TS:          outMsg.TS,
			Payload:     outMsg.Payload,
			FileIDs:     outMsg.FileIDs,
			Signature:   outMsg.Signature,
			WrappedKeys: outMsg.WrappedKeys,
		})
		if err != nil {
			s.logger.Error("failed to store DM", "conversation", msg.Conversation, "error", err)
		}
	}

	// Broadcast to all connected clients in this conversation
	s.broadcastToConversation(msg.Conversation, outMsg)

	// Notify offline conversation members via push
	if s.store != nil {
		members, err := s.store.GetConversationMembers(msg.Conversation)
		if err == nil {
			go s.notifyOfflineUsers(members)
		}
	}
}

// handleTyping broadcasts a typing indicator to others (not the sender).
func (s *Server) handleTyping(c *Client, raw json.RawMessage) {
	if !s.limiter.allow("typing:"+c.Username, float64(s.cfg.Server.RateLimits.TypingPerSecond)) {
		return // silently dropped per spec
	}

	var msg protocol.Typing
	if err := json.Unmarshal(raw, &msg); err != nil {
		return
	}

	// Track typing for server-side expiry
	s.typing.Touch(c.Username, msg.Room, msg.Conversation)

	out := protocol.Typing{
		Type:         "typing",
		Room:         msg.Room,
		Conversation: msg.Conversation,
		User:         c.Username,
	}

	if msg.Room != "" {
		s.broadcastToRoomExcept(msg.Room, c.DeviceID, out)
	} else if msg.Conversation != "" {
		s.broadcastToConversationExcept(msg.Conversation, c.DeviceID, out)
	}
}

// handleRead broadcasts a read receipt and stores the position.
func (s *Server) handleRead(c *Client, raw json.RawMessage) {
	var msg protocol.Read
	if err := json.Unmarshal(raw, &msg); err != nil {
		return
	}

	// Store read position
	if s.store != nil {
		s.store.SetReadPosition(c.Username, c.DeviceID, msg.Room, msg.Conversation, msg.LastRead)
	}

	out := protocol.Read{
		Type:         "read",
		Room:         msg.Room,
		Conversation: msg.Conversation,
		User:         c.Username,
		LastRead:     msg.LastRead,
	}

	if msg.Room != "" {
		s.broadcastToRoomExcept(msg.Room, c.DeviceID, out)
	} else if msg.Conversation != "" {
		s.broadcastToConversationExcept(msg.Conversation, c.DeviceID, out)
	}
}

// handleReact processes a reaction.
func (s *Server) handleReact(c *Client, raw json.RawMessage) {
	var msg protocol.React
	if err := json.Unmarshal(raw, &msg); err != nil {
		c.Encoder.Encode(protocol.Error{Type: "error", Code: "invalid_message", Message: "malformed react"})
		return
	}

	// Reject DM reactions targeting retired members (1:1 DM case)
	if msg.Conversation != "" && s.store != nil {
		if members, err := s.store.GetConversationMembers(msg.Conversation); err == nil {
			if retired := s.findRetiredMember(members); retired != "" {
				c.Encoder.Encode(protocol.Error{
					Type:    "error",
					Code:    protocol.ErrUserRetired,
					Message: fmt.Sprintf("Cannot react — %s's account has been retired", retired),
				})
				return
			}
		}
	}

	reactionID := generateID("react_")

	reaction := protocol.Reaction{
		Type:         "reaction",
		ReactionID:   reactionID,
		ID:           msg.ID,
		Room:         msg.Room,
		Conversation: msg.Conversation,
		User:         c.Username,
		TS:           time.Now().Unix(),
		Epoch:        msg.Epoch,
		WrappedKeys:  msg.WrappedKeys,
		Payload:      msg.Payload,
		Signature:    msg.Signature,
	}

	// Store in the appropriate DB
	if s.store != nil {
		if msg.Room != "" {
			db, err := s.store.RoomDB(msg.Room)
			if err == nil {
				db.Exec(`INSERT INTO reactions (reaction_id, message_id, user, ts, epoch, payload, signature)
					VALUES (?, ?, ?, ?, ?, ?, ?)`,
					reactionID, msg.ID, c.Username, reaction.TS, msg.Epoch, msg.Payload, msg.Signature)
			}
		} else if msg.Conversation != "" {
			db, err := s.store.ConvDB(msg.Conversation)
			if err == nil {
				wrappedKeys := ""
				if len(msg.WrappedKeys) > 0 {
					data, _ := json.Marshal(msg.WrappedKeys)
					wrappedKeys = string(data)
				}
				db.Exec(`INSERT INTO reactions (reaction_id, message_id, user, ts, epoch, payload, signature, wrapped_keys)
					VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
					reactionID, msg.ID, c.Username, reaction.TS, msg.Epoch, msg.Payload, msg.Signature, wrappedKeys)
			}
		}
	}

	// Broadcast
	if msg.Room != "" {
		s.broadcastToRoom(msg.Room, reaction)
	} else if msg.Conversation != "" {
		s.broadcastToConversation(msg.Conversation, reaction)
	}
}

// handleUnreact processes a reaction removal.
func (s *Server) handleUnreact(c *Client, raw json.RawMessage) {
	var msg protocol.Unreact
	if err := json.Unmarshal(raw, &msg); err != nil {
		return
	}

	// Look up the reaction to find its target and room/conversation
	if s.store == nil {
		return
	}

	// Search room DBs and conv DBs for this reaction
	// For now, we need the room/conversation context to broadcast the removal.
	// The client should include this context. Let's search for it.
	var targetID, room, conversation, user string
	var found bool

	s.mu.RLock()
	s.cfg.RLock()
	rooms := s.cfg.Users[c.Username].Rooms
	s.cfg.RUnlock()
	s.mu.RUnlock()

	for _, r := range rooms {
		db, err := s.store.RoomDB(r)
		if err != nil {
			continue
		}
		err = db.QueryRow(`SELECT message_id, user FROM reactions WHERE reaction_id = ?`, msg.ReactionID).
			Scan(&targetID, &user)
		if err == nil && user == c.Username {
			room = r
			found = true
			db.Exec(`DELETE FROM reactions WHERE reaction_id = ?`, msg.ReactionID)
			break
		}
	}

	if !found {
		convs, err := s.store.GetUserConversations(c.Username)
		if err == nil {
			for _, conv := range convs {
				db, err := s.store.ConvDB(conv.ID)
				if err != nil {
					continue
				}
				err = db.QueryRow(`SELECT message_id, user FROM reactions WHERE reaction_id = ?`, msg.ReactionID).
					Scan(&targetID, &user)
				if err == nil && user == c.Username {
					conversation = conv.ID
					found = true
					db.Exec(`DELETE FROM reactions WHERE reaction_id = ?`, msg.ReactionID)
					break
				}
			}
		}
	}

	if !found {
		return
	}

	removed := protocol.ReactionRemoved{
		Type:         "reaction_removed",
		ReactionID:   msg.ReactionID,
		ID:           targetID,
		Room:         room,
		Conversation: conversation,
		User:         c.Username,
	}

	if room != "" {
		s.broadcastToRoom(room, removed)
	} else if conversation != "" {
		s.broadcastToConversation(conversation, removed)
	}
}

// handlePin processes a pin request.
func (s *Server) handlePin(c *Client, raw json.RawMessage) {
	var msg protocol.Pin
	if err := json.Unmarshal(raw, &msg); err != nil {
		return
	}

	if s.store != nil {
		db, err := s.store.RoomDB(msg.Room)
		if err == nil {
			db.Exec(`INSERT OR IGNORE INTO pins (message_id, pinned_by, ts) VALUES (?, ?, ?)`,
				msg.ID, c.Username, time.Now().Unix())
		}
	}

	s.broadcastToRoom(msg.Room, protocol.Pinned{
		Type:     "pinned",
		Room:     msg.Room,
		ID:       msg.ID,
		PinnedBy: c.Username,
		TS:       time.Now().Unix(),
	})
}

// handleUnpin processes an unpin request.
func (s *Server) handleUnpin(c *Client, raw json.RawMessage) {
	var msg protocol.Unpin
	if err := json.Unmarshal(raw, &msg); err != nil {
		return
	}

	if s.store != nil {
		db, err := s.store.RoomDB(msg.Room)
		if err == nil {
			db.Exec(`DELETE FROM pins WHERE message_id = ?`, msg.ID)
		}
	}

	s.broadcastToRoom(msg.Room, protocol.Unpinned{
		Type: "unpinned",
		Room: msg.Room,
		ID:   msg.ID,
	})
}

// handleCreateDM creates a new DM conversation.
func (s *Server) handleCreateDM(c *Client, raw json.RawMessage) {
	var msg protocol.CreateDM
	if err := json.Unmarshal(raw, &msg); err != nil {
		c.Encoder.Encode(protocol.Error{Type: "error", Code: "invalid_message", Message: "malformed create_dm"})
		return
	}

	// Add sender to members
	allMembers := append([]string{c.Username}, msg.Members...)

	// Reject if any proposed member is retired
	if retired := s.findRetiredMember(msg.Members); retired != "" {
		c.Encoder.Encode(protocol.Error{
			Type:    "error",
			Code:    protocol.ErrUserRetired,
			Message: fmt.Sprintf("Cannot create conversation — %s's account has been retired", retired),
		})
		return
	}

	// Max group DM size: 50 members
	if len(allMembers) > 50 {
		c.Encoder.Encode(protocol.Error{
			Type:    "error",
			Code:    "too_many_members",
			Message: "Group DMs are limited to 50 members. Use a room for larger groups.",
		})
		return
	}

	// Deduplicate 1:1 conversations
	if len(msg.Members) == 1 && s.store != nil {
		existing, err := s.store.FindOneOnOneConversation(c.Username, msg.Members[0])
		if err == nil && existing != "" {
			// Return existing conversation
			members, _ := s.store.GetConversationMembers(existing)
			c.Encoder.Encode(protocol.DMCreated{
				Type:         "dm_created",
				Conversation: existing,
				Members:      members,
			})
			return
		}
	}

	convID := generateID("conv_")

	if s.store != nil {
		if err := s.store.CreateConversation(convID, allMembers, msg.Name); err != nil {
			s.logger.Error("failed to create conversation", "error", err)
			c.Encoder.Encode(protocol.Error{Type: "error", Code: "internal", Message: "failed to create conversation"})
			return
		}
	}

	created := protocol.DMCreated{
		Type:         "dm_created",
		Conversation: convID,
		Members:      allMembers,
		Name:         msg.Name,
	}

	// Send dm_created to the creator
	c.Encoder.Encode(created)

	// Also notify all other online members so they know the conversation exists
	s.mu.RLock()
	memberSet := make(map[string]bool, len(allMembers))
	for _, m := range allMembers {
		memberSet[m] = true
	}
	for _, client := range s.clients {
		if client.DeviceID == c.DeviceID {
			continue // already sent to creator
		}
		if memberSet[client.Username] {
			client.Encoder.Encode(created)
		}
	}
	s.mu.RUnlock()

	s.logger.Info("conversation created",
		"conversation", convID,
		"created_by", c.Username,
		"members", allMembers,
	)
}

// handleDelete processes a message deletion.
func (s *Server) handleDelete(c *Client, raw json.RawMessage) {
	var msg protocol.Delete
	if err := json.Unmarshal(raw, &msg); err != nil {
		return
	}

	if s.store == nil {
		return
	}

	// Check if user is admin (admins can delete any room message)
	s.cfg.RLock()
	isAdmin := false
	for _, a := range s.cfg.Server.Server.Admins {
		if a == c.Username {
			isAdmin = true
			break
		}
	}
	rooms := s.cfg.Users[c.Username].Rooms
	s.cfg.RUnlock()

	// Search room DBs for the message
	for _, room := range rooms {
		db, err := s.store.RoomDB(room)
		if err != nil {
			continue
		}
		var sender string
		err = db.QueryRow(`SELECT sender FROM messages WHERE id = ? AND deleted = 0`, msg.ID).Scan(&sender)
		if err != nil {
			continue
		}

		// Permission check: own messages or admin
		if sender != c.Username && !isAdmin {
			c.Encoder.Encode(protocol.Error{
				Type:    "error",
				Code:    protocol.ErrNotAuthorized,
				Message: "You can only delete your own messages",
				Ref:     msg.ID,
			})
			return
		}

		if err := s.store.DeleteRoomMessage(room, msg.ID, c.Username); err != nil {
			s.logger.Error("delete failed", "room", room, "id", msg.ID, "error", err)
			return
		}

		s.broadcastToRoom(room, protocol.Deleted{
			Type:      "deleted",
			ID:        msg.ID,
			DeletedBy: c.Username,
			TS:        time.Now().Unix(),
			Room:      room,
		})
		return
	}

	// Search conversation DBs
	convs, err := s.store.GetUserConversations(c.Username)
	if err != nil {
		return
	}

	for _, conv := range convs {
		db, err := s.store.ConvDB(conv.ID)
		if err != nil {
			continue
		}
		var sender string
		err = db.QueryRow(`SELECT sender FROM messages WHERE id = ? AND deleted = 0`, msg.ID).Scan(&sender)
		if err != nil {
			continue
		}

		// DMs: own messages only, no admin override
		if sender != c.Username {
			c.Encoder.Encode(protocol.Error{
				Type:    "error",
				Code:    protocol.ErrNotAuthorized,
				Message: "You can only delete your own messages in DMs",
				Ref:     msg.ID,
			})
			return
		}

		if err := s.store.DeleteConvMessage(conv.ID, msg.ID, c.Username); err != nil {
			s.logger.Error("delete failed", "conversation", conv.ID, "id", msg.ID, "error", err)
			return
		}

		s.broadcastToConversation(conv.ID, protocol.Deleted{
			Type:         "deleted",
			ID:           msg.ID,
			DeletedBy:    c.Username,
			TS:           time.Now().Unix(),
			Conversation: conv.ID,
		})
		return
	}
}

// handleLeaveConversation removes a user from a DM conversation.
func (s *Server) handleLeaveConversation(c *Client, raw json.RawMessage) {
	var msg protocol.LeaveConversation
	if err := json.Unmarshal(raw, &msg); err != nil {
		return
	}

	if s.store != nil {
		if err := s.store.RemoveConversationMember(msg.Conversation, c.Username); err != nil {
			s.logger.Error("failed to leave conversation", "user", c.Username, "error", err)
			return
		}
	}

	// Notify remaining members
	s.broadcastToConversation(msg.Conversation, protocol.ConversationEvent{
		Type:         "conversation_event",
		Conversation: msg.Conversation,
		Event:        "leave",
		User:         c.Username,
	})

	s.logger.Info("conversation leave",
		"user", c.Username,
		"conversation", msg.Conversation,
	)
}

// handleRenameConversation updates a conversation's name and broadcasts.
func (s *Server) handleRenameConversation(c *Client, raw json.RawMessage) {
	var msg protocol.RenameConversation
	if err := json.Unmarshal(raw, &msg); err != nil {
		return
	}

	if s.store != nil {
		isMember, err := s.store.IsConversationMember(msg.Conversation, c.Username)
		if err != nil || !isMember {
			c.Encoder.Encode(protocol.Error{
				Type: "error", Code: protocol.ErrUnknownConversation,
				Message: "You are not a member of this conversation",
			})
			return
		}

		if err := s.store.RenameConversation(msg.Conversation, msg.Name); err != nil {
			s.logger.Error("failed to rename conversation", "conversation", msg.Conversation, "error", err)
			return
		}
	}

	s.broadcastToConversation(msg.Conversation, protocol.ConversationRenamed{
		Type:         "conversation_renamed",
		Conversation: msg.Conversation,
		Name:         msg.Name,
		RenamedBy:    c.Username,
	})

	s.logger.Info("conversation renamed",
		"conversation", msg.Conversation,
		"name", msg.Name,
		"renamed_by", c.Username,
	)
}

// handleSetProfile updates a user's profile and broadcasts.
func (s *Server) handleSetProfile(c *Client, raw json.RawMessage) {
	var msg protocol.SetProfile
	if err := json.Unmarshal(raw, &msg); err != nil {
		return
	}

	// Reject empty display name
	if msg.DisplayName == "" {
		c.Encoder.Encode(protocol.Error{
			Type:    "error",
			Code:    "invalid_profile",
			Message: "Display name cannot be empty",
		})
		return
	}

	// Check for duplicate display name across all users (case-insensitive)
	s.cfg.RLock()
	for username, user := range s.cfg.Users {
		if username == c.Username {
			continue // skip self
		}
		// Check against config display_name
		if strings.EqualFold(user.DisplayName, msg.DisplayName) {
			s.cfg.RUnlock()
			c.Encoder.Encode(protocol.Error{
				Type:    "error",
				Code:    "username_taken",
				Message: fmt.Sprintf("Display name %q is already in use", msg.DisplayName),
			})
			return
		}
		// Check against config username (can't take someone's username as your display name)
		if strings.EqualFold(username, msg.DisplayName) {
			s.cfg.RUnlock()
			c.Encoder.Encode(protocol.Error{
				Type:    "error",
				Code:    "username_taken",
				Message: fmt.Sprintf("Display name %q is already in use", msg.DisplayName),
			})
			return
		}
	}
	s.cfg.RUnlock()

	// Also check stored display names (from set_profile, which may differ from config)
	if s.store != nil {
		var existingUser string
		s.store.UsersDB().QueryRow(
			`SELECT user FROM profiles WHERE LOWER(display_name) = LOWER(?) AND user != ?`,
			msg.DisplayName, c.Username).Scan(&existingUser)
		if existingUser != "" {
			c.Encoder.Encode(protocol.Error{
				Type:    "error",
				Code:    "username_taken",
				Message: fmt.Sprintf("Display name %q is already in use", msg.DisplayName),
			})
			return
		}
	}

	// Update in store
	if s.store != nil {
		s.store.UsersDB().Exec(`
			INSERT INTO profiles (user, display_name, avatar_id) VALUES (?, ?, ?)
			ON CONFLICT (user) DO UPDATE SET display_name = excluded.display_name, avatar_id = excluded.avatar_id`,
			c.Username, msg.DisplayName, msg.AvatarID)
	}

	// Build profile message with pubkey
	s.cfg.RLock()
	user := s.cfg.Users[c.Username]
	s.cfg.RUnlock()

	parsed, _, _, _, err := ssh.ParseAuthorizedKey([]byte(user.Key))
	if err != nil {
		return
	}

	isAdmin := false
	for _, a := range s.cfg.Server.Server.Admins {
		if a == c.Username {
			isAdmin = true
			break
		}
	}

	profile := protocol.Profile{
		Type:           "profile",
		User:           c.Username,
		DisplayName:    msg.DisplayName,
		AvatarID:       msg.AvatarID,
		PubKey:         user.Key,
		KeyFingerprint: ssh.FingerprintSHA256(parsed),
		Admin:          isAdmin,
	}

	// Broadcast to all users who can see this user
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, client := range s.clients {
		client.Encoder.Encode(profile)
	}
}

// handleSetStatus updates a user's status text.
func (s *Server) handleSetStatus(c *Client, raw json.RawMessage) {
	var msg protocol.SetStatus
	if err := json.Unmarshal(raw, &msg); err != nil {
		return
	}

	if s.store != nil {
		s.store.UsersDB().Exec(`
			INSERT INTO profiles (user, status_text) VALUES (?, ?)
			ON CONFLICT (user) DO UPDATE SET status_text = excluded.status_text`,
			c.Username, msg.Text)
	}
}

// broadcastToRoom sends a message to all connected clients in a room.
func (s *Server) broadcastToRoom(room string, msg any) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	s.cfg.RLock()
	defer s.cfg.RUnlock()

	for _, client := range s.clients {
		user := s.cfg.Users[client.Username]
		for _, r := range user.Rooms {
			if r == room {
				client.Encoder.Encode(msg)
				break
			}
		}
	}
}

// broadcastToConversation sends a message to all connected clients in a conversation.
func (s *Server) broadcastToConversation(convID string, msg any) {
	if s.store == nil {
		return
	}

	members, err := s.store.GetConversationMembers(convID)
	if err != nil {
		s.logger.Error("failed to get conversation members", "conversation", convID, "error", err)
		return
	}

	memberSet := make(map[string]bool, len(members))
	for _, m := range members {
		memberSet[m] = true
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, client := range s.clients {
		if memberSet[client.Username] {
			client.Encoder.Encode(msg)
		}
	}
}

// broadcastToRoomExcept sends to all room members except the given device.
func (s *Server) broadcastToRoomExcept(room, excludeDevice string, msg any) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	s.cfg.RLock()
	defer s.cfg.RUnlock()

	for _, client := range s.clients {
		if client.DeviceID == excludeDevice {
			continue
		}
		user := s.cfg.Users[client.Username]
		for _, r := range user.Rooms {
			if r == room {
				client.Encoder.Encode(msg)
				break
			}
		}
	}
}

// broadcastToConversationExcept sends to all conversation members except the given device.
func (s *Server) broadcastToConversationExcept(convID, excludeDevice string, msg any) {
	if s.store == nil {
		return
	}

	members, err := s.store.GetConversationMembers(convID)
	if err != nil {
		return
	}

	memberSet := make(map[string]bool, len(members))
	for _, m := range members {
		memberSet[m] = true
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, client := range s.clients {
		if client.DeviceID == excludeDevice {
			continue
		}
		if memberSet[client.Username] {
			client.Encoder.Encode(msg)
		}
	}
}

// handleListPendingKeys returns the list of pending (unapproved) SSH keys.
// Admin-only — non-admin clients receive an error.
func (s *Server) handleListPendingKeys(c *Client) {
	isAdmin := false
	s.cfg.RLock()
	for _, a := range s.cfg.Server.Server.Admins {
		if a == c.Username {
			isAdmin = true
			break
		}
	}
	s.cfg.RUnlock()

	if !isAdmin {
		c.Encoder.Encode(protocol.Error{
			Type:    "error",
			Code:    protocol.ErrNotAuthorized,
			Message: "Only admins can list pending keys",
		})
		return
	}

	var keys []protocol.PendingKeyEntry
	if s.store != nil {
		rows, err := s.store.UsersDB().Query(
			`SELECT fingerprint, attempts, first_seen, last_seen
			 FROM pending_keys ORDER BY last_seen DESC`)
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var k protocol.PendingKeyEntry
				if rows.Scan(&k.Fingerprint, &k.Attempts, &k.FirstSeen, &k.LastSeen) == nil {
					keys = append(keys, k)
				}
			}
		}
	}

	c.Encoder.Encode(protocol.PendingKeysList{
		Type: "pending_keys_list",
		Keys: keys,
	})
}
