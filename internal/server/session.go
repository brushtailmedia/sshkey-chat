package server

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/brushtailmedia/sshkey-chat/internal/config"
	"github.com/brushtailmedia/sshkey-chat/internal/protocol"
	"github.com/brushtailmedia/sshkey-chat/internal/store"
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
func (s *Server) handleSession(userID string, conn *ssh.ServerConn, ch ssh.Channel, dlChanCh <-chan ssh.Channel) {
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
		s.logger.Error("failed to send server_hello", "user", userID, "error", err)
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
			"user", userID,
			"protocol", clientHello.Protocol,
			"version", clientHello.Version,
		)
		s.sendInstallBanner(enc)
		return
	}

	// Negotiate capabilities
	active := negotiateCapabilities(clientHello.Capabilities)

	// Build room and group DM lists for this user (nanoid IDs)
	var rooms []string
	if s.store != nil {
		rooms = s.store.GetUserRoomIDs(userID)
	}
	displayName := s.store.GetUserDisplayName(userID)
	isAdmin := s.store.IsAdmin(userID)

	// Group DM IDs for the welcome envelope. Rich info (members, names)
	// arrives separately via the group_list message sent just after
	// welcome in the connect sequence.
	var groups []string
	if s.store != nil {
		if gs, err := s.store.GetUserGroups(userID); err == nil {
			for _, g := range gs {
				groups = append(groups, g.ID)
			}
		}
	}

	// Step 3: Send welcome
	pendingSync := clientHello.LastSyncedAt != "" // sync follows if client has a last_synced_at
	err = enc.Encode(protocol.Welcome{
		Type:               "welcome",
		User:               userID,
		DisplayName:        displayName,
		Admin:              isAdmin,
		Rooms:              rooms,
		Groups:             groups,
		PendingSync:        pendingSync,
		ActiveCapabilities: active,
	})
	if err != nil {
		s.logger.Error("failed to send welcome", "user", userID, "error", err)
		return
	}

	s.logger.Info("handshake complete",
		"user", userID,
		"device", clientHello.DeviceID,
		"capabilities", active,
	)

	// Check device revocation and register
	if s.store != nil {
		revoked, err := s.store.IsDeviceRevoked(userID, clientHello.DeviceID)
		if err == nil && revoked {
			enc.Encode(protocol.DeviceRevoked{
				Type:     "device_revoked",
				DeviceID: clientHello.DeviceID,
				Reason:   "admin_action",
			})
			return
		}

		deviceCount, err := s.store.UpsertDevice(userID, clientHello.DeviceID)
		if err != nil {
			s.logger.Error("device registration failed", "user", userID, "error", err)
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
		UserID:       userID,
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
		s.logger.Debug("no download channel", "user", userID, "device", clientHello.DeviceID)
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
			if p.user == client.UserID {
				delete(s.files.uploads, id)
			}
		}
		s.files.mu.Unlock()
	}()

	// Send the list of rooms this user has previously /delete'd. Sent
	// BEFORE room_list so the client purges before populating its
	// sidebar — devices that were offline when the room_deleted live
	// echo went out catch up via this message. Phase 12 parallel to
	// sendDeletedGroups.
	s.sendDeletedRooms(client)

	// Send the list of retired rooms this user is still a member of.
	// Sent BEFORE room_list so the client has the retired state in
	// hand before the sidebar is populated. Catches up offline devices
	// that missed the live room_retired broadcast. Phase 12.
	s.sendRetiredRooms(client)

	// Send room list
	s.sendRoomList(client)

	// Send the list of groups this user has previously /delete'd. Sent
	// BEFORE group_list so the client can apply the catchup purges
	// before its sidebar is populated. Catches up offline devices that
	// missed the live group_deleted echo.
	s.sendDeletedGroups(client)

	// Send group DM list
	s.sendGroupList(client)

	// Send 1:1 DM list
	s.sendDMList(client)

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
	s.broadcastPresence(userID, "online")
	defer s.broadcastPresence(userID, "offline")

	// Trigger initial epoch rotation for fresh rooms (after message loop can handle responses)
	go func() {
		var rooms []string
		if s.store != nil {
			rooms = s.store.GetUserRoomIDs(userID)
		}

		for _, roomID := range rooms {
			if s.epochs.currentEpochNum(roomID) == 0 {
				s.triggerEpochRotation(client, roomID, "initial")
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
	if s.store == nil {
		return
	}

	var rooms []protocol.RoomInfo
	for _, roomID := range s.store.GetUserRoomIDs(c.UserID) {
		room, _ := s.store.GetRoomByID(roomID)
		displayName := ""
		topic := ""
		if room != nil {
			displayName = room.DisplayName
			topic = room.Topic
		}
		members := s.store.GetRoomMemberIDsByRoomID(roomID)
		rooms = append(rooms, protocol.RoomInfo{
			ID:      roomID,
			Name:    displayName,
			Topic:   topic,
			Members: len(members),
		})
	}

	c.Encoder.Encode(protocol.RoomList{
		Type:  "room_list",
		Rooms: rooms,
	})
}

// sendGroupList sends the group_list message to the client.
func (s *Server) sendGroupList(c *Client) {
	if s.store == nil {
		return
	}

	groups, err := s.store.GetUserGroups(c.UserID)
	if err != nil {
		s.logger.Error("failed to get groups", "user", c.UserID, "error", err)
		return
	}

	if len(groups) == 0 {
		return
	}

	var infos []protocol.GroupInfo
	for _, g := range groups {
		// Phase 14: fetch the admin subset so the client can render
		// admin indicators and gate admin commands on reconnect without
		// a round-trip. Failures are logged and fall through to an empty
		// admins list — the client will still see the group, just
		// without admin state (the next group_event{promote/demote}
		// will populate the in-memory cache).
		admins, err := s.store.GetGroupAdminIDs(g.ID)
		if err != nil {
			s.logger.Error("failed to fetch group admins for group_list",
				"group", g.ID, "error", err)
		}
		infos = append(infos, protocol.GroupInfo{
			ID:      g.ID,
			Members: g.Members,
			Admins:  admins,
			Name:    g.Name,
		})
	}

	c.Encoder.Encode(protocol.GroupList{
		Type:   "group_list",
		Groups: infos,
	})
}

// sendDMList sends the dm_list message to the client on connect.
func (s *Server) sendDMList(c *Client) {
	if s.store == nil {
		return
	}

	dms, err := s.store.GetDirectMessagesForUser(c.UserID)
	if err != nil {
		s.logger.Error("failed to get DMs", "user", c.UserID, "error", err)
		return
	}

	if len(dms) == 0 {
		return
	}

	var infos []protocol.DMInfo
	for _, dm := range dms {
		infos = append(infos, protocol.DMInfo{
			ID:              dm.ID,
			Members:         []string{dm.UserA, dm.UserB},
			LeftAtForCaller: dm.CutoffFor(c.UserID),
		})
	}

	c.Encoder.Encode(protocol.DMList{
		Type: "dm_list",
		DMs:  infos,
	})
}

// sendDeletedGroups emits a deleted_groups message during the connect
// handshake listing every group ID this user has previously /delete'd.
// Sent BEFORE sendGroupList so the client purges before populating its
// sidebar — devices that were offline when the group_deleted live echo
// went out catch up via this message.
//
// No-op if the user has no deletion records.
func (s *Server) sendDeletedGroups(c *Client) {
	if s.store == nil {
		return
	}
	groups, err := s.store.GetDeletedGroupsForUser(c.UserID)
	if err != nil {
		s.logger.Error("failed to get deleted groups",
			"user", c.UserID, "error", err)
		return
	}
	if len(groups) == 0 {
		return
	}
	c.Encoder.Encode(protocol.DeletedGroupsList{
		Type:   "deleted_groups",
		Groups: groups,
	})
}

// sendDeletedRooms emits a deleted_rooms message during the connect
// handshake listing every room ID this user has previously /delete'd.
// Sent BEFORE sendRoomList so the client purges before populating its
// sidebar — devices that were offline when the room_deleted live echo
// went out catch up via this message. Phase 12 parallel to
// sendDeletedGroups.
//
// No-op if the user has no deletion records.
func (s *Server) sendDeletedRooms(c *Client) {
	if s.store == nil {
		return
	}
	rooms, err := s.store.GetDeletedRoomsForUser(c.UserID)
	if err != nil {
		s.logger.Error("failed to get deleted rooms",
			"user", c.UserID, "error", err)
		return
	}
	if len(rooms) == 0 {
		return
	}
	c.Encoder.Encode(protocol.DeletedRoomsList{
		Type:  "deleted_rooms",
		Rooms: rooms,
	})
}

// sendRetiredRooms emits a retired_rooms message during the connect
// handshake listing every retired room this user is still a member
// of. Sent BEFORE sendRoomList so the client can apply retirement
// state to its rooms table before the sidebar is populated. Catches
// up offline devices that missed the live room_retired broadcast.
// Phase 12.
//
// Filter per Q8 of the Phase 12 design: GetRetiredRoomsForUser joins
// room_members, so users who voluntarily left a room BEFORE it was
// retired do NOT see the room in this list. Only users who are still
// formal members see the retirement in their catchup.
//
// No-op if the user has no retired rooms in their membership.
func (s *Server) sendRetiredRooms(c *Client) {
	if s.store == nil {
		return
	}
	rooms, err := s.store.GetRetiredRoomsForUser(c.UserID)
	if err != nil {
		s.logger.Error("failed to get retired rooms",
			"user", c.UserID, "error", err)
		return
	}
	if len(rooms) == 0 {
		return
	}

	out := make([]protocol.RoomRetired, 0, len(rooms))
	for _, r := range rooms {
		out = append(out, protocol.RoomRetired{
			Type:        "room_retired",
			Room:        r.ID,
			DisplayName: r.DisplayName,
			RetiredAt:   r.RetiredAt,
			RetiredBy:   r.RetiredBy,
		})
	}

	c.Encoder.Encode(protocol.RetiredRoomsList{
		Type:  "retired_rooms",
		Rooms: out,
	})
}

// sendProfiles sends profile messages for all users visible to this client
// (shared rooms, group DMs, and 1:1 DMs).
func (s *Server) sendProfiles(c *Client) {
	// Collect all visible usernames (users who share a room with this client)
	visible := make(map[string]bool)

	if s.store != nil {
		for _, roomID := range s.store.GetUserRoomIDs(c.UserID) {
			for _, uid := range s.store.GetRoomMemberIDsByRoomID(roomID) {
				visible[uid] = true
			}
		}
	}

	// Also include group DM members
	if s.store != nil {
		groups, err := s.store.GetUserGroups(c.UserID)
		if err == nil {
			for _, g := range groups {
				for _, m := range g.Members {
					visible[m] = true
				}
			}
		}
	}

	// Also include 1:1 DM partners
	if s.store != nil {
		dms, err := s.store.GetDirectMessagesForUser(c.UserID)
		if err == nil {
			for _, dm := range dms {
				visible[dm.UserA] = true
				visible[dm.UserB] = true
			}
		}
	}

	// Send profiles
	for userID := range visible {
		user := s.store.GetUserByID(userID)
		if user == nil {
			continue
		}
		parsed, _, _, _, err := ssh.ParseAuthorizedKey([]byte(user.Key))
		if err != nil {
			continue
		}

		displayName := user.DisplayName
		avatarID := ""
		// Merge stored profile data (avatar, display_name overrides from
		// set_profile) with users.db defaults. DB avatar takes precedence
		// for fields users can customize at runtime.
		if s.store != nil {
			var dbDisplayName, dbAvatarID sql.NullString
			s.store.DataDB().QueryRow(
				`SELECT display_name, avatar_id FROM profiles WHERE user = ?`,
				userID).Scan(&dbDisplayName, &dbAvatarID)
			if dbDisplayName.Valid && dbDisplayName.String != "" {
				displayName = dbDisplayName.String
			}
			if dbAvatarID.Valid {
				avatarID = dbAvatarID.String
			}
		}

		c.Encoder.Encode(protocol.Profile{
			Type:           "profile",
			User:           userID,
			DisplayName:    displayName,
			AvatarID:       avatarID,
			PubKey:         user.Key,
			KeyFingerprint: ssh.FingerprintSHA256(parsed),
			Admin:          s.store.IsAdmin(userID),
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
				s.logger.Error("read error", "user", c.UserID, "error", err)
			}
			return
		}

		msgType, err := protocol.TypeOf(raw)
		if err != nil {
			s.logger.Warn("invalid message", "user", c.UserID, "error", err)
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
	case "edit":
		s.handleEdit(c, raw)
	case "edit_group":
		s.handleEditGroup(c, raw)
	case "edit_dm":
		s.handleEditDM(c, raw)
	case "send_group":
		s.handleSendGroup(c, raw)
	case "create_group":
		s.handleCreateGroup(c, raw)
	case "epoch_rotate":
		s.handleEpochRotate(c, raw)
	case "delete":
		s.handleDelete(c, raw)
	case "leave_group":
		s.handleLeaveGroup(c, raw)
	case "delete_group":
		s.handleDeleteGroup(c, raw)
	case "leave_room":
		s.handleLeaveRoom(c, raw)
	case "delete_room":
		s.handleDeleteRoom(c, raw)
	case "create_dm":
		s.handleCreateDM(c, raw)
	case "send_dm":
		s.handleSendDM(c, raw)
	case "leave_dm":
		s.handleLeaveDM(c, raw)
	case "rename_group":
		s.handleRenameGroup(c, raw)
	case "add_to_group":
		s.handleAddToGroup(c, raw)
	case "remove_from_group":
		s.handleRemoveFromGroup(c, raw)
	case "promote_group_admin":
		s.handlePromoteGroupAdmin(c, raw)
	case "demote_group_admin":
		s.handleDemoteGroupAdmin(c, raw)
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
	case "room_members":
		s.handleRoomMembers(c, raw)
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
		s.logger.Debug("unhandled message type", "user", c.UserID, "type", msgType)
	}
}

// handleSend processes a room message.
func (s *Server) handleSend(c *Client, raw json.RawMessage) {
	// Rate limit
	if !s.limiter.allow("msg:"+c.UserID, float64(s.cfg.Server.RateLimits.MessagesPerSecond)) {
		c.Encoder.Encode(protocol.Error{Type: "error", Code: protocol.ErrRateLimited, Message: "Slow down — too many messages. Try again in a moment"})
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

	// Verify user is in this room. Privacy: the response for "room
	// does not exist", "DB lookup failed", and "you are not a member
	// of an existing room" MUST be byte-identical so a probing client
	// cannot use send to discover whether a given room ID exists.
	// Matches the convention in handleSendGroup, handleSendDM, and
	// handleLeaveRoom — uses ErrUnknownRoom with a generic message,
	// no room ID embedded in the wire response.
	inRoom := s.store != nil && s.store.IsRoomMemberByID(msg.Room, c.UserID)
	if !inRoom {
		c.Encoder.Encode(protocol.Error{
			Type:    "error",
			Code:    protocol.ErrUnknownRoom,
			Message: "You are not a member of this room",
		})
		return
	}

	// Reject writes to retired rooms. Ordered AFTER the membership gate
	// so non-members still get the byte-identical ErrUnknownRoom — only
	// members see the informative "archived" message. Per Q11 of the
	// Phase 12 design: retired state is admin-public to members (the
	// retirement broadcast already told them), so revealing it via this
	// rejection is not a probing vector.
	if s.store.IsRoomRetired(msg.Room) {
		c.Encoder.Encode(protocol.Error{
			Type:    "error",
			Code:    protocol.ErrRoomRetired,
			Message: "This room has been archived and is read-only",
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
		From:      c.UserID,
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

// handleSendGroup processes a group DM message.
func (s *Server) handleSendGroup(c *Client, raw json.RawMessage) {
	if len(raw) > maxPayloadBytes {
		c.Encoder.Encode(protocol.Error{Type: "error", Code: protocol.ErrMessageTooLarge, Message: "Message exceeds 16KB limit"})
		return
	}

	var msg protocol.SendGroup
	if err := json.Unmarshal(raw, &msg); err != nil {
		c.Encoder.Encode(protocol.Error{Type: "error", Code: "invalid_message", Message: "malformed send_group"})
		return
	}

	// Validate group exists and user is a member
	if s.store != nil {
		isMember, err := s.store.IsGroupMember(msg.Group, c.UserID)
		if err != nil || !isMember {
			c.Encoder.Encode(protocol.Error{
				Type:    "error",
				Code:    protocol.ErrUnknownGroup,
				Message: "You are not a member of this group",
			})
			return
		}

		// Validate wrapped_keys match group member list
		members, err := s.store.GetGroupMembers(msg.Group)
		if err == nil {
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
					Message: "wrapped_keys must match group member list",
				})
				return
			}
			for m := range memberSet {
				if !wrappedSet[m] {
					c.Encoder.Encode(protocol.Error{
						Type:    "error",
						Code:    protocol.ErrInvalidWrappedKeys,
						Message: "wrapped_keys must match group member list",
					})
					return
				}
			}
		}
	}

	outMsg := protocol.GroupMessage{
		Type:        "group_message",
		ID:          generateID("msg_"),
		From:        c.UserID,
		Group:       msg.Group,
		TS:          time.Now().Unix(),
		WrappedKeys: msg.WrappedKeys,
		Payload:     msg.Payload,
		FileIDs:     msg.FileIDs,
		Signature:   msg.Signature,
	}

	// Store in group DM DB
	if s.store != nil {
		err := s.store.InsertGroupMessage(msg.Group, store.StoredMessage{
			ID:          outMsg.ID,
			Sender:      outMsg.From,
			TS:          outMsg.TS,
			Payload:     outMsg.Payload,
			FileIDs:     outMsg.FileIDs,
			Signature:   outMsg.Signature,
			WrappedKeys: outMsg.WrappedKeys,
		})
		if err != nil {
			s.logger.Error("failed to store group message", "group", msg.Group, "error", err)
		}
	}

	// Broadcast to all connected clients in this group
	s.broadcastToGroup(msg.Group, outMsg)

	// Notify offline group members via push
	if s.store != nil {
		members, err := s.store.GetGroupMembers(msg.Group)
		if err == nil {
			go s.notifyOfflineUsers(members)
		}
	}
}

// handleTyping broadcasts a typing indicator to others (not the sender).
func (s *Server) handleTyping(c *Client, raw json.RawMessage) {
	if !s.limiter.allow("typing:"+c.UserID, float64(s.cfg.Server.RateLimits.TypingPerSecond)) {
		return // silently dropped per spec
	}

	var msg protocol.Typing
	if err := json.Unmarshal(raw, &msg); err != nil {
		return
	}

	// Track typing for server-side expiry (DMs use the DM ID as context)
	typingCtx := msg.Room + msg.Group + msg.DM
	s.typing.Touch(c.UserID, msg.Room, typingCtx)

	out := protocol.Typing{
		Type:  "typing",
		Room:  msg.Room,
		Group: msg.Group,
		DM:    msg.DM,
		User:  c.UserID,
	}

	if msg.Room != "" {
		s.broadcastToRoomExcept(msg.Room, c.DeviceID, out)
	} else if msg.Group != "" {
		s.broadcastToGroupExcept(msg.Group, c.DeviceID, out)
	} else if msg.DM != "" {
		// For 1:1 DMs, send to the other party's sessions
		if s.store != nil {
			if dm, err := s.store.GetDirectMessage(msg.DM); err == nil && dm != nil {
				s.mu.RLock()
				for _, client := range s.clients {
					if client.DeviceID == c.DeviceID {
						continue
					}
					if client.UserID == dm.UserA || client.UserID == dm.UserB {
						client.Encoder.Encode(out)
					}
				}
				s.mu.RUnlock()
			}
		}
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
		s.store.SetReadPosition(c.UserID, c.DeviceID, msg.Room, msg.Group, msg.DM, msg.LastRead)
	}

	out := protocol.Read{
		Type:     "read",
		Room:     msg.Room,
		Group:    msg.Group,
		DM:       msg.DM,
		User:     c.UserID,
		LastRead: msg.LastRead,
	}

	if msg.Room != "" {
		s.broadcastToRoomExcept(msg.Room, c.DeviceID, out)
	} else if msg.Group != "" {
		s.broadcastToGroupExcept(msg.Group, c.DeviceID, out)
	} else if msg.DM != "" {
		// For 1:1 DMs, broadcast to both members' other devices
		if dm, err := s.store.GetDirectMessage(msg.DM); err == nil && dm != nil {
			s.mu.RLock()
			for _, client := range s.clients {
				if client.DeviceID == c.DeviceID {
					continue
				}
				if client.UserID == dm.UserA || client.UserID == dm.UserB {
					client.Encoder.Encode(out)
				}
			}
			s.mu.RUnlock()
		}
	}
}

// isReactableMessage reports whether a message row in the given
// per-context DB is a valid react target: it must exist AND not be
// tombstoned. Used by handleReact's Phase 15 follow-up guard that
// closes the race between an incoming `react` envelope and a
// concurrent `delete` tombstoning the target row. Silent false on any
// error (missing row, DB failure, scan error) — the caller treats
// any ambiguity as "don't insert" and skips the broadcast.
//
// The check is a single indexed point query on the primary key so
// the overhead is negligible even at high reaction rates.
func (s *Server) isReactableMessage(db *sql.DB, msgID string) bool {
	var deleted int
	err := db.QueryRow(`SELECT deleted FROM messages WHERE id = ?`, msgID).Scan(&deleted)
	if err != nil {
		return false
	}
	return deleted == 0
}

// handleReact processes a reaction.
func (s *Server) handleReact(c *Client, raw json.RawMessage) {
	if !s.limiter.allowPerMinute("react:"+c.UserID, s.cfg.Server.RateLimits.ReactionsPerMinute) {
		c.Encoder.Encode(protocol.Error{Type: "error", Code: protocol.ErrRateLimited, Message: "Too many reactions — wait a moment"})
		return
	}

	var msg protocol.React
	if err := json.Unmarshal(raw, &msg); err != nil {
		c.Encoder.Encode(protocol.Error{Type: "error", Code: "invalid_message", Message: "malformed react"})
		return
	}

	// Room branch: verify membership (byte-identical privacy) and
	// reject writes to retired rooms (Q11: informative message, only
	// visible after the membership gate so non-members can't probe for
	// retired-room existence). Group and DM branches have their own
	// verification paths inside the store layer.
	if msg.Room != "" && s.store != nil {
		if !s.store.IsRoomMemberByID(msg.Room, c.UserID) {
			c.Encoder.Encode(protocol.Error{
				Type:    "error",
				Code:    protocol.ErrUnknownRoom,
				Message: "You are not a member of this room",
			})
			return
		}
		if s.store.IsRoomRetired(msg.Room) {
			c.Encoder.Encode(protocol.Error{
				Type:    "error",
				Code:    protocol.ErrRoomRetired,
				Message: "This room has been archived and is read-only",
			})
			return
		}
	}

	reactionID := generateID("react_")

	reaction := protocol.Reaction{
		Type:        "reaction",
		ReactionID:  reactionID,
		ID:          msg.ID,
		Room:        msg.Room,
		Group:       msg.Group,
		User:        c.UserID,
		TS:          time.Now().Unix(),
		Epoch:       msg.Epoch,
		WrappedKeys: msg.WrappedKeys,
		Payload:     msg.Payload,
		Signature:   msg.Signature,
	}

	// Store in the appropriate DB.
	//
	// Phase 15 follow-up: guard against reacting to a tombstoned or
	// nonexistent message. Before Phase 15 this gate was missing,
	// allowing a race where a `react` envelope could arrive after a
	// `delete` had already tombstoned the target row. The old path
	// inserted an orphan reaction row (FK passes because soft-delete
	// keeps the row) and broadcast it; receiving clients' TUI filtered
	// it at render time but the orphan persisted in per-context DBs
	// and in clients' local stores. Now we check the `deleted` column
	// before INSERT and silently return on miss/tombstone — matches
	// `handleDelete`'s behavior when a target msgID isn't found
	// (silent no-op, no error surfaced to the caller). Uses the same
	// privacy posture as delete: the caller is already proven to be a
	// room member, but revealing "your target was tombstoned" adds
	// nothing useful over "your react silently failed" and avoids an
	// extra protocol surface.
	if s.store != nil {
		if msg.Room != "" {
			db, err := s.store.RoomDB(msg.Room)
			if err != nil {
				return
			}
			if !s.isReactableMessage(db, msg.ID) {
				return
			}
			db.Exec(`INSERT INTO reactions (reaction_id, message_id, user, ts, epoch, payload, signature)
				VALUES (?, ?, ?, ?, ?, ?, ?)`,
				reactionID, msg.ID, c.UserID, reaction.TS, msg.Epoch, msg.Payload, msg.Signature)
		} else if msg.Group != "" {
			db, err := s.store.GroupDB(msg.Group)
			if err != nil {
				return
			}
			if !s.isReactableMessage(db, msg.ID) {
				return
			}
			wrappedKeys := ""
			if len(msg.WrappedKeys) > 0 {
				data, _ := json.Marshal(msg.WrappedKeys)
				wrappedKeys = string(data)
			}
			db.Exec(`INSERT INTO reactions (reaction_id, message_id, user, ts, epoch, payload, signature, wrapped_keys)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
				reactionID, msg.ID, c.UserID, reaction.TS, msg.Epoch, msg.Payload, msg.Signature, wrappedKeys)
		} else if msg.DM != "" {
			db, err := s.store.DMDB(msg.DM)
			if err != nil {
				return
			}
			if !s.isReactableMessage(db, msg.ID) {
				return
			}
			wrappedKeys := ""
			if len(msg.WrappedKeys) > 0 {
				data, _ := json.Marshal(msg.WrappedKeys)
				wrappedKeys = string(data)
			}
			db.Exec(`INSERT INTO reactions (reaction_id, message_id, user, ts, epoch, payload, signature, wrapped_keys)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
				reactionID, msg.ID, c.UserID, reaction.TS, msg.Epoch, msg.Payload, msg.Signature, wrappedKeys)
		}
	}
	// If s.store is nil (unusual, only hit in in-memory tests without
	// persistence wired up) we fall through to the broadcast below.
	// Real deployments always have a store, so the tombstone guard
	// always fires in production.

	// Broadcast
	if msg.Room != "" {
		s.broadcastToRoom(msg.Room, reaction)
	} else if msg.Group != "" {
		s.broadcastToGroup(msg.Group, reaction)
	} else if msg.DM != "" {
		// For 1:1 DMs, broadcast to both members
		if dm, err := s.store.GetDirectMessage(msg.DM); err == nil && dm != nil {
			s.mu.RLock()
			for _, client := range s.clients {
				if client.UserID == dm.UserA || client.UserID == dm.UserB {
					client.Encoder.Encode(reaction)
				}
			}
			s.mu.RUnlock()
		}
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

	// Search room DBs, group DBs, and DM DBs for this reaction.
	//
	// Phase 12 note: GetUserRoomIDs filters WHERE r.retired = 0, so
	// retired rooms are naturally excluded from this search. A user
	// trying to unreact in a retired room will fall through all three
	// loops and return silently. That's suboptimal UX (the user won't
	// see an informative "this room has been archived" error) but is
	// not a data integrity or privacy issue — the reaction remains in
	// the retired room's DB and the user's intent is simply not
	// honored. Acceptable for Phase 12; improving requires a parallel
	// GetAllUserRoomIDs that includes retired rooms, which is a Phase
	// 15 concern (admin CLI audit may generalize this).
	var targetID, room, group, dmID, user string
	var found bool

	rooms := s.store.GetUserRoomIDs(c.UserID)

	for _, r := range rooms {
		db, err := s.store.RoomDB(r)
		if err != nil {
			continue
		}
		err = db.QueryRow(`SELECT message_id, user FROM reactions WHERE reaction_id = ?`, msg.ReactionID).
			Scan(&targetID, &user)
		if err == nil && user == c.UserID {
			room = r
			found = true
			db.Exec(`DELETE FROM reactions WHERE reaction_id = ?`, msg.ReactionID)
			break
		}
	}

	if !found {
		groups, err := s.store.GetUserGroups(c.UserID)
		if err == nil {
			for _, g := range groups {
				db, err := s.store.GroupDB(g.ID)
				if err != nil {
					continue
				}
				err = db.QueryRow(`SELECT message_id, user FROM reactions WHERE reaction_id = ?`, msg.ReactionID).
					Scan(&targetID, &user)
				if err == nil && user == c.UserID {
					group = g.ID
					found = true
					db.Exec(`DELETE FROM reactions WHERE reaction_id = ?`, msg.ReactionID)
					break
				}
			}
		}
	}

	if !found {
		dms, err := s.store.GetDirectMessagesForUser(c.UserID)
		if err == nil {
			for _, dm := range dms {
				db, err := s.store.DMDB(dm.ID)
				if err != nil {
					continue
				}
				err = db.QueryRow(`SELECT message_id, user FROM reactions WHERE reaction_id = ?`, msg.ReactionID).
					Scan(&targetID, &user)
				if err == nil && user == c.UserID {
					dmID = dm.ID
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
		Type:       "reaction_removed",
		ReactionID: msg.ReactionID,
		ID:         targetID,
		Room:       room,
		Group:      group,
		DM:         dmID,
		User:       c.UserID,
	}

	if room != "" {
		s.broadcastToRoom(room, removed)
	} else if group != "" {
		s.broadcastToGroup(group, removed)
	} else if dmID != "" {
		if dm, err := s.store.GetDirectMessage(dmID); err == nil && dm != nil {
			s.mu.RLock()
			for _, client := range s.clients {
				if client.UserID == dm.UserA || client.UserID == dm.UserB {
					client.Encoder.Encode(removed)
				}
			}
			s.mu.RUnlock()
		}
	}
}

// handlePin processes a pin request.
func (s *Server) handlePin(c *Client, raw json.RawMessage) {
	if !s.limiter.allowPerMinute("pin:"+c.UserID, s.cfg.Server.RateLimits.PinsPerMinute) {
		c.Encoder.Encode(protocol.Error{Type: "error", Code: protocol.ErrRateLimited, Message: "Too many pins — wait a moment"})
		return
	}

	var msg protocol.Pin
	if err := json.Unmarshal(raw, &msg); err != nil {
		return
	}

	// Verify membership (byte-identical privacy) and reject writes to
	// retired rooms. Ordered so non-members get ErrUnknownRoom and
	// members of retired rooms get the informative ErrRoomRetired
	// (Phase 12 Q11). Matches handleSend's pattern.
	if s.store == nil {
		return
	}
	if !s.store.IsRoomMemberByID(msg.Room, c.UserID) {
		c.Encoder.Encode(protocol.Error{
			Type:    "error",
			Code:    protocol.ErrUnknownRoom,
			Message: "You are not a member of this room",
		})
		return
	}
	if s.store.IsRoomRetired(msg.Room) {
		c.Encoder.Encode(protocol.Error{
			Type:    "error",
			Code:    protocol.ErrRoomRetired,
			Message: "This room has been archived and is read-only",
		})
		return
	}

	db, err := s.store.RoomDB(msg.Room)
	if err == nil {
		db.Exec(`INSERT OR IGNORE INTO pins (message_id, pinned_by, ts) VALUES (?, ?, ?)`,
			msg.ID, c.UserID, time.Now().Unix())
	}

	s.broadcastToRoom(msg.Room, protocol.Pinned{
		Type:     "pinned",
		Room:     msg.Room,
		ID:       msg.ID,
		PinnedBy: c.UserID,
		TS:       time.Now().Unix(),
	})
}

// handleUnpin processes an unpin request.
func (s *Server) handleUnpin(c *Client, raw json.RawMessage) {
	if !s.limiter.allowPerMinute("pin:"+c.UserID, s.cfg.Server.RateLimits.PinsPerMinute) {
		c.Encoder.Encode(protocol.Error{Type: "error", Code: protocol.ErrRateLimited, Message: "Too many pins — wait a moment"})
		return
	}

	var msg protocol.Unpin
	if err := json.Unmarshal(raw, &msg); err != nil {
		return
	}

	// Verify membership (byte-identical privacy) and reject writes to
	// retired rooms. Same pattern as handlePin.
	if s.store == nil {
		return
	}
	if !s.store.IsRoomMemberByID(msg.Room, c.UserID) {
		c.Encoder.Encode(protocol.Error{
			Type:    "error",
			Code:    protocol.ErrUnknownRoom,
			Message: "You are not a member of this room",
		})
		return
	}
	if s.store.IsRoomRetired(msg.Room) {
		c.Encoder.Encode(protocol.Error{
			Type:    "error",
			Code:    protocol.ErrRoomRetired,
			Message: "This room has been archived and is read-only",
		})
		return
	}

	db, err := s.store.RoomDB(msg.Room)
	if err == nil {
		db.Exec(`DELETE FROM pins WHERE message_id = ?`, msg.ID)
	}

	s.broadcastToRoom(msg.Room, protocol.Unpinned{
		Type: "unpinned",
		Room: msg.Room,
		ID:   msg.ID,
	})
}

// handleCreateGroup creates a new group DM.
//
// 1:1 DMs are NOT supported here — they live in the `direct_messages` table
// with their own create_dm handler. This handler always creates a multi-
// party group, even when the requested member list has only one other user.
//
// Design intent: groups are private peer DMs, not admin-managed channels.
// There is no add_to_group / remove_from_group / kick path. Membership is
// fixed at create time; the only mutations are self-leave (handleLeaveGroup),
// self-delete (handleDeleteGroup), and retirement-driven removal of a
// retiring user (handleRetirement). If a member needs to be added later,
// the workflow is to create a new group with the desired member set. This
// is a deliberate security and privacy choice that mirrors the way 1:1
// DMs work — the parties to a private conversation control who can be
// in it, not an admin role. Admins manage rooms, not groups.
func (s *Server) handleCreateGroup(c *Client, raw json.RawMessage) {
	if !s.limiter.allowPerMinute("group_create:"+c.UserID, s.cfg.Server.RateLimits.DMCreatesPerMinute) {
		c.Encoder.Encode(protocol.Error{Type: "error", Code: protocol.ErrRateLimited, Message: "Too many groups — wait a moment"})
		return
	}

	var msg protocol.CreateGroup
	if err := json.Unmarshal(raw, &msg); err != nil {
		c.Encoder.Encode(protocol.Error{Type: "error", Code: "invalid_message", Message: "malformed create_group"})
		return
	}

	// Add sender to members
	allMembers := append([]string{c.UserID}, msg.Members...)

	// Reject if any proposed member is retired
	if retired := s.findRetiredMember(msg.Members); retired != "" {
		c.Encoder.Encode(protocol.Error{
			Type:    "error",
			Code:    protocol.ErrUserRetired,
			Message: fmt.Sprintf("Cannot create group — %s's account has been retired", retired),
		})
		return
	}

	// Max group size: 150 members. Per-message wrapped keys scale linearly
	// with member count (~80 bytes per member per message on the wire, plus
	// one ECDH+HKDF+AES-GCM wrapping op per member per send). At 150
	// members this is ~12KB of key material per message and ~15ms of crypto
	// per send — acceptable for most use cases but noticeably heavier than
	// rooms (which use a shared epoch key). The client shows a soft warning
	// at 50 members suggesting a room for high-traffic conversations.
	if len(allMembers) > 150 {
		c.Encoder.Encode(protocol.Error{
			Type:    "error",
			Code:    "too_many_members",
			Message: "Group DMs are limited to 150 members. Use a room for larger groups.",
		})
		return
	}

	groupID := generateID("group_")

	if s.store != nil {
		// Phase 14: caller becomes the initial admin. c.UserID is already at
		// index 0 of allMembers (via the append above), so the validation
		// inside CreateGroup will pass.
		if err := s.store.CreateGroup(groupID, c.UserID, allMembers, msg.Name); err != nil {
			s.logger.Error("failed to create group", "error", err)
			c.Encoder.Encode(protocol.Error{Type: "error", Code: "internal", Message: "failed to create group"})
			return
		}
	}

	// Phase 14: the creator becomes the initial admin, so GroupCreated
	// carries a single-element Admins list. Clients use this to
	// populate the local is_admin flag and in-memory admin set
	// without an extra round-trip.
	created := protocol.GroupCreated{
		Type:    "group_created",
		Group:   groupID,
		Members: allMembers,
		Admins:  []string{c.UserID},
		Name:    msg.Name,
	}

	// Send group_created to the creator
	c.Encoder.Encode(created)

	// Also notify all other online members so they know the group exists
	s.mu.RLock()
	memberSet := make(map[string]bool, len(allMembers))
	for _, m := range allMembers {
		memberSet[m] = true
	}
	for _, client := range s.clients {
		if client.DeviceID == c.DeviceID {
			continue // already sent to creator
		}
		if memberSet[client.UserID] {
			client.Encoder.Encode(created)
		}
	}
	s.mu.RUnlock()

	s.logger.Info("group created",
		"group", groupID,
		"created_by", c.UserID,
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
	isAdmin := s.store.IsAdmin(c.UserID)

	// Phase 12 note: GetUserRoomIDs filters WHERE r.retired = 0, so
	// retired rooms are naturally excluded from the room search below.
	// A user trying to delete a message in a retired room will fall
	// through to group/DM search and return without action. Matches
	// the behavior in handleUnreact; same limitation, same rationale.
	rooms := s.store.GetUserRoomIDs(c.UserID)

	// Rate limit — admins get a higher limit
	limit := s.cfg.Server.RateLimits.DeletesPerMinute
	if isAdmin {
		limit = s.cfg.Server.RateLimits.AdminDeletesPerMinute
	}
	if !s.limiter.allowPerMinute("delete:"+c.UserID, limit) {
		c.Encoder.Encode(protocol.Error{Type: "error", Code: protocol.ErrRateLimited, Message: "Too many deletes — wait a moment"})
		return
	}

	// Search room DBs for the message
	for _, roomID := range rooms {
		db, err := s.store.RoomDB(roomID)
		if err != nil {
			continue
		}
		var sender string
		err = db.QueryRow(`SELECT sender FROM messages WHERE id = ? AND deleted = 0`, msg.ID).Scan(&sender)
		if err != nil {
			continue
		}

		// Permission check: own messages or admin
		if sender != c.UserID && !isAdmin {
			c.Encoder.Encode(protocol.Error{
				Type:    "error",
				Code:    protocol.ErrNotAuthorized,
				Message: "You can only delete your own messages",
				Ref:     msg.ID,
			})
			return
		}

		fileIDs, err := s.store.DeleteRoomMessage(roomID, msg.ID, c.UserID)
		if err != nil {
			s.logger.Error("delete failed", "room", roomID, "id", msg.ID, "error", err)
			return
		}
		s.cleanupFiles(fileIDs)

		s.broadcastToRoom(roomID, protocol.Deleted{
			Type:      "deleted",
			ID:        msg.ID,
			DeletedBy: c.UserID,
			TS:        time.Now().Unix(),
			Room:      roomID,
		})
		return
	}

	// Search group DM DBs
	groups, err := s.store.GetUserGroups(c.UserID)
	if err != nil {
		return
	}

	for _, g := range groups {
		db, err := s.store.GroupDB(g.ID)
		if err != nil {
			continue
		}
		var sender string
		err = db.QueryRow(`SELECT sender FROM messages WHERE id = ? AND deleted = 0`, msg.ID).Scan(&sender)
		if err != nil {
			continue
		}

		// DMs: own messages only, no admin override
		if sender != c.UserID {
			c.Encoder.Encode(protocol.Error{
				Type:    "error",
				Code:    protocol.ErrNotAuthorized,
				Message: "You can only delete your own messages in DMs",
				Ref:     msg.ID,
			})
			return
		}

		fileIDs, err := s.store.DeleteGroupMessage(g.ID, msg.ID, c.UserID)
		if err != nil {
			s.logger.Error("delete failed", "group", g.ID, "id", msg.ID, "error", err)
			return
		}
		s.cleanupFiles(fileIDs)

		s.broadcastToGroup(g.ID, protocol.Deleted{
			Type:      "deleted",
			ID:        msg.ID,
			DeletedBy: c.UserID,
			TS:        time.Now().Unix(),
			Group:     g.ID,
		})
		return
	}

	// Search 1:1 DM DBs
	dms, err := s.store.GetDirectMessagesForUser(c.UserID)
	if err != nil {
		return
	}

	for _, dm := range dms {
		db, err := s.store.DMDB(dm.ID)
		if err != nil {
			continue
		}
		var sender string
		err = db.QueryRow(`SELECT sender FROM messages WHERE id = ? AND deleted = 0`, msg.ID).Scan(&sender)
		if err != nil {
			continue
		}

		// DMs: own messages only, no admin override
		if sender != c.UserID {
			c.Encoder.Encode(protocol.Error{
				Type:    "error",
				Code:    protocol.ErrNotAuthorized,
				Message: "You can only delete your own messages in DMs",
				Ref:     msg.ID,
			})
			return
		}

		fileIDs, err := s.store.DeleteDMMessage(dm.ID, msg.ID, c.UserID)
		if err != nil {
			s.logger.Error("delete failed", "dm", dm.ID, "id", msg.ID, "error", err)
			return
		}
		s.cleanupFiles(fileIDs)

		// Broadcast to both DM members
		deleted := protocol.Deleted{
			Type:      "deleted",
			ID:        msg.ID,
			DeletedBy: c.UserID,
			TS:        time.Now().Unix(),
			DM:        dm.ID,
		}
		s.mu.RLock()
		for _, client := range s.clients {
			if client.UserID == dm.UserA || client.UserID == dm.UserB {
				client.Encoder.Encode(deleted)
			}
		}
		s.mu.RUnlock()
		return
	}
}

// cleanupFiles deletes file blobs from disk and their hash entries.
func (s *Server) cleanupFiles(fileIDs []string) {
	if s.files == nil || s.store == nil || len(fileIDs) == 0 {
		return
	}
	for _, fid := range fileIDs {
		if fid == "" {
			continue
		}
		os.Remove(filepath.Join(s.files.dir, fid))
		s.store.DeleteFileHash(fid)
	}
}

// handleLeaveGroup removes a user from a group DM via the leave_group
// protocol message. Self-leave path: validates membership, then delegates
// to performGroupLeave for the actual mutation + broadcast + echo.
func (s *Server) handleLeaveGroup(c *Client, raw json.RawMessage) {
	var msg protocol.LeaveGroup
	if err := json.Unmarshal(raw, &msg); err != nil {
		return
	}

	if s.store != nil {
		// Membership check before mutation. Privacy: the response for
		// "group does not exist", "DB lookup failed", and "you are not
		// a member of an existing group" MUST be byte-identical so a
		// probing client cannot use leave_group to discover whether a
		// group ID exists or who its members are. Matches the convention
		// in handleSendGroup and handleLeaveDM. Uses ErrUnknownGroup
		// rather than ErrNotAuthorized to align with handleSendGroup.
		isMember, err := s.store.IsGroupMember(msg.Group, c.UserID)
		if err != nil || !isMember {
			c.Encoder.Encode(protocol.Error{
				Type:    "error",
				Code:    protocol.ErrUnknownGroup,
				Message: "You are not a member of this group",
			})
			return
		}
	}

	// Phase 14: last-admin gate. If caller is the sole admin AND the
	// group has other members, reject with ErrForbidden — they must
	// promote a successor first. The check is skipped when the caller
	// is the SOLE member of the group: there's no governance concern
	// (nobody to be ungoverned), no successor to promote to, and the
	// performGroupLeave path will correctly trigger last-member cleanup
	// on its own. Without this carve-out a solo member would be
	// permanently trapped.
	if s.store != nil {
		if isAdmin, _ := s.store.IsGroupAdmin(msg.Group, c.UserID); isAdmin {
			if count, _ := s.store.CountGroupAdmins(msg.Group); count == 1 {
				if members, _ := s.store.GetGroupMembers(msg.Group); len(members) > 1 {
					c.Encoder.Encode(protocol.Error{
						Type:    "error",
						Code:    protocol.ErrForbidden,
						Message: "Cannot leave — you are the last admin. Promote another member first, or use /delete to dissolve the group.",
					})
					return
				}
			}
		}
	}

	// Self-leave: empty reason, empty by. The shared performGroupLeave
	// handles removal, last-member cleanup, broadcasting group_event{leave}
	// to remaining members, and echoing group_left to the leaver's own
	// sessions.
	s.performGroupLeave(msg.Group, c.UserID, "", "")
}

// performGroupLeave is the shared post-validation leave path used by
// handleLeaveGroup (self-leave, empty reason and by), handleRemoveFromGroup
// (admin-initiated, reason="removed" with by=<admin user ID>), and the
// per-group branch of handleRetirement (reason="retirement", empty by).
// It is idempotent at the data layer:
//   - RemoveGroupMember is a no-op if the user is already gone
//   - Last-member cleanup is idempotent via DeleteGroupConversation
//
// Side effects:
//   - Removes userID from group_members (idempotent)
//   - Records a group_events row (per Phase 14 audit contract — this is the
//     SOLE recording site for "leave" events; callers MUST NOT duplicate).
//     Audit is written BEFORE the last-member cleanup check so the row lands
//     in the surviving DB file on non-terminal leaves, and is harmlessly
//     reaped along with the file on last-member cleanup.
//   - Triggers DeleteGroupConversation if the group is now empty
//   - Broadcasts group_event{leave, user, reason, by} to remaining members
//   - Echoes group_left{group, reason, by} to all of userID's connected
//     sessions
//
// reason/by are propagated through both the audit row, the broadcast, and
// the echo so clients can render specific status messages — "alice left"
// vs "bob was removed by alice" vs "carol's account was retired".
//
// Ordering inside this helper follows the audit contract from groups_admin.md:
// mutation → audit → last-member-cleanup → broadcast → echo. The state
// mutation must commit first; audit runs best-effort (logged + continue);
// cleanup runs before broadcast so broadcasts reflect fully-committed state;
// echo last so the leaver's sessions see their removal after remaining members.
func (s *Server) performGroupLeave(groupID, userID, reason, by string) {
	if s.store != nil {
		if err := s.store.RemoveGroupMember(groupID, userID); err != nil {
			s.logger.Error("failed to remove group member",
				"user", userID, "group", groupID, "error", err)
			// Continue anyway — broadcast/echo are best-effort and the
			// caller may have already done the removal directly.
		}

		// Record audit event BEFORE last-member cleanup so the row lands
		// in the surviving file on non-terminal leaves. On last-member
		// cleanup the per-group DB file gets unlinked and this row dies
		// with it — harmless, since there's nobody left to read it anyway.
		// Best-effort: audit failure does not block broadcast or cleanup.
		if err := s.store.RecordGroupEvent(
			groupID, "leave", userID, by, reason, "", false, time.Now().Unix(),
		); err != nil {
			s.logger.Error("failed to record group event",
				"group", groupID, "event", "leave", "user", userID, "error", err)
		}

		// Last-member cleanup: if removing this user emptied the group,
		// drop the row + group-<id>.db file + cached *sql.DB handle.
		// Idempotent — safe under concurrent calls.
		if remaining, err := s.store.GetGroupMembers(groupID); err == nil && len(remaining) == 0 {
			if err := s.store.DeleteGroupConversation(groupID); err != nil {
				s.logger.Error("group cleanup failed",
					"group", groupID, "error", err)
			} else {
				s.logger.Info("group cleaned up (last member left)",
					"group", groupID, "user", userID, "reason", reason)
			}
		}
	}

	// Notify remaining members
	s.broadcastToGroup(groupID, protocol.GroupEvent{
		Type:   "group_event",
		Group:  groupID,
		Event:  "leave",
		User:   userID,
		By:     by,
		Reason: reason,
	})

	// Echo group_left to all of the leaver's own sessions. They are NOT
	// in the broadcast set above (already removed from members), so this
	// echo is the only way they learn the leave succeeded.
	left := protocol.GroupLeft{
		Type:   "group_left",
		Group:  groupID,
		Reason: reason,
		By:     by,
	}
	s.mu.RLock()
	for _, client := range s.clients {
		if client.UserID == userID {
			client.Encoder.Encode(left)
		}
	}
	s.mu.RUnlock()

	s.logger.Info("group leave",
		"user", userID,
		"group", groupID,
		"reason", reason,
		"by", by,
	)
}

// handleDeleteGroup processes a client request to remove a group from
// every device on the user's account. Distinct from leave_group:
//
//   - leave_group is a membership change. The user stops being a member
//     of the group; remaining members are notified; the leaver's local
//     state stays (sidebar greys, history scrollable until /delete).
//
//   - delete_group is leave + multi-device purge intent. The user leaves
//     server-side (if still a member) AND records a deletion intent so
//     every other device of the same user — currently connected via the
//     group_deleted echo, or offline-then-syncing via deleted_groups —
//     wipes the group's local state.
//
// The handler is idempotent: re-running on a group the user has already
// left just records the deletion intent (which is itself idempotent via
// INSERT OR IGNORE) and re-broadcasts the echo. Both Are safe.
//
// Ordering matters: the deletion intent is RECORDED FIRST, before the
// inline leave logic. If the user is the last member and the leave
// triggers DeleteGroupConversation, that cleanup deliberately does NOT
// touch deleted_groups (see store/group_deletion.go), so the row we
// just wrote survives the cleanup. Offline devices catching up later
// see the deletion record and purge correctly.
func (s *Server) handleDeleteGroup(c *Client, raw json.RawMessage) {
	var msg protocol.DeleteGroup
	if err := json.Unmarshal(raw, &msg); err != nil {
		return
	}

	if s.store == nil {
		return
	}

	// Phase 14: inline last-admin gate. Only applies when caller is
	// currently a member — non-members can always /delete to clean up
	// their own view because they cannot be the last admin of a group
	// they are not in. The check runs BEFORE RecordGroupDeletion so a
	// rejected /delete leaves no stale sidecar row. Error message is
	// intentionally identical to handleLeaveGroup's rejection — the
	// client's inline promote-picker dialog handles the UX delta, the
	// raw server error is the fallback path.
	//
	// This check is inline and does NOT refactor handleDeleteGroup to
	// delegate to performGroupLeave. Three load-bearing differences
	// prevent that collapse:
	//  1. Echo type is GroupDeleted (purge local history) vs GroupLeft
	//     (keep local history, read-only) — multi-device /delete
	//     semantics depend on the distinction.
	//  2. RecordGroupDeletion MUST run BEFORE any leave steps so the
	//     sidecar row survives potential last-member cleanup.
	//     performGroupLeave has no equivalent ordering constraint.
	//  3. Non-member idempotency: handleDeleteGroup still records the
	//     deletion intent and echoes group_deleted even if the caller
	//     has already left the group. performGroupLeave assumes the
	//     caller was a member.
	isMemberGate, _ := s.store.IsGroupMember(msg.Group, c.UserID)
	if isMemberGate {
		if isAdmin, _ := s.store.IsGroupAdmin(msg.Group, c.UserID); isAdmin {
			if count, _ := s.store.CountGroupAdmins(msg.Group); count == 1 {
				// Same solo-member carve-out as handleLeaveGroup: if the
				// caller is the only member of the group, /delete is
				// equivalent to "dissolve the group entirely" and the
				// last-admin rule doesn't apply (nobody to be ungoverned).
				if members, _ := s.store.GetGroupMembers(msg.Group); len(members) > 1 {
					c.Encoder.Encode(protocol.Error{
						Type:    "error",
						Code:    protocol.ErrForbidden,
						Message: "Cannot leave — you are the last admin. Promote another member first, or use /delete to dissolve the group.",
					})
					return
				}
			}
		}
	}

	// 1. Record the deletion intent FIRST. This is the catchup signal
	//    for the user's offline devices and must survive any subsequent
	//    leave/cleanup. INSERT OR IGNORE makes it safe to record before
	//    we know whether the user is currently a member, and safe to
	//    re-run on a previously-deleted group (no-op).
	if err := s.store.RecordGroupDeletion(c.UserID, msg.Group); err != nil {
		s.logger.Error("failed to record group deletion",
			"user", c.UserID, "group", msg.Group, "error", err)
		// Continue anyway — the deletion intent is best-effort. The
		// live group_deleted echo will still tell connected devices to
		// purge; only the offline-catchup path is degraded.
	}

	// 2. Run the leave logic if the user is still a member. Reuse the
	//    membership result from the last-admin gate above to avoid a
	//    second query on the hot path. If the user has already left
	//    (e.g. previously /leave'd, or this is a second device
	//    retroactively /delete'ing), skip the leave but still proceed
	//    to the echo step.
	isMember := isMemberGate
	if isMember {
		if err := s.store.RemoveGroupMember(msg.Group, c.UserID); err != nil {
			s.logger.Error("failed to remove group member during delete",
				"user", c.UserID, "group", msg.Group, "error", err)
		} else {
			// Phase 14 audit: record the leave BEFORE last-member cleanup
			// so the row lands in the surviving file on non-terminal paths.
			// On last-member cleanup the row dies with the file (harmless).
			// Best-effort — audit failures don't block the broadcast.
			if err := s.store.RecordGroupEvent(
				msg.Group, "leave", c.UserID, "", "", "", false, time.Now().Unix(),
			); err != nil {
				s.logger.Error("failed to record group event",
					"group", msg.Group, "event", "leave", "user", c.UserID, "error", err)
			}

			// Notify remaining members the same way leave_group does.
			// Empty By/Reason mirror self-leave semantics.
			s.broadcastToGroup(msg.Group, protocol.GroupEvent{
				Type:  "group_event",
				Group: msg.Group,
				Event: "leave",
				User:  c.UserID,
			})

			// Last-member cleanup. If we just removed the only remaining
			// member, drop the group row + db file. The cleanup does NOT
			// touch the deleted_groups row we wrote in step 1, so offline
			// catchup still works.
			if remaining, err := s.store.GetGroupMembers(msg.Group); err == nil && len(remaining) == 0 {
				if err := s.store.DeleteGroupConversation(msg.Group); err != nil {
					s.logger.Error("group cleanup failed",
						"group", msg.Group, "error", err)
				} else {
					s.logger.Info("group cleaned up (last member /delete'd)",
						"group", msg.Group, "user", c.UserID)
				}
			}
		}
	}

	// 3. Echo group_deleted to ALL of the user's currently-connected
	//    sessions. This is the canonical multi-device propagation path —
	//    every device of this user that is online RIGHT NOW will receive
	//    this and purge. Devices that are offline pick up the deletion
	//    via deleted_groups on their next handshake.
	deleted := protocol.GroupDeleted{
		Type:  "group_deleted",
		Group: msg.Group,
	}
	s.mu.RLock()
	for _, client := range s.clients {
		if client.UserID == c.UserID {
			client.Encoder.Encode(deleted)
		}
	}
	s.mu.RUnlock()

	s.logger.Info("group delete",
		"user", c.UserID,
		"group", msg.Group,
		"was_member", isMember,
	)
}

// handleLeaveRoom removes a user from a room via the leave_room
// protocol message. Self-leave path: validates membership, checks the
// allow_self_leave_rooms policy gate, then delegates to performRoomLeave
// for the actual mutation + broadcast + echo + epoch rotation.
//
// Rooms are admin-managed, so the policy gate exists for deployments
// that want admins to control all room membership. The flag defaults
// to false (admins manage), but can be enabled per-deployment in
// server.toml. Hot-reloadable.
func (s *Server) handleLeaveRoom(c *Client, raw json.RawMessage) {
	var msg protocol.LeaveRoom
	if err := json.Unmarshal(raw, &msg); err != nil {
		return
	}

	if s.store == nil {
		return
	}

	// Membership check first. Privacy: the response for "room does
	// not exist" and "you are not a member of an existing room" MUST
	// be byte-identical so a probing client cannot use leave_room to
	// discover whether a given room ID exists. Matches the convention
	// in handleSend, handleSendGroup, handleSendDM, handleLeaveGroup,
	// and handleLeaveDM — uses ErrUnknownRoom with a generic message.
	//
	// The policy gate below uses a DIFFERENT error (ErrForbidden) and
	// only fires for users who passed this check, so the membership
	// status is implicit in which error code the client sees. That's
	// fine — a user who is a member of a room already knows they are,
	// so the disclosure is a no-op.
	if !s.store.IsRoomMemberByID(msg.Room, c.UserID) {
		c.Encoder.Encode(protocol.Error{
			Type:    "error",
			Code:    protocol.ErrUnknownRoom,
			Message: "You are not a member of this room",
		})
		return
	}

	// Policy gate. Hot-reloadable: read under cfg RLock so a config reload
	// flipping the flag mid-session takes effect on the next /leave attempt
	// without any client refresh.
	//
	// Phase 12: the gate branches on retired state. Active rooms use
	// allow_self_leave_rooms (default false — admin-managed membership).
	// Retired rooms use allow_self_leave_retired_rooms (default true —
	// users can clean up dead rooms even when active-room leave is
	// locked down). See Q10 of the Phase 12 design.
	isRetired := s.store.IsRoomRetired(msg.Room)
	s.cfg.RLock()
	var allowed bool
	if isRetired {
		allowed = s.cfg.Server.Server.AllowSelfLeaveRetiredRooms
	} else {
		allowed = s.cfg.Server.Server.AllowSelfLeaveRooms
	}
	s.cfg.RUnlock()
	if !allowed {
		c.Encoder.Encode(protocol.Error{
			Type:    "error",
			Code:    protocol.ErrForbidden,
			Message: "Forbidden — please contact an admin to leave this room",
		})
		return
	}

	// Self-leave: empty reason. The shared performRoomLeave handles
	// removal, broadcasting room_event{leave} to remaining members,
	// echoing room_left to the leaver's own sessions, and marking the
	// room for epoch rotation.
	s.performRoomLeave(msg.Room, c.UserID, "")
}

// performRoomLeave is the shared post-validation leave path for rooms.
// Used today by handleLeaveRoom (self-leave, empty reason); will be
// reused by Phase 12's room retirement path (reason "retirement"), the
// future admin remove-from-room kick mechanism (reason "admin"), and
// the user-retirement-affects-rooms path (reason "user_retired").
//
// Mirrors performGroupLeave structurally but with three room-specific
// differences:
//
//  1. No last-member cleanup. Rooms are admin-managed and persist even
//     when empty — an admin can re-add members or retire the room
//     explicitly. This is the opposite of groups, where the last-member
//     leave triggers full cleanup.
//
//  2. Epoch rotation is required. Rooms use epoch-based encryption,
//     so removing a member must rotate the key for forward secrecy
//     (the leaver cannot decrypt messages sent after they leave).
//     Groups and DMs use per-message wrapped keys and don't need this.
//
//  3. The broadcastToRoom function reads the current member set from
//     the store, so it AUTOMATICALLY excludes the leaver after the
//     RemoveRoomMember call above. No manual filtering needed.
//
// Caller must have already validated membership and policy.
func (s *Server) performRoomLeave(roomID, userID, reason string) {
	if s.store == nil {
		return
	}

	if err := s.store.RemoveRoomMember(roomID, userID); err != nil {
		s.logger.Error("failed to remove room member",
			"user", userID, "room", roomID, "error", err)
		// Continue anyway — broadcast/echo are best-effort.
	}

	// Notify remaining members. broadcastToRoom rebuilds the member set
	// AFTER the delete above, so the leaver is automatically excluded.
	s.broadcastToRoom(roomID, protocol.RoomEvent{
		Type:   "room_event",
		Room:   roomID,
		Event:  "leave",
		User:   userID,
		Reason: reason,
	})

	// Echo room_left to all of the leaver's own sessions. They are not
	// in the broadcast above (already removed from members), so without
	// this echo they would never know the leave succeeded.
	left := protocol.RoomLeft{
		Type:   "room_left",
		Room:   roomID,
		Reason: reason,
	}
	s.mu.RLock()
	for _, client := range s.clients {
		if client.UserID == userID {
			client.Encoder.Encode(left)
		}
	}
	s.mu.RUnlock()

	// Mark room for epoch rotation. Same path handleRetirement uses for
	// users: the next sender will trigger epoch_trigger and the new key
	// will be distributed to the now-smaller member set, excluding the
	// leaver. Forward secrecy: leaver cannot decrypt messages sent after
	// this point.
	s.epochs.getOrCreate(roomID, s.epochs.currentEpochNum(roomID))

	s.logger.Info("room leave",
		"user", userID,
		"room", roomID,
		"reason", reason,
	)
}

// handleDeleteRoom processes a client request to remove a room from
// every device on the user's account. Structurally parallel to
// handleDeleteGroup (Phase 11), with three room-specific differences:
//
//  1. Policy gate branches on retired state — active rooms use
//     allow_self_leave_rooms, retired rooms use
//     allow_self_leave_retired_rooms. Q10 of the Phase 12 design: no
//     split action, if the policy denies the whole /delete is
//     rejected.
//
//  2. Epoch rotation happens for active rooms only. Retired rooms
//     don't rotate (Q4: existing keys stay intact for history
//     decryption; writes are already blocked by IsRoomRetired so a
//     defensive rotation is pointless work).
//
//  3. Last-member cleanup calls DeleteRoomRecord — the cascade that
//     drops the rooms row, room_members rows, epoch_keys rows, and
//     unlinks the per-room DB file.
//
// Ordering matters: the deletion intent is RECORDED FIRST in the
// deleted_rooms sidecar, before the inline leave logic. If the user is
// the last member and the leave triggers DeleteRoomRecord, that
// cleanup deliberately does NOT touch deleted_rooms (see
// store/room_deletion.go), so the row we just wrote survives the
// cleanup. Offline devices catching up later see the deletion record
// and purge correctly.
//
// The handler is idempotent: re-running on a room the user has already
// left just records the deletion intent (INSERT OR IGNORE) and
// re-broadcasts the echo. Both are safe.
func (s *Server) handleDeleteRoom(c *Client, raw json.RawMessage) {
	var msg protocol.DeleteRoom
	if err := json.Unmarshal(raw, &msg); err != nil {
		return
	}

	if s.store == nil {
		return
	}

	// Membership check first. Privacy: the response for "room does not
	// exist" and "you are not a member of an existing room" MUST be
	// byte-identical so a probing client cannot use delete_room to
	// discover whether a given room ID exists. Matches the convention
	// in handleSend, handleLeaveRoom, and the other membership-gated
	// handlers.
	//
	// The policy gate below uses ErrForbidden which DOES reveal
	// membership (distinct from unknown-room), but the user already
	// knows they're a member, so the disclosure is a no-op.
	if !s.store.IsRoomMemberByID(msg.Room, c.UserID) {
		c.Encoder.Encode(protocol.Error{
			Type:    "error",
			Code:    protocol.ErrUnknownRoom,
			Message: "You are not a member of this room",
		})
		return
	}

	// Policy gate — branches on retired state. Active rooms use
	// allow_self_leave_rooms, retired rooms use
	// allow_self_leave_retired_rooms. Hot-reloadable via cfg RLock.
	isRetired := s.store.IsRoomRetired(msg.Room)
	s.cfg.RLock()
	var allowed bool
	if isRetired {
		allowed = s.cfg.Server.Server.AllowSelfLeaveRetiredRooms
	} else {
		allowed = s.cfg.Server.Server.AllowSelfLeaveRooms
	}
	s.cfg.RUnlock()
	if !allowed {
		c.Encoder.Encode(protocol.Error{
			Type:    "error",
			Code:    protocol.ErrForbidden,
			Message: "Forbidden — please contact an admin to delete this room",
		})
		return
	}

	// 1. Record the deletion intent FIRST. This is the catchup signal
	//    for the user's offline devices and must survive any subsequent
	//    leave/cleanup. INSERT OR IGNORE makes it safe to re-run on a
	//    previously-deleted room.
	if err := s.store.RecordRoomDeletion(c.UserID, msg.Room); err != nil {
		s.logger.Error("failed to record room deletion",
			"user", c.UserID, "room", msg.Room, "error", err)
		// Continue anyway — the deletion intent is best-effort. The
		// live room_deleted echo will still tell connected devices to
		// purge; only the offline-catchup path is degraded.
	}

	// 2. Run the leave logic. RemoveRoomMember is idempotent at the
	//    store layer (no error for a user who's already gone).
	if err := s.store.RemoveRoomMember(msg.Room, c.UserID); err != nil {
		s.logger.Error("failed to remove room member during delete",
			"user", c.UserID, "room", msg.Room, "error", err)
	}

	// Broadcast the leave to remaining members. Same shape as
	// performRoomLeave's broadcast, but with an empty reason (self-
	// initiated delete, not admin/retirement). broadcastToRoom reads
	// the current member set AFTER the removal above, so the caller
	// is automatically excluded.
	s.broadcastToRoom(msg.Room, protocol.RoomEvent{
		Type:   "room_event",
		Room:   msg.Room,
		Event:  "leave",
		User:   c.UserID,
		Reason: "",
	})

	// 3. Last-member cleanup. If we just removed the only remaining
	//    member, run the full cleanup cascade: drop the rooms row,
	//    room_members rows, epoch_keys rows, and unlink the per-room
	//    DB file. The cascade deliberately does NOT touch deleted_rooms
	//    (see DeleteRoomRecord in store/room_deletion.go), so the row
	//    we wrote in step 1 survives.
	if remaining := s.store.GetRoomMemberIDsByRoomID(msg.Room); len(remaining) == 0 {
		if err := s.store.DeleteRoomRecord(msg.Room); err != nil {
			s.logger.Error("room cleanup failed",
				"room", msg.Room, "error", err)
		} else {
			s.logger.Info("room cleaned up (last member /delete'd)",
				"room", msg.Room, "user", c.UserID)
		}
	} else if !isRetired {
		// 4. Mark the room for epoch rotation. Only for active rooms —
		//    retired rooms don't rotate (Q4). If this was the last
		//    member, we skipped the cleanup branch anyway because the
		//    room is now gone.
		s.epochs.getOrCreate(msg.Room, s.epochs.currentEpochNum(msg.Room))
	}

	// 5. Echo room_deleted to ALL of the user's currently-connected
	//    sessions. This is the canonical multi-device propagation path:
	//    every device of this user that is online RIGHT NOW will
	//    receive this and purge local state. Devices that are offline
	//    pick up the deletion via deleted_rooms on their next
	//    handshake.
	//
	//    Distinct from room_left: room_left is the leave echo (keeps
	//    local history), room_deleted is the delete echo (purges
	//    local history).
	deleted := protocol.RoomDeleted{
		Type: "room_deleted",
		Room: msg.Room,
	}
	s.mu.RLock()
	for _, client := range s.clients {
		if client.UserID == c.UserID {
			client.Encoder.Encode(deleted)
		}
	}
	s.mu.RUnlock()

	s.logger.Info("room delete",
		"user", c.UserID,
		"room", msg.Room,
		"retired", isRetired,
	)
}

// handleRenameGroup updates a group DM's name and broadcasts. Phase 14
// added the admin gate and the byte-identical privacy convention (non-admin
// rejection collapses into the same ErrUnknownGroup frame as unknown group
// and non-member). Also added the RecordGroupEvent call (audit contract:
// rename is one of the five admin event types with a dedicated recording
// site in this handler) and the Quiet flag.
//
// The historical group_renamed echo is KEPT for backward compatibility
// alongside the new group_event{rename} broadcast. Clients on the latest
// protocol version process the group_event; older clients fall back to
// group_renamed. Sending both lets the upgrade land without a coordinated
// client push.
func (s *Server) handleRenameGroup(c *Client, raw json.RawMessage) {
	var msg protocol.RenameGroup
	if err := json.Unmarshal(raw, &msg); err != nil {
		return
	}

	if !s.checkAdminActionRateLimit(c, msg.Group) {
		return
	}
	if !s.checkGroupAdminAuth(c, msg.Group) {
		return
	}

	if err := s.store.RenameGroup(msg.Group, msg.Name); err != nil {
		s.logger.Error("failed to rename group", "group", msg.Group, "error", err)
		c.Encoder.Encode(protocol.Error{Type: "error", Code: "internal", Message: "failed to rename group"})
		return
	}

	// Audit (best-effort).
	if err := s.store.RecordGroupEvent(
		msg.Group, "rename", c.UserID, c.UserID, "", msg.Name, msg.Quiet, time.Now().Unix(),
	); err != nil {
		s.logger.Error("failed to record group event",
			"group", msg.Group, "event", "rename", "error", err)
	}

	// Dual broadcast during the single-repo upgrade window:
	//
	//   1. Legacy GroupRenamed for pre-Phase-14 clients that only know
	//      about the old shape (sshkey-term is not yet at Phase 14 when
	//      this server chunk lands — chunks 3-6 update it).
	//   2. New GroupEvent{rename} for post-Phase-14 clients and sync
	//      replay (GetGroupEventsSince returns rename events that the
	//      client routes through the unified group_event dispatch path,
	//      so live broadcasts and sync replay must use the same shape).
	//
	// Once sshkey-term is fully at Phase 14, the legacy GroupRenamed
	// broadcast can be removed in a follow-up cleanup.
	s.broadcastToGroup(msg.Group, protocol.GroupRenamed{
		Type:      "group_renamed",
		Group:     msg.Group,
		Name:      msg.Name,
		RenamedBy: c.UserID,
	})
	s.broadcastToGroup(msg.Group, protocol.GroupEvent{
		Type:  "group_event",
		Group: msg.Group,
		Event: "rename",
		User:  c.UserID,
		By:    c.UserID,
		Name:  msg.Name,
		Quiet: msg.Quiet,
	})

	s.logger.Info("group renamed",
		"group", msg.Group,
		"name", msg.Name,
		"renamed_by", c.UserID,
	)
}

// handleCreateDM creates or returns an existing 1:1 DM between the caller
// and a single other user. The pair is canonicalized alphabetically and
// deduplicates: calling twice for the same pair returns the same row.
func (s *Server) handleCreateDM(c *Client, raw json.RawMessage) {
	if !s.limiter.allowPerMinute("dm_create:"+c.UserID, s.cfg.Server.RateLimits.DMCreatesPerMinute) {
		c.Encoder.Encode(protocol.Error{Type: "error", Code: protocol.ErrRateLimited, Message: "Too many DMs — wait a moment"})
		return
	}

	var msg protocol.CreateDM
	if err := json.Unmarshal(raw, &msg); err != nil {
		c.Encoder.Encode(protocol.Error{Type: "error", Code: "invalid_message", Message: "malformed create_dm"})
		return
	}

	if msg.Other == c.UserID {
		c.Encoder.Encode(protocol.Error{Type: "error", Code: "invalid_message", Message: "Cannot create a DM with yourself"})
		return
	}

	// Reject if the other user is retired
	if retired := s.findRetiredMember([]string{msg.Other}); retired != "" {
		c.Encoder.Encode(protocol.Error{
			Type:    "error",
			Code:    protocol.ErrUserRetired,
			Message: fmt.Sprintf("Cannot create DM — %s's account has been retired", retired),
		})
		return
	}

	if s.store == nil {
		return
	}

	// Serialize against any concurrent 1:1 DM cleanup. If a cleanup is in
	// progress (handleLeaveDM holding dmCleanupMu), TryLock fails and we
	// return ErrServerBusy so the client can retry. By the next attempt
	// the cleanup will have finished and CreateOrGetDirectMessage will
	// either find no row (and create a fresh one) or find a still-alive
	// DM the user is reconnecting to. Holding the lock across the create
	// guarantees we never dedup to a row that is about to be deleted.
	if !s.dmCleanupMu.TryLock() {
		c.Encoder.Encode(protocol.Error{
			Type:    "error",
			Code:    protocol.ErrServerBusy,
			Message: "Server is processing another DM operation, please try again",
		})
		return
	}
	defer s.dmCleanupMu.Unlock()

	dmID := generateID("dm_")
	dm, err := s.store.CreateOrGetDirectMessage(dmID, c.UserID, msg.Other)
	if err != nil {
		s.logger.Error("failed to create DM", "error", err)
		c.Encoder.Encode(protocol.Error{Type: "error", Code: "internal", Message: "failed to create DM"})
		return
	}

	created := protocol.DMCreated{
		Type:    "dm_created",
		DM:      dm.ID,
		Members: []string{dm.UserA, dm.UserB},
	}

	// Send dm_created to all sessions of both members
	s.mu.RLock()
	for _, client := range s.clients {
		if client.UserID == dm.UserA || client.UserID == dm.UserB {
			client.Encoder.Encode(created)
		}
	}
	s.mu.RUnlock()

	s.logger.Info("DM created",
		"dm", dm.ID,
		"created_by", c.UserID,
		"other", msg.Other,
	)
}

// handleSendDM processes a 1:1 DM message.
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

	if s.store == nil {
		return
	}

	// Validate DM exists and caller is a party
	dm, err := s.store.GetDirectMessage(msg.DM)
	if err != nil || dm == nil || (dm.UserA != c.UserID && dm.UserB != c.UserID) {
		c.Encoder.Encode(protocol.Error{
			Type:    "error",
			Code:    protocol.ErrUnknownDM,
			Message: "You are not a party to this DM",
		})
		return
	}

	// Reject sends to a retired recipient
	other := dm.OtherUser(c.UserID)
	if s.store.IsUserRetired(other) {
		c.Encoder.Encode(protocol.Error{
			Type:    "error",
			Code:    protocol.ErrUserRetired,
			Message: fmt.Sprintf("Cannot send — %s's account has been retired", other),
		})
		return
	}

	// Validate wrapped_keys has exactly 2 entries matching the pair
	if len(msg.WrappedKeys) != 2 {
		c.Encoder.Encode(protocol.Error{
			Type:    "error",
			Code:    protocol.ErrInvalidWrappedKeys,
			Message: "wrapped_keys must have exactly 2 entries for a 1:1 DM",
		})
		return
	}
	if _, ok := msg.WrappedKeys[dm.UserA]; !ok {
		c.Encoder.Encode(protocol.Error{Type: "error", Code: protocol.ErrInvalidWrappedKeys, Message: "wrapped_keys must include both DM members"})
		return
	}
	if _, ok := msg.WrappedKeys[dm.UserB]; !ok {
		c.Encoder.Encode(protocol.Error{Type: "error", Code: protocol.ErrInvalidWrappedKeys, Message: "wrapped_keys must include both DM members"})
		return
	}

	outMsg := protocol.DM{
		Type:        "dm",
		ID:          generateID("msg_"),
		From:        c.UserID,
		DM:          dm.ID,
		TS:          time.Now().Unix(),
		WrappedKeys: msg.WrappedKeys,
		Payload:     msg.Payload,
		FileIDs:     msg.FileIDs,
		Signature:   msg.Signature,
	}

	// Store in DM DB — messages are always written regardless of cutoffs.
	// The cutoff filters on read, not on write.
	if err := s.store.InsertDMMessage(dm.ID, store.StoredMessage{
		ID:          outMsg.ID,
		Sender:      outMsg.From,
		TS:          outMsg.TS,
		Payload:     outMsg.Payload,
		FileIDs:     outMsg.FileIDs,
		Signature:   outMsg.Signature,
		WrappedKeys: outMsg.WrappedKeys,
	}); err != nil {
		s.logger.Error("failed to store DM", "dm", dm.ID, "error", err)
	}

	// Broadcast to both members' active sessions
	s.mu.RLock()
	for _, client := range s.clients {
		if client.UserID == dm.UserA || client.UserID == dm.UserB {
			client.Encoder.Encode(outMsg)
		}
	}
	s.mu.RUnlock()

	// Notify offline members via push
	go s.notifyOfflineUsers([]string{dm.UserA, dm.UserB})
}

// handleLeaveDM processes a silent leave for a 1:1 DM. Sets the per-user
// history cutoff so the leaver no longer sees messages past this point.
// No broadcast to the other party — the only signal is the dm_left echo
// sent to every active session of the leaver.
func (s *Server) handleLeaveDM(c *Client, raw json.RawMessage) {
	var msg protocol.LeaveDM
	if err := json.Unmarshal(raw, &msg); err != nil {
		return
	}

	if s.store == nil {
		return
	}

	// Load and validate the DM up front. Privacy: the wire response for
	// "DM does not exist", "DB lookup failed", and "you are not a party"
	// MUST be byte-identical so a probing client cannot use /leave to
	// discover whether a given DM ID exists or who is talking to whom.
	// Matches the convention in handleSendDM and the DM history branch.
	dm, err := s.store.GetDirectMessage(msg.DM)
	if err != nil || dm == nil || (dm.UserA != c.UserID && dm.UserB != c.UserID) {
		if err != nil {
			s.logger.Error("failed to load DM", "user", c.UserID, "dm", msg.DM, "error", err)
		}
		c.Encoder.Encode(protocol.Error{
			Type:    "error",
			Code:    protocol.ErrUnknownDM,
			Message: "You are not a party to this DM",
		})
		return
	}

	if err := s.store.SetDMLeftAt(msg.DM, c.UserID, time.Now().Unix()); err != nil {
		// Reaching this branch requires having already passed the membership
		// gate above, so a more specific error here does not leak existence.
		s.logger.Error("failed to leave DM", "user", c.UserID, "dm", msg.DM, "error", err)
		c.Encoder.Encode(protocol.Error{
			Type:    "error",
			Code:    protocol.ErrUnknownDM,
			Message: "Failed to leave DM",
		})
		return
	}

	// Cleanup check: if both parties have now left, the DM is dormant —
	// no one will ever read another message from it. Delete the row and
	// the dm-<id>.db file immediately. dmCleanupMu serializes against
	// handleCreateDM so a concurrent /newdm with the same pair cannot
	// dedup to a row that is mid-deletion. The lock is server-wide but
	// the critical section is microseconds, so contention is negligible.
	s.cleanupDormantDM(msg.DM)

	// Echo to all of the leaver's active sessions. No broadcast to the
	// other party — 1:1 leave is silent by design.
	left := protocol.DMLeft{
		Type: "dm_left",
		DM:   msg.DM,
	}
	s.mu.RLock()
	for _, client := range s.clients {
		if client.UserID == c.UserID {
			client.Encoder.Encode(left)
		}
	}
	s.mu.RUnlock()

	s.logger.Info("DM leave (silent)",
		"user", c.UserID,
		"dm", msg.DM,
	)
}

// cleanupDormantDM checks whether both parties of a 1:1 DM have left and,
// if so, deletes the DM row + per-DM database file. Holds dmCleanupMu so
// that concurrent handleCreateDM calls cannot race the delete.
//
// Re-checks the cutoff state inside the lock so two leavers racing each
// other (alice and bob both calling /leave at the same instant, both
// observing "both > 0" after their respective SetDMLeftAt) result in
// exactly one delete, not a double-free.
func (s *Server) cleanupDormantDM(dmID string) {
	if s.store == nil {
		return
	}

	s.dmCleanupMu.Lock()
	defer s.dmCleanupMu.Unlock()

	dm, err := s.store.GetDirectMessage(dmID)
	if err != nil || dm == nil {
		return
	}
	if dm.UserALeftAt == 0 || dm.UserBLeftAt == 0 {
		return
	}

	if err := s.store.DeleteDirectMessage(dmID); err != nil {
		s.logger.Error("dm cleanup failed", "dm", dmID, "error", err)
		return
	}
	s.logger.Info("DM cleaned up (both parties left)",
		"dm", dmID,
		"user_a", dm.UserA,
		"user_b", dm.UserB,
	)
}

// handleSetProfile updates a user's profile and broadcasts.
func (s *Server) handleSetProfile(c *Client, raw json.RawMessage) {
	if !s.limiter.allowPerMinute("profile:"+c.UserID, s.cfg.Server.RateLimits.ProfilesPerMinute) {
		c.Encoder.Encode(protocol.Error{Type: "error", Code: protocol.ErrRateLimited, Message: "Profile updated too often — wait a moment"})
		return
	}

	var msg protocol.SetProfile
	if err := json.Unmarshal(raw, &msg); err != nil {
		return
	}

	// Validate display name (trim, length, printable characters)
	cleaned, err := config.ValidateDisplayName(msg.DisplayName)
	if err != nil {
		c.Encoder.Encode(protocol.Error{
			Type:    "error",
			Code:    "invalid_profile",
			Message: err.Error(),
		})
		return
	}
	msg.DisplayName = cleaned

	// Check for duplicate display name across all users (case-insensitive)
	if s.store.IsDisplayNameTaken(msg.DisplayName, c.UserID) {
		c.Encoder.Encode(protocol.Error{
			Type:    "error",
			Code:    "username_taken",
			Message: fmt.Sprintf("Display name %q is already in use", msg.DisplayName),
		})
		return
	}

	// Update display name in users.db
	s.store.SetUserDisplayName(c.UserID, msg.DisplayName)

	// Update avatar in data.db profiles table
	if s.store != nil {
		s.store.DataDB().Exec(`
			INSERT INTO profiles (user, avatar_id) VALUES (?, ?)
			ON CONFLICT (user) DO UPDATE SET avatar_id = excluded.avatar_id`,
			c.UserID, msg.AvatarID)
	}

	// Build profile message with pubkey
	pubKey := s.store.GetUserKey(c.UserID)
	parsed, _, _, _, err := ssh.ParseAuthorizedKey([]byte(pubKey))
	if err != nil {
		return
	}

	isAdmin := s.store.IsAdmin(c.UserID)

	profile := protocol.Profile{
		Type:           "profile",
		User:           c.UserID,
		DisplayName:    msg.DisplayName,
		AvatarID:       msg.AvatarID,
		PubKey:         pubKey,
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
		s.store.DataDB().Exec(`
			INSERT INTO profiles (user, status_text) VALUES (?, ?)
			ON CONFLICT (user) DO UPDATE SET status_text = excluded.status_text`,
			c.UserID, msg.Text)
	}
}

// broadcastToRoom sends a message to all connected clients in a room.
func (s *Server) broadcastToRoom(roomID string, msg any) {
	if s.store == nil {
		return
	}
	memberSet := make(map[string]bool)
	for _, uid := range s.store.GetRoomMemberIDsByRoomID(roomID) {
		memberSet[uid] = true
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, client := range s.clients {
		if memberSet[client.UserID] {
			client.Encoder.Encode(msg)
		}
	}
}

// broadcastToGroup sends a message to all connected clients in a group DM.
func (s *Server) broadcastToGroup(groupID string, msg any) {
	if s.store == nil {
		return
	}

	members, err := s.store.GetGroupMembers(groupID)
	if err != nil {
		s.logger.Error("failed to get group members", "group", groupID, "error", err)
		return
	}

	memberSet := make(map[string]bool, len(members))
	for _, m := range members {
		memberSet[m] = true
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, client := range s.clients {
		if memberSet[client.UserID] {
			client.Encoder.Encode(msg)
		}
	}
}

// broadcastToRoomExcept sends to all room members except the given device.
func (s *Server) broadcastToRoomExcept(roomID, excludeDevice string, msg any) {
	if s.store == nil {
		return
	}
	memberSet := make(map[string]bool)
	for _, uid := range s.store.GetRoomMemberIDsByRoomID(roomID) {
		memberSet[uid] = true
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, client := range s.clients {
		if client.DeviceID == excludeDevice {
			continue
		}
		if memberSet[client.UserID] {
			client.Encoder.Encode(msg)
		}
	}
}

// broadcastToGroupExcept sends to all group DM members except the given device.
func (s *Server) broadcastToGroupExcept(groupID, excludeDevice string, msg any) {
	if s.store == nil {
		return
	}

	members, err := s.store.GetGroupMembers(groupID)
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
		if memberSet[client.UserID] {
			client.Encoder.Encode(msg)
		}
	}
}

// handleListPendingKeys returns the list of pending (unapproved) SSH keys.
// Admin-only — non-admin clients receive an error.
func (s *Server) handleListPendingKeys(c *Client) {
	if !s.store.IsAdmin(c.UserID) {
		c.Encoder.Encode(protocol.Error{
			Type:    "error",
			Code:    protocol.ErrNotAuthorized,
			Message: "Only admins can list pending keys",
		})
		return
	}

	var keys []protocol.PendingKeyEntry
	if s.store != nil {
		rows, err := s.store.DataDB().Query(
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

func (s *Server) handleRoomMembers(c *Client, raw json.RawMessage) {
	var req protocol.RoomMembers
	if err := json.Unmarshal(raw, &req); err != nil || req.Room == "" {
		c.Encoder.Encode(protocol.Error{
			Type:    "error",
			Code:    protocol.ErrUnknownRoom,
			Message: "Invalid room_members request",
		})
		return
	}

	// Check membership via rooms.db (req.Room is a nanoid)
	if s.store == nil || !s.store.IsRoomMemberByID(req.Room, c.UserID) {
		c.Encoder.Encode(protocol.Error{
			Type:    "error",
			Code:    protocol.ErrNotAuthorized,
			Message: "You are not a member of room: " + req.Room,
		})
		return
	}

	members := s.store.GetRoomMemberIDsByRoomID(req.Room)

	c.Encoder.Encode(protocol.RoomMembersList{
		Type:    "room_members_list",
		Room:    req.Room,
		Members: members,
	})
}
