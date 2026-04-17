package server

// Phase 15 — message editing handlers.
//
// Three new handlers mirror the existing send-family shape:
//
//   handleEdit       — rooms       (edit / edited)
//   handleEditGroup  — group DMs   (edit_group / group_edited)
//   handleEditDM     — 1:1 DMs     (edit_dm / dm_edited)
//
// All three enforce the same invariant stack (see `message_editing.md`
// for the canonical design):
//
//   1. Membership check (server-side store lookup, byte-identical
//      ErrUnknownX on non-member)
//   2. Retired check (rooms only — ErrRoomRetired)
//   3. Rate limit (EditsPerMinute, shared bucket per user across all
//      three verbs)
//   4. Row fetch by msgID (ErrNoRows → byte-identical ErrUnknownX)
//   5. Author check (row.Sender == c.UserID → byte-identical ErrUnknownX
//      on non-author)
//   6. Deleted check (row.Deleted == true → byte-identical ErrUnknownX
//      so a probing client cannot enumerate tombstones)
//   7. Most-recent check (ErrEditNotMostRecent surfaced — caller is
//      proven author at this point so specific errors are safe)
//   8. Epoch window check (rooms only — ErrEditWindowExpired surfaced)
//   9. WrappedKeys match current membership (groups/DMs only —
//      ErrInvalidWrappedKeys, mirrors handleSendGroup/handleSendDM)
//  10. DB update via UpdateXMessageEdited[WithKeys] (also clears
//      reactions for the edited msgID in the same transaction)
//  11. Broadcast the `edited` / `group_edited` / `dm_edited` envelope
//      to current recipients (rooms/groups via broadcastToX; DMs via
//      direct session iteration)
//
// Signatures are relayed as opaque blobs — the server does not verify
// them on send today, and edit follows the same pattern. Recipients
// verify client-side via their TOFU pinned-key table. See Decision
// log Q12-Q13 in `message_editing.md` for the reasoning and the
// reactions-clearing semantics.

import (
	"database/sql"
	"encoding/json"
	"time"

	"github.com/brushtailmedia/sshkey-chat/internal/protocol"
	"github.com/brushtailmedia/sshkey-chat/internal/store"
)

// handleEdit — rooms.
func (s *Server) handleEdit(c *Client, raw json.RawMessage) {
	if len(raw) > maxPayloadBytes {
		c.Encoder.Encode(protocol.Error{Type: "error", Code: protocol.ErrMessageTooLarge, Message: "Message exceeds 16KB limit"})
		return
	}

	var msg protocol.Edit
	if err := json.Unmarshal(raw, &msg); err != nil {
		c.Encoder.Encode(protocol.Error{Type: "error", Code: "invalid_message", Message: "malformed edit"})
		return
	}

	if s.store == nil {
		return
	}

	// Step 1: membership. Non-members get the byte-identical "unknown"
	// response so a probing client cannot use edit to enumerate room
	// existence. Same pattern as handleSend.
	if !s.store.IsRoomMemberByID(msg.Room, c.UserID) {
		s.sendUnknownRoom(c)
		return
	}

	// Step 2: retired rooms reject writes, per the Phase 12 gate pattern.
	// Ordered after the membership check so non-members still collapse
	// into the unknown response — retired state is members-only info.
	if s.store.IsRoomRetired(msg.Room) {
		c.Encoder.Encode(protocol.Error{
			Type:    "error",
			Code:    protocol.ErrRoomRetired,
			Message: "This room has been archived and is read-only",
		})
		return
	}

	// Step 3: rate limit.
	if !s.limiter.allowPerMinute("edit:"+c.UserID, s.cfg.Server.RateLimits.EditsPerMinute) {
		c.Encoder.Encode(protocol.Error{Type: "error", Code: protocol.ErrRateLimited, Message: "Too many edits — wait a moment"})
		return
	}

	// Step 4-6: fetch row, author check, deleted check. All three failure
	// modes collapse into the same byte-identical "unknown" response.
	row, err := s.store.GetRoomMessageByID(msg.Room, msg.ID)
	if err == sql.ErrNoRows || (err == nil && row != nil && (row.Sender != c.UserID || row.Deleted)) {
		s.sendUnknownRoom(c)
		return
	}
	if err != nil {
		s.logger.Error("edit: fetch row failed", "room", msg.Room, "id", msg.ID, "error", err)
		s.sendUnknownRoom(c)
		return
	}

	// Step 7: most-recent check. Caller is now proven to be the author, so
	// we can surface a specific error.
	mostRecentID, _, err := s.store.GetUserMostRecentMessageIDRoom(msg.Room, c.UserID)
	if err != nil {
		s.logger.Error("edit: most-recent lookup failed", "room", msg.Room, "error", err)
		s.sendUnknownRoom(c)
		return
	}
	if mostRecentID != msg.ID {
		c.Encoder.Encode(protocol.Error{
			Type:    "error",
			Code:    protocol.ErrEditNotMostRecent,
			Message: "You can only edit your most recent message in this room",
			Ref:     msg.ID,
		})
		return
	}

	// Step 8: epoch window. Matches the grace window in handleSend —
	// edit is allowed in the current epoch or the previous one.
	currentEpoch := s.epochs.currentEpochNum(msg.Room)
	if currentEpoch > 0 && (msg.Epoch < currentEpoch-1 || msg.Epoch > currentEpoch) {
		c.Encoder.Encode(protocol.Error{
			Type:    "error",
			Code:    protocol.ErrEditWindowExpired,
			Message: "Edit window expired — epoch has rotated past the grace window",
			Ref:     msg.ID,
		})
		return
	}

	// Step 10: DB update. Rooms use the vanilla UpdateRoomMessageEdited
	// (no wrapped_keys rewrap — rooms share an epoch key). The helper
	// also clears reactions on the edited row in the same transaction.
	editedAt := time.Now().Unix()
	if err := s.store.UpdateRoomMessageEdited(msg.Room, msg.ID, msg.Payload, msg.Signature, editedAt); err != nil {
		if err == sql.ErrNoRows {
			// Row was deleted between our fetch and the update — race with
			// a concurrent delete. Collapse into the byte-identical "unknown".
			s.sendUnknownRoom(c)
			return
		}
		s.logger.Error("edit: update failed", "room", msg.Room, "id", msg.ID, "error", err)
		return
	}

	// Step 11: broadcast. ts is preserved from the stored row (the
	// ORIGINAL send time, not the edit time). edited_at carries the edit
	// moment. file_ids is preserved from the original row — the envelope
	// does not carry a new file_ids field by design.
	s.broadcastToRoom(msg.Room, protocol.Edited{
		Type:      "edited",
		ID:        msg.ID,
		From:      c.UserID,
		Room:      msg.Room,
		TS:        row.TS,
		Epoch:     msg.Epoch,
		Payload:   msg.Payload,
		FileIDs:   row.FileIDs,
		Signature: msg.Signature,
		EditedAt:  editedAt,
	})
	s.logger.Info("room message edited", "room", msg.Room, "id", msg.ID, "user", c.UserID)
}

// handleEditGroup — group DMs.
func (s *Server) handleEditGroup(c *Client, raw json.RawMessage) {
	if len(raw) > maxPayloadBytes {
		c.Encoder.Encode(protocol.Error{Type: "error", Code: protocol.ErrMessageTooLarge, Message: "Message exceeds 16KB limit"})
		return
	}

	var msg protocol.EditGroup
	if err := json.Unmarshal(raw, &msg); err != nil {
		c.Encoder.Encode(protocol.Error{Type: "error", Code: "invalid_message", Message: "malformed edit_group"})
		return
	}

	if s.store == nil {
		return
	}

	// Step 1: membership.
	isMember, err := s.store.IsGroupMember(msg.Group, c.UserID)
	if err != nil || !isMember {
		s.sendUnknownGroup(c)
		return
	}

	// Step 3: rate limit.
	if !s.limiter.allowPerMinute("edit:"+c.UserID, s.cfg.Server.RateLimits.EditsPerMinute) {
		c.Encoder.Encode(protocol.Error{Type: "error", Code: protocol.ErrRateLimited, Message: "Too many edits — wait a moment"})
		return
	}

	// Step 4-6: fetch + author + deleted.
	row, err := s.store.GetGroupMessageByID(msg.Group, msg.ID)
	if err == sql.ErrNoRows || (err == nil && row != nil && (row.Sender != c.UserID || row.Deleted)) {
		s.sendUnknownGroup(c)
		return
	}
	if err != nil {
		s.logger.Error("edit_group: fetch row failed", "group", msg.Group, "id", msg.ID, "error", err)
		s.sendUnknownGroup(c)
		return
	}

	// Step 7: most-recent check.
	mostRecentID, _, err := s.store.GetUserMostRecentMessageIDGroup(msg.Group, c.UserID)
	if err != nil {
		s.logger.Error("edit_group: most-recent lookup failed", "group", msg.Group, "error", err)
		s.sendUnknownGroup(c)
		return
	}
	if mostRecentID != msg.ID {
		c.Encoder.Encode(protocol.Error{
			Type:    "error",
			Code:    protocol.ErrEditNotMostRecent,
			Message: "You can only edit your most recent message in this group",
			Ref:     msg.ID,
		})
		return
	}

	// Step 9: wrapped_keys must match the CURRENT group member set. The
	// client fetches members via Client.GroupMembers before building the
	// edit envelope; if membership changed between fetch and send the
	// server rejects with invalid_wrapped_keys, same as handleSendGroup.
	members, err := s.store.GetGroupMembers(msg.Group)
	if err != nil {
		s.logger.Error("edit_group: GetGroupMembers failed", "group", msg.Group, "error", err)
		s.sendUnknownGroup(c)
		return
	}
	if !wrappedKeysMatchMemberSet(msg.WrappedKeys, members) {
		c.Encoder.Encode(protocol.Error{
			Type:    "error",
			Code:    protocol.ErrInvalidWrappedKeys,
			Message: "wrapped_keys must exactly match current group member set",
		})
		return
	}

	// Step 10: DB update with rewrapped keys. The group DM edit produces
	// a fresh K_msg (Decision log Q11) so wrapped_keys changes and must
	// be persisted alongside the payload.
	editedAt := time.Now().Unix()
	wrappedKeysJSON := store.EncodeWrappedKeys(msg.WrappedKeys)
	if err := s.store.UpdateGroupMessageEditedWithKeys(msg.Group, msg.ID, msg.Payload, msg.Signature, wrappedKeysJSON, editedAt); err != nil {
		if err == sql.ErrNoRows {
			s.sendUnknownGroup(c)
			return
		}
		s.logger.Error("edit_group: update failed", "group", msg.Group, "id", msg.ID, "error", err)
		return
	}

	// Step 11: broadcast.
	s.broadcastToGroup(msg.Group, protocol.GroupEdited{
		Type:        "group_edited",
		ID:          msg.ID,
		From:        c.UserID,
		Group:       msg.Group,
		TS:          row.TS,
		WrappedKeys: msg.WrappedKeys,
		Payload:     msg.Payload,
		FileIDs:     row.FileIDs,
		Signature:   msg.Signature,
		EditedAt:    editedAt,
	})
	s.logger.Info("group message edited", "group", msg.Group, "id", msg.ID, "user", c.UserID)
}

// handleEditDM — 1:1 DMs.
func (s *Server) handleEditDM(c *Client, raw json.RawMessage) {
	if len(raw) > maxPayloadBytes {
		c.Encoder.Encode(protocol.Error{Type: "error", Code: protocol.ErrMessageTooLarge, Message: "Message exceeds 16KB limit"})
		return
	}

	var msg protocol.EditDM
	if err := json.Unmarshal(raw, &msg); err != nil {
		c.Encoder.Encode(protocol.Error{Type: "error", Code: "invalid_message", Message: "malformed edit_dm"})
		return
	}

	if s.store == nil {
		return
	}

	// Step 1: caller is a party to the DM. Byte-identical privacy
	// response on unknown-or-non-member, matching handleSendDM's pattern.
	dm, err := s.store.GetDirectMessage(msg.DM)
	if err != nil || dm == nil || (dm.UserA != c.UserID && dm.UserB != c.UserID) {
		s.sendUnknownDM(c)
		return
	}

	// Extra gate: if the caller's per-user left_at ratchet is set, their
	// view of the DM is frozen at that cutoff — they cannot mutate a row
	// that is past their cutoff. Return byte-identical "unknown" so the
	// leaver's frozen view stays consistent.
	if dm.CutoffFor(c.UserID) > 0 {
		s.sendUnknownDM(c)
		return
	}

	// Step 3: rate limit.
	if !s.limiter.allowPerMinute("edit:"+c.UserID, s.cfg.Server.RateLimits.EditsPerMinute) {
		c.Encoder.Encode(protocol.Error{Type: "error", Code: protocol.ErrRateLimited, Message: "Too many edits — wait a moment"})
		return
	}

	// Step 4-6.
	row, err := s.store.GetDMMessageByID(msg.DM, msg.ID)
	if err == sql.ErrNoRows || (err == nil && row != nil && (row.Sender != c.UserID || row.Deleted)) {
		s.sendUnknownDM(c)
		return
	}
	if err != nil {
		s.logger.Error("edit_dm: fetch row failed", "dm", msg.DM, "id", msg.ID, "error", err)
		s.sendUnknownDM(c)
		return
	}

	// Step 7: most-recent check.
	mostRecentID, _, err := s.store.GetUserMostRecentMessageIDDM(msg.DM, c.UserID)
	if err != nil {
		s.logger.Error("edit_dm: most-recent lookup failed", "dm", msg.DM, "error", err)
		s.sendUnknownDM(c)
		return
	}
	if mostRecentID != msg.ID {
		c.Encoder.Encode(protocol.Error{
			Type:    "error",
			Code:    protocol.ErrEditNotMostRecent,
			Message: "You can only edit your most recent message in this DM",
			Ref:     msg.ID,
		})
		return
	}

	// Step 9: wrapped_keys must have exactly 2 entries matching the DM's
	// two parties.
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

	// Step 10.
	editedAt := time.Now().Unix()
	wrappedKeysJSON := store.EncodeWrappedKeys(msg.WrappedKeys)
	if err := s.store.UpdateDMMessageEditedWithKeys(msg.DM, msg.ID, msg.Payload, msg.Signature, wrappedKeysJSON, editedAt); err != nil {
		if err == sql.ErrNoRows {
			s.sendUnknownDM(c)
			return
		}
		s.logger.Error("edit_dm: update failed", "dm", msg.DM, "id", msg.ID, "error", err)
		return
	}

	// Step 11: broadcast to both parties' active sessions. Mirrors the
	// handleSendDM session iteration pattern — 1:1 DMs don't have a
	// generic broadcast helper.
	out := protocol.DMEdited{
		Type:        "dm_edited",
		ID:          msg.ID,
		From:        c.UserID,
		DM:          dm.ID,
		TS:          row.TS,
		WrappedKeys: msg.WrappedKeys,
		Payload:     msg.Payload,
		FileIDs:     row.FileIDs,
		Signature:   msg.Signature,
		EditedAt:    editedAt,
	}
	// Phase 17 Step 3: lock-release pattern.
	s.mu.RLock()
	var targets []*Client
	for _, client := range s.clients {
		if client.UserID == dm.UserA || client.UserID == dm.UserB {
			targets = append(targets, client)
		}
	}
	s.mu.RUnlock()
	s.fanOut("dm_edited", out, targets)
	s.logger.Info("dm message edited", "dm", dm.ID, "id", msg.ID, "user", c.UserID)
}

// Byte-identical privacy response helpers. Extracted as tiny closures
// so the edit handlers can return the exact same wire frame for every
// ambiguous failure mode (non-member, row not found, non-author,
// deleted row, row-gone-during-race). The test suite uses bytes.Equal
// on the wire output to lock this in.

func (s *Server) sendUnknownRoom(c *Client) {
	c.Encoder.Encode(protocol.Error{
		Type:    "error",
		Code:    protocol.ErrUnknownRoom,
		Message: "You are not a member of this room",
	})
}

func (s *Server) sendUnknownGroup(c *Client) {
	c.Encoder.Encode(protocol.Error{
		Type:    "error",
		Code:    protocol.ErrUnknownGroup,
		Message: "You are not a member of this group",
	})
}

func (s *Server) sendUnknownDM(c *Client) {
	c.Encoder.Encode(protocol.Error{
		Type:    "error",
		Code:    protocol.ErrUnknownDM,
		Message: "You are not a party to this DM",
	})
}

// wrappedKeysMatchMemberSet returns true when the keys in the wrapped
// map exactly match the given member set (no missing, no extra). Used
// by handleEditGroup to reject mid-flight membership changes, matching
// the validation handleSendGroup applies on the send path.
func wrappedKeysMatchMemberSet(wrappedKeys map[string]string, members []string) bool {
	if len(wrappedKeys) != len(members) {
		return false
	}
	for _, m := range members {
		if _, ok := wrappedKeys[m]; !ok {
			return false
		}
	}
	return true
}
