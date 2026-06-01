package server

import (
	"database/sql"
	"time"

	"github.com/brushtailmedia/sshkey-chat/internal/actionauth"
	"github.com/brushtailmedia/sshkey-chat/internal/counters"
	"github.com/brushtailmedia/sshkey-chat/internal/protocol"
)

// exactlyOneContext validates that exactly one of room/group/dm is set and
// returns its (kind, contextID). ok=false if zero or more than one is set. The
// shared validate-and-derive used by the F6 signed-action router.
func exactlyOneContext(room, group, dm string) (kind, contextID string, ok bool) {
	n := 0
	if room != "" {
		n++
		kind, contextID = "room", room
	}
	if group != "" {
		n++
		kind, contextID = "group", group
	}
	if dm != "" {
		n++
		kind, contextID = "dm", dm
	}
	return kind, contextID, n == 1
}

// verifyDeleteSignature verifies the client's delete signature against the
// session user's stored public key — a DATA-INTEGRITY gate (so the server never
// blanks content on a cryptographically-invalid request), NOT the security
// boundary (the SSH session is already authenticated; clients re-verify on
// receipt). Returns false on an unresolvable/unparseable key or a bad signature.
func (s *Server) verifyDeleteSignature(userID, kind, contextID, msgID string, sig []byte) bool {
	user := s.store.GetUserByID(userID)
	if user == nil {
		return false
	}
	pub, err := actionauth.ParseSSHEd25519PubKey(user.Key)
	if err != nil {
		return false
	}
	return actionauth.VerifyDelete(pub, kind, contextID, msgID, sig)
}

// rejectDeleteBadSig rejects a delete whose signature failed verification. It
// runs only after the privacy/authz gates have passed (the caller is proven a
// member and the message's author or a room admin), so naming the failure
// leaks no context/row existence; a conformant client never triggers it.
func (s *Server) rejectDeleteBadSig(c *Client, corrID string) {
	s.rejectAndLog(c, counters.SignalMalformedFrame, "delete", "delete signature verification failed",
		&protocol.Error{Type: "error", Code: "invalid_message", Message: "delete signature verification failed", CorrID: corrID})
}

// handleDeleteRoomMessage soft-deletes a room message after proving membership,
// authorization (own message OR room admin), and the request signature. Mirrors
// handleEdit's privacy collapse: non-member / not-found / already-deleted / lost
// race all return the room's unknown response, never revealing existence.
func (s *Server) handleDeleteRoomMessage(c *Client, msg protocol.Delete, roomID string, sig []byte, isAdmin bool) {
	if !s.store.IsRoomMemberByID(roomID, c.UserID) {
		s.respondError(c, msg.CorrID, protocol.ErrUnknownRoom, "You are not a member of this room", 0)
		return
	}
	if s.store.IsRoomRetired(roomID) {
		s.respondError(c, msg.CorrID, protocol.ErrRoomRetired, "This room has been archived and is read-only", 0)
		return
	}
	row, err := s.store.GetRoomMessageByID(roomID, msg.ID)
	if err == sql.ErrNoRows || (err == nil && (row == nil || row.Deleted)) {
		s.respondError(c, msg.CorrID, protocol.ErrUnknownRoom, "You are not a member of this room", 0)
		return
	}
	if err != nil {
		s.logger.Error("delete: room row fetch failed", "room", roomID, "id", msg.ID, "error", err)
		s.respondError(c, msg.CorrID, protocol.ErrUnknownRoom, "You are not a member of this room", 0)
		return
	}
	// Authz: own message OR room admin (room is the only admin-override context).
	if row.Sender != c.UserID && !isAdmin {
		s.respondError(c, msg.CorrID, protocol.ErrUnknownRoom, "You are not a member of this room", 0)
		return
	}
	targetSender := row.Sender

	// Data-integrity gate — verified after the privacy/authz gates so an invalid
	// signature can never probe context/message existence.
	if !s.verifyDeleteSignature(c.UserID, "room", roomID, msg.ID, sig) {
		s.rejectDeleteBadSig(c, msg.CorrID)
		return
	}

	deletedResult, err := s.store.DeleteRoomMessageWithResult(roomID, msg.ID, c.UserID, msg.Signature)
	if err == sql.ErrNoRows { // lost a concurrent-delete race
		s.respondError(c, msg.CorrID, protocol.ErrUnknownRoom, "You are not a member of this room", 0)
		return
	}
	if err != nil {
		s.logger.Error("delete failed", "room", roomID, "id", msg.ID, "error", err)
		return
	}
	s.cleanupFiles(deletedResult.FileIDs)

	// Best-effort audit of a room-admin delete of ANOTHER user's message.
	if isAdmin && targetSender != c.UserID && s.audit != nil {
		s.audit.Log(c.UserID, "room-admin-delete",
			"target="+targetSender+" room="+roomID+" id="+msg.ID+" corr="+msg.CorrID)
	}

	s.broadcastToRoom(roomID, protocol.Deleted{
		Type:        "deleted",
		ID:          msg.ID,
		ServerOrder: deletedResult.ServerOrder,
		DeletedBy:   c.UserID,
		TS:          time.Now().Unix(),
		Room:        roomID,
		Signature:   msg.Signature, // F6: relay for client verify-or-drop
		CorrID:      msg.CorrID,    // Phase 17c
	})
}

// handleDeleteGroupMessage soft-deletes a group-DM message. Group DMs are
// own-message-only (no admin override).
func (s *Server) handleDeleteGroupMessage(c *Client, msg protocol.Delete, groupID string, sig []byte) {
	isMember, err := s.store.IsGroupMember(groupID, c.UserID)
	if err != nil || !isMember {
		s.respondError(c, msg.CorrID, protocol.ErrUnknownGroup, "You are not a member of this group", 0)
		return
	}
	row, err := s.store.GetGroupMessageByID(groupID, msg.ID)
	if err == sql.ErrNoRows || (err == nil && (row == nil || row.Deleted)) {
		s.respondError(c, msg.CorrID, protocol.ErrUnknownGroup, "You are not a member of this group", 0)
		return
	}
	if err != nil {
		s.logger.Error("delete: group row fetch failed", "group", groupID, "id", msg.ID, "error", err)
		s.respondError(c, msg.CorrID, protocol.ErrUnknownGroup, "You are not a member of this group", 0)
		return
	}
	if row.Sender != c.UserID {
		s.respondError(c, msg.CorrID, protocol.ErrUnknownGroup, "You are not a member of this group", 0)
		return
	}
	if !s.verifyDeleteSignature(c.UserID, "group", groupID, msg.ID, sig) {
		s.rejectDeleteBadSig(c, msg.CorrID)
		return
	}
	deletedResult, err := s.store.DeleteGroupMessageWithResult(groupID, msg.ID, c.UserID, msg.Signature)
	if err == sql.ErrNoRows {
		s.respondError(c, msg.CorrID, protocol.ErrUnknownGroup, "You are not a member of this group", 0)
		return
	}
	if err != nil {
		s.logger.Error("delete failed", "group", groupID, "id", msg.ID, "error", err)
		return
	}
	s.cleanupFiles(deletedResult.FileIDs)

	s.broadcastToGroup(groupID, protocol.Deleted{
		Type:        "deleted",
		ID:          msg.ID,
		ServerOrder: deletedResult.ServerOrder,
		DeletedBy:   c.UserID,
		TS:          time.Now().Unix(),
		Group:       groupID,
		Signature:   msg.Signature, // F6
		CorrID:      msg.CorrID,    // Phase 17c
	})
}

// handleDeleteDMMessage soft-deletes a 1:1 DM message. DMs are own-message-only
// (no admin override, and — matching prior delete behavior — no cutoff gate;
// F6 does not redesign DM leave/delete semantics).
func (s *Server) handleDeleteDMMessage(c *Client, msg protocol.Delete, dmID string, sig []byte) {
	dm, err := s.store.GetDirectMessage(dmID)
	if err != nil || dm == nil || (dm.UserA != c.UserID && dm.UserB != c.UserID) {
		s.respondError(c, msg.CorrID, protocol.ErrUnknownDM, "You are not a party to this DM", 0)
		return
	}
	row, err := s.store.GetDMMessageByID(dmID, msg.ID)
	if err == sql.ErrNoRows || (err == nil && (row == nil || row.Deleted)) {
		s.respondError(c, msg.CorrID, protocol.ErrUnknownDM, "You are not a party to this DM", 0)
		return
	}
	if err != nil {
		s.logger.Error("delete: dm row fetch failed", "dm", dmID, "id", msg.ID, "error", err)
		s.respondError(c, msg.CorrID, protocol.ErrUnknownDM, "You are not a party to this DM", 0)
		return
	}
	if row.Sender != c.UserID {
		s.respondError(c, msg.CorrID, protocol.ErrUnknownDM, "You are not a party to this DM", 0)
		return
	}
	if !s.verifyDeleteSignature(c.UserID, "dm", dmID, msg.ID, sig) {
		s.rejectDeleteBadSig(c, msg.CorrID)
		return
	}
	deletedResult, err := s.store.DeleteDMMessageWithResult(dmID, msg.ID, c.UserID, msg.Signature)
	if err == sql.ErrNoRows {
		s.respondError(c, msg.CorrID, protocol.ErrUnknownDM, "You are not a party to this DM", 0)
		return
	}
	if err != nil {
		s.logger.Error("delete failed", "dm", dmID, "id", msg.ID, "error", err)
		return
	}
	s.cleanupFiles(deletedResult.FileIDs)

	deleted := protocol.Deleted{
		Type:        "deleted",
		ID:          msg.ID,
		ServerOrder: deletedResult.ServerOrder,
		DeletedBy:   c.UserID,
		TS:          time.Now().Unix(),
		DM:          dmID,
		Signature:   msg.Signature, // F6
		CorrID:      msg.CorrID,    // Phase 17c
	}
	s.mu.RLock()
	var targets []*Client
	for _, client := range s.clients {
		if client.UserID == dm.UserA || client.UserID == dm.UserB {
			targets = append(targets, client)
		}
	}
	s.mu.RUnlock()
	s.fanOut("deleted", deleted, targets)
}
