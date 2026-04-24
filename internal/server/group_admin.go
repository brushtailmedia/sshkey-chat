package server

// Phase 14: in-group admin verbs — the four new handlers that replaced the
// CLI escape hatch. All four enforce byte-identical privacy for the
// "unknown group / non-member / non-admin" triple: every one of those
// rejection responses is an ErrUnknownGroup frame with the exact same
// human message, so a probing client cannot use these verbs to enumerate
// group membership or admin status. See the privacy convention in
// groups_admin.md and the TestHandle*_PrivacyResponsesIdentical regression
// tests. Distinct errors (ErrUnknownUser, ErrAlreadyMember, ErrAlreadyAdmin,
// ErrForbidden) only fire AFTER the caller has proven membership AND admin
// status — at that point their admin-ness is already known to them, so
// more specific errors are safe to return.
//
// Audit contract: each handler calls RecordGroupEvent exactly ONCE, before
// broadcasting, with mutation → audit → broadcast → echo ordering. Failures
// in RecordGroupEvent are logged at error level and do not block the
// originating action (best-effort; see groups_admin.md "Audit recording
// contract"). The one recording site per event type is easy to audit via
// grep — any duplicate is a bug.
//
// Rate limit: all five admin verbs (these four plus rename_group) share the
// AdminActionsPerMinute bucket, scoped per-user-per-group so one noisy admin
// can't starve another group.

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/brushtailmedia/sshkey-chat/internal/counters"
	"github.com/brushtailmedia/sshkey-chat/internal/protocol"
)

// checkGroupAdminAuth runs the byte-identical privacy gate for every admin
// verb. Returns (ok bool). If ok is false, the error response has already
// been sent and the caller must return immediately.
//
// The gate checks:
//  1. caller is a member of the group
//  2. caller is an admin of the group
//
// Unknown group, non-member, and non-admin all collapse to the same
// ErrUnknownGroup response so a probing client cannot distinguish them.
func (s *Server) checkGroupAdminAuth(c *Client, groupID string) bool {
	if s.store == nil {
		s.respondError(c, "", protocol.ErrUnknownGroup, "You are not a member of this group", 0)
		return false
	}
	isMember, err := s.store.IsGroupMember(groupID, c.UserID)
	if err != nil || !isMember {
		s.respondError(c, "", protocol.ErrUnknownGroup, "You are not a member of this group", 0)
		return false
	}
	isAdmin, err := s.store.IsGroupAdmin(groupID, c.UserID)
	if err != nil || !isAdmin {
		s.respondError(c, "", protocol.ErrUnknownGroup, "You are not a member of this group", 0)
		return false
	}
	return true
}

// checkAdminActionRateLimit enforces AdminActionsPerMinute per-user-per-group.
// Returns true if the action is allowed, false if rate-limited (error
// response already sent). Phase 17 Step 6: populates RetryAfterMs on
// the wire response + fires SignalRateLimited. Single site covers all
// 4 admin verb callers (add/remove/promote/demote).
func (s *Server) checkAdminActionRateLimit(c *Client, groupID string) bool {
	key := "group_admin:" + c.UserID + ":" + groupID
	if allowed, retryMs := s.limiter.allowPerMinuteWithRetry(key, s.cfg.Server.RateLimits.AdminActionsPerMinute); !allowed {
		s.rejectAndLog(c, counters.SignalRateLimited, "group_admin", "admin action rate limit exceeded",
			&protocol.Error{
				Type:         "error",
				Code:         protocol.ErrRateLimited,
				Message:      "Too many admin actions — wait a moment",
				RetryAfterMs: retryMs,
			})
		return false
	}
	return true
}

// handleAddToGroup processes an admin's request to add a new member to a
// group DM. The caller must be an admin of the group. Shape:
//
//  1. Parse + rate limit
//  2. Byte-identical privacy gate (checkGroupAdminAuth)
//  3. Resolve target user; return ErrUnknownUser if not found or retired
//     (the caller has already proven admin status, so distinct errors are
//     safe to return past this point)
//  4. Check if target is already a member; return ErrAlreadyMember if so
//  5. Call AddGroupMember(groupID, targetUserID, false) — new members are
//     always non-admin; promote afterwards via handlePromoteGroupAdmin
//  6. RecordGroupEvent("join", target, by=caller)
//  7. Broadcast group_event{join, user: target, by: caller} to all current
//     members (including the newly added target)
//  8. Send group_added_to direct notification to target's connected sessions
//     so they insert the group into local state without waiting for
//     reconnect catchup
//  9. Echo add_group_result to caller
func (s *Server) handleAddToGroup(c *Client, raw json.RawMessage) {
	var msg protocol.AddToGroup
	if err := json.Unmarshal(raw, &msg); err != nil {
		s.rejectAndLog(c, counters.SignalMalformedFrame, "add_to_group", "malformed add_to_group frame",
			&protocol.Error{Type: "error", Code: "invalid_message", Message: "malformed add_to_group"})
		return
	}

	if !s.checkAdminActionRateLimit(c, msg.Group) {
		return
	}
	if !s.checkGroupAdminAuth(c, msg.Group) {
		return
	}

	// Caller is authorized — resolve target.
	target := s.store.GetUserByID(msg.User)
	if target == nil {
		s.respondError(c, "", protocol.ErrUnknownUser, "No such user", 0)
		return
	}
	if s.store.IsUserRetired(msg.User) {
		s.respondError(c, "", protocol.ErrUnknownUser, "No such user", 0)
		return
	}

	// Already a member?
	alreadyMember, _ := s.store.IsGroupMember(msg.Group, msg.User)
	if alreadyMember {
		s.respondError(c, "", protocol.ErrAlreadyMember, "User is already a member of this group", 0)
		return
	}

	// Phase 17 Step 4d: enforce the group member cap on this path too.
	// Pre-17 handleCreateGroup checked a hardcoded 150 but handleAddToGroup
	// had no cap check — an admin could grow a group past the limit via
	// repeated add_to_group, producing a group whose sends then fail the
	// wrapped_keys envelope cap on every message. Same config value, same
	// error shape (`too_many_members`) as handleCreateGroup for caller
	// consistency.
	currentMembers, err := s.store.GetGroupMembers(msg.Group)
	if err != nil {
		s.logger.Error("failed to load group members for cap check",
			"group", msg.Group, "error", err)
		s.respondError(c, "", protocol.CodeInternal, "failed to add member", 0)
		return
	}
	s.cfg.RLock()
	maxMembers := s.cfg.Server.Groups.MaxMembers
	s.cfg.RUnlock()
	if maxMembers <= 0 {
		maxMembers = 150 // defensive fallback if config load elided the section
	}
	if len(currentMembers) >= maxMembers {
		s.respondError(c, "", "too_many_members",
			fmt.Sprintf("Group DMs are limited to %d members. Use a room for larger groups.", maxMembers), 0)
		return
	}

	// Mutation.
	if err := s.store.AddGroupMember(msg.Group, msg.User, false); err != nil {
		s.logger.Error("failed to add group member",
			"group", msg.Group, "user", msg.User, "by", c.UserID, "error", err)
		s.respondError(c, "", protocol.CodeInternal, "failed to add member", 0)
		return
	}

	// Phase 20: clear any prior leave-history rows for this (user, group).
	// Rejoining is the affirmative undo of a prior leave; stale rows would
	// re-surface in the target's next left_groups catchup otherwise. The
	// catchup-query filter against group_members is defensive against
	// cleanup failures.
	if err := s.store.DeleteUserLeftGroupRows(msg.User, msg.Group); err != nil {
		s.logger.Error("failed to clear prior leave history on re-add",
			"user", msg.User, "group", msg.Group, "error", err)
	}

	// Audit (best-effort).
	if err := s.store.RecordGroupEvent(
		msg.Group, "join", msg.User, c.UserID, "", "", msg.Quiet, time.Now().Unix(),
	); err != nil {
		s.logger.Error("failed to record group event",
			"group", msg.Group, "event", "join", "user", msg.User, "error", err)
	}

	// Broadcast to all current members (includes the new one).
	s.broadcastToGroup(msg.Group, protocol.GroupEvent{
		Type:  "group_event",
		Group: msg.Group,
		Event: "join",
		User:  msg.User,
		By:    c.UserID,
		Quiet: msg.Quiet,
	})

	// Direct notification to target's sessions so they insert the group
	// into local state without waiting for a reconnect catchup. Carries
	// the current member + admin lists so the local insert is fully
	// populated.
	members, _ := s.store.GetGroupMembers(msg.Group)
	admins, _ := s.store.GetGroupAdminIDs(msg.Group)
	var groupName string
	if groups, err := s.store.GetUserGroups(c.UserID); err == nil {
		for _, g := range groups {
			if g.ID == msg.Group {
				groupName = g.Name
				break
			}
		}
	}
	addedTo := protocol.GroupAddedTo{
		Type:    "group_added_to",
		Group:   msg.Group,
		Name:    groupName,
		Members: members,
		Admins:  admins,
		AddedBy: c.UserID,
	}
	// Phase 17 Step 3: lock-release pattern.
	s.mu.RLock()
	var targets []*Client
	for _, client := range s.clients {
		if client.UserID == msg.User {
			targets = append(targets, client)
		}
	}
	s.mu.RUnlock()
	s.fanOut("group_added_to", addedTo, targets)

	// Echo to caller.
	c.Encoder.Encode(protocol.AddGroupResult{
		Type:  "add_group_result",
		Group: msg.Group,
		User:  msg.User,
	})

	s.logger.Info("group add",
		"group", msg.Group, "user", msg.User, "by", c.UserID)
}

// handleRemoveFromGroup processes an admin's request to remove a member
// from a group DM. Shape:
//
//  1. Parse + rate limit
//  2. Byte-identical privacy gate
//  3. Verify target is a member (ErrUnknownGroup on no — matches the
//     byte-identical convention; non-members of an admin-validated group
//     surface as "unknown group" to preserve membership privacy)
//  4. Self-kick shortcut: if target == caller, route to handleLeaveGroup
//     flow (avoids "alice removed alice" audit entries and keeps semantics
//     consistent with /leave, including the last-admin gate)
//  5. Last-admin check: if target is an admin AND they're the only admin,
//     reject with ErrForbidden — the caller must promote a successor first
//  6. Call performGroupLeave(groupID, target, "removed", callerUserID) —
//     this runs the mutation + RecordGroupEvent + broadcast + echo path
//     for the target's sessions. The "removed" reason with non-empty by
//     tells the client to render "You were removed from the group by
//     alice" instead of the generic self-leave message.
//  7. Echo remove_group_result to caller
func (s *Server) handleRemoveFromGroup(c *Client, raw json.RawMessage) {
	var msg protocol.RemoveFromGroup
	if err := json.Unmarshal(raw, &msg); err != nil {
		s.rejectAndLog(c, counters.SignalMalformedFrame, "remove_from_group", "malformed remove_from_group frame",
			&protocol.Error{Type: "error", Code: "invalid_message", Message: "malformed remove_from_group"})
		return
	}

	if !s.checkAdminActionRateLimit(c, msg.Group) {
		return
	}
	if !s.checkGroupAdminAuth(c, msg.Group) {
		return
	}

	// Verify target is a member. Privacy: for admin-authenticated callers,
	// a non-member target collapses to the same ErrUnknownGroup frame.
	isMember, _ := s.store.IsGroupMember(msg.Group, msg.User)
	if !isMember {
		s.respondError(c, "", protocol.ErrUnknownGroup, "You are not a member of this group", 0)
		return
	}

	// Self-kick shortcut: route to self-leave path. This keeps the audit
	// trail clean ("alice left" instead of "alice removed alice") and
	// applies the last-admin gate from handleLeaveGroup.
	if msg.User == c.UserID {
		// Re-encode the leave request shape and dispatch. We could call
		// handleLeaveGroup directly but going through the JSON path keeps
		// one code path authoritative for self-leave.
		leaveRaw, _ := json.Marshal(protocol.LeaveGroup{Type: "leave_group", Group: msg.Group})
		s.handleLeaveGroup(c, leaveRaw)
		return
	}

	// Last-admin check: if target is an admin and removing them would leave
	// the group with zero admins, reject. Requires a successor promotion
	// first.
	if isAdmin, _ := s.store.IsGroupAdmin(msg.Group, msg.User); isAdmin {
		if count, _ := s.store.CountGroupAdmins(msg.Group); count == 1 {
			s.respondError(c, "", protocol.ErrForbidden, "Cannot remove last admin — promote another member first", 0)
			return
		}
	}

	// Route through the shared leave helper — it handles mutation, audit,
	// last-member cleanup, broadcast, and target echo.
	s.performGroupLeave(msg.Group, msg.User, "removed", c.UserID, c.UserID)

	// Echo result to the calling admin (the target's own sessions get the
	// group_left echo from inside performGroupLeave).
	c.Encoder.Encode(protocol.RemoveGroupResult{
		Type:  "remove_group_result",
		Group: msg.Group,
		User:  msg.User,
	})

	s.logger.Info("group remove",
		"group", msg.Group, "user", msg.User, "by", c.UserID)
}

// handlePromoteGroupAdmin promotes a member to admin. Unilateral — any
// admin can promote any non-admin member. Shape:
//
//  1. Parse + rate limit
//  2. Byte-identical privacy gate
//  3. Verify target is a member (ErrUnknownGroup if not — privacy)
//  4. Check if target is already an admin; return ErrAlreadyAdmin if so
//  5. SetGroupMemberAdmin(groupID, target, true)
//  6. RecordGroupEvent("promote", target, by=caller)
//  7. Broadcast group_event{promote, user, by} to all current members
//  8. Echo promote_admin_result to caller
func (s *Server) handlePromoteGroupAdmin(c *Client, raw json.RawMessage) {
	var msg protocol.PromoteGroupAdmin
	if err := json.Unmarshal(raw, &msg); err != nil {
		s.rejectAndLog(c, counters.SignalMalformedFrame, "promote_group_admin", "malformed promote_group_admin frame",
			&protocol.Error{Type: "error", Code: "invalid_message", Message: "malformed promote_group_admin"})
		return
	}

	if !s.checkAdminActionRateLimit(c, msg.Group) {
		return
	}
	if !s.checkGroupAdminAuth(c, msg.Group) {
		return
	}

	isMember, _ := s.store.IsGroupMember(msg.Group, msg.User)
	if !isMember {
		s.respondError(c, "", protocol.ErrUnknownGroup, "You are not a member of this group", 0)
		return
	}

	if isAdmin, _ := s.store.IsGroupAdmin(msg.Group, msg.User); isAdmin {
		s.respondError(c, "", protocol.ErrAlreadyAdmin, "User is already an admin of this group", 0)
		return
	}

	if err := s.store.SetGroupMemberAdmin(msg.Group, msg.User, true); err != nil {
		s.logger.Error("failed to promote group member",
			"group", msg.Group, "user", msg.User, "by", c.UserID, "error", err)
		s.respondError(c, "", protocol.CodeInternal, "failed to promote member", 0)
		return
	}

	if err := s.store.RecordGroupEvent(
		msg.Group, "promote", msg.User, c.UserID, "", "", msg.Quiet, time.Now().Unix(),
	); err != nil {
		s.logger.Error("failed to record group event",
			"group", msg.Group, "event", "promote", "user", msg.User, "error", err)
	}

	s.broadcastToGroup(msg.Group, protocol.GroupEvent{
		Type:  "group_event",
		Group: msg.Group,
		Event: "promote",
		User:  msg.User,
		By:    c.UserID,
		Quiet: msg.Quiet,
	})

	c.Encoder.Encode(protocol.PromoteAdminResult{
		Type:  "promote_admin_result",
		Group: msg.Group,
		User:  msg.User,
	})

	s.logger.Info("group promote",
		"group", msg.Group, "user", msg.User, "by", c.UserID)
}

// handleDemoteGroupAdmin demotes an admin back to regular member. May be
// self-demote. Shape:
//
//  1. Parse + rate limit
//  2. Byte-identical privacy gate
//  3. Verify target is a member AND currently an admin (ErrUnknownGroup
//     on either failure — privacy, even though "not an admin" is
//     technically a distinct state, the byte-identical convention means
//     all three rejection shapes collapse to the same frame)
//  4. Last-admin check: if this demotion would leave zero admins, reject
//     with ErrForbidden. Covers both same-target and self-demote.
//  5. SetGroupMemberAdmin(groupID, target, false)
//  6. RecordGroupEvent("demote", target, by=caller)
//  7. Broadcast group_event{demote, user, by} to all current members
//  8. Echo demote_admin_result to caller
func (s *Server) handleDemoteGroupAdmin(c *Client, raw json.RawMessage) {
	var msg protocol.DemoteGroupAdmin
	if err := json.Unmarshal(raw, &msg); err != nil {
		s.rejectAndLog(c, counters.SignalMalformedFrame, "demote_group_admin", "malformed demote_group_admin frame",
			&protocol.Error{Type: "error", Code: "invalid_message", Message: "malformed demote_group_admin"})
		return
	}

	if !s.checkAdminActionRateLimit(c, msg.Group) {
		return
	}
	if !s.checkGroupAdminAuth(c, msg.Group) {
		return
	}

	isMember, _ := s.store.IsGroupMember(msg.Group, msg.User)
	if !isMember {
		s.respondError(c, "", protocol.ErrUnknownGroup, "You are not a member of this group", 0)
		return
	}
	isAdmin, _ := s.store.IsGroupAdmin(msg.Group, msg.User)
	if !isAdmin {
		// Byte-identical privacy: non-admin target response matches
		// unknown-group / non-member frames.
		s.respondError(c, "", protocol.ErrUnknownGroup, "You are not a member of this group", 0)
		return
	}

	// Last-admin check.
	if count, _ := s.store.CountGroupAdmins(msg.Group); count <= 1 {
		s.respondError(c, "", protocol.ErrForbidden, "Cannot demote last admin", 0)
		return
	}

	if err := s.store.SetGroupMemberAdmin(msg.Group, msg.User, false); err != nil {
		s.logger.Error("failed to demote group member",
			"group", msg.Group, "user", msg.User, "by", c.UserID, "error", err)
		s.respondError(c, "", protocol.CodeInternal, "failed to demote member", 0)
		return
	}

	if err := s.store.RecordGroupEvent(
		msg.Group, "demote", msg.User, c.UserID, "", "", msg.Quiet, time.Now().Unix(),
	); err != nil {
		s.logger.Error("failed to record group event",
			"group", msg.Group, "event", "demote", "user", msg.User, "error", err)
	}

	s.broadcastToGroup(msg.Group, protocol.GroupEvent{
		Type:  "group_event",
		Group: msg.Group,
		Event: "demote",
		User:  msg.User,
		By:    c.UserID,
		Quiet: msg.Quiet,
	})

	c.Encoder.Encode(protocol.DemoteAdminResult{
		Type:  "demote_admin_result",
		Group: msg.Group,
		User:  msg.User,
	})

	s.logger.Info("group demote",
		"group", msg.Group, "user", msg.User, "by", c.UserID)
}
