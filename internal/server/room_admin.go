package server

// Room admin helpers. Parallel to group_admin.go but for room-scoped
// admin verbs. At v1 the only such verb is room_update (the
// in-session topic update request handled in room_update.go), but
// the helper file gives a logical home for future additions (e.g.,
// an in-session room rename request) without forcing a second
// refactor.
//
// "Room admin" here means a SERVER admin (users.admin flag) acting
// on a room — rooms have no per-room admin role in this phase. The
// "room_admin_action" rate-limit bucket key prefix denotes
// "admin-class action on a room by a server admin", parallel to
// group_admin.go's "group_admin" prefix. Distinct prefix keeps
// grep + audit-log review unambiguous about which path produced a
// rate-limit signal.

import (
	"github.com/brushtailmedia/sshkey-chat/internal/counters"
	"github.com/brushtailmedia/sshkey-chat/internal/protocol"
)

// checkRoomAdminActionRateLimit enforces AdminActionsPerMinute
// per-user for room-admin verbs. Returns true if the action
// is allowed, false if rate-limited (error response already sent and
// SignalRateLimited counter incremented — caller must return
// immediately).
//
// Parallel construction to checkAdminActionRateLimit in
// group_admin.go. Differences:
//   - bucket key prefix is "room_admin_action:" (vs "group_admin:")
//   - rejectAndLog verb tag is "room_admin_action" (vs "group_admin")
//
// Same AdminActionsPerMinute config knob — there's no need for a
// separate room knob in this phase. Future room admin verbs can call
// this same helper.
//
// Ordering note: the rate limit runs BEFORE the auth check
// (IsAdmin + IsRoomMemberByID). Using a per-user bucket prevents
// room-ID rotation from bypassing this pre-auth choke point.
func (s *Server) checkRoomAdminActionRateLimit(c *Client, corrID string) bool {
	key := "room_admin_action:" + c.UserID
	if allowed, retryMs := s.limiter.allowPerMinuteWithRetry(key, s.cfg.Server.RateLimits.AdminActionsPerMinute); !allowed {
		s.rejectAndLog(c, counters.SignalRateLimited, "room_admin_action", "room admin action rate limit exceeded",
			&protocol.Error{
				Type:         "error",
				Code:         protocol.ErrRateLimited,
				Message:      "Too many admin actions — wait a moment",
				RetryAfterMs: retryMs,
				CorrID:       corrID,
			})
		return false
	}
	return true
}
