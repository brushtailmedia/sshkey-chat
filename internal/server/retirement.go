package server

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/brushtailmedia/sshkey-chat/internal/protocol"
)

// handleRetirement processes the downstream effects of a user being retired.
// The caller must have already marked the user as retired in users.db — this
// function does not touch the retired flag itself.
//
// It fires room_event leaves for every room the user was in, iterates the
// user's group DMs performing last-admin succession + per-group leave via
// performGroupLeave, sets per-user DM cutoffs, clears the retiring user's
// deleted_groups records, broadcasts user_retired to all connected clients,
// terminates any active sessions for the retiring user, and audits the
// event.
//
// Note: 1:1 DMs are NOT handled by performGroupLeave — they have their own
// per-user history cutoff model with separate SetDMLeftAt logic below.
//
// Called from:
//   - retireUser (server-side retirement via protocol or CLI)
//   - handleRetireMe (the retire_me protocol handler)
//
// oldRooms is the list of rooms the user was in immediately before retirement,
// captured by the caller (before room memberships were cleared). reason is
// recorded in the audit log; it should be one of: self_compromise | admin |
// key_lost.
func (s *Server) handleRetirement(userID string, oldRooms []string, reason string) {
	// 1+2+3. Per-room: remove from members, broadcast room_event{leave,
	// reason: "user_retired"} to remaining members, echo room_left to
	// the retiring user's still-connected sessions, mark for epoch
	// rotation. Delegated to performRoomLeave so the retirement path
	// stays in sync with the self-leave path — same broadcast shape,
	// same epoch rotation, same Reason field plumbing. The reason
	// "user_retired" lets client UIs render a different system message
	// for remaining members ("alice's account was retired" instead of
	// "alice left").
	//
	// The retiring user's sessions get terminated a few steps below
	// (step 9), so any room_left echoes from performRoomLeave will be
	// briefly delivered before the connection closes. Harmless.
	for _, roomID := range oldRooms {
		s.performRoomLeave(roomID, userID, "user_retired")
	}

	// 4. Phase 14: per-group iteration via performGroupLeave with
	// last-admin succession. Replaces the pre-Phase-14 bulk
	// RetireUserFromGroups path which had three issues: (a) it was a
	// separate code path from self-leave and admin-kick, missing the
	// new RecordGroupEvent audit + unified GroupLeft echo shape;
	// (b) when the retiring user was solo in a group, the bulk DELETE
	// never triggered DeleteGroupConversation, leaving the group row
	// and group-{id}.db file orbiting forever (orphan-on-solo bug);
	// (c) it couldn't perform last-admin succession because the
	// broadcast loop ran AFTER the membership mutation.
	//
	// New flow per group: check if retiring user is the sole admin; if
	// so, auto-promote the oldest remaining member before they leave;
	// then route through performGroupLeave(reason="retirement", by="").
	// performGroupLeave handles RemoveGroupMember, RecordGroupEvent,
	// last-member cleanup, and broadcasting to remaining members. For
	// solo-member groups it naturally triggers the cleanup cascade —
	// orphan bug fixed as a side effect.
	//
	// Reason stays "retirement" (not "user_retired") for groups — the
	// value is load-bearing across 9+ sites and the Conventions section
	// in groups_admin.md is authoritative. The By field is empty
	// because retirement is unilateral, not kicking-admin-initiated.
	//
	// While the loop runs, the retiring user's sessions are still open
	// (termination is step 9 below), so each performGroupLeave call
	// delivers a GroupLeft echo to those sessions before close. This
	// is harmless and matches how performRoomLeave already behaves on
	// the rooms side for the same reason.
	groupCount := 0
	if s.store != nil {
		groups, err := s.store.GetUserGroups(userID)
		if err != nil {
			s.logger.Error("failed to list groups for retirement",
				"user", userID, "error", err)
		} else {
			groupCount = len(groups)
			for _, g := range groups {
				// Last-admin succession: if retiring user is the sole
				// admin, auto-promote the oldest remaining member before
				// leaving. If no other members exist, skip the promote
				// entirely — the performGroupLeave call below will run
				// the last-member cleanup cascade.
				if isAdmin, _ := s.store.IsGroupAdmin(g.ID, userID); isAdmin {
					if count, _ := s.store.CountGroupAdmins(g.ID); count == 1 {
						successor, _ := s.store.GetOldestGroupMember(g.ID, userID)
						if successor != "" {
							if err := s.store.SetGroupMemberAdmin(g.ID, successor, true); err == nil {
								s.broadcastToGroup(g.ID, protocol.GroupEvent{
									Type:   "group_event",
									Group:  g.ID,
									Event:  "promote",
									User:   successor,
									Reason: "retirement_succession",
								})
								// Audit the succession promote. The
								// subsequent performGroupLeave call
								// records its own "leave" event — two
								// distinct event types, two recording
								// sites, no duplication.
								if err := s.store.RecordGroupEvent(
									g.ID, "promote", successor, "", "retirement_succession", "", false, time.Now().Unix(),
								); err != nil {
									s.logger.Error("failed to record retirement-succession promote event",
										"group", g.ID, "successor", successor, "error", err)
								}
								s.logger.Info("retirement-succession promote",
									"group", g.ID, "successor", successor, "retiring_user", userID)
							} else {
								s.logger.Error("failed to auto-promote successor",
									"group", g.ID, "successor", successor, "error", err)
							}
						}
					}
				}
				s.performGroupLeave(g.ID, userID, "retirement", "")
			}
		}
	}

	// 5. Set per-user cutoff on all 1:1 DMs (silent leave — no broadcast).
	// The cutoff means the retired user (who can no longer connect) won't
	// see any messages sent after this timestamp. The other party's row is
	// unchanged — they still see the DM in their sidebar, can read history,
	// but sends are blocked by the retired-recipient check in handleSendDM.
	dmCount := 0
	if s.store != nil {
		now := time.Now().Unix()
		dms, err := s.store.GetDirectMessagesForUser(userID)
		if err != nil {
			s.logger.Error("failed to get DMs for retirement",
				"user", userID,
				"error", err,
			)
		} else {
			dmCount = len(dms)
			for _, dm := range dms {
				if err := s.store.SetDMLeftAt(dm.ID, userID, now); err != nil {
					s.logger.Error("failed to set DM cutoff on retirement",
						"user", userID,
						"dm", dm.ID,
						"error", err,
					)
				}
			}
		}
	}

	// 6. Clear this user's deleted_groups records — they're dead weight
	// once the account is retired (the user can never reconnect to
	// consume them via sync). Also opportunistically prune any other
	// users' rows that are older than the retention threshold; this is
	// the second amortization point for the deleted_groups GC, alongside
	// DeleteGroupConversation.
	if s.store != nil {
		if err := s.store.ClearGroupDeletionsForUser(userID); err != nil {
			s.logger.Error("failed to clear deleted_groups on retirement",
				"user", userID, "error", err)
		}
		if pruned, err := s.store.PruneOldGroupDeletions(365 * 24 * 60 * 60); err == nil && pruned > 0 {
			s.logger.Info("opportunistic deleted_groups prune at retirement",
				"user", userID, "pruned", pruned)
		}
	}

	// 7. Broadcast user_retired to all connected clients so their UIs update.
	// We broadcast widely rather than computing a per-client visibility set —
	// retirement is rare and clients must gracefully ignore users they don't
	// know about (forward-compat rule).
	retiredEvent := protocol.UserRetired{
		Type: "user_retired",
		User: userID,
		Ts:   time.Now().Unix(),
	}
	s.mu.RLock()
	for _, client := range s.clients {
		if client.UserID == userID {
			continue // don't send to the retiring user's own sessions
		}
		client.Encoder.Encode(retiredEvent)
	}
	s.mu.RUnlock()

	// 8. Update stored profile display_name to the suffixed version
	if s.store != nil {
		newDisplayName := s.store.GetUserDisplayName(userID)
		s.store.DataDB().Exec(
			`INSERT INTO profiles (user, display_name) VALUES (?, ?)
			 ON CONFLICT (user) DO UPDATE SET display_name = excluded.display_name`,
			userID, newDisplayName)
	}

	// 9. Terminate active sessions for the retired user
	s.mu.RLock()
	for _, client := range s.clients {
		if client.UserID == userID {
			client.Encoder.Encode(protocol.Error{
				Type:    "error",
				Code:    protocol.ErrUserRetired,
				Message: "Your account has been retired",
			})
			client.Channel.Close()
		}
	}
	s.mu.RUnlock()

	// 10. Audit log
	if s.audit != nil {
		s.audit.Log("server", "retire",
			fmt.Sprintf("user=%s reason=%s rooms=%d groups=%d dms=%d",
				userID, reason, len(oldRooms), groupCount, dmCount,
			),
		)
	}

	s.logger.Info("user retired",
		"user", userID,
		"reason", reason,
		"rooms", len(oldRooms),
		"groups", groupCount,
		"dms", dmCount,
	)
}

// findRetiredMember returns the first retired userID in members, or empty
// string if none are retired. Used by handleCreateGroup to reject group DM
// creation that would include a retired user.
//
// Group DMs have retired members removed from group_members at retirement
// time, so live group send paths don't need this check — only the create
// path does. Once 1:1 DMs land in chunk C of Phase 11 they will reuse this
// helper for the equivalent create_dm guard.
func (s *Server) findRetiredMember(members []string) string {
	for _, m := range members {
		if s.store.IsUserRetired(m) {
			return m
		}
	}
	return ""
}

// handleRetireMe processes a client's request to retire their own account.
// This is authenticated by the SSH connection — the user is holding their key.
// Retirement is monotonic: if this succeeds, the user cannot reconnect with
// the same key, and a new account must be created to regain access.
func (s *Server) handleRetireMe(c *Client, raw json.RawMessage) {
	var msg protocol.RetireMe
	if err := json.Unmarshal(raw, &msg); err != nil {
		c.Encoder.Encode(protocol.Error{
			Type:    "error",
			Code:    "invalid_message",
			Message: "malformed retire_me",
		})
		return
	}

	// Validate reason
	reason := msg.Reason
	switch reason {
	case "self_compromise", "switching_key", "other":
		// accepted
	default:
		reason = "other"
	}

	s.logger.Info("retire_me received",
		"user", c.UserID,
		"device", c.DeviceID,
		"reason", reason,
	)

	if err := s.retireUser(c.UserID, reason); err != nil {
		s.logger.Error("retire_me failed",
			"user", c.UserID,
			"error", err,
		)
		c.Encoder.Encode(protocol.Error{
			Type:    "error",
			Code:    "internal",
			Message: "retirement failed — contact an admin",
		})
		return
	}

	// Note: handleRetirement already terminated this client's session. No
	// further action needed — the connection will close.
}

// sendRetiredUsers sends the list of retired users visible to this client
// on connect. This lets fresh clients learn about retirements that happened
// while they were offline, so they can render [retired] markers correctly
// on historical messages and show [retired] sidebar markers.
//
// Visibility is computed from 1:1 DMs: retirement preserves the DM row
// (with the retired user's cutoff set), so the connecting client still
// has the retired user as a DM partner. Group memberships and room
// memberships are cleared on retirement, so they contribute no visibility
// for retired users.
func (s *Server) sendRetiredUsers(c *Client) {
	// Compute visible retired users from 1:1 DM partners
	visible := make(map[string]bool)

	if s.store != nil {
		dms, err := s.store.GetDirectMessagesForUser(c.UserID)
		if err == nil {
			for _, dm := range dms {
				other := dm.OtherUser(c.UserID)
				if other != "" && s.store.IsUserRetired(other) {
					visible[other] = true
				}
			}
		}
	}

	if len(visible) == 0 {
		return
	}

	var list []protocol.RetiredUser
	for userID := range visible {
		user := s.store.GetUserByID(userID)
		if user == nil || !user.Retired {
			continue
		}
		list = append(list, protocol.RetiredUser{
			User:      userID,
			RetiredAt: user.RetiredAt,
		})
	}

	if len(list) == 0 {
		return
	}

	c.Encoder.Encode(protocol.RetiredUsers{
		Type:  "retired_users",
		Users: list,
	})
}

// retireUser performs a self-retirement or admin-initiated retirement of a
// user. It marks the user as retired in users.db and runs handleRetirement
// to fire all downstream events.
//
// Returns an error if the user doesn't exist, is already retired, or if the
// database write fails. Callers should check the returned error; if it's
// non-nil the retirement did NOT happen and no events were fired.
//
// Valid reasons: "self_compromise", "switching_key", "admin", "key_lost".
func (s *Server) retireUser(userID, reason string) error {
	user := s.store.GetUserByID(userID)
	if user == nil {
		return fmt.Errorf("user %q does not exist", userID)
	}
	if user.Retired {
		return fmt.Errorf("user %q is already retired", userID)
	}

	// Capture rooms before retirement (needed for leave events)
	oldRooms := s.store.GetUserRoomIDs(userID)

	// Mark retired in users.db (handles display-name suffix and timestamp)
	if err := s.store.SetUserRetired(userID, reason); err != nil {
		return fmt.Errorf("retire user %q: %w", userID, err)
	}

	s.handleRetirement(userID, oldRooms, reason)
	return nil
}
