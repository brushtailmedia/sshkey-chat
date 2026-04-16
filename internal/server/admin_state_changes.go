package server

// Phase 16 Gap 1 — runAdminStateChangeProcessor and
// processPendingAdminStateChanges. Shared processor for promote,
// demote, and rename-user — all three CLI verbs flip a column on a
// single users.db row and need to broadcast a fresh profile event
// to connected clients so their in-memory profile cache picks up
// the change.
//
// Why one processor for three actions:
//   - All three actions produce identical wire output: a fresh
//     protocol.Profile broadcast for the affected user
//   - The action enum is only used for the audit log entry — the
//     broadcast payload is uniformly built from the post-change
//     user row by re-reading users.db
//   - Three near-duplicate processors would be code bloat with no
//     architectural benefit
//
// Critical for the support story: users find admins via the admin
// badge in the members list, and that badge needs to propagate live
// so newly-promoted admins appear immediately rather than on next
// reconnect. Same reasoning applies to rename-user (moderation tool
// where the operator wants the new name to take effect right now).

import (
	"database/sql"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/brushtailmedia/sshkey-chat/internal/protocol"
	"github.com/brushtailmedia/sshkey-chat/internal/store"
)

// adminStateChangePollInterval is how often the admin state change
// processor checks the pending_admin_state_changes queue. Five
// seconds matches the other Phase 16 Gap 1 processors.
const adminStateChangePollInterval = 5 * time.Second

// runAdminStateChangeProcessor is the polling loop that bridges the
// CLI's pending_admin_state_changes queue with the running server's
// broadcast surface. Started by Server.Run alongside the other
// Phase 16 Gap 1 processors.
func (s *Server) runAdminStateChangeProcessor() {
	ticker := time.NewTicker(adminStateChangePollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-s.adminStateChangeStop:
			return
		case <-ticker.C:
			s.processPendingAdminStateChanges()
		}
	}
}

// processPendingAdminStateChanges consumes the queue and broadcasts
// a fresh protocol.Profile event for each row. Each call:
//   - Atomically reads + deletes the queue rows
//   - For each row, re-reads the user from users.db (so the
//     broadcast carries the current state, not whatever was
//     captured at enqueue time)
//   - Writes an audit log entry with the action-specific verb
//     (promote / demote / rename-user)
//   - Builds a fresh protocol.Profile and broadcasts to all
//     connected clients (wide broadcast matching the user_retired
//     pattern; clients that don't know the user just cache the
//     profile harmlessly)
//
// Errors are logged but don't stop processing — one bad row
// shouldn't poison the whole batch.
func (s *Server) processPendingAdminStateChanges() {
	if s.store == nil {
		return
	}

	pending, err := s.store.ConsumePendingAdminStateChanges()
	if err != nil {
		s.logger.Error("failed to consume admin state change queue", "error", err)
		return
	}
	if len(pending) == 0 {
		return
	}

	for _, p := range pending {
		s.logger.Info("processing admin state change",
			"user", p.UserID,
			"action", string(p.Action),
			"changed_by", p.ChangedBy,
			"queued_at", p.QueuedAt,
		)

		// Re-fetch the user row to capture the post-change state.
		// The CLI side already mutated users.db before enqueueing,
		// so this read returns the current values.
		user := s.store.GetUserByID(p.UserID)
		if user == nil {
			s.logger.Warn("queued admin state change references missing user",
				"user", p.UserID, "action", string(p.Action))
			continue
		}

		// Audit credit. The action-to-verb mapping is intentional
		// — the audit log uses the public CLI verb names so
		// operators reading the log see what they actually typed.
		var auditAction string
		switch p.Action {
		case store.AdminStateChangePromote:
			auditAction = "promote"
		case store.AdminStateChangeDemote:
			auditAction = "demote"
		case store.AdminStateChangeRename:
			auditAction = "rename-user"
		default:
			s.logger.Warn("unknown admin state change action",
				"action", string(p.Action))
			continue
		}
		if s.audit != nil {
			s.audit.Log(p.ChangedBy, auditAction,
				"user="+p.UserID+" display_name="+user.DisplayName)
		}

		// Build and broadcast the fresh profile.
		s.broadcastUserProfile(user)
	}
}

// broadcastUserProfile constructs a protocol.Profile for the given
// user (matching the shape sendProfiles produces during connect)
// and broadcasts it to every connected client. The client's
// existing handleInternal "profile" case will upsert into its
// in-memory profile cache, refreshing display name, admin status,
// and retired state in one step.
//
// We broadcast widely (every connected client) rather than
// computing a per-client visibility set because:
//   - Profile updates are rare (admin state changes, rename moderation)
//   - Clients that don't know the user just cache the profile and
//     it's harmless
//   - Computing visibility per broadcast would require walking
//     room_members + group_members + direct_messages for every
//     connected client — significant cost for marginal privacy
//     benefit
//   - Matches the existing user_retired wide-broadcast pattern
func (s *Server) broadcastUserProfile(user *store.UserRecord) {
	if user == nil || s.store == nil {
		return
	}

	parsed, _, _, _, err := ssh.ParseAuthorizedKey([]byte(user.Key))
	if err != nil {
		s.logger.Warn("failed to parse user key for profile broadcast",
			"user", user.ID, "error", err)
		return
	}

	// Merge stored profile data (avatar, display_name overrides
	// from set_profile) with users.db defaults — same logic as
	// sendProfiles in session.go. The CLI rename-user updates
	// users.display_name, but a previous /settings call may have
	// also written to the profiles table; we honor the profiles
	// override for parity with sendProfiles.
	displayName := user.DisplayName
	avatarID := ""
	var dbDisplayName, dbAvatarID sql.NullString
	s.store.DataDB().QueryRow(
		`SELECT display_name, avatar_id FROM profiles WHERE user = ?`,
		user.ID).Scan(&dbDisplayName, &dbAvatarID)
	if dbDisplayName.Valid && dbDisplayName.String != "" {
		displayName = dbDisplayName.String
	}
	if dbAvatarID.Valid {
		avatarID = dbAvatarID.String
	}

	event := protocol.Profile{
		Type:           "profile",
		User:           user.ID,
		DisplayName:    displayName,
		AvatarID:       avatarID,
		PubKey:         user.Key,
		KeyFingerprint: ssh.FingerprintSHA256(parsed),
		Admin:          s.store.IsAdmin(user.ID),
		Retired:        user.Retired,
		RetiredAt:      user.RetiredAt,
	}

	s.mu.RLock()
	for _, client := range s.clients {
		client.Encoder.Encode(event)
	}
	s.mu.RUnlock()
}
