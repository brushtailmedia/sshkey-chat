package server

import (
	"time"
)

// runAdminKickProcessor is the polling loop that bridges the CLI's
// pending_admin_kicks queue with the running server's broadcast surface.
//
// Why polling instead of IPC: the CLI is a separate process that owns
// nothing but filesystem access to the server's data dir. There is no
// existing IPC mechanism between sshkey-ctl and sshkey-server. Adding
// one (unix sockets, signal-based reload, etc.) would be a meaningful
// new dependency for a single edge-case feature. A 5-second poll on a
// usually-empty table is functionally equivalent for the moderation
// use case (admin removes an abusive user from a group; kicked user
// finds out within 5 seconds via a live group_left echo) and adds
// nothing more than one goroutine + one periodic SELECT.
//
// The CLI also performs the membership mutation directly via
// RemoveGroupMember, so the kick takes effect at the data layer
// regardless of whether the server is running. This processor is
// purely about live notification delivery.
func (s *Server) runAdminKickProcessor() {
	ticker := time.NewTicker(adminKickPollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-s.adminKickStop:
			return
		case <-ticker.C:
			s.processPendingAdminKicks()
		}
	}
}

// processPendingAdminKicks consumes the pending_admin_kicks queue and
// dispatches each row through performGroupLeave. Each call:
//   - Atomically reads + deletes the queue rows (so a concurrent
//     processor invocation can't double-process)
//   - For each consumed row, calls performGroupLeave which:
//       * Removes the user from group_members (idempotent — the CLI
//         already did this)
//       * Triggers last-member cleanup if the group is now empty
//       * Broadcasts group_event{leave, reason} to remaining members
//       * Echoes group_left{reason} to all of the kicked user's
//         currently-connected sessions
//
// Errors are logged but don't stop processing — one bad row shouldn't
// poison the whole batch.
func (s *Server) processPendingAdminKicks() {
	if s.store == nil {
		return
	}

	kicks, err := s.store.ConsumePendingAdminKicks()
	if err != nil {
		s.logger.Error("failed to consume admin kick queue", "error", err)
		return
	}
	if len(kicks) == 0 {
		return
	}

	for _, k := range kicks {
		s.logger.Info("processing admin kick",
			"user", k.UserID,
			"group", k.GroupID,
			"reason", k.Reason,
			"queued_at", k.QueuedAt,
		)
		s.performGroupLeave(k.GroupID, k.UserID, k.Reason)
	}
}
