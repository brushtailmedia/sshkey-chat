package server

// Phase 16 Gap 1 — runUserRetirementProcessor and
// processPendingUserRetirements.
//
// User-level analog of runRoomRetirementProcessor (room_retirements.go).
// Same architecture, same ticker cadence, same bridging role.
//
// The CLI runs `sshkey-ctl retire-user`, which directly mutates
// users.db via SetUserRetired and then enqueues a row on
// pending_user_retirements. The processor here drains that queue and
// calls handleRetirement, which fires per-room leave events with
// reason "user_retired", iterates the user's group DMs performing
// last-admin succession + per-group leave, sets per-user 1:1 DM
// cutoffs, broadcasts user_retired to all connected clients, and
// terminates active sessions for the retired user.
//
// Order of operations matters: the CLI flips the retired flag BEFORE
// enqueueing, so by the time the processor reads the row, users.db
// already shows the user as retired. handleRetirement does not
// re-flip the flag — it only handles the downstream effects.
//
// The "retired_by" field carries the OS uid of whoever ran
// sshkey-ctl (formatted as "os:<uid>" by the CLI) so audit entries
// identify the operator. handleRetirement currently writes its audit
// entry with source="server", so the processor adds an additional
// audit entry crediting the actual operator before invoking
// handleRetirement.

import (
	"time"
)

// userRetirementPollInterval is how often the user retirement
// processor checks the pending_user_retirements queue. Five seconds
// matches the room retirement processor — same justification: the
// retirement takes effect at the data layer immediately, the polling
// interval just determines live-notification latency.
const userRetirementPollInterval = 5 * time.Second

// runUserRetirementProcessor is the polling loop that bridges the
// CLI's pending_user_retirements queue with the running server's
// broadcast surface. Started by Server.Run alongside
// runRoomRetirementProcessor.
//
// On startup, Server.Run also calls processPendingUserRetirements
// once before entering the ticker loop, so any rows queued while the
// server was down get processed immediately on restart.
func (s *Server) runUserRetirementProcessor() {
	ticker := time.NewTicker(userRetirementPollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-s.userRetirementStop:
			return
		case <-ticker.C:
			s.processPendingUserRetirements()
		}
	}
}

// processPendingUserRetirements consumes the pending_user_retirements
// queue and dispatches each row through handleRetirement. Each call:
//   - Atomically reads + deletes the queue rows
//   - For each consumed row, captures the user's room memberships
//     (handleRetirement needs the list to fire per-room leave events)
//   - Writes an audit log entry crediting the operator who triggered
//     the retirement
//   - Calls handleRetirement which performs the full cascade
//
// Errors are logged but don't stop processing — one bad row
// shouldn't poison the whole batch. Idempotency is provided by the
// CLI side flipping users.retired before enqueueing: if the
// processor double-processes (race between polling and a manual
// invocation), the second pass finds the user already retired and
// the room/group leave loops are no-ops because room_members and
// group_members were cleared on the first pass.
func (s *Server) processPendingUserRetirements() {
	if s.store == nil {
		return
	}

	pending, err := s.store.ConsumePendingUserRetirements()
	if err != nil {
		s.logger.Error("failed to consume user retirement queue", "error", err)
		return
	}
	if len(pending) == 0 {
		return
	}

	for _, p := range pending {
		s.logger.Info("processing user retirement",
			"user", p.UserID,
			"retired_by", p.RetiredBy,
			"reason", p.Reason,
			"queued_at", p.QueuedAt,
		)

		// Sanity check: the CLI should have flipped users.retired=1
		// before enqueueing. If the user row doesn't exist or isn't
		// retired, log loudly and skip — something is wrong but it's
		// not the processor's job to fix it.
		user := s.store.GetUserByID(p.UserID)
		if user == nil {
			s.logger.Warn("queued user retirement references missing user",
				"user", p.UserID)
			continue
		}
		if !user.Retired {
			s.logger.Warn("queued user retirement but users.retired=0 — CLI did not flip the flag before enqueueing",
				"user", p.UserID)
			continue
		}

		// Capture rooms before handleRetirement clears them. Note
		// that SetUserRetired (called by the CLI) does not touch
		// room_members — it only suffixes the display name and sets
		// the retired flag. So GetUserRoomIDs returns the full set
		// of memberships at the moment we read it. handleRetirement
		// then iterates the list and calls performRoomLeave on each,
		// which removes the room_members rows.
		oldRooms := s.store.GetUserRoomIDs(p.UserID)

		// Audit the operator credit before invoking handleRetirement
		// (which writes its own "server"-sourced audit entry for the
		// downstream effects). Two distinct entries with two
		// different sources is the right shape — the operator entry
		// captures intent, the server entry captures execution.
		if s.audit != nil {
			s.audit.Log(p.RetiredBy, "retire-user",
				"user="+p.UserID+" reason="+p.Reason)
		}

		// handleRetirement does the full cascade: per-room leaves,
		// group exits with last-admin succession, DM cutoffs, the
		// user_retired broadcast, profile display name update,
		// active session termination, and its own audit entry.
		s.handleRetirement(p.UserID, oldRooms, p.Reason)
	}
}
