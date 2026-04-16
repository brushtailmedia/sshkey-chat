package server

// Phase 16 Gap 1 — runUserUnretirementProcessor and
// processPendingUserUnretirements.
//
// Inverse of runUserRetirementProcessor (user_retirements.go). Same
// architecture, same ticker cadence, same bridging role, simpler
// payload because unretirement does much less work than retirement.
//
// The CLI runs `sshkey-ctl unretire-user`, which:
//   1. Calls SetUserUnretired on users.db (flips retired=0, clears
//      retired_at/retired_reason, strips the retirement display-name
//      suffix)
//   2. Enqueues a row on pending_user_unretirements
//
// The processor here drains the queue and broadcasts user_unretired
// to all connected clients so they can flush the [retired] marker
// from their profile cache. That's the entire downstream effect —
// unretirement is intentionally minimal and does NOT restore room
// or group memberships (the retirement cascade removed them, and
// rebuilding requires admin intent that the operator must express
// via add-to-room / in-group /add separately).

import (
	"time"

	"github.com/brushtailmedia/sshkey-chat/internal/protocol"
)

// userUnretirementPollInterval is how often the unretirement
// processor checks the pending_user_unretirements queue. Five
// seconds matches the retirement processor — same justification.
const userUnretirementPollInterval = 5 * time.Second

// runUserUnretirementProcessor is the polling loop that bridges the
// CLI's pending_user_unretirements queue with the running server's
// broadcast surface. Started by Server.Run alongside
// runUserRetirementProcessor.
func (s *Server) runUserUnretirementProcessor() {
	ticker := time.NewTicker(userUnretirementPollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-s.userUnretirementStop:
			return
		case <-ticker.C:
			s.processPendingUserUnretirements()
		}
	}
}

// processPendingUserUnretirements consumes the
// pending_user_unretirements queue and broadcasts user_unretired
// for each row. Each call:
//   - Atomically reads + deletes the queue rows
//   - For each row, verifies the user is no longer retired (CLI
//     should have flipped the flag before enqueueing — log loudly
//     if not)
//   - Writes an audit log entry crediting the operator
//   - Broadcasts user_unretired to all connected clients (matching
//     the wide broadcast pattern of user_retired, with the
//     forward-compat rule that clients should ignore unknown
//     users gracefully)
//
// Errors are logged but don't stop processing — one bad row
// shouldn't poison the whole batch.
func (s *Server) processPendingUserUnretirements() {
	if s.store == nil {
		return
	}

	pending, err := s.store.ConsumePendingUserUnretirements()
	if err != nil {
		s.logger.Error("failed to consume user unretirement queue", "error", err)
		return
	}
	if len(pending) == 0 {
		return
	}

	for _, p := range pending {
		s.logger.Info("processing user unretirement",
			"user", p.UserID,
			"unretired_by", p.UnretiredBy,
			"queued_at", p.QueuedAt,
		)

		// Sanity check: the CLI should have flipped users.retired=0
		// before enqueueing. If the user row doesn't exist or is
		// still retired, log loudly and skip — something is wrong
		// but it's not the processor's job to fix it. Mirrors the
		// retirement processor's precondition check (just with the
		// flag in the opposite direction).
		user := s.store.GetUserByID(p.UserID)
		if user == nil {
			s.logger.Warn("queued user unretirement references missing user",
				"user", p.UserID)
			continue
		}
		if user.Retired {
			s.logger.Warn("queued user unretirement but users.retired=1 — CLI did not flip the flag before enqueueing",
				"user", p.UserID)
			continue
		}

		// Audit the operator credit.
		if s.audit != nil {
			s.audit.Log(p.UnretiredBy, "unretire-user",
				"user="+p.UserID)
		}

		// Broadcast user_unretired to all connected clients. We
		// broadcast widely rather than computing a per-client
		// visibility set because:
		//   - retirement uses the same wide broadcast pattern, so
		//     unretirement should mirror it for symmetry
		//   - unretirement is rare (escape hatch for mistakes), so
		//     broadcast cost is negligible
		//   - the forward-compat rule says clients must gracefully
		//     ignore unknown users
		//   - the only state change on receipt is `delete(c.retired,
		//     user)` which is safe even for users the client never
		//     had in the cache
		event := protocol.UserUnretired{
			Type: "user_unretired",
			User: p.UserID,
			Ts:   time.Now().Unix(),
		}
		s.mu.RLock()
		for _, client := range s.clients {
			client.Encoder.Encode(event)
		}
		s.mu.RUnlock()
	}
}
