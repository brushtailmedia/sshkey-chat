package server

import (
	"time"

	"github.com/brushtailmedia/sshkey-chat/internal/protocol"
)

// runRoomRetirementProcessor is the polling loop that bridges the
// CLI's pending_room_retirements queue with the running server's
// broadcast surface. Phase 12.
//
// Why polling instead of IPC: the CLI is a separate process that owns
// nothing but filesystem access to the server's data dir. There is no
// existing IPC mechanism between sshkey-ctl and sshkey-server — the
// decision_no_remote_admin_commands.md memory note explains the
// security design ("no remote admin commands, ever"). A queue table +
// polling goroutine is the canonical bridge pattern for CLI-initiated
// state changes that need live broadcasts.
//
// The CLI also performs the retirement mutation directly via
// SetRoomRetired on rooms.db, so retirement takes effect at the data
// layer regardless of whether the server is running. This processor
// is purely about live notification delivery to connected members —
// offline devices pick up the retirement via the retired_rooms
// catchup list on their next handshake.
func (s *Server) runRoomRetirementProcessor() {
	ticker := time.NewTicker(roomRetirementPollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-s.roomRetirementStop:
			return
		case <-ticker.C:
			s.processPendingRoomRetirements()
		}
	}
}

// processPendingRoomRetirements consumes the pending_room_retirements
// queue and dispatches each row as a room_retired broadcast. Each
// call:
//   - Atomically reads + deletes the queue rows (so a concurrent
//     processor invocation can't double-process)
//   - For each consumed row, looks up the room (which the CLI has
//     already marked retired) and broadcasts protocol.RoomRetired to
//     every connected session of every current room_members row for
//     that room
//   - Writes an audit log entry crediting the admin who triggered it
//
// Errors are logged but don't stop processing — one bad row shouldn't
// poison the whole batch.
//
// Called on server startup (before entering the ticker loop) so any
// rows that were queued while the server was down are processed
// immediately on restart, and then on every tick of the processor
// loop.
func (s *Server) processPendingRoomRetirements() {
	if s.store == nil {
		return
	}

	pending, err := s.store.ConsumePendingRoomRetirements()
	if err != nil {
		s.logger.Error("failed to consume room retirement queue", "error", err)
		return
	}
	if len(pending) == 0 {
		return
	}

	for _, p := range pending {
		s.logger.Info("processing room retirement",
			"room", p.RoomID,
			"retired_by", p.RetiredBy,
			"reason", p.Reason,
			"queued_at", p.QueuedAt,
		)

		// Re-fetch the room from rooms.db to get the post-retirement
		// (suffixed) display name. The CLI already updated rooms.db
		// via SetRoomRetired before writing this queue row, so the
		// lookup returns the retired state.
		room, err := s.store.GetRoomByID(p.RoomID)
		if err != nil {
			s.logger.Error("failed to lookup retired room during processing",
				"room", p.RoomID, "error", err)
			continue
		}
		if room == nil {
			s.logger.Warn("queued room retirement references missing room",
				"room", p.RoomID)
			continue
		}

		// Build the broadcast event. Display name carries the
		// post-retirement suffixed form so clients update their local
		// cache in one step.
		event := protocol.RoomRetired{
			Type:        "room_retired",
			Room:        p.RoomID,
			DisplayName: room.DisplayName,
			RetiredAt:   room.RetiredAt,
			RetiredBy:   p.RetiredBy,
			Reason:      p.Reason,
		}

		// Look up current members from rooms.db. SetRoomRetired does
		// NOT touch room_members — members remain in the membership
		// table until they explicitly /leave or /delete. So this
		// returns the full member set at the time of retirement.
		members := s.store.GetRoomMemberIDsByRoomID(p.RoomID)
		memberSet := make(map[string]bool, len(members))
		for _, m := range members {
			memberSet[m] = true
		}

		// Deliver to every connected session whose UserID is in the
		// member set. Phase 17 Step 3: lock-release pattern.
		s.mu.RLock()
		var targets []*Client
		for _, client := range s.clients {
			if memberSet[client.UserID] {
				targets = append(targets, client)
			}
		}
		s.mu.RUnlock()
		s.fanOut("room_retired", event, targets)

		// Audit log entry crediting the admin. The CLI can't write to
		// the audit log directly (it's a separate process with its
		// own filesystem scope), so the server logs it here as part
		// of processing.
		if s.audit != nil {
			s.audit.Log(p.RetiredBy, "retire-room",
				"room="+p.RoomID+" reason="+p.Reason)
		}

		// Phase 20: record a room_event audit row so members see
		// "this room was retired by an admin" inline in the
		// transcript. Best-effort — failure doesn't block the
		// broadcast above. Note: we use the original (pre-suffix)
		// context naturally since the event lives in the per-room
		// DB keyed by roomID, which doesn't change on retirement.
		if err := s.store.RecordRoomEvent(
			p.RoomID, "retire", "", p.RetiredBy, p.Reason, "", false, time.Now().Unix(),
		); err != nil {
			s.logger.Error("failed to record room event",
				"room", p.RoomID, "event", "retire", "error", err)
		}
	}
}
