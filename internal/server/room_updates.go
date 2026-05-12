package server

// Phase 16 Gap 1 — runRoomUpdatesProcessor and
// processPendingRoomUpdates. Shared processor for update-topic and
// rename-room — both CLI verbs mutate a column on a single rooms.db
// row and need to broadcast a fresh room_updated event to connected
// members of the affected room.
//
// Architecturally identical to admin_state_changes.go but for room
// properties instead of user properties, and with a NARROW broadcast
// scope (members of the room only) instead of wide. Same shape as
// the existing room_retirements processor.
//
// The post-write side-effect pipeline (re-read room, audit, record
// room_event, build RoomUpdated, narrow fan-out) lives in the
// emitRoomUpdate helper at the bottom of this file. The helper is
// shared between this CLI queue processor and the in-session
// handleRoomUpdate request handler in room_update.go, so both
// trigger paths produce byte-identical audit rows, room_event rows,
// and room_updated broadcasts.

import (
	"time"

	"github.com/brushtailmedia/sshkey-chat/internal/protocol"
	"github.com/brushtailmedia/sshkey-chat/internal/store"
)

// roomUpdatePollInterval is how often the room update processor
// checks the pending_room_updates queue. Five seconds matches the
// other Phase 16 Gap 1 processors.
const roomUpdatePollInterval = 5 * time.Second

// runRoomUpdatesProcessor is the polling loop that bridges the CLI's
// pending_room_updates queue with the running server's broadcast
// surface. Started by Server.Run alongside the other Phase 16 Gap 1
// processors.
func (s *Server) runRoomUpdatesProcessor() {
	ticker := time.NewTicker(roomUpdatePollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-s.roomUpdateStop:
			return
		case <-ticker.C:
			s.processPendingRoomUpdates()
		}
	}
}

// processPendingRoomUpdates consumes the queue and emits a
// room_updated fan-out for each row via emitRoomUpdate. Each call:
//   - Atomically reads + deletes the queue rows
//   - Calls the shared emitRoomUpdate helper for each row
//
// Errors are logged but don't stop processing.
func (s *Server) processPendingRoomUpdates() {
	if s.store == nil {
		return
	}

	pending, err := s.store.ConsumePendingRoomUpdates()
	if err != nil {
		s.logger.Error("failed to consume room update queue", "error", err)
		return
	}
	if len(pending) == 0 {
		return
	}

	for _, p := range pending {
		s.logger.Info("processing room update",
			"room", p.RoomID,
			"action", string(p.Action),
			"changed_by", p.ChangedBy,
			"queued_at", p.QueuedAt,
		)
		s.emitRoomUpdate(p.Action, p.RoomID, p.ChangedBy, p.NewValue)
	}
}

// emitRoomUpdate is the shared post-write side-effect pipeline used
// by both the CLI queue processor (processPendingRoomUpdates) and
// the in-session request handler (handleRoomUpdate in
// room_update.go). It:
//
//  1. Re-reads the room row to capture the post-change state.
//  2. Writes an audit log entry (action-specific verb), guarded by
//     `s.audit != nil` for nil-audit test contexts.
//  3. Records a room_event row via RecordRoomEvent (best-effort —
//     audit failure doesn't block the live broadcast below).
//  4. Builds the protocol.RoomUpdated event from the post-change
//     row.
//  5. Narrow-fans-out to connected members of the affected room
//     only (Phase 17 Step 3 lock-release pattern: hold s.mu.RLock
//     only long enough to build the recipient slice, then release
//     BEFORE calling s.fanOut — back-pressure safety, no s.mu lock
//     held during the per-recipient Encode).
//
// Missing room / unknown action are non-fatal: logged + skipped.
// All errors are logged; none stop the flow. This matches the
// CLI queue processor's prior inline behavior — for the in-session
// handler the caller (handleRoomUpdate) verifies membership and
// loads the room row BEFORE calling the helper, so a missing-room
// outcome at this point would be a TOCTOU race (rare; logged and
// skipped without explicit caller-side error).
//
// Inputs:
//   - action:    store.RoomUpdateAction; determines audit verb and
//     room_event type. Unknown values are logged and
//     skipped.
//   - roomID:    target room nanoid.
//   - changedBy: user ID that initiated the change. For CLI path
//     this is the os:UID format; for in-session it's
//     the connected user's UserID.
//   - newValue:  the new value (topic or display name) recorded in
//     the room_event row's Name field. Not used in the
//     audit message — that pulls from the (post-write)
//     room row instead, so the audit always reflects
//     current state regardless of which action ran.
func (s *Server) emitRoomUpdate(action store.RoomUpdateAction, roomID, changedBy, newValue string) {
	if s.store == nil {
		return
	}

	// Re-fetch the room row to capture the post-change state.
	room, err := s.store.GetRoomByID(roomID)
	if err != nil {
		s.logger.Error("failed to lookup room during update processing",
			"room", roomID, "error", err)
		return
	}
	if room == nil {
		s.logger.Warn("room update references missing room",
			"room", roomID, "action", string(action))
		return
	}

	// Audit credit. The action-to-verb mapping uses the CLI verb
	// names so operators reading the log see what they typed.
	var auditAction, eventType string
	switch action {
	case store.RoomUpdateActionUpdateTopic:
		auditAction = "update-topic"
		eventType = "topic"
	case store.RoomUpdateActionRenameRoom:
		auditAction = "rename-room"
		eventType = "rename"
	default:
		s.logger.Warn("unknown room update action",
			"action", string(action))
		return
	}
	if s.audit != nil {
		s.audit.Log(changedBy, auditAction,
			"room="+roomID+" display_name="+room.DisplayName+" topic="+room.Topic)
	}

	// Phase 20: record a room_event audit row so members see
	// inline "alice changed the topic to 'foo'" / "alice renamed
	// the room to 'bar'" on their next sync. Best-effort — audit
	// failure doesn't block the live broadcast below.
	if err := s.store.RecordRoomEvent(
		roomID, eventType, "", changedBy, "", newValue, false, time.Now().Unix(),
	); err != nil {
		s.logger.Error("failed to record room event",
			"room", roomID, "event", eventType, "error", err)
	}
	// Live room_event fan-out so connected members see the inline
	// topic/rename system message immediately instead of waiting for
	// next sync replay.
	s.broadcastToRoom(roomID, protocol.RoomEvent{
		Type:  "room_event",
		Room:  roomID,
		Event: eventType,
		By:    changedBy,
		Name:  newValue,
	})

	// Build the broadcast event with the full post-change room
	// state — both fields populated even if only one changed,
	// so the client can apply the event with a single upsert.
	event := protocol.RoomUpdated{
		Type:        "room_updated",
		Room:        roomID,
		DisplayName: room.DisplayName,
		Topic:       room.Topic,
	}

	// Narrow broadcast: members of the affected room only.
	// Mirrors the room_retired pattern. Members who aren't
	// currently connected pick up the update on their next
	// reconnect via the existing room_list catchup.
	members := s.store.GetRoomMemberIDsByRoomID(roomID)
	memberSet := make(map[string]bool, len(members))
	for _, m := range members {
		memberSet[m] = true
	}

	// Phase 17 Step 3: lock-release pattern.
	s.mu.RLock()
	var targets []*Client
	for _, client := range s.clients {
		if memberSet[client.UserID] {
			targets = append(targets, client)
		}
	}
	s.mu.RUnlock()
	s.fanOut("room_updated", event, targets)
}
