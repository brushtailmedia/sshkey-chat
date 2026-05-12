package server

// handleRoomUpdate implements the room_update request — the in-
// session, low-latency companion to the operator-only CLI path
// (`sshkey-ctl update-topic` + the pending_room_updates queue +
// processPendingRoomUpdates in room_updates.go).
//
// Spec: topic.md in this repo (2026-05-12 rewrite). This is the
// server-side bug-close for the situation where the sshkey-term
// client already sends room_update envelopes (handleTopicCommand
// in internal/tui/app.go + SendRoomUpdate in internal/client/
// send.go) but the dispatcher had no case to receive them, so
// envelopes were silently dropped.
//
// Scope: TOPIC ONLY. Room rename is intentionally NOT in this
// wire surface — renames stay operator-only via the CLI's
// `sshkey-ctl rename-room` path. Adding rename to this request
// surface is a future extension explicitly deferred in §9 of
// topic.md.
//
// Authorization (§3 decision 2 of the spec, repeated here so the
// next reader doesn't have to cross-reference):
//   - "admin" throughout this handler means SERVER admin (the
//     users.admin flag, set via `sshkey-ctl approve --admin` /
//     `sshkey-ctl promote`). Rooms have no per-room admin role
//     in this phase. The membership requirement at step 7 is
//     what restricts in-session topic moderation to admins who
//     are also participants of the affected room — the CLI path
//     bypasses that for operator-override scenarios.
//
// 12-step flow (matches §5.2 of topic.md):
//
//  1. Decode JSON into protocol.RoomUpdate.
//  2. On decode error: rejectAndLog with SignalMalformedFrame +
//     send invalid_message. Pre-unmarshal — no corr_id available.
//  3. Validate corr_id via validateCorrIDOrReject. On violation
//     the response is silent-drop on the wire (per the shared
//     convention across the verb surface — server log line +
//     SignalMalformedFrame counter, but client receives no typed
//     response); caller must return immediately.
//  4. Require s.store != nil; else internal_error.
//  5. Apply admin-action rate limit via
//     checkRoomAdminActionRateLimit. Runs BEFORE auth check to
//     DoS-protect the auth-check DB reads against repeated
//     unauthorized attempts.
//  6. Require server-admin (users.admin); else forbidden.
//  7. Require room membership (IsRoomMemberByID); else
//     unknown_room (privacy-preserving — indistinguishable from
//     the missing-room case at step 8).
//  8. Load room row by ID. Not found → unknown_room (defense-
//     in-depth — step 7 normally catches this; orphan
//     room_members rows would slip past). Retired →
//     room_retired. (SetRoomTopic at step 10 also enforces the
//     retired check at the store layer; the handler's check is
//     early-rejection for clearer error-code routing.)
//  9. Idempotency — same-value topic is treated as success no-
//     op: send the caller a room_updated echo (single-element
//     fanOut, NOT a direct Encode — inherits the same drop-
//     tracking + back-pressure semantics as the broadcast path)
//     and return without writing, auditing, recording a
//     room_event, or fanning out to other members. Symmetric
//     with the CLI update-topic path which silently writes the
//     same value.
// 10. Persist via SetRoomTopic.
// 11. Trigger emitRoomUpdate side-effect pipeline (audit log +
//     room_event row + narrow fan-out to all connected room
//     members including the caller). The shared helper lives in
//     room_updates.go and is reused verbatim from the CLI
//     processor path, so audit, room_event, and room_updated
//     payloads are byte-identical between the two trigger
//     paths.
// 12. No direct success frame — caller receives room_updated via
//     the fan-out in step 11.
//
// CorrID rule: once unmarshal succeeds, all typed errors echo
// req.CorrID via respondError(..., req.CorrID, ...) for send-
// queue correlation parity with the other corr_id-carrying
// verbs. The pre-unmarshal malformed-frame response at step 2
// carries empty corrID — there's no parsed corrID available at
// that point.

import (
	"encoding/json"

	"github.com/brushtailmedia/sshkey-chat/internal/counters"
	"github.com/brushtailmedia/sshkey-chat/internal/protocol"
	"github.com/brushtailmedia/sshkey-chat/internal/store"
)

func (s *Server) handleRoomUpdate(c *Client, raw json.RawMessage) {
	// Step 1-2: decode + malformed-frame rejection.
	var req protocol.RoomUpdate
	if err := json.Unmarshal(raw, &req); err != nil {
		s.rejectAndLog(c, counters.SignalMalformedFrame, "room_update", "malformed room_update frame",
			&protocol.Error{Type: "error", Code: "invalid_message", Message: "malformed room_update"})
		return
	}

	// Step 3: corr_id shape validation (silent-drop on violation).
	if !s.validateCorrIDOrReject(c, "room_update", req.CorrID) {
		return
	}

	// Step 4: storage nil-guard.
	if s.store == nil {
		s.respondError(c, req.CorrID, protocol.CodeInternal, "storage not available", 0)
		return
	}

	// Step 5: admin-action rate limit. BEFORE auth check —
	// DoS-protects the IsAdmin lookup against unauthorized spam.
	if !s.checkRoomAdminActionRateLimit(c, req.CorrID) {
		return
	}

	// Step 6: server-admin gate (users.admin flag).
	if !s.store.IsAdmin(c.UserID) {
		s.respondError(c, req.CorrID, protocol.ErrForbidden, "Admin access required", 0)
		return
	}

	// Step 7: room-membership gate. unknown_room is deliberately
	// indistinguishable from the missing-room outcome at step 8 —
	// a non-member can't probe room existence.
	if !s.store.IsRoomMemberByID(req.Room, c.UserID) {
		s.respondError(c, req.CorrID, protocol.ErrUnknownRoom, "You are not a member of this room", 0)
		return
	}

	// Step 8: load the (pre-write) room row for retired check +
	// idempotency comparison.
	room, err := s.store.GetRoomByID(req.Room)
	if err != nil {
		s.logger.Error("failed to lookup room in handleRoomUpdate",
			"room", req.Room, "error", err)
		s.respondError(c, req.CorrID, protocol.CodeInternal, "failed to load room", 0)
		return
	}
	if room == nil {
		// Defense-in-depth: orphan room_members row referencing a
		// deleted room. Privacy parity with step 7 — same
		// unknown_room response so the caller can't distinguish
		// "room doesn't exist" from "I'm not in it".
		s.respondError(c, req.CorrID, protocol.ErrUnknownRoom, "You are not a member of this room", 0)
		return
	}
	if room.Retired {
		s.respondError(c, req.CorrID, protocol.ErrRoomRetired, "This room has been archived and is read-only", 0)
		return
	}

	// Step 9: idempotency. Same-value topic is treated as
	// success no-op — caller-only room_updated echo, no DB
	// write, no audit, no room_event, no fanout.
	if room.Topic == req.Topic {
		event := protocol.RoomUpdated{
			Type:        "room_updated",
			Room:        req.Room,
			DisplayName: room.DisplayName,
			Topic:       room.Topic,
		}
		s.fanOut("room_updated", event, []*Client{c})
		return
	}

	// Step 10: persist.
	if err := s.store.SetRoomTopic(req.Room, req.Topic); err != nil {
		s.logger.Error("failed to set room topic",
			"room", req.Room, "error", err)
		s.respondError(c, req.CorrID, protocol.CodeInternal, "failed to update topic", 0)
		return
	}

	// Step 11: shared post-write side effects. The caller is a
	// member of the room (step 7), so they receive the
	// room_updated event via the helper's fanOut — no direct
	// success frame is sent (step 12).
	s.emitRoomUpdate(store.RoomUpdateActionUpdateTopic, req.Room, c.UserID, req.Topic)
}
