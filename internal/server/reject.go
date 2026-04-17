package server

import (
	"github.com/brushtailmedia/sshkey-chat/internal/protocol"
)

// rejectAndLog is the single chokepoint for Phase 17 Step 4-6 rejection
// sites. It performs three actions in order:
//
//  1. Derive deviceID from c (empty string if c is nil, otherwise
//     c.DeviceID). Increment the per-device signal counter.
//  2. Emit a structured slog.Warn("rejection", ...) with signal, device,
//     verb, reason, and count fields. logReason MAY include private state
//     (room IDs, membership, epoch numbers) — it only reaches server logs,
//     never clients.
//  3. If c != nil AND clientErr != nil, write clientErr verbatim to the
//     client's NDJSON channel. The helper does NOT synthesize, transform,
//     or map clientErr — caller constructed it exactly, helper encodes it
//     exactly. This structural separation between logReason (server log)
//     and clientErr (client response) enforces Phase 14's privacy invariant
//     at the type-system level: a caller emitting an opaque rejection
//     builds an opaque *protocol.Error; a caller emitting an informative
//     rejection builds an informative one.
//
// Caller discipline: every caller MUST `return` immediately after invoking
// rejectAndLog. The helper does NOT break control flow — forgetting the
// return means the handler continues with inconsistent state (e.g., a
// rejected send still gets broadcast). Step 4-6 tests verify short-circuit
// behavior at each callsite.
//
// c == nil is accepted (deviceID falls back to empty string, client write
// is skipped). This covers Channel 3 rejections where the server cannot
// resolve the specific device — the counter increments under the empty
// deviceID bucket and an auxiliary slog.Warn fires in the counters package
// to surface the attribution gap. See counters.Inc and Phase 17b's
// "Channel 3 device attribution" design note for context.
//
// clientErr == nil is accepted (client write is skipped; counter + log
// still run). Use this for rejections where there's no NDJSON return path
// — Channel 3 binary-frame rejections are the primary case.
func (s *Server) rejectAndLog(
	c *Client,
	signal string,
	verb string,
	logReason string,
	clientErr *protocol.Error,
) {
	deviceID := ""
	if c != nil {
		deviceID = c.DeviceID
	}

	count := s.counters.Inc(signal, deviceID)

	s.logger.Warn("rejection",
		"signal", signal,
		"device", deviceID,
		"verb", verb,
		"reason", logReason,
		"count", count,
	)

	if c != nil && clientErr != nil {
		// Encode to the client. The encoder is mutex-protected so this is
		// safe from any handler goroutine. Encode errors are intentionally
		// swallowed — if the client connection is dead we can't do anything
		// useful, and returning an error from a rejection site would create
		// its own caller-discipline trap ("what do I do if rejection fails?").
		_ = c.Encoder.Encode(clientErr)
	}
}
