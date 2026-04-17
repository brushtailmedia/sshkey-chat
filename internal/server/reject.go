package server

import (
	"github.com/brushtailmedia/sshkey-chat/internal/counters"
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

// fanOut encodes msg to each recipient in the supplied slice. Callers build
// the recipient slice under the server mutex (or any other selection
// mechanism); fanOut itself holds NO lock and encodes outside any lock — the
// whole point of the helper is to NOT hold `s.mu.RLock()` while blocking on
// a slow recipient's Encode. Phase 17 Step 3 broadcast back-pressure fix.
//
// Usage (standard pattern, applies to 20 of the 21 broadcast sites):
//
//	s.mu.RLock()
//	var targets []*Client
//	for _, c := range s.clients {
//	    if <site-specific filter> {
//	        targets = append(targets, c)
//	    }
//	}
//	s.mu.RUnlock()
//	s.fanOut("message", msg, targets)
//
// Drop handling: if a recipient's Encode returns an error (typically because
// the SSH channel closed or its write buffer is full and the session is
// tearing down), fanOut increments `counters.SignalBroadcastDropped` for the
// recipient's device and emits a Debug-level log line. Debug level, not
// Warn, because broadcast drops during client disconnect are routine (not
// server bugs); operators enable Debug logging if they want live visibility,
// otherwise the counter surface via `Snapshot()` is sufficient.
//
// The `verb` parameter mirrors the `rejectAndLog` pattern — it names the
// high-level action that triggered the broadcast (e.g. "message", "profile",
// "epoch_key"), carried into the log record for aggregation / filtering.
//
// `handleEpochRotate` (epoch.go) is the one site that does NOT use fanOut
// because it encodes a different message per recipient (each member gets
// their own wrapped epoch key). That site follows the same pattern inline
// — collect (client, msg) pairs under RLock, release, iterate and encode
// outside the lock — and uses the same counter + Debug log shape for drops.
// Keeping the helper focused on the uniform case (same msg to many targets)
// is cleaner than adding a second helper variant for one caller.
func (s *Server) fanOut(verb string, msg any, recipients []*Client) {
	for _, c := range recipients {
		if err := c.Encoder.Encode(msg); err != nil {
			s.counters.Inc(counters.SignalBroadcastDropped, c.DeviceID)
			s.logger.Debug("broadcast dropped",
				"verb", verb,
				"device", c.DeviceID,
				"error", err,
			)
		}
	}
}
