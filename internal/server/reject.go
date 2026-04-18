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
// Drop handling (updated Phase 17b Step 5b): fanOut now non-blocking-
// enqueues into each recipient's per-client outbound queue (Client.sendCh).
// A full queue indicates a slow reader; the drop increments
// SignalBroadcastDropped and advances the recipient's consecutiveDrops
// counter. When that counter crosses s.cfg.Server.RateLimits.
// ConsecutiveDropDisconnectThreshold, fanOut closes the recipient's SSH
// channel — disconnect (not auto-revoke) is the remedy, and the client
// recovers via normal reconnect + sync-catchup.
//
// Clients constructed in test code without a sendCh (Client.sendCh == nil)
// take a fallback synchronous-Encode path so existing tests that
// verify fanOut wire output via a captured io.Writer continue to pass.
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
		s.fanOutOne(verb, msg, c)
	}
}

// fanOutOne enqueues msg to a single recipient with drop-tracking and
// consecutive-drop disconnect. Used by fanOut and by handleEpochRotate's
// inline per-recipient path (where each recipient gets a different
// message). Phase 17b Step 5b.
func (s *Server) fanOutOne(verb string, msg any, c *Client) {
	// Test-mode fallback: Client constructed without a sendCh (see
	// fanout_test.go, reject_test.go fixtures). Synchronous Encode
	// preserves pre-5b behavior for those tests.
	if c.sendCh == nil {
		if err := c.Encoder.Encode(msg); err != nil {
			s.counters.Inc(counters.SignalBroadcastDropped, c.DeviceID)
			s.logger.Debug("broadcast dropped (sync test path)",
				"verb", verb,
				"device", c.DeviceID,
				"error", err,
			)
		}
		return
	}

	queued, drops := c.TryEnqueue(msg)
	if queued {
		return
	}

	s.counters.Inc(counters.SignalBroadcastDropped, c.DeviceID)
	s.logger.Debug("broadcast dropped (queue full)",
		"verb", verb,
		"device", c.DeviceID,
		"consecutive_drops", drops,
	)

	threshold := s.cfg.Server.RateLimits.ConsecutiveDropDisconnectThreshold
	if threshold > 0 && drops >= int32(threshold) {
		s.logger.Warn("slow-reader disconnect",
			"verb", verb,
			"user", c.UserID,
			"device", c.DeviceID,
			"consecutive_drops", drops,
			"threshold", threshold,
		)
		c.Channel.Close()
	}
}

// respondError is the Phase 17c Step 1 chokepoint for typed error
// responses. Every error a handler returns to a client goes through
// this function. Responsibilities:
//
//  1. Consult the per-device error-response rate limiter. If the
//     client has exceeded the ErrorResponsesPerMinute budget, silently
//     drop the error (no wire bytes, no client-visible log entry)
//     AND increment SignalErrorFlood so Phase 17b auto-revoke can
//     escalate cross-connection abusers. Silent-drop preserves
//     Category D's byte-identical privacy invariant: a rate-limited
//     client sees "no response at all" regardless of the original
//     rejection reason.
//
//  2. Encode the typed protocol.Error{} onto the client's NDJSON
//     channel via the mutex-protected safeEncoder. Sets Type="error"
//     automatically so callers don't have to remember it. retryAfterMs
//     uses `omitempty` so 0 is elided from the wire (callers pass 0
//     for non-Category-A errors).
//
// Callers MUST `return` immediately after invoking respondError — like
// rejectAndLog, this helper does NOT break control flow, and forgetting
// the return leaves the handler executing with inconsistent state.
//
// corrID is echoed from the inbound request (possibly empty if the
// client didn't supply one). Server never persists it; respondError
// simply includes it in the response when non-empty.
//
// c == nil is accepted but effectively a no-op (rate-limit skipped,
// encode skipped) — matches rejectAndLog's nil-safety for Channel 3
// and similar no-client-available paths.
func (s *Server) respondError(c *Client, corrID, code, message string, retryAfterMs int64) {
	if c == nil {
		return
	}

	// Per-device error-response rate limit. 0 disables.
	limit := s.cfg.Server.RateLimits.ErrorResponsesPerMinute
	if limit > 0 {
		if allowed, _ := s.limiter.allowPerMinuteWithRetry("errors:"+c.DeviceID, limit); !allowed {
			// Silent drop: count the rate-limit rejection as a
			// SignalErrorFlood event so Phase 17b can escalate
			// cross-connection abusers. NO wire response, no
			// client-visible log (the drop IS the enforcement).
			s.counters.Inc(counters.SignalErrorFlood, c.DeviceID)
			s.logger.Debug("error response silently dropped (rate limit)",
				"device", c.DeviceID,
				"code", code,
			)
			return
		}
	}

	_ = c.Encoder.Encode(protocol.Error{
		Type:         "error",
		Code:         code,
		Message:      message,
		RetryAfterMs: retryAfterMs,
		CorrID:       corrID,
	})
}

// respondOpaque is the Category D helper: byte-identical privacy
// rejection. Always emits the same wire shape (code="denied",
// message="operation rejected") regardless of the underlying
// server-side reason — preserves Phase 14's privacy invariant that
// probing clients can't distinguish "not a member" from "room
// doesn't exist" from "deleted row".
//
// corrID is echoed; rest of the wire shape is fixed by
// protocol.OpaqueReject(). Routes through respondError so the
// per-device error-rate-limit + SignalErrorFlood discipline applies
// uniformly.
func (s *Server) respondOpaque(c *Client, corrID string) {
	s.respondError(c, corrID, protocol.CodeDenied, "operation rejected", 0)
}
