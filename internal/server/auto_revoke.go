package server

// Phase 17b Step 3 — auto-revoke processor.
//
// Shape: matches the 6 existing Phase 16 Gap 1 processors
// (runDeviceRevocationProcessor etc.). The auto-revoke goroutine ticks
// at autoRevokePollInterval, evaluates configured [server.auto_revoke]
// thresholds against the counter sliding windows, and enqueues
// revocations for devices that cross. The existing
// runDeviceRevocationProcessor drains the queue and kicks sessions.
//
// Behavior matrix (keyed on cfg.Server.Server.AutoRevoke.Enabled):
//
//   enabled = true:
//     - Device crosses threshold → enqueue into pending_device_revocations
//       with revoked_by="server:auto_revoke" and a human-readable reason
//     - Emit slog.Warn("auto_revoke", ...) with structured fields
//     - Write audit log row tagged "auto-revoke-device"
//
//   enabled = false (observer mode, D3 per Step 0 audit):
//     - Goroutine still runs and still evaluates thresholds
//     - No enqueue, no revocation
//     - Emit slog.Info("auto_revoke_would_fire", ...) with the same
//       structured fields — operators see what the breaker WOULD do
//       during diagnostic periods
//
// Idempotency: before each enqueue, check IsDeviceRevoked. If the
// device is already revoked (by admin or by a prior auto-revoke tick
// that fired before the drain processor caught up), skip. This keeps
// the queue shallow under sustained misbehavior and avoids
// double-counting in audit logs.
//
// Reason-string format is server-owned (D2 per Step 0 audit): the
// string produced here is what the TUI DeviceRevokedModel renders
// verbatim. Client stays dumb; server holds the signal → description
// mapping.

import (
	"fmt"
	"time"

	"github.com/brushtailmedia/sshkey-chat/internal/config"
	"github.com/brushtailmedia/sshkey-chat/internal/counters"
)

// autoRevokePollInterval is how often the auto-revoke processor
// evaluates thresholds. 10s is slow enough to amortize the per-tick
// cost over any sustained misbehavior (a 60s window accumulates
// plenty of events to trigger) and fast enough that a hostile device
// is stopped within seconds of crossing threshold.
const autoRevokePollInterval = 10 * time.Second

// autoRevokeDescriptions maps counter signal names to user-facing
// human descriptions. The full reason string embedded in the
// device_revoked event (and rendered verbatim by the TUI) is:
//
//   "Automatic revocation: <description> (<count> events in <window>s)"
//
// Signals missing from this map fall back to a generic "signal X"
// prefix — this shouldn't happen for correctly-configured signals but
// is the safe behavior for forward-compat with signals added in later
// phases.
var autoRevokeDescriptions = map[string]string{
	counters.SignalMalformedFrame:       "too many malformed frames",
	counters.SignalOversizedBody:        "too many oversized messages",
	counters.SignalUnknownVerb:          "too many unknown commands",
	counters.SignalInvalidNanoID:        "too many invalid identifiers",
	counters.SignalWrappedKeysOverCap:   "too many oversized key envelopes",
	counters.SignalFileIDsOverCap:       "too many oversized attachment lists",
	counters.SignalInvalidContentHash:   "too many malformed upload hashes",
	counters.SignalOversizedUploadFrame: "too many oversized upload frames",
	counters.SignalNonMemberContext:     "too many requests to contexts you don't belong to",
	counters.SignalDownloadNotFound:     "too many invalid download requests",
	counters.SignalDownloadNoChannel:    "upload channel misuse (client bug)",
	// SignalReconnectFlood will land here in Step 5.
}

// buildAutoRevokeReason builds the operator-readable reason string
// embedded in the device_revocation row. This is the string the TUI
// renders verbatim; server owns formatting.
func buildAutoRevokeReason(signal string, count, windowSec int) string {
	desc, ok := autoRevokeDescriptions[signal]
	if !ok {
		desc = "signal " + signal
	}
	return fmt.Sprintf("Automatic revocation: %s (%d events in %ds)", desc, count, windowSec)
}

// resolveDeviceUser returns the user ID that owns the given device ID.
// Fast path: iterate s.clients (active connections). Fallback: store
// lookup for offline devices.
//
// Returns ("", false) if no mapping found (race between revocation and
// device-row deletion, misconfigured test, etc.). Caller logs + skips.
func (s *Server) resolveDeviceUser(deviceID string) (string, bool) {
	s.mu.RLock()
	for _, c := range s.clients {
		if c.DeviceID == deviceID {
			user := c.UserID
			s.mu.RUnlock()
			return user, user != ""
		}
	}
	s.mu.RUnlock()

	if s.store == nil {
		return "", false
	}
	user, err := s.store.GetDeviceOwner(deviceID)
	if err != nil || user == "" {
		return "", false
	}
	return user, true
}

// runAutoRevokeProcessor is the ticker loop. Matches the other Phase
// 16 Gap 1 processor shapes for consistency and grep-ability.
func (s *Server) runAutoRevokeProcessor() {
	ticker := time.NewTicker(autoRevokePollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-s.autoRevokeStop:
			return
		case <-ticker.C:
			s.processAutoRevoke()
		}
	}
}

// processAutoRevoke evaluates all configured thresholds once and
// enqueues revocations for any device that crosses. Called on every
// ticker tick.
//
// Errors are logged but never stop the processor — the auto-revoke
// ticker must be resilient against transient store hiccups.
func (s *Server) processAutoRevoke() {
	if s.store == nil {
		return
	}

	// Snapshot config under its RWMutex. Hot-reload may have
	// replaced the AutoRevoke block between ticks; take a consistent
	// copy.
	s.cfg.RLock()
	ar := s.cfg.Server.Server.AutoRevoke
	s.cfg.RUnlock()

	// ParseAndValidate is idempotent — cfg was validated at load
	// time, so this should never error in practice. If it does
	// (hot-reloaded bad config), log and skip this tick.
	rules, _, err := ar.ParseAndValidate()
	if err != nil {
		s.logger.Error("auto_revoke: threshold config invalid at tick, skipping",
			"error", err)
		return
	}
	if len(rules) == 0 {
		// No thresholds configured. Enabled=true + zero thresholds
		// fired a warning at startup; we silently no-op here each
		// tick.
		return
	}

	for _, rule := range rules {
		devices := s.counters.DevicesFor(rule.Signal)
		for _, deviceID := range devices {
			if !s.counters.Check(rule.Signal, deviceID, rule.Count, rule.WindowSec) {
				continue
			}
			s.handleAutoRevokeCrossing(ar.Enabled, rule, deviceID)
		}
	}
}

// handleAutoRevokeCrossing is the per-device path invoked when Check
// reports threshold crossed. Enqueue branch (enabled=true) writes to
// pending_device_revocations + audit log; observer branch
// (enabled=false) just logs at Info.
//
// Idempotency: skip if device already in revoked_devices. This covers
// both (a) admin-initiated revocations that happened between ticks
// and (b) auto-revoke firings from a prior tick whose queue row has
// been drained and written to revoked_devices. Without this check,
// an actively-misbehaving device would accumulate duplicate queue
// rows every 10s until its session finally dies.
func (s *Server) handleAutoRevokeCrossing(enabled bool, rule config.ThresholdRule, deviceID string) {
	userID, ok := s.resolveDeviceUser(deviceID)
	if !ok {
		s.logger.Warn("auto_revoke: cannot resolve user for device",
			"device", deviceID, "signal", rule.Signal)
		return
	}

	revoked, err := s.store.IsDeviceRevoked(userID, deviceID)
	if err != nil {
		s.logger.Error("auto_revoke: IsDeviceRevoked failed",
			"user", userID, "device", deviceID, "signal", rule.Signal, "error", err)
		return
	}
	if revoked {
		// Already revoked — no-op. Counter will age out of the
		// sliding window naturally; if the device reconnects
		// after being restored, counters reset via in-memory state.
		return
	}

	reason := buildAutoRevokeReason(rule.Signal, rule.Count, rule.WindowSec)

	if !enabled {
		s.logger.Info("auto_revoke_would_fire",
			"device", deviceID,
			"user", userID,
			"signal", rule.Signal,
			"count", rule.Count,
			"window", rule.WindowSec,
			"reason", reason,
		)
		return
	}

	if err := s.store.RecordPendingDeviceRevocation(userID, deviceID, reason, "server:auto_revoke"); err != nil {
		s.logger.Error("auto_revoke: enqueue failed",
			"user", userID, "device", deviceID, "signal", rule.Signal, "error", err)
		return
	}

	s.logger.Warn("auto_revoke",
		"device", deviceID,
		"user", userID,
		"signal", rule.Signal,
		"count", rule.Count,
		"window", rule.WindowSec,
		"reason", reason,
	)

	if s.audit != nil {
		s.audit.Log("server:auto_revoke", "auto-revoke-device",
			"user="+userID+" device="+deviceID+" signal="+rule.Signal+" reason="+reason)
	}
}
