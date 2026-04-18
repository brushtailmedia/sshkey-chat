package server

// Phase 17b Step 5a — NDJSON idle-timeout watchdog.
//
// Per-connection goroutine that tracks Client.LastActivity (stamped
// by messageLoop on every successful Decode) and closes Channel 1 if
// no frames arrive within the configured window.
//
// Why a watchdog rather than SSH-level SetReadDeadline: ssh.Channel
// has no Deadline interface. A goroutine that closes the channel on
// staleness makes the blocked Read in messageLoop error out, which
// triggers the existing session-cleanup defer chain. No special
// shutdown coordination needed.
//
// Why NDJSON-level rather than transport-level: the server's SSH
// keepalive loop (server.go around line 628) already kills dead TCP
// connections every 30s via SSH request ping. This watchdog covers
// the residual case: a live TCP connection that responds to SSH
// keepalives but sends zero protocol traffic (slow-loris at the
// application layer).
//
// Default behavior: disabled. rate_limits.idle_timeout_seconds = 0
// means "don't start the watchdog at all." Operators enable post-launch
// once legitimate quiet-user patterns are observed.

import (
	"time"
)

// idleWatchdogMinCheck is the floor on watchdog polling cadence when
// timeoutSec/4 would be below 1s. Without it, a very short timeout
// (e.g. 2s in a test) would tick 500ms and eat CPU needlessly.
const idleWatchdogMinCheck = time.Second

// runIdleWatchdog closes c.Channel if c.LastActivity stays stale past
// timeoutSec seconds. Intended to run as `go s.runIdleWatchdog(...)`;
// terminates when `done` is closed (typically via defer in
// handleSession) or after firing once on staleness.
//
// checkEvery is the poll cadence. Default: min(30s, timeoutSec/4s),
// clamped to >= 1s. Exposed as a parameter for tests that need tight
// cadence; callers typically use computeIdleWatchdogCadence.
func (s *Server) runIdleWatchdog(c *Client, timeoutSec int, checkEvery time.Duration, done <-chan struct{}) {
	if timeoutSec <= 0 {
		return
	}
	ticker := time.NewTicker(checkEvery)
	defer ticker.Stop()

	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			last := c.LastActivity.Load()
			// last == 0: client is fresh (messageLoop hasn't yet
			// stamped). Grant one full window from watchdog start
			// by stamping "now" as the baseline the first time we
			// see zero — prevents a slow handshake from triggering
			// the watchdog before the first frame.
			if last == 0 {
				c.LastActivity.Store(time.Now().Unix())
				continue
			}
			idle := time.Now().Unix() - last
			if idle > int64(timeoutSec) {
				s.logger.Info("idle timeout — closing NDJSON channel",
					"user", c.UserID,
					"device", c.DeviceID,
					"idle_seconds", idle,
					"timeout_seconds", timeoutSec,
				)
				c.Channel.Close()
				return
			}
		}
	}
}

// computeIdleWatchdogCadence returns the default watchdog poll
// interval for the given timeout. Kept in a helper so session.go
// setup reads cleanly.
func computeIdleWatchdogCadence(timeoutSec int) time.Duration {
	quarter := time.Duration(timeoutSec) * time.Second / 4
	cadence := 30 * time.Second
	if quarter < cadence {
		cadence = quarter
	}
	if cadence < idleWatchdogMinCheck {
		cadence = idleWatchdogMinCheck
	}
	return cadence
}
