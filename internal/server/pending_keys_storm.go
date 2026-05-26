package server

import (
	"sync"
	"time"

	"github.com/brushtailmedia/sshkey-chat/internal/config"
)

// pendingNotifyLimiter is a dedicated token bucket for first-attempt pending-key
// admin notifications (unknown-key-storm-hardening gap D). It is deliberately
// NOT the shared auth/conn rateLimiter: that one clamps every bucket's burst to
// a minimum of 5, the wrong shape for a default pending-notify burst of 1. It
// reads rate + burst from current config on every call, so a
// [server.pending_keys] hot-reload takes effect on the next notification without
// resetting any other limiter's state.
type pendingNotifyLimiter struct {
	mu         sync.Mutex
	tokens     float64
	lastRefill time.Time
}

// allow reports whether a pending-key notification may fire now, under the given
// sustained per-minute rate and burst ceiling. Token-bucket semantics: starts
// full at burst, refills at perMinute/60 tokens/sec, capped at burst. A token is
// consumed only when the call returns true. Non-positive inputs deny (defensive;
// callers normalize via pendingKeysCfg so this never happens in practice).
func (l *pendingNotifyLimiter) allow(perMinute, burst int) bool {
	if perMinute <= 0 || burst <= 0 {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	burstF := float64(burst)
	if l.lastRefill.IsZero() {
		l.tokens = burstF // first call starts full
	} else {
		l.tokens += now.Sub(l.lastRefill).Seconds() * float64(perMinute) / 60.0
		if l.tokens > burstF {
			l.tokens = burstF
		}
	}
	l.lastRefill = now

	if l.tokens >= 1 {
		l.tokens--
		return true
	}
	return false
}

// pendingKeysCfg returns the current [server.pending_keys] config under the
// config read lock, normalizing any non-positive value back to the documented
// default. Real servers always carry validated positive values (LoadServerConfig
// requires them), so the normalization only affects hand-built test configs —
// but it keeps prune/notify safe regardless of construction path (notably, it
// prevents a zero max_age_hours from pruning the entire table, or a zero
// notify budget from silently suppressing all admin notifications).
func (s *Server) pendingKeysCfg() config.PendingKeysSection {
	s.cfg.RLock()
	pk := s.cfg.Server.Server.PendingKeys
	s.cfg.RUnlock()

	def := config.DefaultServerConfig().Server.PendingKeys
	if pk.MaxAgeHours <= 0 {
		pk.MaxAgeHours = def.MaxAgeHours
	}
	if pk.MaxRows <= 0 {
		pk.MaxRows = def.MaxRows
	}
	if pk.PruneIntervalSeconds <= 0 {
		pk.PruneIntervalSeconds = def.PruneIntervalSeconds
	}
	if pk.NotifyPerMinute <= 0 {
		pk.NotifyPerMinute = def.NotifyPerMinute
	}
	if pk.NotifyBurst < 1 || pk.NotifyBurst > pk.NotifyPerMinute {
		pk.NotifyBurst = def.NotifyBurst
	}
	return pk
}

// allowPendingNotify rate-limits a first-attempt pending-key admin notification
// through the dedicated limiter, using the current (hot-reloadable) config. Only
// call this on a first attempt — it consumes a token when it returns true.
func (s *Server) allowPendingNotify() bool {
	pk := s.pendingKeysCfg()
	return s.pendingNotify.allow(pk.NotifyPerMinute, pk.NotifyBurst)
}

// enforcePendingKeyCap applies the configured hard storage ceiling. It is kept
// separate from the TTL prune so logPendingKey can enforce the cap immediately
// after recording a fresh contact without running a full age-based prune on
// every unknown-key attempt.
func (s *Server) enforcePendingKeyCap(maxRows int) {
	if s.store == nil {
		return
	}
	if n, err := s.store.EnforcePendingKeyCap(maxRows); err != nil {
		s.logger.Error("pending-key cap eviction failed", "error", err)
	} else if n > 0 {
		s.logger.Info("evicted pending keys over cap", "rows", n, "max_rows", maxRows)
	}
}

// prunePendingKeys runs the TTL prune (gap B) + hard-cap eviction (gap A) once,
// unconditionally. This is maintenance, not a safety gate: errors are logged and
// swallowed (matching pruneOldQuotaRows) so a prune failure never aborts startup
// or suppresses recording the current unknown key. Used by startup and by the
// interval-gated TTL maintenance path; logPendingKey also enforces the cap
// immediately after each record.
func (s *Server) prunePendingKeys() {
	if s.store == nil {
		return
	}
	pk := s.pendingKeysCfg()
	if n, err := s.store.PruneOldPendingKeys(int64(pk.MaxAgeHours) * 3600); err != nil {
		s.logger.Error("pending-key TTL prune failed", "error", err)
	} else if n > 0 {
		s.logger.Info("pruned old pending keys (TTL)", "rows", n, "max_age_hours", pk.MaxAgeHours)
	}
	s.enforcePendingKeyCap(pk.MaxRows)
}

func (s *Server) markPendingPruneRan() {
	s.pendingPruneMu.Lock()
	s.lastPendingPrune = time.Now()
	s.pendingPruneMu.Unlock()
}

// maybePrunePendingKeys runs the full TTL maintenance pass at most once per
// prune_interval_seconds, single-flighting concurrent SSH auth callbacks: the
// last-prune timestamp is claimed under the mutex BEFORE the (lock-free) DB work
// runs, so a storm of concurrent unknown keys triggers at most one age-based
// prune per interval. The hard row cap is enforced separately on every record.
func (s *Server) maybePrunePendingKeys() {
	interval := time.Duration(s.pendingKeysCfg().PruneIntervalSeconds) * time.Second

	s.pendingPruneMu.Lock()
	if !s.lastPendingPrune.IsZero() && time.Since(s.lastPendingPrune) < interval {
		s.pendingPruneMu.Unlock()
		return
	}
	s.lastPendingPrune = time.Now() // claim the slot before releasing
	s.pendingPruneMu.Unlock()

	s.prunePendingKeys()
}
