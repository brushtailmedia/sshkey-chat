package config

// Phase 17b Step 1 — [server.auto_revoke] config section.
//
// Schema (see refactor_plan.md §Phase 17b):
//
//   [server.auto_revoke]
//   enabled = true
//   prune_after_hours = 168
//
//   [server.auto_revoke.thresholds]
//   malformed_frame = "3:60"
//   ...
//
// Threshold keys are snake_case names matching counters.Signal*
// constant string values byte-for-byte. This means adding a new
// AutoRevokeSignals entry in the counters package automatically makes
// that signal valid in server.toml — zero config-loader code change.
//
// ParseAndValidate is the enforcement chokepoint. It is called from
// ServerConfig.Validate() (see config.go), which LoadServerConfig
// invokes right after TOML decode. Invalid config fails startup with
// category-tagged error messages — load signals and observational
// signals are rejected with clear "cannot auto-revoke on <category>
// signal" text so operators know why their key was refused.

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/brushtailmedia/sshkey-chat/internal/counters"
)

// AutoRevokeSection configures Phase 17b auto-revoke on sustained
// misbehavior. Nested under [server] as [server.auto_revoke].
//
// Thresholds is a raw string map; ParseAndValidate converts it to the
// structured []ThresholdRule consumed by the auto-revoke goroutine.
// Keeping the raw form in the config struct lets TOML round-trip
// cleanly and lets validation errors reference the exact operator-typed
// string.
type AutoRevokeSection struct {
	// Enabled gates whether threshold crossings enqueue device
	// revocations. When false, the auto-revoke goroutine still runs
	// and still evaluates sliding windows — it just emits
	// slog.Info("auto_revoke_would_fire", ...) instead of enqueuing
	// (observer mode for operators diagnosing false positives).
	Enabled bool `toml:"enabled"`

	// PruneAfterHours is the TTL for stale counter entries. 0
	// disables TTL-based pruning (entries persist until restart).
	// Must strictly exceed the largest configured window (converted
	// to hours, rounded up) when nonzero — a TTL shorter than the
	// widest sliding window would evict data the auto-revoke check
	// still needs.
	PruneAfterHours int `toml:"prune_after_hours"`

	// Thresholds maps signal name → "count:window_seconds" string.
	// Keys must be in counters.AutoRevokeSignals (misbehavior
	// signals only — load and observational signals are rejected at
	// load time with a category-tagged error).
	Thresholds map[string]string `toml:"thresholds"`
}

// ThresholdRule is the validated, structured form of a single
// threshold entry. The auto-revoke goroutine iterates []ThresholdRule,
// calling counters.Check(Signal, deviceID, Count, WindowSec).
type ThresholdRule struct {
	Signal    string // snake_case signal name, guaranteed in counters.AutoRevokeSignals
	Count     int    // events required to cross the threshold (> 0)
	WindowSec int    // sliding-window size in seconds (> 0)
}

// ParseAndValidate walks the raw Thresholds map, enforces the
// misbehavior-signal accept list + threshold format, and returns the
// parsed rules alongside any non-fatal startup warnings. Errors are
// hard failures — they abort server startup.
//
// Category-tagged errors: rejections for load signals (rate_limited)
// and observational signals (broadcast_dropped) identify the category
// explicitly so the operator understands WHY their key was refused,
// not just that it was. Typos fall into the generic "unknown signal"
// bucket with the list of accepted names.
func (a AutoRevokeSection) ParseAndValidate() (rules []ThresholdRule, warnings []string, err error) {
	// Build accept set from the canonical AutoRevokeSignals slice —
	// single source of truth. Adding a signal there makes it
	// config-accepted here with no code change.
	accept := make(map[string]struct{}, len(counters.AutoRevokeSignals))
	for _, s := range counters.AutoRevokeSignals {
		accept[s] = struct{}{}
	}

	// Category sets for error quality. If the key is a known-but-
	// wrong-category signal, the error says so. If it's neither
	// in AutoRevokeSignals nor in these sets, it's an unknown key
	// (typo).
	loadSet := map[string]struct{}{
		counters.SignalRateLimited: {},
	}
	obsSet := map[string]struct{}{
		counters.SignalBroadcastDropped: {},
	}

	for key, raw := range a.Thresholds {
		if _, ok := accept[key]; !ok {
			switch {
			case contains(loadSet, key):
				return nil, nil, fmt.Errorf(
					"[server.auto_revoke.thresholds] %q: %q is a load signal (nonzero legitimate baseline) — load signals cannot be auto-revoke inputs; remove this key or choose a misbehavior signal",
					key, key)
			case contains(obsSet, key):
				return nil, nil, fmt.Errorf(
					"[server.auto_revoke.thresholds] %q: %q is an observational signal (server-internal, not client-visible) — observational signals cannot be auto-revoke inputs; remove this key or choose a misbehavior signal",
					key, key)
			default:
				return nil, nil, fmt.Errorf(
					"[server.auto_revoke.thresholds] %q: unknown signal; valid misbehavior signals are %v",
					key, counters.AutoRevokeSignals)
			}
		}
		count, window, perr := parseThresholdSpec(raw)
		if perr != nil {
			return nil, nil, fmt.Errorf("[server.auto_revoke.thresholds] %q = %q: %w", key, raw, perr)
		}
		rules = append(rules, ThresholdRule{Signal: key, Count: count, WindowSec: window})
	}

	if a.PruneAfterHours < 0 {
		return nil, nil, fmt.Errorf(
			"[server.auto_revoke].prune_after_hours = %d: must be >= 0", a.PruneAfterHours)
	}
	if a.PruneAfterHours > 0 && len(rules) > 0 {
		var maxWindowSec int
		for _, r := range rules {
			if r.WindowSec > maxWindowSec {
				maxWindowSec = r.WindowSec
			}
		}
		// Ceil divide — a 5400s window needs at least 2h of TTL,
		// not 1h, so the window never sees evicted data.
		maxWindowHours := (maxWindowSec + 3599) / 3600
		if a.PruneAfterHours <= maxWindowHours {
			return nil, nil, fmt.Errorf(
				"[server.auto_revoke].prune_after_hours = %d: must strictly exceed the largest configured window (%ds ≈ %dh) so sliding-window evaluation never loses data to TTL eviction",
				a.PruneAfterHours, maxWindowSec, maxWindowHours)
		}
	}

	// Non-fatal: enabled = true with zero thresholds configured.
	// The breaker is on but has no triggers — likely a
	// misconfiguration rather than a deliberate disable (operators
	// disable via enabled = false, which is the supported form).
	if a.Enabled && len(rules) == 0 {
		warnings = append(warnings,
			"[server.auto_revoke] enabled = true but no thresholds configured — auto-revoke breaker will never fire; to disable explicitly, set enabled = false")
	}

	return rules, warnings, nil
}

// parseThresholdSpec parses "count:window_seconds" into (count, window).
// Both must be positive integers; anything else is a hard error.
func parseThresholdSpec(s string) (count, window int, err error) {
	parts := strings.Split(s, ":")
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf(`malformed threshold: want "count:window_seconds"`)
	}
	count, err = strconv.Atoi(strings.TrimSpace(parts[0]))
	if err != nil {
		return 0, 0, fmt.Errorf("malformed count: %w", err)
	}
	if count <= 0 {
		return 0, 0, fmt.Errorf("count must be positive, got %d", count)
	}
	window, err = strconv.Atoi(strings.TrimSpace(parts[1]))
	if err != nil {
		return 0, 0, fmt.Errorf("malformed window_seconds: %w", err)
	}
	if window <= 0 {
		return 0, 0, fmt.Errorf("window_seconds must be positive, got %d", window)
	}
	return count, window, nil
}

// contains is a tiny helper — Go 1.26 maps.Contains exists but we
// avoid the dependency here to keep the diff minimal.
func contains(m map[string]struct{}, k string) bool {
	_, ok := m[k]
	return ok
}
