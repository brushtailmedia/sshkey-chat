// Package counters tracks per-device signal counts for observability and for
// Phase 17b's auto-revoke policy. Signals come in three kinds, distinguished
// by auto-revoke eligibility:
//
// Misbehavior signals — rejections with zero legitimate baseline. Well-behaved
// clients produce none of these. Any nonzero rate on a single device indicates
// a broken or hostile client. These are the valid inputs to Phase 17b's
// [server.autoRevoke] config, listed in the AutoRevokeSignals slice.
//
// Load signals — rejections with a legitimate baseline. Bursty-but-well-behaved
// clients produce these during normal use (app-open catchup, deep scroll-back,
// attachment-heavy chat opening). The rate limiter IS the response — it rejects
// the excess request and returns retry_after_ms. Counted for observability but
// NEVER valid auto-revoke inputs.
//
// Observational signals — server-internal events of operational interest; NOT
// client-visible rejections. Slow or disconnected clients can produce them
// through no misbehavior of their own. Counted for visibility only; NEVER
// valid auto-revoke inputs.
//
// Entries carry a lastInc timestamp (unix seconds) updated on every Inc call.
// The timestamp enables Phase 17b's write-path opportunistic pruning without
// requiring a Step 2 → 17b refactor of the entry shape. Phase 17b adds the
// stale-filter logic in Get/Snapshot and the pruneStaleLocked helper; Step 2
// ships the timestamp substrate only.
package counters

import (
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

// Misbehavior signals — valid auto-revoke inputs.
const (
	SignalMalformedFrame       = "malformed_frame"
	SignalOversizedBody        = "oversized_body"
	SignalUnknownVerb          = "unknown_verb"
	SignalInvalidNanoID        = "invalid_nanoid"
	SignalWrappedKeysOverCap   = "wrapped_keys_over_cap"
	SignalFileIDsOverCap       = "file_ids_over_cap"
	SignalInvalidContentHash   = "invalid_content_hash"
	SignalOversizedUploadFrame = "oversized_upload_frame"

	// SignalNonMemberContext fires when a client sends a well-formed
	// frame referencing a context (room / group / dm) they are not a
	// member of. Byte-identical privacy response on the wire
	// (Phase 14 invariant); this signal distinguishes the cases
	// server-side so Phase 17b threshold analysis can discriminate
	// one-shot legit races (membership-change, stale reconnect state)
	// from sustained probing or buggy-client loops. Added Phase 17
	// Step 4c follow-up.
	SignalNonMemberContext = "non_member_context"

	// SignalDownloadNotFound fires on handleDownload rejection for
	// every path that produces a byte-identical `not_found` wire
	// response to the client:
	//   (1) ACL-deny — forward-secrecy gate or post-leave cached message
	//   (2) file missing on disk — cascade-cleanup race, admin purge
	//   (3) server-side I/O error — os.Open failure after os.Stat
	//       succeeded (rare race or degraded disk)
	//
	// Merged to match Phase 17c Category D (privacy-identical rejection
	// = one signal). Server logs preserve the per-path reason via
	// rejectAndLog's logReason field; forensics remain intact.
	//
	// Circuit-breaker behavior on server disk faults: by including path
	// (3) here as an AutoRevoke-eligible signal, a degrading disk that
	// affects every active user cascades to mass auto-revoke, stopping
	// further writes against compromised storage. Admin recovery is
	// structural (OS-SSH + sshkey-ctl approve-device); Phase 17b's
	// operator-manual cascade-disable (enabled = false + restart) is
	// the documented response if the breaker over-fires.
	SignalDownloadNotFound = "download_not_found"

	// SignalDownloadNoChannel fires when a client sends a `download`
	// verb on Channel 1 without having opened the download channel
	// (Channel 2) during session setup within the 500ms grace period.
	// A buggy client hits this on every download; a legit client
	// should never hit it.
	SignalDownloadNoChannel = "download_no_channel"
)

// Load signals — counted but NEVER auto-revoke inputs.
const (
	SignalRateLimited = "rate_limited"
)

// Observational signals — counted but NEVER auto-revoke inputs.
const (
	SignalBroadcastDropped = "broadcast_dropped"
)

// AutoRevokeSignals enumerates the signal names that are valid inputs to the
// Phase 17b [server.autoRevoke] config. The config parser rejects threshold
// entries for signals not listed here — load signals (rate_limited) and
// observational signals (broadcast_dropped) are deliberately excluded because
// they have nonzero legitimate baselines.
//
// Adding a new misbehavior signal means: add a Signal* constant, add to this
// slice, document in the package doc-comment block above. Phase 17b's config
// loader automatically accepts the new signal once it's in this slice.
var AutoRevokeSignals = []string{
	SignalMalformedFrame,
	SignalOversizedBody,
	SignalUnknownVerb,
	SignalInvalidNanoID,
	SignalWrappedKeysOverCap,
	SignalFileIDsOverCap,
	SignalInvalidContentHash,
	SignalOversizedUploadFrame,
	SignalNonMemberContext,
	SignalDownloadNotFound,
	SignalDownloadNoChannel,
}

// key identifies a single counter — (signal, deviceID). Unexported so callers
// cannot construct keys outside Inc/Get.
type key struct {
	signal   string
	deviceID string
}

// entry holds a counter value plus the unix-seconds timestamp of the most
// recent Inc. Both fields use atomic access so concurrent Inc/Get on an
// existing entry does not need the map's RWMutex.
type entry struct {
	value   atomic.Int64
	lastInc atomic.Int64 // unix seconds; updated on every Inc
}

// Counters tracks per-(signal, device) counts. Zero-value is not usable;
// callers must use New(). Safe for concurrent use from any number of
// goroutines.
type Counters struct {
	mu   sync.RWMutex
	data map[key]*entry
}

// New returns an initialized Counters.
func New() *Counters {
	return &Counters{
		data: make(map[key]*entry),
	}
}

// Inc increments the counter for (signal, deviceID) and returns the new
// count. Thread-safe. Updates the entry's lastInc timestamp on every call
// (Phase 17b consumes this for write-path opportunistic pruning).
//
// deviceID == "" is accepted but indicates a caller bug (in the current
// architecture every rejection site runs post-auth, so the device should
// always be known). A slog.Warn fires on empty deviceID to surface the bug;
// the increment still proceeds so no data is lost.
func (c *Counters) Inc(signal, deviceID string) int64 {
	if deviceID == "" {
		slog.Warn("counters: Inc called with empty deviceID", "signal", signal)
	}
	now := time.Now().Unix()
	k := key{signal: signal, deviceID: deviceID}

	// Fast path: entry exists.
	c.mu.RLock()
	e, ok := c.data[k]
	c.mu.RUnlock()
	if ok {
		e.lastInc.Store(now)
		return e.value.Add(1)
	}

	// Slow path: create a new entry. Take write lock.
	c.mu.Lock()
	defer c.mu.Unlock()

	// Re-check under write lock — another goroutine may have created it.
	if e, ok := c.data[k]; ok {
		e.lastInc.Store(now)
		return e.value.Add(1)
	}

	e = &entry{}
	e.lastInc.Store(now)
	c.data[k] = e
	return e.value.Add(1)
}

// Get returns the current count for (signal, deviceID). Returns 0 if the key
// is not present. Thread-safe.
func (c *Counters) Get(signal, deviceID string) int64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	e, ok := c.data[key{signal: signal, deviceID: deviceID}]
	if !ok {
		return 0
	}
	return e.value.Load()
}

// Snapshot returns a deep copy of the current counter state, keyed by
// signal → deviceID → count. The returned map is a fresh copy — mutating
// it does not affect internal state, and subsequent Snapshot calls return
// new maps.
func (c *Counters) Snapshot() map[string]map[string]int64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make(map[string]map[string]int64, len(c.data))
	for k, e := range c.data {
		bySignal, ok := out[k.signal]
		if !ok {
			bySignal = make(map[string]int64)
			out[k.signal] = bySignal
		}
		bySignal[k.deviceID] = e.value.Load()
	}
	return out
}
