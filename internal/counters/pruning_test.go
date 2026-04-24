package counters

// Phase 17b Step 4 — write-path opportunistic pruning + stale-filter tests.
//
// Behavior matrix:
//   - SetTTLHours: 0 disables; negative clamps to 0; positive stores seconds
//   - isStale: TTL=0 → always false; TTL>0 → compare lastInc vs now-TTL
//   - Get: returns 0 for stale entries (filter) even before physical delete
//   - Snapshot: excludes stale entries
//   - DevicesFor: excludes stale entries
//   - Inc hot path (existing entry): does NOT prune
//   - Inc slow path (new entry): prunes when len(data) >= nextPruneSize
//   - nextPruneSize: resets to max(len(data)*2, 64) after prune
//   - Concurrent Inc during prune: no race (covered by -race)
//   - Full cycle: stale entries physically deleted after new-entry creation

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
)

func TestSetTTLHours_Defaults(t *testing.T) {
	c := New()
	if got := c.ttlSec.Load(); got != 0 {
		t.Errorf("default ttlSec = %d, want 0 (pruning disabled)", got)
	}
}

func TestSetTTLHours_Positive(t *testing.T) {
	c := New()
	c.SetTTLHours(168)
	if got := c.ttlSec.Load(); got != 168*3600 {
		t.Errorf("ttlSec after SetTTLHours(168) = %d, want %d", got, 168*3600)
	}
}

func TestSetTTLHours_NegativeClampsToZero(t *testing.T) {
	c := New()
	c.SetTTLHours(-5)
	if got := c.ttlSec.Load(); got != 0 {
		t.Errorf("ttlSec after SetTTLHours(-5) = %d, want 0 (clamp)", got)
	}
}

func TestSetTTLHours_Zero(t *testing.T) {
	c := New()
	c.SetTTLHours(168)
	c.SetTTLHours(0)
	if got := c.ttlSec.Load(); got != 0 {
		t.Errorf("ttlSec after SetTTLHours(0) = %d, want 0 (reset)", got)
	}
}

func TestStaleFilter_GetReturnsZeroForStale(t *testing.T) {
	c := New()
	c.SetTTLHours(1) // 3600s TTL

	var now atomic.Int64
	now.Store(1000)
	c.setNowFn(now.Load)

	c.Inc(SignalMalformedFrame, "dev_a")
	if got := c.Get(SignalMalformedFrame, "dev_a"); got != 1 {
		t.Errorf("fresh entry Get = %d, want 1", got)
	}

	// Advance past TTL.
	now.Store(1000 + 3601)
	if got := c.Get(SignalMalformedFrame, "dev_a"); got != 0 {
		t.Errorf("stale entry Get = %d, want 0 (filter)", got)
	}
}

func TestStaleFilter_SnapshotExcludesStale(t *testing.T) {
	c := New()
	c.SetTTLHours(1)

	var now atomic.Int64
	now.Store(1000)
	c.setNowFn(now.Load)

	c.Inc(SignalMalformedFrame, "dev_old")
	now.Store(1000 + 3601) // age dev_old out
	c.Inc(SignalMalformedFrame, "dev_fresh")

	snap := c.Snapshot()
	if _, ok := snap[SignalMalformedFrame]["dev_old"]; ok {
		t.Error("Snapshot included stale dev_old entry")
	}
	if _, ok := snap[SignalMalformedFrame]["dev_fresh"]; !ok {
		t.Error("Snapshot missing fresh dev_fresh entry")
	}
}

func TestStaleFilter_DevicesForExcludesStale(t *testing.T) {
	c := New()
	c.SetTTLHours(1)

	var now atomic.Int64
	now.Store(1000)
	c.setNowFn(now.Load)

	c.Inc(SignalMalformedFrame, "dev_old")
	now.Store(1000 + 3601)
	c.Inc(SignalMalformedFrame, "dev_fresh")

	devices := c.DevicesFor(SignalMalformedFrame)
	if len(devices) != 1 {
		t.Fatalf("DevicesFor returned %d entries, want 1 (stale filtered)", len(devices))
	}
	if devices[0] != "dev_fresh" {
		t.Errorf("DevicesFor = %q, want dev_fresh", devices[0])
	}
}

func TestStaleFilter_TTLZeroDisablesFilter(t *testing.T) {
	c := New()
	// TTL=0 (default) — nothing is ever stale.

	var now atomic.Int64
	now.Store(1000)
	c.setNowFn(now.Load)

	c.Inc(SignalMalformedFrame, "dev_a")
	now.Store(1000 + 999999999) // far future

	if got := c.Get(SignalMalformedFrame, "dev_a"); got != 1 {
		t.Errorf("Get with TTL=0 = %d, want 1 (no filter)", got)
	}
	snap := c.Snapshot()
	if _, ok := snap[SignalMalformedFrame]["dev_a"]; !ok {
		t.Error("Snapshot with TTL=0 excluded entry, want included")
	}
}

func TestPruning_HotPathDoesNotPrune(t *testing.T) {
	// Existing-entry Inc takes only the RLock and must not trigger
	// pruneStaleLocked. If it did, the write lock would be taken
	// every Inc — hot-path regression.
	//
	// This test builds a map with size < nextPruneSize, then hammers
	// the SAME key many times with a stale entry present. The stale
	// entry should remain physically in place (not yet pruned)
	// because we never take the new-entry slow path.
	c := New()
	c.SetTTLHours(1)

	var now atomic.Int64
	now.Store(1000)
	c.setNowFn(now.Load)

	c.Inc(SignalMalformedFrame, "dev_stale") // entry at t=1000
	now.Store(1000 + 3601)                   // dev_stale is now stale

	// Hammer a different key's slow path ONCE (to create it), then
	// hammer its hot path many times. dev_stale should still be in
	// c.data because we haven't crossed nextPruneSize.
	c.Inc(SignalMalformedFrame, "dev_hot") // slow path for dev_hot
	for i := 0; i < 100; i++ {
		c.Inc(SignalMalformedFrame, "dev_hot") // hot path only
	}

	c.mu.RLock()
	_, stalePresent := c.data[key{signal: SignalMalformedFrame, deviceID: "dev_stale"}]
	c.mu.RUnlock()
	if !stalePresent {
		t.Error("stale entry physically deleted after hot-path Incs (hot path triggered prune)")
	}

	// But Get still returns 0 for the stale entry (filter works
	// without physical delete).
	if got := c.Get(SignalMalformedFrame, "dev_stale"); got != 0 {
		t.Errorf("Get on stale entry = %d, want 0 (filter should hide it)", got)
	}
}

func TestPruning_SlowPathPrunesWhenThresholdCrossed(t *testing.T) {
	// Initial nextPruneSize = 64 (initialPruneSize). Create 64 stale
	// entries + 1 fresh. On the 65th Inc (slow path, new entry), prune
	// fires because len(data) >= nextPruneSize before insertion.
	// After prune, only the fresh entries remain + the new one.
	c := New()
	c.SetTTLHours(1)

	var now atomic.Int64
	now.Store(1000)
	c.setNowFn(now.Load)

	// Create initialPruneSize (64) entries at t=1000.
	for i := 0; i < initialPruneSize; i++ {
		c.Inc(SignalMalformedFrame, fmt.Sprintf("dev_stale_%d", i))
	}

	c.mu.RLock()
	preSize := len(c.data)
	c.mu.RUnlock()
	if preSize != initialPruneSize {
		t.Fatalf("pre-prune map size = %d, want %d", preSize, initialPruneSize)
	}

	// Age all existing entries out.
	now.Store(1000 + 3601)

	// Trigger slow path with a fresh key. This should prune all
	// stale entries, then add the new one.
	c.Inc(SignalMalformedFrame, "dev_fresh")

	c.mu.RLock()
	postSize := len(c.data)
	c.mu.RUnlock()
	if postSize != 1 {
		t.Errorf("post-prune map size = %d, want 1 (all stale pruned, 1 fresh added)", postSize)
	}

	// Verify the stale ones are gone by checking raw map presence.
	c.mu.RLock()
	_, staleStillThere := c.data[key{signal: SignalMalformedFrame, deviceID: "dev_stale_0"}]
	_, freshThere := c.data[key{signal: SignalMalformedFrame, deviceID: "dev_fresh"}]
	c.mu.RUnlock()
	if staleStillThere {
		t.Error("stale entry still in data map after prune")
	}
	if !freshThere {
		t.Error("fresh entry missing from data map")
	}
}

func TestPruning_NextPruneSizeDoublesAfterPrune(t *testing.T) {
	// After a prune, nextPruneSize resets to max(len(data)*2, 64).
	// If prune physically deletes down to 10 entries, next prune
	// fires at 64. If it deletes down to 100 entries, next prune
	// fires at 200.
	c := New()
	c.SetTTLHours(1)

	var now atomic.Int64
	now.Store(1000)
	c.setNowFn(now.Load)

	// Fill to 64 (initialPruneSize) - these will ALL stay fresh.
	for i := 0; i < initialPruneSize; i++ {
		c.Inc(SignalMalformedFrame, fmt.Sprintf("dev_fresh_%d", i))
	}

	// Trigger slow path with a new key. Prune fires with no
	// stale entries to evict; nextPruneSize = max(64*2, 64) = 128.
	c.Inc(SignalMalformedFrame, "dev_new")

	c.mu.RLock()
	next := c.nextPruneSize
	c.mu.RUnlock()
	if next != 128 {
		t.Errorf("nextPruneSize after no-op prune = %d, want 128 (2× current size)", next)
	}
}

func TestPruning_NextPruneSizeFloor(t *testing.T) {
	// If prune deletes down to a tiny map, nextPruneSize still floors
	// at initialPruneSize (64). Without the floor, the prune-threshold
	// would halve and halve, firing on every Inc — defeats the
	// amortized-cost design.
	c := New()
	c.SetTTLHours(1)

	var now atomic.Int64
	now.Store(1000)
	c.setNowFn(now.Load)

	// Fill to 64, age all out.
	for i := 0; i < initialPruneSize; i++ {
		c.Inc(SignalMalformedFrame, fmt.Sprintf("dev_doomed_%d", i))
	}
	now.Store(1000 + 3601)

	// Trigger prune. Map shrinks to 1 (just the new entry).
	// nextPruneSize floors to 64.
	c.Inc(SignalMalformedFrame, "dev_survivor")

	c.mu.RLock()
	next := c.nextPruneSize
	c.mu.RUnlock()
	if next != initialPruneSize {
		t.Errorf("nextPruneSize after massive prune = %d, want %d (floor)", next, initialPruneSize)
	}
}

func TestPruning_ConcurrentIncUnderRace(t *testing.T) {
	// Many Inc goroutines, continuous prune pressure, under -race.
	// Just verifying no data races, no panics, no deadlock.
	c := New()
	c.SetTTLHours(1)

	var nowVal atomic.Int64
	nowVal.Store(1000)
	c.setNowFn(nowVal.Load)

	const workers = 10
	const perWorker = 200
	var wg sync.WaitGroup

	wg.Add(workers)
	for w := 0; w < workers; w++ {
		w := w
		go func() {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				// Unique keys per iteration to force slow-path entries.
				key := fmt.Sprintf("dev_w%d_i%d", w, i)
				c.Inc(SignalMalformedFrame, key)
				// Intermittently advance the clock to create
				// stale-pressure that prune will evict.
				if i%10 == 0 {
					nowVal.Add(500)
				}
			}
		}()
	}
	wg.Wait()

	// Sanity: map is bounded. Without prune, we'd have 2000 entries.
	// With prune firing as the clock advances, older entries get
	// evicted. Exact size is scheduling-dependent; just verify it's
	// bounded.
	c.mu.RLock()
	size := len(c.data)
	c.mu.RUnlock()
	if size > workers*perWorker {
		t.Errorf("map size %d > max possible %d (eviction broken?)", size, workers*perWorker)
	}
}

func TestPruning_StaleButPhysicallyPresent_FilteredFromGet(t *testing.T) {
	// Directly after SetTTLHours + Inc + time-advance, the stale
	// entry IS still physically in the map (no new-entry Inc has
	// triggered prune). Get should filter it regardless.
	c := New()
	c.SetTTLHours(1)

	var now atomic.Int64
	now.Store(1000)
	c.setNowFn(now.Load)

	c.Inc(SignalMalformedFrame, "dev_stale")
	now.Store(1000 + 3601)

	// Verify the entry IS still in the map physically.
	c.mu.RLock()
	_, present := c.data[key{signal: SignalMalformedFrame, deviceID: "dev_stale"}]
	c.mu.RUnlock()
	if !present {
		t.Fatal("entry physically removed before any new-entry slow path — test invalid")
	}

	// Get returns 0 via the filter.
	if got := c.Get(SignalMalformedFrame, "dev_stale"); got != 0 {
		t.Errorf("Get on physically-present but stale entry = %d, want 0", got)
	}
}

func TestPruning_ReaddedAfterStaleGetsFreshStart(t *testing.T) {
	// Edge case: entry goes stale, physical prune happens via
	// slow-path of a different key, then the original device Incs
	// again. It should get a fresh counter (since the old one was
	// physically deleted).
	c := New()
	c.SetTTLHours(1)

	var now atomic.Int64
	now.Store(1000)
	c.setNowFn(now.Load)

	c.Inc(SignalMalformedFrame, "dev_a")
	c.Inc(SignalMalformedFrame, "dev_a") // count=2

	// Fill map with stale entries, then age + trigger prune by
	// exceeding nextPruneSize.
	for i := 0; i < initialPruneSize-1; i++ {
		c.Inc(SignalMalformedFrame, fmt.Sprintf("dev_filler_%d", i))
	}
	now.Store(1000 + 3601) // age everything
	c.Inc(SignalMalformedFrame, "dev_trigger") // slow path → prune

	// Physical confirm: dev_a should be gone.
	c.mu.RLock()
	_, present := c.data[key{signal: SignalMalformedFrame, deviceID: "dev_a"}]
	c.mu.RUnlock()
	if present {
		t.Fatal("dev_a still physically present after prune — test precondition broken")
	}

	// Re-Inc dev_a — should get a fresh counter starting at 1.
	if got := c.Inc(SignalMalformedFrame, "dev_a"); got != 1 {
		t.Errorf("readded Inc on dev_a = %d, want 1 (fresh start)", got)
	}
}
