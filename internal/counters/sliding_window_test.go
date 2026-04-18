package counters

// Phase 17b Step 2 — sliding-window Check tests.
//
// Deterministic: tests inject a mock clock via setNowFn so we can
// advance "time" without sleeping. Real-time tests (the existing
// TestLastInc_UpdatedOnEveryInc) still use time.Sleep in counters_test.go.
//
// Coverage matrix:
//   - Check on absent entry → false
//   - Check on sub-threshold count → false
//   - Check at exactly threshold → true
//   - Check well over threshold → true
//   - Events outside window are aged out → correct count
//   - Ring-cap behavior: more events than cap, within window, only the
//     last `cap` events count (oldest overwritten circularly)
//   - Circular overwrite correctness (many rounds through the ring)
//   - Defensive: threshold <= 0 → false
//   - Defensive: windowSec <= 0 → false
//   - Keys are scoped — different (signal, device) pairs independent
//   - Concurrent Inc + Check under -race produces safe results

import (
	"sync"
	"sync/atomic"
	"testing"
)

// mockClock returns (now func, advance func). `now` yields a stable
// unix-second value; `advance` bumps it forward. Both are safe for
// concurrent use (atomic.Int64).
func mockClock(start int64) (now func() int64, advance func(seconds int64)) {
	var v atomic.Int64
	v.Store(start)
	return v.Load, func(s int64) { v.Add(s) }
}

func TestCheck_AbsentEntry(t *testing.T) {
	c := New()
	if c.Check(SignalMalformedFrame, "dev_never", 1, 60) {
		t.Error("Check on absent entry = true, want false")
	}
}

func TestCheck_SubThreshold(t *testing.T) {
	c := New()
	now, _ := mockClock(1000)
	c.setNowFn(now)

	c.Inc(SignalMalformedFrame, "dev_a")
	c.Inc(SignalMalformedFrame, "dev_a")

	if c.Check(SignalMalformedFrame, "dev_a", 3, 60) {
		t.Error("Check(threshold=3) with 2 events = true, want false")
	}
}

func TestCheck_ExactThreshold(t *testing.T) {
	c := New()
	now, _ := mockClock(1000)
	c.setNowFn(now)

	for i := 0; i < 3; i++ {
		c.Inc(SignalMalformedFrame, "dev_a")
	}

	if !c.Check(SignalMalformedFrame, "dev_a", 3, 60) {
		t.Error("Check(threshold=3) with exactly 3 events = false, want true")
	}
}

func TestCheck_OverThreshold(t *testing.T) {
	c := New()
	now, _ := mockClock(1000)
	c.setNowFn(now)

	for i := 0; i < 10; i++ {
		c.Inc(SignalMalformedFrame, "dev_a")
	}

	if !c.Check(SignalMalformedFrame, "dev_a", 3, 60) {
		t.Error("Check(threshold=3) with 10 events = false, want true")
	}
}

func TestCheck_OldEventsAgedOut(t *testing.T) {
	c := New()
	now, advance := mockClock(1000)
	c.setNowFn(now)

	// 3 events at t=1000.
	for i := 0; i < 3; i++ {
		c.Inc(SignalMalformedFrame, "dev_a")
	}

	// Advance past the window (60s window, advance 61s).
	advance(61)

	if c.Check(SignalMalformedFrame, "dev_a", 3, 60) {
		t.Error("Check after events aged out of window = true, want false")
	}

	// Add fresh events and re-check — sliding window should now count
	// only the new ones.
	for i := 0; i < 3; i++ {
		c.Inc(SignalMalformedFrame, "dev_a")
	}
	if !c.Check(SignalMalformedFrame, "dev_a", 3, 60) {
		t.Error("Check after 3 fresh events (post-aging) = false, want true")
	}
}

func TestCheck_PartialAging(t *testing.T) {
	// 2 events at t=1000, then advance 30s, then 1 event at t=1030.
	// Check with window=60 at t=1030 sees all 3. Advance to t=1061;
	// the first 2 are now outside the window (1061 - 60 = 1001 > 1000),
	// the last is still inside — count = 1, sub-threshold.
	c := New()
	now, advance := mockClock(1000)
	c.setNowFn(now)

	c.Inc(SignalMalformedFrame, "dev_a")
	c.Inc(SignalMalformedFrame, "dev_a")
	advance(30)
	c.Inc(SignalMalformedFrame, "dev_a")

	if !c.Check(SignalMalformedFrame, "dev_a", 3, 60) {
		t.Error("all 3 events in window at t=1030, Check = false, want true")
	}

	advance(31) // t=1061
	if c.Check(SignalMalformedFrame, "dev_a", 3, 60) {
		t.Error("2 events aged out at t=1061, Check(threshold=3) = true, want false")
	}
	if !c.Check(SignalMalformedFrame, "dev_a", 1, 60) {
		t.Error("1 event still in window at t=1061, Check(threshold=1) = false, want true")
	}
}

func TestCheck_RingCapBounds(t *testing.T) {
	// With a small ring cap, events beyond cap overflow circularly.
	// Configuring cap=4 and firing 10 events in the same second means
	// the ring holds only the last 4 — Check(threshold=5) cannot
	// return true even though 10 Incs fired. This is the documented
	// boundary: operators configuring thresholds above ring cap must
	// enlarge the ring via NewWithRingCap.
	c := NewWithRingCap(4)
	now, _ := mockClock(1000)
	c.setNowFn(now)

	for i := 0; i < 10; i++ {
		c.Inc(SignalMalformedFrame, "dev_a")
	}

	if got := c.Get(SignalMalformedFrame, "dev_a"); got != 10 {
		t.Errorf("raw count after 10 Incs = %d, want 10 (ring cap doesn't affect raw Get)", got)
	}

	// threshold=4 fits within ring cap, should fire.
	if !c.Check(SignalMalformedFrame, "dev_a", 4, 60) {
		t.Error("Check(threshold=4, ringCap=4) with 10 events = false, want true")
	}
	// threshold=5 exceeds ring cap — Check can only count 4 ring entries.
	if c.Check(SignalMalformedFrame, "dev_a", 5, 60) {
		t.Error("Check(threshold=5, ringCap=4) = true, want false (ring bound)")
	}
}

func TestCheck_RingCircularCorrectness(t *testing.T) {
	// Fire many rounds through the ring to verify the circular
	// overwrite doesn't corrupt state. With cap=4, fire 20 events
	// across 20 distinct seconds (all within a 60s window) — the
	// ring ends up holding seconds {17, 18, 19, 20} and Check with
	// window=60 should see exactly 4.
	c := NewWithRingCap(4)
	v := int64(1000)
	c.setNowFn(func() int64 { return v })

	for i := 0; i < 20; i++ {
		c.Inc(SignalMalformedFrame, "dev_a")
		v++ // advance 1s per event
	}
	// Now at t=1020. Window=60 reaches back to t=960; all ring
	// entries (the last 4 seconds = t=1016-1019) are within window.
	if !c.Check(SignalMalformedFrame, "dev_a", 4, 60) {
		t.Error("ring cap=4 after 20 Incs, all within window, Check(4) = false, want true")
	}
	if c.Check(SignalMalformedFrame, "dev_a", 5, 60) {
		t.Error("ring cap=4 cannot fire threshold=5 regardless of raw count")
	}
}

func TestCheck_DefensiveZeroThreshold(t *testing.T) {
	c := New()
	now, _ := mockClock(1000)
	c.setNowFn(now)

	for i := 0; i < 10; i++ {
		c.Inc(SignalMalformedFrame, "dev_a")
	}

	if c.Check(SignalMalformedFrame, "dev_a", 0, 60) {
		t.Error("Check(threshold=0) = true, want false (defensive)")
	}
	if c.Check(SignalMalformedFrame, "dev_a", -5, 60) {
		t.Error("Check(threshold=-5) = true, want false (defensive)")
	}
}

func TestCheck_DefensiveZeroWindow(t *testing.T) {
	c := New()
	now, _ := mockClock(1000)
	c.setNowFn(now)

	for i := 0; i < 10; i++ {
		c.Inc(SignalMalformedFrame, "dev_a")
	}

	if c.Check(SignalMalformedFrame, "dev_a", 1, 0) {
		t.Error("Check(windowSec=0) = true, want false (defensive)")
	}
	if c.Check(SignalMalformedFrame, "dev_a", 1, -60) {
		t.Error("Check(windowSec=-60) = true, want false (defensive)")
	}
}

func TestCheck_KeysAreScoped(t *testing.T) {
	c := New()
	now, _ := mockClock(1000)
	c.setNowFn(now)

	// 5 events for (malformed_frame, dev_a)
	for i := 0; i < 5; i++ {
		c.Inc(SignalMalformedFrame, "dev_a")
	}
	// 0 events for (malformed_frame, dev_b) and (invalid_nanoid, dev_a).

	if !c.Check(SignalMalformedFrame, "dev_a", 3, 60) {
		t.Error("Check(malformed_frame, dev_a, 3) = false, want true")
	}
	if c.Check(SignalMalformedFrame, "dev_b", 1, 60) {
		t.Error("Check(malformed_frame, dev_b) = true, want false (no events)")
	}
	if c.Check(SignalInvalidNanoID, "dev_a", 1, 60) {
		t.Error("Check(invalid_nanoid, dev_a) = true, want false (different signal)")
	}
}

func TestCheck_BoundaryEquality(t *testing.T) {
	// An event at exactly `now - windowSec` is inside the window
	// (the check is `ts >= since`, inclusive). An event at
	// `now - windowSec - 1` is outside.
	c := New()
	v := int64(1000)
	c.setNowFn(func() int64 { return v })

	c.Inc(SignalMalformedFrame, "dev_a") // ts=1000
	v = 1060                              // now at t=1060
	// window=60 → since = 1060 - 60 = 1000. Event at 1000 is inside.
	if !c.Check(SignalMalformedFrame, "dev_a", 1, 60) {
		t.Error("event at exact window boundary (ts == now-windowSec) = false, want true (inclusive)")
	}
	v = 1061 // now at t=1061
	// window=60 → since = 1001. Event at 1000 is outside.
	if c.Check(SignalMalformedFrame, "dev_a", 1, 60) {
		t.Error("event 1s past window = true, want false")
	}
}

func TestCheck_ConcurrentIncCheck(t *testing.T) {
	// Under -race: concurrent Inc from N goroutines and Check from M
	// goroutines must not race, must not deadlock, and Check must
	// eventually return true as events accumulate within the window.
	c := New()
	const incWorkers = 10
	const incPerWorker = 200
	const checkers = 4
	const checksPerCher = 100

	var wg sync.WaitGroup

	// Inc workers.
	wg.Add(incWorkers)
	for i := 0; i < incWorkers; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < incPerWorker; j++ {
				c.Inc(SignalMalformedFrame, "dev_shared")
			}
		}()
	}

	// Check workers (run concurrently with Inc). Just verifying no
	// race and no panic — the return value may be true or false
	// depending on scheduling.
	wg.Add(checkers)
	for i := 0; i < checkers; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < checksPerCher; j++ {
				_ = c.Check(SignalMalformedFrame, "dev_shared", 1, 3600)
			}
		}()
	}

	wg.Wait()

	// Post-run: final state should show all Incs counted, and Check
	// with a generous window + low threshold should fire.
	wantTotal := int64(incWorkers * incPerWorker)
	if got := c.Get(SignalMalformedFrame, "dev_shared"); got != wantTotal {
		t.Errorf("raw count after concurrent Inc = %d, want %d", got, wantTotal)
	}
	if !c.Check(SignalMalformedFrame, "dev_shared", 1, 3600) {
		t.Error("Check after concurrent Inc flood = false, want true")
	}
}

func TestCheck_RingCapCountsCorrectEventsPostAging(t *testing.T) {
	// Ring cap = 4, fire 4 events at t=1000, then 2 more at t=1050.
	// Ring holds [1000, 1000, 1000, 1000] → overwrite → [1050, 1050, 1000, 1000]
	// Wait, no — circular overwrite starts at ringPos=0 after fill.
	// Fill to 4 at t=1000 → ring=[1000,1000,1000,1000], ringPos=0.
	// Append at 1050 → ring[0]=1050, ringPos=1 → [1050,1000,1000,1000]
	// Append at 1050 → ring[1]=1050, ringPos=2 → [1050,1050,1000,1000]
	//
	// Advance to t=1065 (window=60 → since=1005). Events at 1000 are
	// outside; events at 1050 are inside. Expected count in window = 2.
	c := NewWithRingCap(4)
	v := int64(1000)
	c.setNowFn(func() int64 { return v })

	for i := 0; i < 4; i++ {
		c.Inc(SignalMalformedFrame, "dev_a")
	}
	v = 1050
	c.Inc(SignalMalformedFrame, "dev_a")
	c.Inc(SignalMalformedFrame, "dev_a")

	v = 1065
	if !c.Check(SignalMalformedFrame, "dev_a", 2, 60) {
		t.Error("2 fresh events within window, Check(2) = false, want true")
	}
	if c.Check(SignalMalformedFrame, "dev_a", 3, 60) {
		t.Error("only 2 fresh events within window, Check(3) = true, want false")
	}
}
