package counters

import (
	"bytes"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestInc_HappyPath(t *testing.T) {
	c := New()
	got := c.Inc(SignalMalformedFrame, "dev_abc")
	if got != 1 {
		t.Errorf("first Inc = %d, want 1", got)
	}
	got = c.Inc(SignalMalformedFrame, "dev_abc")
	if got != 2 {
		t.Errorf("second Inc = %d, want 2", got)
	}
	if g := c.Get(SignalMalformedFrame, "dev_abc"); g != 2 {
		t.Errorf("Get after two Incs = %d, want 2", g)
	}
}

func TestGet_AbsentKey(t *testing.T) {
	c := New()
	if g := c.Get(SignalMalformedFrame, "dev_never_seen"); g != 0 {
		t.Errorf("Get on absent key = %d, want 0", g)
	}
}

func TestDistinctKeys_SameSignalDifferentDevices(t *testing.T) {
	c := New()
	c.Inc(SignalMalformedFrame, "dev_a")
	c.Inc(SignalMalformedFrame, "dev_a")
	c.Inc(SignalMalformedFrame, "dev_b")

	if g := c.Get(SignalMalformedFrame, "dev_a"); g != 2 {
		t.Errorf("Get(dev_a) = %d, want 2", g)
	}
	if g := c.Get(SignalMalformedFrame, "dev_b"); g != 1 {
		t.Errorf("Get(dev_b) = %d, want 1", g)
	}
}

func TestDistinctKeys_SameDeviceDifferentSignals(t *testing.T) {
	c := New()
	c.Inc(SignalMalformedFrame, "dev_a")
	c.Inc(SignalInvalidNanoID, "dev_a")
	c.Inc(SignalInvalidNanoID, "dev_a")

	if g := c.Get(SignalMalformedFrame, "dev_a"); g != 1 {
		t.Errorf("Get(malformed_frame) = %d, want 1", g)
	}
	if g := c.Get(SignalInvalidNanoID, "dev_a"); g != 2 {
		t.Errorf("Get(invalid_nanoid) = %d, want 2", g)
	}
}

func TestConcurrentInc_SameKey(t *testing.T) {
	c := New()
	const N = 20   // goroutines
	const M = 500  // iterations each

	var wg sync.WaitGroup
	wg.Add(N)
	for i := 0; i < N; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < M; j++ {
				c.Inc(SignalMalformedFrame, "dev_shared")
			}
		}()
	}
	wg.Wait()

	want := int64(N * M)
	if g := c.Get(SignalMalformedFrame, "dev_shared"); g != want {
		t.Errorf("concurrent Inc: got %d, want %d", g, want)
	}
}

func TestConcurrentInc_DistinctKeys(t *testing.T) {
	c := New()
	const N = 20
	const M = 100

	var wg sync.WaitGroup
	wg.Add(N)
	for i := 0; i < N; i++ {
		i := i
		go func() {
			defer wg.Done()
			device := fmt.Sprintf("dev_%d", i)
			for j := 0; j < M; j++ {
				c.Inc(SignalMalformedFrame, device)
			}
		}()
	}
	wg.Wait()

	for i := 0; i < N; i++ {
		device := fmt.Sprintf("dev_%d", i)
		if g := c.Get(SignalMalformedFrame, device); g != int64(M) {
			t.Errorf("device %s: got %d, want %d", device, g, M)
		}
	}
}

func TestSnapshot_DeepCopy(t *testing.T) {
	c := New()
	c.Inc(SignalMalformedFrame, "dev_a")
	c.Inc(SignalInvalidNanoID, "dev_b")
	c.Inc(SignalInvalidNanoID, "dev_b")

	snap := c.Snapshot()

	// Mutate the returned map.
	snap[SignalMalformedFrame]["dev_a"] = 999
	snap["fresh_signal"] = map[string]int64{"dev_x": 42}

	// Re-snapshot and verify original state intact.
	snap2 := c.Snapshot()
	if snap2[SignalMalformedFrame]["dev_a"] != 1 {
		t.Errorf("original mutated: got %d, want 1", snap2[SignalMalformedFrame]["dev_a"])
	}
	if _, ok := snap2["fresh_signal"]; ok {
		t.Error("fresh_signal leaked back into internal state")
	}
	if snap2[SignalInvalidNanoID]["dev_b"] != 2 {
		t.Errorf("dev_b count wrong: got %d, want 2", snap2[SignalInvalidNanoID]["dev_b"])
	}
}

func TestSnapshot_EmptyCounters(t *testing.T) {
	c := New()
	snap := c.Snapshot()
	if len(snap) != 0 {
		t.Errorf("empty counters snapshot should be empty map, got %d entries", len(snap))
	}
}

func TestUnknownSignal_Accepted(t *testing.T) {
	// The public API accepts any string — preserves flexibility for future
	// signals without breaking-change API churn. Constants exist to prevent
	// typos at known callsites, but Inc/Get don't enforce the list.
	c := New()
	c.Inc("fresh_signal_not_in_constants", "dev_x")
	if g := c.Get("fresh_signal_not_in_constants", "dev_x"); g != 1 {
		t.Errorf("Inc with unknown signal: got %d, want 1", g)
	}
}

func TestEmptyDeviceID_LogsWarning(t *testing.T) {
	// Empty deviceID is accepted (data preservation wins) but fires a
	// slog.Warn because in the current architecture every rejection site
	// runs post-auth — an empty deviceID indicates a caller bug.
	var buf bytes.Buffer
	handler := slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})
	restore := captureDefaultLogger(handler)
	defer restore()

	c := New()
	c.Inc(SignalMalformedFrame, "")
	if g := c.Get(SignalMalformedFrame, ""); g != 1 {
		t.Errorf("Inc with empty deviceID: got %d, want 1", g)
	}

	got := buf.String()
	if !strings.Contains(got, "empty deviceID") {
		t.Errorf("expected warning log about empty deviceID, got: %q", got)
	}
	if !strings.Contains(got, SignalMalformedFrame) {
		t.Errorf("expected warning to include signal name, got: %q", got)
	}
}

func TestEmptyDeviceID_NonEmptyDoesNotWarn(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})
	restore := captureDefaultLogger(handler)
	defer restore()

	c := New()
	c.Inc(SignalMalformedFrame, "dev_real")
	if strings.Contains(buf.String(), "empty deviceID") {
		t.Errorf("warning fired on non-empty deviceID: %q", buf.String())
	}
}

func TestLastInc_UpdatedOnEveryInc(t *testing.T) {
	// Phase 17b consumes lastInc for write-path opportunistic pruning.
	// Step 2 ships the timestamp substrate only — verify it advances on
	// every call so Phase 17b's prune logic has accurate data.
	c := New()
	k := key{signal: SignalMalformedFrame, deviceID: "dev_a"}

	c.Inc(SignalMalformedFrame, "dev_a")
	c.mu.RLock()
	t1 := c.data[k].lastInc.Load()
	c.mu.RUnlock()
	if t1 == 0 {
		t.Fatal("lastInc not set on first Inc")
	}

	// Sleep to guarantee a new unix second.
	time.Sleep(1100 * time.Millisecond)

	c.Inc(SignalMalformedFrame, "dev_a")
	c.mu.RLock()
	t2 := c.data[k].lastInc.Load()
	c.mu.RUnlock()
	if t2 <= t1 {
		t.Errorf("lastInc did not advance: t1=%d t2=%d", t1, t2)
	}
}

func TestAutoRevokeSignals_ExactList(t *testing.T) {
	// Guard against accidental inclusion of load/observational signals.
	// Adding a new misbehavior signal means updating this test + the slice.
	want := map[string]bool{
		SignalMalformedFrame:       true,
		SignalOversizedBody:        true,
		SignalUnknownVerb:          true,
		SignalInvalidNanoID:        true,
		SignalWrappedKeysOverCap:   true,
		SignalFileIDsOverCap:       true,
		SignalInvalidContentHash:   true,
		SignalOversizedUploadFrame: true,
		SignalNonMemberContext:     true,
		SignalDownloadNotFound:     true,
		SignalDownloadNoChannel:    true,
	}
	if len(AutoRevokeSignals) != len(want) {
		t.Errorf("AutoRevokeSignals len = %d, want %d", len(AutoRevokeSignals), len(want))
	}
	for _, s := range AutoRevokeSignals {
		if !want[s] {
			t.Errorf("AutoRevokeSignals contains %q which is not a misbehavior signal", s)
		}
		delete(want, s)
	}
	for s := range want {
		t.Errorf("AutoRevokeSignals missing misbehavior signal %q", s)
	}

	// Load and observational signals must NOT be in the list.
	for _, s := range AutoRevokeSignals {
		if s == SignalRateLimited {
			t.Error("AutoRevokeSignals must not contain SignalRateLimited (load signal)")
		}
		if s == SignalBroadcastDropped {
			t.Error("AutoRevokeSignals must not contain SignalBroadcastDropped (observational signal)")
		}
	}
}

// captureDefaultLogger swaps slog's default logger for one writing to the
// supplied handler. Returns a restore function to defer.
func captureDefaultLogger(h slog.Handler) func() {
	prev := slog.Default()
	slog.SetDefault(slog.New(h))
	return func() { slog.SetDefault(prev) }
}
