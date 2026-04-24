package server

// Phase 17b Step 5a — idle watchdog tests.
//
// Uses noopChannel from device_revocations_test.go to verify Channel.Close
// fires (or doesn't) on the expected schedule.

import (
	"io"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"
)

func TestComputeIdleWatchdogCadence_ShortTimeout(t *testing.T) {
	// timeoutSec=4 → quarter=1s → floor to 1s (min check).
	got := computeIdleWatchdogCadence(4)
	if got != time.Second {
		t.Errorf("cadence for timeout=4 = %v, want 1s (floor)", got)
	}
}

func TestComputeIdleWatchdogCadence_MediumTimeout(t *testing.T) {
	// timeoutSec=60 → quarter=15s → < 30s → 15s.
	got := computeIdleWatchdogCadence(60)
	if got != 15*time.Second {
		t.Errorf("cadence for timeout=60 = %v, want 15s", got)
	}
}

func TestComputeIdleWatchdogCadence_LongTimeout(t *testing.T) {
	// timeoutSec=600 → quarter=150s → > 30s → cap at 30s.
	got := computeIdleWatchdogCadence(600)
	if got != 30*time.Second {
		t.Errorf("cadence for timeout=600 = %v, want 30s (cap)", got)
	}
}

func TestComputeIdleWatchdogCadence_BelowMin(t *testing.T) {
	// timeoutSec=2 → quarter=500ms → below 1s floor → 1s.
	got := computeIdleWatchdogCadence(2)
	if got != time.Second {
		t.Errorf("cadence for timeout=2 = %v, want 1s (floor)", got)
	}
}

func TestRunIdleWatchdog_DisabledWhenTimeoutZero(t *testing.T) {
	s := newTestServer(t)
	ch := &noopChannel{}
	c := &Client{Channel: ch, UserID: "alice", DeviceID: "dev_x"}

	done := make(chan struct{})
	defer close(done)

	// timeoutSec=0 returns immediately without ticking.
	didReturn := make(chan struct{})
	go func() {
		s.runIdleWatchdog(c, 0, time.Millisecond, done)
		close(didReturn)
	}()

	select {
	case <-didReturn:
		// expected — watchdog returned right away
	case <-time.After(100 * time.Millisecond):
		t.Fatal("runIdleWatchdog with timeoutSec=0 did not return")
	}

	if got := ch.closed.Load(); got != 0 {
		t.Errorf("Channel.Close called %d times with timeoutSec=0, want 0", got)
	}
}

func TestRunIdleWatchdog_ClosesChannelOnStaleness(t *testing.T) {
	s := newTestServer(t)
	// Swap logger to discard — we don't want watchdog Info logs
	// polluting test output.
	s.logger = slog.New(slog.NewTextHandler(io.Discard, nil))

	ch := &noopChannel{}
	c := &Client{Channel: ch, UserID: "alice", DeviceID: "dev_idle"}
	// Pre-stamp LastActivity to a timestamp well past the timeout
	// so the very first tick sees staleness.
	c.LastActivity.Store(time.Now().Unix() - 10)

	done := make(chan struct{})
	defer close(done)

	go s.runIdleWatchdog(c, 2, 20*time.Millisecond, done)

	// Wait up to 200ms for the watchdog to fire.
	deadline := time.Now().Add(200 * time.Millisecond)
	for time.Now().Before(deadline) {
		if ch.closed.Load() > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	if got := ch.closed.Load(); got != 1 {
		t.Errorf("Channel.Close called %d times, want 1 (watchdog should fire on stale activity)", got)
	}
}

func TestRunIdleWatchdog_FreshActivityPreventsClose(t *testing.T) {
	s := newTestServer(t)
	s.logger = slog.New(slog.NewTextHandler(io.Discard, nil))

	ch := &noopChannel{}
	c := &Client{Channel: ch, UserID: "alice", DeviceID: "dev_active"}

	// Keep the client "active" for the duration of the watchdog run.
	// stop signals the refresher to exit.
	stop := make(chan struct{})
	refresherDone := make(chan struct{})
	go func() {
		defer close(refresherDone)
		ticker := time.NewTicker(5 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				c.LastActivity.Store(time.Now().Unix())
			}
		}
	}()

	done := make(chan struct{})
	go s.runIdleWatchdog(c, 2, 10*time.Millisecond, done)

	// Let the watchdog tick several times while the refresher keeps
	// LastActivity fresh.
	time.Sleep(80 * time.Millisecond)

	// Stop the refresher + watchdog.
	close(stop)
	<-refresherDone
	close(done)

	if got := ch.closed.Load(); got != 0 {
		t.Errorf("Channel.Close called %d times despite fresh activity, want 0", got)
	}
}

func TestRunIdleWatchdog_StampsZeroLastActivityAsGrace(t *testing.T) {
	// When LastActivity == 0 on the first tick, the watchdog stamps
	// "now" as the baseline — granting one full timeout window to
	// fresh connections. Without this grace, a session whose first
	// decode is delayed by >timeoutSec would get killed mid-handshake.
	s := newTestServer(t)
	s.logger = slog.New(slog.NewTextHandler(io.Discard, nil))

	ch := &noopChannel{}
	c := &Client{Channel: ch, UserID: "alice", DeviceID: "dev_fresh"}
	// LastActivity starts at zero (struct zero value).

	done := make(chan struct{})
	defer close(done)

	go s.runIdleWatchdog(c, 10, 10*time.Millisecond, done)
	time.Sleep(50 * time.Millisecond)

	if last := c.LastActivity.Load(); last == 0 {
		t.Error("watchdog did not stamp initial LastActivity from 0 → now")
	}
	if got := ch.closed.Load(); got != 0 {
		t.Errorf("watchdog closed channel during grace window, want no close")
	}
}

func TestRunIdleWatchdog_ExitsOnDone(t *testing.T) {
	s := newTestServer(t)
	s.logger = slog.New(slog.NewTextHandler(io.Discard, nil))

	ch := &noopChannel{}
	c := &Client{Channel: ch, UserID: "alice", DeviceID: "dev_exit"}
	c.LastActivity.Store(time.Now().Unix()) // fresh, watchdog won't fire

	done := make(chan struct{})
	didReturn := make(chan struct{})
	go func() {
		s.runIdleWatchdog(c, 10, 20*time.Millisecond, done)
		close(didReturn)
	}()

	time.Sleep(30 * time.Millisecond) // let it tick once
	close(done)

	select {
	case <-didReturn:
		// expected
	case <-time.After(100 * time.Millisecond):
		t.Fatal("watchdog did not return after done closed")
	}
}

// TestRunIdleWatchdog_ConcurrentLastActivityStores — run under -race.
// messageLoop writes LastActivity from one goroutine; runIdleWatchdog
// reads from another. Both via atomic.Int64 so no race. This test
// just hammers both concurrently to surface any regression.
func TestRunIdleWatchdog_ConcurrentLastActivityStores(t *testing.T) {
	s := newTestServer(t)
	s.logger = slog.New(slog.NewTextHandler(io.Discard, nil))

	ch := &noopChannel{}
	c := &Client{Channel: ch, UserID: "alice", DeviceID: "dev_race"}
	c.LastActivity.Store(time.Now().Unix())

	done := make(chan struct{})
	stop := make(chan struct{})
	var stamps atomic.Int64

	go s.runIdleWatchdog(c, 5, 5*time.Millisecond, done)

	refresherDone := make(chan struct{})
	go func() {
		defer close(refresherDone)
		for {
			select {
			case <-stop:
				return
			default:
				c.LastActivity.Store(time.Now().Unix())
				stamps.Add(1)
			}
		}
	}()

	time.Sleep(50 * time.Millisecond)
	close(stop)
	<-refresherDone
	close(done)

	if stamps.Load() == 0 {
		t.Error("refresher didn't run (test harness broken)")
	}
}
