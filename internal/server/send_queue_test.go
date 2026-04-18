package server

// Phase 17b Step 5b — per-client send-queue tests.
//
// Coverage matrix:
//
//   Client.TryEnqueue:
//   - success path resets consecutiveDrops
//   - full queue returns false + increments drops
//   - nil sendCh (test-mode) returns (false, 0)
//
//   runSendWriter:
//   - drains queued messages through the safeEncoder
//   - exits cleanly on sessionDone close
//   - exits on Encode error (counts drop)
//
//   fanOutOne disconnect policy:
//   - full queue fires SignalBroadcastDropped and closes channel
//     after ConsecutiveDropDisconnectThreshold
//   - successful enqueue resets the drop counter
//   - slow reader does NOT block fanOut progression for other recipients

import (
	"bytes"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/brushtailmedia/sshkey-chat/internal/counters"
	"github.com/brushtailmedia/sshkey-chat/internal/protocol"
)

// newQueuedClient builds a Client with a real sendCh + sessionDone so
// we can exercise the Step 5b code paths in tests.
func newQueuedClient(deviceID string, bufSize int, out io.Writer) *Client {
	c := &Client{
		UserID:      "usr_test",
		DeviceID:    deviceID,
		Encoder:     newSafeEncoder(protocol.NewEncoder(out)),
		sendCh:      make(chan any, bufSize),
		sessionDone: make(chan struct{}),
	}
	return c
}

func TestTryEnqueue_SuccessResetsDrops(t *testing.T) {
	c := newQueuedClient("dev_tryok", 4, io.Discard)
	c.consecutiveDrops.Store(7) // simulate prior drops

	queued, drops := c.TryEnqueue("msg")
	if !queued {
		t.Fatal("TryEnqueue with room = false, want true")
	}
	if drops != 0 {
		t.Errorf("TryEnqueue success reset drops to %d, want 0", drops)
	}
	if c.consecutiveDrops.Load() != 0 {
		t.Errorf("consecutiveDrops after success = %d, want 0", c.consecutiveDrops.Load())
	}
}

func TestTryEnqueue_FullQueueIncrementsDrops(t *testing.T) {
	c := newQueuedClient("dev_full", 2, io.Discard)
	// No writer draining — fill the buffer.
	c.sendCh <- "a"
	c.sendCh <- "b"

	queued, drops := c.TryEnqueue("overflow")
	if queued {
		t.Error("TryEnqueue to full queue = true, want false")
	}
	if drops != 1 {
		t.Errorf("first drop: drops = %d, want 1", drops)
	}

	// Second attempt should return drops=2
	_, drops2 := c.TryEnqueue("overflow_again")
	if drops2 != 2 {
		t.Errorf("second drop: drops = %d, want 2", drops2)
	}
}

func TestTryEnqueue_NilSendCh(t *testing.T) {
	c := &Client{UserID: "u", DeviceID: "d"} // no sendCh
	queued, drops := c.TryEnqueue("msg")
	if queued {
		t.Error("nil sendCh TryEnqueue = true, want false")
	}
	if drops != 0 {
		t.Errorf("nil sendCh drops = %d, want 0 (no tracking)", drops)
	}
}

func TestRunSendWriter_DrainsAndEncodes(t *testing.T) {
	s := newTestServer(t)
	s.logger = slog.New(slog.NewTextHandler(io.Discard, nil))

	var out bytes.Buffer
	c := newQueuedClient("dev_writer", 4, &out)

	// Enqueue before starting so we can assert the writer drains.
	c.sendCh <- protocol.OpaqueReject()
	c.sendCh <- protocol.OpaqueReject()

	done := make(chan struct{})
	go func() {
		s.runSendWriter(c)
		close(done)
	}()

	// Wait for the writer to drain (sendCh len → 0).
	deadline := time.Now().Add(200 * time.Millisecond)
	for time.Now().Before(deadline) && len(c.sendCh) > 0 {
		time.Sleep(5 * time.Millisecond)
	}
	if len(c.sendCh) != 0 {
		t.Fatalf("writer failed to drain sendCh, %d still queued", len(c.sendCh))
	}

	// Stop writer + wait for exit BEFORE reading the buffer — avoids
	// race on bytes.Buffer (not concurrent-safe).
	close(c.sessionDone)
	select {
	case <-done:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("writer did not exit after sessionDone close")
	}

	lines := bytes.Count(out.Bytes(), []byte("\n"))
	if lines != 2 {
		t.Errorf("wrote %d lines, want 2", lines)
	}
}

func TestRunSendWriter_ExitsOnSessionDone(t *testing.T) {
	s := newTestServer(t)
	s.logger = slog.New(slog.NewTextHandler(io.Discard, nil))

	c := newQueuedClient("dev_stop", 4, io.Discard)

	done := make(chan struct{})
	go func() {
		s.runSendWriter(c)
		close(done)
	}()

	// Close sessionDone immediately.
	close(c.sessionDone)

	select {
	case <-done:
		// expected
	case <-time.After(200 * time.Millisecond):
		t.Fatal("runSendWriter did not exit after sessionDone close")
	}
}

// erroringWriter returns a sentinel error on Write. Used to simulate
// a dead SSH channel in the writer-goroutine tests.
type erroringWriter struct{ err error }

func (e *erroringWriter) Write(p []byte) (int, error) { return 0, e.err }

func TestRunSendWriter_ExitsOnEncodeError(t *testing.T) {
	s := newTestServer(t)
	s.logger = slog.New(slog.NewTextHandler(io.Discard, nil))

	w := &erroringWriter{err: errors.New("ssh channel closed")}
	c := newQueuedClient("dev_errwriter", 4, w)

	c.sendCh <- protocol.OpaqueReject() // first encode will fail → writer exits

	done := make(chan struct{})
	go func() {
		s.runSendWriter(c)
		close(done)
	}()

	select {
	case <-done:
		// expected
	case <-time.After(200 * time.Millisecond):
		t.Fatal("runSendWriter did not exit after encode error")
	}

	if got := s.counters.Get(counters.SignalBroadcastDropped, "dev_errwriter"); got != 1 {
		t.Errorf("SignalBroadcastDropped after encode error = %d, want 1", got)
	}

	close(c.sessionDone) // no-op since writer already exited
}

func TestFanOutOne_SuccessResetsDrops(t *testing.T) {
	s := newTestServer(t)
	s.logger = slog.New(slog.NewTextHandler(io.Discard, nil))

	var out bytes.Buffer
	c := newQueuedClient("dev_reset", 4, &out)
	c.consecutiveDrops.Store(5) // prior drops

	s.fanOutOne("test", protocol.OpaqueReject(), c)

	if c.consecutiveDrops.Load() != 0 {
		t.Errorf("consecutiveDrops after successful enqueue = %d, want 0", c.consecutiveDrops.Load())
	}
	// Pull the queued message out so the test doesn't leak.
	select {
	case <-c.sendCh:
	default:
		t.Error("fanOutOne did not enqueue anything")
	}
}

// fakeChannelForQueue implements ssh.Channel for the slow-reader
// disconnect test. We need Close tracked; Read/Write/etc. are no-ops.
// Reuse noopChannel from device_revocations_test.go.

func TestFanOutOne_ConsecutiveDropsTriggerDisconnect(t *testing.T) {
	s := newTestServer(t)
	s.logger = slog.New(slog.NewTextHandler(io.Discard, nil))

	// Force threshold to 3 for this test.
	s.cfg.Lock()
	s.cfg.Server.RateLimits.ConsecutiveDropDisconnectThreshold = 3
	s.cfg.Unlock()

	ch := &noopChannel{}
	c := newQueuedClient("dev_slow", 2, io.Discard)
	c.Channel = ch
	// Fill the buffer so every enqueue fails.
	c.sendCh <- "filler1"
	c.sendCh <- "filler2"

	msg := protocol.OpaqueReject()

	// Attempts 1 and 2: drops increment but no disconnect yet.
	s.fanOutOne("test", msg, c)
	s.fanOutOne("test", msg, c)
	if got := ch.closed.Load(); got != 0 {
		t.Errorf("channel closed prematurely at %d drops; threshold is 3", c.consecutiveDrops.Load())
	}

	// Attempt 3: crosses threshold, should close.
	s.fanOutOne("test", msg, c)
	if got := ch.closed.Load(); got != 1 {
		t.Errorf("channel not closed after crossing threshold, closed=%d", got)
	}

	if got := s.counters.Get(counters.SignalBroadcastDropped, "dev_slow"); got != 3 {
		t.Errorf("SignalBroadcastDropped = %d, want 3", got)
	}
}

func TestFanOutOne_SuccessBetweenDropsResetsCounter(t *testing.T) {
	// "Consecutive" semantics: a single successful enqueue between
	// drops resets the counter to 0. After the reset, the next drop
	// counts as 1, not as a continuation of the prior run.
	s := newTestServer(t)
	s.logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	s.cfg.Lock()
	s.cfg.Server.RateLimits.ConsecutiveDropDisconnectThreshold = 10
	s.cfg.Unlock()

	ch := &noopChannel{}
	c := newQueuedClient("dev_intermittent", 2, io.Discard)
	c.Channel = ch

	// Fill the buffer so TryEnqueue fails.
	c.sendCh <- "filler_a"
	c.sendCh <- "filler_b"

	// Two consecutive drops.
	s.fanOutOne("test", "drop1", c)
	s.fanOutOne("test", "drop2", c)
	if got := c.consecutiveDrops.Load(); got != 2 {
		t.Fatalf("after 2 consecutive drops, counter = %d, want 2", got)
	}

	// Drain one slot. Now the buffer has capacity for 1 more.
	<-c.sendCh

	// Successful enqueue resets the counter.
	s.fanOutOne("test", "ok", c)
	if got := c.consecutiveDrops.Load(); got != 0 {
		t.Fatalf("after successful enqueue, counter = %d, want 0", got)
	}

	// Buffer is now back at capacity (1 filler + 1 ok = 2).
	// Next fanOutOne should drop fresh: counter=1, not 3.
	s.fanOutOne("test", "drop_after_reset", c)
	if got := c.consecutiveDrops.Load(); got != 1 {
		t.Errorf("after reset+drop, counter = %d, want 1 (fresh consecutive run)", got)
	}
}

// TestFanOut_SlowReaderDoesNotBlock — end-to-end: three recipients,
// one of them slow. fanOut (the full helper, not fanOutOne) must
// return promptly for all three even though one has a full queue
// because the non-blocking enqueue doesn't wait.
//
// Reads bytes.Buffer only AFTER stopping writer goroutines to avoid
// the intra-buffer race detector warning (bytes.Buffer is not
// concurrent-safe).
func TestFanOut_SlowReaderDoesNotBlock(t *testing.T) {
	s := newTestServer(t)
	s.logger = slog.New(slog.NewTextHandler(io.Discard, nil))

	var fast1, fast2 bytes.Buffer

	// Two fast clients with running writer goroutines.
	c1 := newQueuedClient("dev_fast1", 4, &fast1)
	c2 := newQueuedClient("dev_fast2", 4, &fast2)
	w1Done := make(chan struct{})
	w2Done := make(chan struct{})
	go func() { s.runSendWriter(c1); close(w1Done) }()
	go func() { s.runSendWriter(c2); close(w2Done) }()

	// One "slow" client with a full buffer and no writer. fanOut
	// enqueues should fail immediately (drop).
	cSlow := newQueuedClient("dev_slow", 1, io.Discard)
	cSlow.sendCh <- "filler"
	cSlow.Channel = &noopChannel{} // so drop-disconnect doesn't nil-panic

	msg := protocol.OpaqueReject()

	start := time.Now()
	s.fanOut("test", msg, []*Client{c1, cSlow, c2})
	elapsed := time.Since(start)

	if elapsed > 100*time.Millisecond {
		t.Errorf("fanOut with slow reader took %v, expected < 100ms (should be non-blocking)", elapsed)
	}

	// Wait for writer goroutines to drain their single message each
	// (synchronous sendCh check — safe because this goroutine is the
	// only one draining sendCh in test-mode control).
	waitForDrain := func(name string, ch chan any) {
		t.Helper()
		deadline := time.Now().Add(200 * time.Millisecond)
		for time.Now().Before(deadline) {
			if len(ch) == 0 {
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
		t.Errorf("%s sendCh not drained: %d messages still queued", name, len(ch))
	}
	waitForDrain("c1", c1.sendCh)
	waitForDrain("c2", c2.sendCh)

	// Stop writer goroutines + wait for them to exit BEFORE reading
	// buffers. This serializes with the writers' Write calls.
	close(c1.sessionDone)
	close(c2.sessionDone)
	<-w1Done
	<-w2Done

	if fast1.Len() == 0 {
		t.Error("fast1 received no bytes despite fanOut completing")
	}
	if fast2.Len() == 0 {
		t.Error("fast2 received no bytes despite fanOut completing")
	}

	if got := s.counters.Get(counters.SignalBroadcastDropped, "dev_slow"); got != 1 {
		t.Errorf("slow recipient drop count = %d, want 1", got)
	}
}

// TestFanOutOne_TestModeFallback verifies fanOutOne's test-mode
// fallback path (Client with nil sendCh) still encodes synchronously,
// preserving behavior for fixtures that don't run writer goroutines.
func TestFanOutOne_TestModeFallback(t *testing.T) {
	s := newTestServer(t)
	s.logger = slog.New(slog.NewTextHandler(io.Discard, nil))

	var out bytes.Buffer
	c := &Client{
		UserID:   "usr_test",
		DeviceID: "dev_fallback",
		Encoder:  newSafeEncoder(protocol.NewEncoder(&out)),
		// No sendCh — test-mode fallback
	}

	s.fanOutOne("test", protocol.OpaqueReject(), c)

	if out.Len() == 0 {
		t.Error("test-mode fallback produced no output; sync Encode path should write to buffer")
	}
	// Match the NDJSON shape: the OpaqueReject() should contain
	// "denied" as its Code field.
	if !strings.Contains(out.String(), "denied") {
		t.Errorf("output missing expected 'denied' code: %q", out.String())
	}
}
