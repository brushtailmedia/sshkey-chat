package server

import (
	"bytes"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/brushtailmedia/sshkey-chat/internal/counters"
	"github.com/brushtailmedia/sshkey-chat/internal/protocol"
)

// -----------------------------------------------------------------------------
// slowWriter: an io.Writer that simulates a slow/stalled SSH channel writer
// for broadcast-back-pressure testing. After `acceptBytes` bytes have been
// written, subsequent Write calls block until the test unblocks via release()
// or the test context cancels. Thread-safe for concurrent Writes (matches
// ssh.Channel semantics — multiple goroutines would serialize through the
// channel's internal lock).
//
// Also supports a "return error on Write" mode via setErr() for testing
// the drop-counting path without needing an actual channel close.
// -----------------------------------------------------------------------------

type slowWriter struct {
	buf         bytes.Buffer
	mu          sync.Mutex
	written     int           // bytes accepted so far (only counted while not stalled)
	acceptBytes int           // stall threshold (< 0 = never stall)
	unblock     chan struct{} // closed when release() called
	err         error         // if non-nil, Write returns this error
}

// newSlowWriter returns a writer that blocks on Write once acceptBytes bytes
// have been accepted. Pass acceptBytes=-1 to never block (pure buffer).
func newSlowWriter(acceptBytes int) *slowWriter {
	return &slowWriter{
		acceptBytes: acceptBytes,
		unblock:     make(chan struct{}),
	}
}

// Write implements io.Writer. Blocks after acceptBytes have been written
// until release() is called. Returns the configured err immediately if one
// has been set via setErr.
func (w *slowWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	if w.err != nil {
		err := w.err
		w.mu.Unlock()
		return 0, err
	}
	if w.acceptBytes >= 0 && w.written >= w.acceptBytes {
		unblock := w.unblock
		w.mu.Unlock()
		// Block until released. Not holding the mutex while blocked so
		// setErr()/release() can proceed from test goroutines.
		<-unblock
		// After release, just append and return success — mimics a drained
		// channel buffer catching up.
		w.mu.Lock()
	}
	n, err := w.buf.Write(p)
	w.written += n
	w.mu.Unlock()
	return n, err
}

// release unblocks any goroutine currently waiting in Write. Idempotent.
func (w *slowWriter) release() {
	w.mu.Lock()
	defer w.mu.Unlock()
	select {
	case <-w.unblock:
		// already closed
	default:
		close(w.unblock)
	}
}

// setErr configures the writer to return err from subsequent Write calls.
// Use for testing the drop-counting path.
func (w *slowWriter) setErr(err error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.err = err
}

// bytesWritten returns the total bytes accepted so far.
func (w *slowWriter) bytesWritten() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.written
}

// -----------------------------------------------------------------------------
// fanOut helper tests.
// -----------------------------------------------------------------------------

func TestFanOut_AllRecipientsReceive(t *testing.T) {
	s := newRejectTestServer(t, nil)

	// Three recipients with bytes.Buffer-backed Encoders (fast writers).
	var b1, b2, b3 bytes.Buffer
	c1 := newRejectTestClient("dev_1", &b1)
	c2 := newRejectTestClient("dev_2", &b2)
	c3 := newRejectTestClient("dev_3", &b3)

	msg := protocol.OpaqueReject()
	s.fanOut("test", msg, []*Client{c1, c2, c3})

	for _, b := range []*bytes.Buffer{&b1, &b2, &b3} {
		if b.Len() == 0 {
			t.Errorf("recipient received no bytes")
		}
	}

	// No drops should be counted on the happy path.
	for _, dev := range []string{"dev_1", "dev_2", "dev_3"} {
		if got := s.counters.Get(counters.SignalBroadcastDropped, dev); got != 0 {
			t.Errorf("happy-path broadcast produced drop for %s: got %d", dev, got)
		}
	}
}

func TestFanOut_EmptyRecipients_NoOp(t *testing.T) {
	s := newRejectTestServer(t, nil)
	// Should not panic, should not emit any logs, should not increment anything.
	s.fanOut("test", protocol.OpaqueReject(), nil)
	s.fanOut("test", protocol.OpaqueReject(), []*Client{})
	// No assertions needed beyond "did not panic."
}

func TestFanOut_OneFailingRecipient_CountsDropAndContinues(t *testing.T) {
	s := newRejectTestServer(t, nil)

	var good1, good2 bytes.Buffer
	c1 := newRejectTestClient("dev_good_1", &good1)
	c2 := newRejectTestClient("dev_good_2", &good2)

	// Third recipient's Encoder writes into a slowWriter that returns an
	// error. The other two recipients must still receive.
	sw := newSlowWriter(-1)
	sw.setErr(errors.New("channel closed"))
	c3 := &Client{
		UserID:   "usr_test",
		DeviceID: "dev_bad",
		Encoder:  newSafeEncoder(protocol.NewEncoder(sw)),
	}

	msg := protocol.OpaqueReject()
	s.fanOut("test", msg, []*Client{c1, c3, c2}) // bad in middle — verify others still get delivery

	if good1.Len() == 0 {
		t.Error("c1 (before bad recipient) received no bytes")
	}
	if good2.Len() == 0 {
		t.Error("c2 (after bad recipient) received no bytes — fanOut did not continue past the error")
	}
	if got := s.counters.Get(counters.SignalBroadcastDropped, "dev_bad"); got != 1 {
		t.Errorf("drop counter for dev_bad = %d, want 1", got)
	}
	// Good recipients should show no drop.
	for _, dev := range []string{"dev_good_1", "dev_good_2"} {
		if got := s.counters.Get(counters.SignalBroadcastDropped, dev); got != 0 {
			t.Errorf("good recipient %s has drop count %d, want 0", dev, got)
		}
	}
}

func TestFanOut_DropLogsAtDebugWithVerbAndDevice(t *testing.T) {
	// We log at Debug level, so our logger must be configured to capture Debug.
	var logBuf bytes.Buffer
	s := newRejectTestServer(t, &logBuf)
	// Override with a Debug-level handler — newRejectTestServer defaults to Warn.
	s.logger = newTestLogger(&logBuf)

	sw := newSlowWriter(-1)
	sw.setErr(errors.New("dead channel"))
	c := &Client{
		UserID:   "usr_test",
		DeviceID: "dev_failing",
		Encoder:  newSafeEncoder(protocol.NewEncoder(sw)),
	}
	s.fanOut("epoch_key", protocol.OpaqueReject(), []*Client{c})

	logOut := logBuf.String()
	for _, want := range []string{"broadcast dropped", "epoch_key", "dev_failing", "dead channel"} {
		if !strings.Contains(logOut, want) {
			t.Errorf("log missing %q in: %q", want, logOut)
		}
	}
}

func TestFanOut_MutexProtectedEncoder_ConcurrentCallsSafe(t *testing.T) {
	// protocol.Encoder is internally mutex-protected. Concurrent fanOut calls
	// to the same client's Encoder must not race under -race.
	s := newRejectTestServer(t, nil)

	var b bytes.Buffer
	c := newRejectTestClient("dev_shared", &b)

	msg := protocol.OpaqueReject()
	const N = 8
	const M = 50

	var wg sync.WaitGroup
	wg.Add(N)
	for i := 0; i < N; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < M; j++ {
				s.fanOut("test", msg, []*Client{c})
			}
		}()
	}
	wg.Wait()

	// Each call writes one NDJSON line; expect N*M lines.
	lines := bytes.Count(b.Bytes(), []byte("\n"))
	if lines != N*M {
		t.Errorf("concurrent fanOut wrote %d lines, want %d", lines, N*M)
	}
	if got := s.counters.Get(counters.SignalBroadcastDropped, "dev_shared"); got != 0 {
		t.Errorf("concurrent happy path produced %d drops, want 0", got)
	}
}

// -----------------------------------------------------------------------------
// slowWriter unit tests — verify the helper itself works before we rely on
// it for the broadcast integration test.
// -----------------------------------------------------------------------------

func TestSlowWriter_WritesUpToAcceptThenBlocks(t *testing.T) {
	sw := newSlowWriter(10) // accept first 10 bytes, then stall

	// Write 5 bytes — should succeed.
	n, err := sw.Write([]byte("hello"))
	if err != nil || n != 5 {
		t.Fatalf("first write: n=%d err=%v, want n=5 nil", n, err)
	}

	// Write 5 more — reaches threshold; this one accepts (we only stall AFTER
	// reaching acceptBytes on NEXT call). Inspect.
	n, err = sw.Write([]byte("world"))
	if err != nil || n != 5 {
		t.Fatalf("second write: n=%d err=%v, want n=5 nil", n, err)
	}
	if sw.bytesWritten() != 10 {
		t.Errorf("bytesWritten = %d, want 10", sw.bytesWritten())
	}

	// Third write should block. Run in a goroutine with a timeout.
	done := make(chan struct{})
	go func() {
		sw.Write([]byte("X"))
		close(done)
	}()

	select {
	case <-done:
		t.Error("slowWriter third Write did not block after threshold")
	case <-time.After(100 * time.Millisecond):
		// expected: still blocked
	}

	// Release and verify the pending Write completes.
	sw.release()
	select {
	case <-done:
		// ok
	case <-time.After(1 * time.Second):
		t.Error("slowWriter did not unblock after release()")
	}
}

func TestSlowWriter_SetErrReturnsError(t *testing.T) {
	sw := newSlowWriter(-1) // never stall
	sentinel := errors.New("boom")
	sw.setErr(sentinel)

	n, err := sw.Write([]byte("hello"))
	if n != 0 || !errors.Is(err, sentinel) {
		t.Errorf("Write after setErr: n=%d err=%v, want n=0 err=%v", n, err, sentinel)
	}
}

// -----------------------------------------------------------------------------
// Integration test: synthetic slow-reader. Demonstrates that with fanOut,
// one stalled recipient does NOT block the others. Runs the fanOut helper
// on a mix of fast + slow recipients and asserts completion within a bounded
// time budget.
//
// Before Step 3's fix, this test would hang (blocked on the slow writer
// while holding s.mu.RLock()); after Step 3's fix, the helper doesn't hold
// the mutex and each recipient's Encode blocks independently.
// -----------------------------------------------------------------------------

func TestFanOut_SlowRecipientDoesNotBlockFastRecipients(t *testing.T) {
	s := newRejectTestServer(t, nil)

	// Two fast recipients via plain bytes.Buffer.
	var fast1, fast2 bytes.Buffer
	cFast1 := newRejectTestClient("dev_fast_1", &fast1)
	cFast2 := newRejectTestClient("dev_fast_2", &fast2)

	// One slow recipient that blocks after 1 byte.
	sw := newSlowWriter(1)
	cSlow := &Client{
		UserID:   "usr_slow",
		DeviceID: "dev_slow",
		Encoder:  newSafeEncoder(protocol.NewEncoder(sw)),
	}

	// Drive fanOut from a goroutine. It should complete for the fast
	// recipients even though the slow one is blocked, because fanOut
	// iterates sequentially — the fast recipients at positions 0 and 1 get
	// encoded before we reach the slow one at position 2.
	//
	// More importantly, another concurrent fanOut call targeting ONLY the
	// fast recipients must proceed without being blocked by the stalled
	// goroutine (demonstrates the independence the Step 3 fix provides).
	msg := protocol.OpaqueReject()

	stalledDone := make(chan struct{})
	go func() {
		s.fanOut("test", msg, []*Client{cFast1, cSlow, cFast2})
		close(stalledDone)
	}()

	// Hit the fast-only path concurrently. Under the old lock-held design
	// this wouldn't matter (different recipients), but this confirms the
	// helper doesn't serialize independent broadcasts.
	fastDone := make(chan struct{})
	go func() {
		for i := 0; i < 10; i++ {
			s.fanOut("test", msg, []*Client{cFast1, cFast2})
		}
		close(fastDone)
	}()

	// Fast-only broadcasts must complete promptly. Before the fix, if the
	// slow broadcast held s.mu.RLock() (not relevant here since fanOut
	// doesn't take the lock — but validating the broader "no shared
	// blocking" property), all would stall.
	select {
	case <-fastDone:
		// ok
	case <-time.After(2 * time.Second):
		t.Fatal("fast-only fanOut calls did not complete within 2s — likely blocked on the stalled goroutine")
	}

	// Fast recipients should have received the 1 (from stalled call) + 10
	// NDJSON lines each.
	for name, buf := range map[string]*bytes.Buffer{"fast1": &fast1, "fast2": &fast2} {
		gotLines := bytes.Count(buf.Bytes(), []byte("\n"))
		if gotLines < 10 {
			t.Errorf("%s received %d lines, want at least 10", name, gotLines)
		}
	}

	// Release the slow writer and confirm the stalled broadcast completes.
	sw.release()
	select {
	case <-stalledDone:
		// ok
	case <-time.After(2 * time.Second):
		t.Error("stalled broadcast did not complete after release")
	}
}

// -----------------------------------------------------------------------------
// Helper: a logger capturing at Debug level.
// -----------------------------------------------------------------------------

func newTestLogger(w io.Writer) *slog.Logger {
	return slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{Level: slog.LevelDebug}))
}
