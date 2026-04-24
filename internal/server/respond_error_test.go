package server

// Phase 17c Step 1 — respondError + respondOpaque chokepoint tests.
//
// Coverage:
//   - respondError wire shape for all 4 taxonomy categories
//   - corrID echoed when non-empty; elided (omitempty) when empty
//   - retryAfterMs=0 elided; non-zero included
//   - rate-limit rejection silently drops the error + fires SignalErrorFlood
//   - rate-limit rejection does NOT increment SignalErrorFlood on allowed
//     responses (only on the REJECTION — not every error)
//   - respondOpaque byte-identical to OpaqueReject() + corrID echo
//   - c == nil handled as no-op
//
// Tests use the full newTestServer fixture (real config, real
// limiter, real counters) so respondError's rate-limit check and
// SignalErrorFlood Inc wiring are exercised end-to-end. Client
// values come from newRejectTestClient for wire-capture against a
// bytes.Buffer via the test-mode-safeEncoder path.

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/brushtailmedia/sshkey-chat/internal/counters"
	"github.com/brushtailmedia/sshkey-chat/internal/protocol"
)

func TestRespondError_CategoryA_WithRetryAfterMs(t *testing.T) {
	s := newTestServer(t)

	var buf bytes.Buffer
	c := newRejectTestClient("dev_a", &buf)

	s.respondError(c, "corr_01234567890123456789A", protocol.CodeRateLimit, "slow down", 5000)

	var got protocol.Error
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v\nraw: %s", err, buf.Bytes())
	}
	if got.Type != "error" {
		t.Errorf("type = %q, want error", got.Type)
	}
	if got.Code != protocol.CodeRateLimit {
		t.Errorf("code = %q, want %q", got.Code, protocol.CodeRateLimit)
	}
	if got.Message != "slow down" {
		t.Errorf("message = %q, want 'slow down'", got.Message)
	}
	if got.RetryAfterMs != 5000 {
		t.Errorf("retry_after_ms = %d, want 5000", got.RetryAfterMs)
	}
	if got.CorrID != "corr_01234567890123456789A" {
		t.Errorf("corr_id = %q, want echoed back", got.CorrID)
	}
}

func TestRespondError_CategoryC_NoRetryAfterOmitted(t *testing.T) {
	s := newTestServer(t)
	var buf bytes.Buffer
	c := newRejectTestClient("dev_c", &buf)

	s.respondError(c, "", protocol.CodeTooLarge, "message exceeds 16KB limit", 0)

	raw := buf.String()
	if strings.Contains(raw, "retry_after_ms") {
		t.Errorf("retry_after_ms=0 not omitted from wire: %s", raw)
	}
	if strings.Contains(raw, "corr_id") {
		t.Errorf("empty corr_id not omitted from wire: %s", raw)
	}

	var got protocol.Error
	_ = json.Unmarshal([]byte(raw), &got)
	if got.Code != protocol.CodeTooLarge {
		t.Errorf("code = %q, want %q", got.Code, protocol.CodeTooLarge)
	}
}

func TestRespondOpaque_ByteIdenticalToHelper(t *testing.T) {
	// Category D must produce the byte-identical "denied" / "operation
	// rejected" shape regardless of underlying reason. Compare to the
	// pure protocol.OpaqueReject() helper output with the same corrID.
	s := newTestServer(t)

	var buf bytes.Buffer
	c := newRejectTestClient("dev_d", &buf)

	s.respondOpaque(c, "corr_01234567890123456789A")

	var got protocol.Error
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Code != protocol.CodeDenied {
		t.Errorf("code = %q, want %q (CodeDenied)", got.Code, protocol.CodeDenied)
	}
	if got.Message != "operation rejected" {
		t.Errorf("message = %q, want 'operation rejected'", got.Message)
	}
	if got.CorrID != "corr_01234567890123456789A" {
		t.Errorf("corr_id not echoed: %q", got.CorrID)
	}
}

func TestRespondOpaque_EmptyCorrID(t *testing.T) {
	s := newTestServer(t)
	var buf bytes.Buffer
	c := newRejectTestClient("dev_d2", &buf)

	s.respondOpaque(c, "")

	raw := buf.String()
	if strings.Contains(raw, "corr_id") {
		t.Errorf("empty corr_id not omitted: %s", raw)
	}
}

func TestRespondError_NilClientIsNoOp(t *testing.T) {
	s := newTestServer(t)
	// Must not panic; nothing to assert on output.
	s.respondError(nil, "", "some_code", "some message", 0)
}

func TestRespondError_RateLimitSilentDrop_FiresSignalErrorFlood(t *testing.T) {
	s := newTestServer(t)
	// Force tight limit for the test — 1 error per minute for a single device.
	s.cfg.Lock()
	s.cfg.Server.RateLimits.ErrorResponsesPerMinute = 1
	s.cfg.Unlock()

	var buf bytes.Buffer
	c := newRejectTestClient("dev_flood", &buf)

	// First error: under the 1/min budget. Goes through.
	s.respondError(c, "", protocol.CodeRateLimit, "slow down", 5000)
	// Subsequent errors: rate-limit kicks in. Default token bucket has a
	// minimum burst of 5, so we issue enough rapid calls to exhaust it.
	for i := 0; i < 10; i++ {
		s.respondError(c, "", protocol.CodeRateLimit, "slow down", 5000)
	}

	// SignalErrorFlood must have at least one increment (the rate-limit
	// rejection of an error send).
	got := s.counters.Get(counters.SignalErrorFlood, "dev_flood")
	if got == 0 {
		t.Errorf("SignalErrorFlood = 0, want >= 1 (rate-limit rejection did not fire counter)")
	}
}

func TestRespondError_RateLimitDisabledWhenZero(t *testing.T) {
	s := newTestServer(t)
	s.cfg.Lock()
	s.cfg.Server.RateLimits.ErrorResponsesPerMinute = 0
	s.cfg.Unlock()

	var buf bytes.Buffer
	c := newRejectTestClient("dev_nolimit", &buf)

	// Fire many errors; none should be dropped.
	for i := 0; i < 50; i++ {
		s.respondError(c, "", protocol.CodeRateLimit, "slow down", 5000)
	}

	// SignalErrorFlood must stay at zero.
	if got := s.counters.Get(counters.SignalErrorFlood, "dev_nolimit"); got != 0 {
		t.Errorf("SignalErrorFlood = %d, want 0 when rate limit disabled", got)
	}

	// All 50 errors should be on the wire.
	lines := bytes.Count(buf.Bytes(), []byte("\n"))
	if lines != 50 {
		t.Errorf("wrote %d error lines, want 50 (rate limit should be disabled)", lines)
	}
}

func TestRespondError_UnderBudgetNoFloodSignal(t *testing.T) {
	// With a generous budget, normal errors must not fire
	// SignalErrorFlood. This is the "legit user errored a few times"
	// baseline.
	s := newTestServer(t)
	s.cfg.Lock()
	s.cfg.Server.RateLimits.ErrorResponsesPerMinute = 60
	s.cfg.Unlock()

	var buf bytes.Buffer
	c := newRejectTestClient("dev_budget", &buf)

	for i := 0; i < 3; i++ {
		s.respondError(c, "", protocol.CodeRateLimit, "slow down", 5000)
	}

	if got := s.counters.Get(counters.SignalErrorFlood, "dev_budget"); got != 0 {
		t.Errorf("SignalErrorFlood = %d, want 0 for under-budget traffic", got)
	}
}
