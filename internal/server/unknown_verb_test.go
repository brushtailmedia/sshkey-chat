package server

// Phase 17 Step 4e — unknown-verb warn-and-count tests. Verifies that
// the `default:` case in handleMessage:
//
//   1. Increments counters.SignalUnknownVerb (keyed by device).
//   2. Emits a Warn-level log line via rejectAndLog.
//   3. Does NOT write any response to the client — preserves the
//      pre-Phase-17 "silent default" wire behavior (responding with a
//      typed error would leak the valid-verb list to a probing client).
//
// These tests cover dispatch-level behavior. Lower-level rejectAndLog
// smoke tests live in reject_test.go.

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/brushtailmedia/sshkey-chat/internal/counters"
)

func TestHandleMessage_UnknownVerb_IncrementsCounterAndLogs(t *testing.T) {
	var encBuf bytes.Buffer
	var logBuf bytes.Buffer
	s := newRejectTestServer(t, &logBuf)
	c := newRejectTestClient("dev_unknown_verb_test", &encBuf)

	raw := json.RawMessage(`{"type":"not_a_real_verb","junk":"ignored"}`)
	s.handleMessage(c, "not_a_real_verb", raw)

	// Counter incremented under the device's bucket.
	if got := s.counters.Get(counters.SignalUnknownVerb, "dev_unknown_verb_test"); got != 1 {
		t.Errorf("counter after unknown verb = %d, want 1", got)
	}

	// Log line carries the expected fields.
	logOut := logBuf.String()
	for _, want := range []string{"rejection", "unknown_verb", "dev_unknown_verb_test", "not_a_real_verb", "count=1"} {
		if !strings.Contains(logOut, want) {
			t.Errorf("log missing %q in: %q", want, logOut)
		}
	}

	// CRITICAL PRIVACY CHECK: no response on the wire. If this ever
	// starts emitting a typed error, a probing client can enumerate the
	// valid verb space by diffing responses. Keep the default silent.
	if encBuf.Len() != 0 {
		t.Errorf("unknown verb must not write to client (leaks valid-verb list); got: %q", encBuf.String())
	}
}

func TestHandleMessage_UnknownVerb_CountsPerDevice(t *testing.T) {
	// Different devices sending the same unknown verb track separately.
	// Phase 17b auto-revoke needs per-device attribution; this test locks
	// that in at the dispatch level.
	var logBuf bytes.Buffer
	s := newRejectTestServer(t, &logBuf)

	var encA, encB bytes.Buffer
	cA := newRejectTestClient("dev_a", &encA)
	cB := newRejectTestClient("dev_b", &encB)

	raw := json.RawMessage(`{"type":"bogus"}`)
	s.handleMessage(cA, "bogus", raw)
	s.handleMessage(cA, "bogus", raw)
	s.handleMessage(cA, "bogus", raw)
	s.handleMessage(cB, "bogus", raw)

	if got := s.counters.Get(counters.SignalUnknownVerb, "dev_a"); got != 3 {
		t.Errorf("dev_a counter = %d, want 3", got)
	}
	if got := s.counters.Get(counters.SignalUnknownVerb, "dev_b"); got != 1 {
		t.Errorf("dev_b counter = %d, want 1", got)
	}
}

func TestHandleMessage_UnknownVerb_DifferentVerbsShareSignal(t *testing.T) {
	// Different unknown verbs all fire the same SignalUnknownVerb — the
	// counter is per-(signal, device), not per-verb. Verb appears in the
	// log line for forensics but not in the counter key (keeps
	// cardinality bounded per Phase 17 Step 2's design).
	var encBuf bytes.Buffer
	var logBuf bytes.Buffer
	s := newRejectTestServer(t, &logBuf)
	c := newRejectTestClient("dev_multi", &encBuf)

	s.handleMessage(c, "verb_one", json.RawMessage(`{"type":"verb_one"}`))
	s.handleMessage(c, "verb_two", json.RawMessage(`{"type":"verb_two"}`))
	s.handleMessage(c, "verb_three", json.RawMessage(`{"type":"verb_three"}`))

	if got := s.counters.Get(counters.SignalUnknownVerb, "dev_multi"); got != 3 {
		t.Errorf("counter = %d, want 3 (three distinct unknown verbs share the signal)", got)
	}

	// All three verbs appear in the logs — forensics-friendly.
	logOut := logBuf.String()
	for _, verb := range []string{"verb_one", "verb_two", "verb_three"} {
		if !strings.Contains(logOut, verb) {
			t.Errorf("log missing verb %q in: %q", verb, logOut)
		}
	}
}

func TestHandleMessage_KnownVerb_DoesNotFireUnknownVerbSignal(t *testing.T) {
	// Known verbs that reach other dispatch cases must NOT increment the
	// unknown-verb counter, even if they reject for other reasons.
	// Covers the risk of an accidental fall-through.
	var encBuf bytes.Buffer
	var logBuf bytes.Buffer
	s := newRejectTestServer(t, &logBuf)
	c := newRejectTestClient("dev_known", &encBuf)

	// "typing" is a known verb. Calling the dispatcher with malformed
	// payload will likely fail inside handleTyping, but it must NOT
	// route through the default case. We only check that the
	// unknown-verb counter stays at zero; whether handleTyping itself
	// logs something is orthogonal.
	defer func() {
		// handleTyping may panic on completely empty input — swallow it;
		// this test is about the dispatcher's routing, not handleTyping's
		// own input-validation behavior.
		_ = recover()
	}()
	s.handleMessage(c, "typing", json.RawMessage(`{"type":"typing"}`))

	if got := s.counters.Get(counters.SignalUnknownVerb, "dev_known"); got != 0 {
		t.Errorf("known verb should not fire unknown_verb signal; got count %d", got)
	}
}
