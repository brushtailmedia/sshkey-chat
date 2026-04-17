package server

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/brushtailmedia/sshkey-chat/internal/counters"
	"github.com/brushtailmedia/sshkey-chat/internal/protocol"
)

// newRejectTestServer returns a minimally-initialized *Server suitable for
// rejectAndLog smoke tests — just counters + logger wired up. No real
// store, no SSH config, no channels.
func newRejectTestServer(t *testing.T, logWriter io.Writer) *Server {
	t.Helper()
	var logger *slog.Logger
	if logWriter == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	} else {
		logger = slog.New(slog.NewTextHandler(logWriter, &slog.HandlerOptions{Level: slog.LevelWarn}))
	}
	return &Server{
		logger:   logger,
		counters: counters.New(),
	}
}

// newRejectTestClient returns a minimally-initialized *Client whose Encoder writes
// to the supplied buffer. Suitable for asserting on the wire output of
// rejectAndLog when it encodes a clientErr.
func newRejectTestClient(deviceID string, encBuf *bytes.Buffer) *Client {
	return &Client{
		UserID:   "usr_test",
		DeviceID: deviceID,
		Encoder:  protocol.NewEncoder(encBuf),
	}
}

func TestRejectAndLog_NonNilClient_NonNilErr_EncodesResponse(t *testing.T) {
	var encBuf bytes.Buffer
	var logBuf bytes.Buffer
	s := newRejectTestServer(t, &logBuf)
	c := newRejectTestClient("dev_abc", &encBuf)

	s.rejectAndLog(c, counters.SignalInvalidNanoID, "send",
		"bad nanoid in Room field", protocol.OpaqueReject())

	// Counter incremented.
	if got := s.counters.Get(counters.SignalInvalidNanoID, "dev_abc"); got != 1 {
		t.Errorf("counter after rejection = %d, want 1", got)
	}

	// Log line emitted with expected fields.
	logOut := logBuf.String()
	for _, want := range []string{"rejection", "invalid_nanoid", "dev_abc", "send", "count=1"} {
		if !strings.Contains(logOut, want) {
			t.Errorf("log missing %q in: %q", want, logOut)
		}
	}

	// Client response encoded on the wire — exactly the OpaqueReject shape.
	var got protocol.Error
	if err := json.Unmarshal(bytes.TrimSpace(encBuf.Bytes()), &got); err != nil {
		t.Fatalf("unmarshal encoded error: %v", err)
	}
	if got.Type != "error" || got.Code != protocol.CodeDenied || got.Message != "operation rejected" {
		t.Errorf("encoded response = %+v, want OpaqueReject shape", got)
	}
}

func TestRejectAndLog_NonNilClient_NilErr_NoEncode(t *testing.T) {
	var encBuf bytes.Buffer
	s := newRejectTestServer(t, nil)
	c := newRejectTestClient("dev_abc", &encBuf)

	s.rejectAndLog(c, counters.SignalOversizedUploadFrame, "upload",
		"frame exceeds MaxFileSize", nil)

	// Counter incremented.
	if got := s.counters.Get(counters.SignalOversizedUploadFrame, "dev_abc"); got != 1 {
		t.Errorf("counter = %d, want 1", got)
	}

	// No bytes written to the client — nil clientErr means skip encode.
	if encBuf.Len() != 0 {
		t.Errorf("nil clientErr should not write to client, got: %q", encBuf.String())
	}
}

func TestRejectAndLog_NilClient_NilErr_StillCountsAndLogs(t *testing.T) {
	var logBuf bytes.Buffer
	s := newRejectTestServer(t, &logBuf)

	s.rejectAndLog(nil, counters.SignalOversizedUploadFrame, "upload_frame",
		"frame arrived before upload_start", nil)

	// Counter incremented under the empty-deviceID bucket. (The counters
	// package emits its own slog.Warn for the empty deviceID — expected
	// in the Channel 3 unattributed case.)
	if got := s.counters.Get(counters.SignalOversizedUploadFrame, ""); got != 1 {
		t.Errorf("counter under empty deviceID = %d, want 1", got)
	}

	// Primary rejection log still fires.
	if !strings.Contains(logBuf.String(), "rejection") {
		t.Errorf("expected 'rejection' log line, got: %q", logBuf.String())
	}
}

func TestRejectAndLog_NilClient_NonNilErr_DoesNotPanic(t *testing.T) {
	// Defensive: caller passes a non-nil clientErr with a nil client.
	// The helper should not attempt to encode (there's no client to
	// encode to) and should not panic.
	s := newRejectTestServer(t, nil)
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("rejectAndLog panicked: %v", r)
		}
	}()
	s.rejectAndLog(nil, counters.SignalMalformedFrame, "unknown",
		"malformed JSON pre-attribution", protocol.OpaqueReject())
	if got := s.counters.Get(counters.SignalMalformedFrame, ""); got != 1 {
		t.Errorf("counter = %d, want 1", got)
	}
}

func TestRejectAndLog_MultipleCallsAccumulateCounters(t *testing.T) {
	s := newRejectTestServer(t, nil)
	var encBuf bytes.Buffer
	c := newRejectTestClient("dev_x", &encBuf)

	for i := 0; i < 5; i++ {
		s.rejectAndLog(c, counters.SignalInvalidNanoID, "send", "bad id", protocol.OpaqueReject())
	}
	if got := s.counters.Get(counters.SignalInvalidNanoID, "dev_x"); got != 5 {
		t.Errorf("counter after 5 calls = %d, want 5", got)
	}
	// Each call encodes a response to the client.
	lines := bytes.Count(bytes.TrimSpace(encBuf.Bytes()), []byte("\n")) + 1
	if lines != 5 {
		t.Errorf("encoded %d responses, want 5", lines)
	}
}

func TestRejectAndLog_LogIncludesRetryAfterMsReason(t *testing.T) {
	// Sanity check that logReason with structured data (e.g. a retry hint
	// inlined in the reason string) survives formatting.
	var logBuf bytes.Buffer
	s := newRejectTestServer(t, &logBuf)
	var encBuf bytes.Buffer
	c := newRejectTestClient("dev_z", &encBuf)

	s.rejectAndLog(c, counters.SignalRateLimited, "send",
		"rate-limit floor 30/min exceeded", protocol.RateLimit(5000))

	logOut := logBuf.String()
	if !strings.Contains(logOut, "rate-limit floor") {
		t.Errorf("log missing reason text: %q", logOut)
	}

	// Wire response carries the retry hint.
	var got protocol.Error
	if err := json.Unmarshal(bytes.TrimSpace(encBuf.Bytes()), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.RetryAfterMs != 5000 {
		t.Errorf("RetryAfterMs = %d, want 5000", got.RetryAfterMs)
	}
}
