package protocol

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestOpaqueReject_ExactShape(t *testing.T) {
	// The Phase 14 privacy invariant requires byte-identical response shape
	// for all Category D rejections — non-member, unknown-room, deleted-row
	// must all look the same on the wire so probing clients cannot
	// distinguish. Assert the exact constructor output.
	got := OpaqueReject()
	if got.Type != "error" {
		t.Errorf("Type = %q, want %q", got.Type, "error")
	}
	if got.Code != CodeDenied {
		t.Errorf("Code = %q, want %q", got.Code, CodeDenied)
	}
	if got.Code != "denied" {
		t.Errorf("CodeDenied value = %q, want %q — wire contract", got.Code, "denied")
	}
	if got.Message != "operation rejected" {
		t.Errorf("Message = %q, want %q — wire contract", got.Message, "operation rejected")
	}
	if got.Ref != "" {
		t.Errorf("Ref = %q, want empty", got.Ref)
	}
	if got.RetryAfterMs != 0 {
		t.Errorf("RetryAfterMs = %d, want 0", got.RetryAfterMs)
	}
}

func TestOpaqueReject_JSONRoundTrip(t *testing.T) {
	orig := OpaqueReject()
	b, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// Privacy invariant: no extra fields on the wire. Ref and RetryAfterMs
	// must be omitted via omitempty.
	s := string(b)
	if strings.Contains(s, "ref") {
		t.Errorf("JSON contains 'ref' field: %s", s)
	}
	if strings.Contains(s, "retry_after_ms") {
		t.Errorf("JSON contains 'retry_after_ms' field: %s", s)
	}

	var round Error
	if err := json.Unmarshal(b, &round); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if round.Type != orig.Type || round.Code != orig.Code || round.Message != orig.Message {
		t.Errorf("round-trip changed fields: orig=%+v round=%+v", orig, round)
	}
}

func TestRateLimit_WithBackoff(t *testing.T) {
	got := RateLimit(5000)
	if got.Type != "error" {
		t.Errorf("Type = %q, want %q", got.Type, "error")
	}
	if got.Code != CodeRateLimit {
		t.Errorf("Code = %q, want %q", got.Code, CodeRateLimit)
	}
	if got.Code != "rate_limited" {
		t.Errorf("CodeRateLimit value = %q, want %q — wire contract", got.Code, "rate_limited")
	}
	if got.Message != "please slow down" {
		t.Errorf("Message = %q, want %q", got.Message, "please slow down")
	}
	if got.RetryAfterMs != 5000 {
		t.Errorf("RetryAfterMs = %d, want 5000", got.RetryAfterMs)
	}
}

func TestRateLimit_ZeroBackoff(t *testing.T) {
	// Zero retry hint is valid — caller has no specific backoff to suggest.
	// RetryAfterMs uses `omitempty` so zero should be elided from wire.
	got := RateLimit(0)
	if got.RetryAfterMs != 0 {
		t.Errorf("RetryAfterMs = %d, want 0", got.RetryAfterMs)
	}
	b, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(b), "retry_after_ms") {
		t.Errorf("zero RetryAfterMs should be omitted, got: %s", string(b))
	}
}

func TestRateLimit_JSONRoundTrip(t *testing.T) {
	orig := RateLimit(3000)
	b, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(b), `"retry_after_ms":3000`) {
		t.Errorf("expected retry_after_ms:3000 in JSON, got: %s", string(b))
	}
	var round Error
	if err := json.Unmarshal(b, &round); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if round.RetryAfterMs != 3000 {
		t.Errorf("round-trip RetryAfterMs = %d, want 3000", round.RetryAfterMs)
	}
}

func TestMalformedField_FormatAndFields(t *testing.T) {
	got := MalformedField("file_ids", "too many")
	if got.Type != "error" {
		t.Errorf("Type = %q, want %q", got.Type, "error")
	}
	if got.Code != CodeMalformed {
		t.Errorf("Code = %q, want %q", got.Code, CodeMalformed)
	}
	if got.Code != "malformed" {
		t.Errorf("CodeMalformed value = %q, want %q — wire contract", got.Code, "malformed")
	}
	want := "file_ids: too many"
	if got.Message != want {
		t.Errorf("Message = %q, want %q", got.Message, want)
	}
}

func TestMalformedField_JSONRoundTrip(t *testing.T) {
	orig := MalformedField("wrapped_keys", "exceeds member cap")
	b, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var round Error
	if err := json.Unmarshal(b, &round); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if round.Message != orig.Message {
		t.Errorf("round-trip Message changed: orig=%q round=%q", orig.Message, round.Message)
	}
	if round.Code != orig.Code {
		t.Errorf("round-trip Code changed: orig=%q round=%q", orig.Code, round.Code)
	}
}

func TestWireCodes_StableValues(t *testing.T) {
	// Wire codes are stable protocol tokens. Changing their string values
	// is a protocol-breaking change — guard against accidental edits.
	cases := []struct {
		name, got, want string
	}{
		{"CodeDenied", CodeDenied, "denied"},
		{"CodeRateLimit", CodeRateLimit, "rate_limited"},
		{"CodeMalformed", CodeMalformed, "malformed"},
		{"CodeInvalidID", CodeInvalidID, "invalid_id"},
		{"CodeTooLarge", CodeTooLarge, "payload_too_large"},
		{"CodeUnknownVerb", CodeUnknownVerb, "unknown_verb"},
		{"CodeInternal", CodeInternal, "internal_error"},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s = %q, want %q", c.name, c.got, c.want)
		}
	}
}

func TestError_JSONOmitsEmptyFields(t *testing.T) {
	// Baseline Error with minimal fields should serialize without the
	// optional omitempty fields.
	e := &Error{Type: "error", Code: "x", Message: "y"}
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	s := string(b)
	if strings.Contains(s, "ref") {
		t.Errorf("empty Ref should be omitted: %s", s)
	}
	if strings.Contains(s, "retry_after_ms") {
		t.Errorf("zero RetryAfterMs should be omitted: %s", s)
	}
}
