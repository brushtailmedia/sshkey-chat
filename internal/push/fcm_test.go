package push

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"testing"
	"time"
)

func TestFCMSend_ShortToken_UnregisteredPathDoesNotPanic(t *testing.T) {
	sender := &FCMSender{
		endpoint: "https://example.invalid",
		client: &http.Client{
			Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusBadRequest,
					Body: io.NopCloser(bytes.NewBufferString(
						`{"error":{"details":[{"errorCode":"UNREGISTERED"}]}}`,
					)),
					Header:  make(http.Header),
					Request: req,
				}, nil
			}),
		},
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		// Pre-seed a valid token so Send() does not attempt OAuth exchange.
		token:    "cached_access_token",
		tokenExp: time.Now().Add(10 * time.Minute),
	}

	for _, tok := range []string{"", "a", "1234567"} {
		t.Run(tok, func(t *testing.T) {
			valid, err := sender.Send(tok)
			if valid {
				t.Fatalf("valid = true, want false for UNREGISTERED token")
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}
