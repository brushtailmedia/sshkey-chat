package push

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func testAPNsSender(t *testing.T, status int) *APNsSender {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ecdsa key: %v", err)
	}

	return &APNsSender{
		key:      key,
		keyID:    "kid",
		teamID:   "team",
		bundleID: "com.example.test",
		endpoint: "https://example.invalid",
		client: &http.Client{
			Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: status,
					Body:       io.NopCloser(bytes.NewReader(nil)),
					Header:     make(http.Header),
					Request:    req,
				}, nil
			}),
		},
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

func TestAPNsSend_ShortToken_ErrorBranchesDoNotPanic(t *testing.T) {
	cases := []struct {
		name      string
		status    int
		wantValid bool
		wantErr   bool
	}{
		{name: "bad_request_400", status: 400, wantValid: false, wantErr: false},
		{name: "gone_410", status: 410, wantValid: false, wantErr: false},
		{name: "server_error_500", status: 500, wantValid: true, wantErr: true},
	}

	shortTokens := []string{"", "a", "1234567"}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sender := testAPNsSender(t, tc.status)
			for _, tok := range shortTokens {
				t.Run(fmt.Sprintf("token_%q", tok), func(t *testing.T) {
					valid, err := sender.Send(tok)
					if valid != tc.wantValid {
						t.Fatalf("valid = %v, want %v", valid, tc.wantValid)
					}
					if tc.wantErr && err == nil {
						t.Fatalf("expected error for status %d", tc.status)
					}
					if !tc.wantErr && err != nil {
						t.Fatalf("unexpected error for status %d: %v", tc.status, err)
					}
				})
			}
		})
	}
}
