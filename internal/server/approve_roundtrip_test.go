package server

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"net"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// TestAuthenticateKey_ApproveRoundTrip locks the store↔auth key-normalization
// contract (audit S10 #6). The store path (`sshkey-ctl approve` → InsertUser)
// keeps the comment-stripped `type base64` form of the operator-pasted key,
// while the auth path (authenticateKey → MarshalAuthorizedKey → GetUserByKey)
// looks up the canonical re-serialization of the presented key. For a valid
// key these coincide, but if the two normalizations ever drift a key could be
// approved yet fail to log in (a fail-closed lockout). This round-trip — store
// as approve does, then authenticate via the real auth path — catches any such
// drift, across pasted-line variants (comment, trailing whitespace, multi-word
// comment).
func TestAuthenticateKey_ApproveRoundTrip(t *testing.T) {
	s := newTestServer(t)

	cases := []struct {
		name   string
		suffix string // appended to the canonical authorized-key line before storing
	}{
		{"canonical", ""},
		{"with comment", " operator@laptop"},
		{"trailing whitespace", "   "},
		{"multi-word comment", " my work laptop"},
	}

	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, priv, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatalf("genkey: %v", err)
			}
			signer, err := ssh.NewSignerFromKey(priv)
			if err != nil {
				t.Fatalf("signer: %v", err)
			}
			pub := signer.PublicKey()

			// The line an operator pastes into `approve` (canonical authorized
			// key + optional comment/whitespace). InsertUser normalizes it the
			// same way cmdApprove does (strings.Fields → "type base64").
			pasted := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub))) + tc.suffix
			uid := fmt.Sprintf("usr_rt_%d", i)
			if err := s.store.InsertUser(uid, pasted, fmt.Sprintf("RoundTrip%d", i)); err != nil {
				t.Fatalf("InsertUser: %v", err)
			}

			// Authenticate with the parsed key via the real auth path. Distinct
			// source IP per subtest so the per-IP auth rate limiter can't
			// interfere between cases.
			conn := fakeConnMetadata{
				remote: &net.TCPAddr{IP: net.ParseIP(fmt.Sprintf("10.0.0.%d", i+1)), Port: 40000},
				local:  &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 2222},
			}
			perms, err := s.authenticateKey(conn, pub)
			if err != nil {
				t.Fatalf("approved key (%s) failed to authenticate: %v", tc.name, err)
			}
			if perms == nil || perms.Extensions["username"] != uid {
				t.Fatalf("authenticated as %+v, want username=%s", perms, uid)
			}
		})
	}
}
