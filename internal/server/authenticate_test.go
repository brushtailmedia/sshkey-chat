package server

import (
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

type fakeConnMetadata struct {
	user   string
	remote net.Addr
	local  net.Addr
}

func (f fakeConnMetadata) User() string          { return f.user }
func (f fakeConnMetadata) SessionID() []byte     { return []byte("session") }
func (f fakeConnMetadata) ClientVersion() []byte { return []byte("SSH-2.0-test") }
func (f fakeConnMetadata) ServerVersion() []byte { return []byte("SSH-2.0-sshkey-chat-test") }
func (f fakeConnMetadata) RemoteAddr() net.Addr  { return f.remote }
func (f fakeConnMetadata) LocalAddr() net.Addr   { return f.local }

var _ ssh.ConnMetadata = fakeConnMetadata{}

func TestAuthenticateKey_RetiredUserRejected(t *testing.T) {
	s := newTestServer(t)

	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(testKeyBob))
	if err != nil {
		t.Fatalf("ParseAuthorizedKey(testKeyBob): %v", err)
	}
	conn := fakeConnMetadata{
		remote: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 40000},
		local:  &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 2222},
	}

	// Baseline: bob authenticates before retirement.
	perms, err := s.authenticateKey(conn, pub)
	if err != nil {
		t.Fatalf("authenticateKey baseline: %v", err)
	}
	if perms == nil || perms.Extensions["username"] != "bob" {
		t.Fatalf("expected username=bob permissions, got %+v", perms)
	}

	// Policy gate: retired users are rejected at auth callback.
	if err := s.store.SetUserRetired("bob", "test_policy"); err != nil {
		t.Fatalf("SetUserRetired: %v", err)
	}

	perms, err = s.authenticateKey(conn, pub)
	if err == nil {
		t.Fatal("expected retired-user authentication to fail, got nil error")
	}
	if perms != nil {
		t.Fatalf("expected nil permissions on retired auth failure, got %+v", perms)
	}
	if !strings.Contains(strings.ToLower(err.Error()), "retired") {
		t.Fatalf("error = %q, want retired wording", err.Error())
	}
}

// TestAuthenticateKey_CapturesRequestedUsername exercises the full unknown-key
// callback seam: conn.User() → SanitizeRequestedNameHint → logPendingKey →
// pending_keys.requested_username. (Distinct source IPs so the per-IP auth
// rate limiter can't interfere between the two attempts.)
func TestAuthenticateKey_CapturesRequestedUsername(t *testing.T) {
	s := newTestServer(t)

	mkConn := func(user, ip string) fakeConnMetadata {
		return fakeConnMetadata{
			user:   user,
			remote: &net.TCPAddr{IP: net.ParseIP(ip), Port: 40000},
			local:  &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 2222},
		}
	}

	// A clean SSH username is captured as the hint.
	good := freshUnknownPub(t)
	if _, err := s.authenticateKey(mkConn("alice", "127.0.0.1"), good); err == nil {
		t.Fatal("unknown key should be rejected by authenticateKey")
	}
	if got := pendingHintFor(t, s, ssh.FingerprintSHA256(good)); got != "alice" {
		t.Errorf("requested_username = %q, want alice", got)
	}

	// A '+'-bearing username is rejected by the sanitizer → empty hint, but the
	// key is still recorded as a pending contact.
	bad := freshUnknownPub(t)
	if _, err := s.authenticateKey(mkConn("bad+name", "127.0.0.2"), bad); err == nil {
		t.Fatal("unknown key should be rejected by authenticateKey")
	}
	if got := pendingHintFor(t, s, ssh.FingerprintSHA256(bad)); got != "" {
		t.Errorf("rejected username should yield empty hint, got %q", got)
	}
}

func freshUnknownPub(t *testing.T) ssh.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("ssh pub: %v", err)
	}
	return sshPub
}

func pendingHintFor(t *testing.T, s *Server, fp string) string {
	t.Helper()
	rows, err := s.store.ListPendingKeys()
	if err != nil {
		t.Fatalf("list pending: %v", err)
	}
	for _, r := range rows {
		if r.Fingerprint == fp {
			return r.RequestedUsername
		}
	}
	t.Fatalf("no pending row for %s", fp)
	return ""
}
