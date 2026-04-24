package server

import (
	"net"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

type fakeConnMetadata struct {
	remote net.Addr
	local  net.Addr
}

func (f fakeConnMetadata) User() string          { return "test" }
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
