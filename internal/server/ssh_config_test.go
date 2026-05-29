package server

import (
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// TestSecureSSHConfig_PolicyContract pins the algorithm allowlist's policy
// (audit S4): AEAD-only ciphers, PQ-hybrid KEX preferred, ETM-SHA2 MACs, and no
// weak primitive anywhere.
func TestSecureSSHConfig_PolicyContract(t *testing.T) {
	cfg := secureSSHConfig()

	if len(cfg.KeyExchanges) == 0 || cfg.KeyExchanges[0] != ssh.KeyExchangeMLKEM768X25519 {
		t.Errorf("KeyExchanges = %v, want %q first (PQ-hybrid preferred)", cfg.KeyExchanges, ssh.KeyExchangeMLKEM768X25519)
	}

	aead := map[string]bool{
		ssh.CipherChaCha20Poly1305: true,
		ssh.CipherAES256GCM:        true,
		ssh.CipherAES128GCM:        true,
	}
	if len(cfg.Ciphers) == 0 {
		t.Fatal("Ciphers must be pinned")
	}
	for _, c := range cfg.Ciphers {
		if !aead[c] {
			t.Errorf("non-AEAD cipher %q pinned", c)
		}
	}

	for _, m := range cfg.MACs {
		if !strings.HasPrefix(m, "hmac-sha2-") || !strings.HasSuffix(m, "-etm@openssh.com") {
			t.Errorf("MAC %q is not ETM-SHA2", m)
		}
	}

	for _, list := range [][]string{cfg.Ciphers, cfg.KeyExchanges, cfg.MACs} {
		for _, alg := range list {
			for _, weak := range []string{"cbc", "3des", "arcfour", "rc4", "sha1", "md5"} {
				if strings.Contains(alg, weak) {
					t.Errorf("weak algorithm %q (matches %q) pinned", alg, weak)
				}
			}
		}
	}
}

// TestNewServer_WiresPinnedSSHConfig guards that New() actually wires the pin
// into the live server config — deleting the `Config: secureSSHConfig()` line
// would silently revert to x/crypto defaults, and this catches that.
func TestNewServer_WiresPinnedSSHConfig(t *testing.T) {
	s := newTestServer(t)

	want := secureSSHConfig()
	got := s.sshCfg.Config
	if len(got.KeyExchanges) == 0 || got.KeyExchanges[0] != want.KeyExchanges[0] {
		t.Errorf("server KeyExchanges = %v, want pinned %v", got.KeyExchanges, want.KeyExchanges)
	}
	if len(got.Ciphers) != len(want.Ciphers) {
		t.Errorf("server Ciphers = %v, want pinned %v (pin not wired?)", got.Ciphers, want.Ciphers)
	}
}

// TestSecureSSHConfig_HandshakeEnforcement is the end-to-end proof (audit S4):
// the pinned server config completes a handshake with a client offering the
// same pin, and REJECTS a client that offers only a non-AEAD (weak) cipher.
// This also proves the pinned algorithm names are real and mutually
// negotiable — the contract test alone cannot.
//
// Uses a real TCP loopback rather than net.Pipe: SSH sends KEXINIT from both
// ends simultaneously, which deadlocks on a synchronous unbuffered pipe.
func TestSecureSSHConfig_HandshakeEnforcement(t *testing.T) {
	hostSigner := sshConfigTestSigner(t)

	// listen accepts exactly one connection and runs the pinned server-side
	// handshake on it, reporting the handshake result on the returned channel.
	// NoClientAuth is test-only: this exercises transport algorithm
	// negotiation, which happens (and, for the negative case, fails) before any
	// authentication step. Production config has no NoClientAuth.
	listen := func(t *testing.T) (string, chan error) {
		t.Helper()
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		t.Cleanup(func() { ln.Close() })
		srvErr := make(chan error, 1)
		go func() {
			nc, err := ln.Accept()
			if err != nil {
				srvErr <- err
				return
			}
			defer nc.Close()
			sc := &ssh.ServerConfig{Config: secureSSHConfig(), NoClientAuth: true}
			sc.AddHostKey(hostSigner)
			conn, chans, reqs, err := ssh.NewServerConn(nc, sc)
			if err != nil {
				srvErr <- err
				return
			}
			go ssh.DiscardRequests(reqs)
			go func() {
				for ch := range chans {
					_ = ch.Reject(ssh.Prohibited, "test")
				}
			}()
			srvErr <- nil
			conn.Wait()
		}()
		return ln.Addr().String(), srvErr
	}

	t.Run("matching pin negotiates", func(t *testing.T) {
		addr, srvErr := listen(t)
		cc := &ssh.ClientConfig{
			Config:          secureSSHConfig(),
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
			Timeout:         5 * time.Second,
		}
		client, err := ssh.Dial("tcp", addr, cc)
		if err != nil {
			t.Fatalf("handshake with matching pin failed: %v", err)
		}
		client.Close()
		if err := <-srvErr; err != nil {
			t.Fatalf("server side: %v", err)
		}
	})

	t.Run("weak-only client rejected", func(t *testing.T) {
		addr, srvErr := listen(t)
		cc := &ssh.ClientConfig{
			Config:          ssh.Config{Ciphers: []string{ssh.InsecureCipherAES128CBC}},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
			Timeout:         5 * time.Second,
		}
		if client, err := ssh.Dial("tcp", addr, cc); err == nil {
			client.Close()
			t.Fatal("expected weak-only client to be rejected at cipher negotiation, got success")
		}
		if err := <-srvErr; err == nil {
			t.Error("server accepted a weak-only client")
		}
	})
}

func sshConfigTestSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	sg, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	return sg
}
