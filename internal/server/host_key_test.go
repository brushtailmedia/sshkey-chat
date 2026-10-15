package server

// Host-key relocation (relocate-host-key): the key lives at
// <dataDir>/data/host_key — not in the config dir — so the config dir can
// be root-owned/read-only. These lock the generation path + mode, the
// load-not-regenerate property, the empty-dataDir guard, and the headline
// "boots with a read-only config dir" property.

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/brushtailmedia/sshkey-chat/internal/config"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestLoadOrGenerateHostKey_WritesToDataSubdirNotConfigDir(t *testing.T) {
	dataDir := t.TempDir() // deliberately NOT creating data/ — proves the MkdirAll
	s := &Server{logger: discardLogger(), dataDir: dataDir}

	signer, err := s.loadOrGenerateHostKey()
	if err != nil {
		t.Fatalf("loadOrGenerateHostKey: %v", err)
	}
	keyPath := filepath.Join(dataDir, "data", "host_key")
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("host key not written at %s: %v", keyPath, err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("host key mode = %o, want 0600", info.Mode().Perm())
	}
	first := ssh.FingerprintSHA256(signer.PublicKey())

	// A second server on the same data dir must LOAD, not regenerate.
	s2 := &Server{logger: discardLogger(), dataDir: dataDir}
	signer2, err := s2.loadOrGenerateHostKey()
	if err != nil {
		t.Fatalf("second loadOrGenerateHostKey: %v", err)
	}
	if got := ssh.FingerprintSHA256(signer2.PublicKey()); got != first {
		t.Fatalf("host key regenerated on reload: %s != %s", got, first)
	}
}

func TestLoadOrGenerateHostKey_EmptyDataDirErrors(t *testing.T) {
	s := &Server{logger: discardLogger()}
	if _, err := s.loadOrGenerateHostKey(); err == nil {
		t.Fatal("expected an error with no data directory (CWD-relative key path would be a silent regeneration trap)")
	} else if want := "data directory"; !strings.Contains(err.Error(), want) {
		t.Fatalf("error = %q, want it to mention %q", err, want)
	}
}

// TestNew_BootsWithReadOnlyConfigDir is the relocation's headline property:
// the server must start with a config dir it cannot write to, because the
// host key — its only former config-dir write — now lives in the data dir.
func TestNew_BootsWithReadOnlyConfigDir(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses chmod; the read-only property cannot be observed")
	}
	configDir := t.TempDir()
	dataDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(configDir, "server.toml"), []byte(`
[server]
port = 2222
bind = "127.0.0.1"

[server.auto_revoke]
enabled = false
`), 0644); err != nil {
		t.Fatalf("write server.toml: %v", err)
	}
	cfg, err := config.Load(configDir)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if err := os.Chmod(configDir, 0555); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(configDir, 0755) }) // so TempDir cleanup can delete it

	s, err := New(cfg, discardLogger(), dataDir)
	if err != nil {
		t.Fatalf("New with a read-only config dir: %v", err)
	}
	t.Cleanup(func() {
		if s.store != nil {
			s.store.Close()
		}
		// Don't run Close() — ListenAndServe never ran, so the listener
		// fields are nil (same pattern as newSchedulerTestServer).
		_ = os.Remove(filepath.Join(dataDir, lockfileName))
	})

	if _, err := os.Stat(filepath.Join(dataDir, "data", "host_key")); err != nil {
		t.Fatalf("host key must be generated under the data dir: %v", err)
	}
	if _, err := os.Stat(filepath.Join(configDir, "host_key")); !os.IsNotExist(err) {
		t.Fatalf("nothing may be written into the config dir (stat err = %v)", err)
	}
}
