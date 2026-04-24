package server

// Phase 19 Step 2 — integration tests that exercise the lockfile
// behavior through Server.New + Server.Close, not just the lockfile
// package in isolation. Covers:
//
//   - Server.New writes the lockfile at <dataDir>/sshkey-server.pid
//   - A second Server.New against the same dataDir is refused while
//     the first instance holds the lockfile (double-start protection)
//   - Server.Close removes the lockfile cleanly
//   - After a clean Close, a fresh Server.New on the same dataDir
//     succeeds (no stale-file block)

import (
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/brushtailmedia/sshkey-chat/internal/config"
	"github.com/brushtailmedia/sshkey-chat/internal/lockfile"
)

// minimalServerConfig writes a minimal server.toml to the given
// configDir and loads it. Separated from newTestServer because this
// test exercises the lockfile BEFORE reaching user seeding.
func minimalServerConfig(t *testing.T, configDir string) *config.Config {
	t.Helper()
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
	return cfg
}

func TestServerNew_WritesLockfile(t *testing.T) {
	configDir := t.TempDir()
	dataDir := t.TempDir()
	cfg := minimalServerConfig(t, configDir)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	s, err := New(cfg, logger, dataDir)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	t.Cleanup(func() {
		if s.store != nil {
			s.store.Close()
		}
	})

	lockPath := filepath.Join(dataDir, "sshkey-server.pid")
	info, err := lockfile.Read(lockPath)
	if err != nil {
		t.Fatalf("lockfile.Read: %v", err)
	}
	if info.PID != os.Getpid() {
		t.Errorf("lockfile PID = %d, want %d (this process)", info.PID, os.Getpid())
	}
	if !info.Alive {
		t.Error("lockfile Alive = false, want true")
	}
}

func TestServerNew_DoubleStartRefused(t *testing.T) {
	configDir := t.TempDir()
	dataDir := t.TempDir()
	cfg := minimalServerConfig(t, configDir)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// First instance takes the lockfile.
	s1, err := New(cfg, logger, dataDir)
	if err != nil {
		t.Fatalf("first New: %v", err)
	}
	t.Cleanup(func() {
		if s1.store != nil {
			s1.store.Close()
		}
	})

	// Second instance against the same dataDir must be refused.
	_, err = New(cfg, logger, dataDir)
	if err == nil {
		t.Fatal("second New on same dataDir should fail, got nil")
	}
	if !errors.Is(err, lockfile.ErrAlreadyRunning) {
		t.Errorf("second New err = %v, want ErrAlreadyRunning", err)
	}
}

func TestServerClose_RemovesLockfile(t *testing.T) {
	configDir := t.TempDir()
	dataDir := t.TempDir()
	cfg := minimalServerConfig(t, configDir)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	s, err := New(cfg, logger, dataDir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	lockPath := filepath.Join(dataDir, "sshkey-server.pid")

	// Lockfile exists pre-Close.
	if _, err := os.Stat(lockPath); err != nil {
		t.Fatalf("lockfile missing before Close: %v", err)
	}

	// Close with a zero grace period so the test doesn't wait 10s.
	// We override the config's grace period directly.
	s.cfg.Server.Shutdown.GracePeriod = "1ms"
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Lockfile gone post-Close.
	if _, err := os.Stat(lockPath); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("lockfile still present after Close: %v", err)
	}
}

func TestServerNew_SucceedsAfterCleanClose(t *testing.T) {
	configDir := t.TempDir()
	dataDir := t.TempDir()
	cfg := minimalServerConfig(t, configDir)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// First instance, clean shutdown.
	s1, err := New(cfg, logger, dataDir)
	if err != nil {
		t.Fatalf("first New: %v", err)
	}
	s1.cfg.Server.Shutdown.GracePeriod = "1ms"
	if err := s1.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}

	// Second instance on same dataDir should work — previous cleaned up.
	s2, err := New(cfg, logger, dataDir)
	if err != nil {
		t.Fatalf("second New after clean Close: %v", err)
	}
	t.Cleanup(func() {
		s2.cfg.Server.Shutdown.GracePeriod = "1ms"
		s2.Close()
	})
}
