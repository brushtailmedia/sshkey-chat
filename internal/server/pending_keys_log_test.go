package server

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLogPendingKey_WritesToDataDirPath(t *testing.T) {
	root := t.TempDir()
	configDir := filepath.Join(root, "config")
	dataDir := filepath.Join(root, "var")
	if err := os.MkdirAll(configDir, 0755); err != nil {
		t.Fatalf("mkdir config dir: %v", err)
	}

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

	const fp = "SHA256:test-pending-log-path"
	s.logPendingKey(fp, "127.0.0.1:2222")

	wantPath := filepath.Join(dataDir, "data", "pending-keys.log")
	b, err := os.ReadFile(wantPath)
	if err != nil {
		t.Fatalf("read %s: %v", wantPath, err)
	}
	if !strings.Contains(string(b), "fingerprint="+fp) {
		t.Fatalf("pending log missing fingerprint; got %q", string(b))
	}

	legacyPath := filepath.Join(filepath.Dir(cfg.Dir), "data", "pending-keys.log")
	if legacyPath != wantPath {
		if _, err := os.Stat(legacyPath); err == nil {
			t.Fatalf("unexpected legacy pending log path exists: %s", legacyPath)
		}
	}
}
