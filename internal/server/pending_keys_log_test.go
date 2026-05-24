package server

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
)

// TestLogPendingKey_RecordsDBRowNoLogFile verifies that an unknown-key contact
// is recorded in the authoritative pending_keys table (with the pubkey) and
// that NO pending-keys.log file is created — the flat-log projection was
// removed in favor of the DB-backed `sshkey-ctl pending` view.
func TestLogPendingKey_RecordsDBRowNoLogFile(t *testing.T) {
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

	const fp = "SHA256:test-pending-db-row"
	const key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestPendingKey"
	s.logPendingKey(fp, "127.0.0.1:2222", key)

	// Recorded in the DB with the pubkey, attempts == 1.
	rows, err := s.store.ListPendingKeys()
	if err != nil {
		t.Fatalf("list pending: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 pending row, got %d", len(rows))
	}
	if rows[0].Fingerprint != fp {
		t.Errorf("fingerprint = %q, want %q", rows[0].Fingerprint, fp)
	}
	if rows[0].PubKey != key {
		t.Errorf("pubkey = %q, want %q", rows[0].PubKey, key)
	}
	if rows[0].Attempts != 1 {
		t.Errorf("attempts = %d, want 1", rows[0].Attempts)
	}

	// A repeat attempt bumps the counter and updates the remote (server-level
	// integration of the UPSERT) without adding a row.
	s.logPendingKey(fp, "10.0.0.1:3333", key)
	rows, _ = s.store.ListPendingKeys()
	if len(rows) != 1 {
		t.Fatalf("repeat should not add a row; got %d", len(rows))
	}
	if rows[0].Attempts != 2 {
		t.Errorf("attempts after repeat = %d, want 2", rows[0].Attempts)
	}
	if rows[0].RemoteAddr != "10.0.0.1:3333" {
		t.Errorf("remote_addr after repeat = %q, want updated", rows[0].RemoteAddr)
	}

	// No flat-log file is created anywhere.
	for _, p := range []string{
		filepath.Join(dataDir, "data", "pending-keys.log"),
		filepath.Join(filepath.Dir(cfg.Dir), "data", "pending-keys.log"),
	} {
		if _, err := os.Stat(p); err == nil {
			t.Fatalf("pending-keys.log should not be created, but found: %s", p)
		}
	}
}
