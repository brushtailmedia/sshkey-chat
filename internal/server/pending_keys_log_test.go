package server

import (
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/brushtailmedia/sshkey-chat/internal/protocol"
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

	seedTestUser(t, s, "alice", testKeyAlice, "Alice", true, nil)
	admin := testClientFor("alice", "dev_alice_pending_admin_notify")
	s.mu.Lock()
	s.clients[admin.DeviceID] = admin.Client
	s.mu.Unlock()

	const fp = "SHA256:test-pending-db-row"
	const key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestPendingKey"
	s.logPendingKey(fp, "127.0.0.1:2222", key, "Alice")

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
	if rows[0].RequestedUsername != "Alice" {
		t.Errorf("requested_username = %q, want Alice", rows[0].RequestedUsername)
	}

	msgs := admin.messages()
	if len(msgs) != 1 {
		t.Fatalf("expected 1 admin_notify, got %d", len(msgs))
	}
	var notify protocol.AdminNotify
	if err := json.Unmarshal(msgs[0], &notify); err != nil {
		t.Fatalf("unmarshal admin_notify: %v", err)
	}
	if notify.Type != "admin_notify" || notify.Event != "pending_key" {
		t.Fatalf("admin notify type/event = %q/%q, want admin_notify/pending_key", notify.Type, notify.Event)
	}
	if notify.Fingerprint != fp {
		t.Errorf("admin notify fingerprint = %q, want %q", notify.Fingerprint, fp)
	}
	if notify.Attempts != 1 {
		t.Errorf("admin notify attempts = %d, want 1", notify.Attempts)
	}
	if notify.FirstSeen == "" {
		t.Error("admin notify first_seen should be non-empty")
	}
	if notify.RequestedUsername != "Alice" {
		t.Errorf("admin notify requested_username = %q, want Alice", notify.RequestedUsername)
	}

	// A repeat attempt bumps the counter and updates the remote (server-level
	// integration of the UPSERT) without adding a row. The EMPTY hint here
	// (e.g. a term reconnect sending no SSH username) must NOT clobber the
	// captured name — DP4 latest-non-empty.
	s.logPendingKey(fp, "10.0.0.1:3333", key, "")
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
	if rows[0].RequestedUsername != "Alice" {
		t.Errorf("empty reconnect clobbered hint = %q, want Alice preserved", rows[0].RequestedUsername)
	}
	if got := len(admin.messages()); got != 1 {
		t.Fatalf("repeat pending attempt should not send another admin_notify, got %d total messages", got)
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
