package server

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReloadServerConfig_ReloadsAutoRevokeAndQuotaSections(t *testing.T) {
	s := newTestServer(t)

	s.cfg.RLock()
	initialAutoRevoke := s.cfg.Server.Server.AutoRevoke.Enabled
	initialQuota := s.cfg.Server.Server.Quotas.User.Enabled
	s.cfg.RUnlock()

	if initialAutoRevoke {
		t.Fatal("test setup: expected auto_revoke to start disabled")
	}

	updated := `
[server]
port = 2222
bind = "127.0.0.1"

[server.auto_revoke]
enabled = true
prune_after_hours = 24

[server.auto_revoke.thresholds]
reconnect_flood = "3:60"

[server.quotas.user]
enabled = false
allow_exempt_users = true
daily_upload_bytes_warn = "2KB"
daily_upload_bytes_block = "4KB"
flag_consecutive_days = 2
retention_days = 7
`
	if err := os.WriteFile(filepath.Join(s.cfg.Dir, "server.toml"), []byte(updated), 0644); err != nil {
		t.Fatalf("write updated server.toml: %v", err)
	}

	s.reloadServerConfig()

	s.cfg.RLock()
	defer s.cfg.RUnlock()

	if !s.cfg.Server.Server.AutoRevoke.Enabled {
		t.Fatal("reload should apply [server.auto_revoke].enabled")
	}
	if s.cfg.Server.Server.AutoRevoke.PruneAfterHours != 24 {
		t.Fatalf("prune_after_hours = %d, want 24", s.cfg.Server.Server.AutoRevoke.PruneAfterHours)
	}
	if got := s.cfg.Server.Server.AutoRevoke.Thresholds["reconnect_flood"]; got != "3:60" {
		t.Fatalf("auto_revoke reconnect_flood threshold = %q, want 3:60", got)
	}
	if s.cfg.Server.Server.Quotas.User.Enabled {
		t.Fatal("reload should apply [server.quotas.user].enabled=false")
	}
	if !s.cfg.Server.Server.Quotas.User.AllowExemptUsers {
		t.Fatal("reload should apply allow_exempt_users=true")
	}
	if s.cfg.Server.Server.Quotas.User.DailyUploadBytesWarn != "2KB" {
		t.Fatalf("daily_upload_bytes_warn = %q, want 2KB", s.cfg.Server.Server.Quotas.User.DailyUploadBytesWarn)
	}
	if s.cfg.Server.Server.Quotas.User.DailyUploadBytesBlock != "4KB" {
		t.Fatalf("daily_upload_bytes_block = %q, want 4KB", s.cfg.Server.Server.Quotas.User.DailyUploadBytesBlock)
	}
	if s.cfg.Server.Server.Quotas.User.RetentionDays != 7 {
		t.Fatalf("retention_days = %d, want 7", s.cfg.Server.Server.Quotas.User.RetentionDays)
	}

	_ = initialQuota
}
