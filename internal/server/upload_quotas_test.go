package server

// Per-user upload quota server-side helper tests.
// Out-of-phase 2026-04-19, originally Phase 25.
//
// Coverage focuses on the helpers that don't require the full upload
// integration harness (which lives in cmd/sshkey-server/main_test.go-
// style end-to-end tests, deferred per the plan to Phase 22 item 11).
//
// In-scope here:
//   - quotaBlockedMessage rendering
//   - formatBytesQuota unit boundaries
//   - todayUTC + dateOffsetUTC return shape
//   - isSustainedPattern truth table
//   - parsedQuota wiring (config flips through)
//   - pruneOldQuotaRows no-op when disabled

import (
	"strings"
	"testing"
	"time"

	"github.com/brushtailmedia/sshkey-chat/internal/store"
)

// -------- quotaBlockedMessage --------

func TestQuotaBlockedMessage_RendersThreshold(t *testing.T) {
	cases := []struct {
		bytes int64
		want  string
	}{
		{5 * 1 << 30, "5.0 GB"},
		{10 * 1 << 30, "10.0 GB"},
		{500 * 1 << 20, "500.0 MB"},
		{1 << 30, "1.0 GB"},
	}
	for _, tc := range cases {
		msg := quotaBlockedMessage(tc.bytes)
		if !strings.Contains(msg, tc.want) {
			t.Errorf("quotaBlockedMessage(%d) = %q, want substring %q", tc.bytes, msg, tc.want)
		}
		if !strings.Contains(msg, "chat app") {
			t.Errorf("quotaBlockedMessage(%d) missing policy framing: %q", tc.bytes, msg)
		}
		if !strings.Contains(msg, "UTC midnight") {
			t.Errorf("quotaBlockedMessage(%d) missing reset cadence: %q", tc.bytes, msg)
		}
	}
}

// -------- formatBytesQuota boundaries --------

func TestFormatBytesQuota(t *testing.T) {
	cases := map[int64]string{
		0:           "0 B",
		512:         "512 B",
		1024:        "1.0 KB",
		1<<20 - 1:   "1024.0 KB",
		1 << 20:     "1.0 MB",
		1 << 30:     "1.0 GB",
		5 * 1 << 30: "5.0 GB",
	}
	for b, want := range cases {
		if got := formatBytesQuota(b); got != want {
			t.Errorf("formatBytesQuota(%d) = %q, want %q", b, got, want)
		}
	}
}

// -------- date helpers --------

func TestTodayUTC_HasExpectedShape(t *testing.T) {
	d := todayUTC()
	if len(d) != 10 {
		t.Errorf("todayUTC() = %q, want YYYY-MM-DD shape", d)
	}
	// Parse it round-trip to confirm valid date.
	if _, err := time.Parse("2006-01-02", d); err != nil {
		t.Errorf("todayUTC() = %q, not parseable as YYYY-MM-DD: %v", d, err)
	}
}

func TestDateOffsetUTC_GoesBackwards(t *testing.T) {
	today := todayUTC()
	yesterday := dateOffsetUTC(1)
	if yesterday >= today {
		t.Errorf("dateOffsetUTC(1) = %q, expected to be < today (%q)", yesterday, today)
	}
	// Sanity: 0 returns today.
	if got := dateOffsetUTC(0); got != today {
		t.Errorf("dateOffsetUTC(0) = %q, want today (%q)", got, today)
	}
}

// -------- isSustainedPattern truth table --------

func TestIsSustainedPattern(t *testing.T) {
	const warn = int64(1 << 30) // 1GB
	today := todayUTC()
	yesterday := dateOffsetUTC(1)
	dayBefore := dateOffsetUTC(2)

	cases := []struct {
		name           string
		recent         []store.DailyUploadRow
		consecutive    int
		want           bool
	}{
		{
			name:        "two contiguous days at warn → sustained=true",
			recent:      []store.DailyUploadRow{{Date: today, BytesTotal: warn}, {Date: yesterday, BytesTotal: warn + 100}},
			consecutive: 2,
			want:        true,
		},
		{
			name:        "two contiguous days, today over warn, yesterday under → sustained=false",
			recent:      []store.DailyUploadRow{{Date: today, BytesTotal: warn}, {Date: yesterday, BytesTotal: warn - 1}},
			consecutive: 2,
			want:        false,
		},
		{
			name: "non-contiguous (gap day) → sustained=false",
			recent: []store.DailyUploadRow{
				{Date: today, BytesTotal: warn + 100},
				{Date: dayBefore, BytesTotal: warn + 100}, // skip yesterday
			},
			consecutive: 2,
			want:        false,
		},
		{
			name:        "fewer rows than consecutive → false",
			recent:      []store.DailyUploadRow{{Date: today, BytesTotal: warn}},
			consecutive: 2,
			want:        false,
		},
		{
			name:        "consecutive=1 returns false (single day = plain warn, not sustained)",
			recent:      []store.DailyUploadRow{{Date: today, BytesTotal: warn}},
			consecutive: 1,
			want:        false,
		},
		{
			name:        "empty recent → false",
			recent:      nil,
			consecutive: 2,
			want:        false,
		},
		{
			name: "three contiguous days, all over warn, consecutive=3 → true",
			recent: []store.DailyUploadRow{
				{Date: today, BytesTotal: warn + 1},
				{Date: yesterday, BytesTotal: warn + 1},
				{Date: dayBefore, BytesTotal: warn + 1},
			},
			consecutive: 3,
			want:        true,
		},
		{
			name: "three contiguous days, middle under warn → false",
			recent: []store.DailyUploadRow{
				{Date: today, BytesTotal: warn + 1},
				{Date: yesterday, BytesTotal: warn - 1},
				{Date: dayBefore, BytesTotal: warn + 1},
			},
			consecutive: 3,
			want:        false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := isSustainedPattern(tc.recent, warn, tc.consecutive)
			if got != tc.want {
				t.Errorf("isSustainedPattern(...) = %v, want %v", got, tc.want)
			}
		})
	}
}

// -------- parsedQuota wires through cfg --------

func TestParsedQuota_DefaultEnabled(t *testing.T) {
	// Default-on revision (2026-04-19): DefaultServerConfig now
	// populates [server.quotas.user] with Enabled=true and the
	// 1GB/5GB/30-day defaults. parsedQuota() should mirror that.
	s := newSchedulerTestServer(t) // reuses the helper from backup_scheduler_test.go
	parsed := s.parsedQuota()
	if !parsed.Enabled {
		t.Fatal("default config now has Enabled=true; parsedQuota should be enabled")
	}
	if parsed.WarnBytes != 1<<30 {
		t.Errorf("default WarnBytes = %d, want 1GB", parsed.WarnBytes)
	}
	if parsed.BlockBytes != 5*1<<30 {
		t.Errorf("default BlockBytes = %d, want 5GB", parsed.BlockBytes)
	}
}

func TestParsedQuota_OverrideTakesEffect(t *testing.T) {
	s := newSchedulerTestServer(t)
	s.cfg.Server.Server.Quotas.User.DailyUploadBytesWarn = "500MB"
	s.cfg.Server.Server.Quotas.User.DailyUploadBytesBlock = "1GB"
	parsed := s.parsedQuota()
	if !parsed.Enabled {
		t.Fatal("after override, parsedQuota should still be enabled")
	}
	if parsed.WarnBytes != 500*1<<20 {
		t.Errorf("WarnBytes = %d, want 500MB", parsed.WarnBytes)
	}
	if parsed.BlockBytes != 1<<30 {
		t.Errorf("BlockBytes = %d, want 1GB", parsed.BlockBytes)
	}
}

func TestParsedQuota_ExplicitDisable(t *testing.T) {
	// Operator opt-out path: explicit Enabled=false in config.
	s := newSchedulerTestServer(t)
	s.cfg.Server.Server.Quotas.User.Enabled = false
	parsed := s.parsedQuota()
	if parsed.Enabled {
		t.Error("Enabled=false in config should yield disabled parsedQuota")
	}
}

func TestParsedQuota_BadConfigDegradesToDisabled(t *testing.T) {
	s := newSchedulerTestServer(t)
	// Mid-flight bad config — startup validation already passed, so
	// this is "operator broke it via SIGHUP"; should disable rather
	// than crash.
	s.cfg.Server.Server.Quotas.User.DailyUploadBytesWarn = "5GB"
	s.cfg.Server.Server.Quotas.User.DailyUploadBytesBlock = "1GB" // reversed
	parsed := s.parsedQuota()
	if parsed.Enabled {
		t.Error("invalid config (reversed warn/block) should yield Enabled=false at runtime")
	}
}

// -------- pruneOldQuotaRows no-op when disabled --------

func TestPruneOldQuotaRows_DisabledIsNoop(t *testing.T) {
	s := newSchedulerTestServer(t)
	// Explicit opt-out — prune should short-circuit cleanly
	// (no DB reads, no errors). Default config now enables
	// quotas, so we set Enabled=false here to exercise the
	// disabled branch.
	s.cfg.Server.Server.Quotas.User.Enabled = false
	s.pruneOldQuotaRows()
	// No assertion beyond "doesn't panic or error" — the function
	// returns void; bug would surface as a panic or stuck goroutine.
}

func TestPruneOldQuotaRows_RunsWhenEnabled(t *testing.T) {
	s := newSchedulerTestServer(t)
	// Default config has quotas enabled with 30-day retention; tighten
	// to 7 days for this test so the seeded ancient row is comfortably
	// past the cutoff.
	s.cfg.Server.Server.Quotas.User.RetentionDays = 7

	// Seed an old row and a new row.
	s.store.IncrementDailyUploadBytes("usr_alice", "2020-01-01", 1000, false)
	s.store.IncrementDailyUploadBytes("usr_alice", todayUTC(), 2000, false)

	s.pruneOldQuotaRows()

	// Old row gone.
	_, _, exists, _ := s.store.GetDailyUploadRow("usr_alice", "2020-01-01")
	if exists {
		t.Error("ancient row should have been pruned")
	}
	// New row preserved.
	_, _, exists, _ = s.store.GetDailyUploadRow("usr_alice", todayUTC())
	if !exists {
		t.Error("today's row should be preserved")
	}
}

// -------- isQuotaExempt gated by AllowExemptUsers --------
//
// The runtime helper consults BOTH the per-user `quota_exempt` DB
// column AND the `[server.quotas.user] allow_exempt_users` config
// gate. Operator intent on flipping `allow_exempt_users = false` is
// "I don't want any quota bypasses" — an exempt flag set when the
// gate was on must NOT keep bypassing once the gate flips off,
// otherwise the config knob is purely cosmetic.

func TestIsQuotaExempt_GateOffOverridesDBFlag(t *testing.T) {
	s := newSchedulerTestServer(t)
	// Default config: Enabled=true, AllowExemptUsers=false.
	if err := s.store.InsertUser("usr_alice", "ssh-ed25519 AAAAfake-alice", "Alice"); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if err := s.store.SetUserQuotaExempt("usr_alice", true); err != nil {
		t.Fatalf("set exempt: %v", err)
	}
	// Sanity: DB does say exempt = 1.
	dbExempt, _ := s.store.IsUserQuotaExempt("usr_alice")
	if !dbExempt {
		t.Fatal("test setup: store should report exempt=true")
	}

	// Now check the runtime helper. With AllowExemptUsers=false in
	// the parsed config, isQuotaExempt MUST return false even
	// though the DB flag is set.
	quota := s.parsedQuota()
	if quota.AllowExemptUsers {
		t.Fatal("test setup: default config should have AllowExemptUsers=false")
	}
	if s.isQuotaExempt(quota, "usr_alice") {
		t.Error("isQuotaExempt should return false when AllowExemptUsers=false, even with DB flag set")
	}
}

func TestIsQuotaExempt_GateOnHonorsDBFlag(t *testing.T) {
	s := newSchedulerTestServer(t)
	s.cfg.Server.Server.Quotas.User.AllowExemptUsers = true
	if err := s.store.InsertUser("usr_alice", "ssh-ed25519 AAAAfake-alice", "Alice"); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if err := s.store.SetUserQuotaExempt("usr_alice", true); err != nil {
		t.Fatalf("set exempt: %v", err)
	}

	quota := s.parsedQuota()
	if !quota.AllowExemptUsers {
		t.Fatal("test setup: AllowExemptUsers should be true after override")
	}
	if !s.isQuotaExempt(quota, "usr_alice") {
		t.Error("isQuotaExempt should return true when AllowExemptUsers=true AND DB flag is set")
	}
}

func TestIsQuotaExempt_GateOnButDBFlagFalse(t *testing.T) {
	s := newSchedulerTestServer(t)
	s.cfg.Server.Server.Quotas.User.AllowExemptUsers = true
	if err := s.store.InsertUser("usr_alice", "ssh-ed25519 AAAAfake-alice", "Alice"); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	// User exists but quota_exempt = 0 (default after InsertUser).

	quota := s.parsedQuota()
	if s.isQuotaExempt(quota, "usr_alice") {
		t.Error("isQuotaExempt should return false when DB flag is unset, regardless of gate")
	}
}

func TestIsQuotaExempt_GateOffSkipsStoreRead(t *testing.T) {
	// Belt-and-braces: the gate-off branch should not touch the
	// store at all. Verify by passing a user_id that doesn't exist
	// in the DB — the helper should return false without erroring
	// or logging a warning (no DB lookup happens). Construction:
	// nil store would let us assert this directly, but we don't
	// have a test seam that nils out s.store; instead we verify
	// the no-existence path returns false cleanly.
	s := newSchedulerTestServer(t)
	// Default config: AllowExemptUsers=false.
	quota := s.parsedQuota()
	if s.isQuotaExempt(quota, "usr_does_not_exist") {
		t.Error("isQuotaExempt should return false for unknown user under gate-off")
	}
}
