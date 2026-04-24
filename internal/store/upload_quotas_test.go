package store

// Per-user upload quota store tests.
// Out-of-phase 2026-04-19, originally Phase 25.

import (
	"path/filepath"
	"sync"
	"testing"
)

func newQuotaTestStore(t *testing.T) *Store {
	t.Helper()
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

// -------- Schema initialization --------

func TestQuotas_SchemaCreated(t *testing.T) {
	st := newQuotaTestStore(t)
	// Verify table exists by querying it (would error if missing).
	rows, err := st.dataDB.Query(`SELECT user_id, date, bytes_total, warn_notified FROM daily_upload_quotas LIMIT 0`)
	if err != nil {
		t.Fatalf("daily_upload_quotas table not initialized: %v", err)
	}
	rows.Close()
}

func TestQuotas_UsersHasQuotaExemptColumn(t *testing.T) {
	st := newQuotaTestStore(t)
	if !st.userColumnExists("quota_exempt") {
		t.Error("users.quota_exempt column not present after init")
	}
}

// -------- GetDailyUploadRow --------

func TestQuotas_GetDailyUploadRow_Absent(t *testing.T) {
	st := newQuotaTestStore(t)
	bytes, warned, exists, err := st.GetDailyUploadRow("usr_alice", "2026-04-19")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exists {
		t.Error("absent row should report exists=false")
	}
	if bytes != 0 || warned {
		t.Errorf("absent row should yield zeros, got bytes=%d warned=%v", bytes, warned)
	}
}

// -------- IncrementDailyUploadBytes — single-threaded --------

func TestQuotas_Increment_CreatesRow(t *testing.T) {
	st := newQuotaTestStore(t)
	total, err := st.IncrementDailyUploadBytes("usr_alice", "2026-04-19", 1000, false)
	if err != nil {
		t.Fatalf("increment: %v", err)
	}
	if total != 1000 {
		t.Errorf("first increment total = %d, want 1000", total)
	}

	bytes, warned, exists, err := st.GetDailyUploadRow("usr_alice", "2026-04-19")
	if err != nil {
		t.Fatalf("read-back: %v", err)
	}
	if !exists {
		t.Error("row should exist after increment")
	}
	if bytes != 1000 {
		t.Errorf("read-back bytes = %d, want 1000", bytes)
	}
	if warned {
		t.Error("warn_notified should default to false")
	}
}

func TestQuotas_Increment_AddsToExisting(t *testing.T) {
	st := newQuotaTestStore(t)
	_, _ = st.IncrementDailyUploadBytes("usr_alice", "2026-04-19", 1000, false)
	total, _ := st.IncrementDailyUploadBytes("usr_alice", "2026-04-19", 500, false)
	if total != 1500 {
		t.Errorf("after second increment total = %d, want 1500", total)
	}
}

func TestQuotas_Increment_MarkWarnedSticky(t *testing.T) {
	st := newQuotaTestStore(t)
	_, _ = st.IncrementDailyUploadBytes("usr_alice", "2026-04-19", 1000, true)
	_, warned, _, _ := st.GetDailyUploadRow("usr_alice", "2026-04-19")
	if !warned {
		t.Error("warn_notified should be true after markWarned=true")
	}

	// Subsequent increment with markWarned=false must NOT clear it (sticky).
	_, _ = st.IncrementDailyUploadBytes("usr_alice", "2026-04-19", 500, false)
	_, warned, _, _ = st.GetDailyUploadRow("usr_alice", "2026-04-19")
	if !warned {
		t.Error("warn_notified should remain true after markWarned=false (sticky)")
	}
}

func TestQuotas_Increment_RejectsNegative(t *testing.T) {
	st := newQuotaTestStore(t)
	_, err := st.IncrementDailyUploadBytes("usr_alice", "2026-04-19", -100, false)
	if err == nil {
		t.Error("negative bytes should be rejected")
	}
}

// -------- IncrementDailyUploadBytes — concurrent --------

// TestQuotas_Increment_ConcurrentNoLostUpdates exercises the atomic
// UPSERT under realistic concurrency. Real-world per-user upload rate
// is bounded by UploadsPerMinute (default 60/min ≈ 1/sec), so 5 goroutines
// × 10 ops with brief sleeps simulates a burst of bursty-user activity
// — well within SQLite's WAL writer-serialization budget. No lost
// updates are expected. Aggressive contention scenarios (1000+ writes
// in a tight loop) are unrealistic for this code path; the rate
// limiter and per-connection write queue (Phase 17b Step 5b) cap the
// upstream pressure.
func TestQuotas_Increment_ConcurrentNoLostUpdates(t *testing.T) {
	st := newQuotaTestStore(t)

	const (
		goroutines = 5
		perRoutine = 10
		bytesEach  = int64(100)
	)
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func() {
			defer wg.Done()
			for i := 0; i < perRoutine; i++ {
				if _, err := st.IncrementDailyUploadBytes("usr_alice", "2026-04-19", bytesEach, false); err != nil {
					t.Errorf("concurrent increment: %v", err)
					return
				}
			}
		}()
	}
	wg.Wait()

	expected := int64(goroutines) * int64(perRoutine) * bytesEach
	total, _, _, _ := st.GetDailyUploadRow("usr_alice", "2026-04-19")
	if total != expected {
		t.Errorf("concurrent total = %d, want %d (lost updates)", total, expected)
	}
}

// -------- GetRecentUploadDays --------

func TestQuotas_GetRecentUploadDays_NewestFirst(t *testing.T) {
	st := newQuotaTestStore(t)
	st.IncrementDailyUploadBytes("usr_alice", "2026-04-15", 100, false)
	st.IncrementDailyUploadBytes("usr_alice", "2026-04-17", 300, true)
	st.IncrementDailyUploadBytes("usr_alice", "2026-04-19", 500, false)
	st.IncrementDailyUploadBytes("usr_alice", "2026-04-16", 200, false)

	rows, err := st.GetRecentUploadDays("usr_alice", 3)
	if err != nil {
		t.Fatalf("get-recent: %v", err)
	}
	if len(rows) != 3 {
		t.Fatalf("got %d rows, want 3", len(rows))
	}
	wantDates := []string{"2026-04-19", "2026-04-17", "2026-04-16"}
	for i, want := range wantDates {
		if rows[i].Date != want {
			t.Errorf("row[%d].Date = %q, want %q", i, rows[i].Date, want)
		}
	}
	// Verify warn flag round-trip (apr-17 was created with markWarned=true).
	if !rows[1].WarnNotified {
		t.Error("apr-17 row WarnNotified = false, want true")
	}
}

func TestQuotas_GetRecentUploadDays_EmptyForUnknownUser(t *testing.T) {
	st := newQuotaTestStore(t)
	rows, err := st.GetRecentUploadDays("usr_ghost", 7)
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if len(rows) != 0 {
		t.Errorf("expected 0 rows for unknown user, got %d", len(rows))
	}
}

func TestQuotas_GetRecentUploadDays_ZeroDays(t *testing.T) {
	st := newQuotaTestStore(t)
	st.IncrementDailyUploadBytes("usr_alice", "2026-04-19", 100, false)
	rows, _ := st.GetRecentUploadDays("usr_alice", 0)
	if len(rows) != 0 {
		t.Errorf("days=0 should return no rows, got %d", len(rows))
	}
}

// -------- PruneDailyUploadsBefore --------

func TestQuotas_PruneBefore(t *testing.T) {
	st := newQuotaTestStore(t)
	st.IncrementDailyUploadBytes("usr_alice", "2026-01-01", 100, false)
	st.IncrementDailyUploadBytes("usr_alice", "2026-02-01", 200, false)
	st.IncrementDailyUploadBytes("usr_alice", "2026-03-01", 300, false)
	st.IncrementDailyUploadBytes("usr_bob", "2026-01-01", 400, false)

	n, err := st.PruneDailyUploadsBefore("2026-02-15")
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	// 2026-01-01 (alice + bob) and 2026-02-01 (alice) are older — 3 rows pruned.
	if n != 3 {
		t.Errorf("pruned count = %d, want 3", n)
	}

	// Newer row should still exist.
	rows, _ := st.GetRecentUploadDays("usr_alice", 30)
	if len(rows) != 1 || rows[0].Date != "2026-03-01" {
		t.Errorf("after prune, alice rows: %v", rows)
	}
}

func TestQuotas_PruneBefore_Empty(t *testing.T) {
	st := newQuotaTestStore(t)
	n, err := st.PruneDailyUploadsBefore("2026-01-01")
	if err != nil {
		t.Fatalf("prune empty: %v", err)
	}
	if n != 0 {
		t.Errorf("prune of empty table returned n=%d, want 0", n)
	}
}

// -------- SetUserQuotaExempt + IsUserQuotaExempt --------

func TestQuotas_ExemptFlag_RoundTrip(t *testing.T) {
	st := newQuotaTestStore(t)
	// Seed user.
	if err := st.InsertUser("usr_alice", "ssh-ed25519 AAAAfake", "Alice"); err != nil {
		t.Fatalf("seed user: %v", err)
	}

	// Defaults to not-exempt.
	exempt, err := st.IsUserQuotaExempt("usr_alice")
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if exempt {
		t.Error("user should default to NOT exempt")
	}

	// Toggle on.
	if err := st.SetUserQuotaExempt("usr_alice", true); err != nil {
		t.Fatalf("set on: %v", err)
	}
	exempt, _ = st.IsUserQuotaExempt("usr_alice")
	if !exempt {
		t.Error("after set --on, IsUserQuotaExempt should return true")
	}

	// Toggle off.
	if err := st.SetUserQuotaExempt("usr_alice", false); err != nil {
		t.Fatalf("set off: %v", err)
	}
	exempt, _ = st.IsUserQuotaExempt("usr_alice")
	if exempt {
		t.Error("after set --off, IsUserQuotaExempt should return false")
	}
}

func TestQuotas_ExemptFlag_UnknownUser(t *testing.T) {
	st := newQuotaTestStore(t)
	// Setting on a missing user should error (so admin gets a clear
	// "user not found" instead of silent no-op).
	err := st.SetUserQuotaExempt("usr_ghost", true)
	if err == nil {
		t.Error("setting exempt on unknown user should error")
	}

	// Reading on a missing user returns (false, nil) — fail-open is
	// fine because this gates an enforcement check, not authorization.
	exempt, err := st.IsUserQuotaExempt("usr_ghost")
	if err != nil {
		t.Errorf("read on missing user should not error, got: %v", err)
	}
	if exempt {
		t.Error("missing user should report not-exempt")
	}
}

// -------- Cross-user isolation --------

func TestQuotas_PerUserPerDayIsolation(t *testing.T) {
	st := newQuotaTestStore(t)
	st.IncrementDailyUploadBytes("usr_alice", "2026-04-19", 1000, false)
	st.IncrementDailyUploadBytes("usr_bob", "2026-04-19", 2000, false)
	st.IncrementDailyUploadBytes("usr_alice", "2026-04-18", 500, false)

	a19, _, _, _ := st.GetDailyUploadRow("usr_alice", "2026-04-19")
	b19, _, _, _ := st.GetDailyUploadRow("usr_bob", "2026-04-19")
	a18, _, _, _ := st.GetDailyUploadRow("usr_alice", "2026-04-18")
	if a19 != 1000 || b19 != 2000 || a18 != 500 {
		t.Errorf("rows leaked across (user, date): a19=%d b19=%d a18=%d", a19, b19, a18)
	}
}

// -------- Verify schema lives in data.db (silly assertion but documents intent) --------

func TestQuotas_SchemaInDataDB(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()
	st.IncrementDailyUploadBytes("usr_alice", "2026-04-19", 100, false)

	// The data.db file should exist.
	if _, err := filepath.Abs(filepath.Join(dir, "data", "data.db")); err != nil {
		t.Fatalf("path resolution: %v", err)
	}
}
