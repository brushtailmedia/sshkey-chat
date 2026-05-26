package store

import (
	"fmt"
	"testing"
	"time"
)

const testAuthKeyA = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITESTKEYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

func TestPendingKeys_FreshSchemaHasExpectedColumns(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	if !columnExists(st.dataDB, "pending_keys", "pubkey") {
		t.Fatal("fresh pending_keys schema is missing the pubkey column")
	}
	if !columnExists(st.dataDB, "pending_keys", "requested_username") {
		t.Fatal("fresh pending_keys schema is missing the requested_username column")
	}
}

func TestEnsurePendingKeysSchema_MigratesAndIdempotent(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	// Simulate a legacy DB created before the pubkey/requested_username columns
	// existed.
	if _, err := st.dataDB.Exec(`DROP TABLE pending_keys`); err != nil {
		t.Fatalf("drop: %v", err)
	}
	if _, err := st.dataDB.Exec(`CREATE TABLE pending_keys (
		fingerprint TEXT PRIMARY KEY,
		remote_addr TEXT,
		attempts    INTEGER NOT NULL DEFAULT 1,
		first_seen  TEXT NOT NULL DEFAULT (datetime('now')),
		last_seen   TEXT NOT NULL DEFAULT (datetime('now'))
	)`); err != nil {
		t.Fatalf("recreate legacy: %v", err)
	}
	if columnExists(st.dataDB, "pending_keys", "pubkey") {
		t.Fatal("legacy table should not have pubkey yet")
	}
	if columnExists(st.dataDB, "pending_keys", "requested_username") {
		t.Fatal("legacy table should not have requested_username yet")
	}

	if err := st.ensurePendingKeysSchema(); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if !columnExists(st.dataDB, "pending_keys", "pubkey") {
		t.Fatal("pubkey column should exist after migrate")
	}
	if !columnExists(st.dataDB, "pending_keys", "requested_username") {
		t.Fatal("requested_username column should exist after migrate")
	}
	// Idempotent: a second call on an already-migrated DB is a no-op.
	if err := st.ensurePendingKeysSchema(); err != nil {
		t.Fatalf("second migrate should be a no-op: %v", err)
	}
}

// TestRecordPendingKey_RETURNING proves the INSERT ... ON CONFLICT DO UPDATE
// ... RETURNING shape works on the bundled modernc.org/sqlite version (no other
// code path uses RETURNING) and that isFirstAttempt derives from attempts == 1.
func TestRecordPendingKey_RETURNING(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	fp := "SHA256:abc"
	firstSeen, isFirst, err := st.RecordPendingKey(fp, "1.2.3.4:5", testAuthKeyA, "")
	if err != nil {
		t.Fatalf("record (first): %v", err)
	}
	if !isFirst {
		t.Error("first attempt should report isFirstAttempt=true")
	}
	if firstSeen == "" {
		t.Error("first_seen should be non-empty")
	}

	// Repeat: same fingerprint, new remote. Not a first attempt; first_seen
	// is stable; attempts bumps; remote updates.
	firstSeen2, isFirst2, err := st.RecordPendingKey(fp, "9.9.9.9:9", testAuthKeyA, "")
	if err != nil {
		t.Fatalf("record (repeat): %v", err)
	}
	if isFirst2 {
		t.Error("repeat attempt should report isFirstAttempt=false")
	}
	if firstSeen2 != firstSeen {
		t.Errorf("first_seen drifted on repeat: %q != %q", firstSeen2, firstSeen)
	}

	got, err := st.ListPendingKeys()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 row, got %d", len(got))
	}
	if got[0].Attempts != 2 {
		t.Errorf("attempts = %d, want 2", got[0].Attempts)
	}
	if got[0].RemoteAddr != "9.9.9.9:9" {
		t.Errorf("remote_addr = %q, want updated 9.9.9.9:9", got[0].RemoteAddr)
	}
	if got[0].PubKey != testAuthKeyA {
		t.Errorf("pubkey = %q, want %q", got[0].PubKey, testAuthKeyA)
	}
}

func TestRecordPendingKey_PubkeySetOnceAndBackfill(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	// Set-once: a present pubkey is not overwritten by a later different one.
	fp := "SHA256:setonce"
	if _, _, err := st.RecordPendingKey(fp, "1.1.1.1:1", testAuthKeyA, ""); err != nil {
		t.Fatalf("record A: %v", err)
	}
	if _, _, err := st.RecordPendingKey(fp, "1.1.1.1:1", "ssh-ed25519 DIFFERENTKEY", ""); err != nil {
		t.Fatalf("record B: %v", err)
	}
	got := findPending(t, st, fp)
	if got.PubKey != testAuthKeyA {
		t.Errorf("pubkey was overwritten: %q, want set-once %q", got.PubKey, testAuthKeyA)
	}

	// Backfill: a legacy row with NULL pubkey heals on the next attempt.
	if _, err := st.dataDB.Exec(
		`INSERT INTO pending_keys (fingerprint, remote_addr, pubkey) VALUES (?, ?, NULL)`,
		"SHA256:legacy", "2.2.2.2:2"); err != nil {
		t.Fatalf("seed legacy NULL row: %v", err)
	}
	if _, _, err := st.RecordPendingKey("SHA256:legacy", "3.3.3.3:3", testAuthKeyA, ""); err != nil {
		t.Fatalf("record backfill: %v", err)
	}
	healed := findPending(t, st, "SHA256:legacy")
	if healed.PubKey != testAuthKeyA {
		t.Errorf("NULL pubkey was not backfilled: %q, want %q", healed.PubKey, testAuthKeyA)
	}
}

func TestListPendingKeys_NullPubkeySafe(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	if _, err := st.dataDB.Exec(
		`INSERT INTO pending_keys (fingerprint, remote_addr, pubkey) VALUES (?, NULL, NULL)`,
		"SHA256:nullboth"); err != nil {
		t.Fatalf("seed: %v", err)
	}
	got, err := st.ListPendingKeys()
	if err != nil {
		t.Fatalf("list with NULL pubkey/remote should not error: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 row, got %d", len(got))
	}
	if got[0].PubKey != "" || got[0].RemoteAddr != "" {
		t.Errorf("NULL columns should scan to empty strings, got pubkey=%q remote=%q", got[0].PubKey, got[0].RemoteAddr)
	}
}

func TestPendingKeys_DeleteClearCount(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	st.RecordPendingKey("SHA256:a", "1:1", testAuthKeyA, "")
	st.RecordPendingKey("SHA256:b", "2:2", testAuthKeyA, "")

	if n, _ := st.CountPendingKeys(); n != 2 {
		t.Fatalf("count = %d, want 2", n)
	}

	if err := st.DeletePendingKey("SHA256:a"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if err := st.DeletePendingKey("SHA256:absent"); err != nil {
		t.Errorf("deleting an absent fingerprint should not error: %v", err)
	}
	if n, _ := st.CountPendingKeys(); n != 1 {
		t.Fatalf("count after delete = %d, want 1", n)
	}

	cleared, err := st.ClearPendingKeys()
	if err != nil {
		t.Fatalf("clear: %v", err)
	}
	if cleared != 1 {
		t.Errorf("cleared = %d, want 1", cleared)
	}
	if n, _ := st.CountPendingKeys(); n != 0 {
		t.Errorf("count after clear = %d, want 0", n)
	}
}

func findPending(t *testing.T, st *Store, fingerprint string) PendingKey {
	t.Helper()
	rows, err := st.ListPendingKeys()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	for _, r := range rows {
		if r.Fingerprint == fingerprint {
			return r
		}
	}
	t.Fatalf("fingerprint %q not found in pending list", fingerprint)
	return PendingKey{}
}

func TestRecordPendingKey_RequestedUsername(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	fp := "SHA256:hintfp"

	// First contact with a hint → stored.
	if _, _, err := st.RecordPendingKey(fp, "1:1", testAuthKeyA, "Alice"); err != nil {
		t.Fatalf("record (hint): %v", err)
	}
	if got := findPending(t, st, fp).RequestedUsername; got != "Alice" {
		t.Fatalf("requested_username = %q, want Alice", got)
	}

	// DP4 latest-NON-EMPTY wins: a genuine new name overwrites.
	if _, _, err := st.RecordPendingKey(fp, "1:1", testAuthKeyA, "Alice Smith"); err != nil {
		t.Fatalf("record (rename): %v", err)
	}
	if got := findPending(t, st, fp).RequestedUsername; got != "Alice Smith" {
		t.Fatalf("after rename = %q, want Alice Smith", got)
	}

	// An empty reconnect (e.g. term sends an empty conn.User()) must NOT clobber
	// the captured hint — the whole point of Option C.
	if _, _, err := st.RecordPendingKey(fp, "2:2", testAuthKeyA, ""); err != nil {
		t.Fatalf("record (empty): %v", err)
	}
	if got := findPending(t, st, fp).RequestedUsername; got != "Alice Smith" {
		t.Fatalf("empty reconnect clobbered hint = %q, want Alice Smith preserved", got)
	}

	// Empty FIRST contact stores NULL → surfaces as "".
	if _, _, err := st.RecordPendingKey("SHA256:nohint", "3:3", testAuthKeyA, ""); err != nil {
		t.Fatalf("record (no hint): %v", err)
	}
	if got := findPending(t, st, "SHA256:nohint").RequestedUsername; got != "" {
		t.Errorf("no-hint row RequestedUsername = %q, want empty", got)
	}
}

func TestGetPendingKeyByFingerprint(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	// Absent → ok=false, no error.
	if _, ok, err := st.GetPendingKeyByFingerprint("SHA256:absent"); err != nil || ok {
		t.Fatalf("absent fingerprint: ok=%v err=%v, want ok=false err=nil", ok, err)
	}

	if _, _, err := st.RecordPendingKey("SHA256:present", "1:1", testAuthKeyA, "Bob"); err != nil {
		t.Fatalf("record: %v", err)
	}
	pk, ok, err := st.GetPendingKeyByFingerprint("SHA256:present")
	if err != nil || !ok {
		t.Fatalf("present fingerprint: ok=%v err=%v, want ok=true err=nil", ok, err)
	}
	if pk.RequestedUsername != "Bob" {
		t.Errorf("RequestedUsername = %q, want Bob", pk.RequestedUsername)
	}
	if pk.PubKey != testAuthKeyA {
		t.Errorf("PubKey = %q, want %q", pk.PubKey, testAuthKeyA)
	}
}

// sqliteTime formats a time as the SQLite datetime('now') TEXT shape the
// pending_keys schema uses, so seeded first_seen/last_seen sort/compare
// correctly against the in-query cutoff.
func sqliteTime(t time.Time) string {
	return t.UTC().Format("2006-01-02 15:04:05")
}

// seedPendingRow inserts a pending_keys row with explicit first_seen/last_seen
// so prune/cap behavior can be exercised deterministically.
func seedPendingRow(t *testing.T, st *Store, fp, firstSeen, lastSeen string) {
	t.Helper()
	if _, err := st.dataDB.Exec(
		`INSERT INTO pending_keys (fingerprint, remote_addr, pubkey, first_seen, last_seen)
		 VALUES (?, '1.2.3.4:5', ?, ?, ?)`,
		fp, testAuthKeyA, firstSeen, lastSeen); err != nil {
		t.Fatalf("seed %s: %v", fp, err)
	}
}

func pendingFingerprints(t *testing.T, st *Store) map[string]bool {
	t.Helper()
	rows, err := st.ListPendingKeys()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	out := make(map[string]bool, len(rows))
	for _, r := range rows {
		out[r.Fingerprint] = true
	}
	return out
}

// TestPruneOldPendingKeys_AgesByFirstSeen proves the TTL keys off first_seen,
// not last_seen: a reconnecting key (old first_seen, fresh last_seen) STILL
// ages out, while a genuinely fresh contact survives. Also implicitly checks
// the cutoff is a SQLite datetime TEXT comparison, not Unix seconds.
func TestPruneOldPendingKeys_AgesByFirstSeen(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	now := time.Now()
	old := sqliteTime(now.AddDate(0, 0, -30))  // 30 days ago
	fresh := sqliteTime(now)                   // just now
	future := sqliteTime(now.AddDate(0, 0, 1)) // tomorrow (definitely fresh)

	seedPendingRow(t, st, "SHA256:old", old, old)
	// Reconnecting key: OLD first contact, RECENT activity — must still age out.
	seedPendingRow(t, st, "SHA256:reconnect", old, future)
	seedPendingRow(t, st, "SHA256:fresh", fresh, fresh)

	removed, err := st.PruneOldPendingKeys(7 * 24 * 3600) // 7-day window
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if removed != 2 {
		t.Errorf("removed = %d, want 2 (old + reconnecting)", removed)
	}
	got := pendingFingerprints(t, st)
	if len(got) != 1 || !got["SHA256:fresh"] {
		t.Errorf("survivors = %v, want only SHA256:fresh", got)
	}
}

// TestEnforcePendingKeyCap_EvictsOldestByLastSeen checks the hard cap evicts
// the least-recently-active rows and is a no-op under the cap.
func TestEnforcePendingKeyCap_EvictsOldestByLastSeen(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	base := time.Now().UTC()
	for i := 1; i <= 5; i++ {
		ts := sqliteTime(base.Add(time.Duration(i) * time.Minute)) // r1 oldest active … r5 newest
		seedPendingRow(t, st, fmt.Sprintf("SHA256:r%d", i), ts, ts)
	}

	removed, err := st.EnforcePendingKeyCap(3)
	if err != nil {
		t.Fatalf("cap: %v", err)
	}
	if removed != 2 {
		t.Errorf("removed = %d, want 2", removed)
	}
	if n, _ := st.CountPendingKeys(); n != 3 {
		t.Errorf("count after cap = %d, want 3", n)
	}
	got := pendingFingerprints(t, st)
	if got["SHA256:r1"] || got["SHA256:r2"] {
		t.Errorf("oldest-by-last_seen rows should be evicted, got %v", got)
	}
	if !got["SHA256:r3"] || !got["SHA256:r4"] || !got["SHA256:r5"] {
		t.Errorf("newest rows should survive, got %v", got)
	}

	// Under the cap → no-op.
	if removed, err := st.EnforcePendingKeyCap(10); err != nil || removed != 0 {
		t.Errorf("under-cap: removed=%d err=%v, want 0/nil", removed, err)
	}
}

// TestEnforcePendingKeyCap_TieBreakByRowid proves same-second timestamps evict
// in deterministic insertion (rowid) order — the storm case where many rows
// share a second-resolution datetime('now').
func TestEnforcePendingKeyCap_TieBreakByRowid(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	same := sqliteTime(time.Now()) // identical last_seen/first_seen for all four
	for i := 1; i <= 4; i++ {
		seedPendingRow(t, st, fmt.Sprintf("SHA256:t%d", i), same, same)
	}

	// Cap at 2 → the two lowest-rowid (earliest-inserted) rows go first.
	if _, err := st.EnforcePendingKeyCap(2); err != nil {
		t.Fatalf("cap: %v", err)
	}
	got := pendingFingerprints(t, st)
	if got["SHA256:t1"] || got["SHA256:t2"] {
		t.Errorf("earliest-inserted rows should be evicted on tie, got %v", got)
	}
	if !got["SHA256:t3"] || !got["SHA256:t4"] {
		t.Errorf("later-inserted rows should survive on tie, got %v", got)
	}
}
