package store

import "testing"

const testAuthKeyA = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITESTKEYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

func TestPendingKeys_FreshSchemaHasPubkey(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	if !columnExists(st.dataDB, "pending_keys", "pubkey") {
		t.Fatal("fresh pending_keys schema is missing the pubkey column")
	}
}

func TestEnsurePendingKeysSchema_MigratesAndIdempotent(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	// Simulate a legacy DB created before the pubkey column existed.
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

	if err := st.ensurePendingKeysSchema(); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if !columnExists(st.dataDB, "pending_keys", "pubkey") {
		t.Fatal("pubkey column should exist after migrate")
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
	firstSeen, isFirst, err := st.RecordPendingKey(fp, "1.2.3.4:5", testAuthKeyA)
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
	firstSeen2, isFirst2, err := st.RecordPendingKey(fp, "9.9.9.9:9", testAuthKeyA)
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
	if _, _, err := st.RecordPendingKey(fp, "1.1.1.1:1", testAuthKeyA); err != nil {
		t.Fatalf("record A: %v", err)
	}
	if _, _, err := st.RecordPendingKey(fp, "1.1.1.1:1", "ssh-ed25519 DIFFERENTKEY"); err != nil {
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
	if _, _, err := st.RecordPendingKey("SHA256:legacy", "3.3.3.3:3", testAuthKeyA); err != nil {
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

	st.RecordPendingKey("SHA256:a", "1:1", testAuthKeyA)
	st.RecordPendingKey("SHA256:b", "2:2", testAuthKeyA)

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
