package store

import (
	"os"
	"path/filepath"
	"testing"
)

// TestDeleteDirectMessage_RemovesRowAndFile verifies that DeleteDirectMessage
// drops the row from direct_messages, evicts the cached *sql.DB handle, and
// unlinks the dm-<id>.db file (plus its WAL/SHM sidecars).
func TestDeleteDirectMessage_RemovesRowAndFile(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	dm, err := s.CreateOrGetDirectMessage(GenerateID("dm_"), "alice", "bob")
	if err != nil {
		t.Fatalf("create DM: %v", err)
	}

	// Insert a message so the per-DM database file is actually created
	// on disk (DMDB is lazy — it only opens the file on first use).
	if err := s.InsertDMMessage(dm.ID, StoredMessage{
		ID: "msg_1", Sender: "alice", TS: 100, Payload: "hi",
	}); err != nil {
		t.Fatalf("insert DM message: %v", err)
	}

	dbPath := filepath.Join(s.dir, "dm-"+dm.ID+".db")
	if _, err := os.Stat(dbPath); err != nil {
		t.Fatalf("dm-<id>.db should exist before delete: %v", err)
	}

	if err := s.DeleteDirectMessage(dm.ID); err != nil {
		t.Fatalf("delete DM: %v", err)
	}

	// Row must be gone
	got, err := s.GetDirectMessage(dm.ID)
	if err != nil {
		t.Fatalf("get after delete: %v", err)
	}
	if got != nil {
		t.Errorf("row still exists after delete: %+v", got)
	}

	// Cache must be gone
	s.mu.RLock()
	_, cached := s.dmDBs[dm.ID]
	s.mu.RUnlock()
	if cached {
		t.Error("dmDBs cache still holds the deleted DM")
	}

	// File and sidecars must be gone
	for _, suffix := range []string{"", "-wal", "-shm"} {
		if _, err := os.Stat(dbPath + suffix); !os.IsNotExist(err) {
			t.Errorf("file %s should not exist after delete (err=%v)", dbPath+suffix, err)
		}
	}
}

// TestDeleteDirectMessage_Idempotent verifies that deleting a DM that does
// not exist (or has already been deleted) is a no-op rather than an error.
// The cleanup re-check inside the server's dmCleanupMu critical section
// relies on this — two racing leavers may both call DeleteDirectMessage and
// the second one must not error.
func TestDeleteDirectMessage_Idempotent(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	// Delete a DM that never existed.
	if err := s.DeleteDirectMessage(GenerateID("dm_")); err != nil {
		t.Errorf("delete of nonexistent DM should be no-op, got: %v", err)
	}

	// Create, delete, then delete again.
	dm, _ := s.CreateOrGetDirectMessage(GenerateID("dm_"), "alice", "bob")
	if err := s.DeleteDirectMessage(dm.ID); err != nil {
		t.Fatalf("first delete: %v", err)
	}
	if err := s.DeleteDirectMessage(dm.ID); err != nil {
		t.Errorf("second delete should be no-op, got: %v", err)
	}
}
