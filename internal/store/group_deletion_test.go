package store

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestRecordAndGetGroupDeletion verifies the basic record/read cycle.
func TestRecordAndGetGroupDeletion(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	if err := s.RecordGroupDeletion("alice", "group_1"); err != nil {
		t.Fatalf("record 1: %v", err)
	}
	if err := s.RecordGroupDeletion("alice", "group_2"); err != nil {
		t.Fatalf("record 2: %v", err)
	}
	// Different user, same group — should not appear in alice's list
	if err := s.RecordGroupDeletion("bob", "group_3"); err != nil {
		t.Fatalf("record 3: %v", err)
	}

	got, err := s.GetDeletedGroupsForUser("alice")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 deletions for alice, got %d (%v)", len(got), got)
	}
	want := map[string]bool{"group_1": true, "group_2": true}
	for _, id := range got {
		if !want[id] {
			t.Errorf("unexpected group in alice's deletions: %q", id)
		}
	}
}

// TestRecordGroupDeletion_Idempotent verifies that re-recording the same
// (user, group) pair is a no-op (does not error, does not duplicate).
func TestRecordGroupDeletion_Idempotent(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	if err := s.RecordGroupDeletion("alice", "group_1"); err != nil {
		t.Fatalf("first record: %v", err)
	}
	if err := s.RecordGroupDeletion("alice", "group_1"); err != nil {
		t.Errorf("second record should be no-op, got: %v", err)
	}

	got, _ := s.GetDeletedGroupsForUser("alice")
	if len(got) != 1 {
		t.Errorf("expected 1 row after duplicate record, got %d", len(got))
	}
}

// TestGetDeletedGroupsForUser_None verifies the empty case returns nil
// without error rather than failing.
func TestGetDeletedGroupsForUser_None(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	got, err := s.GetDeletedGroupsForUser("nobody")
	if err != nil {
		t.Errorf("empty case should not error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected empty list, got %v", got)
	}
}

// TestClearGroupDeletionsForUser verifies retirement-time cleanup wipes
// only the target user's records, not other users'.
func TestClearGroupDeletionsForUser(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	s.RecordGroupDeletion("alice", "group_1")
	s.RecordGroupDeletion("alice", "group_2")
	s.RecordGroupDeletion("bob", "group_3")

	if err := s.ClearGroupDeletionsForUser("alice"); err != nil {
		t.Fatalf("clear: %v", err)
	}

	if got, _ := s.GetDeletedGroupsForUser("alice"); len(got) != 0 {
		t.Errorf("alice should have no deletions, got %v", got)
	}
	if got, _ := s.GetDeletedGroupsForUser("bob"); len(got) != 1 {
		t.Errorf("bob should still have 1 deletion, got %v", got)
	}
}

// TestClearGroupDeletion_Single verifies the single-row clear used by
// the future re-add path.
func TestClearGroupDeletion_Single(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	s.RecordGroupDeletion("alice", "group_1")
	s.RecordGroupDeletion("alice", "group_2")

	if err := s.ClearGroupDeletion("alice", "group_1"); err != nil {
		t.Fatalf("clear: %v", err)
	}

	got, _ := s.GetDeletedGroupsForUser("alice")
	if len(got) != 1 || got[0] != "group_2" {
		t.Errorf("expected only group_2 to remain, got %v", got)
	}
}

// TestPruneOldGroupDeletions verifies the age-based prune. Inserts rows
// with controlled timestamps directly via SQL (RecordGroupDeletion uses
// time.Now() so we can't test old timestamps with it alone).
func TestPruneOldGroupDeletions(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	now := time.Now().Unix()
	twoYearsAgo := now - (2 * 365 * 24 * 60 * 60)
	yesterday := now - (24 * 60 * 60)

	// Insert one stale row, one fresh row.
	s.dataDB.Exec(`INSERT INTO deleted_groups (user_id, group_id, deleted_at) VALUES (?, ?, ?)`,
		"alice", "stale_group", twoYearsAgo)
	s.dataDB.Exec(`INSERT INTO deleted_groups (user_id, group_id, deleted_at) VALUES (?, ?, ?)`,
		"alice", "fresh_group", yesterday)

	// Prune anything older than 1 year — only the stale row should go.
	pruned, err := s.PruneOldGroupDeletions(365 * 24 * 60 * 60)
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if pruned != 1 {
		t.Errorf("expected 1 row pruned, got %d", pruned)
	}

	got, _ := s.GetDeletedGroupsForUser("alice")
	if len(got) != 1 || got[0] != "fresh_group" {
		t.Errorf("expected only fresh_group to remain, got %v", got)
	}
}

// TestPruneOldGroupDeletions_Empty verifies prune on an empty table is a
// no-op without error.
func TestPruneOldGroupDeletions_Empty(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	pruned, err := s.PruneOldGroupDeletions(365 * 24 * 60 * 60)
	if err != nil {
		t.Errorf("prune empty table should not error: %v", err)
	}
	if pruned != 0 {
		t.Errorf("expected 0 pruned, got %d", pruned)
	}
}

// TestDeleteGroupConversation verifies the full cleanup: cached handle
// closed, group_conversations row gone, group_members rows gone, db file
// + WAL/SHM unlinked, idempotent on missing.
func TestDeleteGroupConversation(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	// Create a group with two members
	if err := s.CreateGroup("group_x", "alice", []string{"alice", "bob"}, "Test"); err != nil {
		t.Fatalf("create group: %v", err)
	}

	// Insert a message so the per-group db file actually exists on disk
	if err := s.InsertGroupMessage("group_x", StoredMessage{
		ID: "m1", Sender: "alice", TS: 100, Payload: "hi",
	}); err != nil {
		t.Fatalf("insert msg: %v", err)
	}

	dbPath := filepath.Join(s.dir, "group-group_x.db")
	if _, err := os.Stat(dbPath); err != nil {
		t.Fatalf("group db file should exist before delete: %v", err)
	}

	if err := s.DeleteGroupConversation("group_x"); err != nil {
		t.Fatalf("delete: %v", err)
	}

	// Cache evicted
	s.mu.RLock()
	_, cached := s.groupDBs["group_x"]
	s.mu.RUnlock()
	if cached {
		t.Error("groupDBs cache still holds the deleted group")
	}

	// File and sidecars gone
	for _, suffix := range []string{"", "-wal", "-shm"} {
		if _, err := os.Stat(dbPath + suffix); !os.IsNotExist(err) {
			t.Errorf("file %s should not exist after delete (err=%v)", dbPath+suffix, err)
		}
	}

	// Members gone
	members, _ := s.GetGroupMembers("group_x")
	if len(members) != 0 {
		t.Errorf("group_members should be empty after delete, got %v", members)
	}
}

// TestDeleteGroupConversation_Idempotent verifies missing rows / files
// don't error on second invocation.
func TestDeleteGroupConversation_Idempotent(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	if err := s.DeleteGroupConversation("never_existed"); err != nil {
		t.Errorf("delete of nonexistent group should be no-op, got: %v", err)
	}

	s.CreateGroup("group_x", "alice", []string{"alice"}, "")
	s.DeleteGroupConversation("group_x")
	if err := s.DeleteGroupConversation("group_x"); err != nil {
		t.Errorf("second delete should be no-op, got: %v", err)
	}
}

// TestDeleteGroupConversation_PreservesDeletedGroupsRows is the regression
// test for the design decision: when a group is fully cleaned up, the
// deleted_groups rows for that group MUST persist so offline devices can
// catch up later via sendDeletedGroups. This test would have failed
// against the original "cascade cleanup" design.
func TestDeleteGroupConversation_PreservesDeletedGroupsRows(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	// alice records a deletion against group_x
	if err := s.RecordGroupDeletion("alice", "group_x"); err != nil {
		t.Fatalf("record: %v", err)
	}

	// Create the group then immediately fully clean it up
	s.CreateGroup("group_x", "alice", []string{"alice"}, "")
	if err := s.DeleteGroupConversation("group_x"); err != nil {
		t.Fatalf("delete: %v", err)
	}

	// alice's deletion record must still be there — this is the catchup
	// signal for any offline device of alice that comes online later.
	got, _ := s.GetDeletedGroupsForUser("alice")
	if len(got) != 1 || got[0] != "group_x" {
		t.Errorf("deletion record must survive group cleanup; got %v", got)
	}
}

// TestDeleteGroupConversation_OpportunisticPrune verifies that the prune
// piggybacked on cleanup actually fires. Inserts a stale row, runs the
// cleanup (on a different group), verifies the stale row is gone.
func TestDeleteGroupConversation_OpportunisticPrune(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	// Insert a stale (>1yr) row directly
	twoYearsAgo := time.Now().Unix() - (2 * 365 * 24 * 60 * 60)
	s.dataDB.Exec(`INSERT INTO deleted_groups (user_id, group_id, deleted_at) VALUES (?, ?, ?)`,
		"alice", "stale_group", twoYearsAgo)

	// Insert a fresh row
	s.RecordGroupDeletion("alice", "fresh_group")

	// Trigger a cleanup of an unrelated group — the prune piggybacks
	s.CreateGroup("unrelated", "bob", []string{"bob"}, "")
	if err := s.DeleteGroupConversation("unrelated"); err != nil {
		t.Fatalf("delete: %v", err)
	}

	got, _ := s.GetDeletedGroupsForUser("alice")
	if len(got) != 1 || got[0] != "fresh_group" {
		t.Errorf("opportunistic prune did not run; got %v", got)
	}
}
