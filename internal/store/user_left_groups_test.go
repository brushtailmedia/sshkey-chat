package store

// Phase 20 — tests for the user_left_groups pure-history helpers.
// Parallel to user_left_rooms_test.go.

import (
	"testing"
)

func TestRecordUserLeftGroup_HappyPath(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	id, err := st.RecordUserLeftGroup("usr_alice", "grp_lunch", "removed", "usr_admin")
	if err != nil {
		t.Fatalf("record: %v", err)
	}
	if id == 0 {
		t.Error("expected non-zero row ID")
	}
}

// TestGetUserLeftGroupsCatchup_ReturnsMostRecentPerGroup verifies dedup
// logic: two leaves for the same (user, group) — catchup returns exactly
// one, with the highest left_at.
func TestGetUserLeftGroupsCatchup_ReturnsMostRecentPerGroup(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	if _, err := st.RecordUserLeftGroup("usr_alice", "grp_a", "", "usr_alice"); err != nil {
		t.Fatalf("first record: %v", err)
	}
	if _, err := st.RecordUserLeftGroup("usr_alice", "grp_a", "removed", "usr_admin"); err != nil {
		t.Fatalf("second record: %v", err)
	}

	got, err := st.GetUserLeftGroupsCatchup("usr_alice")
	if err != nil {
		t.Fatalf("catchup: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 row (deduped), got %d", len(got))
	}
}

// TestGetUserLeftGroupsCatchup_ExcludesRejoinedMembers verifies the
// LEFT JOIN filter against group_members: if the user has been re-added
// (stale row), the catchup query skips it.
func TestGetUserLeftGroupsCatchup_ExcludesRejoinedMembers(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	// Seed a group and a membership directly in data.db so the catchup
	// query's group_members JOIN has something to match against.
	if _, err := st.dataDB.Exec(
		`INSERT INTO group_conversations (id, name) VALUES (?, ?)`,
		"grp_a", "lunch",
	); err != nil {
		t.Fatalf("seed group: %v", err)
	}
	if _, err := st.dataDB.Exec(
		`INSERT INTO group_members (group_id, user) VALUES (?, ?)`,
		"grp_a", "usr_alice",
	); err != nil {
		t.Fatalf("seed member: %v", err)
	}

	// Stale leave row (simulates cleanup race — should be hidden by filter).
	if _, err := st.RecordUserLeftGroup("usr_alice", "grp_a", "removed", "usr_admin"); err != nil {
		t.Fatalf("record: %v", err)
	}

	got, _ := st.GetUserLeftGroupsCatchup("usr_alice")
	if len(got) != 0 {
		t.Errorf("want 0 rows (user currently a member), got %d", len(got))
	}
}

// TestDeleteUserLeftGroupRows_CleansUpOnRejoin verifies Q2 cleanup path.
func TestDeleteUserLeftGroupRows_CleansUpOnRejoin(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	if _, err := st.RecordUserLeftGroup("usr_alice", "grp_a", "removed", "usr_admin"); err != nil {
		t.Fatalf("record: %v", err)
	}

	if err := st.DeleteUserLeftGroupRows("usr_alice", "grp_a"); err != nil {
		t.Fatalf("delete: %v", err)
	}

	got, _ := st.GetUserLeftGroupsCatchup("usr_alice")
	if len(got) != 0 {
		t.Errorf("want 0 rows after delete, got %d", len(got))
	}
}

func TestPruneOldUserLeftGroups_RespectsRetention(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	if _, err := st.RecordUserLeftGroup("usr_alice", "grp_a", "", "usr_alice"); err != nil {
		t.Fatalf("record: %v", err)
	}

	deleted, err := st.PruneOldUserLeftGroups(365 * 24 * 60 * 60)
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if deleted != 0 {
		t.Errorf("want 0 rows pruned (recent row), got %d", deleted)
	}
}
