package store

// Phase 16 Gap 1 — tests for the pending_admin_state_changes queue
// helpers. Same shape as the other Phase 16 Gap 1 queue tests.
//
// Coverage:
//   - empty consume returns no rows
//   - record + consume round-trips each action type
//   - atomic delete (rows gone after consume)
//   - insertion order preserved
//   - schema CHECK constraint rejects unknown actions

import (
	"strings"
	"testing"
)

func TestConsumePendingAdminStateChanges_Empty(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	got, err := st.ConsumePendingAdminStateChanges()
	if err != nil {
		t.Fatalf("consume: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected 0 rows, got %d", len(got))
	}
}

func TestRecordAndConsumePendingAdminStateChange_Promote(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	if err := st.RecordPendingAdminStateChange("usr_alice", AdminStateChangePromote, "os:1000"); err != nil {
		t.Fatalf("record: %v", err)
	}

	got, _ := st.ConsumePendingAdminStateChanges()
	if len(got) != 1 {
		t.Fatalf("expected 1 row, got %d", len(got))
	}
	if got[0].UserID != "usr_alice" {
		t.Errorf("UserID = %q, want usr_alice", got[0].UserID)
	}
	if got[0].Action != AdminStateChangePromote {
		t.Errorf("Action = %q, want promote", got[0].Action)
	}
	if got[0].ChangedBy != "os:1000" {
		t.Errorf("ChangedBy = %q, want os:1000", got[0].ChangedBy)
	}
}

func TestRecordAndConsumePendingAdminStateChange_Demote(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	st.RecordPendingAdminStateChange("usr_bob", AdminStateChangeDemote, "os:1000")
	got, _ := st.ConsumePendingAdminStateChanges()
	if len(got) != 1 || got[0].Action != AdminStateChangeDemote {
		t.Errorf("expected 1 demote row, got %+v", got)
	}
}

func TestRecordAndConsumePendingAdminStateChange_Rename(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	st.RecordPendingAdminStateChange("usr_carol", AdminStateChangeRename, "os:1000")
	got, _ := st.ConsumePendingAdminStateChanges()
	if len(got) != 1 || got[0].Action != AdminStateChangeRename {
		t.Errorf("expected 1 rename row, got %+v", got)
	}
}

func TestConsumePendingAdminStateChanges_AtomicDelete(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	st.RecordPendingAdminStateChange("usr_alice", AdminStateChangePromote, "os:1000")
	st.RecordPendingAdminStateChange("usr_bob", AdminStateChangeDemote, "os:1000")
	st.RecordPendingAdminStateChange("usr_carol", AdminStateChangeRename, "os:1000")

	first, _ := st.ConsumePendingAdminStateChanges()
	if len(first) != 3 {
		t.Fatalf("first consume: expected 3 rows, got %d", len(first))
	}

	second, _ := st.ConsumePendingAdminStateChanges()
	if len(second) != 0 {
		t.Errorf("second consume should be empty, got %d rows", len(second))
	}
}

func TestRecordPendingAdminStateChange_PreservesOrder(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	users := []string{"usr_alice", "usr_bob", "usr_carol", "usr_dave"}
	actions := []AdminStateChangeAction{
		AdminStateChangePromote,
		AdminStateChangeDemote,
		AdminStateChangeRename,
		AdminStateChangePromote,
	}
	for i, u := range users {
		st.RecordPendingAdminStateChange(u, actions[i], "os:1000")
	}

	got, _ := st.ConsumePendingAdminStateChanges()
	if len(got) != len(users) {
		t.Fatalf("expected %d rows, got %d", len(users), len(got))
	}
	for i, row := range got {
		if row.UserID != users[i] {
			t.Errorf("row %d UserID = %q, want %q", i, row.UserID, users[i])
		}
		if row.Action != actions[i] {
			t.Errorf("row %d Action = %q, want %q", i, row.Action, actions[i])
		}
	}
}

// TestRecordPendingAdminStateChange_RejectsUnknownAction verifies the
// schema CHECK constraint rejects actions outside the allowed enum.
// Catches CLI bugs at the schema layer rather than letting bad rows
// reach the processor.
func TestRecordPendingAdminStateChange_RejectsUnknownAction(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	err = st.RecordPendingAdminStateChange("usr_alice", AdminStateChangeAction("bogus"), "os:1000")
	if err == nil {
		t.Fatal("expected CHECK constraint to reject unknown action")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "check") &&
		!strings.Contains(strings.ToLower(err.Error()), "constraint") {
		t.Errorf("error should mention check/constraint, got: %v", err)
	}
}
