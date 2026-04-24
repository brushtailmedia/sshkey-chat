package store

// Phase 16 Gap 1 — tests for the pending_user_retirements queue
// helpers. Mirrors the room_retirement queue tests in shape; see
// pending_user_retirements.go for the architectural rationale.
//
// Coverage:
//   - empty consume returns no rows, no error
//   - record + consume round-trips the fields
//   - consume is atomic: rows are removed after consume
//   - multiple rows preserved in insertion order
//   - record with empty reason is allowed (CLI default)

import (
	"testing"
)

func TestConsumePendingUserRetirements_Empty(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	got, err := st.ConsumePendingUserRetirements()
	if err != nil {
		t.Fatalf("consume: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected 0 rows, got %d", len(got))
	}
}

func TestRecordAndConsumePendingUserRetirement(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	if err := st.RecordPendingUserRetirement("usr_alice", "os:1000", "admin"); err != nil {
		t.Fatalf("record: %v", err)
	}

	got, err := st.ConsumePendingUserRetirements()
	if err != nil {
		t.Fatalf("consume: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 row, got %d", len(got))
	}
	row := got[0]
	if row.UserID != "usr_alice" {
		t.Errorf("UserID = %q, want usr_alice", row.UserID)
	}
	if row.RetiredBy != "os:1000" {
		t.Errorf("RetiredBy = %q, want os:1000", row.RetiredBy)
	}
	if row.Reason != "admin" {
		t.Errorf("Reason = %q, want admin", row.Reason)
	}
	if row.QueuedAt == 0 {
		t.Error("QueuedAt should be populated")
	}
}

// TestConsumePendingUserRetirements_AtomicDelete verifies that consume
// removes the rows from the queue. A second consume immediately after
// should return zero rows.
func TestConsumePendingUserRetirements_AtomicDelete(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	st.RecordPendingUserRetirement("usr_alice", "os:1000", "admin")
	st.RecordPendingUserRetirement("usr_bob", "os:1000", "key_lost")

	first, _ := st.ConsumePendingUserRetirements()
	if len(first) != 2 {
		t.Fatalf("first consume: expected 2 rows, got %d", len(first))
	}

	second, _ := st.ConsumePendingUserRetirements()
	if len(second) != 0 {
		t.Errorf("second consume should be empty, got %d rows", len(second))
	}
}

// TestRecordPendingUserRetirement_PreservesOrder verifies that consumed
// rows come back in insertion order. The queue uses an autoincrement
// id and ORDER BY id, so this should be deterministic.
func TestRecordPendingUserRetirement_PreservesOrder(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	users := []string{"usr_alice", "usr_bob", "usr_carol", "usr_dave"}
	for _, u := range users {
		if err := st.RecordPendingUserRetirement(u, "os:1000", "test"); err != nil {
			t.Fatalf("record %s: %v", u, err)
		}
	}

	got, err := st.ConsumePendingUserRetirements()
	if err != nil {
		t.Fatalf("consume: %v", err)
	}
	if len(got) != len(users) {
		t.Fatalf("expected %d rows, got %d", len(users), len(got))
	}
	for i, row := range got {
		if row.UserID != users[i] {
			t.Errorf("row %d UserID = %q, want %q", i, row.UserID, users[i])
		}
	}
}

// TestRecordPendingUserRetirement_EmptyReason verifies that an empty
// reason string is accepted. The schema has DEFAULT '' so this should
// just store empty.
func TestRecordPendingUserRetirement_EmptyReason(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	if err := st.RecordPendingUserRetirement("usr_alice", "os:1000", ""); err != nil {
		t.Fatalf("record with empty reason: %v", err)
	}
	got, _ := st.ConsumePendingUserRetirements()
	if len(got) != 1 {
		t.Fatalf("expected 1 row, got %d", len(got))
	}
	if got[0].Reason != "" {
		t.Errorf("Reason = %q, want empty", got[0].Reason)
	}
}
