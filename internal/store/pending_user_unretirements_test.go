package store

// Phase 16 Gap 1 — tests for the pending_user_unretirements queue
// helpers AND the SetUserUnretired store method. Mirrors the
// pending_user_retirements_test.go suite in shape.
//
// Coverage:
//   - SetUserUnretired: happy path (flips flag, clears fields, strips
//     display-name suffix), error on nonexistent user, error on
//     non-retired user, short-userID edge case (no suffix added)
//   - queue: empty consume, record + consume round-trip, atomic
//     delete, insertion order preserved

import (
	"testing"
)

// --- SetUserUnretired tests ---

func TestSetUserUnretired_HappyPath(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	// Insert + retire a user with a long enough ID for the suffix
	// logic to fire (len > 8).
	if err := st.InsertUser("usr_alice12345", "ssh-ed25519 AAAA fake", "alice"); err != nil {
		t.Fatalf("insert: %v", err)
	}
	if err := st.SetUserRetired("usr_alice12345", "key_lost"); err != nil {
		t.Fatalf("retire: %v", err)
	}

	// Verify the suffix was added.
	retired := st.GetUserByID("usr_alice12345")
	if retired == nil || !retired.Retired {
		t.Fatal("user should be retired")
	}
	expectedSuffixed := "alice_alic" // userID[4:8] = "alic"
	if retired.DisplayName != expectedSuffixed {
		t.Fatalf("expected suffixed display name %q, got %q", expectedSuffixed, retired.DisplayName)
	}

	// Now unretire.
	if err := st.SetUserUnretired("usr_alice12345"); err != nil {
		t.Fatalf("unretire: %v", err)
	}

	unretired := st.GetUserByID("usr_alice12345")
	if unretired == nil {
		t.Fatal("user should still exist after unretire")
	}
	if unretired.Retired {
		t.Error("retired flag should be cleared")
	}
	if unretired.RetiredAt != "" {
		t.Errorf("retired_at should be empty, got %q", unretired.RetiredAt)
	}
	if unretired.RetiredReason != "" {
		t.Errorf("retired_reason should be empty, got %q", unretired.RetiredReason)
	}
	if unretired.DisplayName != "alice" {
		t.Errorf("display name should be restored to %q, got %q", "alice", unretired.DisplayName)
	}
}

func TestSetUserUnretired_NonexistentUser(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	err = st.SetUserUnretired("usr_ghost")
	if err == nil {
		t.Fatal("expected error for nonexistent user")
	}
}

func TestSetUserUnretired_NotRetiredUser(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	if err := st.InsertUser("usr_alice12345", "ssh-ed25519 AAAA fake", "alice"); err != nil {
		t.Fatalf("insert: %v", err)
	}
	// alice is NOT retired — unretire should error.

	err = st.SetUserUnretired("usr_alice12345")
	if err == nil {
		t.Fatal("expected error for non-retired user")
	}
}

// TestSetUserUnretired_ShortUserID covers the edge case where the
// userID is too short for the suffix logic to fire (len <= 8). On
// retire, no suffix is added; on unretire, no suffix is stripped.
// The display name passes through unchanged.
func TestSetUserUnretired_ShortUserID(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	// 7-char user ID — not greater than 8, so no suffix logic.
	shortID := "usr_abc"
	if err := st.InsertUser(shortID, "ssh-ed25519 AAAA fake", "shorty"); err != nil {
		t.Fatalf("insert: %v", err)
	}
	if err := st.SetUserRetired(shortID, "test"); err != nil {
		t.Fatalf("retire: %v", err)
	}

	retired := st.GetUserByID(shortID)
	if retired.DisplayName != "shorty" {
		t.Errorf("short-ID retire should not add suffix, got %q", retired.DisplayName)
	}

	if err := st.SetUserUnretired(shortID); err != nil {
		t.Fatalf("unretire: %v", err)
	}
	unretired := st.GetUserByID(shortID)
	if unretired.DisplayName != "shorty" {
		t.Errorf("short-ID unretire should leave name unchanged, got %q", unretired.DisplayName)
	}
	if unretired.Retired {
		t.Error("retired flag should be cleared")
	}
}

// TestSetUserUnretired_ManuallyEditedDisplayName covers the case where
// the operator manually changed the display name during retirement
// (e.g. via a future rename-user verb). The suffix-strip should be
// best-effort: if the current name doesn't end with the expected
// suffix, leave it alone rather than mangling it.
func TestSetUserUnretired_ManuallyEditedDisplayName(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	if err := st.InsertUser("usr_alice12345", "ssh-ed25519 AAAA fake", "alice"); err != nil {
		t.Fatalf("insert: %v", err)
	}
	if err := st.SetUserRetired("usr_alice12345", "test"); err != nil {
		t.Fatalf("retire: %v", err)
	}

	// Simulate operator manually renaming the retired user.
	if err := st.SetUserDisplayName("usr_alice12345", "former-alice"); err != nil {
		t.Fatalf("manual rename: %v", err)
	}

	if err := st.SetUserUnretired("usr_alice12345"); err != nil {
		t.Fatalf("unretire: %v", err)
	}
	u := st.GetUserByID("usr_alice12345")
	if u.DisplayName != "former-alice" {
		t.Errorf("manually-edited name should be preserved, got %q", u.DisplayName)
	}
}

// --- Queue tests (mirror pending_user_retirements_test.go) ---

func TestConsumePendingUserUnretirements_Empty(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	got, err := st.ConsumePendingUserUnretirements()
	if err != nil {
		t.Fatalf("consume: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected 0 rows, got %d", len(got))
	}
}

func TestRecordAndConsumePendingUserUnretirement(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	if err := st.RecordPendingUserUnretirement("usr_alice", "os:1000"); err != nil {
		t.Fatalf("record: %v", err)
	}

	got, err := st.ConsumePendingUserUnretirements()
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
	if row.UnretiredBy != "os:1000" {
		t.Errorf("UnretiredBy = %q, want os:1000", row.UnretiredBy)
	}
	if row.QueuedAt == 0 {
		t.Error("QueuedAt should be populated")
	}
}

func TestConsumePendingUserUnretirements_AtomicDelete(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	st.RecordPendingUserUnretirement("usr_alice", "os:1000")
	st.RecordPendingUserUnretirement("usr_bob", "os:1000")

	first, _ := st.ConsumePendingUserUnretirements()
	if len(first) != 2 {
		t.Fatalf("first consume: expected 2 rows, got %d", len(first))
	}

	second, _ := st.ConsumePendingUserUnretirements()
	if len(second) != 0 {
		t.Errorf("second consume should be empty, got %d rows", len(second))
	}
}

func TestRecordPendingUserUnretirement_PreservesOrder(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	users := []string{"usr_alice", "usr_bob", "usr_carol", "usr_dave"}
	for _, u := range users {
		if err := st.RecordPendingUserUnretirement(u, "os:1000"); err != nil {
			t.Fatalf("record %s: %v", u, err)
		}
	}

	got, err := st.ConsumePendingUserUnretirements()
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
