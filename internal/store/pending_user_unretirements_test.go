package store

// Phase 16 Gap 1 — tests for the pending_user_unretirements queue
// helpers AND the SetUserUnretired store method. Mirrors the
// pending_user_retirements_test.go suite in shape.
//
// Coverage:
//   - SetUserUnretired: happy path (flips flag, clears fields, restores the
//     stripped original name + restoredOriginal=true), error on nonexistent
//     user, error on non-retired user, short-userID edge case (no suffix added),
//     manually-edited name, and the fallback path (original name taken → unique
//     placeholder assigned + restoredOriginal=false)
//   - SetUserRetired: rune-safe truncate-on-retire so name+suffix stays within
//     the display-name byte cap
//   - queue: empty consume, record + consume round-trip, atomic
//     delete, insertion order preserved

import (
	"strings"
	"testing"
	"unicode/utf8"
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

	// Now unretire — the original name "alice" is free, so it is restored.
	chosen, restoredOriginal, err := st.SetUserUnretired("usr_alice12345")
	if err != nil {
		t.Fatalf("unretire: %v", err)
	}
	if !restoredOriginal {
		t.Error("restoredOriginal should be true when the original name is free")
	}
	if chosen != "alice" {
		t.Errorf("restored name = %q, want alice", chosen)
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

	_, _, err = st.SetUserUnretired("usr_ghost")
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

	_, _, err = st.SetUserUnretired("usr_alice12345")
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

	if _, _, err := st.SetUserUnretired(shortID); err != nil {
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

	if _, _, err := st.SetUserUnretired("usr_alice12345"); err != nil {
		t.Fatalf("unretire: %v", err)
	}
	u := st.GetUserByID("usr_alice12345")
	if u.DisplayName != "former-alice" {
		t.Errorf("manually-edited name should be preserved, got %q", u.DisplayName)
	}
}

// TestSetUserUnretired_FallbackWhenOriginalTaken covers the race the fix
// targets: retirement frees the original name, another account claims it, and
// unretire must NOT silently re-take it (no DB unique index would catch the
// duplicate). Instead a unique placeholder is assigned and restoredOriginal is
// false; the user renames later.
func TestSetUserUnretired_FallbackWhenOriginalTaken(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	// Retire alice → "alice_alic", freeing "alice".
	if err := st.InsertUser("usr_alice12345", "ssh-ed25519 AAAA fake", "alice"); err != nil {
		t.Fatalf("insert alice: %v", err)
	}
	if err := st.SetUserRetired("usr_alice12345", "key_lost"); err != nil {
		t.Fatalf("retire: %v", err)
	}
	// Another account claims the freed name.
	if err := st.InsertUser("usr_bob67890", "ssh-ed25519 BBBB fake", "alice"); err != nil {
		t.Fatalf("insert bob: %v", err)
	}

	chosen, restoredOriginal, err := st.SetUserUnretired("usr_alice12345")
	if err != nil {
		t.Fatalf("unretire: %v", err)
	}
	if restoredOriginal {
		t.Error("restoredOriginal should be false when the original name is taken")
	}
	if chosen == "alice" || chosen == "" {
		t.Errorf("placeholder should differ from the taken original and be non-empty, got %q", chosen)
	}
	// The placeholder must not collide with any other account.
	if st.IsDisplayNameTaken(chosen, "usr_alice12345") {
		t.Errorf("assigned placeholder %q collides with an existing name", chosen)
	}
	u := st.GetUserByID("usr_alice12345")
	if u == nil || u.Retired {
		t.Fatal("alice should be unretired")
	}
	if u.DisplayName != chosen {
		t.Errorf("stored display name %q != returned %q", u.DisplayName, chosen)
	}
	// bob's claim on "alice" is untouched.
	if bob := st.GetUserByID("usr_bob67890"); bob == nil || bob.DisplayName != "alice" {
		t.Errorf("bob's claimed name should be intact, got %+v", bob)
	}
}

// TestSetUserRetired_TruncatesLongNameToFit verifies option (b): when the name
// plus the retirement suffix would exceed the 32-byte cap, the name is truncated
// on a UTF-8 rune boundary so the result stays <= 32 bytes, is valid UTF-8, and
// still ends with the suffix.
func TestSetUserRetired_TruncatesLongNameToFit(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	cases := []struct {
		userID, key, name, label string
	}{
		{"usr_alice12345", "ssh-ed25519 AAAA fake", strings.Repeat("a", 30), "ascii-30-bytes"},
		{"usr_bobby6789x", "ssh-ed25519 BBBB fake", strings.Repeat("日", 10), "cjk-30-bytes"}, // 10 runes x 3 bytes
	}
	for _, tc := range cases {
		t.Run(tc.label, func(t *testing.T) {
			// Distinct key per sub-case — users.key is UNIQUE (on key material).
			if err := st.InsertUser(tc.userID, tc.key, tc.name); err != nil {
				t.Fatalf("insert: %v", err)
			}
			if err := st.SetUserRetired(tc.userID, "test"); err != nil {
				t.Fatalf("retire: %v", err)
			}
			u := st.GetUserByID(tc.userID)
			if u == nil {
				t.Fatal("user missing after retire")
			}
			got := u.DisplayName
			suffix := "_" + tc.userID[4:8]
			if len(got) > maxDisplayNameBytes {
				t.Errorf("retired name is %d bytes (> %d): %q", len(got), maxDisplayNameBytes, got)
			}
			if !utf8.ValidString(got) {
				t.Errorf("retired name is not valid UTF-8: %q", got)
			}
			if !strings.HasSuffix(got, suffix) {
				t.Errorf("retired name %q does not end with suffix %q", got, suffix)
			}
		})
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
