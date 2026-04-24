package store

// Phase 17 Step 4a — store-boundary path-safety tests.
//
// Locks in that RoomDB / GroupDB / DMDB and their deletion-path
// siblings (DeleteRoomRecord / DeleteGroupConversation /
// DeleteDirectMessage) reject malformed IDs BEFORE any filesystem
// operation. Without this check, a malformed ID like "../../etc/passwd"
// in a room_id flows into `filepath.Join(s.dir, "room-<ID>.db")` and
// then into `openDB` / `os.Remove`, which would escape the data
// directory and operate on files outside it.
//
// The Phase 17 Step 1 ValidateNanoID helper is the single source of
// truth for the shape check. These tests exercise it at the 6 store
// boundary sites without relying on ValidateNanoID internals — just
// the observable "bad input → error, no side effect" invariant.

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// pathTraversalInputs enumerates the adversarial ID shapes a hostile
// client could send. Each must be rejected at the shape check before
// any filesystem touch.
var pathTraversalInputs = []struct {
	name string
	id   string
}{
	{"empty", ""},
	{"no prefix", "abcdefghijklmnopqrstu"},
	{"wrong prefix", "badprefix_abcdefghijklmnopqrstu"},
	{"shortstub", "room_x"},
	{"path traversal unix", "room_../../etc/passwd"},
	{"path traversal windows", "room_..\\..\\etc\\passwd"},
	{"null byte", "room_abc\x00defghijklmnopqrs"},
	{"newline", "room_abc\ndefghijklmnopqrs"},
	{"dot segment", "room_.................."},
	{"slash", "room_/tmp/bogusfileidentif"},
	{"backslash", "room_\\windows\\system32\\"},
	{"single slash literal", "room_/"},
	{"emoji", "room_🚀🚀🚀🚀🚀🚀🚀🚀🚀🚀🚀🚀🚀🚀🚀🚀🚀🚀🚀🚀🚀"},
}

func TestRoomDB_RejectsMalformedID(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	for _, tc := range pathTraversalInputs {
		t.Run(tc.name, func(t *testing.T) {
			_, err := s.RoomDB(tc.id)
			if err == nil {
				t.Errorf("RoomDB(%q) should reject malformed ID, got nil error", tc.id)
			}
			// The error must wrap an ErrInvalidNanoID* sentinel so
			// rejectAndLog can inc the right counter with errors.Is.
			if !errors.Is(err, ErrInvalidNanoIDPrefix) &&
				!errors.Is(err, ErrInvalidNanoIDLength) &&
				!errors.Is(err, ErrInvalidNanoIDAlphabet) {
				t.Errorf("RoomDB(%q) error %v should wrap an ErrInvalidNanoID* sentinel", tc.id, err)
			}
		})
	}

	// No files should have been created in the data directory at all.
	// A single opportunistic ls check: if path traversal had partly
	// succeeded, we'd see artifacts here.
	assertNoRoomFilesCreated(t, filepath.Join(dir, "data"))
}

func TestGroupDB_RejectsMalformedID(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	// Reuse the same inputs, swapping the nominal prefix. The shape
	// check still rejects them all (wrong prefix + wrong length + bad
	// alphabet all apply across the fixture set).
	for _, tc := range pathTraversalInputs {
		t.Run(tc.name, func(t *testing.T) {
			// Also try prefixing the test's known-bad payload with
			// "group_" to ensure prefix-match alone isn't enough —
			// the length + alphabet checks kick in next.
			_, err := s.GroupDB(strings.Replace(tc.id, "room_", "group_", 1))
			if err == nil {
				t.Errorf("GroupDB(%q) should reject malformed ID, got nil error", tc.id)
			}
		})
	}
}

func TestDMDB_RejectsMalformedID(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	for _, tc := range pathTraversalInputs {
		t.Run(tc.name, func(t *testing.T) {
			_, err := s.DMDB(strings.Replace(tc.id, "room_", "dm_", 1))
			if err == nil {
				t.Errorf("DMDB(%q) should reject malformed ID, got nil error", tc.id)
			}
		})
	}
}

func TestDeleteRoomRecord_RejectsMalformedID(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	// Write a sentinel file inside the data dir. If the deletion path
	// ever escaped via "../" etc., it could clobber files we didn't
	// name — this sentinel catches that.
	sentinelPath := filepath.Join(dir, "data", "sentinel.txt")
	if err := os.WriteFile(sentinelPath, []byte("do not remove"), 0600); err != nil {
		t.Fatalf("write sentinel: %v", err)
	}

	for _, tc := range pathTraversalInputs {
		t.Run(tc.name, func(t *testing.T) {
			err := s.DeleteRoomRecord(tc.id)
			if err == nil {
				t.Errorf("DeleteRoomRecord(%q) should reject malformed ID, got nil error", tc.id)
			}
		})
	}

	// Sentinel must still exist.
	if _, err := os.Stat(sentinelPath); err != nil {
		t.Errorf("sentinel file was touched by a malformed-ID deletion: %v", err)
	}
}

func TestDeleteGroupConversation_RejectsMalformedID(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	for _, tc := range pathTraversalInputs {
		t.Run(tc.name, func(t *testing.T) {
			err := s.DeleteGroupConversation(strings.Replace(tc.id, "room_", "group_", 1))
			if err == nil {
				t.Errorf("DeleteGroupConversation(%q) should reject malformed ID, got nil error", tc.id)
			}
		})
	}
}

func TestDeleteDirectMessage_RejectsMalformedID(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	for _, tc := range pathTraversalInputs {
		t.Run(tc.name, func(t *testing.T) {
			err := s.DeleteDirectMessage(strings.Replace(tc.id, "room_", "dm_", 1))
			if err == nil {
				t.Errorf("DeleteDirectMessage(%q) should reject malformed ID, got nil error", tc.id)
			}
		})
	}
}

// TestValidIDsPass smoke-tests the happy path: well-formed IDs via
// GenerateID still succeed at all 6 sites. Without this, a regression
// that tightens the check too hard (e.g. rejecting legal characters)
// could look "correct" in the malformed-input tests but break
// production.
func TestStoreBoundary_ValidIDsPass(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	// Generate one valid ID per prefix.
	roomID := GenerateID("room_")
	groupID := GenerateID("group_")
	dmID := GenerateID("dm_")

	// RoomDB / GroupDB / DMDB: happy path opens the DB without error.
	// The per-context DB file creation is a side effect — we don't care
	// about the *content*, just that the shape check passed.
	if _, err := s.RoomDB(roomID); err != nil {
		t.Errorf("RoomDB(valid) = %v, want nil", err)
	}
	if _, err := s.GroupDB(groupID); err != nil {
		t.Errorf("GroupDB(valid) = %v, want nil", err)
	}
	if _, err := s.DMDB(dmID); err != nil {
		t.Errorf("DMDB(valid) = %v, want nil", err)
	}

	// Delete*: idempotent on non-existent rows; happy path returns nil.
	if err := s.DeleteRoomRecord(GenerateID("room_")); err != nil {
		t.Errorf("DeleteRoomRecord(valid-unused) = %v, want nil (idempotent)", err)
	}
	if err := s.DeleteGroupConversation(GenerateID("group_")); err != nil {
		t.Errorf("DeleteGroupConversation(valid-unused) = %v, want nil (idempotent)", err)
	}
	if err := s.DeleteDirectMessage(GenerateID("dm_")); err != nil {
		t.Errorf("DeleteDirectMessage(valid-unused) = %v, want nil (idempotent)", err)
	}
}

// assertNoRoomFilesCreated scans the data dir and fails if any
// "room-*" file appears. Called after a batch of malformed-ID
// RoomDB calls to catch the "validation bypassed, file created"
// regression class.
func assertNoRoomFilesCreated(t *testing.T, dataDir string) {
	t.Helper()
	entries, err := os.ReadDir(dataDir)
	if err != nil {
		// Data dir may not exist yet if no legit operations happened.
		if os.IsNotExist(err) {
			return
		}
		t.Fatalf("readdir %s: %v", dataDir, err)
	}
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, "room-") && strings.HasSuffix(name, ".db") {
			t.Errorf("unexpected room file %q in data dir — validation bypassed?", name)
		}
	}
}
