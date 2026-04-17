package server

// Phase 17 Step 4.f — cascade cleanup tests. Covers:
//
//   - Upload completion writes the file_contexts binding alongside
//     StoreFileHash (handleBinaryChannel exit path).
//   - Context-gone cleanup: DeleteRoomRecord / DeleteGroupConversation /
//     DeleteDirectMessage call sites all cascade file_contexts rows and
//     eager-GC the orphaned bytes + file_hashes.
//   - Message-gone cleanup: cleanupFiles drops the binding alongside
//     bytes + file_hashes.
//   - Per-user transitions (leave, kick) do NOT cascade — remaining
//     members retain access.
//   - cleanOrphanFiles extended pass reconverges file_hashes rows with
//     no file_contexts binding.
//
// These are store/server-level tests — no SSH channel scaffolding.

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/brushtailmedia/sshkey-chat/internal/store"
)

// seedOrphanableFile helper: writes bytes + file_hashes row + file_contexts
// binding for a single file. Mirrors what a successful upload completion
// produces; used to set up tests that exercise what happens when the
// file's context is torn down.
func seedOrphanableFile(t *testing.T, s *Server, fileID, ctxType, ctxID string, ts int64) {
	t.Helper()
	path := filepath.Join(s.files.dir, fileID)
	if err := os.WriteFile(path, []byte("encrypted bytes"), 0644); err != nil {
		t.Fatalf("write bytes: %v", err)
	}
	if err := s.store.StoreFileHash(fileID, "blake2b-256:fake", 15); err != nil {
		t.Fatalf("store hash: %v", err)
	}
	if err := s.store.InsertFileContext(fileID, ctxType, ctxID, ts); err != nil {
		t.Fatalf("insert binding: %v", err)
	}
}

// assertFileFullyGone asserts the file is gone from disk, the hash row
// is gone, and the binding is gone. This is the "successful cascade"
// invariant.
func assertFileFullyGone(t *testing.T, s *Server, fileID string) {
	t.Helper()
	path := filepath.Join(s.files.dir, fileID)
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("%s bytes should be gone, stat err=%v", fileID, err)
	}
	hash, _ := s.store.GetFileHash(fileID)
	if hash != "" {
		t.Errorf("%s file_hashes row should be gone, got %q", fileID, hash)
	}
	binding, _ := s.store.GetFileContext(fileID)
	if binding != nil {
		t.Errorf("%s file_contexts binding should be gone, got %+v", fileID, binding)
	}
}

// assertFileFullyPresent asserts the reverse — all three still exist.
// Used in negative tests (per-user transition MUST NOT trigger cleanup).
func assertFileFullyPresent(t *testing.T, s *Server, fileID string) {
	t.Helper()
	path := filepath.Join(s.files.dir, fileID)
	if _, err := os.Stat(path); err != nil {
		t.Errorf("%s bytes should still exist, stat err=%v", fileID, err)
	}
	if hash, _ := s.store.GetFileHash(fileID); hash == "" {
		t.Errorf("%s file_hashes row should still exist", fileID)
	}
	if binding, _ := s.store.GetFileContext(fileID); binding == nil {
		t.Errorf("%s file_contexts binding should still exist", fileID)
	}
}

// ============================================================================
// Context-gone cascade: room delete
// ============================================================================

// TestCleanupFilesForContext_RoomLastMemberDelete verifies the cascade
// when the last member of a room /deletes: file_contexts rows for that
// room are removed, and orphaned bytes + file_hashes are GC'd eagerly.
func TestCleanupFilesForContext_RoomLastMemberDelete(t *testing.T) {
	s := newTestServer(t)
	generalID := s.store.RoomDisplayNameToID("general")

	seedOrphanableFile(t, s, "file_room_cleanup", store.FileContextRoom, generalID, 100)

	// Simulate the cleanup path invoking cleanupFilesForContext.
	s.cleanupFilesForContext(store.FileContextRoom, generalID)

	assertFileFullyGone(t, s, "file_room_cleanup")
}

func TestCleanupFilesForContext_GroupLastMemberDelete(t *testing.T) {
	s := newTestServer(t)
	if err := s.store.CreateGroup("group_cleanup", "alice", []string{"alice"}, "Test"); err != nil {
		t.Fatalf("create group: %v", err)
	}

	seedOrphanableFile(t, s, "file_group_cleanup", store.FileContextGroup, "group_cleanup", 100)

	s.cleanupFilesForContext(store.FileContextGroup, "group_cleanup")

	assertFileFullyGone(t, s, "file_group_cleanup")
}

func TestCleanupFilesForContext_DMBothPartiesLeft(t *testing.T) {
	s := newTestServer(t)
	dm, err := s.store.CreateOrGetDirectMessage("dm_cleanup", "alice", "bob")
	if err != nil {
		t.Fatalf("create dm: %v", err)
	}

	seedOrphanableFile(t, s, "file_dm_cleanup", store.FileContextDM, dm.ID, 100)

	s.cleanupFilesForContext(store.FileContextDM, dm.ID)

	assertFileFullyGone(t, s, "file_dm_cleanup")
}

// TestCleanupFilesForContext_PreservesUnrelatedFiles ensures that
// cleaning up context X only touches X's files, not files bound to
// other contexts — even if they happen to share a file_id string
// (unlikely in production but the schema should handle it correctly).
func TestCleanupFilesForContext_PreservesUnrelatedFiles(t *testing.T) {
	s := newTestServer(t)
	generalID := s.store.RoomDisplayNameToID("general")
	engID := s.store.RoomDisplayNameToID("engineering")

	seedOrphanableFile(t, s, "file_doomed", store.FileContextRoom, generalID, 100)
	seedOrphanableFile(t, s, "file_survivor", store.FileContextRoom, engID, 100)

	s.cleanupFilesForContext(store.FileContextRoom, generalID)

	assertFileFullyGone(t, s, "file_doomed")
	assertFileFullyPresent(t, s, "file_survivor")
}

// ============================================================================
// Per-user transitions MUST NOT trigger cleanup
// ============================================================================

// TestPerUserLeave_DoesNotCleanupFileContexts is the negative-regression
// guardrail for the most likely future mistake: someone adds a
// file_contexts DELETE inside performRoomLeave or performGroupLeave,
// silently breaking attachment access for remaining members. This test
// seeds a file and simulates a non-last-member leave, then verifies
// the file is still fully accessible.
func TestPerUserLeave_DoesNotCleanupFileContexts(t *testing.T) {
	s := newTestServer(t)
	generalID := s.store.RoomDisplayNameToID("general")

	seedOrphanableFile(t, s, "file_shared", store.FileContextRoom, generalID, 100)

	// bob leaves general. alice and carol remain, so the room isn't
	// cleaned up — but the file_contexts row must stay intact so alice
	// and carol retain download access.
	s.performRoomLeave(generalID, "bob", "", "bob")

	assertFileFullyPresent(t, s, "file_shared")
}

// ============================================================================
// Message-gone cascade (cleanupFiles)
// ============================================================================

// TestCleanupFiles_DropsFileContextBinding verifies that tombstoning a
// message with attachments removes the file_contexts binding alongside
// the existing bytes + file_hashes removal. Ensures the download ACL
// correctly says "not found" for a file whose owning message was
// deleted.
func TestCleanupFiles_DropsFileContextBinding(t *testing.T) {
	s := newTestServer(t)
	generalID := s.store.RoomDisplayNameToID("general")

	seedOrphanableFile(t, s, "file_msg_attached", store.FileContextRoom, generalID, 100)

	// Simulate handleDelete invoking cleanupFiles after the message is
	// tombstoned and DeleteRoomMessage returned the file_ids.
	s.cleanupFiles([]string{"file_msg_attached"})

	assertFileFullyGone(t, s, "file_msg_attached")
}

// ============================================================================
// Startup backstop (cleanOrphanFiles extended pass)
// ============================================================================

// TestCleanOrphanFiles_ReconvergesOrphanedHashRows verifies the lazy
// backstop: a file_hashes row with no file_contexts binding (result of
// an eager-cleanup failure) is reaped at next startup.
func TestCleanOrphanFiles_ReconvergesOrphanedHashRows(t *testing.T) {
	s := newTestServer(t)

	// Simulate a partial-cleanup artifact: write the bytes + hash row
	// but no file_contexts binding. This is the "eager GC failed"
	// scenario that the lazy pass catches.
	path := filepath.Join(s.files.dir, "file_orphan_hash")
	if err := os.WriteFile(path, []byte("stale"), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := s.store.StoreFileHash("file_orphan_hash", "blake2b-256:fake", 5); err != nil {
		t.Fatalf("store hash: %v", err)
	}

	s.cleanOrphanFiles()

	assertFileFullyGone(t, s, "file_orphan_hash")
}

// TestCleanOrphanFiles_LeavesBoundFilesAlone is the negative-regression
// check: files with an active file_contexts binding must NOT be reaped
// by the startup sweep.
func TestCleanOrphanFiles_LeavesBoundFilesAlone(t *testing.T) {
	s := newTestServer(t)
	generalID := s.store.RoomDisplayNameToID("general")

	seedOrphanableFile(t, s, "file_bound", store.FileContextRoom, generalID, 100)

	s.cleanOrphanFiles()

	assertFileFullyPresent(t, s, "file_bound")
}
