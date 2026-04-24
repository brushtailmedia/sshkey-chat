package store

import (
	"testing"
)

// TestInsertFileContext_HappyPath verifies basic round-trip on the
// canonical flow: upload completion inserts a binding, handleDownload
// reads it back via GetFileContext.
func TestInsertFileContext_HappyPath(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	if err := s.InsertFileContext("file_abc", FileContextRoom, "room_general", 12345); err != nil {
		t.Fatalf("insert: %v", err)
	}

	got, err := s.GetFileContext("file_abc")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got == nil {
		t.Fatal("expected binding, got nil")
	}
	if got.FileID != "file_abc" || got.ContextType != "room" || got.ContextID != "room_general" || got.TS != 12345 {
		t.Errorf("got %+v, wanted file_abc/room/room_general/12345", got)
	}
}

// TestGetFileContext_Missing verifies the "nothing bound" path returns
// (nil, nil) — the signal handleDownload uses to route to the
// privacy-preserving "not found" response.
func TestGetFileContext_Missing(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	got, err := s.GetFileContext("file_never_uploaded")
	if err != nil {
		t.Errorf("expected nil err on missing, got %v", err)
	}
	if got != nil {
		t.Errorf("expected nil binding on missing, got %+v", got)
	}
}

// TestInsertFileContext_RejectsInvalidType ensures the context_type guard
// catches typos before they land in the DB. A row with a mis-typed
// context_type would never match any DeleteFileContextsByContext call
// (which queries by exact string) and would persist as a ghost binding,
// silently failing cascade cleanup.
func TestInsertFileContext_RejectsInvalidType(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	for _, bad := range []string{"rooms", "Room", "", "dm_", "channel"} {
		err := s.InsertFileContext("file_x", bad, "ctx_x", 1)
		if err == nil {
			t.Errorf("expected error for invalid context_type %q, got nil", bad)
		}
	}
}

// TestInsertFileContext_RejectsEmptyIDs catches the other trivial mis-use:
// caller forgot to check that file_id / context_id are non-empty before
// calling. Empty strings would insert rows that collide in unpredictable
// ways later.
func TestInsertFileContext_RejectsEmptyIDs(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	if err := s.InsertFileContext("", FileContextRoom, "room_x", 1); err == nil {
		t.Error("expected error for empty file_id")
	}
	if err := s.InsertFileContext("file_x", FileContextRoom, "", 1); err == nil {
		t.Error("expected error for empty context_id")
	}
}

// TestInsertFileContext_Idempotent verifies that INSERT OR IGNORE makes
// re-insertion of the same (file_id, context_type, context_id) a no-op.
// Important because the upload-completion path runs InsertFileContext
// once per successful upload, but a buggy retry or race could call it
// twice for the same file_id.
func TestInsertFileContext_Idempotent(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	if err := s.InsertFileContext("file_idem", FileContextGroup, "group_x", 100); err != nil {
		t.Fatalf("first insert: %v", err)
	}
	// Second insert with DIFFERENT ts — should be ignored (first write wins).
	if err := s.InsertFileContext("file_idem", FileContextGroup, "group_x", 200); err != nil {
		t.Fatalf("second insert: %v", err)
	}

	got, err := s.GetFileContext("file_idem")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.TS != 100 {
		t.Errorf("ts = %d, want 100 (first-write-wins)", got.TS)
	}
}

// TestDeleteFileContextsByContext verifies the context-gone cascade:
// deleting a context returns the file_ids that were bound so the caller
// can run eager physical-file GC on each one.
func TestDeleteFileContextsByContext(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	// Bind three files to the same room, one to a different room.
	for _, fid := range []string{"file_1", "file_2", "file_3"} {
		if err := s.InsertFileContext(fid, FileContextRoom, "room_doomed", 1); err != nil {
			t.Fatalf("insert %s: %v", fid, err)
		}
	}
	if err := s.InsertFileContext("file_other", FileContextRoom, "room_alive", 1); err != nil {
		t.Fatalf("insert other: %v", err)
	}

	fileIDs, err := s.DeleteFileContextsByContext(FileContextRoom, "room_doomed")
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	if len(fileIDs) != 3 {
		t.Errorf("expected 3 file_ids, got %d: %v", len(fileIDs), fileIDs)
	}

	// The three doomed files no longer have bindings.
	for _, fid := range []string{"file_1", "file_2", "file_3"} {
		if got, _ := s.GetFileContext(fid); got != nil {
			t.Errorf("%s should have no binding after delete, got %+v", fid, got)
		}
	}
	// The untouched file still has its binding.
	if got, _ := s.GetFileContext("file_other"); got == nil {
		t.Error("file_other binding should survive unrelated cascade")
	}
}

// TestDeleteFileContextsByContext_Empty verifies the no-op path: deleting
// a context with no bindings returns an empty slice, not nil-vs-err
// confusion. The cleanup sites call this unconditionally; returning an
// empty set on "nothing to clean" is correct.
func TestDeleteFileContextsByContext_Empty(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	fileIDs, err := s.DeleteFileContextsByContext(FileContextRoom, "room_empty")
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	if len(fileIDs) != 0 {
		t.Errorf("expected empty, got %v", fileIDs)
	}
}

// TestDeleteFileContextByFileID verifies the message-gone cleanup path:
// tombstoning a message with an attachment removes the single binding
// for that file, which in the single-binding model means the file is
// now orphan-eligible.
func TestDeleteFileContextByFileID(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	if err := s.InsertFileContext("file_del", FileContextDM, "dm_x", 1); err != nil {
		t.Fatalf("insert: %v", err)
	}
	if err := s.DeleteFileContextByFileID("file_del"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	got, _ := s.GetFileContext("file_del")
	if got != nil {
		t.Errorf("expected nil after delete, got %+v", got)
	}

	// Idempotent — second call on already-deleted should succeed.
	if err := s.DeleteFileContextByFileID("file_del"); err != nil {
		t.Errorf("second delete should be no-op, got %v", err)
	}
	// Empty file_id no-ops (defensive).
	if err := s.DeleteFileContextByFileID(""); err != nil {
		t.Errorf("empty delete should no-op, got %v", err)
	}
}

// TestFileHasRemainingBindings exercises the eager-GC sequencing: after
// the caller deletes bindings for one context, this check determines
// whether the file is truly orphaned (no bindings anywhere) or still
// referenced from another context.
//
// Under today's single-binding model the "still referenced" branch
// won't fire in production, but the test locks in the semantics so a
// future multi-binding feature works correctly.
func TestFileHasRemainingBindings(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	if err := s.InsertFileContext("file_solo", FileContextRoom, "room_x", 1); err != nil {
		t.Fatalf("insert solo: %v", err)
	}

	has, err := s.FileHasRemainingBindings("file_solo")
	if err != nil {
		t.Fatalf("has (bound): %v", err)
	}
	if !has {
		t.Error("expected bindings remain while file_solo is active")
	}

	if err := s.DeleteFileContextByFileID("file_solo"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	has, err = s.FileHasRemainingBindings("file_solo")
	if err != nil {
		t.Fatalf("has (unbound): %v", err)
	}
	if has {
		t.Error("expected no remaining bindings after delete")
	}

	// Unknown file — no bindings.
	has, err = s.FileHasRemainingBindings("file_unknown")
	if err != nil {
		t.Fatalf("has (unknown): %v", err)
	}
	if has {
		t.Error("unknown file should report no bindings")
	}
}

// TestOrphanedFileHashes exercises the lazy-backstop path used by
// cleanOrphanFiles at startup. A file with a file_hashes row but no
// file_contexts row is orphan-eligible — this usually only happens if
// eager cleanup failed (os.Remove error, crash between DELETE
// statements). The startup sweep catches it.
func TestOrphanedFileHashes(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	// Write three file_hashes rows; bind only two in file_contexts.
	for _, fid := range []string{"file_bound_a", "file_bound_b", "file_orphan"} {
		if err := s.StoreFileHash(fid, "blake2b-256:"+fid, 100); err != nil {
			t.Fatalf("store hash %s: %v", fid, err)
		}
	}
	if err := s.InsertFileContext("file_bound_a", FileContextRoom, "room_x", 1); err != nil {
		t.Fatalf("bind a: %v", err)
	}
	if err := s.InsertFileContext("file_bound_b", FileContextRoom, "room_x", 1); err != nil {
		t.Fatalf("bind b: %v", err)
	}

	orphans, err := s.OrphanedFileHashes()
	if err != nil {
		t.Fatalf("orphans: %v", err)
	}
	if len(orphans) != 1 || orphans[0] != "file_orphan" {
		t.Errorf("expected [file_orphan], got %v", orphans)
	}
}

// TestFileContexts_DistinctTypesSameID verifies the composite PK
// correctly distinguishes context_type. A file bound to room "x" and a
// different file bound to group "x" — both rows with context_id="x" —
// should coexist without collision. The forward-proofing on the PK was
// meant for a future multi-binding feature, but this test locks in the
// simpler "two different files happen to share a context_id string"
// case today. (Realistically, room IDs are room_xxx and group IDs are
// group_xxx so collisions don't happen in production, but the schema
// must still handle it correctly.)
func TestFileContexts_DistinctTypesSameID(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	if err := s.InsertFileContext("file_a", FileContextRoom, "shared_id", 1); err != nil {
		t.Fatalf("insert a: %v", err)
	}
	if err := s.InsertFileContext("file_b", FileContextGroup, "shared_id", 2); err != nil {
		t.Fatalf("insert b: %v", err)
	}

	a, _ := s.GetFileContext("file_a")
	b, _ := s.GetFileContext("file_b")
	if a == nil || b == nil {
		t.Fatalf("both should resolve: a=%v b=%v", a, b)
	}
	if a.ContextType != "room" || b.ContextType != "group" {
		t.Errorf("context_type mismatch: a=%s b=%s", a.ContextType, b.ContextType)
	}

	// Cascade for the room side removes file_a but leaves file_b.
	ids, err := s.DeleteFileContextsByContext(FileContextRoom, "shared_id")
	if err != nil {
		t.Fatalf("cascade: %v", err)
	}
	if len(ids) != 1 || ids[0] != "file_a" {
		t.Errorf("expected cascade to return [file_a], got %v", ids)
	}
	if got, _ := s.GetFileContext("file_b"); got == nil {
		t.Error("file_b should survive room cascade")
	}
}
