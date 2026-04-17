package store

import (
	"database/sql"
	"fmt"
)

// FileContext is the persisted binding of a file_id to its owning
// conversation context. Used by Phase 17 Step 4.f's download ACL to
// determine (a) whether the file exists server-side, and (b) which
// membership check applies to the caller requesting it.
//
// The Type / ID pair is exactly one of:
//   - ("room",  <room_id>)
//   - ("group", <group_id>)
//   - ("dm",    <dm_id>)
//
// TS is the attachment timestamp (upload completion wall-clock). The
// download ACL uses this for the first_seen / joined_at forward-secrecy
// gate in rooms and groups. DMs ignore TS — their access model is party
// membership only (see context_lifecycle_model memory note).
type FileContext struct {
	FileID      string
	ContextType string // 'room' | 'group' | 'dm'
	ContextID   string
	TS          int64
}

// Context type constants. Use these instead of raw strings at insert /
// delete sites to prevent typo-induced row mismatches that would leave
// orphans (insert with "group", delete with "groups" = silently wrong).
const (
	FileContextRoom  = "room"
	FileContextGroup = "group"
	FileContextDM    = "dm"
)

// validFileContextType is the set of legal context_type values. Guards
// insert-time inputs so a future caller passing an unexpected string
// (e.g. a plural, a typo) fails loudly rather than creating orphan rows
// that the cascade cleanup would miss.
func validFileContextType(t string) bool {
	switch t {
	case FileContextRoom, FileContextGroup, FileContextDM:
		return true
	}
	return false
}

// InsertFileContext records the binding between a file_id and its
// context. Called once per file at upload completion (handleBinaryChannel
// success path, alongside StoreFileHash). Uses INSERT OR IGNORE because
// re-ingest of the same upload should be a no-op; the binding is
// file_id-keyed and first-write-wins.
//
// Rejects unknown context_type values at the caller boundary — a typo
// here would silently break the download ACL for that file.
func (s *Store) InsertFileContext(fileID, contextType, contextID string, ts int64) error {
	if !validFileContextType(contextType) {
		return fmt.Errorf("file_contexts: invalid context_type %q (expected one of room/group/dm)", contextType)
	}
	if fileID == "" || contextID == "" {
		return fmt.Errorf("file_contexts: file_id and context_id must be non-empty")
	}
	_, err := s.dataDB.Exec(`
		INSERT OR IGNORE INTO file_contexts (file_id, context_type, context_id, ts)
		VALUES (?, ?, ?, ?)`,
		fileID, contextType, contextID, ts)
	return err
}

// GetFileContext returns the single binding for a file_id, or nil if no
// binding exists (download request for an unknown or already-cleaned-up
// file — caller should treat as "not found" with a privacy-preserving
// response). Current usage is single-binding-per-file; if forwards ever
// become a feature that reuses file_ids across contexts, switch to a
// plural Query / loop model and update the caller.
//
// Single row returned means the composite PK is never actually hit by
// multiple rows for one file_id in today's code, but the plural-fallback
// could land without a schema change — see download_fix.md's
// "forward-proof" note.
func (s *Store) GetFileContext(fileID string) (*FileContext, error) {
	var fc FileContext
	err := s.dataDB.QueryRow(`
		SELECT file_id, context_type, context_id, ts
		FROM file_contexts
		WHERE file_id = ?
		LIMIT 1`,
		fileID,
	).Scan(&fc.FileID, &fc.ContextType, &fc.ContextID, &fc.TS)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get file_context: %w", err)
	}
	return &fc, nil
}

// DeleteFileContextsByContext removes all bindings for a single context
// (used by the three context-gone cleanup sites: DeleteRoomRecord,
// DeleteGroupConversation, DeleteDirectMessage). Returns the list of
// file_ids that were bound to this context so the caller can run the
// eager physical-file GC (check each for remaining bindings; if none,
// delete the bytes + file_hashes row).
//
// The SELECT-then-DELETE pattern (inside a single transaction) ensures
// the returned list is precisely the set of files that need GC-checking,
// even if another INSERT races mid-cleanup. Callers don't need a
// transaction wrapper themselves; this function handles it.
func (s *Store) DeleteFileContextsByContext(contextType, contextID string) ([]string, error) {
	if !validFileContextType(contextType) {
		return nil, fmt.Errorf("file_contexts: invalid context_type %q", contextType)
	}

	tx, err := s.dataDB.Begin()
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback() // no-op if Commit succeeds

	rows, err := tx.Query(`
		SELECT file_id FROM file_contexts
		WHERE context_type = ? AND context_id = ?`,
		contextType, contextID)
	if err != nil {
		return nil, fmt.Errorf("select file_contexts: %w", err)
	}

	var fileIDs []string
	for rows.Next() {
		var fid string
		if err := rows.Scan(&fid); err != nil {
			rows.Close()
			return nil, fmt.Errorf("scan file_id: %w", err)
		}
		fileIDs = append(fileIDs, fid)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows err: %w", err)
	}

	if _, err := tx.Exec(`
		DELETE FROM file_contexts
		WHERE context_type = ? AND context_id = ?`,
		contextType, contextID); err != nil {
		return nil, fmt.Errorf("delete file_contexts: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit: %w", err)
	}
	return fileIDs, nil
}

// DeleteFileContextByFileID removes all bindings for a single file_id.
// Used by the message-gone cleanup site (cleanupFiles in session.go
// after a message tombstone) and the admin-purge site (cmdPurge in
// sshkey-ctl after bulk message deletion). Both contexts of use fall
// under the single-binding model: one file, one row, delete the row.
//
// Idempotent: re-running on a file_id whose row was already deleted
// is a no-op (DELETE on zero matching rows returns zero without error).
func (s *Store) DeleteFileContextByFileID(fileID string) error {
	if fileID == "" {
		return nil
	}
	_, err := s.dataDB.Exec(`DELETE FROM file_contexts WHERE file_id = ?`, fileID)
	if err != nil {
		return fmt.Errorf("delete file_context by file_id: %w", err)
	}
	return nil
}

// FileHasRemainingBindings reports whether any file_contexts row remains
// for a given file_id. Called after DeleteFileContextsByContext returns
// a list of affected file_ids, so the caller can GC each one that's no
// longer bound anywhere (bytes on disk + file_hashes row become orphan).
//
// Under single-binding-per-file this always returns false after
// DeleteFileContextsByContext (since the only row was already deleted).
// Kept as an explicit check anyway so that (a) the eager-GC code reads
// naturally, (b) future multi-binding scenarios work without
// restructuring this layer, and (c) it handles the rare race where a
// new binding for the same file_id was inserted between the cleanup's
// SELECT and the caller's GC-check.
func (s *Store) FileHasRemainingBindings(fileID string) (bool, error) {
	var n int
	err := s.dataDB.QueryRow(
		`SELECT COUNT(*) FROM file_contexts WHERE file_id = ? LIMIT 1`,
		fileID,
	).Scan(&n)
	if err != nil {
		return false, fmt.Errorf("count file_contexts: %w", err)
	}
	return n > 0, nil
}

// OrphanedFileHashes returns file_ids that have a file_hashes row but
// no matching file_contexts row. Used by cleanOrphanFiles at startup as
// the lazy backstop for the hybrid GC — catches any file whose binding
// was deleted but whose file_hashes row + bytes weren't cleaned up
// (crash or error in the eager path).
//
// Bounded by total file_hashes count; acceptable at startup. Not called
// on the hot path.
func (s *Store) OrphanedFileHashes() ([]string, error) {
	rows, err := s.dataDB.Query(`
		SELECT fh.file_id
		FROM file_hashes fh
		LEFT JOIN file_contexts fc ON fc.file_id = fh.file_id
		WHERE fc.file_id IS NULL`)
	if err != nil {
		return nil, fmt.Errorf("select orphaned file_hashes: %w", err)
	}
	defer rows.Close()

	var ids []string
	for rows.Next() {
		var fid string
		if err := rows.Scan(&fid); err != nil {
			return nil, fmt.Errorf("scan orphaned file_id: %w", err)
		}
		ids = append(ids, fid)
	}
	return ids, rows.Err()
}
