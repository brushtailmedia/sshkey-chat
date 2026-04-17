package server

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/ssh"

	"github.com/brushtailmedia/sshkey-chat/internal/config"
	"github.com/brushtailmedia/sshkey-chat/internal/counters"
	"github.com/brushtailmedia/sshkey-chat/internal/protocol"
	"github.com/brushtailmedia/sshkey-chat/internal/store"
)

// contentHash computes a BLAKE2b-256 hash in tagged format.
func contentHash(data []byte) string {
	h := blake2b.Sum256(data)
	return fmt.Sprintf("blake2b-256:%x", h)
}

// fileManager handles file uploads (Channel 3) and downloads (Channel 2).
type fileManager struct {
	dir string // file storage directory

	mu      sync.RWMutex
	uploads map[string]*pendingUpload // upload_id -> pending
}

type pendingUpload struct {
	uploadID    string
	fileID      string
	size        int64
	contentHash string // "blake2b-256:<hex>" from upload_start (empty if client didn't send)
	user        string
	room        string
	groupID     string
	dmID        string
}

func newFileManager(dataDir string) *fileManager {
	dir := filepath.Join(dataDir, "data", "files")
	os.MkdirAll(dir, 0750)
	return &fileManager{
		dir:     dir,
		uploads: make(map[string]*pendingUpload),
	}
}

// cleanOrphanFiles is the lazy backstop for the Phase 17 Step 4.f hybrid
// GC model. Called once on server startup. Catches two kinds of orphan:
//
//  1. Files on disk with no file_hashes row — artifacts of crashed
//     mid-uploads that were written to disk but never completed.
//     (Pre-existing behavior.)
//
//  2. file_hashes rows with no file_contexts binding — orphans left by
//     a context-gone cleanup where the eager file-byte removal didn't
//     complete (os.Remove error, crash between DELETE statements).
//     (New — reconverges the "file exists iff it has a binding"
//     invariant every time the server boots.)
//
// Both passes are idempotent and bounded by the number of files on disk
// / rows in file_hashes. Not called on any hot path; safe to run even
// on large deployments because startup is rare and operators expect it.
func (s *Server) cleanOrphanFiles() {
	if s.files == nil || s.store == nil {
		return
	}

	// Pass 1: files on disk with no hash row (pre-existing invariant).
	entries, err := os.ReadDir(s.files.dir)
	if err != nil {
		return
	}

	removed := 0
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		fileID := entry.Name()
		hash, err := s.store.GetFileHash(fileID)
		if err != nil || hash == "" {
			// No hash record → orphan file from a crashed upload
			os.Remove(filepath.Join(s.files.dir, fileID))
			removed++
		}
	}

	// Pass 2: file_hashes rows with no file_contexts binding (Step 4.f
	// invariant). Each one means eager GC failed partway; clean up now.
	unbound, err := s.store.OrphanedFileHashes()
	if err != nil {
		s.logger.Error("orphan file_hashes scan failed", "error", err)
	} else {
		for _, fid := range unbound {
			os.Remove(filepath.Join(s.files.dir, fid))
			s.store.DeleteFileHash(fid)
			removed++
		}
	}

	if removed > 0 {
		s.logger.Info("cleaned orphan files", "count", removed)
	}
}

// cleanupFilesForContext runs the Phase 17 Step 4.f file_contexts
// cascade for a single context that's about to be torn down. MUST be
// called BEFORE the matching store-layer teardown
// (`DeleteRoomRecord` / `DeleteGroupConversation` / `DeleteDirectMessage`)
// so the file_ids can still be looked up via the binding table.
//
// Steps:
//  1. Delete all file_contexts rows for this context; capture file_ids.
//  2. For each formerly-bound file_id, check remaining bindings. Under
//     today's single-binding model there's nothing left, so we proceed
//     to GC. The check is kept anyway for future multi-binding scenarios
//     and to handle the rare race where a new binding for the same
//     file_id was inserted between steps 1 and 2.
//  3. For truly-orphaned files, delete the bytes on disk and the
//     file_hashes row. cleanOrphanFiles' lazy pass reconverges anything
//     this eager pass misses (e.g., os.Remove error on a locked file).
//
// Errors log and continue — partial cleanup is better than none, and
// the lazy backstop catches what partial cleanup leaves behind.
func (s *Server) cleanupFilesForContext(ctxType, ctxID string) {
	if s.store == nil || s.files == nil {
		return
	}

	fileIDs, err := s.store.DeleteFileContextsByContext(ctxType, ctxID)
	if err != nil {
		s.logger.Error("file_contexts cascade failed",
			"context_type", ctxType,
			"context_id", ctxID,
			"error", err,
		)
		return
	}

	for _, fid := range fileIDs {
		remaining, err := s.store.FileHasRemainingBindings(fid)
		if err != nil {
			s.logger.Error("file_contexts remaining check failed",
				"file_id", fid, "error", err)
			continue
		}
		if remaining {
			continue // still bound elsewhere — don't GC
		}
		// Truly orphaned — remove bytes + hash row.
		if err := os.Remove(filepath.Join(s.files.dir, fid)); err != nil && !os.IsNotExist(err) {
			s.logger.Warn("file bytes removal failed during context cleanup",
				"file_id", fid, "error", err)
		}
		s.store.DeleteFileHash(fid)
	}
}

// handleUploadStart processes an upload_start request on Channel 1.
func (s *Server) handleUploadStart(c *Client, raw json.RawMessage) {
	var msg protocol.UploadStart
	if err := json.Unmarshal(raw, &msg); err != nil {
		// No upload_id parsed yet — fall back to generic error
		c.Encoder.Encode(protocol.Error{Type: "error", Code: "invalid_message", Message: "malformed upload_start"})
		return
	}

	if !s.limiter.allowPerMinute("upload:"+c.UserID, s.cfg.Server.RateLimits.UploadsPerMinute) {
		c.Encoder.Encode(protocol.UploadError{
			Type:     "upload_error",
			UploadID: msg.UploadID,
			Code:     protocol.ErrRateLimited,
			Message:  "Too many uploads — wait a moment",
		})
		return
	}

	// Validate file size against config
	s.cfg.RLock()
	maxSizeStr := s.cfg.Server.Files.MaxFileSize
	s.cfg.RUnlock()
	maxSize, err := config.ParseSize(maxSizeStr)
	if err != nil || maxSize <= 0 {
		maxSize = 50 * 1024 * 1024 // fallback: 50MB
	}
	if msg.Size > maxSize {
		c.Encoder.Encode(protocol.UploadError{
			Type:     "upload_error",
			UploadID: msg.UploadID,
			Code:     protocol.ErrUploadTooLarge,
			Message:  fmt.Sprintf("File exceeds maximum size (%d bytes)", maxSize),
		})
		return
	}

	if msg.ContentHash == "" {
		c.Encoder.Encode(protocol.UploadError{
			Type:     "upload_error",
			UploadID: msg.UploadID,
			Code:     "missing_hash",
			Message:  "content_hash is required",
		})
		return
	}

	// Authorization: caller must be a member of the claimed context. Without
	// this check, any authenticated user could post upload_start with an
	// arbitrary room/group/dm ID, the server would allocate a fileID and
	// accept bytes on Channel 3, and the file would persist on disk as an
	// orphan (subsequent `send` referencing it fails the same membership
	// check, but the bytes remain until next startup cleanup — which only
	// removes files WITHOUT hash records, and upload completion records one).
	// Rate-limited DoS, not a data leak, but the cross-context upload path
	// should never have been accepted.
	//
	// Privacy: responses match handleSend/handleSendGroup/handleSendDM —
	// byte-identical "not a member" reply whether the context exists or not,
	// so a probing client cannot use upload_start to enumerate room/group/dm
	// existence.
	contextCount := 0
	if msg.Room != "" {
		contextCount++
	}
	if msg.Group != "" {
		contextCount++
	}
	if msg.DM != "" {
		contextCount++
	}
	if contextCount != 1 {
		c.Encoder.Encode(protocol.UploadError{
			Type:     "upload_error",
			UploadID: msg.UploadID,
			Code:     "invalid_context",
			Message:  "upload_start requires exactly one of room, group, or dm",
		})
		return
	}

	if s.store == nil {
		c.Encoder.Encode(protocol.UploadError{
			Type:     "upload_error",
			UploadID: msg.UploadID,
			Code:     "internal",
			Message:  "storage not available",
		})
		return
	}

	switch {
	case msg.Room != "":
		if !s.store.IsRoomMemberByID(msg.Room, c.UserID) {
			c.Encoder.Encode(protocol.UploadError{
				Type:     "upload_error",
				UploadID: msg.UploadID,
				Code:     protocol.ErrUnknownRoom,
				Message:  "You are not a member of this room",
			})
			return
		}
	case msg.Group != "":
		isMember, err := s.store.IsGroupMember(msg.Group, c.UserID)
		if err != nil || !isMember {
			c.Encoder.Encode(protocol.UploadError{
				Type:     "upload_error",
				UploadID: msg.UploadID,
				Code:     protocol.ErrUnknownGroup,
				Message:  "You are not a member of this group",
			})
			return
		}
	case msg.DM != "":
		dm, err := s.store.GetDirectMessage(msg.DM)
		if err != nil || dm == nil || (dm.UserA != c.UserID && dm.UserB != c.UserID) {
			c.Encoder.Encode(protocol.UploadError{
				Type:     "upload_error",
				UploadID: msg.UploadID,
				Code:     protocol.ErrUnknownDM,
				Message:  "You are not a party to this DM",
			})
			return
		}
	}

	fileID := generateID("file_")

	s.files.mu.Lock()
	s.files.uploads[msg.UploadID] = &pendingUpload{
		uploadID:    msg.UploadID,
		fileID:      fileID,
		size:        msg.Size,
		contentHash: msg.ContentHash,
		user:        c.UserID,
		room:        msg.Room,
		groupID:     msg.Group,
		dmID:        msg.DM,
	}
	s.files.mu.Unlock()

	c.Encoder.Encode(protocol.UploadReady{
		Type:     "upload_ready",
		UploadID: msg.UploadID,
	})
}

// authorizeDownload runs the ACL check for a single download request.
// Returns true iff the caller is allowed to download file_id under the
// per-context rules documented in download_fix.md §"Download access
// check" and §"Temporal gate semantics".
//
// Per-context semantics:
//   - Room: current member of the file's bound room AND first_seen
//     <= file.ts (forward-secrecy gate — new joiners cannot download
//     attachments sent before they joined).
//   - Group: current member AND joined_at <= file.ts. Group re-join
//     produces a fresh joined_at (AddGroupMember is DELETE-then-INSERT),
//     so re-joiners correctly lose access to files attached during
//     their absence window.
//   - 1:1 DM: party check only. user_*_left_at is a history-hiding
//     lower bound on message reads (ghost-conversation fix), NOT an
//     upper-bound access gate. See context_lifecycle_model memory
//     note — misreading this as a forward-secrecy gate would break
//     the ghost-conversation design by rejecting downloads a leaver
//     is entitled to after re-engaging.
//
// Privacy: this function returns a single bool. Callers render the
// "no" case byte-identically to "file doesn't exist" — the caller
// cannot distinguish "no binding row" from "no membership" from
// "before my join time" from the false return.
func (s *Server) authorizeDownload(userID, fileID string) bool {
	if s.store == nil {
		return false
	}
	binding, err := s.store.GetFileContext(fileID)
	if err != nil || binding == nil {
		return false
	}

	switch binding.ContextType {
	case store.FileContextRoom:
		if !s.store.IsRoomMemberByID(binding.ContextID, userID) {
			return false
		}
		firstSeen, _, _ := s.store.GetUserRoom(userID, binding.ContextID)
		if firstSeen <= 0 {
			return false
		}
		return firstSeen <= binding.TS

	case store.FileContextGroup:
		isMember, err := s.store.IsGroupMember(binding.ContextID, userID)
		if err != nil || !isMember {
			return false
		}
		joinedAt, err := s.store.GetUserGroupJoinedAt(userID, binding.ContextID)
		if err != nil || joinedAt <= 0 {
			return false
		}
		return joinedAt <= binding.TS

	case store.FileContextDM:
		dm, err := s.store.GetDirectMessage(binding.ContextID)
		if err != nil || dm == nil {
			return false
		}
		return dm.UserA == userID || dm.UserB == userID

	default:
		// Unknown context_type — reject. InsertFileContext guards
		// against bad values at write time, so this should never hit.
		s.logger.Error("download: unknown context_type in binding",
			"file_id", fileID,
			"context_type", binding.ContextType,
		)
		return false
	}
}

// handleDownload processes a download request arriving as a Channel 1
// NDJSON message. Writes the binary frame to the client's per-session
// DownloadChannel (2nd session channel) and echoes
// download_start/download_complete on Channel 1.
//
// Security: runs authorizeDownload (membership + forward-secrecy gate
// per context type). The file_id is also validated via strict
// ValidateNanoID (path-traversal defense — file_id flows into
// filepath.Join below). An attacker sending
// `file_id = "../../etc/passwd"` is rejected at the validator before
// any filesystem access.
//
// Privacy: not-found / no-access / no-channel responses all use
// `not_found` code with an identical message; a probing client cannot
// distinguish "the file exists but you can't read it" from "the file
// doesn't exist" from "you haven't opened a download channel".
func (s *Server) handleDownload(c *Client, raw json.RawMessage) {
	var msg protocol.Download
	if err := json.Unmarshal(raw, &msg); err != nil {
		c.Encoder.Encode(protocol.Error{
			Type: "error", Code: "invalid_message",
			Message: "malformed download",
		})
		return
	}

	// Path-traversal defense: file_id flows into filepath.Join below.
	// Strict nanoid shape check catches "../../etc/passwd" and other
	// filesystem-escape attempts at the wire boundary.
	if err := store.ValidateNanoID(msg.FileID, "file_"); err != nil {
		s.counters.Inc(counters.SignalInvalidNanoID, c.DeviceID)
		c.Encoder.Encode(protocol.DownloadError{
			Type:    "download_error",
			FileID:  msg.FileID,
			Code:    "invalid_file_id",
			Message: "invalid file_id",
		})
		return
	}

	// ACL check: caller must be a current member of the file's bound
	// context, and (for rooms/groups) joined before the file was
	// attached. Forward-secrecy gate for rooms/groups; party-only for
	// DMs (no joined_at check, per the ghost-conversation design).
	if !s.authorizeDownload(c.UserID, msg.FileID) {
		c.Encoder.Encode(protocol.DownloadError{
			Type:    "download_error",
			FileID:  msg.FileID,
			Code:    "not_found",
			Message: "File not found: " + msg.FileID,
		})
		return
	}

	// DownloadChannel is the 2nd session channel. A well-behaved
	// client always opens it during connect; nil here means the
	// client failed to open Channel 2 within the grace period in
	// handleSession. Treat as not_found to preserve the privacy
	// envelope (no leak of the underlying cause).
	if c.DownloadChannel == nil {
		s.logger.Debug("download request without Channel 2 open",
			"user", c.UserID, "device", c.DeviceID)
		c.Encoder.Encode(protocol.DownloadError{
			Type:    "download_error",
			FileID:  msg.FileID,
			Code:    "not_found",
			Message: "File not found: " + msg.FileID,
		})
		return
	}

	filePath := filepath.Join(s.files.dir, msg.FileID)
	info, err := os.Stat(filePath)
	if err != nil {
		c.Encoder.Encode(protocol.DownloadError{
			Type:    "download_error",
			FileID:  msg.FileID,
			Code:    "not_found",
			Message: "File not found: " + msg.FileID,
		})
		return
	}

	f, err := os.Open(filePath)
	if err != nil {
		s.logger.Error("download: open failed", "file", msg.FileID, "error", err)
		c.Encoder.Encode(protocol.DownloadError{
			Type:    "download_error",
			FileID:  msg.FileID,
			Code:    "not_found",
			Message: "File not found: " + msg.FileID,
		})
		return
	}
	defer f.Close()

	// Stored content hash for end-to-end integrity verification.
	var storedHash string
	if s.store != nil {
		storedHash, _ = s.store.GetFileHash(msg.FileID)
	}

	c.Encoder.Encode(protocol.DownloadStart{
		Type:        "download_start",
		FileID:      msg.FileID,
		Size:        info.Size(),
		ContentHash: storedHash,
	})

	if err := writeBinaryFrame(c.DownloadChannel, msg.FileID, f, info.Size()); err != nil {
		s.logger.Error("download: write failed", "file", msg.FileID, "error", err)
		// Can't signal via Channel 1 cleanly — the client is mid-read
		// on Channel 2 and the binary frame is partial/corrupt. SSH
		// layer will close on connection drop; rely on client-side
		// timeout.
		return
	}

	c.Encoder.Encode(protocol.DownloadComplete{
		Type:   "download_complete",
		FileID: msg.FileID,
	})
}

// handleBinaryChannel processes incoming upload frames on the upload
// channel (the 3rd "session"-type SSH channel on a client connection).
func (s *Server) handleBinaryChannel(userID string, ch ssh.Channel) {
	defer ch.Close()

	for {
		// Read binary frame: id_len(1) | id(variable) | data_len(8) | data(variable)
		var idLen [1]byte
		if _, err := io.ReadFull(ch, idLen[:]); err != nil {
			if err != io.EOF {
				s.logger.Debug("upload channel read id_len", "error", err)
			}
			return
		}

		idBuf := make([]byte, idLen[0])
		if _, err := io.ReadFull(ch, idBuf); err != nil {
			s.logger.Error("upload channel read id", "error", err)
			return
		}
		uploadID := string(idBuf)

		var dataLen [8]byte
		if _, err := io.ReadFull(ch, dataLen[:]); err != nil {
			s.logger.Error("upload channel read data_len", "error", err)
			return
		}
		size := binary.BigEndian.Uint64(dataLen[:])

		// Look up the pending upload
		s.files.mu.RLock()
		pending, ok := s.files.uploads[uploadID]
		s.files.mu.RUnlock()

		if !ok {
			// Unknown upload — discard the data
			io.CopyN(io.Discard, ch, int64(size))
			continue
		}

		// Write to file
		filePath := filepath.Join(s.files.dir, pending.fileID)
		f, err := os.Create(filePath)
		if err != nil {
			s.logger.Error("upload: create file failed", "error", err)
			io.CopyN(io.Discard, ch, int64(size))
			continue
		}

		written, err := io.CopyN(f, ch, int64(size))
		f.Close()

		if err != nil || written != int64(size) {
			s.logger.Error("upload: write failed", "expected", size, "written", written, "error", err)
			os.Remove(filePath)
			continue
		}

		// Verify content hash (required — always present)
		fileData, err := os.ReadFile(filePath)
		if err != nil {
			s.logger.Error("upload: read-back for hash failed", "file", pending.fileID, "error", err)
			os.Remove(filePath)
			continue
		}
		serverHash := contentHash(fileData)
		if serverHash != pending.contentHash {
			s.logger.Error("upload: content hash mismatch",
				"file", pending.fileID,
				"expected", pending.contentHash,
				"got", serverHash,
			)
			os.Remove(filePath)
			// Phase 17 Step 3: lock-release pattern. Preserve find-first-by-
			// UserID semantics (upload response goes to one originating
			// device, not all the user's devices) — select under lock, fanOut
			// with a single-element target slice.
			s.mu.RLock()
			var targets []*Client
			for _, client := range s.clients {
				if client.UserID == userID {
					targets = []*Client{client}
					break
				}
			}
			s.mu.RUnlock()
			s.fanOut("upload_error", protocol.UploadError{
				Type:     "upload_error",
				UploadID: uploadID,
				Code:     "hash_mismatch",
				Message:  "Content hash mismatch — file corrupted in transit",
			}, targets)
			s.files.mu.Lock()
			delete(s.files.uploads, uploadID)
			s.files.mu.Unlock()
			continue
		}

		// Store content hash in DB for download verification. Atomically
		// with this, write the file_contexts binding (Phase 17 Step 4.f)
		// so the file is authorized for download by members of the
		// context it was uploaded to. Both writes live in data.db, so a
		// crash between them leaves an orphan the cleanOrphanFiles
		// startup sweep reconciles; no intermediate state is queryable
		// in a way that matters for correctness or security.
		if s.store != nil {
			s.store.StoreFileHash(pending.fileID, pending.contentHash, int64(size))

			var ctxType, ctxID string
			switch {
			case pending.room != "":
				ctxType, ctxID = store.FileContextRoom, pending.room
			case pending.groupID != "":
				ctxType, ctxID = store.FileContextGroup, pending.groupID
			case pending.dmID != "":
				ctxType, ctxID = store.FileContextDM, pending.dmID
			}
			if ctxType != "" {
				if err := s.store.InsertFileContext(
					pending.fileID, ctxType, ctxID, time.Now().Unix(),
				); err != nil {
					s.logger.Error("failed to insert file_context binding",
						"file_id", pending.fileID,
						"context_type", ctxType,
						"context_id", ctxID,
						"error", err,
					)
					// Don't fail the upload — client has uploaded successfully
					// and the hash is stored. A missing binding just means
					// this file won't be downloadable until either (a) the
					// binding is re-inserted on a future upload of the same
					// bytes (hash dedup), or (b) cleanOrphanFiles reaps it.
					// Logged so operators can spot persistent issues.
				}
			}
		}

		// Clean up pending
		s.files.mu.Lock()
		delete(s.files.uploads, uploadID)
		s.files.mu.Unlock()

		s.logger.Info("file uploaded",
			"user", userID,
			"upload_id", uploadID,
			"file_id", pending.fileID,
			"size", size,
		)

		// Send upload_complete on Channel 1 — find the originating client.
		// Phase 17 Step 3: lock-release pattern with find-first semantics.
		s.mu.RLock()
		var targets []*Client
		for _, client := range s.clients {
			if client.UserID == userID {
				targets = []*Client{client}
				break
			}
		}
		s.mu.RUnlock()
		s.fanOut("upload_complete", protocol.UploadComplete{
			Type:     "upload_complete",
			UploadID: uploadID,
			FileID:   pending.fileID,
		}, targets)
	}
}

// writeBinaryFrame writes a binary frame on either the download or upload channel.
func writeBinaryFrame(w io.Writer, id string, r io.Reader, size int64) error {
	// id_len (1 byte)
	if _, err := w.Write([]byte{byte(len(id))}); err != nil {
		return err
	}
	// id (variable)
	if _, err := w.Write([]byte(id)); err != nil {
		return err
	}
	// data_len (8 bytes, big-endian)
	var dataLen [8]byte
	binary.BigEndian.PutUint64(dataLen[:], uint64(size))
	if _, err := w.Write(dataLen[:]); err != nil {
		return err
	}
	// data
	_, err := io.CopyN(w, r, size)
	return err
}
