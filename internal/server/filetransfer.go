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

// validContentHash enforces the strict wire contract for content_hash:
// exactly `blake2b-256:<64 hex chars>`, lowercase only. Protocol spec
// (PROTOCOL.md File Transfer section) states this explicitly — clients
// MUST emit lowercase hex; the server rejects otherwise.
//
// Phase 17 Step 4c: early-reject at upload_start shape check, before
// any pendingUpload allocation. Pre-4c a malformed hash propagated all
// the way to the re-compute step at upload completion and surfaced as
// a noisy "hash_mismatch" — costing server bandwidth for no reason
// AND giving the operator no Phase-17b-compatible signal distinguishing
// hostile malformed-hash clients from legitimate corrupt-in-transit
// mismatches.
//
// Implementation avoids the regexp package on the hot path: two
// constant string checks + a 64-byte alphabet loop, zero allocation.
func validContentHash(h string) bool {
	const prefix = "blake2b-256:"
	if len(h) != len(prefix)+64 {
		return false
	}
	if h[:len(prefix)] != prefix {
		return false
	}
	for i := len(prefix); i < len(h); i++ {
		c := h[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
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

// failUpload cleans up per-upload state on any error path in
// handleBinaryChannel. Removes the physical file (if filePath
// non-empty) and drops the pendingUpload map entry. Best-effort on
// os.Remove — missing files are tolerated silently. Idempotent.
//
// Phase 17 Step 4b introduced this helper to fix three leak sites
// that removed the partial file but forgot to delete the
// pendingUpload map entry — accumulating map cruft over a connection
// lifetime. Every error path in handleBinaryChannel now calls this
// helper.
//
// Caller sites:
//   - data_len > MaxFileSize (oversized frame, 4b)
//   - os.Create failure
//   - Write / short-write failure
//   - Hash read-back failure
//   - Hash mismatch (already cleaned the entry pre-4b, now uses helper for consistency)
func (s *Server) failUpload(uploadID, filePath string) {
	if filePath != "" {
		_ = os.Remove(filePath)
	}
	s.files.mu.Lock()
	delete(s.files.uploads, uploadID)
	s.files.mu.Unlock()
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
		s.rejectAndLog(c, counters.SignalMalformedFrame, "upload_start", "malformed upload_start frame",
			&protocol.Error{Type: "error", Code: "invalid_message", Message: "malformed upload_start"})
		return
	}

	if allowed, retryMs := s.limiter.allowPerMinuteWithRetry("upload:"+c.UserID, s.cfg.Server.RateLimits.UploadsPerMinute); !allowed {
		// Phase 17 Step 4c Part 3 + Step 6: count the rejection AND
		// populate retry_after_ms on the UploadError wire response.
		// Counted for observability only; rate_limited is NOT in
		// AutoRevokeSignals (load signal — legitimate clients trip
		// this during bursty catchup).
		s.rejectAndLog(c, counters.SignalRateLimited, "upload_start",
			"upload rate limit exceeded", nil)
		c.Encoder.Encode(protocol.UploadError{
			Type:         "upload_error",
			UploadID:     msg.UploadID,
			Code:         protocol.ErrRateLimited,
			Message:      "Too many uploads — wait a moment",
			RetryAfterMs: retryMs,
		})
		return
	}

	// Phase 17 Step 4c: strict upload_id shape. UploadID is client-
	// generated (protocol contract: `up_` + 21-char nanoid body) and
	// becomes the map key for pending uploads. Without this check a
	// client can wedge the pending-uploads map with 1MB-long keys.
	// Malformed upload_id is NOT echoed back in the UploadError —
	// avoids log-injection via buggy clients shipping control chars.
	if err := store.ValidateNanoID(msg.UploadID, "up_"); err != nil {
		s.rejectAndLog(c, counters.SignalInvalidNanoID, "upload_start",
			fmt.Sprintf("invalid upload_id: %v", err), nil)
		c.Encoder.Encode(protocol.UploadError{
			Type:    "upload_error",
			Code:    "invalid_upload_id",
			Message: "invalid upload_id",
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
		// Phase 17 Step 4c Part 3: client declared upload size exceeds
		// MaxFileSize (config knob, default 50MB). No legitimate client
		// has a reason to declare >50MB for a chat attachment — this is
		// a hostile or broken client. SignalOversizedBody is an
		// AutoRevokeSignals-eligible misbehavior signal; Phase 17b will
		// threshold on sustained rate.
		s.rejectAndLog(c, counters.SignalOversizedBody, "upload_start",
			fmt.Sprintf("declared size=%d exceeds max=%d", msg.Size, maxSize), nil)
		c.Encoder.Encode(protocol.UploadError{
			Type:     "upload_error",
			UploadID: msg.UploadID,
			Code:     protocol.ErrUploadTooLarge,
			Message:  fmt.Sprintf("File exceeds maximum size (%d bytes)", maxSize),
		})
		return
	}

	if msg.ContentHash == "" {
		// Phase 17 Step 4c Part 3: content_hash is a required protocol
		// field. Omission is a protocol violation — legitimate clients
		// always include it. SignalMalformedFrame fires so Phase 17b
		// can threshold on sustained rate.
		s.rejectAndLog(c, counters.SignalMalformedFrame, "upload_start",
			"missing required content_hash field", nil)
		c.Encoder.Encode(protocol.UploadError{
			Type:     "upload_error",
			UploadID: msg.UploadID,
			Code:     "missing_hash",
			Message:  "content_hash is required",
		})
		return
	}

	// Phase 17 Step 4c: strict format check on content_hash.
	// `^blake2b-256:[0-9a-f]{64}$` — lowercase hex only, per the
	// protocol contract. Pre-4c a malformed hash reached the re-compute
	// path at upload completion and surfaced as a silent hash_mismatch;
	// now we reject early with a distinct signal that Phase 17b can
	// act on.
	if !validContentHash(msg.ContentHash) {
		s.rejectAndLog(c, counters.SignalInvalidContentHash, "upload_start",
			"content_hash fails blake2b-256:<hex64> format", nil)
		c.Encoder.Encode(protocol.UploadError{
			Type:     "upload_error",
			UploadID: msg.UploadID,
			Code:     "invalid_content_hash",
			Message:  "content_hash must match blake2b-256:<64 lowercase hex chars>",
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
		// Phase 17 Step 4c Part 3: envelope must specify exactly one of
		// room/group/dm. Zero contexts or >1 contexts is a protocol
		// violation — legitimate clients know where they're sending.
		// SignalMalformedFrame fires for Phase 17b observability.
		s.rejectAndLog(c, counters.SignalMalformedFrame, "upload_start",
			fmt.Sprintf("contextCount=%d (want exactly 1 of room/group/dm)", contextCount), nil)
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

	// Phase 17 Step 4c follow-up: each non-member branch fires
	// SignalNonMemberContext so Phase 17b threshold analysis can
	// discriminate one-shot legit races (kick-during-compose, stale
	// reconnect state → 1-2 events) from sustained probing / buggy
	// clients (many events). Wire response stays byte-identical per
	// Phase 14 privacy invariant.
	switch {
	case msg.Room != "":
		if !s.store.IsRoomMemberByID(msg.Room, c.UserID) {
			s.rejectAndLog(c, counters.SignalNonMemberContext, "upload_start",
				fmt.Sprintf("not-a-member of room=%s", msg.Room), nil)
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
			s.rejectAndLog(c, counters.SignalNonMemberContext, "upload_start",
				fmt.Sprintf("not-a-member of group=%s", msg.Group), nil)
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
			s.rejectAndLog(c, counters.SignalNonMemberContext, "upload_start",
				fmt.Sprintf("not-a-party of dm=%s", msg.DM), nil)
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
	// Phase 17 Step 5: rate-limit per-user download verbs. Default
	// 60/min (1/sec) is higher than other refresh verbs because
	// attachment-heavy chat views (photo gallery, multi-image threads)
	// legitimately fire bursts of download requests when opened.
	if allowed, retryMs := s.limiter.allowPerMinuteWithRetry("download:"+c.UserID, s.cfg.Server.RateLimits.DownloadRequestsPerMinute); !allowed {
		s.rejectAndLog(c, counters.SignalRateLimited, "download", "download rate limit exceeded",
			&protocol.Error{Type: "error", Code: protocol.ErrRateLimited, Message: "Too many download requests — wait a moment", RetryAfterMs: retryMs})
		return
	}

	var msg protocol.Download
	if err := json.Unmarshal(raw, &msg); err != nil {
		s.rejectAndLog(c, counters.SignalMalformedFrame, "download", "malformed download frame",
			&protocol.Error{
				Type: "error", Code: "invalid_message",
				Message: "malformed download",
			})
		return
	}

	// Path-traversal defense: file_id flows into filepath.Join below.
	// Strict nanoid shape check catches "../../etc/passwd" and other
	// filesystem-escape attempts at the wire boundary. Phase 17 Step 5
	// amendment: route through rejectAndLog (was direct counters.Inc,
	// legacy from Step 4.f) for the structured Warn log. Wire response
	// is a DownloadError (not the generic Error that rejectAndLog's
	// clientErr param encodes), so we pass nil and Encode separately.
	if err := store.ValidateNanoID(msg.FileID, "file_"); err != nil {
		s.rejectAndLog(c, counters.SignalInvalidNanoID, "download",
			fmt.Sprintf("invalid file_id: %v", err), nil)
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
	//
	// Phase 17 Step 4c follow-up: ACL-deny fires SignalDownloadNotFound
	// (misbehavior). Wire response stays byte-identical to the
	// file-missing case below. One-shot post-leave click stays under
	// threshold; sustained probing crosses it.
	if !s.authorizeDownload(c.UserID, msg.FileID) {
		s.rejectAndLog(c, counters.SignalDownloadNotFound, "download",
			fmt.Sprintf("ACL deny for file_id=%s", msg.FileID), nil)
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
	//
	// Phase 17 Step 4c follow-up: SignalDownloadNoChannel fires so
	// Phase 17b can auto-revoke broken clients that repeatedly send
	// download verbs without Channel 2 open. Legit clients never hit
	// this path; a buggy client hits it every download.
	if c.DownloadChannel == nil {
		s.rejectAndLog(c, counters.SignalDownloadNoChannel, "download",
			fmt.Sprintf("download request without Channel 2 open for file_id=%s", msg.FileID), nil)
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
		// Phase 17 Step 4c follow-up: file-missing path fires the same
		// SignalDownloadNotFound as ACL-deny (single signal for the
		// first cut — wire response is byte-identical anyway;
		// post-launch data tells us if we need to split).
		s.rejectAndLog(c, counters.SignalDownloadNotFound, "download",
			fmt.Sprintf("file missing on disk for file_id=%s", msg.FileID), nil)
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
		// Phase 17 Step 4c follow-up: server-side I/O error after
		// os.Stat succeeded. Fires SignalDownloadNotFound — merged
		// with the ACL-deny + file-missing paths above because the
		// wire response is byte-identical (Phase 17c Category D:
		// one signal per privacy-identical response). Circuit-
		// breaker behavior: a degrading disk that affects every
		// active user cascades to mass auto-revoke via Phase 17b
		// thresholds, stopping further writes against compromised
		// storage. Recovery is operator-manual per Phase 17b
		// design (`enabled = false` + restart, or OS-SSH +
		// `sshkey-ctl approve-device`).
		s.rejectAndLog(c, counters.SignalDownloadNotFound, "download",
			fmt.Sprintf("os.Open failed for file_id=%s: %v", msg.FileID, err), nil)
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
			// Unknown upload — discard the data and continue. Not
			// strictly hostile (may be a timing race where the client
			// disconnected the control channel before the server saw
			// upload_start) so no counter increment. The refactor plan
			// notes this as a low-priority observability gap.
			io.CopyN(io.Discard, ch, int64(size))
			continue
		}

		// Phase 17 Step 4b: bound `size` (the wire-supplied data_len)
		// against the upload_start-declared size before any allocation.
		// A hostile client can set data_len to ExaBytes — io.CopyN
		// below would then attempt an ExaByte allocation. pending.size
		// is already bounded by MaxFileSize at upload_start, so using
		// it as the ceiling here composes the two checks correctly.
		// On reject: increment SignalOversizedUploadFrame (Phase 17b
		// misbehavior signal), notify the originator via find-first-
		// by-UserID (matching the hash-mismatch pattern below), drop
		// the pending entry, and close the upload channel — draining
		// ExaBytes of garbage is not an option.
		if size > uint64(pending.size) {
			s.rejectAndLog(nil, counters.SignalOversizedUploadFrame, "upload_frame",
				fmt.Sprintf("upload_id=%s data_len=%d exceeds declared size=%d", uploadID, size, pending.size), nil)
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
				Code:     protocol.ErrUploadTooLarge,
				Message:  "Upload frame exceeds declared size",
			}, targets)
			s.failUpload(uploadID, "")
			return
		}

		// Write to file
		filePath := filepath.Join(s.files.dir, pending.fileID)
		f, err := os.Create(filePath)
		if err != nil {
			s.logger.Error("upload: create file failed", "error", err)
			io.CopyN(io.Discard, ch, int64(size))
			s.failUpload(uploadID, "") // Phase 17 Step 4b: was leaking pending entry
			continue
		}

		written, err := io.CopyN(f, ch, int64(size))
		f.Close()

		if err != nil || written != int64(size) {
			s.logger.Error("upload: write failed", "expected", size, "written", written, "error", err)
			s.failUpload(uploadID, filePath) // Phase 17 Step 4b: was leaking pending entry
			continue
		}

		// Verify content hash (required — always present)
		fileData, err := os.ReadFile(filePath)
		if err != nil {
			s.logger.Error("upload: read-back for hash failed", "file", pending.fileID, "error", err)
			s.failUpload(uploadID, filePath) // Phase 17 Step 4b: was leaking pending entry
			continue
		}
		serverHash := contentHash(fileData)
		if serverHash != pending.contentHash {
			// Phase 17 Step 4c Part 3: count hash-mismatch rejections so
			// Phase 17b observability sees them. Hash mismatch at commit
			// time is unusual — legitimate clients use the same library
			// the server does, matching byte-for-byte; a mismatch is
			// either in-transit corruption (rare) or a client bug / attack
			// probing the re-compute path. Channel 3 attribution limitation
			// applies: rejection counts under empty deviceID per Step 2 spec.
			s.rejectAndLog(nil, counters.SignalInvalidContentHash, "upload_frame",
				fmt.Sprintf("upload_id=%s file_id=%s hash mismatch (expected=%s got=%s)",
					uploadID, pending.fileID, pending.contentHash, serverHash), nil)
			s.logger.Error("upload: content hash mismatch",
				"file", pending.fileID,
				"expected", pending.contentHash,
				"got", serverHash,
			)
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
			s.failUpload(uploadID, filePath)
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
