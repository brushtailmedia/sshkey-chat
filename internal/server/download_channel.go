package server

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/brushtailmedia/sshkey-chat/internal/counters"
	"github.com/brushtailmedia/sshkey-chat/internal/protocol"
	"github.com/brushtailmedia/sshkey-chat/internal/store"
)

// DownloadChannelType is the SSH channel subtype a client opens to
// request a single file download. One channel per download, streamed
// independently. The per-connection dispatcher in handleConnection
// accepts this type alongside "session"; see download_fix.md
// §"SSH channel dispatch model".
const DownloadChannelType = "sshkey-chat-download"

// handleDownloadChannel serves one file download on a fresh SSH channel
// (Phase 17 Step 4.f). The channel is client-initiated via
// OpenChannel("sshkey-chat-download"); this handler runs per channel
// and owns its lifecycle end-to-end:
//
//  1. Enforce per-connection concurrency cap (atomic CAS on
//     activeDownloads, rejecting channel open past the cap).
//  2. Register a hard wall-clock TTL via time.AfterFunc — cancelled
//     on normal close, fires ch.Close() on timeout to defend against
//     hostile slow-read.
//  3. Read a single line-delimited JSON download request off the
//     channel. No channel-1 coupling; the request lives on the new
//     channel.
//  4. Look up the file's context binding (file_contexts table).
//  5. Run the per-context ACL check (membership + join-watermark for
//     rooms/groups; party-only for 1:1 DMs — see
//     context_lifecycle_model memory note for the DM design).
//  6. On success: write a download_start JSON line, stream the file
//     bytes via writeBinaryFrame, write download_complete, close.
//     On failure: write a download_error JSON line and close.
//
// Identity discipline: userID is the authenticated SSH-connection
// identity (sshConn.Permissions.Extensions["username"]), never
// anything read from the channel. See download_fix.md §"Identity
// sourcing — discipline for the new channel handler".
//
// activeDownloads is per-SSH-connection (scoped to the caller's
// handleConnection invocation). A user with N connected devices has
// N activeDownloads counters, each independently enforced.
func (s *Server) handleDownloadChannel(
	userID string,
	sshConn *ssh.ServerConn,
	newCh ssh.NewChannel,
	activeDownloads *atomic.Int32,
) {
	// Step 1: cap check BEFORE accepting. Rejecting before accept
	// avoids the cost of channel setup and keeps the counter honest.
	// CAS loop handles the race where another download channel opens
	// concurrently on this same connection.
	s.cfg.RLock()
	cap := int32(s.cfg.Server.Downloads.MaxConcurrentPerClient)
	ttlSec := s.cfg.Server.Downloads.ChannelTTLSeconds
	s.cfg.RUnlock()
	if cap <= 0 {
		cap = 3 // defensive fallback matching DefaultServerConfig
	}
	if ttlSec <= 0 {
		ttlSec = 60
	}

	for {
		current := activeDownloads.Load()
		if current >= cap {
			// Over cap — reject the channel open and increment the
			// observability counter. Device attribution via
			// sshConn.Permissions is not available on NewChannel, so
			// we pass userID as the counter key instead. Slightly
			// coarser than device-level but sufficient for Phase 17b
			// auto-revoke (multi-device misbehavior still registers
			// on every device attempt).
			s.counters.Inc(counters.SignalDownloadChannelRejected, userID)
			newCh.Reject(ssh.ResourceShortage, "concurrent download limit reached")
			s.logger.Debug("download channel rejected (over cap)",
				"user", userID,
				"cap", cap,
				"current", current,
			)
			return
		}
		if activeDownloads.CompareAndSwap(current, current+1) {
			break
		}
		// CAS lost — another goroutine won, retry with fresh value.
	}
	// If we accepted, we must decrement on exit.
	defer activeDownloads.Add(-1)

	ch, chReqs, err := newCh.Accept()
	if err != nil {
		s.logger.Error("download channel accept failed", "user", userID, "error", err)
		return
	}
	go ssh.DiscardRequests(chReqs)

	// Step 2: TTL timer. Hard cap on channel lifetime defends against
	// slow-read abuse. Cancelled on normal return; if it fires first,
	// ch.Close() unblocks any pending I/O in the streaming loop.
	ttl := time.Duration(ttlSec) * time.Second
	ttlTimer := time.AfterFunc(ttl, func() {
		s.logger.Debug("download channel TTL expired",
			"user", userID,
			"ttl_seconds", ttlSec,
		)
		ch.Close()
	})
	defer ttlTimer.Stop()
	defer ch.Close() // belt-and-braces; Close is idempotent on ssh.Channel

	// Step 3: read the download request from the channel. One line of
	// JSON followed by server bytes on success. Bounded read — the
	// request is a small JSON object, cap at 4 KB to prevent hostile
	// clients from sending multi-MB "requests" that never terminate.
	reader := bufio.NewReaderSize(ch, 4096)
	reqLine, err := reader.ReadBytes('\n')
	if err != nil {
		s.logger.Debug("download channel request read failed",
			"user", userID,
			"error", err,
		)
		return
	}

	var req protocol.Download
	if err := json.Unmarshal(reqLine, &req); err != nil {
		s.sendDownloadError(ch, "", "invalid_request", "malformed download request")
		return
	}
	if req.Type != "download" {
		s.sendDownloadError(ch, req.FileID, "invalid_request", "expected type=\"download\"")
		return
	}

	// Step 4: path-traversal defense. file_id must be shape-safe because
	// it flows directly into filepath.Join below. The nanoid alphabet
	// (0-9A-Za-z_-) inherently blocks '/', '\', '.', null bytes — any
	// traversal attempt is caught here at the channel boundary.
	if err := store.ValidateNanoID(req.FileID, "file_"); err != nil {
		s.counters.Inc(counters.SignalInvalidNanoID, userID)
		s.sendDownloadError(ch, req.FileID, "invalid_file_id", "invalid file_id")
		return
	}

	// Step 5: ACL check. Lookup the file_contexts binding; if absent,
	// or if the caller's access doesn't clear the per-context gate,
	// respond with a privacy-preserving "not_found" — byte-identical
	// across "file doesn't exist" and "you can't read this file" so a
	// probing client with a leaked file_id cannot distinguish the two.
	if !s.authorizeDownload(userID, req.FileID) {
		s.sendDownloadError(ch, req.FileID, "not_found", "file not found")
		return
	}

	// Step 6: stream the bytes. filepath.Join under files.dir is safe
	// now that file_id is validated. os.Stat + os.Open can still fail
	// if the hash row exists but bytes are missing (disk corruption or
	// mid-cleanup race) — treat as not_found for the same privacy
	// reason.
	filePath := filepath.Join(s.files.dir, req.FileID)
	info, err := os.Stat(filePath)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			s.logger.Error("download: stat failed",
				"file", req.FileID, "error", err)
		}
		s.sendDownloadError(ch, req.FileID, "not_found", "file not found")
		return
	}

	f, err := os.Open(filePath)
	if err != nil {
		s.logger.Error("download: open failed",
			"file", req.FileID, "error", err)
		s.sendDownloadError(ch, req.FileID, "not_found", "file not found")
		return
	}
	defer f.Close()

	// Fetch the stored hash so the client can verify bytes end-to-end.
	var storedHash string
	if s.store != nil {
		storedHash, _ = s.store.GetFileHash(req.FileID)
	}

	// Write the download_start JSON line with size + hash. Client uses
	// size to size its read buffer and hash to verify on completion.
	if err := writeJSONLine(ch, protocol.DownloadStart{
		Type:        "download_start",
		FileID:      req.FileID,
		Size:        info.Size(),
		ContentHash: storedHash,
	}); err != nil {
		s.logger.Debug("download: download_start write failed",
			"file", req.FileID, "error", err)
		return
	}

	// Stream bytes. writeBinaryFrame uses the same id_len/id/data_len/data
	// format as the upload channel; keeping the frame shape consistent
	// lets the client's decoder reuse its upload-frame reader logic.
	if err := writeBinaryFrame(ch, req.FileID, f, info.Size()); err != nil {
		s.logger.Error("download: write failed",
			"file", req.FileID, "error", err)
		// Can't usefully report — the binary frame is partially written,
		// any further JSON on this channel would corrupt the client's
		// decoder. Just close; client times out or sees short read.
		return
	}

	// download_complete signals a clean end-of-stream. Client uses this
	// to know it's done reading (vs TTL-aborted mid-stream).
	if err := writeJSONLine(ch, protocol.DownloadComplete{
		Type:   "download_complete",
		FileID: req.FileID,
	}); err != nil {
		s.logger.Debug("download: download_complete write failed",
			"file", req.FileID, "error", err)
		return
	}

	s.logger.Debug("download complete",
		"user", userID,
		"file", req.FileID,
		"size", info.Size(),
	)
}

// authorizeDownload runs the ACL check for a single download request.
// Returns true iff the caller is allowed to download file_id under the
// per-context rules documented in download_fix.md §"Download access
// check" and §"Temporal gate semantics".
//
// Privacy: this function returns a single bool. Callers must render
// the "no" case byte-identically to "file doesn't exist" — the caller
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
		// Forward-secrecy gate: file must have been attached AFTER the
		// user joined this room. Mirrors the sync-path first_seen gate
		// at sync.go:syncRoom. first_seen == 0 means no record — fail
		// closed (non-member or data gap).
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
		// Same forward-secrecy gate as rooms, via joined_at. Group
		// re-join produces a fresh joined_at (AddGroupMember is
		// DELETE-then-INSERT), so re-joiners correctly lose access to
		// files attached during their absence window.
		joinedAt, err := s.store.GetUserGroupJoinedAt(userID, binding.ContextID)
		if err != nil || joinedAt <= 0 {
			return false
		}
		return joinedAt <= binding.TS

	case store.FileContextDM:
		// 1:1 DM: party check only. user_*_left_at is a history-hiding
		// lower bound on message reads (ghost-conversation fix), NOT an
		// upper-bound access gate. See context_lifecycle_model memory
		// note — misreading this as a forward-secrecy gate would break
		// the ghost-conversation design by rejecting downloads a leaver
		// is entitled to after re-engaging. Party membership is the
		// authoritative access boundary for DMs.
		dm, err := s.store.GetDirectMessage(binding.ContextID)
		if err != nil || dm == nil {
			return false
		}
		return dm.UserA == userID || dm.UserB == userID

	default:
		// Unknown context_type — reject. Shouldn't happen; InsertFileContext
		// guards against bad values at write time.
		s.logger.Error("download: unknown context_type in binding",
			"file_id", fileID,
			"context_type", binding.ContextType,
		)
		return false
	}
}

// sendDownloadError writes a download_error JSON line to the channel
// and returns. The caller typically does `return` right after so the
// outer defer chain closes the channel. Byte-identical privacy across
// "file doesn't exist" (no binding) / "caller can't read this file"
// (ACL denied) is the caller's responsibility — this function does
// not synthesize the error, it encodes what the caller passes.
func (s *Server) sendDownloadError(ch ssh.Channel, fileID, code, msg string) {
	_ = writeJSONLine(ch, protocol.DownloadError{
		Type:    "download_error",
		FileID:  fileID,
		Code:    code,
		Message: msg,
	})
}

// writeJSONLine marshals v to JSON and writes it to w followed by a
// newline. Matches the NDJSON shape the Channel 1 encoder uses so
// clients can reuse a single parser across channels.
func writeJSONLine(w interface {
	Write([]byte) (int, error)
}, v interface{}) error {
	data, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	data = append(data, '\n')
	_, err = w.Write(data)
	return err
}
