package server

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/ssh"

	"github.com/brushtailmedia/sshkey-chat/internal/config"
	"github.com/brushtailmedia/sshkey-chat/internal/protocol"
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
	convID      string
}

func newFileManager(dataDir string) *fileManager {
	dir := filepath.Join(dataDir, "data", "files")
	os.MkdirAll(dir, 0750)
	return &fileManager{
		dir:     dir,
		uploads: make(map[string]*pendingUpload),
	}
}

// cleanOrphanFiles removes files in the files directory that have no
// corresponding entry in the file_hashes table. These are artifacts of
// crashed mid-uploads that were written to disk but never completed.
// Called once on server startup.
func (s *Server) cleanOrphanFiles() {
	if s.files == nil || s.store == nil {
		return
	}

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

	if removed > 0 {
		s.logger.Info("cleaned orphan files", "count", removed)
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

	if !s.limiter.allowPerMinute("upload:"+c.Username, s.cfg.Server.RateLimits.UploadsPerMinute) {
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

	fileID := generateID("file_")

	s.files.mu.Lock()
	s.files.uploads[msg.UploadID] = &pendingUpload{
		uploadID:    msg.UploadID,
		fileID:      fileID,
		size:        msg.Size,
		contentHash: msg.ContentHash,
		user:        c.Username,
		room:        msg.Room,
		convID:      msg.Conversation,
	}
	s.files.mu.Unlock()

	c.Encoder.Encode(protocol.UploadReady{
		Type:     "upload_ready",
		UploadID: msg.UploadID,
	})
}

// handleDownload processes a download request on Channel 1.
func (s *Server) handleDownload(c *Client, raw json.RawMessage) {
	var msg protocol.Download
	if err := json.Unmarshal(raw, &msg); err != nil {
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

	if c.DownloadChannel == nil {
		s.logger.Error("download: no download channel", "user", c.Username)
		c.Encoder.Encode(protocol.DownloadError{
			Type:    "download_error",
			FileID:  msg.FileID,
			Code:    "no_channel",
			Message: "Download channel not open",
		})
		return
	}

	f, err := os.Open(filePath)
	if err != nil {
		s.logger.Error("download: open failed", "file", msg.FileID, "error", err)
		c.Encoder.Encode(protocol.DownloadError{
			Type:    "download_error",
			FileID:  msg.FileID,
			Code:    "open_failed",
			Message: "Server could not open file",
		})
		return
	}
	defer f.Close()

	// Look up stored content hash to include in download_start
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
		// Can't signal via Channel 1 anymore — the client is mid-read on
		// Channel 2 and the binary frame is partial/corrupt. Closing the
		// download channel is the only way to abort cleanly, but that
		// would tear down other concurrent downloads too. Log and hope
		// the client times out (SSH layer will close on connection drop).
		return
	}

	c.Encoder.Encode(protocol.DownloadComplete{
		Type:   "download_complete",
		FileID: msg.FileID,
	})
}

// handleBinaryChannel processes incoming upload frames on SSH Channel 3.
func (s *Server) handleBinaryChannel(username string, ch ssh.Channel) {
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
			s.mu.RLock()
			for _, client := range s.clients {
				if client.Username == username {
					client.Encoder.Encode(protocol.UploadError{
						Type:     "upload_error",
						UploadID: uploadID,
						Code:     "hash_mismatch",
						Message:  "Content hash mismatch — file corrupted in transit",
					})
					break
				}
			}
			s.mu.RUnlock()
			s.files.mu.Lock()
			delete(s.files.uploads, uploadID)
			s.files.mu.Unlock()
			continue
		}

		// Store content hash in DB for download verification
		if s.store != nil {
			s.store.StoreFileHash(pending.fileID, pending.contentHash, int64(size))
		}

		// Clean up pending
		s.files.mu.Lock()
		delete(s.files.uploads, uploadID)
		s.files.mu.Unlock()

		s.logger.Info("file uploaded",
			"user", username,
			"upload_id", uploadID,
			"file_id", pending.fileID,
			"size", size,
		)

		// Send upload_complete on Channel 1 — find the client
		s.mu.RLock()
		for _, client := range s.clients {
			if client.Username == username {
				client.Encoder.Encode(protocol.UploadComplete{
					Type:     "upload_complete",
					UploadID: uploadID,
					FileID:   pending.fileID,
				})
				break
			}
		}
		s.mu.RUnlock()
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
