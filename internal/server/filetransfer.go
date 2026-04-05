package server

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"golang.org/x/crypto/ssh"

	"github.com/brushtailmedia/sshkey/internal/protocol"
)

// fileManager handles file uploads and downloads via Channel 2.
type fileManager struct {
	dir string // file storage directory

	mu      sync.RWMutex
	uploads map[string]*pendingUpload // upload_id -> pending
}

type pendingUpload struct {
	uploadID string
	fileID   string
	size     int64
	user     string
	room     string
	convID   string
}

func newFileManager(dataDir string) *fileManager {
	dir := filepath.Join(dataDir, "data", "files")
	os.MkdirAll(dir, 0750)
	return &fileManager{
		dir:     dir,
		uploads: make(map[string]*pendingUpload),
	}
}

// handleUploadStart processes an upload_start request on Channel 1.
func (s *Server) handleUploadStart(c *Client, raw json.RawMessage) {
	if !s.limiter.allowPerMinute("upload:"+c.Username, s.cfg.Server.RateLimits.UploadsPerMinute) {
		c.Encoder.Encode(protocol.Error{Type: "error", Code: protocol.ErrRateLimited, Message: "Upload rate limit exceeded"})
		return
	}

	var msg protocol.UploadStart
	if err := json.Unmarshal(raw, &msg); err != nil {
		c.Encoder.Encode(protocol.Error{Type: "error", Code: "invalid_message", Message: "malformed upload_start"})
		return
	}

	// Validate file size
	// TODO: parse max_file_size from config string to bytes
	maxSize := int64(50 * 1024 * 1024) // 50MB default
	if msg.Size > maxSize {
		c.Encoder.Encode(protocol.Error{
			Type:    "error",
			Code:    protocol.ErrUploadTooLarge,
			Message: fmt.Sprintf("File exceeds maximum size (%d bytes)", maxSize),
		})
		return
	}

	fileID := generateID("file_")

	s.files.mu.Lock()
	s.files.uploads[msg.UploadID] = &pendingUpload{
		uploadID: msg.UploadID,
		fileID:   fileID,
		size:     msg.Size,
		user:     c.Username,
		room:     msg.Room,
		convID:   msg.Conversation,
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
		c.Encoder.Encode(protocol.Error{
			Type:    "error",
			Code:    "not_found",
			Message: "File not found: " + msg.FileID,
		})
		return
	}

	c.Encoder.Encode(protocol.DownloadStart{
		Type:   "download_start",
		FileID: msg.FileID,
		Size:   info.Size(),
	})

	// Send file bytes on Channel 2
	if c.BinaryChannel != nil {
		f, err := os.Open(filePath)
		if err != nil {
			s.logger.Error("download: open failed", "file", msg.FileID, "error", err)
			return
		}
		defer f.Close()

		if err := writeBinaryFrame(c.BinaryChannel, msg.FileID, f, info.Size()); err != nil {
			s.logger.Error("download: write failed", "file", msg.FileID, "error", err)
			return
		}
	} else {
		s.logger.Error("download: no binary channel", "user", c.Username)
	}

	c.Encoder.Encode(protocol.DownloadComplete{
		Type:   "download_complete",
		FileID: msg.FileID,
	})
}

// handleBinaryChannel processes incoming data on SSH Channel 2 (file uploads).
func (s *Server) handleBinaryChannel(username string, ch ssh.Channel) {
	defer ch.Close()

	for {
		// Read binary frame: id_len(1) | id(variable) | data_len(8) | data(variable)
		var idLen [1]byte
		if _, err := io.ReadFull(ch, idLen[:]); err != nil {
			if err != io.EOF {
				s.logger.Debug("binary channel read id_len", "error", err)
			}
			return
		}

		idBuf := make([]byte, idLen[0])
		if _, err := io.ReadFull(ch, idBuf); err != nil {
			s.logger.Error("binary channel read id", "error", err)
			return
		}
		uploadID := string(idBuf)

		var dataLen [8]byte
		if _, err := io.ReadFull(ch, dataLen[:]); err != nil {
			s.logger.Error("binary channel read data_len", "error", err)
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

// writeBinaryFrame writes a Channel 2 binary frame.
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
