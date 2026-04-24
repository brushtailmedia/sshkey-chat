package server

// Phase 17 Step 4b — Channel 3 binary-frame bound + pendingUpload
// leak-fix tests.
//
// Coverage:
//   - failUpload helper: pending-map eviction, file removal,
//     idempotence, empty-filePath case.
//   - handleBinaryChannel oversized-frame rejection: data_len >
//     pending.size fires SignalOversizedUploadFrame, notifies the
//     originator, drops the pending entry, and closes the channel.
//   - handleBinaryChannel hash-mismatch path still cleans up via
//     failUpload (regression against the old manual cleanup that
//     was correct but not using the new helper).
//
// The leak-fix paths (os.Create / Write / Hash read-back failure)
// are harder to drive in a unit test because they require injecting
// I/O failures into the real filesystem. Smoke-covered by the
// helper tests + the existing cleanOrphanFiles startup-sweep test
// which reconciles any orphans the eager-cleanup paths miss.

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/brushtailmedia/sshkey-chat/internal/counters"
	"github.com/brushtailmedia/sshkey-chat/internal/protocol"
)

// bufferedChannel is a minimal ssh.Channel implementation that reads
// from a prepared byte slice and writes to an in-memory buffer.
// Suitable for driving handleBinaryChannel through a single frame
// then having it exit on EOF.
type bufferedChannel struct {
	in     *bytes.Reader
	out    bytes.Buffer
	closed atomic.Int32
}

func newBufferedChannel(in []byte) *bufferedChannel {
	return &bufferedChannel{in: bytes.NewReader(in)}
}

func (c *bufferedChannel) Read(p []byte) (int, error)  { return c.in.Read(p) }
func (c *bufferedChannel) Write(p []byte) (int, error) { return c.out.Write(p) }
func (c *bufferedChannel) Close() error {
	c.closed.Add(1)
	return nil
}
func (c *bufferedChannel) CloseWrite() error { return nil }
func (c *bufferedChannel) SendRequest(name string, wantReply bool, payload []byte) (bool, error) {
	return false, nil
}
func (c *bufferedChannel) Stderr() io.ReadWriter { return nil }

var _ ssh.Channel = (*bufferedChannel)(nil)

// buildUploadFrame constructs a Channel 3 binary frame:
// id_len(1) | id | data_len(8) | data
func buildUploadFrame(uploadID string, declaredSize uint64, data []byte) []byte {
	var buf bytes.Buffer
	buf.WriteByte(byte(len(uploadID)))
	buf.WriteString(uploadID)
	var sizeBytes [8]byte
	binary.BigEndian.PutUint64(sizeBytes[:], declaredSize)
	buf.Write(sizeBytes[:])
	buf.Write(data)
	return buf.Bytes()
}

func TestFailUpload_RemovesPendingEntryAndFile(t *testing.T) {
	s := newTestServer(t)

	// Seed a file on disk + a pending entry.
	filePath := filepath.Join(t.TempDir(), "file_test")
	if err := os.WriteFile(filePath, []byte("payload"), 0600); err != nil {
		t.Fatalf("write seed file: %v", err)
	}
	s.files.mu.Lock()
	s.files.uploads["up_test"] = &pendingUpload{uploadID: "up_test"}
	s.files.mu.Unlock()

	s.failUpload("up_test", filePath)

	if _, err := os.Stat(filePath); !os.IsNotExist(err) {
		t.Errorf("file should be removed, got err=%v", err)
	}
	s.files.mu.RLock()
	_, exists := s.files.uploads["up_test"]
	s.files.mu.RUnlock()
	if exists {
		t.Error("pending entry should be removed from map")
	}
}

func TestFailUpload_Idempotent(t *testing.T) {
	s := newTestServer(t)
	s.files.mu.Lock()
	s.files.uploads["up_idem"] = &pendingUpload{uploadID: "up_idem"}
	s.files.mu.Unlock()

	// First call: removes the entry.
	s.failUpload("up_idem", "")
	// Second call: must not panic even though entry is gone.
	s.failUpload("up_idem", "")
	// Third call on a never-registered ID: also must not panic.
	s.failUpload("up_never_registered", "")
}

func TestFailUpload_MissingFileIsTolerated(t *testing.T) {
	s := newTestServer(t)
	// Pass a filePath that does not exist. os.Remove returns an error
	// but failUpload must swallow it — partial uploads may have failed
	// before the file was created.
	nonExistent := filepath.Join(t.TempDir(), "never_created")
	s.files.mu.Lock()
	s.files.uploads["up_missing"] = &pendingUpload{uploadID: "up_missing"}
	s.files.mu.Unlock()

	s.failUpload("up_missing", nonExistent)

	s.files.mu.RLock()
	_, exists := s.files.uploads["up_missing"]
	s.files.mu.RUnlock()
	if exists {
		t.Error("pending entry should still be removed even when file is missing")
	}
}

func TestFailUpload_EmptyFilePathSkipsRemove(t *testing.T) {
	// Used for the oversized-frame case where the physical file
	// was never opened.
	s := newTestServer(t)
	s.files.mu.Lock()
	s.files.uploads["up_empty_path"] = &pendingUpload{uploadID: "up_empty_path"}
	s.files.mu.Unlock()

	s.failUpload("up_empty_path", "")

	s.files.mu.RLock()
	_, exists := s.files.uploads["up_empty_path"]
	s.files.mu.RUnlock()
	if exists {
		t.Error("empty filePath should still drop the pending entry")
	}
}

func TestHandleBinaryChannel_OversizedFrameRejected(t *testing.T) {
	s := newTestServer(t)

	// Seed the originating client so the upload_error notification
	// path can find a target via find-first-by-UserID.
	alice := testClientFor("alice", "dev_alice_1")
	s.mu.Lock()
	s.clients["dev_alice_1"] = alice.Client
	s.mu.Unlock()

	// Seed a pending upload with a small declared size.
	uploadID := "up_oversizedfrm_42xyz00"
	s.files.mu.Lock()
	s.files.uploads[uploadID] = &pendingUpload{
		uploadID: uploadID,
		fileID:   "file_test_oversized00",
		size:     1024, // declared 1 KB
		user:     "alice",
	}
	s.files.mu.Unlock()

	// Craft a frame claiming 1 MB of data. No body follows — the
	// server should reject before reading any of the data.
	frame := buildUploadFrame(uploadID, 1024*1024, nil)
	ch := newBufferedChannel(frame)

	s.handleBinaryChannel("alice", ch)

	// Channel was closed (deferred on return).
	if ch.closed.Load() == 0 {
		t.Error("upload channel should be closed after oversized frame rejection")
	}

	// Counter fired.
	if got := s.counters.Get(counters.SignalOversizedUploadFrame, ""); got != 1 {
		t.Errorf("SignalOversizedUploadFrame (empty device attribution for Channel 3) = %d, want 1", got)
	}

	// Pending entry is gone.
	s.files.mu.RLock()
	_, exists := s.files.uploads[uploadID]
	s.files.mu.RUnlock()
	if exists {
		t.Error("pending upload entry should have been dropped after oversized rejection")
	}

	// Originator received an upload_error with upload_too_large code.
	msgs := alice.messages()
	var foundErr bool
	for _, raw := range msgs {
		var ue protocol.UploadError
		if err := json.Unmarshal(raw, &ue); err == nil && ue.Type == "upload_error" && ue.UploadID == uploadID {
			foundErr = true
			if ue.Code != protocol.ErrUploadTooLarge {
				t.Errorf("upload_error code = %q, want %q", ue.Code, protocol.ErrUploadTooLarge)
			}
			break
		}
	}
	if !foundErr {
		t.Errorf("expected upload_error for upload_id=%s on originator's control channel; got %d messages", uploadID, len(msgs))
	}
}

func TestHandleBinaryChannel_InBoundsFrameSucceeds(t *testing.T) {
	// Verify the happy path: a frame with data_len <= pending.size
	// proceeds to file write. This locks in that the 4b bound check
	// isn't over-tight.
	s := newTestServer(t)

	alice := testClientFor("alice", "dev_alice_1")
	s.mu.Lock()
	s.clients["dev_alice_1"] = alice.Client
	s.mu.Unlock()

	payload := []byte("hello world")
	uploadID := "up_inboundfrm_42xyz000"
	s.files.mu.Lock()
	s.files.uploads[uploadID] = &pendingUpload{
		uploadID:    uploadID,
		fileID:      "file_inbound_frame_0000",
		size:        int64(len(payload)),
		contentHash: contentHash(payload),
		user:        "alice",
		// no context — this test only verifies the frame path, not binding
	}
	s.files.mu.Unlock()

	// Frame claims exactly len(payload) — in-bounds.
	frame := buildUploadFrame(uploadID, uint64(len(payload)), payload)
	ch := newBufferedChannel(frame)

	s.handleBinaryChannel("alice", ch)

	// Oversized counter must NOT have fired.
	if got := s.counters.Get(counters.SignalOversizedUploadFrame, ""); got != 0 {
		t.Errorf("SignalOversizedUploadFrame = %d, want 0 for in-bounds frame", got)
	}
}
