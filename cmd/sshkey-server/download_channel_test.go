package main

// Phase 17 Step 4.f end-to-end coverage for the per-request
// `sshkey-chat-download` channel protocol. These tests run against a
// real in-process server bound to a random TCP port (via newTestEnv),
// use real SSH client handshakes, and exercise the full download flow:
// open channel → inline JSON request → download_start + binary frame +
// download_complete → close.
//
// Coverage:
//   - Successful download round-trip (bytes + hash + full envelope)
//   - Concurrent downloads (3 channels in parallel, up to the cap)
//   - Cap enforcement (over-cap channel opens rejected with
//     ssh.ResourceShortage; client can retry after one completes)
//   - ACL reject for non-member of the bound context (privacy-identical
//     `not_found` response — caller cannot distinguish "doesn't exist"
//     from "no access")
//   - Invalid file_id shape (path-traversal defense)
//
// TTL expiry is NOT covered here — it'd require a multi-second sleep
// per test and is better verified manually or via a separate slow-test
// build tag. The TTL logic is small and exercised by integration in
// production; covering it with a 60-second test per run is not worth
// the CI cost.

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/ssh"

	"github.com/brushtailmedia/sshkey-chat/internal/protocol"
	"github.com/brushtailmedia/sshkey-chat/internal/store"
)

// seedDownloadableFile writes file bytes to the server's files_dir and
// inserts the matching file_hashes + file_contexts rows via a second
// store.Store connection. Bypasses the upload protocol so the
// download-side tests stay focused — the upload-side tests live in
// upload_auth_test.go (server package) and don't need to repeat here.
//
// Uses SQLite WAL + 5s busy_timeout (set by store.Open) so the second
// connection doesn't conflict with the server's live store.
func seedDownloadableFile(t *testing.T, e *testEnv, fileID, ctxType, ctxID string, ts int64, data []byte) string {
	t.Helper()
	filesDir := filepath.Join(e.dataDir, "data", "files")
	if err := os.MkdirAll(filesDir, 0755); err != nil {
		t.Fatalf("mkdir files: %v", err)
	}
	if err := os.WriteFile(filepath.Join(filesDir, fileID), data, 0644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	st, err := store.Open(e.dataDir)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer st.Close()

	h := blake2b.Sum256(data)
	hash := fmt.Sprintf("blake2b-256:%x", h)
	if err := st.StoreFileHash(fileID, hash, int64(len(data))); err != nil {
		t.Fatalf("store hash: %v", err)
	}
	if err := st.InsertFileContext(fileID, ctxType, ctxID, ts); err != nil {
		t.Fatalf("insert file_context: %v", err)
	}
	return hash
}

// openDownloadChannel runs the full client side of the Phase 17 Step 4.f
// download protocol on the given SSH connection. Returns the downloaded
// bytes + the ContentHash reported by download_start + any error.
//
// On success, the function reads the full download_start JSON line, the
// binary frame, and the download_complete trailing line before
// returning — mirrors how a real client would verify the trailer before
// committing bytes to disk.
//
// On failure, returns a formatted error with the server's code + message.
func openDownloadChannel(conn *ssh.Client, fileID string) (data []byte, contentHash string, err error) {
	ch, reqs, err := conn.OpenChannel("sshkey-chat-download", nil)
	if err != nil {
		return nil, "", fmt.Errorf("open channel: %w", err)
	}
	defer ch.Close()
	go ssh.DiscardRequests(reqs)

	// Send the download request inline on the new channel.
	reqLine, err := json.Marshal(protocol.Download{Type: "download", FileID: fileID})
	if err != nil {
		return nil, "", fmt.Errorf("marshal request: %w", err)
	}
	reqLine = append(reqLine, '\n')
	if _, err := ch.Write(reqLine); err != nil {
		return nil, "", fmt.Errorf("send request: %w", err)
	}

	reader := bufio.NewReaderSize(ch, 4096)
	firstLine, err := reader.ReadBytes('\n')
	if err != nil {
		return nil, "", fmt.Errorf("read response: %w", err)
	}

	var probe struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(firstLine, &probe); err != nil {
		return nil, "", fmt.Errorf("parse response: %w", err)
	}

	switch probe.Type {
	case "download_error":
		var de protocol.DownloadError
		if err := json.Unmarshal(firstLine, &de); err != nil {
			return nil, "", fmt.Errorf("parse download_error: %w", err)
		}
		return nil, "", fmt.Errorf("download_error: %s: %s", de.Code, de.Message)
	case "download_start":
		// fall through
	default:
		return nil, "", fmt.Errorf("unexpected response type %q: %s", probe.Type, firstLine)
	}

	var ds protocol.DownloadStart
	if err := json.Unmarshal(firstLine, &ds); err != nil {
		return nil, "", fmt.Errorf("parse download_start: %w", err)
	}

	data, err = readBinaryFrameForTest(reader, ds.Size)
	if err != nil {
		return nil, "", fmt.Errorf("read binary frame: %w", err)
	}

	// Read the trailing download_complete line.
	completeLine, err := reader.ReadBytes('\n')
	if err != nil {
		return nil, "", fmt.Errorf("read trailer: %w", err)
	}
	if err := json.Unmarshal(completeLine, &probe); err != nil {
		return nil, "", fmt.Errorf("parse trailer: %w", err)
	}
	if probe.Type != "download_complete" {
		return nil, "", fmt.Errorf("expected download_complete trailer, got %q: %s", probe.Type, completeLine)
	}

	return data, ds.ContentHash, nil
}

// readBinaryFrameForTest parses the id_len|id|data_len|data binary frame
// the server writes after download_start. Asserts the inline size matches
// the announced download_start size so tests catch server-side length
// drift.
func readBinaryFrameForTest(r io.Reader, announcedSize int64) ([]byte, error) {
	var idLen [1]byte
	if _, err := io.ReadFull(r, idLen[:]); err != nil {
		return nil, fmt.Errorf("read id_len: %w", err)
	}
	idBuf := make([]byte, idLen[0])
	if _, err := io.ReadFull(r, idBuf); err != nil {
		return nil, fmt.Errorf("read id: %w", err)
	}
	var lenBuf [8]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, fmt.Errorf("read data_len: %w", err)
	}
	dataLen := binary.BigEndian.Uint64(lenBuf[:])
	if int64(dataLen) != announcedSize {
		return nil, fmt.Errorf("frame data_len=%d doesn't match download_start size=%d", dataLen, announcedSize)
	}
	data := make([]byte, dataLen)
	if _, err := io.ReadFull(r, data); err != nil {
		return nil, fmt.Errorf("read data: %w", err)
	}
	return data, nil
}

// ============================================================================
// Tests
// ============================================================================

// TestDownloadChannel_HappyPath verifies the full download round-trip
// works on the new per-request channel: alice (a member of "general")
// receives the bytes + hash of a file bound to that room.
func TestDownloadChannel_HappyPath(t *testing.T) {
	e := newTestEnv(t)
	alice := e.connect("/tmp/sshkey-test-key", "dev_alice")

	generalID := e.roomIDByName("general")
	payload := []byte("hello from phase 17 step 4.f")
	fileID := store.GenerateID("file_")
	expectedHash := seedDownloadableFile(t, e, fileID, store.FileContextRoom, generalID, aliceFutureTSForTest(), payload)

	data, hash, err := openDownloadChannel(alice.conn, fileID)
	if err != nil {
		t.Fatalf("download: %v", err)
	}
	if !bytes.Equal(data, payload) {
		t.Errorf("data mismatch: got %q, want %q", data, payload)
	}
	if hash != expectedHash {
		t.Errorf("hash = %q, want %q", hash, expectedHash)
	}
}

// TestDownloadChannel_NonMemberDenied_ACL verifies the ACL rejects a
// non-member. bob is NOT in "engineering" per the fixture seed; a
// download of a file bound to engineering must get `not_found`
// (privacy-preserving) rather than the bytes.
func TestDownloadChannel_NonMemberDenied_ACL(t *testing.T) {
	e := newTestEnv(t)
	bob := e.connect("/tmp/sshkey-test-key-bob", "dev_bob")

	engID := e.roomIDByName("engineering")
	fileID := store.GenerateID("file_")
	seedDownloadableFile(t, e, fileID, store.FileContextRoom, engID, aliceFutureTSForTest(), []byte("eng-only content"))

	_, _, err := openDownloadChannel(bob.conn, fileID)
	if err == nil {
		t.Fatal("expected download rejection, got success")
	}
	if !strings.Contains(err.Error(), "not_found") {
		t.Errorf("expected not_found error, got: %v", err)
	}
}

// TestDownloadChannel_UnknownFileID_NotFound verifies a request for a
// never-uploaded file_id is rejected with the same `not_found` code as
// the ACL-deny case (privacy guarantee).
func TestDownloadChannel_UnknownFileID_NotFound(t *testing.T) {
	e := newTestEnv(t)
	alice := e.connect("/tmp/sshkey-test-key", "dev_alice")

	fileID := store.GenerateID("file_") // valid shape, but never seeded
	_, _, err := openDownloadChannel(alice.conn, fileID)
	if err == nil {
		t.Fatal("expected rejection, got success")
	}
	if !strings.Contains(err.Error(), "not_found") {
		t.Errorf("expected not_found, got: %v", err)
	}
}

// TestDownloadChannel_InvalidFileID_Rejected verifies that a file_id
// with a bad shape (path-traversal attempt) is rejected at the
// validation boundary before any filesystem access. Crucial security
// invariant — without this check, `file_id = "../../etc/passwd"`
// would escape the files directory.
func TestDownloadChannel_InvalidFileID_Rejected(t *testing.T) {
	e := newTestEnv(t)
	alice := e.connect("/tmp/sshkey-test-key", "dev_alice")

	// "../../etc/passwd" has neither the file_ prefix nor the required
	// nanoid shape. Server should reject with invalid_file_id BEFORE
	// hitting os.Stat.
	_, _, err := openDownloadChannel(alice.conn, "../../etc/passwd")
	if err == nil {
		t.Fatal("expected rejection for path-traversal attempt")
	}
	if !strings.Contains(err.Error(), "invalid_file_id") {
		t.Errorf("expected invalid_file_id error, got: %v", err)
	}
}

// TestDownloadChannel_Concurrent verifies that multiple downloads on a
// single SSH connection run in parallel. Locks in the UX win of the
// Phase 17 Step 4.f refactor — the old shared-Channel-2 design
// serialized all downloads per client, making chat views with multiple
// attachments feel slow. The new per-request channels let a client
// parallelize up to the cap (default 3).
func TestDownloadChannel_Concurrent(t *testing.T) {
	e := newTestEnv(t)
	alice := e.connect("/tmp/sshkey-test-key", "dev_alice")

	generalID := e.roomIDByName("general")
	ts := aliceFutureTSForTest()

	// Seed three downloadable files. Distinct payloads so we can verify
	// each channel got the right bytes (no interleaving, no mix-up).
	files := []struct {
		id      string
		payload []byte
	}{
		{store.GenerateID("file_"), []byte("AAAAAAAAAA")},
		{store.GenerateID("file_"), []byte("BBBBBBBBBBBBBBBBBBBB")},
		{store.GenerateID("file_"), []byte("CCCCCCCCCCCCCCCCCCCCCCCCCCCCCC")},
	}
	for _, f := range files {
		seedDownloadableFile(t, e, f.id, store.FileContextRoom, generalID, ts, f.payload)
	}

	// Launch three downloads simultaneously, collect results, verify
	// each got the correct bytes.
	type result struct {
		id   string
		data []byte
		err  error
	}
	results := make(chan result, len(files))
	var wg sync.WaitGroup
	for _, f := range files {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			data, _, err := openDownloadChannel(alice.conn, id)
			results <- result{id: id, data: data, err: err}
		}(f.id)
	}
	wg.Wait()
	close(results)

	got := make(map[string][]byte)
	for r := range results {
		if r.err != nil {
			t.Errorf("%s: download failed: %v", r.id, r.err)
			continue
		}
		got[r.id] = r.data
	}
	for _, f := range files {
		if !bytes.Equal(got[f.id], f.payload) {
			t.Errorf("%s: got %q, want %q", f.id, got[f.id], f.payload)
		}
	}
}

// TestDownloadChannel_CapEnforced verifies the per-connection cap
// blocks a 4th concurrent download. Default is 3; the 4th OpenChannel
// must return an SSH error (ssh.ResourceShortage) rather than proceed.
// After one of the 3 completes, a subsequent open succeeds — cap is a
// ceiling, not a quota.
//
// To hold 3 channels open deterministically, we open them and pause
// BEFORE reading the response. The server's handler is blocked in its
// write loop waiting for our Read, so activeDownloads stays at 3 while
// we attempt the 4th open.
func TestDownloadChannel_CapEnforced(t *testing.T) {
	e := newTestEnv(t)
	alice := e.connect("/tmp/sshkey-test-key", "dev_alice")

	generalID := e.roomIDByName("general")
	ts := aliceFutureTSForTest()

	// Large enough payload that the server's write will block on our
	// (slow) read — gives us time to attempt the 4th open while the
	// first three are still in-flight. x/crypto/ssh default channel
	// window is ~2MB; need a payload that EXCEEDS that so the server's
	// writeBinaryFrame goroutine blocks inside io.CopyN waiting for
	// the client to drain flow control.
	big := bytes.Repeat([]byte("X"), 4*1024*1024)
	fileIDs := []string{store.GenerateID("file_"), store.GenerateID("file_"), store.GenerateID("file_")}
	for _, id := range fileIDs {
		seedDownloadableFile(t, e, id, store.FileContextRoom, generalID, ts, big)
	}

	// Open 3 channels and send requests, but DON'T drain them — this
	// keeps the server-side handler goroutines alive inside
	// writeBinaryFrame, holding activeDownloads at 3.
	channels := make([]ssh.Channel, 3)
	for i, id := range fileIDs {
		ch, reqs, err := alice.conn.OpenChannel("sshkey-chat-download", nil)
		if err != nil {
			t.Fatalf("open channel %d: %v", i, err)
		}
		go ssh.DiscardRequests(reqs)
		channels[i] = ch
		reqLine, _ := json.Marshal(protocol.Download{Type: "download", FileID: id})
		reqLine = append(reqLine, '\n')
		if _, err := ch.Write(reqLine); err != nil {
			t.Fatalf("send request %d: %v", i, err)
		}
	}
	// Let the server spin up all 3 handlers and hit the streaming loop.
	time.Sleep(200 * time.Millisecond)

	// Attempt the 4th — must be rejected.
	_, _, err := alice.conn.OpenChannel("sshkey-chat-download", nil)
	if err == nil {
		t.Fatal("expected 4th concurrent download to be rejected, got success")
	}
	// ssh.OpenChannelError carries a RejectionReason. We just verify
	// SOME rejection — the exact reason is less important than "not
	// accepted."
	var ocErr *ssh.OpenChannelError
	if !errorIsOpenChannelError(err, &ocErr) {
		t.Errorf("expected *ssh.OpenChannelError, got %T: %v", err, err)
	}

	// Drain one channel to free a slot, then verify a fresh open
	// succeeds.
	drainChannel(t, channels[0])
	channels[0].Close()
	channels[0] = nil

	ch4, reqs, err := alice.conn.OpenChannel("sshkey-chat-download", nil)
	if err != nil {
		t.Fatalf("4th download after one drain: %v", err)
	}
	go ssh.DiscardRequests(reqs)
	ch4.Close()

	// Clean up the remaining two held channels.
	for _, ch := range channels {
		if ch != nil {
			ch.Close()
		}
	}
}

// ============================================================================
// Helpers
// ============================================================================

// aliceFutureTSForTest returns a timestamp > alice's seeded first_seen
// so the forward-secrecy gate passes in authorizeDownload. Matches the
// helper in the server package's download_acl_test.go (duplicated to
// avoid a cross-package test import).
func aliceFutureTSForTest() int64 {
	return time.Now().Add(1 * time.Hour).Unix()
}

// roomIDByName looks up a room nanoid by display name via a fresh
// store.Open. Used by tests that need a concrete room_id to seed
// file_contexts bindings against.
func (e *testEnv) roomIDByName(name string) string {
	e.t.Helper()
	st, err := store.Open(e.dataDir)
	if err != nil {
		e.t.Fatalf("open store: %v", err)
	}
	defer st.Close()
	id := st.RoomDisplayNameToID(name)
	if id == "" {
		e.t.Fatalf("room %q not found", name)
	}
	return id
}

// drainChannel reads all remaining bytes on the channel until EOF so
// the server-side writeBinaryFrame goroutine can complete and decrement
// activeDownloads. Used by the cap test to release a slot.
func drainChannel(t *testing.T, ch ssh.Channel) {
	t.Helper()
	// Give the server time to finish writing — use a bounded copy with
	// a reasonable upper limit so we don't block forever if something
	// goes wrong.
	done := make(chan struct{})
	go func() {
		io.Copy(io.Discard, ch)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		// Partial drain is fine — test just needs activeDownloads to
		// decrement via channel close below.
	}
}

// errorIsOpenChannelError extracts *ssh.OpenChannelError from an error
// chain. Helper because errors.As can't do direct pointer-to-pointer
// unwrapping of non-pointer ssh errors across versions.
func errorIsOpenChannelError(err error, out **ssh.OpenChannelError) bool {
	oc, ok := err.(*ssh.OpenChannelError)
	if ok {
		*out = oc
	}
	return ok
}
