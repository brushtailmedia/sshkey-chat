package main

// End-to-end coverage for the shared-Channel-2 download path (the only
// download path after the 2026-04-17 revert of the per-request channel
// work; see refactor_plan.md Phase 22 item 10). Flow:
//
//   Client opens 3 session channels (1=NDJSON, 2=download, 3=upload).
//   Client writes `{"type":"download","file_id":"..."}` on Channel 1.
//   Server runs ValidateNanoID + authorizeDownload, writes binary
//   frame to Channel 2.
//   Client reads `download_start` + binary frame + `download_complete`
//   all via the existing testClient infrastructure (Channel 1 reads
//   plus a dedicated reader goroutine on Channel 2).
//
// Coverage:
//   - Happy path: download succeeds, bytes + hash verify.
//   - ACL deny: non-member gets `not_found` response on Channel 1.
//   - Invalid file_id shape: path-traversal attempt rejected at the
//     ValidateNanoID boundary.
//   - Unknown file_id: indistinguishable `not_found` response
//     (privacy-preserving — can't probe file existence).

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
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
// download-side tests stay focused.
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

// aliceFutureTSForTest returns a timestamp > alice's seeded first_seen
// so the forward-secrecy gate passes in authorizeDownload. Alice's
// first_seen is stamped to time.Now() when she's seeded by newTestEnv,
// so any ts ahead of that is safe.
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

// legacyClient is a testClient extension that also holds the legacy
// Channel 2 (server→client download stream). Tests open all 3 session
// channels to simulate a legacy-only client.
type legacyClient struct {
	*testClient
	downloadCh ssh.Channel
	uploadCh   ssh.Channel
}

// connectLegacy opens all three session channels in the pre-Phase-17-
// Step-4.f order: 1=NDJSON, 2=download, 3=upload. Must open all three
// BEFORE sending client_hello so the server's handleSession wait
// (500ms for dlChanCh) receives the download channel before timing out
// — matches the real term client's connect flow.
//
// This duplicates the SSH dial + handshake logic from testEnv.connect
// because that helper opens only Channel 1 before handshake, which is
// incompatible with the legacy path's 3-session-channel requirement.
func (e *testEnv) connectLegacy(keyPath, deviceID string) *legacyClient {
	e.t.Helper()

	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		e.t.Fatalf("read key: %v", err)
	}
	signer, err := ssh.ParsePrivateKey(keyData)
	if err != nil {
		e.t.Fatalf("parse key: %v", err)
	}
	clientCfg := &ssh.ClientConfig{
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}
	conn, err := ssh.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", e.port), clientCfg)
	if err != nil {
		e.t.Fatalf("dial: %v", err)
	}
	e.t.Cleanup(func() { conn.Close() })

	// Open all 3 session channels BEFORE sending client_hello so the
	// server's handleSession dlChanCh wait sees Channel 2 arrive.
	ch1, req1, err := conn.OpenChannel("session", nil)
	if err != nil {
		e.t.Fatalf("open Ch1: %v", err)
	}
	go ssh.DiscardRequests(req1)

	dlCh, req2, err := conn.OpenChannel("session", nil)
	if err != nil {
		e.t.Fatalf("open Ch2 (download): %v", err)
	}
	go ssh.DiscardRequests(req2)

	ulCh, req3, err := conn.OpenChannel("session", nil)
	if err != nil {
		e.t.Fatalf("open Ch3 (upload): %v", err)
	}
	go ssh.DiscardRequests(req3)
	tc := &testClient{
		enc:  protocol.NewEncoder(ch1),
		dec:  protocol.NewDecoder(ch1),
		ch:   ch1,
		conn: conn,
		t:    e.t,
	}

	// Handshake: server_hello, client_hello, welcome, drain to sync_complete.
	tc.expectType("server_hello")
	tc.enc.Encode(protocol.ClientHello{
		Type:          "client_hello",
		Protocol:      "sshkey-chat",
		Version:       1,
		Client:        "test",
		ClientVersion: "0.0.1",
		DeviceID:      deviceID,
		Capabilities:  []string{"typing", "reactions", "signatures"},
	})
	tc.expectType("welcome")
	tc.drainUntil("sync_complete")

	return &legacyClient{testClient: tc, downloadCh: dlCh, uploadCh: ulCh}
}

// readLegacyDownloadFrame reads the binary frame the server writes to
// the legacy download channel. Returns the file_id header + the payload
// bytes. Mirrors the client-side logic in sshkey-term's
// readBinaryFrame.
func readLegacyDownloadFrame(r io.Reader) (string, []byte, error) {
	var idLen [1]byte
	if _, err := io.ReadFull(r, idLen[:]); err != nil {
		return "", nil, fmt.Errorf("read id_len: %w", err)
	}
	idBuf := make([]byte, idLen[0])
	if _, err := io.ReadFull(r, idBuf); err != nil {
		return "", nil, fmt.Errorf("read id: %w", err)
	}
	var lenBuf [8]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return "", nil, fmt.Errorf("read data_len: %w", err)
	}
	dataLen := binary.BigEndian.Uint64(lenBuf[:])
	data := make([]byte, dataLen)
	if _, err := io.ReadFull(r, data); err != nil {
		return "", nil, fmt.Errorf("read data: %w", err)
	}
	return string(idBuf), data, nil
}

// readCh1UntilTypes reads Channel 1 messages until one matches any of
// the expected types. Unrelated messages (epoch_trigger, presence,
// etc.) are skipped. Needed because the server emits assorted
// connection-lifecycle messages on Channel 1 alongside download
// responses; the real term client dispatches them via handleIncoming,
// but this test harness has no such dispatcher.
//
// Returns the raw message + the type it matched. Returns error on
// decode failure or timeout.
func readCh1UntilTypes(tc *legacyClient, types ...string) (json.RawMessage, string, error) {
	wantSet := make(map[string]bool, len(types))
	for _, t := range types {
		wantSet[t] = true
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		var raw json.RawMessage
		if err := tc.dec.Decode(&raw); err != nil {
			return nil, "", fmt.Errorf("decode: %w", err)
		}
		var probe struct {
			Type string `json:"type"`
		}
		if err := json.Unmarshal(raw, &probe); err != nil {
			return nil, "", fmt.Errorf("parse type: %w", err)
		}
		if wantSet[probe.Type] {
			return raw, probe.Type, nil
		}
		// Otherwise: unrelated background message, skip and continue.
	}
	return nil, "", fmt.Errorf("timeout waiting for %v", types)
}

// legacyDownload runs the full client side of the legacy download flow:
// send `download` on Channel 1, read `download_start` on Channel 1
// (filtering past unrelated messages), read binary frame on Channel 2,
// read `download_complete` on Channel 1. Returns the bytes + hash + any
// error.
func legacyDownload(tc *legacyClient, fileID string) (data []byte, hash string, err error) {
	if err := tc.enc.Encode(protocol.Download{Type: "download", FileID: fileID}); err != nil {
		return nil, "", fmt.Errorf("send download: %w", err)
	}

	// Read Channel 1 responses until we see download_start OR download_error.
	raw, typ, err := readCh1UntilTypes(tc, "download_start", "download_error")
	if err != nil {
		return nil, "", fmt.Errorf("read Ch1 response: %w", err)
	}

	if typ == "download_error" {
		var de protocol.DownloadError
		if err := json.Unmarshal(raw, &de); err != nil {
			return nil, "", fmt.Errorf("parse download_error: %w", err)
		}
		return nil, "", fmt.Errorf("download_error: %s: %s", de.Code, de.Message)
	}

	var ds protocol.DownloadStart
	if err := json.Unmarshal(raw, &ds); err != nil {
		return nil, "", fmt.Errorf("parse download_start: %w", err)
	}
	hash = ds.ContentHash

	// Read the binary frame from Channel 2.
	_, data, err = readLegacyDownloadFrame(tc.downloadCh)
	if err != nil {
		return nil, "", fmt.Errorf("read Ch2: %w", err)
	}

	// Read the download_complete trailer on Channel 1.
	if _, _, err := readCh1UntilTypes(tc, "download_complete"); err != nil {
		return nil, "", fmt.Errorf("read trailer: %w", err)
	}
	return data, hash, nil
}

// ============================================================================
// Tests
// ============================================================================

// TestLegacyDownload_HappyPath verifies the full legacy download
// round-trip: alice downloads a file bound to "general" via the old
// Channel-1-request + Channel-2-binary-frame protocol.
func TestLegacyDownload_HappyPath(t *testing.T) {
	e := newTestEnv(t)
	alice := e.connectLegacy(fixtureKeyPath(t, "alice"), "dev_alice")

	generalID := e.roomIDByName("general")
	payload := []byte("legacy path still works fine")
	fileID := store.GenerateID("file_")
	expectedHash := seedDownloadableFile(t, e, fileID, store.FileContextRoom, generalID, aliceFutureTSForTest(), payload)

	data, hash, err := legacyDownload(alice, fileID)
	if err != nil {
		t.Fatalf("legacy download: %v", err)
	}
	if !bytes.Equal(data, payload) {
		t.Errorf("data mismatch: got %q, want %q", data, payload)
	}
	if hash != expectedHash {
		t.Errorf("hash = %q, want %q", hash, expectedHash)
	}
}

// TestLegacyDownload_NonMemberDenied verifies the authorizeDownload
// ACL: a non-member of the file's bound context gets `not_found` on
// Channel 1 and no bytes written to Channel 2.
func TestLegacyDownload_NonMemberDenied(t *testing.T) {
	e := newTestEnv(t)
	bob := e.connectLegacy(fixtureKeyPath(t, "bob"), "dev_bob")

	engID := e.roomIDByName("engineering")
	fileID := store.GenerateID("file_")
	seedDownloadableFile(t, e, fileID, store.FileContextRoom, engID, aliceFutureTSForTest(), []byte("engineering only"))

	_, _, err := legacyDownload(bob, fileID)
	if err == nil {
		t.Fatal("expected download rejection, got success")
	}
	if !strings.Contains(err.Error(), "not_found") {
		t.Errorf("expected not_found error, got: %v", err)
	}
}

// TestLegacyDownload_InvalidFileID verifies the legacy path also
// rejects path-traversal attempts at the validation boundary. Without
// this check, `file_id = "../../etc/passwd"` would escape the files
// directory via filepath.Join.
func TestLegacyDownload_InvalidFileID(t *testing.T) {
	e := newTestEnv(t)
	alice := e.connectLegacy(fixtureKeyPath(t, "alice"), "dev_alice")

	_, _, err := legacyDownload(alice, "../../etc/passwd")
	if err == nil {
		t.Fatal("expected rejection for path-traversal attempt")
	}
	if !strings.Contains(err.Error(), "invalid_file_id") {
		t.Errorf("expected invalid_file_id error, got: %v", err)
	}
}

// TestLegacyDownload_UnknownFileIDIsNotFound verifies the
// privacy-preserving response: a request for a never-uploaded file_id
// gets the same `not_found` code as an ACL-deny, so a probing client
// cannot distinguish "doesn't exist" from "no access."
func TestLegacyDownload_UnknownFileIDIsNotFound(t *testing.T) {
	e := newTestEnv(t)
	alice := e.connectLegacy(fixtureKeyPath(t, "alice"), "dev_alice")

	fileID := store.GenerateID("file_") // valid shape, never seeded
	_, _, err := legacyDownload(alice, fileID)
	if err == nil {
		t.Fatal("expected not_found, got success")
	}
	if !strings.Contains(err.Error(), "not_found") {
		t.Errorf("expected not_found, got: %v", err)
	}
}
