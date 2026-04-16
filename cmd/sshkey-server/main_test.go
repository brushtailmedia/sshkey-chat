package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/brushtailmedia/sshkey-chat/internal/config"
	"github.com/brushtailmedia/sshkey-chat/internal/protocol"
	"github.com/brushtailmedia/sshkey-chat/internal/server"
	"github.com/brushtailmedia/sshkey-chat/internal/store"
)

// Test fixture keys generated once per TestMain run. Written to /tmp
// for backwards compatibility with pre-existing test code that expects
// them there. Phase 16 Gap 4 removed users.toml support, so the
// fixture code no longer writes a users.toml file — instead, the user
// metadata is stored in testFixtureUsers and seeded into users.db
// directly via store.InsertUser inside newTestEnv after the server is
// created.
type testFixtureUser struct {
	UserID      string // nanoid-style internal ID
	DisplayName string
	KeyPath     string // private key file path on disk (for client connect)
	PubKey      string // public key in authorized_keys format (with comment)
	Rooms       []string
}

var (
	testFixtureOnce   sync.Once
	testFixtureDir    string             // temp config dir (server.toml + rooms.toml only)
	testFixtureUsers  []testFixtureUser  // user metadata for store seeding
	testFixtureErr    error
)

// setupFixtures creates three Ed25519 test keys (alice/bob/carol),
// writes their private keys to /tmp/sshkey-test-key[-bob|-carol], and
// builds a temp config dir containing rooms.toml + server.toml. The
// generated user metadata is stashed in testFixtureUsers for later
// seeding into users.db via store.InsertUser. Called lazily on first
// test that needs the fixtures.
func setupFixtures() (string, []testFixtureUser, error) {
	testFixtureOnce.Do(func() {
		testFixtureDir, testFixtureUsers, testFixtureErr = generateTestFixtures()
	})
	return testFixtureDir, testFixtureUsers, testFixtureErr
}

func generateTestFixtures() (string, []testFixtureUser, error) {
	// Generate the three test keys + pub keys
	users := []testFixtureUser{
		{UserID: "usr_alice_test", DisplayName: "alice", KeyPath: "/tmp/sshkey-test-key", Rooms: []string{"general", "engineering"}},
		{UserID: "usr_bob_test", DisplayName: "bob", KeyPath: "/tmp/sshkey-test-key-bob", Rooms: []string{"general"}},
		{UserID: "usr_carol_test", DisplayName: "carol", KeyPath: "/tmp/sshkey-test-key-carol", Rooms: []string{"general"}},
	}

	tmpConfigDir, err := os.MkdirTemp("", "sshkey-test-config-")
	if err != nil {
		return "", nil, fmt.Errorf("tempdir: %w", err)
	}

	for i := range users {
		u := &users[i]
		// Generate a fresh key (overwrite any stale fixture)
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return "", nil, err
		}
		block, err := ssh.MarshalPrivateKey(priv, "")
		if err != nil {
			return "", nil, err
		}
		if err := os.WriteFile(u.KeyPath, pem.EncodeToMemory(block), 0600); err != nil {
			return "", nil, fmt.Errorf("write %s: %w", u.KeyPath, err)
		}

		sshPub, err := ssh.NewPublicKey(pub)
		if err != nil {
			return "", nil, err
		}
		pubLine := string(ssh.MarshalAuthorizedKey(sshPub))
		// Trim trailing newline; add a comment
		u.PubKey = pubLine[:len(pubLine)-1] + " " + u.DisplayName + "@test"
	}

	// Copy rooms.toml + server.toml from committed testdata
	for _, f := range []string{"rooms.toml", "server.toml"} {
		src := filepath.Join("..", "..", "testdata", "config", f)
		data, err := os.ReadFile(src)
		if err != nil {
			return "", nil, fmt.Errorf("read %s: %w", src, err)
		}
		if err := os.WriteFile(filepath.Join(tmpConfigDir, f), data, 0644); err != nil {
			return "", nil, err
		}
	}

	return tmpConfigDir, users, nil
}

// testEnv holds a running server and its config for tests.
type testEnv struct {
	srv     *server.Server
	cfg     *config.Config
	port    int
	dataDir string
	t       *testing.T
}

// roomID looks up a room nanoid from rooms.db by display name.
func (e *testEnv) roomID(displayName string) string {
	e.t.Helper()
	dbPath := filepath.Join(e.dataDir, "data", "rooms.db")
	db, err := sql.Open("sqlite", dbPath+"?_busy_timeout=5000")
	if err != nil {
		e.t.Fatalf("open rooms.db: %v", err)
	}
	defer db.Close()
	var id string
	err = db.QueryRow("SELECT id FROM rooms WHERE LOWER(display_name) = LOWER(?)", displayName).Scan(&id)
	if err != nil {
		e.t.Fatalf("roomID(%q): %v", displayName, err)
	}
	return id
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	testConfigDir, fixtureUsers, err := setupFixtures()
	if err != nil {
		t.Fatalf("setup fixtures: %v", err)
	}
	testDataDir := t.TempDir()

	cfg, err := config.Load(testConfigDir)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	// Find a free port
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()

	cfg.Server.Server.Port = port
	cfg.Server.Server.Bind = "127.0.0.1"

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	srv, err := server.New(cfg, logger, testDataDir)
	if err != nil {
		t.Fatalf("create server: %v", err)
	}

	// Phase 16 Gap 4: users.toml seeding was removed. Insert the test
	// fixture users directly into users.db / room_members via the
	// public store API, after server.New has initialized the store
	// schema and seeded rooms.db from rooms.toml. Pass testDataDir
	// (not testDataDir+"/data") because store.Open creates the "data"
	// subdirectory itself — passing the joined path would create
	// data/data which the server can't see.
	st, err := store.Open(testDataDir)
	if err != nil {
		t.Fatalf("open store for fixture seeding: %v", err)
	}
	for _, u := range fixtureUsers {
		// Strip the comment from the key for storage parity with
		// cmdApprove.
		parts := strings.Fields(u.PubKey)
		keyForStorage := u.PubKey
		if len(parts) >= 2 {
			keyForStorage = parts[0] + " " + parts[1]
		}
		if err := st.InsertUser(u.UserID, keyForStorage, u.DisplayName); err != nil {
			t.Fatalf("seed user %s: %v", u.UserID, err)
		}
		for _, roomName := range u.Rooms {
			roomID := st.RoomDisplayNameToID(roomName)
			if roomID == "" {
				t.Fatalf("seed user %s: room %s not in rooms.db", u.UserID, roomName)
			}
			if err := st.AddRoomMember(roomID, u.UserID, 0); err != nil {
				t.Fatalf("add %s to %s: %v", u.UserID, roomName, err)
			}
		}
	}
	st.Close()

	go srv.ListenAndServe()
	t.Cleanup(func() { srv.Close() })
	time.Sleep(200 * time.Millisecond)

	return &testEnv{srv: srv, cfg: cfg, port: port, dataDir: testDataDir, t: t}
}

// testClient is a connected protocol client.
type testClient struct {
	enc *protocol.Encoder
	dec *protocol.Decoder
	ch  ssh.Channel
	t   *testing.T
}

func (e *testEnv) connect(keyPath, deviceID string) *testClient {
	e.t.Helper()

	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		e.t.Fatalf("read key %s: %v", keyPath, err)
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

	ch, reqs, err := conn.OpenChannel("session", nil)
	if err != nil {
		e.t.Fatalf("open channel: %v", err)
	}
	go ssh.DiscardRequests(reqs)

	tc := &testClient{
		enc: protocol.NewEncoder(ch),
		dec: protocol.NewDecoder(ch),
		ch:  ch,
		t:   e.t,
	}

	// Read server_hello
	tc.expectType("server_hello")

	// Send client_hello
	tc.enc.Encode(protocol.ClientHello{
		Type:          "client_hello",
		Protocol:      "sshkey-chat",
		Version:       1,
		Client:        "test",
		ClientVersion: "0.0.1",
		DeviceID:      deviceID,
		Capabilities:  []string{"typing", "reactions", "signatures"},
	})

	// Read welcome
	tc.expectType("welcome")

	// Read room_list, optional conversation_list, profiles, optional epoch_keys,
	// optional sync_batches, then sync_complete
	tc.drainUntil("sync_complete")

	return tc
}

func (tc *testClient) expectType(expected string) json.RawMessage {
	tc.t.Helper()
	var raw json.RawMessage
	if err := tc.dec.Decode(&raw); err != nil {
		tc.t.Fatalf("read %s: %v", expected, err)
	}
	msgType, err := protocol.TypeOf(raw)
	if err != nil {
		tc.t.Fatalf("extract type for %s: %v", expected, err)
	}
	if msgType != expected {
		tc.t.Fatalf("expected %s, got %s: %s", expected, msgType, string(raw))
	}
	return raw
}

// drainUntil reads messages until it finds the expected type, returning it.
// Collects all messages read along the way.
func (tc *testClient) drainUntil(expected string) (json.RawMessage, []json.RawMessage) {
	tc.t.Helper()
	var collected []json.RawMessage
	for {
		var raw json.RawMessage
		if err := tc.dec.Decode(&raw); err != nil {
			tc.t.Fatalf("drainUntil(%s): %v", expected, err)
		}
		msgType, _ := protocol.TypeOf(raw)
		if msgType == expected {
			return raw, collected
		}
		collected = append(collected, raw)
	}
}

func (tc *testClient) readMessage() (string, json.RawMessage) {
	tc.t.Helper()
	for {
		var raw json.RawMessage
		if err := tc.dec.Decode(&raw); err != nil {
			tc.t.Fatalf("read message: %v", err)
		}
		msgType, err := protocol.TypeOf(raw)
		if err != nil {
			tc.t.Fatalf("extract type: %v", err)
		}
		// Skip async messages that can arrive between any protocol messages
		switch msgType {
		case "presence", "typing", "epoch_trigger", "epoch_key", "epoch_confirmed":
			continue
		}
		return msgType, raw
	}
}

func TestHandshake(t *testing.T) {
	env := newTestEnv(t)
	client := env.connect("/tmp/sshkey-test-key", "dev_handshake_test")
	_ = client
	t.Log("handshake complete")
}

func TestRoomMessaging(t *testing.T) {
	env := newTestEnv(t)
	generalID := env.roomID("general")
	engineeringID := env.roomID("engineering")

	// Connect alice and bob
	alice := env.connect("/tmp/sshkey-test-key", "dev_alice_001")
	bob := env.connect("/tmp/sshkey-test-key-bob", "dev_bob_001")

	// Alice sends a message to general (both are members)
	err := alice.enc.Encode(protocol.Send{
		Type:      "send",
		Room:      generalID,
		Epoch:     1,
		Payload:   "base64_encrypted_hello",
		Signature: "base64_sig_hello",
	})
	if err != nil {
		t.Fatalf("alice send: %v", err)
	}

	// Both alice and bob should receive the message
	// (broadcast goes to all room members including sender)
	aliceMsgType, aliceRaw := alice.readMessage()
	if aliceMsgType != "message" {
		t.Fatalf("alice expected message, got %s", aliceMsgType)
	}

	bobMsgType, bobRaw := bob.readMessage()
	if bobMsgType != "message" {
		t.Fatalf("bob expected message, got %s", bobMsgType)
	}

	// Verify message content
	var aliceMsg, bobMsg protocol.Message
	json.Unmarshal(aliceRaw, &aliceMsg)
	json.Unmarshal(bobRaw, &bobMsg)

	if aliceMsg.ID == "" {
		t.Error("message has no server-assigned ID")
	}
	if aliceMsg.ID != bobMsg.ID {
		t.Errorf("message IDs don't match: alice=%s bob=%s", aliceMsg.ID, bobMsg.ID)
	}
	if aliceMsg.From != "usr_alice_test" {
		t.Errorf("from = %q, want alice", aliceMsg.From)
	}
	if aliceMsg.Room != generalID {
		t.Errorf("room = %q, want %s", aliceMsg.Room, generalID)
	}
	if aliceMsg.Payload != "base64_encrypted_hello" {
		t.Errorf("payload = %q, want base64_encrypted_hello", aliceMsg.Payload)
	}
	if aliceMsg.Signature != "base64_sig_hello" {
		t.Errorf("signature = %q, want base64_sig_hello", aliceMsg.Signature)
	}
	if aliceMsg.TS == 0 {
		t.Error("message has no timestamp")
	}
	if aliceMsg.Epoch != 1 {
		t.Errorf("epoch = %d, want 1", aliceMsg.Epoch)
	}

	t.Logf("message delivered: id=%s from=%s room=%s ts=%d", aliceMsg.ID, aliceMsg.From, aliceMsg.Room, aliceMsg.TS)

	// Bob sends a message to general
	err = bob.enc.Encode(protocol.Send{
		Type:      "send",
		Room:      generalID,
		Epoch:     1,
		Payload:   "base64_encrypted_reply",
		Signature: "base64_sig_reply",
	})
	if err != nil {
		t.Fatalf("bob send: %v", err)
	}

	// Both should receive bob's message
	aliceMsgType, _ = alice.readMessage()
	if aliceMsgType != "message" {
		t.Fatalf("alice expected message from bob, got %s", aliceMsgType)
	}
	bobMsgType, _ = bob.readMessage()
	if bobMsgType != "message" {
		t.Fatalf("bob expected own message, got %s", bobMsgType)
	}

	// Alice sends to engineering (bob is NOT a member)
	err = alice.enc.Encode(protocol.Send{
		Type:      "send",
		Room:      engineeringID,
		Epoch:     1,
		Payload:   "base64_encrypted_eng",
		Signature: "base64_sig_eng",
	})
	if err != nil {
		t.Fatalf("alice send to engineering: %v", err)
	}

	// Alice should receive her own message
	aliceMsgType, _ = alice.readMessage()
	if aliceMsgType != "message" {
		t.Fatalf("alice expected engineering message, got %s", aliceMsgType)
	}

	// Bob should NOT receive anything (not in engineering)
	// We verify this by sending another general message and checking bob gets that instead
	err = alice.enc.Encode(protocol.Send{
		Type:    "send",
		Room:    generalID,
		Epoch:   1,
		Payload: "base64_after_eng",
	})
	if err != nil {
		t.Fatalf("alice send after eng: %v", err)
	}

	// Alice gets her own general message
	alice.readMessage()

	// Bob should get the general message (not the engineering one)
	bobMsgType, bobRaw = bob.readMessage()
	if bobMsgType != "message" {
		t.Fatalf("bob expected general message, got %s", bobMsgType)
	}
	var bobCheck protocol.Message
	json.Unmarshal(bobRaw, &bobCheck)
	if bobCheck.Room != generalID {
		t.Errorf("bob got room=%q, should be %s (not engineering)", bobCheck.Room, generalID)
	}

	t.Log("room messaging and isolation verified")
}

func TestSyncOnReconnect(t *testing.T) {
	env := newTestEnv(t)
	generalID := env.roomID("general")

	// Connect alice, send some messages
	alice := env.connect("/tmp/sshkey-test-key", "dev_alice_sync")

	for i := 0; i < 3; i++ {
		alice.enc.Encode(protocol.Send{
			Type:    "send",
			Room:    generalID,
			Epoch:   1,
			Payload: fmt.Sprintf("msg_%d", i),
		})
		// Read our own message back
		alice.readMessage()
	}

	// Disconnect alice (close channel)
	alice.ch.Close()
	time.Sleep(100 * time.Millisecond)

	// Reconnect alice -- should get sync batch with the 3 messages
	keyData, _ := os.ReadFile("/tmp/sshkey-test-key")
	signer, _ := ssh.ParsePrivateKey(keyData)

	clientCfg := &ssh.ClientConfig{
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}

	conn, err := ssh.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", env.port), clientCfg)
	if err != nil {
		t.Fatalf("reconnect dial: %v", err)
	}
	defer conn.Close()

	ch, reqs, err := conn.OpenChannel("session", nil)
	if err != nil {
		t.Fatalf("reconnect channel: %v", err)
	}
	go ssh.DiscardRequests(reqs)

	enc := protocol.NewEncoder(ch)
	dec := protocol.NewDecoder(ch)

	// Read server_hello
	var raw json.RawMessage
	dec.Decode(&raw)

	// Send client_hello with a past timestamp to trigger sync
	enc.Encode(protocol.ClientHello{
		Type:          "client_hello",
		Protocol:      "sshkey-chat",
		Version:       1,
		Client:        "test",
		ClientVersion: "0.0.1",
		DeviceID:      "dev_alice_sync2",
		LastSyncedAt:  "2020-01-01T00:00:00Z", // far in the past
		Capabilities:  []string{"typing", "reactions"},
	})

	// Read through welcome, room_list, profiles until we hit sync_batch or sync_complete
	var syncBatches []json.RawMessage
	for {
		var msg json.RawMessage
		if err := dec.Decode(&msg); err != nil {
			t.Fatalf("reconnect read: %v", err)
		}
		msgType, _ := protocol.TypeOf(msg)
		if msgType == "sync_batch" {
			cp := make(json.RawMessage, len(msg))
			copy(cp, msg)
			syncBatches = append(syncBatches, cp)
		}
		if msgType == "sync_complete" {
			break
		}
	}

	if len(syncBatches) == 0 {
		t.Fatal("expected at least one sync_batch, got none")
	}

	// Parse the sync batch
	var batch protocol.SyncBatch
	json.Unmarshal(syncBatches[0], &batch)

	if len(batch.Messages) != 3 {
		t.Errorf("sync batch has %d messages, want 3", len(batch.Messages))
	}

	t.Logf("sync: got %d batch(es) with %d messages total", len(syncBatches), len(batch.Messages))

	// Verify messages are in order (oldest first for sync)
	for i, raw := range batch.Messages {
		var msg protocol.Message
		json.Unmarshal(raw, &msg)
		expected := fmt.Sprintf("msg_%d", i)
		if msg.Payload != expected {
			t.Errorf("message %d payload = %q, want %q", i, msg.Payload, expected)
		}
	}

	t.Log("sync on reconnect verified")
}

func TestHistory(t *testing.T) {
	env := newTestEnv(t)
	generalID := env.roomID("general")

	alice := env.connect("/tmp/sshkey-test-key", "dev_alice_hist")

	// Send 5 messages
	var msgIDs []string
	for i := 0; i < 5; i++ {
		alice.enc.Encode(protocol.Send{
			Type:    "send",
			Room:    generalID,
			Epoch:   1,
			Payload: fmt.Sprintf("hist_%d", i),
		})
		_, raw := alice.readMessage()
		var msg protocol.Message
		json.Unmarshal(raw, &msg)
		msgIDs = append(msgIDs, msg.ID)
	}

	// Request history before the last message
	alice.enc.Encode(protocol.History{
		Type:   "history",
		Room:   generalID,
		Before: msgIDs[4],
		Limit:  2,
	})

	msgType, raw := alice.readMessage()
	if msgType != "history_result" {
		t.Fatalf("expected history_result, got %s", msgType)
	}

	var result protocol.HistoryResult
	json.Unmarshal(raw, &result)

	if result.Room != generalID {
		t.Errorf("room = %q, want %s", result.Room, generalID)
	}
	if len(result.Messages) != 2 {
		t.Fatalf("expected 2 messages, got %d", len(result.Messages))
	}
	if !result.HasMore {
		t.Error("expected has_more=true (there are more messages before these)")
	}

	// Messages should be in descending order (newest first for history)
	var histMsgs []protocol.Message
	for _, raw := range result.Messages {
		var m protocol.Message
		json.Unmarshal(raw, &m)
		histMsgs = append(histMsgs, m)
	}

	// The two messages before msg[4] should be msg[3] and msg[2] (newest first)
	if histMsgs[0].Payload != "hist_3" {
		t.Errorf("first history message payload = %q, want hist_3", histMsgs[0].Payload)
	}
	if histMsgs[1].Payload != "hist_2" {
		t.Errorf("second history message payload = %q, want hist_2", histMsgs[1].Payload)
	}

	t.Logf("history: got %d messages, has_more=%v", len(result.Messages), result.HasMore)
	t.Log("history scroll-back verified")
}

func TestDMConversations(t *testing.T) {
	env := newTestEnv(t)

	alice := env.connect("/tmp/sshkey-test-key", "dev_alice_dm")
	bob := env.connect("/tmp/sshkey-test-key-bob", "dev_bob_dm")

	// Alice creates a 1:1 DM with bob
	alice.enc.Encode(protocol.CreateDM{
		Type:  "create_dm",
		Other: "usr_bob_test",
	})

	// Alice receives dm_created
	msgType, raw := alice.readMessage()
	if msgType != "dm_created" {
		t.Fatalf("expected dm_created, got %s", msgType)
	}
	var created protocol.DMCreated
	json.Unmarshal(raw, &created)

	if created.DM == "" {
		t.Fatal("dm_created has no DM ID")
	}
	if len(created.Members) != 2 {
		t.Fatalf("expected 2 members, got %d", len(created.Members))
	}
	t.Logf("DM created: id=%s members=%v", created.DM, created.Members)

	// Alice creates the same DM again -- should get back the existing one (1:1 dedup)
	alice.enc.Encode(protocol.CreateDM{
		Type:  "create_dm",
		Other: "usr_bob_test",
	})
	msgType, raw = alice.readMessage()
	if msgType != "dm_created" {
		t.Fatalf("expected dm_created (dedup), got %s", msgType)
	}
	var created2 protocol.DMCreated
	json.Unmarshal(raw, &created2)
	if created2.DM != created.DM {
		t.Errorf("1:1 dedup failed: first=%s second=%s", created.DM, created2.DM)
	}
	t.Log("1:1 dedup verified")

	// Alice sends a DM
	dmID := created.DM
	alice.enc.Encode(protocol.SendDM{
		Type:        "send_dm",
		DM:          dmID,
		WrappedKeys: map[string]string{"usr_alice_test": "wrapped_a", "usr_bob_test": "wrapped_b"},
		Payload:     "base64_encrypted_dm",
		Signature:   "base64_sig_dm",
	})

	// Alice receives her own DM
	msgType, raw = alice.readMessage()
	if msgType != "dm" {
		t.Fatalf("alice expected dm, got %s", msgType)
	}

	// Bob receives dm_created pushes (one per create_dm call - alice made two
	// for the dedup test) then the DM itself. Drain all dm_created messages.
	for {
		msgType, raw = bob.readMessage()
		if msgType != "dm_created" {
			break
		}
		t.Log("bob received dm_created push")
	}
	if msgType != "dm" {
		t.Fatalf("bob expected dm, got %s", msgType)
	}

	var bobDM protocol.DM
	json.Unmarshal(raw, &bobDM)

	if bobDM.From != "usr_alice_test" {
		t.Errorf("from = %q, want alice", bobDM.From)
	}
	if bobDM.DM != dmID {
		t.Errorf("dm = %q, want %s", bobDM.DM, dmID)
	}
	if bobDM.Payload != "base64_encrypted_dm" {
		t.Errorf("payload = %q, want base64_encrypted_dm", bobDM.Payload)
	}
	if bobDM.WrappedKeys["usr_bob_test"] != "wrapped_b" {
		t.Errorf("wrapped_keys[bob] = %q, want wrapped_b", bobDM.WrappedKeys["usr_bob_test"])
	}

	t.Logf("DM delivered: id=%s from=%s dm=%s", bobDM.ID, bobDM.From, bobDM.DM)

	// Test invalid wrapped_keys (missing a member)
	alice.enc.Encode(protocol.SendDM{
		Type:        "send_dm",
		DM:          dmID,
		WrappedKeys: map[string]string{"usr_alice_test": "wrapped_a"}, // missing bob
		Payload:     "base64_bad",
	})

	msgType, raw = alice.readMessage()
	if msgType != "error" {
		t.Fatalf("expected error for invalid wrapped_keys, got %s", msgType)
	}
	var errMsg protocol.Error
	json.Unmarshal(raw, &errMsg)
	if errMsg.Code != protocol.ErrInvalidWrappedKeys {
		t.Errorf("error code = %q, want %s", errMsg.Code, protocol.ErrInvalidWrappedKeys)
	}
	t.Log("invalid wrapped_keys rejection verified")

	// Test silent 1:1 leave: bob leaves the DM, receives dm_left echo,
	// alice sees NO event (silent by design). We only verify bob's echo
	// since verifying alice-doesn't-see-it would require a read timeout.
	bob.enc.Encode(protocol.LeaveDM{
		Type: "leave_dm",
		DM:   dmID,
	})

	msgType, raw = bob.readMessage()
	if msgType != "dm_left" {
		t.Fatalf("bob expected dm_left echo, got %s", msgType)
	}
	var leftEcho protocol.DMLeft
	json.Unmarshal(raw, &leftEcho)
	if leftEcho.DM != dmID {
		t.Errorf("dm_left echo has wrong dm: %s", leftEcho.DM)
	}

	t.Log("DM conversations + silent leave fully verified")
}

func itoa(n int) string {
	return fmt.Sprintf("%d", n)
}

// dmRowCutoffs reads the direct_messages row directly from data.db and
// returns (user_a_left_at, user_b_left_at). Used by tests to verify
// per-user cutoff state after leave / retirement. Returns (-1, -1) if
// the row no longer exists (e.g. after cleanup).
func (e *testEnv) dmRowCutoffs(dmID string) (int64, int64) {
	e.t.Helper()
	dbPath := filepath.Join(e.dataDir, "data", "data.db")
	db, err := sql.Open("sqlite", dbPath+"?_busy_timeout=5000")
	if err != nil {
		e.t.Fatalf("open data.db: %v", err)
	}
	defer db.Close()
	var a, b int64
	err = db.QueryRow(
		`SELECT user_a_left_at, user_b_left_at FROM direct_messages WHERE id = ?`,
		dmID,
	).Scan(&a, &b)
	if err == sql.ErrNoRows {
		return -1, -1
	}
	if err != nil {
		e.t.Fatalf("query direct_messages(%s): %v", dmID, err)
	}
	return a, b
}

// TestDMDelete_MultiDeviceSync verifies that /delete on a 1:1 DM from one
// device propagates to the user's OTHER connected devices via the dm_left
// echo broadcast. The other party (bob) must not be notified.
//
// Flow:
//  1. alice connects two devices (alice_A and alice_B) and bob connects one
//  2. alice creates a DM with bob (all three receive dm_created)
//  3. alice sends a message (all three receive it)
//  4. alice on device A sends leave_dm
//  5. Both of alice's devices receive dm_left — the server broadcasts the
//     echo to every session whose UserID matches the leaver
//  6. bob does NOT receive dm_left (silent 1:1 leave)
//  7. Server-side alice_left_at > 0 and bob_left_at == 0 in direct_messages
func TestDMDelete_MultiDeviceSync(t *testing.T) {
	env := newTestEnv(t)

	aliceA := env.connect("/tmp/sshkey-test-key", "dev_alice_A")
	aliceB := env.connect("/tmp/sshkey-test-key", "dev_alice_B")
	bob := env.connect("/tmp/sshkey-test-key-bob", "dev_bob_delete")

	// alice on device A creates the DM
	aliceA.enc.Encode(protocol.CreateDM{Type: "create_dm", Other: "usr_bob_test"})

	// Each connected session receives dm_created: A (as sender), B (sibling),
	// and bob. Drain all three.
	var dmID string
	for _, client := range []*testClient{aliceA, aliceB, bob} {
		msgType, raw := client.readMessage()
		if msgType != "dm_created" {
			t.Fatalf("expected dm_created, got %s", msgType)
		}
		var created protocol.DMCreated
		json.Unmarshal(raw, &created)
		if dmID == "" {
			dmID = created.DM
		} else if created.DM != dmID {
			t.Errorf("dm_created ID mismatch across sessions: %s vs %s", dmID, created.DM)
		}
	}
	t.Logf("DM created and announced to 3 sessions: %s", dmID)

	// alice sends a message so there's some history to purge
	aliceA.enc.Encode(protocol.SendDM{
		Type:        "send_dm",
		DM:          dmID,
		WrappedKeys: map[string]string{"usr_alice_test": "wa", "usr_bob_test": "wb"},
		Payload:     "base64_hi",
		Signature:   "base64_sig",
	})
	for _, client := range []*testClient{aliceA, aliceB, bob} {
		msgType, _ := client.readMessage()
		if msgType != "dm" {
			t.Fatalf("expected dm, got %s (on %p)", msgType, client)
		}
	}

	// alice on device A sends leave_dm — simulating /delete
	aliceA.enc.Encode(protocol.LeaveDM{Type: "leave_dm", DM: dmID})

	// Both of alice's sessions receive dm_left. Order is not guaranteed
	// (broadcast loop), so verify each independently.
	for _, client := range []*testClient{aliceA, aliceB} {
		msgType, raw := client.readMessage()
		if msgType != "dm_left" {
			t.Fatalf("alice session expected dm_left, got %s: %s", msgType, string(raw))
		}
		var left protocol.DMLeft
		json.Unmarshal(raw, &left)
		if left.DM != dmID {
			t.Errorf("dm_left has wrong dm: %s, want %s", left.DM, dmID)
		}
	}
	t.Log("dm_left echoed to both alice sessions")

	// Server-side state: alice's cutoff set, bob's cutoff untouched.
	aLeftAt, bLeftAt := env.dmRowCutoffs(dmID)
	if aLeftAt == -1 {
		t.Fatal("DM row should still exist after one-party leave")
	}
	if aLeftAt == 0 {
		t.Error("alice's cutoff should be non-zero after leave_dm")
	}
	if bLeftAt != 0 {
		t.Errorf("bob's cutoff should be 0, got %d", bLeftAt)
	}

	// Bob should not have received anything since the last message. Send
	// bob a probe (a new message from bob to alice) to verify the DM is
	// still live on the server side and the "fresh on re-contact" path
	// works — alice's sessions should receive the new message even though
	// alice "deleted" the DM.
	bob.enc.Encode(protocol.SendDM{
		Type:        "send_dm",
		DM:          dmID,
		WrappedKeys: map[string]string{"usr_alice_test": "wa2", "usr_bob_test": "wb2"},
		Payload:     "base64_followup",
		Signature:   "base64_sig2",
	})
	// bob's own echo first
	msgType, _ := bob.readMessage()
	if msgType != "dm" {
		t.Fatalf("bob expected own dm echo, got %s", msgType)
	}
	// alice's sessions should also receive the follow-up — the server
	// does not filter live broadcasts by cutoff (filter applies to
	// history reads only), so the message reaches her even though her
	// local clients have purged the DM.
	for _, client := range []*testClient{aliceA, aliceB} {
		msgType, _ := client.readMessage()
		if msgType != "dm" {
			t.Fatalf("alice session expected follow-up dm, got %s", msgType)
		}
	}
	t.Log("fresh-on-re-contact delivery verified: bob's message reached both of alice's sessions after her delete")
}

// TestDMDelete_OfflineCatchupViaDMList verifies the offline-device
// catch-up path: a device that was NOT connected when /delete happened
// sees the cutoff in dm_list on its next connect, and subsequent flows
// respect that cutoff.
//
// Flow:
//  1. alice connects device1, creates a DM with bob, sends a message
//  2. alice on device1 sends leave_dm — her cutoff is now set server-side
//  3. device1 disconnects
//  4. alice connects device2 (fresh session)
//  5. During the connect handshake alice receives dm_list — the DM entry
//     for her/bob must carry LeftAtForCaller > 0
func TestDMDelete_OfflineCatchupViaDMList(t *testing.T) {
	env := newTestEnv(t)

	// Phase 1: device1 creates, sends, then leaves
	device1 := env.connect("/tmp/sshkey-test-key", "dev_alice_catchup1")
	bob := env.connect("/tmp/sshkey-test-key-bob", "dev_bob_catchup")

	device1.enc.Encode(protocol.CreateDM{Type: "create_dm", Other: "usr_bob_test"})
	msgType, raw := device1.readMessage()
	if msgType != "dm_created" {
		t.Fatalf("expected dm_created, got %s", msgType)
	}
	var created protocol.DMCreated
	json.Unmarshal(raw, &created)
	dmID := created.DM

	// Drain bob's dm_created so his inbox is clear
	bob.readMessage()

	device1.enc.Encode(protocol.LeaveDM{Type: "leave_dm", DM: dmID})
	msgType, _ = device1.readMessage()
	if msgType != "dm_left" {
		t.Fatalf("expected dm_left on device1, got %s", msgType)
	}
	t.Log("device1: alice left the DM, cutoff set server-side")

	// Close device1's channel to drop the session. device2 will be a
	// fresh sync target.
	device1.ch.Close()

	// Phase 2: device2 connects fresh, inspect the dm_list during handshake
	device2key := "/tmp/sshkey-test-key"
	keyData, err := os.ReadFile(device2key)
	if err != nil {
		t.Fatalf("read alice key: %v", err)
	}
	signer, _ := ssh.ParsePrivateKey(keyData)
	clientCfg := &ssh.ClientConfig{
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}
	conn, err := ssh.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", env.port), clientCfg)
	if err != nil {
		t.Fatalf("device2 dial: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	ch, reqs, err := conn.OpenChannel("session", nil)
	if err != nil {
		t.Fatalf("device2 open: %v", err)
	}
	go ssh.DiscardRequests(reqs)

	device2 := &testClient{
		enc: protocol.NewEncoder(ch),
		dec: protocol.NewDecoder(ch),
		ch:  ch,
		t:   t,
	}
	// Walk the handshake by hand so we can observe dm_list in the
	// welcome flow instead of letting drainUntil swallow it.
	device2.expectType("server_hello")
	device2.enc.Encode(protocol.ClientHello{
		Type:          "client_hello",
		Protocol:      "sshkey-chat",
		Version:       1,
		Client:        "test",
		ClientVersion: "0.0.1",
		DeviceID:      "dev_alice_catchup2",
		Capabilities:  []string{"typing", "reactions", "signatures"},
	})
	device2.expectType("welcome")

	// Drain until we see the dm_list. Other messages (room_list,
	// group_list, profiles, presence, epoch keys, sync_batch) can come
	// through in any order.
	var dmListRaw json.RawMessage
	for i := 0; i < 80; i++ { // generous cap
		var raw json.RawMessage
		if err := device2.dec.Decode(&raw); err != nil {
			t.Fatalf("device2 read: %v", err)
		}
		mt, _ := protocol.TypeOf(raw)
		if mt == "dm_list" {
			dmListRaw = raw
			break
		}
		if mt == "sync_complete" {
			t.Fatal("sync_complete before dm_list — server didn't emit dm_list at all")
		}
	}
	if dmListRaw == nil {
		t.Fatal("never received dm_list during handshake")
	}

	var dmList protocol.DMList
	if err := json.Unmarshal(dmListRaw, &dmList); err != nil {
		t.Fatalf("parse dm_list: %v", err)
	}

	// Find the alice/bob DM in the list and verify LeftAtForCaller > 0.
	var found *protocol.DMInfo
	for i := range dmList.DMs {
		if dmList.DMs[i].ID == dmID {
			found = &dmList.DMs[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("dm_list does not contain the deleted DM %s (entries: %+v)", dmID, dmList.DMs)
	}
	if found.LeftAtForCaller == 0 {
		t.Errorf("LeftAtForCaller should be > 0 on device2 sync, got 0 (full entry: %+v)", *found)
	}
	t.Logf("device2 catchup verified: LeftAtForCaller = %d for dm %s", found.LeftAtForCaller, dmID)
}

// TestRetirement_DMCutoffPropagation verifies that when a user retires
// their account, every 1:1 DM they're a party to has their per-user
// cutoff advanced (silent leave — the other party is NOT notified at
// the DM level, though they do receive the broader user_retired event).
// This is the "silent retirement" path described in dm_refactor.md § 478.
func TestRetirement_DMCutoffPropagation(t *testing.T) {
	env := newTestEnv(t)

	alice := env.connect("/tmp/sshkey-test-key", "dev_alice_retire")
	bob := env.connect("/tmp/sshkey-test-key-bob", "dev_bob_retire")

	// Create a DM and drain the echoes
	alice.enc.Encode(protocol.CreateDM{Type: "create_dm", Other: "usr_bob_test"})
	msgType, raw := alice.readMessage()
	if msgType != "dm_created" {
		t.Fatalf("expected dm_created, got %s", msgType)
	}
	var created protocol.DMCreated
	json.Unmarshal(raw, &created)
	dmID := created.DM
	bob.readMessage() // bob's dm_created

	// Precondition: both cutoffs zero
	aBefore, bBefore := env.dmRowCutoffs(dmID)
	if aBefore != 0 || bBefore != 0 {
		t.Fatalf("precondition: cutoffs should be 0/0, got alice=%d bob=%d", aBefore, bBefore)
	}

	// Bob retires his account. This triggers handleRetirement which
	// iterates bob's DMs and sets his per-user cutoff on each.
	bob.enc.Encode(protocol.RetireMe{
		Type:   "retire_me",
		Reason: "switching_key",
	})

	// Drain messages on alice until we observe user_retired for bob.
	// retirement also fires epoch rotations and possibly group_event
	// leave broadcasts; we tolerate anything in between.
	sawRetired := false
	for i := 0; i < 40; i++ {
		mt, raw := alice.readMessage()
		if mt == "user_retired" {
			var ur protocol.UserRetired
			json.Unmarshal(raw, &ur)
			if ur.User == "usr_bob_test" {
				sawRetired = true
				break
			}
		}
	}
	if !sawRetired {
		t.Fatal("alice never saw user_retired for bob")
	}

	// Give the server a brief moment to finish the retirement write-out
	// (handleRetirement updates multiple tables; the user_retired emit
	// happens alongside the DM cutoff SET, no guaranteed ordering).
	time.Sleep(50 * time.Millisecond)

	// Verify: bob's cutoff set, alice's cutoff untouched.
	aAfter, bAfter := env.dmRowCutoffs(dmID)
	if aAfter == -1 {
		t.Fatal("DM row should still exist after bob's retirement")
	}
	if aAfter != 0 {
		t.Errorf("alice's cutoff should be untouched (0), got %d", aAfter)
	}
	if bAfter == 0 {
		t.Error("bob's cutoff should be set after retirement")
	}
	t.Logf("retirement DM cutoff verified: alice=%d bob=%d", aAfter, bAfter)
}

// groupExists reads group_conversations directly from data.db to confirm
// whether a group row still exists. Returns true if the row is present,
// false otherwise. Used by tests that verify last-member cleanup.
func (e *testEnv) groupExists(groupID string) bool {
	e.t.Helper()
	dbPath := filepath.Join(e.dataDir, "data", "data.db")
	db, err := sql.Open("sqlite", dbPath+"?_busy_timeout=5000")
	if err != nil {
		e.t.Fatalf("open data.db: %v", err)
	}
	defer db.Close()
	var count int
	if err := db.QueryRow(
		`SELECT COUNT(*) FROM group_conversations WHERE id = ?`, groupID,
	).Scan(&count); err != nil {
		e.t.Fatalf("query group_conversations(%s): %v", groupID, err)
	}
	return count > 0
}

// deletedGroupsForUser reads deleted_groups directly from data.db to
// inspect a user's deletion intents. Used by tests verifying both the
// per-user catchup state and the survivability of records across the
// last-member cleanup.
func (e *testEnv) deletedGroupsForUser(userID string) []string {
	e.t.Helper()
	dbPath := filepath.Join(e.dataDir, "data", "data.db")
	db, err := sql.Open("sqlite", dbPath+"?_busy_timeout=5000")
	if err != nil {
		e.t.Fatalf("open data.db: %v", err)
	}
	defer db.Close()
	rows, err := db.Query(
		`SELECT group_id FROM deleted_groups WHERE user_id = ? ORDER BY group_id`, userID,
	)
	if err != nil {
		e.t.Fatalf("query deleted_groups(%s): %v", userID, err)
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			e.t.Fatalf("scan: %v", err)
		}
		ids = append(ids, id)
	}
	return ids
}

// TestDeleteGroup_HappyPath verifies the basic /delete flow:
//   - alice + bob in a group
//   - alice runs delete_group
//   - alice receives group_deleted echo
//   - bob receives group_event{leave}
//   - server-side: alice removed from members, deletion record created
func TestDeleteGroup_HappyPath(t *testing.T) {
	env := newTestEnv(t)

	alice := env.connect("/tmp/sshkey-test-key", "dev_alice_dgrp")
	bob := env.connect("/tmp/sshkey-test-key-bob", "dev_bob_dgrp")

	// alice creates a group with bob. Phase 14: promote bob to co-admin
	// so alice isn't the sole admin when she /delete's — otherwise the
	// inline last-admin gate would reject her delete (the solo-member
	// carve-out only applies when alice is the ONLY member).
	groupID := "group_happy"
	if err := env.srv.Store().CreateGroup(groupID, "usr_alice_test", []string{"usr_alice_test", "usr_bob_test"}, "Happy"); err != nil {
		t.Fatalf("create group: %v", err)
	}
	if err := env.srv.Store().SetGroupMemberAdmin(groupID, "usr_bob_test", true); err != nil {
		t.Fatalf("promote bob: %v", err)
	}

	// alice deletes
	alice.enc.Encode(protocol.DeleteGroup{Type: "delete_group", Group: groupID})

	// alice should see a group_deleted echo
	msgType, raw := alice.readMessage()
	if msgType != "group_deleted" {
		t.Fatalf("alice expected group_deleted, got %s: %s", msgType, string(raw))
	}
	var del protocol.GroupDeleted
	json.Unmarshal(raw, &del)
	if del.Group != groupID {
		t.Errorf("group = %q, want %s", del.Group, groupID)
	}

	// bob should see group_event{leave, alice}
	msgType, raw = bob.readMessage()
	if msgType != "group_event" {
		t.Fatalf("bob expected group_event, got %s", msgType)
	}
	var ev protocol.GroupEvent
	json.Unmarshal(raw, &ev)
	if ev.Event != "leave" || ev.User != "usr_alice_test" {
		t.Errorf("unexpected group_event: %+v", ev)
	}

	// alice removed from group_members
	members, _ := env.srv.Store().GetGroupMembers(groupID)
	for _, m := range members {
		if m == "usr_alice_test" {
			t.Error("alice should be removed from group_members")
		}
	}

	// deletion record exists for alice
	deleted := env.deletedGroupsForUser("usr_alice_test")
	found := false
	for _, id := range deleted {
		if id == groupID {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("deletion record for %s not found in alice's list: %v", groupID, deleted)
	}

	// group itself still exists (bob is still in it)
	if !env.groupExists(groupID) {
		t.Error("group should still exist while bob is a member")
	}
}

// TestDeleteGroup_LastMemberCleanupAndOfflineCatchup is the regression
// test for the bug originally flagged: alice is the last member, runs
// /delete, the server cleans up the group entirely — but alice's offline
// device must still be able to catch up via deleted_groups when it
// reconnects later.
func TestDeleteGroup_LastMemberCleanupAndOfflineCatchup(t *testing.T) {
	env := newTestEnv(t)

	deviceA := env.connect("/tmp/sshkey-test-key", "dev_alice_solo_A")

	// alice solo in a group
	groupID := "group_solo"
	if err := env.srv.Store().CreateGroup(groupID, "usr_alice_test", []string{"usr_alice_test"}, "Solo"); err != nil {
		t.Fatalf("create group: %v", err)
	}

	// device A deletes
	deviceA.enc.Encode(protocol.DeleteGroup{Type: "delete_group", Group: groupID})

	msgType, _ := deviceA.readMessage()
	if msgType != "group_deleted" {
		t.Fatalf("device A expected group_deleted, got %s", msgType)
	}

	// Group is fully cleaned up (alice was the last member)
	if env.groupExists(groupID) {
		t.Fatal("group should be cleaned up after last member /delete")
	}

	// CRITICAL: alice's deletion record must SURVIVE the cleanup so
	// offline devices can catch up.
	deleted := env.deletedGroupsForUser("usr_alice_test")
	found := false
	for _, id := range deleted {
		if id == groupID {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("deletion record must survive last-member cleanup, got %v", deleted)
	}

	// Now device B (was offline) connects. It should observe the
	// deleted_groups list during sync containing this group.
	device2key := "/tmp/sshkey-test-key"
	keyData, err := os.ReadFile(device2key)
	if err != nil {
		t.Fatalf("read alice key: %v", err)
	}
	signer, _ := ssh.ParsePrivateKey(keyData)
	clientCfg := &ssh.ClientConfig{
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}
	conn, err := ssh.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", env.port), clientCfg)
	if err != nil {
		t.Fatalf("device B dial: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	ch, reqs, err := conn.OpenChannel("session", nil)
	if err != nil {
		t.Fatalf("device B open: %v", err)
	}
	go ssh.DiscardRequests(reqs)

	deviceB := &testClient{
		enc: protocol.NewEncoder(ch),
		dec: protocol.NewDecoder(ch),
		ch:  ch,
		t:   t,
	}
	deviceB.expectType("server_hello")
	deviceB.enc.Encode(protocol.ClientHello{
		Type:          "client_hello",
		Protocol:      "sshkey-chat",
		Version:       1,
		Client:        "test",
		ClientVersion: "0.0.1",
		DeviceID:      "dev_alice_solo_B",
		Capabilities:  []string{"typing", "reactions", "signatures"},
	})
	deviceB.expectType("welcome")

	// Drain until we see deleted_groups OR sync_complete
	var deletedGroupsRaw json.RawMessage
	for i := 0; i < 80; i++ {
		var raw json.RawMessage
		if err := deviceB.dec.Decode(&raw); err != nil {
			t.Fatalf("device B read: %v", err)
		}
		mt, _ := protocol.TypeOf(raw)
		if mt == "deleted_groups" {
			deletedGroupsRaw = raw
			break
		}
		if mt == "sync_complete" {
			t.Fatal("sync_complete before deleted_groups — server didn't emit deleted_groups at all")
		}
	}
	if deletedGroupsRaw == nil {
		t.Fatal("never received deleted_groups during handshake")
	}

	var list protocol.DeletedGroupsList
	json.Unmarshal(deletedGroupsRaw, &list)
	if len(list.Groups) != 1 || list.Groups[0] != groupID {
		t.Errorf("expected [%s] in deleted_groups list, got %v", groupID, list.Groups)
	}
	t.Logf("offline catchup verified: device B received deleted_groups list with %s", groupID)
}

// TestDeleteGroup_MultiDeviceLiveEcho verifies that when alice has two
// devices online and runs /delete on one, BOTH receive the group_deleted
// echo (multi-device propagation through the live broadcast loop).
func TestDeleteGroup_MultiDeviceLiveEcho(t *testing.T) {
	env := newTestEnv(t)

	deviceA := env.connect("/tmp/sshkey-test-key", "dev_alice_multi_A")
	deviceB := env.connect("/tmp/sshkey-test-key", "dev_alice_multi_B")
	bob := env.connect("/tmp/sshkey-test-key-bob", "dev_bob_multi")
	_ = bob // bob is just here so the group has a remaining member

	// Phase 14: promote bob to co-admin so alice isn't blocked by the
	// last-admin gate when she /delete's (same rationale as
	// TestDeleteGroup_HappyPath).
	groupID := "group_multi"
	if err := env.srv.Store().CreateGroup(groupID, "usr_alice_test", []string{"usr_alice_test", "usr_bob_test"}, "Multi"); err != nil {
		t.Fatalf("create group: %v", err)
	}
	if err := env.srv.Store().SetGroupMemberAdmin(groupID, "usr_bob_test", true); err != nil {
		t.Fatalf("promote bob: %v", err)
	}

	// device A initiates the delete
	deviceA.enc.Encode(protocol.DeleteGroup{Type: "delete_group", Group: groupID})

	// Both A and B should receive group_deleted (order not guaranteed)
	for _, dev := range []*testClient{deviceA, deviceB} {
		msgType, raw := dev.readMessage()
		if msgType != "group_deleted" {
			t.Fatalf("device expected group_deleted, got %s: %s", msgType, string(raw))
		}
		var del protocol.GroupDeleted
		json.Unmarshal(raw, &del)
		if del.Group != groupID {
			t.Errorf("wrong group in echo: %s", del.Group)
		}
	}

	// bob received group_event{leave}
	msgType, _ := bob.readMessage()
	if msgType != "group_event" {
		t.Fatalf("bob expected group_event, got %s", msgType)
	}
	t.Log("multi-device live echo verified")
}

// TestDeleteGroup_AlreadyLeft verifies the idempotent path: alice was
// never in the group (or already /leave'd), but runs /delete anyway.
// The server records the deletion intent, doesn't try to remove
// non-existent membership, and echoes back so alice's other devices
// purge their stale local state.
func TestDeleteGroup_AlreadyLeft(t *testing.T) {
	env := newTestEnv(t)

	alice := env.connect("/tmp/sshkey-test-key", "dev_alice_already")

	// Group exists but alice is NOT a member
	groupID := "group_not_a_member"
	if err := env.srv.Store().CreateGroup(groupID, "usr_bob_test", []string{"usr_bob_test", "usr_carol_test"}, "Without Alice"); err != nil {
		t.Fatalf("create group: %v", err)
	}

	alice.enc.Encode(protocol.DeleteGroup{Type: "delete_group", Group: groupID})

	// alice should still get the echo (idempotent path)
	msgType, _ := alice.readMessage()
	if msgType != "group_deleted" {
		t.Fatalf("alice expected group_deleted echo for idempotent delete, got %s", msgType)
	}

	// Server-side: members untouched
	members, _ := env.srv.Store().GetGroupMembers(groupID)
	if len(members) != 2 {
		t.Errorf("expected group to still have 2 members, got %v", members)
	}

	// Deletion record exists for alice
	deleted := env.deletedGroupsForUser("usr_alice_test")
	found := false
	for _, id := range deleted {
		if id == groupID {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("deletion record for already-left case not found: %v", deleted)
	}
}

// ----------------------------------------------------------------------
// Phase 14 E2E tests
// ----------------------------------------------------------------------

// TestGroupAdmin_PromoteE2E is the Phase 14 smoke test for the full
// wire pipeline: real SSH connection, wire-level promote_group_admin,
// real handler, real broadcast, real store mutation. Exhaustive
// coverage of every failure mode lives in internal/server — this
// just proves the verb compiles through the stack end-to-end.
func TestGroupAdmin_PromoteE2E(t *testing.T) {
	env := newTestEnv(t)
	alice := env.connect("/tmp/sshkey-test-key", "dev_alice_promote_e2e")

	groupID := "group_promote_e2e"
	if err := env.srv.Store().CreateGroup(groupID, "usr_alice_test", []string{"usr_alice_test", "usr_bob_test"}, "PromoteE2E"); err != nil {
		t.Fatalf("create group: %v", err)
	}

	// alice promotes bob. drainUntil skips any unrelated broadcasts
	// (including alice's own broadcast copy) and stops at the echo.
	alice.enc.Encode(protocol.PromoteGroupAdmin{
		Type:  "promote_group_admin",
		Group: groupID,
		User:  "usr_bob_test",
	})
	raw, _ := alice.drainUntil("promote_admin_result")
	var result protocol.PromoteAdminResult
	json.Unmarshal(raw, &result)
	if result.Group != groupID || result.User != "usr_bob_test" {
		t.Errorf("result echo wrong: %+v", result)
	}

	// Server-side state: bob is now an admin
	if isAdmin, err := env.srv.Store().IsGroupAdmin(groupID, "usr_bob_test"); err != nil || !isAdmin {
		t.Errorf("bob should be admin after promote (isAdmin=%v err=%v)", isAdmin, err)
	}
}

// TestGroupAdmin_LastAdminRejectionOnLeave_E2E is the E2E regression
// for the "at least one admin" invariant: a sole admin who tries to
// /leave a group with other members is rejected with ErrForbidden.
// They must promote a successor first.
func TestGroupAdmin_LastAdminRejectionOnLeave_E2E(t *testing.T) {
	env := newTestEnv(t)
	alice := env.connect("/tmp/sshkey-test-key", "dev_alice_lastadmin")

	// alice is the sole admin of a 2-member group (she + bob regular member)
	groupID := "group_lastadmin"
	if err := env.srv.Store().CreateGroup(groupID, "usr_alice_test", []string{"usr_alice_test", "usr_bob_test"}, "Last Admin"); err != nil {
		t.Fatalf("create group: %v", err)
	}

	// alice tries to /leave — should be rejected
	alice.enc.Encode(protocol.LeaveGroup{Type: "leave_group", Group: groupID})

	// drainUntil skips past any unrelated traffic (shouldn't be any
	// on the reject path, but defensive).
	raw, _ := alice.drainUntil("error")
	var errResp protocol.Error
	json.Unmarshal(raw, &errResp)
	if errResp.Code != protocol.ErrForbidden {
		t.Errorf("expected ErrForbidden, got %q: %s", errResp.Code, errResp.Message)
	}

	// alice is still a member — the rejection didn't touch state
	isMember, _ := env.srv.Store().IsGroupMember(groupID, "usr_alice_test")
	if !isMember {
		t.Error("alice should still be a member after rejected leave")
	}
}
