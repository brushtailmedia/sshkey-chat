package main

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/brushtailmedia/sshkey/internal/config"
	"github.com/brushtailmedia/sshkey/internal/protocol"
	"github.com/brushtailmedia/sshkey/internal/server"
)

// testEnv holds a running server and its config for tests.
type testEnv struct {
	srv  *server.Server
	cfg  *config.Config
	port int
	t    *testing.T
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	testConfigDir := filepath.Join("..", "..", "testdata", "config")
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

	go srv.ListenAndServe()
	t.Cleanup(func() { srv.Close() })
	time.Sleep(200 * time.Millisecond)

	return &testEnv{srv: srv, cfg: cfg, port: port, t: t}
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

	// Connect alice and bob
	alice := env.connect("/tmp/sshkey-test-key", "dev_alice_001")
	bob := env.connect("/tmp/sshkey-test-key-bob", "dev_bob_001")

	// Alice sends a message to "general" (both are members)
	err := alice.enc.Encode(protocol.Send{
		Type:      "send",
		Room:      "general",
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
	if aliceMsg.From != "alice" {
		t.Errorf("from = %q, want alice", aliceMsg.From)
	}
	if aliceMsg.Room != "general" {
		t.Errorf("room = %q, want general", aliceMsg.Room)
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

	// Bob sends a message to "general"
	err = bob.enc.Encode(protocol.Send{
		Type:      "send",
		Room:      "general",
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

	// Alice sends to "engineering" (bob is NOT a member)
	err = alice.enc.Encode(protocol.Send{
		Type:      "send",
		Room:      "engineering",
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
		Room:    "general",
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
	if bobCheck.Room != "general" {
		t.Errorf("bob got room=%q, should be general (not engineering)", bobCheck.Room)
	}

	t.Log("room messaging and isolation verified")
}

func TestSyncOnReconnect(t *testing.T) {
	env := newTestEnv(t)

	// Connect alice, send some messages
	alice := env.connect("/tmp/sshkey-test-key", "dev_alice_sync")

	for i := 0; i < 3; i++ {
		alice.enc.Encode(protocol.Send{
			Type:    "send",
			Room:    "general",
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

	alice := env.connect("/tmp/sshkey-test-key", "dev_alice_hist")

	// Send 5 messages
	var msgIDs []string
	for i := 0; i < 5; i++ {
		alice.enc.Encode(protocol.Send{
			Type:    "send",
			Room:    "general",
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
		Room:   "general",
		Before: msgIDs[4],
		Limit:  2,
	})

	msgType, raw := alice.readMessage()
	if msgType != "history_result" {
		t.Fatalf("expected history_result, got %s", msgType)
	}

	var result protocol.HistoryResult
	json.Unmarshal(raw, &result)

	if result.Room != "general" {
		t.Errorf("room = %q, want general", result.Room)
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

	// Alice creates a DM with bob
	alice.enc.Encode(protocol.CreateDM{
		Type:    "create_dm",
		Members: []string{"bob"},
	})

	// Alice receives dm_created
	msgType, raw := alice.readMessage()
	if msgType != "dm_created" {
		t.Fatalf("expected dm_created, got %s", msgType)
	}
	var created protocol.DMCreated
	json.Unmarshal(raw, &created)

	if created.Conversation == "" {
		t.Fatal("dm_created has no conversation ID")
	}
	if len(created.Members) != 2 {
		t.Fatalf("expected 2 members, got %d", len(created.Members))
	}
	t.Logf("conversation created: id=%s members=%v", created.Conversation, created.Members)

	// Alice creates the same DM again -- should get back the existing one (1:1 dedup)
	alice.enc.Encode(protocol.CreateDM{
		Type:    "create_dm",
		Members: []string{"bob"},
	})
	msgType, raw = alice.readMessage()
	if msgType != "dm_created" {
		t.Fatalf("expected dm_created (dedup), got %s", msgType)
	}
	var created2 protocol.DMCreated
	json.Unmarshal(raw, &created2)
	if created2.Conversation != created.Conversation {
		t.Errorf("1:1 dedup failed: first=%s second=%s", created.Conversation, created2.Conversation)
	}
	t.Log("1:1 dedup verified")

	// Alice sends a DM
	convID := created.Conversation
	alice.enc.Encode(protocol.SendDM{
		Type:         "send_dm",
		Conversation: convID,
		WrappedKeys:  map[string]string{"alice": "wrapped_a", "bob": "wrapped_b"},
		Payload:      "base64_encrypted_dm",
		Signature:    "base64_sig_dm",
	})

	// Alice receives her own DM
	msgType, raw = alice.readMessage()
	if msgType != "dm" {
		t.Fatalf("alice expected dm, got %s", msgType)
	}

	// Bob receives dm_created (from server push) then the DM
	// Drain dm_created if it comes first
	msgType, raw = bob.readMessage()
	if msgType == "dm_created" {
		t.Log("bob received dm_created push")
		msgType, raw = bob.readMessage()
	}
	if msgType != "dm" {
		t.Fatalf("bob expected dm, got %s", msgType)
	}

	var bobDM protocol.DM
	json.Unmarshal(raw, &bobDM)

	if bobDM.From != "alice" {
		t.Errorf("from = %q, want alice", bobDM.From)
	}
	if bobDM.Conversation != convID {
		t.Errorf("conversation = %q, want %s", bobDM.Conversation, convID)
	}
	if bobDM.Payload != "base64_encrypted_dm" {
		t.Errorf("payload = %q, want base64_encrypted_dm", bobDM.Payload)
	}
	if bobDM.WrappedKeys["bob"] != "wrapped_b" {
		t.Errorf("wrapped_keys[bob] = %q, want wrapped_b", bobDM.WrappedKeys["bob"])
	}

	t.Logf("DM delivered: id=%s from=%s conv=%s", bobDM.ID, bobDM.From, bobDM.Conversation)

	// Test invalid wrapped_keys (missing a member)
	alice.enc.Encode(protocol.SendDM{
		Type:         "send_dm",
		Conversation: convID,
		WrappedKeys:  map[string]string{"alice": "wrapped_a"}, // missing bob
		Payload:      "base64_bad",
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

	// Test leave conversation
	bob.enc.Encode(protocol.LeaveConversation{
		Type:         "leave_conversation",
		Conversation: convID,
	})

	// Alice should receive the leave event
	msgType, raw = alice.readMessage()
	if msgType != "conversation_event" {
		t.Fatalf("expected conversation_event, got %s", msgType)
	}
	var event protocol.ConversationEvent
	json.Unmarshal(raw, &event)
	if event.Event != "leave" || event.User != "bob" {
		t.Errorf("event = %+v, want leave by bob", event)
	}

	t.Log("DM conversations fully verified")
}

func itoa(n int) string {
	return fmt.Sprintf("%d", n)
}
