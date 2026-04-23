package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/brushtailmedia/sshkey-chat/internal/config"
	"github.com/brushtailmedia/sshkey-chat/internal/counters"
	"github.com/brushtailmedia/sshkey-chat/internal/protocol"
)

func waitForClientDisconnect(t *testing.T, tc *testClient, timeout time.Duration) {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- tc.conn.Wait() }()
	select {
	case <-done:
		return
	case <-time.After(timeout):
		t.Fatalf("client connection did not close within %s", timeout)
	}
}

func tryConnectHandshake(port int, keyPath, deviceID string) error {
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("read key: %w", err)
	}
	signer, err := ssh.ParsePrivateKey(keyData)
	if err != nil {
		return fmt.Errorf("parse key: %w", err)
	}

	clientCfg := &ssh.ClientConfig{
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}
	conn, err := ssh.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port), clientCfg)
	if err != nil {
		return err
	}
	defer conn.Close()

	ch, reqs, err := conn.OpenChannel("session", nil)
	if err != nil {
		return fmt.Errorf("open channel: %w", err)
	}
	defer ch.Close()
	go ssh.DiscardRequests(reqs)

	enc := protocol.NewEncoder(ch)
	dec := protocol.NewDecoder(ch)

	var raw json.RawMessage
	if err := dec.Decode(&raw); err != nil {
		return fmt.Errorf("read server_hello: %w", err)
	}
	if mt, _ := protocol.TypeOf(raw); mt != "server_hello" {
		return fmt.Errorf("expected server_hello, got %s", mt)
	}

	if err := enc.Encode(protocol.ClientHello{
		Type:          "client_hello",
		Protocol:      "sshkey-chat",
		Version:       1,
		Client:        "test",
		ClientVersion: "0.0.1",
		DeviceID:      deviceID,
		Capabilities:  []string{"typing", "reactions", "signatures"},
	}); err != nil {
		return fmt.Errorf("write client_hello: %w", err)
	}

	if err := dec.Decode(&raw); err != nil {
		return fmt.Errorf("read post-hello frame: %w", err)
	}
	if mt, _ := protocol.TypeOf(raw); mt != "welcome" {
		return fmt.Errorf("connection not welcomed (first post-hello frame: %s)", mt)
	}
	return nil
}

func signalRule(signal string, count int) map[string]string {
	return map[string]string{signal: fmt.Sprintf("%d:60", count)}
}

func TestAutoRevoke_PerSignalThresholdDouble_RevokesKicksAndRestore(t *testing.T) {
	for i, signal := range counters.AutoRevokeSignals {
		t.Run(signal, func(t *testing.T) {
			e := newTestEnvWithConfig(t, func(cfg *config.Config) {
				cfg.Server.Server.AutoRevoke.Enabled = true
				cfg.Server.Server.AutoRevoke.Thresholds = signalRule(signal, 2)
			})

			deviceID := fmt.Sprintf("dev_autorevoke_hi_%02d", i)
			alice := e.connect(fixtureKeyPath(t, "alice"), deviceID)

			for n := 0; n < 4; n++ { // 2x threshold
				e.srv.CounterIncForTesting(signal, deviceID)
			}

			e.srv.ProcessAutoRevokeForTesting()
			e.srv.ProcessPendingDeviceRevocationsForTesting()

			revoked, err := e.srv.Store().IsDeviceRevoked("usr_alice_test", deviceID)
			if err != nil {
				t.Fatalf("IsDeviceRevoked: %v", err)
			}
			if !revoked {
				t.Fatalf("device %s should be revoked for signal %s", deviceID, signal)
			}

			waitForClientDisconnect(t, alice, 3*time.Second)

			if err := e.srv.Store().RestoreDevice("usr_alice_test", deviceID); err != nil {
				t.Fatalf("restore device: %v", err)
			}
			revoked, err = e.srv.Store().IsDeviceRevoked("usr_alice_test", deviceID)
			if err != nil {
				t.Fatalf("IsDeviceRevoked after restore: %v", err)
			}
			if revoked {
				t.Fatalf("device %s should be restored", deviceID)
			}

			if err := tryConnectHandshake(e.port, fixtureKeyPath(t, "alice"), deviceID); err != nil {
				t.Fatalf("reconnect after restore failed: %v", err)
			}
		})
	}
}

func TestAutoRevoke_PerSignalSubThreshold_NoRevocation(t *testing.T) {
	for i, signal := range counters.AutoRevokeSignals {
		t.Run(signal, func(t *testing.T) {
			e := newTestEnvWithConfig(t, func(cfg *config.Config) {
				cfg.Server.Server.AutoRevoke.Enabled = true
				cfg.Server.Server.AutoRevoke.Thresholds = signalRule(signal, 4)
			})

			deviceID := fmt.Sprintf("dev_autorevoke_lo_%02d", i)
			alice := e.connect(fixtureKeyPath(t, "alice"), deviceID)

			for n := 0; n < 2; n++ { // 0.5x threshold
				e.srv.CounterIncForTesting(signal, deviceID)
			}

			e.srv.ProcessAutoRevokeForTesting()
			e.srv.ProcessPendingDeviceRevocationsForTesting()

			revoked, err := e.srv.Store().IsDeviceRevoked("usr_alice_test", deviceID)
			if err != nil {
				t.Fatalf("IsDeviceRevoked: %v", err)
			}
			if revoked {
				t.Fatalf("device %s should NOT be revoked at sub-threshold for signal %s", deviceID, signal)
			}

			if err := alice.enc.Encode(protocol.ListDevices{Type: "list_devices"}); err != nil {
				t.Fatalf("list_devices encode on non-revoked session: %v", err)
			}
			mt, raw := alice.readMessage()
			if mt != "device_list" {
				t.Fatalf("expected device_list on non-revoked session, got %s: %s", mt, string(raw))
			}
		})
	}
}

func TestAutoRevoke_AdminRecoveryEndToEnd(t *testing.T) {
	e := newTestEnvWithConfig(t, func(cfg *config.Config) {
		cfg.Server.Server.AutoRevoke.Enabled = true
		cfg.Server.Server.AutoRevoke.Thresholds = signalRule(counters.SignalMalformedFrame, 1)
	})
	if err := e.srv.Store().SetAdmin("usr_alice_test", true); err != nil {
		t.Fatalf("set admin: %v", err)
	}

	deviceID := "dev_alice_admin_recovery"
	alice := e.connect(fixtureKeyPath(t, "alice"), deviceID)

	e.srv.CounterIncForTesting(counters.SignalMalformedFrame, deviceID)
	e.srv.ProcessAutoRevokeForTesting()
	e.srv.ProcessPendingDeviceRevocationsForTesting()

	revoked, err := e.srv.Store().IsDeviceRevoked("usr_alice_test", deviceID)
	if err != nil {
		t.Fatalf("IsDeviceRevoked: %v", err)
	}
	if !revoked {
		t.Fatal("admin device should be revoked after threshold crossing")
	}

	waitForClientDisconnect(t, alice, 3*time.Second)

	if err := e.srv.Store().RestoreDevice("usr_alice_test", deviceID); err != nil {
		t.Fatalf("restore admin device: %v", err)
	}

	recovered := e.connect(fixtureKeyPath(t, "alice"), deviceID)
	if err := recovered.enc.Encode(protocol.ListPendingKeys{Type: "list_pending_keys"}); err != nil {
		t.Fatalf("list_pending_keys encode: %v", err)
	}
	mt, raw := recovered.readMessage()
	if mt != "pending_keys_list" {
		t.Fatalf("expected pending_keys_list after admin recovery, got %s: %s", mt, string(raw))
	}
}

func TestAutoRevoke_LaunchGateRepresentativeFlow_NoMisbehaviorSignals(t *testing.T) {
	const deviceID = "dev_launch_gate"
	e := newTestEnvWithConfig(t, func(cfg *config.Config) {
		cfg.Server.Server.AutoRevoke.Enabled = false // observer mode for launch-gate validation
		cfg.Server.Server.AutoRevoke.Thresholds = signalRule(counters.SignalReconnectFlood, 10)
		cfg.Server.Server.Quotas.User.Enabled = true
		cfg.Server.Server.Quotas.User.DailyUploadBytesWarn = "1MB"
		cfg.Server.Server.Quotas.User.DailyUploadBytesBlock = "2MB"
	})

	alice := e.connectLegacy(fixtureKeyPath(t, "alice"), deviceID)
	bob := e.connect(fixtureKeyPath(t, "bob"), "dev_launch_gate_bob")
	roomID := e.roomIDByName("general")

	if err := alice.enc.Encode(protocol.Send{
		Type:      "send",
		Room:      roomID,
		Epoch:     1,
		Payload:   "launch_gate_room_payload",
		Signature: "launch_gate_room_sig",
	}); err != nil {
		t.Fatalf("room send: %v", err)
	}
	mt, raw := alice.readMessage()
	if mt != "message" {
		t.Fatalf("expected room message echo, got %s", mt)
	}
	var roomMsg protocol.Message
	if err := json.Unmarshal(raw, &roomMsg); err != nil {
		t.Fatalf("unmarshal room message: %v", err)
	}
	mt, _ = bob.readMessage()
	if mt != "message" {
		t.Fatalf("bob expected room message, got %s", mt)
	}

	if err := alice.enc.Encode(protocol.Edit{
		Type:      "edit",
		ID:        roomMsg.ID,
		Room:      roomID,
		Epoch:     roomMsg.Epoch,
		Payload:   "launch_gate_room_payload_edit",
		Signature: "launch_gate_room_sig_edit",
	}); err != nil {
		t.Fatalf("room edit: %v", err)
	}
	if mt, _ = alice.readMessage(); mt != "edited" {
		t.Fatalf("alice expected edited, got %s", mt)
	}
	if mt, _ = bob.readMessage(); mt != "edited" {
		t.Fatalf("bob expected edited, got %s", mt)
	}

	if err := alice.enc.Encode(protocol.React{
		Type:      "react",
		ID:        roomMsg.ID,
		Room:      roomID,
		Epoch:     roomMsg.Epoch,
		Payload:   "emoji_payload",
		Signature: "emoji_sig",
	}); err != nil {
		t.Fatalf("react: %v", err)
	}
	mt, raw = alice.readMessage()
	if mt != "reaction" {
		t.Fatalf("expected reaction echo, got %s", mt)
	}
	var reaction protocol.Reaction
	if err := json.Unmarshal(raw, &reaction); err != nil {
		t.Fatalf("unmarshal reaction: %v", err)
	}
	mt, _ = bob.readMessage()
	if mt != "reaction" {
		t.Fatalf("bob expected reaction, got %s", mt)
	}

	if err := alice.enc.Encode(protocol.Unreact{
		Type:       "unreact",
		ReactionID: reaction.ReactionID,
	}); err != nil {
		t.Fatalf("unreact: %v", err)
	}
	if mt, _ = alice.readMessage(); mt != "reaction_removed" {
		t.Fatalf("alice expected reaction_removed, got %s", mt)
	}
	if mt, _ = bob.readMessage(); mt != "reaction_removed" {
		t.Fatalf("bob expected reaction_removed, got %s", mt)
	}

	groupID := "group_launch_gate"
	if err := e.srv.Store().CreateGroup(groupID, "usr_alice_test", []string{"usr_alice_test", "usr_bob_test"}, "Launch Gate Group"); err != nil {
		t.Fatalf("create group: %v", err)
	}
	if err := alice.enc.Encode(protocol.SendGroup{
		Type:  "send_group",
		Group: groupID,
		WrappedKeys: map[string]string{
			"usr_alice_test": "wg_alice",
			"usr_bob_test":   "wg_bob",
		},
		Payload:   "group_payload",
		Signature: "group_sig",
	}); err != nil {
		t.Fatalf("send_group: %v", err)
	}
	mt, raw = alice.readMessage()
	if mt != "group_message" {
		t.Fatalf("alice expected group_message, got %s", mt)
	}
	var groupMsg protocol.GroupMessage
	if err := json.Unmarshal(raw, &groupMsg); err != nil {
		t.Fatalf("unmarshal group_message: %v", err)
	}
	if mt, _ = bob.readMessage(); mt != "group_message" {
		t.Fatalf("bob expected group_message, got %s", mt)
	}
	if err := alice.enc.Encode(protocol.EditGroup{
		Type:  "edit_group",
		ID:    groupMsg.ID,
		Group: groupID,
		WrappedKeys: map[string]string{
			"usr_alice_test": "wg_alice_e",
			"usr_bob_test":   "wg_bob_e",
		},
		Payload:   "group_payload_edit",
		Signature: "group_sig_edit",
	}); err != nil {
		t.Fatalf("edit_group: %v", err)
	}
	if mt, _ = alice.readMessage(); mt != "group_edited" {
		t.Fatalf("alice expected group_edited, got %s", mt)
	}
	if mt, _ = bob.readMessage(); mt != "group_edited" {
		t.Fatalf("bob expected group_edited, got %s", mt)
	}

	if err := alice.enc.Encode(protocol.CreateDM{
		Type:  "create_dm",
		Other: "usr_bob_test",
	}); err != nil {
		t.Fatalf("create_dm: %v", err)
	}
	mt, raw = alice.readMessage()
	if mt != "dm_created" {
		t.Fatalf("alice expected dm_created, got %s", mt)
	}
	var createdDM protocol.DMCreated
	if err := json.Unmarshal(raw, &createdDM); err != nil {
		t.Fatalf("unmarshal dm_created: %v", err)
	}
	for {
		mt, _ = bob.readMessage()
		if mt == "dm_created" {
			break
		}
	}

	if err := alice.enc.Encode(protocol.SendDM{
		Type: "send_dm",
		DM:   createdDM.DM,
		WrappedKeys: map[string]string{
			"usr_alice_test": "wdm_alice",
			"usr_bob_test":   "wdm_bob",
		},
		Payload:   "dm_payload",
		Signature: "dm_sig",
	}); err != nil {
		t.Fatalf("send_dm: %v", err)
	}
	mt, raw = alice.readMessage()
	if mt != "dm" {
		t.Fatalf("alice expected dm, got %s", mt)
	}
	var dmMsg protocol.DM
	if err := json.Unmarshal(raw, &dmMsg); err != nil {
		t.Fatalf("unmarshal dm: %v", err)
	}
	if mt, _ = bob.readMessage(); mt != "dm" {
		t.Fatalf("bob expected dm, got %s", mt)
	}

	if err := alice.enc.Encode(protocol.EditDM{
		Type: "edit_dm",
		ID:   dmMsg.ID,
		DM:   createdDM.DM,
		WrappedKeys: map[string]string{
			"usr_alice_test": "wdm_alice_e",
			"usr_bob_test":   "wdm_bob_e",
		},
		Payload:   "dm_payload_edit",
		Signature: "dm_sig_edit",
	}); err != nil {
		t.Fatalf("edit_dm: %v", err)
	}
	if mt, _ = alice.readMessage(); mt != "dm_edited" {
		t.Fatalf("alice expected dm_edited, got %s", mt)
	}
	if mt, _ = bob.readMessage(); mt != "dm_edited" {
		t.Fatalf("bob expected dm_edited, got %s", mt)
	}

	uploadPayload := []byte("launch-gate-upload")
	upComplete, upErr, err := legacyUploadOnce(alice, uploadStartForPayload("up_launch_gate", roomID, uploadPayload), uploadPayload)
	if err != nil {
		t.Fatalf("upload round-trip: %v", err)
	}
	if upErr != nil {
		t.Fatalf("upload rejected unexpectedly: %+v", *upErr)
	}
	if upComplete == nil || upComplete.FileID == "" {
		t.Fatal("expected upload_complete with file_id")
	}

	for i := 0; i < 4; i++ {
		if err := alice.enc.Encode(protocol.Send{
			Type:      "send",
			Room:      roomID,
			Epoch:     1,
			Payload:   fmt.Sprintf("history_payload_%d", i),
			Signature: "history_sig",
		}); err != nil {
			t.Fatalf("history seed send %d: %v", i, err)
		}
		mt, raw = alice.readMessage()
		if mt != "message" {
			t.Fatalf("history seed expected message, got %s", mt)
		}
		var m protocol.Message
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatalf("unmarshal history seed: %v", err)
		}
		roomMsg.ID = m.ID
		mt, _ = bob.readMessage()
		if mt != "message" {
			t.Fatalf("bob expected history seed message, got %s", mt)
		}
	}

	if err := alice.enc.Encode(protocol.History{
		Type:   "history",
		Room:   roomID,
		Before: roomMsg.ID,
		Limit:  3,
	}); err != nil {
		t.Fatalf("history request: %v", err)
	}
	if mt, _ = alice.readMessage(); mt != "history_result" {
		t.Fatalf("expected history_result, got %s", mt)
	}

	if err := alice.enc.Encode(protocol.RoomMembers{
		Type: "room_members",
		Room: roomID,
	}); err != nil {
		t.Fatalf("room_members: %v", err)
	}
	if mt, _ = alice.readMessage(); mt != "room_members_list" {
		t.Fatalf("expected room_members_list, got %s", mt)
	}

	if err := alice.enc.Encode(protocol.ListDevices{Type: "list_devices"}); err != nil {
		t.Fatalf("list_devices: %v", err)
	}
	if mt, _ = alice.readMessage(); mt != "device_list" {
		t.Fatalf("expected device_list, got %s", mt)
	}

	_ = alice.conn.Close()
	alice = e.connectLegacy(fixtureKeyPath(t, "alice"), deviceID)
	if err := alice.enc.Encode(protocol.ListDevices{Type: "list_devices"}); err != nil {
		t.Fatalf("list_devices after reconnect: %v", err)
	}
	if mt, _ = alice.readMessage(); mt != "device_list" {
		t.Fatalf("expected device_list after reconnect, got %s", mt)
	}

	snap := e.srv.CounterSnapshotForTesting()
	for _, signal := range counters.AutoRevokeSignals {
		got := int64(0)
		if bySignal, ok := snap[signal]; ok {
			got = bySignal[deviceID]
		}
		if signal == counters.SignalReconnectFlood {
			if got != 2 {
				t.Fatalf("signal %s count = %d, want 2 for one reconnect", signal, got)
			}
			continue
		}
		if got != 0 {
			t.Fatalf("launch-gate regression: signal %s count = %d (want 0)", signal, got)
		}
	}
}

func TestAutoRevoke_PerSignalThresholdDouble_DeviceReasonContainsSignalName(t *testing.T) {
	for i, signal := range counters.AutoRevokeSignals {
		t.Run(signal, func(t *testing.T) {
			e := newTestEnvWithConfig(t, func(cfg *config.Config) {
				cfg.Server.Server.AutoRevoke.Enabled = true
				cfg.Server.Server.AutoRevoke.Thresholds = signalRule(signal, 2)
			})
			deviceID := fmt.Sprintf("dev_autoreason_%02d", i)
			_ = e.connect(fixtureKeyPath(t, "alice"), deviceID)
			for n := 0; n < 4; n++ {
				e.srv.CounterIncForTesting(signal, deviceID)
			}
			e.srv.ProcessAutoRevokeForTesting()
			e.srv.ProcessPendingDeviceRevocationsForTesting()

			db := e.srv.Store().DataDB()
			var reason string
			if err := db.QueryRow(`SELECT reason FROM revoked_devices WHERE user = ? AND device_id = ?`, "usr_alice_test", deviceID).Scan(&reason); err != nil {
				t.Fatalf("read revoked reason: %v", err)
			}
			if !strings.Contains(reason, "Automatic revocation:") {
				t.Fatalf("reason %q should include auto-revoke framing for signal %s", reason, signal)
			}
		})
	}
}
