package server

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/brushtailmedia/sshkey-chat/internal/protocol"
)

// captureClient wraps a Client with a buffer-backed Encoder so handler
// responses can be inspected in tests.
type captureClient struct {
	*Client
	buf *bytes.Buffer
}

func (cc *captureClient) messages() []json.RawMessage {
	var out []json.RawMessage
	for _, line := range bytes.Split(cc.buf.Bytes(), []byte{'\n'}) {
		if len(line) == 0 {
			continue
		}
		out = append(out, json.RawMessage(line))
	}
	return out
}

// testClientFor constructs a minimal Client whose Encoder writes to an
// in-memory buffer. Used to test handleListDevices / handleRevokeDevice
// in isolation from the SSH layer.
func testClientFor(userID, deviceID string) *captureClient {
	buf := &bytes.Buffer{}
	c := &Client{
		UserID: userID,
		DeviceID: deviceID,
		Encoder:  protocol.NewEncoder(buf),
	}
	return &captureClient{Client: c, buf: buf}
}

func TestListDevices_EmptyForNewUser(t *testing.T) {
	s := newTestServer(t)
	// Register alice's first device
	if _, err := s.store.UpsertDevice("alice", "dev_alice_1"); err != nil {
		t.Fatalf("register device: %v", err)
	}

	cc := testClientFor("alice", "dev_alice_1")
	s.handleListDevices(cc.Client, nil)

	msgs := cc.messages()
	if len(msgs) != 1 {
		t.Fatalf("expected 1 message, got %d", len(msgs))
	}
	var list protocol.DeviceList
	if err := json.Unmarshal(msgs[0], &list); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if list.Type != "device_list" {
		t.Errorf("type = %q", list.Type)
	}
	if len(list.Devices) != 1 {
		t.Fatalf("expected 1 device, got %d", len(list.Devices))
	}
	if list.Devices[0].DeviceID != "dev_alice_1" {
		t.Errorf("device_id = %q", list.Devices[0].DeviceID)
	}
	if !list.Devices[0].Current {
		t.Error("alice's dev_alice_1 should be marked current")
	}
}

func TestListDevices_MultipleDevicesCurrentFlag(t *testing.T) {
	s := newTestServer(t)
	s.store.UpsertDevice("alice", "dev_laptop")
	s.store.UpsertDevice("alice", "dev_phone")
	s.store.UpsertDevice("alice", "dev_desktop")

	cc := testClientFor("alice", "dev_phone")
	s.handleListDevices(cc.Client, nil)

	var list protocol.DeviceList
	json.Unmarshal(cc.messages()[0], &list)
	if len(list.Devices) != 3 {
		t.Fatalf("expected 3 devices, got %d", len(list.Devices))
	}
	currentCount := 0
	for _, d := range list.Devices {
		if d.Current {
			currentCount++
			if d.DeviceID != "dev_phone" {
				t.Errorf("current flag on wrong device: %s", d.DeviceID)
			}
		}
	}
	if currentCount != 1 {
		t.Errorf("exactly one device should be current, got %d", currentCount)
	}
}

func TestListDevices_IncludesRevokedFlag(t *testing.T) {
	s := newTestServer(t)
	s.store.UpsertDevice("alice", "dev_a")
	s.store.UpsertDevice("alice", "dev_b")
	// Revoke dev_b
	s.store.RevokeDevice("alice", "dev_b", "test")

	cc := testClientFor("alice", "dev_a")
	s.handleListDevices(cc.Client, nil)

	var list protocol.DeviceList
	json.Unmarshal(cc.messages()[0], &list)
	for _, d := range list.Devices {
		if d.DeviceID == "dev_b" && !d.Revoked {
			t.Error("dev_b should be marked revoked")
		}
		if d.DeviceID == "dev_a" && d.Revoked {
			t.Error("dev_a should NOT be marked revoked")
		}
	}
}

func TestListDevices_OnlyUserOwnDevices(t *testing.T) {
	s := newTestServer(t)
	s.store.UpsertDevice("alice", "dev_alice_1")
	s.store.UpsertDevice("bob", "dev_bob_1")
	s.store.UpsertDevice("bob", "dev_bob_2")

	cc := testClientFor("alice", "dev_alice_1")
	s.handleListDevices(cc.Client, nil)

	var list protocol.DeviceList
	json.Unmarshal(cc.messages()[0], &list)
	if len(list.Devices) != 1 {
		t.Errorf("alice should see only her devices, got %d", len(list.Devices))
	}
	for _, d := range list.Devices {
		if d.DeviceID != "dev_alice_1" {
			t.Errorf("alice seeing foreign device: %s", d.DeviceID)
		}
	}
}

func TestRevokeDevice_Success(t *testing.T) {
	s := newTestServer(t)
	s.store.UpsertDevice("alice", "dev_a")
	s.store.UpsertDevice("alice", "dev_b")

	cc := testClientFor("alice", "dev_a")
	raw := json.RawMessage(`{"type":"revoke_device","device_id":"dev_b"}`)
	s.handleRevokeDevice(cc.Client, raw)

	// Check response
	var result protocol.DeviceRevokeResult
	json.Unmarshal(cc.messages()[0], &result)
	if !result.Success {
		t.Errorf("expected success, got error: %q", result.Error)
	}
	if result.DeviceID != "dev_b" {
		t.Errorf("result.device_id = %q", result.DeviceID)
	}

	// Confirm revoked in store
	revoked, err := s.store.IsDeviceRevoked("alice", "dev_b")
	if err != nil {
		t.Fatalf("IsDeviceRevoked: %v", err)
	}
	if !revoked {
		t.Error("dev_b should be revoked in store")
	}
}

func TestRevokeDevice_RejectsForeignDevice(t *testing.T) {
	// Alice tries to revoke bob's device — should fail.
	s := newTestServer(t)
	s.store.UpsertDevice("alice", "dev_a")
	s.store.UpsertDevice("bob", "dev_b")

	cc := testClientFor("alice", "dev_a")
	raw := json.RawMessage(`{"type":"revoke_device","device_id":"dev_b"}`)
	s.handleRevokeDevice(cc.Client, raw)

	var result protocol.DeviceRevokeResult
	json.Unmarshal(cc.messages()[0], &result)
	if result.Success {
		t.Error("alice should not be able to revoke bob's device")
	}
	if result.Error == "" {
		t.Error("expected error message")
	}

	// Confirm NOT revoked
	revoked, _ := s.store.IsDeviceRevoked("bob", "dev_b")
	if revoked {
		t.Error("bob's device should not be revoked")
	}
}

func TestRevokeDevice_EmptyDeviceID(t *testing.T) {
	s := newTestServer(t)
	cc := testClientFor("alice", "dev_a")
	raw := json.RawMessage(`{"type":"revoke_device","device_id":""}`)
	s.handleRevokeDevice(cc.Client, raw)

	var result protocol.DeviceRevokeResult
	json.Unmarshal(cc.messages()[0], &result)
	if result.Success {
		t.Error("empty device_id should fail")
	}
}

func TestRevokeDevice_Malformed(t *testing.T) {
	s := newTestServer(t)
	cc := testClientFor("alice", "dev_a")
	raw := json.RawMessage(`{"type":"revoke_device","device_id":`)
	s.handleRevokeDevice(cc.Client, raw)

	// Should emit an error message (not a DeviceRevokeResult)
	var errMsg protocol.Error
	json.Unmarshal(cc.messages()[0], &errMsg)
	if errMsg.Code == "" {
		t.Error("malformed message should produce error")
	}
}

func TestRevokeDevice_SelfRevocationAllowed(t *testing.T) {
	// A user can revoke their own current device.
	s := newTestServer(t)
	s.store.UpsertDevice("alice", "dev_a")

	cc := testClientFor("alice", "dev_a")
	raw := json.RawMessage(`{"type":"revoke_device","device_id":"dev_a"}`)
	s.handleRevokeDevice(cc.Client, raw)

	var result protocol.DeviceRevokeResult
	json.Unmarshal(cc.messages()[0], &result)
	if !result.Success {
		t.Errorf("self-revocation should succeed, got: %q", result.Error)
	}

	revoked, _ := s.store.IsDeviceRevoked("alice", "dev_a")
	if !revoked {
		t.Error("current device should be revoked")
	}
}

func TestRevokeDevice_NonExistentDevice(t *testing.T) {
	s := newTestServer(t)
	s.store.UpsertDevice("alice", "dev_a")

	cc := testClientFor("alice", "dev_a")
	raw := json.RawMessage(`{"type":"revoke_device","device_id":"dev_never_registered"}`)
	s.handleRevokeDevice(cc.Client, raw)

	var result protocol.DeviceRevokeResult
	json.Unmarshal(cc.messages()[0], &result)
	if result.Success {
		t.Error("revoking non-existent device should fail")
	}
}
