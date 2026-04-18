package server

import (
	"encoding/json"

	"github.com/brushtailmedia/sshkey-chat/internal/counters"
	"github.com/brushtailmedia/sshkey-chat/internal/protocol"
)

// handleListDevices returns the list of devices registered for the
// authenticated user. Revocation status is included so the UI can render
// previously-revoked devices separately.
func (s *Server) handleListDevices(c *Client, raw json.RawMessage) {
	if s.store == nil {
		c.Encoder.Encode(protocol.Error{
			Type:    "error",
			Code:    "internal",
			Message: "storage not available",
		})
		return
	}

	devices, err := s.store.GetDevices(c.UserID)
	if err != nil {
		s.logger.Error("list_devices: failed to fetch devices", "user", c.UserID, "error", err)
		c.Encoder.Encode(protocol.Error{
			Type:    "error",
			Code:    "internal",
			Message: "failed to list devices",
		})
		return
	}

	var out []protocol.DeviceInfo
	for _, d := range devices {
		revoked, _ := s.store.IsDeviceRevoked(c.UserID, d.DeviceID)
		out = append(out, protocol.DeviceInfo{
			DeviceID:     d.DeviceID,
			LastSyncedAt: d.LastSynced,
			CreatedAt:    d.CreatedAt,
			Current:      d.DeviceID == c.DeviceID,
			Revoked:      revoked,
		})
	}

	c.Encoder.Encode(protocol.DeviceList{
		Type:    "device_list",
		Devices: out,
	})
}

// handleRevokeDevice processes a user-initiated revocation of one of their
// own devices. The revoked device is disconnected (if connected) and will
// be rejected on future connection attempts.
//
// Security: the device_id MUST belong to the authenticated user. Users
// cannot revoke devices owned by other users — for that, the admin uses
// sshkey-ctl revoke-device.
//
// A user is allowed to revoke their current device (self-revocation) — the
// server will disconnect them after processing.
func (s *Server) handleRevokeDevice(c *Client, raw json.RawMessage) {
	var msg protocol.RevokeDevice
	if err := json.Unmarshal(raw, &msg); err != nil {
		s.rejectAndLog(c, counters.SignalMalformedFrame, "revoke_device", "malformed revoke_device frame",
			&protocol.Error{
				Type:    "error",
				Code:    "invalid_message",
				Message: "malformed revoke_device",
			})
		return
	}

	if s.store == nil {
		c.Encoder.Encode(protocol.DeviceRevokeResult{
			Type:     "device_revoke_result",
			DeviceID: msg.DeviceID,
			Success:  false,
			Error:    "storage not available",
		})
		return
	}

	if msg.DeviceID == "" {
		c.Encoder.Encode(protocol.DeviceRevokeResult{
			Type:     "device_revoke_result",
			DeviceID: msg.DeviceID,
			Success:  false,
			Error:    "device_id required",
		})
		return
	}

	// Verify the device belongs to this user
	devices, err := s.store.GetDevices(c.UserID)
	if err != nil {
		s.logger.Error("revoke_device: fetch devices", "user", c.UserID, "error", err)
		c.Encoder.Encode(protocol.DeviceRevokeResult{
			Type:     "device_revoke_result",
			DeviceID: msg.DeviceID,
			Success:  false,
			Error:    "internal error",
		})
		return
	}
	owned := false
	for _, d := range devices {
		if d.DeviceID == msg.DeviceID {
			owned = true
			break
		}
	}
	if !owned {
		s.logger.Warn("revoke_device: device not owned by user",
			"user", c.UserID,
			"target_device", msg.DeviceID,
			"requesting_device", c.DeviceID,
		)
		c.Encoder.Encode(protocol.DeviceRevokeResult{
			Type:     "device_revoke_result",
			DeviceID: msg.DeviceID,
			Success:  false,
			Error:    "device not registered to your account",
		})
		return
	}

	// Mark revoked
	if err := s.store.RevokeDevice(c.UserID, msg.DeviceID, "self_revoke"); err != nil {
		s.logger.Error("revoke_device: store", "user", c.UserID, "target", msg.DeviceID, "error", err)
		c.Encoder.Encode(protocol.DeviceRevokeResult{
			Type:     "device_revoke_result",
			DeviceID: msg.DeviceID,
			Success:  false,
			Error:    "internal error",
		})
		return
	}

	// Audit log
	if s.audit != nil {
		s.audit.Log("user", "self_revoke_device",
			"user="+c.UserID+" target_device="+msg.DeviceID+" requesting_device="+c.DeviceID)
	}

	s.logger.Info("device revoked (user-initiated)",
		"user", c.UserID,
		"target_device", msg.DeviceID,
		"requesting_device", c.DeviceID,
	)

	// Notify the requesting client of success
	c.Encoder.Encode(protocol.DeviceRevokeResult{
		Type:     "device_revoke_result",
		DeviceID: msg.DeviceID,
		Success:  true,
	})

	// If the revoked device is connected, notify + disconnect it.
	s.kickRevokedDeviceSession(c.UserID, msg.DeviceID, "self_revoke")
}

// kickRevokedDeviceSession finds any connected client whose UserID +
// DeviceID match the revoked device, sends them a device_revoked
// event so the TUI can show a notice before disconnect, and closes
// the SSH channel to terminate the session.
//
// Idempotent: if no matching client is connected, this is a no-op.
//
// Phase 16 Gap 1 extracted this loop from handleRevokeDevice so the
// CLI-side processor (processPendingDeviceRevocations) could reuse
// it. Both the protocol-path handler (user-initiated self-revoke)
// and the queue-path processor (admin-initiated revoke via
// sshkey-ctl) should produce identical session-termination effects;
// sharing the helper enforces that by construction.
func (s *Server) kickRevokedDeviceSession(userID, deviceID, reason string) {
	// Phase 17 Step 3: lock-release pattern. Encode via fanOut outside the
	// lock, then iterate targets to call Channel.Close().
	s.mu.RLock()
	var targets []*Client
	for _, client := range s.clients {
		if client.UserID == userID && client.DeviceID == deviceID {
			targets = append(targets, client)
		}
	}
	s.mu.RUnlock()

	revoked := protocol.DeviceRevoked{
		Type:     "device_revoked",
		DeviceID: deviceID,
		Reason:   reason,
	}
	s.fanOut("device_revoked", revoked, targets)
	for _, client := range targets {
		client.Channel.Close()
	}
}
