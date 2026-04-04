package server

import (
	"encoding/json"

	"github.com/brushtailmedia/sshkey/internal/protocol"
)

// handleKeyRotate processes a key_rotate request.
// The client connects with their OLD key and requests rotation to a new key.
func (s *Server) handleKeyRotate(c *Client, raw json.RawMessage) {
	var msg protocol.KeyRotate
	if err := json.Unmarshal(raw, &msg); err != nil {
		c.Encoder.Encode(protocol.Error{Type: "error", Code: "invalid_message", Message: "malformed key_rotate"})
		return
	}

	if s.store == nil {
		c.Encoder.Encode(protocol.Error{Type: "error", Code: "internal", Message: "storage not available"})
		return
	}

	// Validate the new key is Ed25519
	if len(msg.NewPubKey) < 11 || msg.NewPubKey[:11] != "ssh-ed25519" {
		c.Encoder.Encode(protocol.Error{
			Type:    "error",
			Code:    "invalid_key",
			Message: "Only Ed25519 keys are supported",
		})
		return
	}

	// Gather all wrapped epoch keys for this user
	keys, err := s.store.GetAllEpochKeysForUser(c.Username)
	if err != nil {
		s.logger.Error("key rotate: failed to get epoch keys", "user", c.Username, "error", err)
		c.Encoder.Encode(protocol.Error{Type: "error", Code: "internal", Message: "failed to retrieve epoch keys"})
		return
	}

	var items []protocol.KeyRotateItem
	for _, k := range keys {
		items = append(items, protocol.KeyRotateItem{
			Room:       k.Room,
			Epoch:      k.Epoch,
			WrappedKey: k.WrappedKey,
		})
	}

	s.logger.Info("key rotation started",
		"user", c.Username,
		"epoch_keys", len(items),
	)

	// Send all wrapped keys to the client for re-wrapping
	c.Encoder.Encode(protocol.KeyRotateKeys{
		Type: "key_rotate_keys",
		Keys: items,
	})
}

// handleKeyRotateComplete processes the re-wrapped keys from the client.
func (s *Server) handleKeyRotateComplete(c *Client, raw json.RawMessage) {
	var msg protocol.KeyRotateComplete
	if err := json.Unmarshal(raw, &msg); err != nil {
		c.Encoder.Encode(protocol.Error{Type: "error", Code: "invalid_message", Message: "malformed key_rotate_complete"})
		return
	}

	if s.store == nil {
		return
	}

	// Store re-wrapped keys
	for _, k := range msg.Keys {
		if err := s.store.StoreEpochKey(k.Room, k.Epoch, c.Username, k.WrappedKey); err != nil {
			s.logger.Error("key rotate: failed to store re-wrapped key",
				"user", c.Username, "room", k.Room, "epoch", k.Epoch, "error", err)
		}
	}

	// Update the user's public key in config
	s.cfg.Lock()
	user := s.cfg.Users[c.Username]
	user.Key = msg.NewPubKey
	s.cfg.Users[c.Username] = user
	s.cfg.Unlock()

	// TODO: persist key change to users.toml on disk

	s.logger.Info("key rotation complete",
		"user", c.Username,
		"re_wrapped", len(msg.Keys),
	)

	// Disconnect the client -- they must reconnect with the new key
	c.Encoder.Encode(protocol.Error{
		Type:    "error",
		Code:    "key_rotated",
		Message: "Key rotation complete. Reconnect with your new key.",
	})
	c.Channel.Close()
}
