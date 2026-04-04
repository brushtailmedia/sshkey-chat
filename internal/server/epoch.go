package server

import (
	"encoding/json"
	"sync"
	"time"

	"github.com/brushtailmedia/sshkey/internal/protocol"
)

// roomEpochState tracks epoch rotation state for a single room.
type roomEpochState struct {
	currentEpoch    int64
	messageCount    int64     // messages since last rotation
	lastRotation    time.Time // time of last rotation
	pendingRotation bool      // rotation in progress
	pendingEpoch    int64     // the epoch being rotated to
}

// epochManager manages epoch state for all rooms.
type epochManager struct {
	mu    sync.Mutex
	rooms map[string]*roomEpochState

	// Rotation thresholds (from config)
	maxMessages int64
	maxDuration time.Duration
}

func newEpochManager() *epochManager {
	return &epochManager{
		rooms:       make(map[string]*roomEpochState),
		maxMessages: 100,
		maxDuration: time.Hour,
	}
}

// getOrCreate returns the epoch state for a room, creating if needed.
func (em *epochManager) getOrCreate(room string, currentEpoch int64) *roomEpochState {
	em.mu.Lock()
	defer em.mu.Unlock()

	state, ok := em.rooms[room]
	if !ok {
		state = &roomEpochState{
			currentEpoch: currentEpoch,
			lastRotation: time.Now(),
		}
		em.rooms[room] = state
	}
	return state
}

// recordMessage increments the message count and returns true if rotation should be triggered.
func (em *epochManager) recordMessage(room string) bool {
	em.mu.Lock()
	defer em.mu.Unlock()

	state, ok := em.rooms[room]
	if !ok {
		return false
	}

	if state.pendingRotation {
		return false // already rotating
	}

	state.messageCount++

	if state.messageCount >= em.maxMessages {
		return true
	}
	if time.Since(state.lastRotation) >= em.maxDuration {
		return true
	}
	return false
}

// startRotation marks a rotation as pending. Returns the new epoch number.
func (em *epochManager) startRotation(room string) int64 {
	em.mu.Lock()
	defer em.mu.Unlock()

	state := em.rooms[room]
	if state == nil {
		return 0
	}

	state.pendingRotation = true
	state.pendingEpoch = state.currentEpoch + 1
	return state.pendingEpoch
}

// completeRotation marks the rotation as done and advances the epoch.
func (em *epochManager) completeRotation(room string, epoch int64) bool {
	em.mu.Lock()
	defer em.mu.Unlock()

	state := em.rooms[room]
	if state == nil || !state.pendingRotation || state.pendingEpoch != epoch {
		return false
	}

	state.currentEpoch = epoch
	state.pendingRotation = false
	state.pendingEpoch = 0
	state.messageCount = 0
	state.lastRotation = time.Now()
	return true
}

// cancelRotation cancels a pending rotation (e.g., stale member list).
func (em *epochManager) cancelRotation(room string) {
	em.mu.Lock()
	defer em.mu.Unlock()

	state := em.rooms[room]
	if state != nil {
		state.pendingRotation = false
		state.pendingEpoch = 0
	}
}

// currentEpoch returns the current epoch for a room.
func (em *epochManager) currentEpochNum(room string) int64 {
	em.mu.Lock()
	defer em.mu.Unlock()

	state := em.rooms[room]
	if state == nil {
		return 0
	}
	return state.currentEpoch
}

// sendEpochKeys sends the current epoch key for each room to a connecting client.
func (s *Server) sendEpochKeys(c *Client) {
	if s.store == nil {
		return
	}

	s.cfg.RLock()
	rooms := s.cfg.Users[c.Username].Rooms
	s.cfg.RUnlock()

	for _, room := range rooms {
		epoch := s.epochs.currentEpochNum(room)
		if epoch == 0 {
			// Try to load from DB
			dbEpoch, err := s.store.GetCurrentEpoch(room)
			if err == nil && dbEpoch > 0 {
				epoch = dbEpoch
				s.epochs.getOrCreate(room, epoch)
			}
		}
		if epoch == 0 {
			continue // no epoch keys yet
		}

		wrappedKey, err := s.store.GetEpochKey(room, epoch, c.Username)
		if err != nil {
			continue // no key for this user (new member, needs rotation)
		}

		c.Encoder.Encode(protocol.EpochKey{
			Type:       "epoch_key",
			Room:       room,
			Epoch:      epoch,
			WrappedKey: wrappedKey,
		})
	}
}

// triggerEpochRotation sends an epoch_trigger to a client and handles the response.
func (s *Server) triggerEpochRotation(c *Client, room string, reason string) {
	newEpoch := s.epochs.startRotation(room)
	if newEpoch == 0 {
		return
	}

	// Build member list with public keys
	s.cfg.RLock()
	var members []protocol.MemberKey
	for username, user := range s.cfg.Users {
		for _, r := range user.Rooms {
			if r == room {
				members = append(members, protocol.MemberKey{
					User:   username,
					PubKey: user.Key,
				})
				break
			}
		}
	}
	s.cfg.RUnlock()

	s.logger.Info("epoch trigger",
		"room", room,
		"new_epoch", newEpoch,
		"triggered_by", c.Username,
		"trigger", reason,
		"members", len(members),
	)

	c.Encoder.Encode(protocol.EpochTrigger{
		Type:     "epoch_trigger",
		Room:     room,
		NewEpoch: newEpoch,
		Members:  members,
	})
}

// handleEpochRotate processes an epoch_rotate message from a client.
func (s *Server) handleEpochRotate(c *Client, raw json.RawMessage) {
	var msg protocol.EpochRotate
	if err := json.Unmarshal(raw, &msg); err != nil {
		c.Encoder.Encode(protocol.Error{Type: "error", Code: "invalid_message", Message: "malformed epoch_rotate"})
		return
	}

	// Validate epoch number matches pending
	s.epochs.mu.Lock()
	state := s.epochs.rooms[msg.Room]
	if state == nil || !state.pendingRotation || state.pendingEpoch != msg.Epoch {
		s.epochs.mu.Unlock()
		c.Encoder.Encode(protocol.Error{
			Type:    "error",
			Code:    protocol.ErrEpochConflict,
			Message: "Epoch rotation conflict or no pending rotation",
		})
		return
	}
	s.epochs.mu.Unlock()

	// Validate member list hasn't changed (compare member_hash)
	s.cfg.RLock()
	var currentMembers []string
	for username, user := range s.cfg.Users {
		for _, r := range user.Rooms {
			if r == msg.Room {
				currentMembers = append(currentMembers, username)
				break
			}
		}
	}
	s.cfg.RUnlock()

	// Check that wrapped_keys covers exactly the current member set
	wrappedSet := make(map[string]bool, len(msg.WrappedKeys))
	for k := range msg.WrappedKeys {
		wrappedSet[k] = true
	}
	for _, m := range currentMembers {
		if !wrappedSet[m] {
			s.epochs.cancelRotation(msg.Room)
			c.Encoder.Encode(protocol.Error{
				Type:    "error",
				Code:    protocol.ErrStaleMemberList,
				Message: "Member list changed during rotation",
			})
			// Re-trigger with updated member list
			s.triggerEpochRotation(c, msg.Room, "stale_member_list_retry")
			return
		}
	}

	// Store wrapped keys for all members
	for username, wrappedKey := range msg.WrappedKeys {
		if err := s.store.StoreEpochKey(msg.Room, msg.Epoch, username, wrappedKey); err != nil {
			s.logger.Error("failed to store epoch key",
				"room", msg.Room, "epoch", msg.Epoch, "user", username, "error", err)
		}
	}

	// Complete the rotation
	if !s.epochs.completeRotation(msg.Room, msg.Epoch) {
		c.Encoder.Encode(protocol.Error{
			Type:    "error",
			Code:    protocol.ErrEpochConflict,
			Message: "Epoch rotation could not be completed",
		})
		return
	}

	s.logger.Info("epoch rotation complete",
		"room", msg.Room,
		"epoch", msg.Epoch,
		"rotated_by", c.Username,
		"members", len(msg.WrappedKeys),
	)

	// Send epoch_confirmed to the rotating client
	c.Encoder.Encode(protocol.EpochConfirmed{
		Type:  "epoch_confirmed",
		Room:  msg.Room,
		Epoch: msg.Epoch,
	})

	// Distribute epoch keys to all other online members
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, client := range s.clients {
		if client.DeviceID == c.DeviceID {
			continue // already sent epoch_confirmed
		}
		wrappedKey, ok := msg.WrappedKeys[client.Username]
		if !ok {
			continue // not in this room
		}
		client.Encoder.Encode(protocol.EpochKey{
			Type:       "epoch_key",
			Room:       msg.Room,
			Epoch:      msg.Epoch,
			WrappedKey: wrappedKey,
		})
	}
}

// checkRotationNeeded checks if a room message should trigger epoch rotation.
func (s *Server) checkRotationNeeded(c *Client, room string) {
	if s.epochs.recordMessage(room) {
		s.triggerEpochRotation(c, room, "message_count")
	}
}
