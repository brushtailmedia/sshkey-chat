package server

import (
	"encoding/json"
	"sync"
	"time"

	"github.com/brushtailmedia/sshkey-chat/internal/protocol"
)

// roomEpochState tracks epoch rotation state for a single room.
type roomEpochState struct {
	currentEpoch    int64     // latest confirmed epoch
	confirmedEpoch  int64     // epoch that has been confirmed and distributed (messages allowed)
	messageCount    int64     // messages since last rotation
	lastRotation    time.Time // time of last rotation
	pendingRotation bool      // rotation in progress
	pendingEpoch    int64     // the epoch being rotated to
	pendingTimer    *time.Timer // 5s timeout for pending rotation
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
func (em *epochManager) getOrCreate(roomID string, currentEpoch int64) *roomEpochState {
	em.mu.Lock()
	defer em.mu.Unlock()

	state, ok := em.rooms[roomID]
	if !ok {
		state = &roomEpochState{
			currentEpoch:   currentEpoch,
			confirmedEpoch: currentEpoch,
			lastRotation:   time.Now(),
		}
		em.rooms[roomID] = state
	}
	return state
}

// recordMessage increments the message count and returns true if rotation should be triggered.
func (em *epochManager) recordMessage(roomID string) bool {
	em.mu.Lock()
	defer em.mu.Unlock()

	state, ok := em.rooms[roomID]
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
// onTimeout is called if the rotation isn't completed within 5 seconds.
func (em *epochManager) startRotation(roomID string, onTimeout func()) int64 {
	em.mu.Lock()
	defer em.mu.Unlock()

	state := em.rooms[roomID]
	if state == nil {
		return 0
	}

	// Cancel any existing timeout
	if state.pendingTimer != nil {
		state.pendingTimer.Stop()
	}

	state.pendingRotation = true
	state.pendingEpoch = state.currentEpoch + 1

	// Start 5-second timeout — if rotation isn't completed, cancel and let next sender retry
	if onTimeout != nil {
		state.pendingTimer = time.AfterFunc(5*time.Second, func() {
			em.mu.Lock()
			if state.pendingRotation && state.pendingEpoch == state.currentEpoch+1 {
				state.pendingRotation = false
				state.pendingEpoch = 0
				state.pendingTimer = nil
			}
			em.mu.Unlock()
			onTimeout()
		})
	}

	return state.pendingEpoch
}

// completeRotation marks the rotation as done and advances the epoch.
func (em *epochManager) completeRotation(roomID string, epoch int64) bool {
	em.mu.Lock()
	defer em.mu.Unlock()

	state := em.rooms[roomID]
	if state == nil || !state.pendingRotation || state.pendingEpoch != epoch {
		return false
	}

	if state.pendingTimer != nil {
		state.pendingTimer.Stop()
		state.pendingTimer = nil
	}

	state.currentEpoch = epoch
	state.confirmedEpoch = epoch
	state.pendingRotation = false
	state.pendingEpoch = 0
	state.messageCount = 0
	state.lastRotation = time.Now()
	return true
}

// cancelRotation cancels a pending rotation (e.g., stale member list).
func (em *epochManager) cancelRotation(roomID string) {
	em.mu.Lock()
	defer em.mu.Unlock()

	state := em.rooms[roomID]
	if state != nil {
		if state.pendingTimer != nil {
			state.pendingTimer.Stop()
			state.pendingTimer = nil
		}
		state.pendingRotation = false
		state.pendingEpoch = 0
	}
}

// currentEpoch returns the current epoch for a room.
func (em *epochManager) currentEpochNum(roomID string) int64 {
	em.mu.Lock()
	defer em.mu.Unlock()

	state := em.rooms[roomID]
	if state == nil {
		return 0
	}
	return state.currentEpoch
}

// confirmedEpochNum returns the confirmed (distributable) epoch for a room.
// Messages with epoch > confirmedEpoch are rejected.
func (em *epochManager) confirmedEpochNum(roomID string) int64 {
	em.mu.Lock()
	defer em.mu.Unlock()

	state := em.rooms[roomID]
	if state == nil {
		return 0
	}
	return state.confirmedEpoch
}

// sendEpochKeys sends the current epoch key for each room to a connecting client.
func (s *Server) sendEpochKeys(c *Client) {
	if s.store == nil {
		return
	}

	rooms := s.store.GetUserRoomIDs(c.UserID)

	for _, roomID := range rooms {
		epoch := s.epochs.currentEpochNum(roomID)
		if epoch == 0 {
			// Try to load from DB
			dbEpoch, err := s.store.GetCurrentEpoch(roomID)
			if err == nil && dbEpoch > 0 {
				epoch = dbEpoch
				s.epochs.getOrCreate(roomID, epoch)
			}
		}
		if epoch == 0 {
			// Fresh room with no epoch — mark for initial rotation after message loop starts.
			// Don't trigger here — the message loop hasn't started yet, so the client
			// can't respond to epoch_trigger. Store a flag and trigger on first message.
			s.epochs.getOrCreate(roomID, 0)
			continue
		}

		wrappedKey, err := s.store.GetEpochKey(roomID, epoch, c.UserID)
		if err != nil {
			continue // no key for this user (new member, needs rotation)
		}

		c.Encoder.Encode(protocol.EpochKey{
			Type:       "epoch_key",
			Room:       roomID,
			Epoch:      epoch,
			WrappedKey: wrappedKey,
		})
	}
}

// triggerEpochRotation sends an epoch_trigger to a client and handles the response.
func (s *Server) triggerEpochRotation(c *Client, roomID string, reason string) {
	newEpoch := s.epochs.startRotation(roomID, func() {
		// Timeout callback — rotation wasn't completed in 5 seconds.
		// Cancel and let the next sender pick it up via checkRotationNeeded.
		s.logger.Warn("epoch rotation timed out",
			"room", roomID,
			"triggered_by", c.UserID,
			"trigger", reason,
		)
	})
	if newEpoch == 0 {
		return
	}

	// Build member list with public keys
	memberIDs := s.store.GetRoomMemberIDsByRoomID(roomID)
	var members []protocol.MemberKey
	for _, uid := range memberIDs {
		if key := s.store.GetUserKey(uid); key != "" {
			members = append(members, protocol.MemberKey{
				User:   uid,
				PubKey: key,
			})
		}
	}

	s.logger.Info("epoch trigger",
		"room", roomID,
		"new_epoch", newEpoch,
		"triggered_by", c.UserID,
		"trigger", reason,
		"members", len(members),
	)

	c.Encoder.Encode(protocol.EpochTrigger{
		Type:     "epoch_trigger",
		Room:     roomID,
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
			Message: "Conflict detected — please try again",
		})
		return
	}
	s.epochs.mu.Unlock()

	// Validate member list hasn't changed (compare member_hash)
	currentMembers := s.store.GetRoomMemberIDsByRoomID(msg.Room)

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
	for userID, wrappedKey := range msg.WrappedKeys {
		if err := s.store.StoreEpochKey(msg.Room, msg.Epoch, userID, wrappedKey); err != nil {
			s.logger.Error("failed to store epoch key",
				"room", msg.Room, "epoch", msg.Epoch, "user", userID, "error", err)
		}
	}

	// Complete the rotation
	if !s.epochs.completeRotation(msg.Room, msg.Epoch) {
		c.Encoder.Encode(protocol.Error{
			Type:    "error",
			Code:    protocol.ErrEpochConflict,
			Message: "Conflict detected — please try again",
		})
		return
	}

	s.logger.Info("epoch rotation complete",
		"room", msg.Room,
		"epoch", msg.Epoch,
		"rotated_by", c.UserID,
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
		wrappedKey, ok := msg.WrappedKeys[client.UserID]
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
func (s *Server) checkRotationNeeded(c *Client, roomID string) {
	if s.epochs.recordMessage(roomID) {
		s.triggerEpochRotation(c, roomID, "message_count")
	}
}
