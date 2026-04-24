package server

// Phase 17c Step 4 — Category B state-fix push.
//
// When a client receives an `invalid_epoch` error (Category B), the
// server preemptively pushes the fresh state the client needs to
// retry successfully. For invalid_epoch this means sending a fresh
// epoch_key for the affected room; the client applies it and resends
// the original payload with the correct epoch.
//
// Without this, a client that's one epoch behind (common case: they
// were offline during a rotation) would receive invalid_epoch, have
// no way to discover the current epoch, and either wait for a
// broadcast or reconnect. Category B is the "self-healing without
// client guesswork" design — server provides the fix alongside the
// error.
//
// Throttle: per-(deviceID, verb) 1-second TTL. A client spamming
// invalid_epoch cannot force 1000 epoch_key pushes per second — the
// first push goes through, subsequent ones within 1s are no-ops.
// Client's retry logic (max-N budget) applies the already-received
// push.

import (
	"time"

	"github.com/brushtailmedia/sshkey-chat/internal/protocol"
)

// stateFixTTL is the minimum gap between state-fix pushes for the
// same (deviceID, verb) pair. Client retry is expected to complete
// within this window; a second push before the client has a chance
// to re-try with the first is pure bandwidth.
const stateFixTTL = 1 * time.Second

// stateFixAllowed returns true if the (deviceID, verb) pair has not
// received a state-fix push in the past stateFixTTL. Stamps the
// current time on success so subsequent calls within the window
// return false.
func (s *Server) stateFixAllowed(deviceID, verb string) bool {
	if deviceID == "" {
		return false
	}
	key := deviceID + ":" + verb
	now := time.Now().Unix()
	s.stateFixMu.Lock()
	defer s.stateFixMu.Unlock()
	if last, ok := s.stateFixLast[key]; ok && now-last < int64(stateFixTTL.Seconds()) {
		return false
	}
	s.stateFixLast[key] = now
	return true
}

// pushEpochKeyFix sends a fresh epoch_key for roomID to the client
// caller, in response to an invalid_epoch rejection. Called AFTER
// respondError — the client receives the typed error first, then the
// state-fix push, and can apply the push on next resend.
//
// Throttled per (deviceID, verb). If the throttle denies the push,
// the call is a no-op.
//
// Called from every site that returns invalid_epoch. See handleSend
// in session.go for the canonical call pattern.
func (s *Server) pushEpochKeyFix(c *Client, verb, roomID string) {
	if c == nil || s.store == nil {
		return
	}
	if !s.stateFixAllowed(c.DeviceID, verb) {
		return
	}
	epoch := s.epochs.currentEpochNum(roomID)
	if epoch == 0 {
		return
	}
	wrappedKey, err := s.store.GetEpochKey(roomID, epoch, c.UserID)
	if err != nil || wrappedKey == "" {
		return
	}
	// Send directly via the client's encoder (the client expects
	// this outside of the error response envelope). Error is
	// intentionally swallowed — if the write fails, the client is
	// disconnecting and the push is moot.
	_ = c.Encoder.Encode(protocol.EpochKey{
		Type:       "epoch_key",
		Room:       roomID,
		Epoch:      epoch,
		WrappedKey: wrappedKey,
	})
}
