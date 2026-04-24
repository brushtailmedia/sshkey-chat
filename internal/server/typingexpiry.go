package server

import (
	"sync"
	"time"
)

// typingTracker tracks active typing indicators and expires them after 5 seconds.
type typingTracker struct {
	mu       sync.Mutex
	timers   map[string]*time.Timer // "user:room_or_group" -> expiry timer
	onExpire func(user, roomID, groupID string)
}

func newTypingTracker(onExpire func(user, roomID, groupID string)) *typingTracker {
	return &typingTracker{
		timers:   make(map[string]*time.Timer),
		onExpire: onExpire,
	}
}

// Touch resets the typing expiry for a user in a room or group DM.
func (t *typingTracker) Touch(user, roomID, groupID string) {
	key := user + ":" + roomID + groupID

	t.mu.Lock()
	defer t.mu.Unlock()

	if timer, ok := t.timers[key]; ok {
		timer.Reset(5 * time.Second)
		return
	}

	t.timers[key] = time.AfterFunc(5*time.Second, func() {
		t.mu.Lock()
		delete(t.timers, key)
		t.mu.Unlock()

		if t.onExpire != nil {
			t.onExpire(user, roomID, groupID)
		}
	})
}

// Remove cancels a typing timer (e.g., when user sends a message).
func (t *typingTracker) Remove(user, roomID, groupID string) {
	key := user + ":" + roomID + groupID

	t.mu.Lock()
	defer t.mu.Unlock()

	if timer, ok := t.timers[key]; ok {
		timer.Stop()
		delete(t.timers, key)
	}
}
