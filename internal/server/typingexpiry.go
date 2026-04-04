package server

import (
	"sync"
	"time"
)

// typingTracker tracks active typing indicators and expires them after 5 seconds.
type typingTracker struct {
	mu      sync.Mutex
	timers  map[string]*time.Timer // "user:room_or_conv" -> expiry timer
	onExpire func(user, room, conversation string)
}

func newTypingTracker(onExpire func(user, room, conversation string)) *typingTracker {
	return &typingTracker{
		timers:   make(map[string]*time.Timer),
		onExpire: onExpire,
	}
}

// Touch resets the typing expiry for a user in a room or conversation.
func (t *typingTracker) Touch(user, room, conversation string) {
	key := user + ":" + room + conversation

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
			t.onExpire(user, room, conversation)
		}
	})
}

// Remove cancels a typing timer (e.g., when user sends a message).
func (t *typingTracker) Remove(user, room, conversation string) {
	key := user + ":" + room + conversation

	t.mu.Lock()
	defer t.mu.Unlock()

	if timer, ok := t.timers[key]; ok {
		timer.Stop()
		delete(t.timers, key)
	}
}
