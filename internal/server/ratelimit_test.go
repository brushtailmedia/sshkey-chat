package server

import (
	"testing"
)

func TestRateLimiter_AllowBasic(t *testing.T) {
	rl := newRateLimiter()

	// 5 per second — initial burst should allow several
	for i := 0; i < 5; i++ {
		if !rl.allow("test", 5.0) {
			t.Errorf("request %d should be allowed (within burst)", i)
		}
	}

	// Next should be denied (burst exhausted, no time to refill)
	if rl.allow("test", 5.0) {
		t.Error("request after burst should be denied")
	}
}

func TestRateLimiter_AllowPerMinute(t *testing.T) {
	rl := newRateLimiter()

	// 10 per minute = burst of 5 (minimum burst)
	allowed := 0
	for i := 0; i < 10; i++ {
		if rl.allowPerMinute("test", 10) {
			allowed++
		}
	}
	if allowed < 5 {
		t.Errorf("should allow at least 5 (burst), got %d", allowed)
	}
	if allowed > 6 {
		t.Errorf("should not allow more than ~5-6 (burst + tiny refill), got %d", allowed)
	}
}

func TestRateLimiter_SeparateKeys(t *testing.T) {
	rl := newRateLimiter()

	// Exhaust key A
	for i := 0; i < 10; i++ {
		rl.allow("a", 5.0)
	}

	// Key B should still have tokens
	if !rl.allow("b", 5.0) {
		t.Error("key b should be independent of key a")
	}
}

func TestRateLimiter_DifferentOperations(t *testing.T) {
	rl := newRateLimiter()

	// Simulate delete and react having separate buckets
	for i := 0; i < 10; i++ {
		rl.allowPerMinute("delete:alice", 10)
	}

	// React should still work (different key)
	if !rl.allowPerMinute("react:alice", 30) {
		t.Error("react should have its own bucket, separate from delete")
	}
}

func TestRateLimiter_AdminHigherLimit(t *testing.T) {
	rl := newRateLimiter()

	// User limit: 10/min (burst ~5)
	userAllowed := 0
	for i := 0; i < 10; i++ {
		if rl.allowPerMinute("delete:user1", 10) {
			userAllowed++
		}
	}

	// Admin limit: 50/min (burst ~5, but higher refill)
	adminAllowed := 0
	for i := 0; i < 10; i++ {
		if rl.allowPerMinute("delete:admin1", 50) {
			adminAllowed++
		}
	}

	// Admin should get more through (higher rate = faster refill)
	if adminAllowed < userAllowed {
		t.Errorf("admin (%d) should get at least as many as user (%d)", adminAllowed, userAllowed)
	}
}

func TestRateLimiter_ZeroRate(t *testing.T) {
	rl := newRateLimiter()

	// 0 per minute = effectively disabled, but burst of 5 means first few pass
	allowed := 0
	for i := 0; i < 10; i++ {
		if rl.allowPerMinute("test", 0) {
			allowed++
		}
	}
	// With 0 rate, bucket never refills but starts with burst
	if allowed > 5 {
		t.Errorf("zero rate should only allow initial burst, got %d", allowed)
	}
}

func TestRateLimiter_PerMinuteLimits_AllOperations(t *testing.T) {
	rl := newRateLimiter()

	// Verify each operation type creates its own bucket
	ops := []struct {
		key  string
		rate int
	}{
		{"delete:alice", 10},
		{"react:alice", 30},
		{"dm_create:alice", 5},
		{"profile:alice", 5},
		{"pin:alice", 10},
	}

	for _, op := range ops {
		if !rl.allowPerMinute(op.key, op.rate) {
			t.Errorf("first request for %q should be allowed", op.key)
		}
	}
}
