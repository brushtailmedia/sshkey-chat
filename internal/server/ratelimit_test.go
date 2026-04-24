package server

import (
	"testing"
)

// --- Phase 17 Step 6: allowWithRetry / allowPerMinuteWithRetry tests ---

func TestRateLimiter_AllowWithRetry_HappyPath(t *testing.T) {
	rl := newRateLimiter()
	// First call should be allowed with retry_after_ms = 0.
	allowed, retry := rl.allowWithRetry("test_happy", 5.0)
	if !allowed {
		t.Error("first call should be allowed")
	}
	if retry != 0 {
		t.Errorf("retry_after_ms on allow = %d, want 0", retry)
	}
}

func TestRateLimiter_AllowWithRetry_RejectReturnsPositiveMs(t *testing.T) {
	rl := newRateLimiter()
	// Drain the burst (5 tokens at <5 rate, clamped to 5 burst).
	for i := 0; i < 5; i++ {
		rl.allowWithRetry("test_drain", 0.1) // 0.1 tokens/sec, burst=5
	}
	// 6th should be rejected with positive retry_after_ms.
	allowed, retry := rl.allowWithRetry("test_drain", 0.1)
	if allowed {
		t.Error("6th call should be denied after burst drain")
	}
	if retry <= 0 {
		t.Errorf("retry_after_ms on reject = %d, want > 0", retry)
	}
	// At 0.1 tokens/sec, 1 full token takes 10s = 10000ms. Allow
	// wide tolerance for float drift; just assert ballpark.
	if retry < 1000 || retry > 15000 {
		t.Errorf("retry_after_ms = %d, want in [1000, 15000] for 0.1 tok/sec rate", retry)
	}
}

func TestRateLimiter_AllowPerMinuteWithRetry_HappyPath(t *testing.T) {
	rl := newRateLimiter()
	allowed, retry := rl.allowPerMinuteWithRetry("test_pm_happy", 60)
	if !allowed {
		t.Error("first call should be allowed")
	}
	if retry != 0 {
		t.Errorf("retry_after_ms on allow = %d, want 0", retry)
	}
}

func TestRateLimiter_AllowPerMinuteWithRetry_RejectReturnsSensibleMs(t *testing.T) {
	rl := newRateLimiter()
	// 6/min = 0.1 tokens/sec, burst = 5. Drain + 1 over.
	for i := 0; i < 5; i++ {
		rl.allowPerMinuteWithRetry("test_pm_drain", 6)
	}
	allowed, retry := rl.allowPerMinuteWithRetry("test_pm_drain", 6)
	if allowed {
		t.Error("6th call should be denied")
	}
	// 6/min = 10 seconds per token, so retry_after_ms should be around 10000.
	// Allow wide tolerance for bucket state + timing.
	if retry < 5000 || retry > 15000 {
		t.Errorf("retry_after_ms = %d, want ~10000 (10s at 6/min)", retry)
	}
}

func TestRateLimiter_AllowWithRetry_NeverReturnsZeroOnReject(t *testing.T) {
	// Reject paths must always return retry_after_ms >= 1. Zero would
	// omitempty-elide off the wire and be indistinguishable from "no
	// hint", defeating the purpose.
	rl := newRateLimiter()
	// Drain until the first rejection rather than assuming a fixed number
	// of iterations; keeps the test deterministic without t.Skip fallback.
	var (
		allowed bool
		retry   int64
	)
	for i := 0; i < 100000; i++ {
		allowed, retry = rl.allowWithRetry("test_no_zero", 1.0)
		if !allowed {
			break
		}
	}
	if allowed {
		t.Fatal("expected reject after draining bucket")
	}
	if retry < 1 {
		t.Errorf("retry_after_ms on reject = %d, want >= 1 (zero elides off wire)", retry)
	}
}

// --- Pre-existing tests below ---

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
