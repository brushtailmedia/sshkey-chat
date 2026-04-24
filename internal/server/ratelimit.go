package server

import (
	"sync"
	"time"
)

// rateLimiter implements per-user token bucket rate limiting.
type rateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
}

type bucket struct {
	tokens    float64
	maxTokens float64
	refillRate float64 // tokens per second
	lastRefill time.Time
}

func newRateLimiter() *rateLimiter {
	return &rateLimiter{
		buckets: make(map[string]*bucket),
	}
}

// allow checks if an action is allowed for the given key.
// maxRate is the maximum actions per second.
func (rl *rateLimiter) allow(key string, maxRate float64) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	b, ok := rl.buckets[key]
	if !ok {
		// Start with enough tokens for a reasonable burst.
		// For per-second limits (maxRate >= 1), burst = rate.
		// For per-minute limits (maxRate < 1), burst = at least 5 to allow short bursts.
		burst := maxRate
		if burst < 5 {
			burst = 5
		}
		b = &bucket{
			tokens:     burst,
			maxTokens:  burst,
			refillRate: maxRate,
			lastRefill: time.Now(),
		}
		rl.buckets[key] = b
	}

	// Refill tokens
	now := time.Now()
	elapsed := now.Sub(b.lastRefill).Seconds()
	b.tokens += elapsed * b.refillRate
	if b.tokens > b.maxTokens {
		b.tokens = b.maxTokens
	}
	b.lastRefill = now

	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}

// allowPerMinute checks if an action is allowed at the given per-minute rate.
func (rl *rateLimiter) allowPerMinute(key string, maxPerMinute int) bool {
	return rl.allow(key, float64(maxPerMinute)/60.0)
}

// allowWithRetry is the Phase 17 Step 6 counterpart to `allow`: same
// token-bucket semantics, but returns the estimated time-to-next-token
// in milliseconds when rejecting. Callers populate this on rate-limit
// wire responses as the `retry_after_ms` hint.
//
// On accept: returns (true, 0).
// On reject: returns (false, ms) where ms is how long the client
// should wait before the bucket will have a full token again. The
// calculation is (1 - tokens_current) / refillRate * 1000 — purely
// a function of bucket state.
//
// Rounding: ms is floored to int64, then one `min=1` floor so
// reject responses always carry a positive retry hint (zero would
// be indistinguishable from "no hint" via `omitempty` serialization).
func (rl *rateLimiter) allowWithRetry(key string, maxRate float64) (bool, int64) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	b, ok := rl.buckets[key]
	if !ok {
		burst := maxRate
		if burst < 5 {
			burst = 5
		}
		b = &bucket{
			tokens:     burst,
			maxTokens:  burst,
			refillRate: maxRate,
			lastRefill: time.Now(),
		}
		rl.buckets[key] = b
	}

	now := time.Now()
	elapsed := now.Sub(b.lastRefill).Seconds()
	b.tokens += elapsed * b.refillRate
	if b.tokens > b.maxTokens {
		b.tokens = b.maxTokens
	}
	b.lastRefill = now

	if b.tokens >= 1 {
		b.tokens--
		return true, 0
	}

	// Bucket empty — compute time-to-next-token.
	remaining := 1.0 - b.tokens
	var retryMs int64
	if b.refillRate > 0 {
		retryMs = int64(remaining / b.refillRate * 1000.0)
	}
	if retryMs < 1 {
		retryMs = 1 // zero would be indistinguishable from "no hint" on the wire
	}
	return false, retryMs
}

// allowPerMinuteWithRetry is the allowWithRetry equivalent of
// allowPerMinute. Same per-minute rate semantics.
func (rl *rateLimiter) allowPerMinuteWithRetry(key string, maxPerMinute int) (bool, int64) {
	return rl.allowWithRetry(key, float64(maxPerMinute)/60.0)
}
