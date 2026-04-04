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
