package handler

import (
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// RateLimiter implements a per-key sliding window rate limiter.
// Each key tracks the timestamps of recent requests; entries older than the
// window are discarded on every check, so the limit is a true sliding window
// (not a fixed-bucket reset).
type RateLimiter struct {
	mu      sync.Mutex
	windows map[string][]time.Time
	limit   int
	window  time.Duration
}

// NewRateLimiter creates a limiter that allows at most `limit` requests per `window`.
func NewRateLimiter(limit int, window time.Duration) *RateLimiter {
	rl := &RateLimiter{
		windows: make(map[string][]time.Time),
		limit:   limit,
		window:  window,
	}
	go rl.cleanup()
	return rl
}

// Allow returns true if the key is within the rate limit and records the request.
func (rl *RateLimiter) Allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-rl.window)

	// Slide the window: discard timestamps older than the cutoff.
	prev := rl.windows[key]
	valid := prev[:0]
	for _, t := range prev {
		if t.After(cutoff) {
			valid = append(valid, t)
		}
	}

	if len(valid) >= rl.limit {
		rl.windows[key] = valid
		return false
	}
	rl.windows[key] = append(valid, now)
	return true
}

// cleanup runs in the background and evicts keys with no recent requests,
// preventing unbounded memory growth when many unique API keys have been used.
func (rl *RateLimiter) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	for range ticker.C {
		rl.mu.Lock()
		cutoff := time.Now().Add(-rl.window)
		for key, times := range rl.windows {
			allOld := true
			for _, t := range times {
				if t.After(cutoff) {
					allOld = false
					break
				}
			}
			if allOld {
				delete(rl.windows, key)
			}
		}
		rl.mu.Unlock()
	}
}

// APIKeyRateLimitMiddleware applies rate limiting to API Key authenticated requests only.
// Passkey sessions (human-operated) are not limited.
// On limit exceeded, responds with HTTP 429 and a Retry-After header.
func APIKeyRateLimitMiddleware(rl *RateLimiter) gin.HandlerFunc {
	return func(c *gin.Context) {
		mode, _ := c.Get("authMode")
		if mode != "apikey" {
			c.Next()
			return
		}

		userID := mustUserID(c)
		key := fmt.Sprintf("apikey:%d", userID)
		if !rl.Allow(key) {
			c.Header("Retry-After", "60")
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error": "rate limit exceeded — API key requests are limited, try again later",
			})
			return
		}
		c.Next()
	}
}
