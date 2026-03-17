package server

import (
	"sync"
	"time"
)

type ipEntry struct {
	count       int
	windowStart time.Time
}

// rateLimiter enforces a fixed-window rate limit per key (typically IP address).
type rateLimiter struct {
	mu     sync.Mutex
	ips    map[string]*ipEntry
	limit  int
	window time.Duration
}

func newRateLimiter(limit int, window time.Duration) *rateLimiter {
	return &rateLimiter{
		ips:    make(map[string]*ipEntry),
		limit:  limit,
		window: window,
	}
}

func (rl *rateLimiter) allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	entry, ok := rl.ips[key]
	if !ok || now.Sub(entry.windowStart) > rl.window {
		rl.ips[key] = &ipEntry{count: 1, windowStart: now}
		return true
	}

	if entry.count >= rl.limit {
		return false
	}

	entry.count++
	return true
}
