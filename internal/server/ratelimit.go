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
	mu        sync.Mutex
	ips       map[string]*ipEntry
	limit     int
	window    time.Duration
	lastSweep time.Time
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

	// Periodically sweep expired entries to prevent unbounded memory growth
	// from unique IPs (e.g. botnet scans). Sweep at most once per window.
	if now.Sub(rl.lastSweep) > rl.window {
		for k, e := range rl.ips {
			if now.Sub(e.windowStart) > rl.window {
				delete(rl.ips, k)
			}
		}
		rl.lastSweep = now
	}

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
