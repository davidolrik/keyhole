package server

import (
	"sync"
	"time"
)

type ipEntry struct {
	timestamps []time.Time
}

// rateLimiter enforces a sliding-window rate limit per key (typically IP address).
// Each request timestamp is recorded, and only requests within the current window
// are counted. This prevents burst attacks across window boundaries that fixed-window
// counters allow.
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

	// Periodically sweep entries with no recent timestamps to prevent
	// unbounded memory growth from unique IPs (e.g. botnet scans).
	if now.Sub(rl.lastSweep) > rl.window {
		for k, e := range rl.ips {
			if len(e.timestamps) == 0 || now.Sub(e.timestamps[len(e.timestamps)-1]) > rl.window {
				delete(rl.ips, k)
			}
		}
		rl.lastSweep = now
	}

	entry, ok := rl.ips[key]
	if !ok {
		rl.ips[key] = &ipEntry{timestamps: []time.Time{now}}
		return true
	}

	// Evict timestamps outside the sliding window
	cutoff := now.Add(-rl.window)
	start := 0
	for start < len(entry.timestamps) && entry.timestamps[start].Before(cutoff) {
		start++
	}
	entry.timestamps = entry.timestamps[start:]

	if len(entry.timestamps) >= rl.limit {
		return false
	}

	entry.timestamps = append(entry.timestamps, now)
	return true
}
