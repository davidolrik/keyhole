package server

import (
	"fmt"
	"testing"
	"time"
)

func TestRateLimiterAllowsUpToLimit(t *testing.T) {
	rl := newRateLimiter(5, time.Minute)

	for i := 0; i < 5; i++ {
		if !rl.allow("1.2.3.4") {
			t.Fatalf("request %d should be allowed", i+1)
		}
	}
}

func TestRateLimiterBlocksAfterLimit(t *testing.T) {
	rl := newRateLimiter(3, time.Minute)

	for i := 0; i < 3; i++ {
		rl.allow("1.2.3.4")
	}

	if rl.allow("1.2.3.4") {
		t.Error("request after limit should be blocked")
	}
}

func TestRateLimiterSeparatesKeys(t *testing.T) {
	rl := newRateLimiter(2, time.Minute)

	rl.allow("1.2.3.4")
	rl.allow("1.2.3.4")

	// Different IP should still be allowed
	if !rl.allow("5.6.7.8") {
		t.Error("different IP should be allowed")
	}
}

func TestRateLimiterResetsAfterWindow(t *testing.T) {
	rl := newRateLimiter(2, 50*time.Millisecond)

	rl.allow("1.2.3.4")
	rl.allow("1.2.3.4")

	if rl.allow("1.2.3.4") {
		t.Error("should be blocked before window expires")
	}

	time.Sleep(60 * time.Millisecond)

	if !rl.allow("1.2.3.4") {
		t.Error("should be allowed after window expires")
	}
}

func TestRateLimiterSlidingWindowPreventsEdgeBurst(t *testing.T) {
	// With a sliding window, requests near the end of one window should
	// still count against the limit in the next window, preventing an
	// attacker from bursting 2x the limit across window boundaries.
	rl := newRateLimiter(4, 100*time.Millisecond)

	// Use 3 of 4 allowed requests
	for i := 0; i < 3; i++ {
		if !rl.allow("1.2.3.4") {
			t.Fatalf("request %d should be allowed", i+1)
		}
	}

	// Wait for half the window to pass, then send 1 more (4th, at the limit)
	time.Sleep(50 * time.Millisecond)
	if !rl.allow("1.2.3.4") {
		t.Fatal("4th request should be allowed (at limit)")
	}

	// Now wait just past the original window boundary. With a fixed-window
	// limiter, all 4 slots would reset and we'd get 4 more immediately.
	// With a sliding window, the 3 early requests have expired but the
	// recent one (50ms ago) still counts — so only 3 more should be allowed.
	time.Sleep(55 * time.Millisecond)

	allowed := 0
	for i := 0; i < 4; i++ {
		if rl.allow("1.2.3.4") {
			allowed++
		}
	}
	if allowed >= 4 {
		t.Errorf("sliding window should limit burst across boundary: got %d allowed, want < 4", allowed)
	}
}

func TestRateLimiterSweepsExpiredEntries(t *testing.T) {
	rl := newRateLimiter(2, 50*time.Millisecond)

	// Generate entries from many IPs
	for i := 0; i < 100; i++ {
		rl.allow(fmt.Sprintf("10.0.0.%d", i))
	}

	rl.mu.Lock()
	beforeSweep := len(rl.ips)
	rl.mu.Unlock()

	if beforeSweep != 100 {
		t.Fatalf("expected 100 entries before sweep, got %d", beforeSweep)
	}

	// Wait for window to expire, then trigger a sweep via allow()
	time.Sleep(60 * time.Millisecond)
	rl.allow("trigger-sweep")

	rl.mu.Lock()
	afterSweep := len(rl.ips)
	rl.mu.Unlock()

	// Only the trigger IP should remain (all 100 old entries swept)
	if afterSweep != 1 {
		t.Errorf("expected 1 entry after sweep, got %d", afterSweep)
	}
}
