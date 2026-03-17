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
