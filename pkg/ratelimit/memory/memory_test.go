// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package memory

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestAllowsExactlyLimitPerWindow pins the boundary: the limit-th request is
// admitted and the one after it is not.
func TestAllowsExactlyLimitPerWindow(t *testing.T) {
	l := NewLimiter(3, time.Minute)

	for i := 1; i <= 3; i++ {
		res, err := l.Allow(context.Background(), "caller")
		if err != nil {
			t.Fatalf("request %d: unexpected error: %v", i, err)
		}
		if !res.Allowed {
			t.Fatalf("request %d: denied, want allowed", i)
		}
		if want := 3 - i; res.Remaining != want {
			t.Errorf("request %d: Remaining = %d, want %d", i, res.Remaining, want)
		}
	}

	res, err := l.Allow(context.Background(), "caller")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Allowed {
		t.Error("request 4 allowed, want denied")
	}
	if res.RetryAfter <= 0 {
		t.Errorf("RetryAfter = %s, want positive", res.RetryAfter)
	}
}

// TestWindowIsDurationNotNanoseconds is a regression test for a window that
// was built with time.Duration(seconds), yielding a nanosecond window that
// reset on every request and silently disabled limiting altogether.
func TestWindowIsDurationNotNanoseconds(t *testing.T) {
	now := time.Now()
	clock := func() time.Time { return now }
	l := NewLimiter(1, 5*time.Minute, WithClock(clock))

	if res, _ := l.Allow(context.Background(), "caller"); !res.Allowed {
		t.Fatal("first request denied, want allowed")
	}

	// Far beyond a nanosecond window, far short of the real one.
	now = now.Add(time.Second)
	res, _ := l.Allow(context.Background(), "caller")
	if res.Allowed {
		t.Fatal("request allowed one second into a five minute window; window is not being applied as a duration")
	}
}

// TestWindowResets confirms budget returns once the window elapses.
func TestWindowResets(t *testing.T) {
	now := time.Now()
	clock := func() time.Time { return now }
	l := NewLimiter(1, time.Minute, WithClock(clock))

	if res, _ := l.Allow(context.Background(), "caller"); !res.Allowed {
		t.Fatal("first request denied, want allowed")
	}
	if res, _ := l.Allow(context.Background(), "caller"); res.Allowed {
		t.Fatal("second request allowed, want denied")
	}

	now = now.Add(time.Minute + time.Second)
	if res, _ := l.Allow(context.Background(), "caller"); !res.Allowed {
		t.Fatal("request after window elapsed denied, want allowed")
	}
}

// TestKeysAreIndependent ensures one caller cannot exhaust another's budget.
func TestKeysAreIndependent(t *testing.T) {
	l := NewLimiter(1, time.Minute)

	if res, _ := l.Allow(context.Background(), "a"); !res.Allowed {
		t.Fatal("caller a denied, want allowed")
	}
	if res, _ := l.Allow(context.Background(), "b"); !res.Allowed {
		t.Fatal("caller b denied, want allowed: budgets are not per-key")
	}
}

// TestConcurrentAllowIsRaceFree must be run under -race. It also asserts the
// limiter never over-admits when hit from many goroutines at once.
func TestConcurrentAllowIsRaceFree(t *testing.T) {
	const (
		limit    = 50
		requests = 500
	)
	l := NewLimiter(limit, time.Minute)

	var allowed atomic.Int64
	var wg sync.WaitGroup
	for range requests {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if res, err := l.Allow(context.Background(), "caller"); err == nil && res.Allowed {
				allowed.Add(1)
			}
		}()
	}
	wg.Wait()

	if got := allowed.Load(); got != limit {
		t.Errorf("allowed %d requests, want exactly %d", got, limit)
	}
}

// TestMaxKeysBoundsMemory ensures the tracked-key set cannot grow without
// limit, since keys derive from caller-controlled token claims.
func TestMaxKeysBoundsMemory(t *testing.T) {
	l := NewLimiter(1, time.Minute, WithMaxKeys(10))

	for i := range 1000 {
		if _, err := l.Allow(context.Background(), string(rune(i))); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	}

	if got := l.store.Len(); got > 10 {
		t.Errorf("store holds %d keys, want at most 10", got)
	}
}
