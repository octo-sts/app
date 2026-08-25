// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package memory implements an in-process fixed-window rate limiter.
package memory

import (
	"context"
	"sync"
	"time"

	expirablelru "github.com/hashicorp/golang-lru/v2/expirable"

	"github.com/octo-sts/app/pkg/ratelimit"
)

// DefaultMaxKeys bounds how many distinct callers are tracked at once.
//
// Bucket keys are derived from caller-supplied tokens, so an unbounded map
// would let a caller with many identities grow the heap without limit. Once
// the cache is full the least-recently-used bucket is evicted, which at worst
// grants an idle caller a fresh window.
const DefaultMaxKeys = 100_000

// bucket is the per-caller state for the current window.
type bucket struct {
	used     int
	resetsAt time.Time
}

// Limiter is an in-process fixed-window limiter.
//
// It is only correct for a single replica: each process holds its own
// counters, so N replicas admit up to N*limit requests per window. Use the
// Redis backend whenever more than one replica serves traffic.
type Limiter struct {
	limit   int
	window  time.Duration
	now     func() time.Time
	maxKeys int

	// mu guards the read-modify-write of a bucket. The underlying cache is
	// itself thread-safe, but Allow must be atomic across get and add.
	mu    sync.Mutex
	store *expirablelru.LRU[string, bucket]
}

// Option configures a Limiter.
type Option func(*Limiter)

// WithClock overrides the time source. It exists so tests can advance time
// without sleeping.
func WithClock(now func() time.Time) Option {
	return func(l *Limiter) {
		if now != nil {
			l.now = now
		}
	}
}

// WithMaxKeys overrides the maximum number of tracked callers.
func WithMaxKeys(maxKeys int) Option {
	return func(l *Limiter) {
		if maxKeys > 0 {
			l.maxKeys = maxKeys
		}
	}
}

// NewLimiter returns a limiter allowing limit requests per window per key.
//
// window is a duration, not a count of seconds; passing the wrong unit here
// was previously silent and disabled limiting entirely.
func NewLimiter(limit int, window time.Duration, opts ...Option) *Limiter {
	l := &Limiter{
		limit:   limit,
		window:  window,
		now:     time.Now,
		maxKeys: DefaultMaxKeys,
	}
	for _, opt := range opts {
		opt(l)
	}

	// The cache TTL only bounds memory; window expiry is enforced against
	// resetsAt so that refreshing an entry cannot extend its window.
	l.store = expirablelru.NewLRU[string, bucket](l.maxKeys, nil, window)
	return l
}

// Allow implements ratelimit.Limiter. It never returns an error.
func (l *Limiter) Allow(_ context.Context, key string) (ratelimit.Result, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	b, ok := l.store.Get(key)
	if !ok || !now.Before(b.resetsAt) {
		b = bucket{resetsAt: now.Add(l.window)}
	}

	if b.used >= l.limit {
		return ratelimit.Result{
			Limit:      l.limit,
			RetryAfter: b.resetsAt.Sub(now),
		}, nil
	}

	b.used++
	l.store.Add(key, b)
	return ratelimit.Result{
		Allowed:   true,
		Limit:     l.limit,
		Remaining: l.limit - b.used,
	}, nil
}

var _ ratelimit.Limiter = (*Limiter)(nil)
