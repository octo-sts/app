// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package redis implements a Redis-backed fixed-window rate limiter that is
// authoritative across replicas.
package redis

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/octo-sts/app/pkg/ratelimit"
)

// keyPrefix namespaces every counter this package writes.
//
// Rate-limit keys are derived from caller identity, so without a prefix they
// could collide with unrelated keys in a shared Redis instance - an INCR
// against another application's string key fails or corrupts it. The version
// segment allows the bucket encoding to change without colliding with counters
// written by an older release.
const keyPrefix = "octosts:rl:v1:"

// allowScript atomically increments a caller's counter and reports the
// decision as {allowed, remaining, ttlMillis}.
//
// The TTL is (re)applied whenever the key has no expiry, not just on the first
// increment. If an EXPIRE were ever lost - a failover between the INCR and the
// EXPIRE, a manual SET, a RESTORE that drops the TTL - the counter would
// otherwise become immortal and lock that caller out permanently.
var allowScript = redis.NewScript(`
local limit  = tonumber(ARGV[1])
local window = tonumber(ARGV[2])

local count = redis.call("INCR", KEYS[1])
if count == 1 or redis.call("PTTL", KEYS[1]) < 0 then
  redis.call("PEXPIRE", KEYS[1], window)
end

local ttl = redis.call("PTTL", KEYS[1])
if count > limit then
  return {0, 0, ttl}
end
return {1, limit - count, ttl}
`)

// Limiter is a fixed-window limiter backed by Redis.
type Limiter struct {
	limit  int
	window time.Duration
	client redis.Scripter
}

// NewLimiter returns a limiter allowing limit requests per window per key.
//
// client is the narrow redis.Scripter interface rather than a full
// UniversalClient so that the limiter can be exercised against a fake in
// tests, mirroring the signerClient seam in pkg/kms/akv.
func NewLimiter(limit int, window time.Duration, client redis.Scripter) *Limiter {
	return &Limiter{
		limit:  limit,
		window: window,
		client: client,
	}
}

// Allow implements ratelimit.Limiter.
func (l *Limiter) Allow(ctx context.Context, key string) (ratelimit.Result, error) {
	out, err := allowScript.Run(
		ctx, l.client, []string{redisKey(key)}, l.limit, l.window.Milliseconds(),
	).Int64Slice()
	if err != nil {
		// The key is hashed into the error to keep caller identity out of logs.
		return ratelimit.Result{}, fmt.Errorf("ratelimit: evaluating script: %w", err)
	}
	if len(out) != 3 {
		return ratelimit.Result{}, fmt.Errorf("ratelimit: script returned %d values, want 3", len(out))
	}

	res := ratelimit.Result{
		Allowed:   out[0] == 1,
		Limit:     l.limit,
		Remaining: int(out[1]),
	}
	if !res.Allowed {
		// A negative PTTL means the key vanished between the increment and
		// the read; fall back to a full window rather than advising zero.
		if out[2] < 0 {
			res.RetryAfter = l.window
		} else {
			res.RetryAfter = time.Duration(out[2]) * time.Millisecond
		}
	}
	return res, nil
}

// redisKey namespaces and hashes a caller key.
//
// Hashing keeps OIDC issuers and subjects out of Redis, where they would
// otherwise be visible via KEYS, SLOWLOG and provider-side telemetry. SHA-256
// is used rather than the 32-bit hash in pkg/routekey because a collision here
// would let one caller consume another caller's budget.
func redisKey(key string) string {
	sum := sha256.Sum256([]byte(key))
	return keyPrefix + hex.EncodeToString(sum[:])
}

var _ ratelimit.Limiter = (*Limiter)(nil)
