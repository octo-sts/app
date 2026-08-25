// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package redis

import (
	"strings"
	"testing"
)

// TestRedisKeyIsNamespaced ensures counters cannot collide with unrelated keys
// in a shared Redis, where an INCR against another application's string key
// would fail or corrupt it.
func TestRedisKeyIsNamespaced(t *testing.T) {
	got := redisKey("https://token.actions.githubusercontent.com|repository_id:1")
	if !strings.HasPrefix(got, keyPrefix) {
		t.Errorf("redisKey(...) = %q, want prefix %q", got, keyPrefix)
	}
}

// TestRedisKeyHidesCallerIdentity ensures OIDC issuers and subjects are not
// written into Redis in the clear, where KEYS, SLOWLOG and provider telemetry
// would expose them.
func TestRedisKeyHidesCallerIdentity(t *testing.T) {
	const subject = "repo:acme/widgets:ref:refs/heads/main"
	got := redisKey("https://token.actions.githubusercontent.com|sub:" + subject)

	if strings.Contains(got, subject) {
		t.Errorf("redisKey(...) = %q, want the caller identity to be hashed", got)
	}
	if strings.Contains(got, "token.actions.githubusercontent.com") {
		t.Errorf("redisKey(...) = %q, want the issuer to be hashed", got)
	}
}

// TestRedisKeyIsDeterministicAndDistinct pins the two properties a bucket key
// must have: the same caller maps to the same bucket, and different callers do
// not share one.
func TestRedisKeyIsDeterministicAndDistinct(t *testing.T) {
	first := redisKey("caller-a")
	second := redisKey("caller-a")
	if first != second {
		t.Errorf("redisKey is not deterministic: %q then %q", first, second)
	}

	other := redisKey("caller-b")
	if first == other {
		t.Error("distinct callers produced the same bucket key")
	}
}
