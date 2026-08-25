// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package redis

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

// fakeScripter is a redis.Scripter that returns a canned reply, so Allow can
// be exercised without a Redis server.
//
// Script.Run calls EvalSha first and only falls back to Eval on NOSCRIPT, so
// both are wired to the same reply and the fallback never triggers here.
type fakeScripter struct {
	val any
	err error
}

func (f *fakeScripter) cmd(ctx context.Context) *redis.Cmd {
	c := redis.NewCmd(ctx)
	if f.err != nil {
		c.SetErr(f.err)
		return c
	}
	c.SetVal(f.val)
	return c
}

func (f *fakeScripter) Eval(ctx context.Context, _ string, _ []string, _ ...any) *redis.Cmd {
	return f.cmd(ctx)
}

func (f *fakeScripter) EvalSha(ctx context.Context, _ string, _ []string, _ ...any) *redis.Cmd {
	return f.cmd(ctx)
}

func (f *fakeScripter) EvalRO(ctx context.Context, _ string, _ []string, _ ...any) *redis.Cmd {
	return f.cmd(ctx)
}

func (f *fakeScripter) EvalShaRO(ctx context.Context, _ string, _ []string, _ ...any) *redis.Cmd {
	return f.cmd(ctx)
}

func (f *fakeScripter) ScriptExists(ctx context.Context, _ ...string) *redis.BoolSliceCmd {
	return redis.NewBoolSliceCmd(ctx)
}

func (f *fakeScripter) ScriptLoad(ctx context.Context, _ string) *redis.StringCmd {
	return redis.NewStringCmd(ctx)
}

var _ redis.Scripter = (*fakeScripter)(nil)

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

// TestAllowReportsClusterRedirect ensures a cluster redirect is reported as
// the configuration error it is.
//
// A non-cluster client cannot follow MOVED or ASK, so pointing one at a
// clustered endpoint fails only for the callers whose key hashes to another
// shard. Without this classification the operator sees a shard address they
// never configured and reads it as a networking fault.
func TestAllowReportsClusterRedirect(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"moved", errors.New("MOVED 3999 10.0.0.1:8501"), true},
		{"ask", errors.New("ASK 3999 10.0.0.1:8501"), true},
		{"ordinary failure", errors.New("connection refused"), false},
		{"permission denied", errors.New("NOPERM this user has no permissions"), false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			l := NewLimiter(100, time.Minute, &fakeScripter{err: tc.err})
			_, err := l.Allow(context.Background(), "caller")
			if err == nil {
				t.Fatal("Allow() returned no error, want one")
			}

			if got := errors.Is(err, ErrClusterRedirect); got != tc.want {
				t.Errorf("errors.Is(err, ErrClusterRedirect) = %v, want %v (err: %v)", got, tc.want, err)
			}
			// The underlying error must stay reachable either way, so the
			// original Redis message is not lost from logs.
			if !errors.Is(err, tc.err) {
				t.Errorf("underlying error was not wrapped: %v", err)
			}
		})
	}
}

// TestAllowDecodesScriptReply pins the mapping from the Lua reply to a
// ratelimit.Result, including the retry advice a denied caller receives.
func TestAllowDecodesScriptReply(t *testing.T) {
	t.Parallel()

	const (
		limit  = 100
		window = time.Minute
	)

	tests := []struct {
		name          string
		val           any
		wantAllowed   bool
		wantRemaining int
		wantRetry     time.Duration
	}{
		{
			name:          "allowed",
			val:           []any{int64(1), int64(99), int64(60000)},
			wantAllowed:   true,
			wantRemaining: 99,
			// An allowed caller is given no retry advice.
			wantRetry: 0,
		},
		{
			name:          "denied uses the remaining window",
			val:           []any{int64(0), int64(0), int64(30000)},
			wantAllowed:   false,
			wantRemaining: 0,
			wantRetry:     30 * time.Second,
		},
		{
			// A negative PTTL means the key vanished between the increment
			// and the read; advising zero would invite an immediate retry.
			name:          "denied with a vanished key falls back to a full window",
			val:           []any{int64(0), int64(0), int64(-2)},
			wantAllowed:   false,
			wantRemaining: 0,
			wantRetry:     window,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			l := NewLimiter(limit, window, &fakeScripter{val: tc.val})
			got, err := l.Allow(context.Background(), "caller")
			if err != nil {
				t.Fatalf("Allow() error = %v", err)
			}

			if got.Allowed != tc.wantAllowed {
				t.Errorf("Allowed = %v, want %v", got.Allowed, tc.wantAllowed)
			}
			if got.Remaining != tc.wantRemaining {
				t.Errorf("Remaining = %d, want %d", got.Remaining, tc.wantRemaining)
			}
			if got.RetryAfter != tc.wantRetry {
				t.Errorf("RetryAfter = %s, want %s", got.RetryAfter, tc.wantRetry)
			}
			if got.Limit != limit {
				t.Errorf("Limit = %d, want %d", got.Limit, limit)
			}
		})
	}
}

// TestAllowRejectsMalformedReply ensures a reply of unexpected shape is an
// error rather than a silently permissive decision.
func TestAllowRejectsMalformedReply(t *testing.T) {
	t.Parallel()

	l := NewLimiter(100, time.Minute, &fakeScripter{val: []any{int64(1), int64(99)}})
	if _, err := l.Allow(context.Background(), "caller"); err == nil {
		t.Fatal("Allow() returned no error for a short reply, want one")
	}
}
