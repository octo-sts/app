// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package factory

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

// closedPort returns a loopback address with nothing listening on it, so that
// a connection attempt is refused immediately rather than waiting for the
// ping timeout.
func closedPort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserving a port: %v", err)
	}
	addr := l.Addr().String()
	if err := l.Close(); err != nil {
		t.Fatalf("releasing the port: %v", err)
	}
	return addr
}

// TestNewRejectsUnknownBackend covers the switch default. Without it the
// factory fell through and handed nil options to the redis client, panicking
// inside the library on a simple typo.
func TestNewRejectsUnknownBackend(t *testing.T) {
	_, _, err := New(context.Background(), Config{
		Backend: "redsi",
		Limit:   10,
		Window:  time.Minute,
	})
	if err == nil {
		t.Fatal("expected an error for an unknown backend, got nil")
	}
	if !strings.Contains(err.Error(), "unsupported rate limit backend") {
		t.Errorf("error = %q, want it to name the unsupported backend", err)
	}
}

// TestRedisOptionsRejectsMissingURL covers the case where neither a URL nor an
// injected client was supplied, which previously left options nil and crashed
// inside the redis library.
func TestURLOptionsRejectsMissingURL(t *testing.T) {
	_, err := urlOptions(Config{})
	if err == nil {
		t.Fatal("expected an error when no redis URL is configured, got nil")
	}
	if !strings.Contains(err.Error(), "redis URL is required") {
		t.Errorf("error = %q, want it to say a redis URL is required", err)
	}
}

// TestURLOptionsCarriesCredentials is a regression test for options that were
// built from the parsed address alone, silently discarding the username,
// password and database and producing unauthenticated connections.
func TestURLOptionsCarriesCredentials(t *testing.T) {
	opts, err := urlOptions(Config{RedisURL: "rediss://alice:s3cret@redis.example.com:6380/3"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got, want := opts.Username, "alice"; got != want {
		t.Errorf("Username = %q, want %q", got, want)
	}
	if got, want := opts.Password, "s3cret"; got != want {
		t.Errorf("Password = %q, want %q", got, want)
	}
	if got, want := opts.DB, 3; got != want {
		t.Errorf("DB = %d, want %d", got, want)
	}
	if opts.TLSConfig == nil {
		t.Error("TLSConfig is nil for a rediss:// URL, want TLS configured")
	}
}

// TestURLOptionsRejectsPlaintextRemote ensures counters and credentials are
// not sent in the clear to a remote host.
func TestURLOptionsRejectsPlaintextRemote(t *testing.T) {
	_, err := urlOptions(Config{RedisURL: "redis://redis.example.com:6379"})
	if err == nil {
		t.Fatal("expected an error for plaintext redis:// to a remote host, got nil")
	}
	if !strings.Contains(err.Error(), "rediss://") {
		t.Errorf("error = %q, want it to point at the rediss:// scheme", err)
	}
}

// TestURLOptionsAllowsPlaintextLoopback keeps local development and tests
// workable without certificates.
func TestURLOptionsAllowsPlaintextLoopback(t *testing.T) {
	for _, url := range []string{"redis://localhost:6379", "redis://127.0.0.1:6379"} {
		if _, err := urlOptions(Config{RedisURL: url}); err != nil {
			t.Errorf("urlOptions(%q) returned %v, want nil", url, err)
		}
	}
}

// TestNewRejectsNonPositiveWindow guards the case where a zero window would
// expire every bucket immediately and silently disable enforcement.
func TestNewRejectsNonPositiveWindow(t *testing.T) {
	if _, _, err := New(context.Background(), Config{Backend: BackendMemory, Limit: 10}); err == nil {
		t.Fatal("expected an error for a zero window, got nil")
	}
	if _, _, err := New(context.Background(), Config{Backend: BackendMemory, Window: time.Minute}); err == nil {
		t.Fatal("expected an error for a zero limit, got nil")
	}
}

// TestNewMemoryReturnsUsableCloser checks the returned Closer is safe to call,
// where a nil-wrapped io.NopCloser was previously used.
func TestNewMemoryReturnsUsableCloser(t *testing.T) {
	limiter, closer, err := New(context.Background(), Config{
		Backend: BackendMemory,
		Limit:   1,
		Window:  time.Minute,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if limiter == nil {
		t.Fatal("limiter is nil")
	}
	if err := closer.Close(); err != nil {
		t.Errorf("Close() = %v, want nil", err)
	}
}

// An unreachable Redis must not be fatal on its own: New returns a usable
// limiter so the caller can choose to start degraded rather than crash-loop
// and take down token exchange entirely.
func TestNewRedisUnreachableReturnsUsableLimiter(t *testing.T) {
	limiter, closer, err := New(context.Background(), Config{
		Backend:  BackendRedis,
		Limit:    10,
		Window:   time.Minute,
		RedisURL: "redis://" + closedPort(t) + "?max_retries=-1",
	})

	if !errors.Is(err, ErrRedisUnreachable) {
		t.Fatalf("error = %v, want it to wrap ErrRedisUnreachable", err)
	}
	if limiter == nil {
		t.Error("limiter is nil, want a usable limiter for a degraded start")
	}
	if closer == nil {
		t.Fatal("closer is nil, want a usable closer for a degraded start")
	}
	if err := closer.Close(); err != nil {
		t.Errorf("Close() = %v, want nil", err)
	}
}

// Configuration mistakes must stay fatal. If they were mistaken for a
// transient outage, a typo would silently disable enforcement instead of
// stopping the process.
func TestConfigErrorsAreNotTreatedAsUnreachable(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  Config
	}{
		{"unknown backend", Config{Backend: "redsi", Limit: 10, Window: time.Minute}},
		{"missing url", Config{Backend: BackendRedis, Limit: 10, Window: time.Minute}},
		{"plaintext remote", Config{Backend: BackendRedis, Limit: 10, Window: time.Minute, RedisURL: "redis://redis.example.com:6379"}},
		{"zero limit", Config{Backend: BackendRedis, Window: time.Minute}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			limiter, closer, err := New(context.Background(), tc.cfg)
			if err == nil {
				t.Fatal("expected an error, got nil")
			}
			if errors.Is(err, ErrRedisUnreachable) {
				t.Errorf("error = %v, want a fatal config error, not ErrRedisUnreachable", err)
			}
			if limiter != nil || closer != nil {
				t.Error("limiter and closer must both be nil for a config error")
			}
		})
	}
}

// The injection seam is what keeps cloud SDKs out of this package, so an
// injected client must take precedence over any URL.
func TestInjectedClientTakesPrecedenceOverURL(t *testing.T) {
	client := redis.NewUniversalClient(&redis.UniversalOptions{Addrs: []string{closedPort(t)}, MaxRetries: -1})
	t.Cleanup(func() { _ = client.Close() })

	// A URL that would fail to parse: reaching it would mean the injected
	// client was ignored.
	_, _, err := New(context.Background(), Config{
		Backend:     BackendRedis,
		Limit:       10,
		Window:      time.Minute,
		RedisURL:    "://not-a-valid-url",
		RedisClient: client,
	})

	if !errors.Is(err, ErrRedisUnreachable) {
		t.Fatalf("error = %v, want ErrRedisUnreachable, which would mean the injected client was used", err)
	}
}

// The caller owns an injected client. Closing it here would leave the caller
// holding a dead client it still believes is live.
func TestInjectedClientIsNotClosedByFactory(t *testing.T) {
	client := redis.NewUniversalClient(&redis.UniversalOptions{Addrs: []string{closedPort(t)}, MaxRetries: -1})
	t.Cleanup(func() { _ = client.Close() })

	_, closer, err := New(context.Background(), Config{
		Backend:     BackendRedis,
		Limit:       10,
		Window:      time.Minute,
		RedisClient: client,
	})
	if !errors.Is(err, ErrRedisUnreachable) {
		t.Fatalf("error = %v, want ErrRedisUnreachable", err)
	}
	if err := closer.Close(); err != nil {
		t.Fatalf("Close() = %v, want nil", err)
	}

	// Connection refused is expected; ErrClosed would mean the factory closed
	// a client it did not own.
	if err := client.Ping(context.Background()).Err(); errors.Is(err, redis.ErrClosed) {
		t.Error("factory closed the injected client, which belongs to the caller")
	}
}

// Connection tuning carried in the URL must survive. These were silently
// dropped when options were copied field by field into UniversalOptions, so
// an operator tuning timeouts or retries got the defaults regardless.
func TestURLOptionsCarriesConnectionTuning(t *testing.T) {
	opts, err := urlOptions(Config{
		RedisURL: "rediss://redis.example.com:6380?max_retries=7&dial_timeout=3s&pool_size=42",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got, want := opts.MaxRetries, 7; got != want {
		t.Errorf("MaxRetries = %d, want %d", got, want)
	}
	if got, want := opts.DialTimeout, 3*time.Second; got != want {
		t.Errorf("DialTimeout = %s, want %s", got, want)
	}
	if got, want := opts.PoolSize, 42; got != want {
		t.Errorf("PoolSize = %d, want %d", got, want)
	}
}
