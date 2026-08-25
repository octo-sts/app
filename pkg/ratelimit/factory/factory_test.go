// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package factory

import (
	"context"
	"strings"
	"testing"
	"time"
)

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

// TestRedisOptionsRejectsUnknownAuth covers the auth switch default, which
// previously left options nil and crash-looped the process.
func TestRedisOptionsRejectsUnknownAuth(t *testing.T) {
	_, err := redisOptions(Config{RedisAuth: "entraid", RedisURL: "rediss://example:6380"})
	if err == nil {
		t.Fatal("expected an error for an unknown auth mode, got nil")
	}
	if !strings.Contains(err.Error(), "unsupported redis auth mode") {
		t.Errorf("error = %q, want it to name the unsupported auth mode", err)
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
