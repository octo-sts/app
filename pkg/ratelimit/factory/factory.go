// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package factory constructs a ratelimit.Limiter from configuration.
//
// It lives in its own package so that the backends can depend on the
// ratelimit contract without creating an import cycle, and so that the
// package can be configured without importing the application's env schema.
//
// It is deliberately cloud-neutral. Provider-specific Redis authentication
// belongs in its own package (see pkg/ratelimit/redisentra) and reaches the
// factory through Config.RedisClient, so that a deployment which does not use
// a given cloud never imports its SDK.
package factory

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/octo-sts/app/pkg/ratelimit"
	"github.com/octo-sts/app/pkg/ratelimit/memory"
	redislimiter "github.com/octo-sts/app/pkg/ratelimit/redis"
)

// Backend selects a rate-limiter implementation.
type Backend string

const (
	// BackendMemory keeps counters in process. Correct for one replica only.
	BackendMemory Backend = "memory"
	// BackendRedis keeps counters in Redis, shared across replicas.
	BackendRedis Backend = "redis"
)

// pingTimeout bounds the startup connectivity check.
const pingTimeout = 5 * time.Second

// ErrRedisUnreachable reports that Redis did not answer the startup ping.
//
// It is distinct from a configuration error because the two demand different
// responses: a bad backend name or a malformed URL is an operator mistake that
// will never fix itself, whereas an unreachable Redis is usually transient.
// When New returns an error wrapping this, the returned Limiter and Closer are
// still non-nil and usable: go-redis reconnects in the background, so a caller
// that prefers availability may start in a degraded state and enforcement will
// resume by itself once Redis returns.
var ErrRedisUnreachable = errors.New("redis unreachable at startup")

// Config describes the limiter to build.
type Config struct {
	// Backend selects the implementation.
	Backend Backend
	// Limit is the number of requests permitted per Window per caller.
	Limit int
	// Window is the fixed window duration.
	Window time.Duration

	// RedisURL is a redis:// or rediss:// URL. It is ignored when
	// RedisClient is set.
	RedisURL string

	// RedisClient, when set, is used as-is instead of dialling RedisURL.
	//
	// This is the seam for provider-specific authentication such as Entra ID
	// workload identity: the caller builds an authenticated client and the
	// factory stays free of cloud SDKs. The caller retains ownership and must
	// close it; the Closer returned by New is a no-op in that case.
	RedisClient redis.UniversalClient

	// MaxKeys bounds the memory backend's tracked callers. Zero uses the
	// package default.
	MaxKeys int
}

// nopCloser is returned by backends that own no resources.
type nopCloser struct{}

func (nopCloser) Close() error { return nil }

// New builds a Limiter along with a Closer that releases any resources it
// owns.
//
// On success the Closer is non-nil. The one case where a non-nil error
// accompanies a usable Limiter and Closer is ErrRedisUnreachable; see its
// documentation. For every other error both are nil.
func New(ctx context.Context, cfg Config) (ratelimit.Limiter, io.Closer, error) {
	if cfg.Limit <= 0 {
		return nil, nil, fmt.Errorf("rate limit must be positive, got %d", cfg.Limit)
	}
	if cfg.Window <= 0 {
		return nil, nil, fmt.Errorf("rate limit window must be positive, got %s", cfg.Window)
	}

	switch Backend(strings.ToLower(string(cfg.Backend))) {
	case BackendMemory:
		return memory.NewLimiter(cfg.Limit, cfg.Window, memory.WithMaxKeys(cfg.MaxKeys)), nopCloser{}, nil
	case BackendRedis:
		return newRedis(ctx, cfg)
	default:
		return nil, nil, fmt.Errorf("unsupported rate limit backend %q (valid: %s, %s)",
			cfg.Backend, BackendMemory, BackendRedis)
	}
}

// newRedis resolves a client and returns a limiter backed by it.
func newRedis(ctx context.Context, cfg Config) (ratelimit.Limiter, io.Closer, error) {
	client, closer, err := redisClient(cfg)
	if err != nil {
		return nil, nil, err
	}

	limiter := redislimiter.NewLimiter(cfg.Limit, cfg.Window, client)

	// A dedicated context: reassigning ctx here would hand a context that is
	// dead after pingTimeout to anything long-lived added below.
	pingCtx, cancel := context.WithTimeout(ctx, pingTimeout)
	defer cancel()
	if err := client.Ping(pingCtx).Err(); err != nil {
		// The client is returned rather than closed so the caller can choose
		// to proceed degraded. A caller that treats this as fatal will exit,
		// which releases the pool anyway.
		return limiter, closer, fmt.Errorf("%w: %w", ErrRedisUnreachable, err)
	}

	return limiter, closer, nil
}

// redisClient returns the injected client, or dials RedisURL.
//
// The returned Closer reflects ownership: an injected client belongs to the
// caller and must not be closed here, or the caller would be left holding a
// dead client it still believes it owns.
func redisClient(cfg Config) (redis.UniversalClient, io.Closer, error) {
	if cfg.RedisClient != nil {
		return cfg.RedisClient, nopCloser{}, nil
	}

	opts, err := urlOptions(cfg)
	if err != nil {
		return nil, nil, err
	}
	rdb := redis.NewClient(opts)
	return rdb, rdb, nil
}

// urlOptions builds options from a redis:// or rediss:// URL.
//
// The parsed options are used as-is rather than being copied field by field
// into UniversalOptions. Copying silently dropped everything not explicitly
// listed - credentials once, and every connection-tuning parameter the URL
// can carry (max_retries, dial_timeout, pool_size and the rest) - and would
// drop any option a future library version adds.
func urlOptions(cfg Config) (*redis.Options, error) {
	if cfg.RedisURL == "" {
		return nil, errors.New("redis URL is required when no Redis client is supplied")
	}

	parsed, err := redis.ParseURL(cfg.RedisURL)
	if err != nil {
		return nil, fmt.Errorf("parsing redis URL: %w", err)
	}
	if err := requireTLS(cfg.RedisURL, parsed); err != nil {
		return nil, err
	}

	return parsed, nil
}

// requireTLS rejects plaintext Redis outside loopback.
//
// redis.ParseURL only configures TLS for the rediss scheme, so a redis:// URL
// would ship credentials and counters in the clear. Loopback is exempt so that
// local development and tests do not need certificates.
func requireTLS(rawURL string, parsed *redis.Options) error {
	if parsed.TLSConfig != nil {
		return nil
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("parsing redis URL: %w", err)
	}
	if isLoopback(u.Hostname()) {
		return nil
	}
	return fmt.Errorf("redis URL must use the rediss:// scheme for non-loopback host %q", u.Hostname())
}

// isLoopback reports whether host refers to the local machine.
func isLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
