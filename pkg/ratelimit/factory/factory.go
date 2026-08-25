// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package factory constructs a ratelimit.Limiter from configuration.
//
// It lives in its own package so that the backends can depend on the
// ratelimit contract without creating an import cycle, and so that the
// package can be configured without importing the application's env schema.
package factory

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"time"

	entraid "github.com/redis/go-redis-entraid"
	"github.com/redis/go-redis-entraid/identity"
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

// RedisAuth selects how the Redis connection authenticates.
type RedisAuth string

const (
	// RedisAuthNone uses the credentials embedded in the Redis URL, if any.
	RedisAuthNone RedisAuth = "none"
	// RedisAuthEntra uses Microsoft Entra ID workload identity.
	RedisAuthEntra RedisAuth = "entra"
)

// redisScope is the Entra ID scope for Azure Managed Redis.
const redisScope = "https://redis.azure.com/.default"

// pingTimeout bounds the startup connectivity check.
const pingTimeout = 5 * time.Second

// Config describes the limiter to build.
type Config struct {
	// Backend selects the implementation.
	Backend Backend
	// Limit is the number of requests permitted per Window per caller.
	Limit int
	// Window is the fixed window duration.
	Window time.Duration

	// RedisURL is a redis:// or rediss:// URL used when RedisAuth is none.
	RedisURL string
	// RedisAddr is a host:port used when RedisAuth is entra.
	RedisAddr string
	// RedisAuth selects the Redis authentication mode.
	RedisAuth RedisAuth

	// MaxKeys bounds the memory backend's tracked callers. Zero uses the
	// package default.
	MaxKeys int
}

// nopCloser is returned by backends that own no resources.
type nopCloser struct{}

func (nopCloser) Close() error { return nil }

// New builds a Limiter along with a Closer that releases any resources it
// owns. The Closer is always non-nil when err is nil.
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

// newRedis dials Redis and returns a limiter backed by it.
func newRedis(ctx context.Context, cfg Config) (ratelimit.Limiter, io.Closer, error) {
	opts, err := redisOptions(cfg)
	if err != nil {
		return nil, nil, err
	}

	rdb := redis.NewUniversalClient(opts)

	// A dedicated context: reassigning ctx here would hand a context that is
	// dead after pingTimeout to anything long-lived added below.
	pingCtx, cancel := context.WithTimeout(ctx, pingTimeout)
	defer cancel()
	if err := rdb.Ping(pingCtx).Err(); err != nil {
		// Close before returning, otherwise the connection pool leaks.
		if cerr := rdb.Close(); cerr != nil {
			return nil, nil, fmt.Errorf("connecting to redis: %w (also failed to close client: %w)", err, cerr)
		}
		return nil, nil, fmt.Errorf("connecting to redis: %w", err)
	}

	return redislimiter.NewLimiter(cfg.Limit, cfg.Window, rdb), rdb, nil
}

// redisOptions builds connection options for the configured auth mode.
func redisOptions(cfg Config) (*redis.UniversalOptions, error) {
	switch RedisAuth(strings.ToLower(string(cfg.RedisAuth))) {
	case RedisAuthEntra:
		return entraOptions(cfg)
	case RedisAuthNone, "":
		return urlOptions(cfg)
	default:
		return nil, fmt.Errorf("unsupported redis auth mode %q (valid: %s, %s)",
			cfg.RedisAuth, RedisAuthNone, RedisAuthEntra)
	}
}

// entraOptions authenticates with Entra ID workload identity.
//
// NewDefaultAzureCredentialsProvider is used rather than the managed-identity
// provider because AKS workload identity presents a federated ServiceAccount
// token, which the IMDS-based managed-identity path cannot consume. This
// matches how pkg/kms/akv and pkg/secrets obtain Azure credentials.
func entraOptions(cfg Config) (*redis.UniversalOptions, error) {
	if cfg.RedisAddr == "" {
		return nil, fmt.Errorf("redis address is required for %s auth", RedisAuthEntra)
	}
	host, _, err := net.SplitHostPort(cfg.RedisAddr)
	if err != nil {
		return nil, fmt.Errorf("redis address must be host:port: %w", err)
	}

	cp, err := entraid.NewDefaultAzureCredentialsProvider(entraid.DefaultAzureCredentialsProviderOptions{
		DefaultAzureIdentityProviderOptions: identity.DefaultAzureIdentityProviderOptions{
			Scopes: []string{redisScope},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("creating Entra credentials provider: %w", err)
	}

	// The username is derived from the token's oid claim by the provider and
	// must not be set here. Entra authentication requires TLS.
	return &redis.UniversalOptions{
		Addrs:                        []string{cfg.RedisAddr},
		StreamingCredentialsProvider: cp,
		TLSConfig:                    &tls.Config{MinVersion: tls.VersionTLS12, ServerName: host},
	}, nil
}

// urlOptions builds options from a redis:// or rediss:// URL.
func urlOptions(cfg Config) (*redis.UniversalOptions, error) {
	if cfg.RedisURL == "" {
		return nil, fmt.Errorf("redis URL is required for %s auth", RedisAuthNone)
	}

	parsed, err := redis.ParseURL(cfg.RedisURL)
	if err != nil {
		return nil, fmt.Errorf("parsing redis URL: %w", err)
	}
	if err := requireTLS(cfg.RedisURL, parsed); err != nil {
		return nil, err
	}

	// Every credential-bearing field must be carried across: building
	// UniversalOptions from Addr alone silently drops authentication and the
	// selected database.
	return &redis.UniversalOptions{
		Addrs:     []string{parsed.Addr},
		Username:  parsed.Username,
		Password:  parsed.Password,
		DB:        parsed.DB,
		TLSConfig: parsed.TLSConfig,
	}, nil
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
