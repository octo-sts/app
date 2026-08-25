// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package ratelimit

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	envConfig "github.com/octo-sts/app/pkg/envconfig"
	"github.com/octo-sts/app/pkg/ratelimit/memory"
	redisLimiter "github.com/octo-sts/app/pkg/ratelimit/redis"
	entraid "github.com/redis/go-redis-entraid"
	"github.com/redis/go-redis-entraid/identity"
	"github.com/redis/go-redis/v9"
)

const (
	MEMORY = "memory"
	REDIS  = "redis"
	ENTRA  = "entra"
	NONE   = "none"
)

type LimiterConfig struct {
	Limit  int
	Window int
}

func NewLimiter(ctx context.Context, limiterType string, config LimiterConfig, cfg *envConfig.EnvConfig) (Limiter, io.Closer, error) {
	switch strings.ToLower(limiterType) {
	case MEMORY:
		return memory.NewLimiter(config.Limit, config.Window), io.NopCloser(nil), nil
	case REDIS:
		return newRedis(ctx, cfg, config.Limit, config.Window)
	default:
		return nil, nil, errors.New("unsupported limiter type")
	}
}

const redisScope = "https://redis.azure.com/.default"

func newRedis(ctx context.Context, cfg *envConfig.EnvConfig, limit int, window int) (Limiter, io.Closer, error) {
	var opts *redis.UniversalOptions
	switch strings.ToLower(cfg.RateLimitRedisAuth) {
	case ENTRA:
		host, _, err := net.SplitHostPort(cfg.RateLimitRedisAddr)
		if err != nil {
			return nil, nil, fmt.Errorf("REDIS_ADDR must be host:port: %w", err)
		}
		cp, err := entraid.NewDefaultAzureCredentialsProvider(
			entraid.DefaultAzureCredentialsProviderOptions{
				DefaultAzureIdentityProviderOptions: identity.DefaultAzureIdentityProviderOptions{
					Scopes: []string{redisScope},
				},
			})
		if err != nil {
			return nil, nil, fmt.Errorf("creating Entra credentials provider: %w", err)
		}
		opts = &redis.UniversalOptions{
			Addrs:                        []string{cfg.RateLimitRedisAddr},
			StreamingCredentialsProvider: cp,
			TLSConfig:                    &tls.Config{MinVersion: tls.VersionTLS12, ServerName: host},
		}
	case NONE, "":
		parsed, err := redis.ParseURL(cfg.RateLimitRedisURL)
		if err != nil {
			return nil, nil, fmt.Errorf("parsing REDIS_URL: %w", err)
		}
		opts = &redis.UniversalOptions{Addrs: []string{parsed.Addr}, TLSConfig: parsed.TLSConfig}
	}
	rdb := redis.NewUniversalClient(opts)

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := rdb.Ping(ctx).Err(); err != nil {
		return nil, nil, fmt.Errorf("connecting to redis: %w", err)
	}

	return redisLimiter.NewLimiter(limit, window, rdb), rdb, nil
}
