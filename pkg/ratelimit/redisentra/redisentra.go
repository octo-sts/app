// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package redisentra dials Azure Managed Redis using Microsoft Entra ID
// workload identity.
//
// It is deliberately separate from pkg/ratelimit/factory so that the factory,
// and therefore the memory and generic-Redis paths, carry no Azure SDK
// imports. Only a deployment that actually authenticates to Redis with Entra
// ID needs to reference this package.
//
// The resulting client is passed to the factory through Config.RedisClient,
// which keeps the rate-limiting core cloud-neutral: the limiter logic is
// identical whichever cloud provides Redis, and only client construction
// differs.
package redisentra

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"

	entraid "github.com/redis/go-redis-entraid"
	"github.com/redis/go-redis-entraid/identity"
	"github.com/redis/go-redis/v9"
)

// Scope is the Entra ID scope for Azure Managed Redis.
const Scope = "https://redis.azure.com/.default"

// ErrNoAddress is returned when no Redis address was configured.
var ErrNoAddress = errors.New("redis address is required for Entra ID auth")

// Options builds Redis connection options authenticated with Entra ID
// workload identity. addr must be host:port.
//
// NewDefaultAzureCredentialsProvider is used rather than the managed-identity
// provider because AKS workload identity presents a federated ServiceAccount
// token, which the IMDS-based managed-identity path cannot consume. This
// matches how pkg/kms/akv and pkg/secrets obtain Azure credentials.
func Options(addr string) (*redis.UniversalOptions, error) {
	if addr == "" {
		return nil, ErrNoAddress
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("redis address must be host:port: %w", err)
	}

	cp, err := entraid.NewDefaultAzureCredentialsProvider(entraid.DefaultAzureCredentialsProviderOptions{
		DefaultAzureIdentityProviderOptions: identity.DefaultAzureIdentityProviderOptions{
			Scopes: []string{Scope},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("creating Entra credentials provider: %w", err)
	}

	// The username is derived from the token's oid claim by the provider and
	// must not be set here. Entra authentication requires TLS.
	return &redis.UniversalOptions{
		Addrs:                        []string{addr},
		StreamingCredentialsProvider: cp,
		TLSConfig:                    &tls.Config{MinVersion: tls.VersionTLS12, ServerName: host},
	}, nil
}

// NewClient builds a Redis client authenticated with Entra ID workload
// identity.
//
// It does not verify connectivity: the caller decides whether an unreachable
// Redis is fatal, and go-redis reconnects on its own once it is reachable.
// The caller owns the returned client and must Close it.
func NewClient(addr string) (redis.UniversalClient, error) {
	opts, err := Options(addr)
	if err != nil {
		return nil, err
	}
	return redis.NewUniversalClient(opts), nil
}
