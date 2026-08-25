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
//
// # Cluster policy
//
// Every Azure Managed Redis instance is internally clustered, on all tiers
// and SKUs, and the cluster policy chosen when the instance is provisioned
// decides whether the client this package builds can talk to it:
//
//   - Enterprise: supported. A proxy routes every request from a single
//     endpoint, so the instance behaves as non-clustered.
//   - Non-clustered: supported. Available up to 25 GB.
//   - OSS: NOT supported by NewClient. This policy exposes the Redis Cluster
//     API, and the client built here is not cluster-aware, so it fails with
//     redis.ErrClusterRedirect for any key whose slot is on another shard.
//
// Provision with the Enterprise or Non-clustered policy. This is worth
// stating explicitly because Azure recommends OSS as the general-purpose
// default, so the incompatible option is the one an operator is most likely
// to pick.
//
// The OSS policy can still be used, but the caller must build the client
// because a cluster-aware client cannot simply be the default here: the
// Enterprise policy blocks CLUSTER NODES and CLUSTER SLOTS, which is exactly
// how go-redis discovers topology, so enabling cluster mode unconditionally
// would break the supported policies instead. To opt in, take Options and
// set IsClusterMode before dialling:
//
//	opts, err := redisentra.Options(addr)
//	if err != nil {
//		return err
//	}
//	opts.IsClusterMode = true
//	client := redis.NewUniversalClient(opts)
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
// The client is not cluster-aware, so the instance must use the Enterprise or
// Non-clustered cluster policy; see the package documentation for why that is
// the default and how to opt in to the OSS policy.
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
