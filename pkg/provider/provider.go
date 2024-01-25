/*
Copyright 2024 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package provider

import (
	"context"
	"fmt"

	"github.com/coreos/go-oidc/v3/oidc"
	lru "github.com/hashicorp/golang-lru"
)

var (
	// providers is an LRU cache of recently used providers.
	providers, _ = lru.New2Q(100 /* size */)
)

func Get(ctx context.Context, issuer string) (provider *oidc.Provider, err error) {
	// Return any verifiers that we have already constructed
	// to avoid paying for discovery again.
	if v, ok := providers.Get(issuer); ok {
		return v.(*oidc.Provider), nil
	}

	// Verify the token before we trust anything about it.
	provider, err = oidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, fmt.Errorf("constructing %q provider: %w", issuer, err)
	}

	// Once it is built, memoize the provider so that we hit the fast
	// path above on subsequent requests for verification.
	providers.Add(issuer, provider)

	return provider, nil
}
