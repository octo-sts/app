// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package provider

import (
	"context"
	"fmt"
	"net/http"

	"github.com/chainguard-dev/clog"
	"github.com/chainguard-dev/terraform-infra-common/pkg/httpmetrics"
	"github.com/coreos/go-oidc/v3/oidc"
	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/octo-sts/app/pkg/maxsize"
)

// MaximumResponseSize is the maximum size of allowed responses from
// OIDC providers.  Some anecdata
//   - Google: needs around 1KiB
//   - GitHub: needs around 5KiB
//   - Chainguard: needs around 2KiB
const MaximumResponseSize = 100 * 1024 // 100KiB

var (
	// providers is an LRU cache of recently used providers.
	providers, _ = lru.New2Q[string, *oidc.Provider](100)
)

func Get(ctx context.Context, issuer string) (provider *oidc.Provider, err error) {
	// Return any verifiers that we have already constructed
	// to avoid paying for discovery again.
	if v, ok := providers.Get(issuer); ok {
		clog.InfoContext(ctx, "found provider in cache")
		return v, nil
	}

	ctx = oidc.ClientContext(ctx, &http.Client{
		Transport: maxsize.NewRoundTripper(MaximumResponseSize, httpmetrics.Transport),
	})

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
