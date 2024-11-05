// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package provider

import (
	"context"
	"fmt"
	"net/http"
	"testing"

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
	providers, _ = lru.New2Q[string, VerifierProvider](100)
)

type VerifierProvider interface {
	Verifier(config *oidc.Config) *oidc.IDTokenVerifier
}

func Get(ctx context.Context, issuer string) (provider VerifierProvider, err error) {
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

type keysetProvider struct {
	issuer string
	keySet oidc.KeySet
}

func (s *keysetProvider) Verifier(config *oidc.Config) *oidc.IDTokenVerifier {
	return oidc.NewVerifier(s.issuer, s.keySet, config)
}

// AddTestKeySetVerifier adds a test key set verifier to the provider cachef or the issuer.
// This is primarily intended for testing - the static key set is not verified against the upstream issuer.
func AddTestKeySetVerifier(t *testing.T, issuer string, keySet oidc.KeySet) {
	providers.Add(issuer, &keysetProvider{
		issuer: issuer,
		keySet: keySet,
	})
}
