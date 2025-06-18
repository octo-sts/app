// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package provider

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/cenkalti/backoff/v5"
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
	provider, err = newProviderWithRetry(ctx, issuer)
	if err != nil {
		return nil, fmt.Errorf("constructing %q provider: %w", issuer, err)
	}

	// Once it is built, memoize the provider so that we hit the fast
	// path above on subsequent requests for verification.
	providers.Add(issuer, provider)

	return provider, nil
}

// newProviderWithRetry creates a new OIDC provider with exponential backoff retry logic
func newProviderWithRetry(ctx context.Context, issuer string) (VerifierProvider, error) {
	attempt := 0

	operation := func() (VerifierProvider, error) {
		attempt++
		p, err := oidc.NewProvider(ctx, issuer)
		if err != nil {
			clog.WarnContext(ctx, "provider creation failed", "attempt", attempt, "issuer", issuer, "error", err)
			// Check for permanent errors that shouldn't be retried
			if isPermanentError(err) {
				return nil, backoff.Permanent(err)
			}
			return nil, err
		}
		if attempt > 1 {
			clog.InfoContext(ctx, "provider creation succeeded after retry", "attempts", attempt, "issuer", issuer)
		}
		return p, nil
	}

	// Configure exponential backoff: 1s → 2s → 4s → 8s → 16s → 30s (max)
	// with ±10% jitter to prevent thundering herd issues
	expBackoff := backoff.NewExponentialBackOff()
	expBackoff.InitialInterval = 1 * time.Second
	expBackoff.MaxInterval = 30 * time.Second
	expBackoff.Multiplier = 2.0
	expBackoff.RandomizationFactor = 0.1

	return backoff.Retry(ctx, operation, backoff.WithBackOff(expBackoff))
}

// isPermanentError checks if an error should not be retried based on HTTP status codes
func isPermanentError(err error) bool {
	// String matching for HTTP status codes embedded in error messages
	// This matches go-oidc's pattern: fmt.Errorf("%s: %s", resp.Status, body)
	errMsg := err.Error()
	if strings.Contains(errMsg, "400 Bad Request") ||
		strings.Contains(errMsg, "401 Unauthorized") ||
		strings.Contains(errMsg, "403 Forbidden") ||
		strings.Contains(errMsg, "404 Not Found") ||
		strings.Contains(errMsg, "405 Method Not Allowed") ||
		strings.Contains(errMsg, "406 Not Acceptable") ||
		strings.Contains(errMsg, "410 Gone") ||
		strings.Contains(errMsg, "415 Unsupported Media Type") ||
		strings.Contains(errMsg, "422 Unprocessable Entity") ||
		strings.Contains(errMsg, "501 Not Implemented") {
		return true // Don't retry these permanent client/server errors
	}

	return false // Retry all other errors
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
func AddTestKeySetVerifier(_ *testing.T, issuer string, keySet oidc.KeySet) {
	providers.Add(issuer, &keysetProvider{
		issuer: issuer,
		keySet: keySet,
	})
}
