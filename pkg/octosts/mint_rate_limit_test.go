// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package octosts

import (
	"encoding/json"
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/bradleyfalzon/ghinstallation/v2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// rateLimitedMints are the ways GitHub answers an over-used token endpoint.
// None of them reach go-github's CheckResponse, so the mint fails with a
// *ghinstallation.HTTPError rather than a typed rate-limit error (#1890).
var rateLimitedMints = []struct {
	name   string
	code   int
	header map[string]string
	docURL string
}{
	{name: "429", code: http.StatusTooManyRequests},
	{name: "403 retry after", code: http.StatusForbidden, header: map[string]string{"Retry-After": "60"}},
	{name: "422 exhausted quota", code: http.StatusUnprocessableEntity, header: map[string]string{"X-RateLimit-Remaining": "0"}},
	{name: "403 secondary limit body", code: http.StatusForbidden, docURL: "https://docs.github.com/rest/using-the-rest-api/rate-limits-for-the-rest-api#about-secondary-rate-limits"},
}

// newRateLimitedMintTransport answers every token mint with code, header and
// docURL, and fails the test if anything reads the policy without a token.
func newRateLimitedMintTransport(t *testing.T, mints *atomic.Int32, code int, header map[string]string, docURL string) *ghinstallation.AppsTransport {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/app/installations/{appID}/access_tokens", func(w http.ResponseWriter, _ *http.Request) {
		mints.Add(1)
		for k, v := range header {
			w.Header().Set(k, v)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"message":           "rate limited",
			"documentation_url": docURL,
		})
	})
	mux.HandleFunc("/", func(_ http.ResponseWriter, r *http.Request) {
		t.Errorf("unexpected request without a token: %s", r.URL.Path)
	})
	return newAppsTransport(t, mux)
}

// TestPolicyReadRateLimitedMint pins #1890: a rate-limited mint is a rate
// limit, not a missing policy. With a stale copy it is served and seeds the
// primary cache, as for a rate-limited contents read; without one the caller
// gets ResourceExhausted, which lets lookupTrustPolicyWithRetry try another App.
func TestPolicyReadRateLimitedMint(t *testing.T) {
	const policy = "issuer: https://example.com\nsubject: sub\n"
	for _, tc := range rateLimitedMints {
		t.Run(tc.name, func(t *testing.T) {
			t.Run("no stale copy", func(t *testing.T) {
				key := freshTPKey(t, "mint-rate-limited")
				var mints atomic.Int32
				atr := newRateLimitedMintTransport(t, &mints, tc.code, tc.header, tc.docURL)

				s := &sts{}
				_, err := s.fetchTrustPolicyRaw(t.Context(), atr, 1234, key)
				if got := status.Code(err); got != codes.ResourceExhausted {
					t.Fatalf("code = %v (%v), want ResourceExhausted", got, err)
				}
				if got := mints.Load(); got != 1 {
					t.Errorf("mints = %d, want 1: a rate limit must not be retried on the same App", got)
				}
				if _, ok := trustPolicies.Get(key); ok {
					t.Error("a rate-limited mint was cached as the policy, or as missing")
				}
			})

			t.Run("stale copy", func(t *testing.T) {
				key := freshTPKey(t, "mint-rate-limited")
				staleTrustPolicies.Add(key, policy)
				var mints atomic.Int32
				atr := newRateLimitedMintTransport(t, &mints, tc.code, tc.header, tc.docURL)

				s := &sts{}
				raw, err := s.fetchTrustPolicyRaw(t.Context(), atr, 1234, key)
				if err != nil || raw != policy {
					t.Fatalf("fetchTrustPolicyRaw = (%q, %v), want the stale copy", raw, err)
				}
				if got, ok := trustPolicies.Get(key); !ok || got != policy {
					t.Errorf("primary cache = (%q, %t), want it seeded with the stale copy", got, ok)
				}
				if got := mints.Load(); got != 1 {
					t.Errorf("mints = %d, want 1", got)
				}
			})
		})
	}
}

// TestPolicyReadRateLimitedMintRotates pins that a rate-limited mint moves the
// read to another App, and that the rotation does not mint again on an App it
// already tried. The fake pool's first Get hands back the App the read started
// on, as a quota-based pick does when a secondary limit leaves its remaining
// quota high.
func TestPolicyReadRateLimitedMintRotates(t *testing.T) {
	key := unreadableKey(t, "mint-rate-limited-rotates")
	var mints atomic.Int32
	limited := newRateLimitedMintTransport(t, &mints, http.StatusForbidden, map[string]string{"Retry-After": "60"}, "")

	id, err := lookupWithPool(t, key, limited, newReadablePolicyTransport(t))
	if err != nil {
		t.Fatalf("lookupTrustPolicyWithRetry: %v", err)
	}
	if id != 1235 {
		t.Errorf("policy read by installation %d, want 1235", id)
	}
	if got := mints.Load(); got != 1 {
		t.Errorf("rate-limited App minted %d times, want 1", got)
	}
}
