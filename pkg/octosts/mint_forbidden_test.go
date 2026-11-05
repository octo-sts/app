// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package octosts

import (
	"encoding/json"
	"net/http"
	"sync/atomic"
	"testing"

	v1 "chainguard.dev/sdk/proto/platform/oidc/v1"
	"github.com/octo-sts/app/pkg/ghinstall"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Exercise both mint points with a warm org-issuer cache: otherwise the issuer
// lookup rejects the exchange before either affected path can run.
func TestExchangeMintForbidden(t *testing.T) {
	const policy = "issuer: https://token.actions.githubusercontent.com\nsubject: foo\naudience: octosts\npermissions:\n  contents: read\n"
	const diagnostic = "GitHub denied access to org (403): check the org's IP allow list, or whether the octo-sts installation is suspended"
	for _, finalMint := range []bool{false, true} {
		stage := "policy"
		if finalMint {
			stage = "final"
		}
		t.Run(stage, func(t *testing.T) {
			for _, tc := range []struct {
				name   string
				scope  string
				header map[string]string
				docURL string
			}{
				{name: "permission denied"},
				{name: "permission denied normalized scope", scope: "./org/repo"},
				{name: "permission denied org scope", scope: "org"},
				{name: "retry after", header: map[string]string{"Retry-After": "60"}},
				{name: "exhausted quota", header: map[string]string{"X-RateLimit-Remaining": "0"}},
				{name: "secondary limit", docURL: "https://docs.github.com/rest/using-the-rest-api/rate-limits-for-the-rest-api#about-secondary-rate-limits"},
				{name: "abuse limit", docURL: "https://docs.github.com/rest/overview/resources-in-the-rest-api#abuse-rate-limits"},
			} {
				t.Run(tc.name, func(t *testing.T) {
					key := freshTPKey(t, "foo")
					cleanupOrgIssuers(t, key.owner)
					orgIssuers.Add(key.owner, absentOrgIssuerEntry())
					staleTrustPolicies.Add(key, policy)
					if finalMint {
						trustPolicies.Add(key, policy)
					}

					var mintCalls, otherCalls atomic.Int32
					mux := http.NewServeMux()
					mux.HandleFunc("/app/installations/{appID}/access_tokens", func(w http.ResponseWriter, _ *http.Request) {
						mintCalls.Add(1)
						for k, v := range tc.header {
							w.Header().Set(k, v)
						}
						w.Header().Set("Content-Type", "application/json")
						w.WriteHeader(http.StatusForbidden)
						json.NewEncoder(w).Encode(map[string]string{
							"message":           "private GitHub response body",
							"documentation_url": tc.docURL,
						})
					})
					mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
						otherCalls.Add(1)
						w.WriteHeader(http.StatusInternalServerError)
					})
					atr := newAppsTransport(t, mux)
					pool := &ghinstall.OrgPool{M: &fakeInstallMgr{atr: atr}, AppCount: 2}
					s := &sts{router: ghinstall.NewOrgRouter(map[string]*ghinstall.OrgPool{key.owner: pool})}
					ctx := newExchangeContext(t)
					scope := tc.scope
					if scope == "" {
						scope = key.owner + "/" + key.repo
					}
					if scope == key.owner {
						// Keep the org-scoped policy under the same isolated cache key.
						s.orgPolicyRepo = key.repo
					}
					denied := tc.header == nil && tc.docURL == ""
					wantCode := codes.NotFound
					wantMessage := `unable to find trust policy for "foo"`
					if finalMint {
						wantCode, wantMessage = codes.Internal, "failed to get token"
					}
					if denied {
						wantCode, wantMessage = codes.PermissionDenied, diagnostic
					}
					for range 2 {
						token, err := s.Exchange(ctx, &v1.ExchangeRequest{Identity: key.identity, Scopes: []string{scope}})
						if token != nil || status.Code(err) != wantCode || status.Convert(err).Message() != wantMessage {
							t.Fatalf("Exchange() = (%v, %v), want no token and %v: %q", token, err, wantCode, wantMessage)
						}
					}
					wantMints := int32(2)
					if denied && !finalMint {
						wantMints = 1
					}
					if got := mintCalls.Load(); got != wantMints {
						t.Errorf("mint calls = %d, want %d", got, wantMints)
					}
					if got := otherCalls.Load(); got != 0 {
						t.Errorf("non-mint requests = %d, want 0", got)
					}
					if _, ok := forbiddenPolicies.Get(key); ok != (denied && !finalMint) {
						t.Errorf("forbidden cooldown present = %t, want %t", ok, denied && !finalMint)
					}
					if raw, ok := staleTrustPolicies.Get(key); ok != (!denied || finalMint) || (ok && raw != policy) {
						t.Errorf("stale policy = (%q, %t), want present = %t", raw, ok, !denied || finalMint)
					}
					if !finalMint {
						if _, ok := trustPolicies.Get(key); ok {
							t.Error("failed mint populated the primary policy cache")
						}
					}
				})
			}
		})
	}
}
