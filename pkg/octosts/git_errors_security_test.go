// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package octosts

import (
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/octo-sts/app/pkg/ghinstall"
)

// Override one Git endpoint while retaining real tree traversal and token minting.
func gitErrorHandler(endpoint string, code int, hits *atomic.Int32) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/app/installations/{id}/access_tokens", defaultOrgFakeMint)
	fakePolicyGit(mux, func(_, repo string) map[string]string {
		if repo == ".github" {
			return map[string]string{OrgTrustedIssuersPath(DefaultPolicyDir): "issuers:\n  - https://example.com\n"}
		}
		return map[string]string{DefaultPolicyDir + "/git-error.sts.yaml": "issuer: https://example.com\nsubject: sub\n"}
	}, nil)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/git/"+endpoint+"/") {
			hits.Add(1)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(code)
			fmt.Fprint(w, `{"message":"injected failure"}`)
			return
		}
		mux.ServeHTTP(w, r)
	})
}

func TestGitErrorsOrgIssuerLookup(t *testing.T) {
	for _, endpoint := range []string{"trees", "blobs"} {
		for _, tc := range []struct {
			code     int
			wantKind fetchKind
			wantCode codes.Code
		}{
			{http.StatusForbidden, fetchForbidden, codes.PermissionDenied},
			{http.StatusTooManyRequests, fetchRateLimited, codes.ResourceExhausted},
		} {
			t.Run(fmt.Sprintf("%s/%d", endpoint, tc.code), func(t *testing.T) {
				const owner = "git-error-issuer"
				cleanupOrgIssuers(t, owner)
				var hits atomic.Int32
				atr := newAppsTransport(t, gitErrorHandler(endpoint, tc.code, &hits))
				s := &sts{router: routerFor(&enumMgr{installs: []ghinstall.Installation{{Transport: atr, ID: 1234, AppID: 10}}}, 1)}

				res := s.fetchOrgIssuersOnce(t.Context(), atr, 1234, owner)
				if res.kind != tc.wantKind || res.entry.state != orgIssuerUnknown || status.Code(res.err) != tc.wantCode {
					t.Fatalf("fetch = %+v, want %v, Unknown, %v", res, tc.wantKind, tc.wantCode)
				}
				entry, err := s.orgIssuerLookup(t.Context(), owner)
				if entry.state != orgIssuerUnknown || status.Code(err) != tc.wantCode {
					t.Fatalf("lookup = (%+v, %v), want Unknown, %v", entry, err, tc.wantCode)
				}
				if got := hits.Load(); got != 2 {
					t.Errorf("failed %s requests = %d, want 2", endpoint, got)
				}
				if _, ok := orgIssuers.Get(owner); ok {
					t.Error("failed lookup populated primary allowlist cache")
				}
				if _, ok := staleOrgIssuers.Get(owner); ok {
					t.Error("failed lookup populated stale allowlist cache")
				}

				allow, err := (&OrgTrustedIssuers{Issuers: []string{testGitHubIssuer}}).Compile()
				if err != nil {
					t.Fatalf("Compile() = %v", err)
				}
				staleOrgIssuers.Add(owner, presentOrgIssuerEntry(allow))
				entry, err = s.orgIssuerLookup(t.Context(), owner)
				if err != nil || entry.state != orgIssuerPresent || entry.allow != allow {
					t.Fatalf("lookup with stale = (%+v, %v), want stale Present", entry, err)
				}
				if got := hits.Load(); got != 3 {
					t.Errorf("failed %s requests with stale = %d, want 3", endpoint, got)
				}
				if _, ok := orgIssuers.Get(owner); ok {
					t.Error("stale fallback populated primary allowlist cache")
				}
				if cached, ok := staleOrgIssuers.Get(owner); !ok || cached.state != orgIssuerPresent || cached.allow != allow {
					t.Errorf("stale allowlist cache = (%+v, %v), want original Present", cached, ok)
				}
			})
		}
	}
}

func TestGitErrorsTrustPolicy(t *testing.T) {
	const policy = "issuer: https://example.com\nsubject: sub\n"
	for _, endpoint := range []string{"trees", "blobs"} {
		for _, code := range []int{http.StatusForbidden, http.StatusTooManyRequests} {
			for _, stale := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%d/stale=%t", endpoint, code, stale), func(t *testing.T) {
					key := freshTPKey(t, "git-error")
					if stale {
						staleTrustPolicies.Add(key, policy)
					}
					var hits atomic.Int32
					atr := newAppsTransport(t, gitErrorHandler(endpoint, code, &hits))
					raw, err := (&sts{}).fetchTrustPolicyRaw(t.Context(), atr, 1234, key)

					wantCode, wantRaw := codes.PermissionDenied, ""
					if code == http.StatusTooManyRequests {
						wantCode = codes.ResourceExhausted
						if stale {
							wantCode, wantRaw = codes.OK, policy
						}
					}
					if status.Code(err) != wantCode || raw != wantRaw {
						t.Fatalf("fetch = (%q, %v), want (%q, %v)", raw, err, wantRaw, wantCode)
					}
					if got := hits.Load(); got != 1 {
						t.Errorf("failed %s requests = %d, want 1", endpoint, got)
					}
					cached, ok := trustPolicies.Get(key)
					wantCached := code == http.StatusTooManyRequests && stale
					if ok != wantCached || (ok && cached != policy) {
						t.Errorf("primary cache = (%q, %v), want cached policy = %v", cached, ok, wantCached)
					}
					cached, ok = staleTrustPolicies.Get(key)
					wantStale := code == http.StatusTooManyRequests && stale
					if ok != wantStale || (ok && cached != policy) {
						t.Errorf("stale cache = (%q, %v), want cached policy = %v", cached, ok, wantStale)
					}
					_, forbidden := forbiddenPolicies.Get(key)
					if forbidden != (code == http.StatusForbidden) {
						t.Errorf("forbidden cooldown = %v, want %v", forbidden, code == http.StatusForbidden)
					}
				})
			}
		}
	}
}
