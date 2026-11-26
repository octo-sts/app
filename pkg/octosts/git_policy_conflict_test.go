// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package octosts

import (
	"crypto/sha1"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-github/v88/github"
	"github.com/octo-sts/app/pkg/ghinstall"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var conflictStages = []string{"metadata", "commit", "root-tree", "nested-tree", "blob"}

func conflictGitHandler(t *testing.T, stage string, code *atomic.Int32, hits *atomic.Int32) http.Handler {
	t.Helper()
	git := http.NewServeMux()
	fakePolicyGit(git, func(_, _ string) map[string]string {
		return map[string]string{
			".github/chainguard/foo.sts.yaml":               "issuer: https://example.com\nsubject: example\n",
			".github/chainguard/trusted-token-issuers.yaml": "issuers: [https://example.com]\n",
		}
	}, nil)
	root := fmt.Sprintf("%x", sha1.Sum([]byte("tree:")))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/v3/") {
			r = r.Clone(r.Context())
			r.URL.Path = strings.TrimPrefix(r.URL.Path, "/api/v3")
			r.URL.RawPath = strings.TrimPrefix(r.URL.RawPath, "/api/v3")
		}
		if strings.HasPrefix(r.URL.Path, "/app/installations/") {
			json.NewEncoder(w).Encode(github.InstallationToken{Token: new("token"), ExpiresAt: &github.Timestamp{Time: time.Now().Add(time.Hour)}})
			return
		}
		if r.URL.Path == "/installation/token" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		p := r.URL.Path
		matched := stage == "metadata" && strings.Count(strings.Trim(p, "/"), "/") == 2 && strings.HasPrefix(p, "/repos/") ||
			stage == "commit" && strings.HasSuffix(p, "/commits/heads/main") ||
			stage == "root-tree" && strings.HasSuffix(p, "/git/trees/"+root) ||
			stage == "nested-tree" && strings.Contains(p, "/git/trees/") && !strings.HasSuffix(p, "/git/trees/"+root) ||
			stage == "blob" && strings.Contains(p, "/git/blobs/")
		if matched {
			hits.Add(1)
			// Even rate-limit headers cannot turn a 409 into evidence of absence.
			w.Header().Set("Retry-After", "1")
			http.Error(w, "failure", int(code.Load()))
			return
		}
		git.ServeHTTP(w, r)
	})
}

func TestReadRegularPolicyConflictByStage(t *testing.T) {
	for _, stage := range conflictStages {
		for _, code := range []int{http.StatusConflict, http.StatusForbidden, http.StatusTooManyRequests} {
			t.Run(fmt.Sprintf("%s/%d", stage, code), func(t *testing.T) {
				var responseCode, hits atomic.Int32
				responseCode.Store(int32(code))
				server := httptest.NewServer(conflictGitHandler(t, stage, &responseCode, &hits))
				defer server.Close()
				client, err := newGitHubClient(server.Client().Transport, server.URL+"/")
				if err != nil {
					t.Fatal(err)
				}
				file, err := readRegularPolicy(t.Context(), client, "org", "repo", ".github/chainguard/foo.sts.yaml")
				if hits.Load() != 1 || file != nil || isContentsNotFound(err) {
					t.Fatalf("hits=%d file=%v err=%v", hits.Load(), file, err)
				}
				if code == http.StatusConflict {
					if !errors.Is(err, errUnsafePolicyPath) {
						t.Fatalf("want unsafe path, got %v", err)
					}
				} else {
					var response *github.ErrorResponse
					if !errors.As(err, &response) || response.Response.StatusCode != code {
						t.Fatalf("want HTTP %d unchanged, got %v", code, err)
					}
				}
			})
		}
	}
}

func TestPolicyConflictInvalidatesStale(t *testing.T) {
	for _, stage := range conflictStages {
		t.Run(stage, func(t *testing.T) {
			key := unreadableKey(t, "conflict-"+stage)
			staleTrustPolicies.Add(key, "stale policy")
			var code, hits atomic.Int32
			code.Store(http.StatusConflict)
			transport := newAppsTransport(t, conflictGitHandler(t, stage, &code, &hits))
			s := &sts{}
			raw, err := s.fetchTrustPolicyRawUncached(t.Context(), transport, 1234, key)
			if raw != "" || status.Code(err) != codes.Unavailable || hits.Load() != 1 {
				t.Fatalf("conflict: raw=%q err=%v hits=%d", raw, err, hits.Load())
			}
			if _, ok := staleTrustPolicies.Get(key); ok {
				t.Fatal("conflict retained stale policy")
			}
			if _, ok := trustPolicies.Get(key); ok {
				t.Fatal("conflict cached a policy or absence")
			}
			code.Store(http.StatusTooManyRequests)
			raw, err = s.fetchTrustPolicyRawUncached(t.Context(), transport, 1234, key)
			if raw != "" || status.Code(err) != codes.ResourceExhausted || hits.Load() != 2 {
				t.Fatalf("429 after conflict: raw=%q err=%v hits=%d", raw, err, hits.Load())
			}
			if _, ok := trustPolicies.Get(key); ok {
				t.Fatal("429 restored stale policy")
			}
		})
	}
}

func TestIssuerConflictInvalidatesStale(t *testing.T) {
	for _, stage := range conflictStages {
		for _, staleState := range []string{"absent", "present"} {
			t.Run(stage+"/"+staleState, func(t *testing.T) {
				owner := "issuer-conflict-" + stage + "-" + staleState
				cleanupOrgIssuers(t, owner)
				stale := absentOrgIssuerEntry()
				if staleState == "present" {
					allow, err := (&OrgTrustedIssuers{Issuers: []string{testGitHubIssuer}}).Compile()
					if err != nil {
						t.Fatal(err)
					}
					stale = presentOrgIssuerEntry(allow)
				}
				staleOrgIssuers.Add(owner, stale)
				var code, hits atomic.Int32
				code.Store(http.StatusConflict)
				transport := newAppsTransport(t, conflictGitHandler(t, stage, &code, &hits))
				s := &sts{router: routerFor(&enumMgr{installs: []ghinstall.Installation{{Transport: transport, ID: 1234, AppID: 10}}}, 1)}
				entry, err := s.orgIssuerLookup(t.Context(), owner)
				if err != nil || entry.state != orgIssuerInvalid || status.Code(entry.err) != codes.FailedPrecondition || hits.Load() != 1 {
					t.Fatalf("conflict: entry=%+v err=%v hits=%d", entry, err, hits.Load())
				}
				if _, ok := staleOrgIssuers.Get(owner); ok {
					t.Fatal("conflict retained stale issuer entry")
				}
				orgIssuers.Remove(owner) // Simulate expiry of the invalid primary entry.
				code.Store(http.StatusTooManyRequests)
				entry, err = s.orgIssuerLookup(t.Context(), owner)
				if status.Code(err) != codes.ResourceExhausted || hits.Load() != 2 {
					t.Fatalf("429 after conflict: entry=%+v err=%v hits=%d", entry, err, hits.Load())
				}
				if _, ok := orgIssuers.Get(owner); ok {
					t.Fatal("429 restored stale issuer entry")
				}
			})
		}
	}
}
