// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package octosts

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/bradleyfalzon/ghinstallation/v2"
	"github.com/google/go-github/v88/github"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/octo-sts/app/pkg/ghinstall"
)

// newUnreadableRepoTransport is an installation that GitHub refuses a token for
// the policy repository, as it does for an App installed on selected
// repositories that do not include it, and for a repository that does not
// exist. mints counts the refused mints.
func newUnreadableRepoTransport(t *testing.T, mints *atomic.Int32) *ghinstallation.AppsTransport {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/app/installations/{appID}/access_tokens", func(w http.ResponseWriter, _ *http.Request) {
		mints.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = w.Write([]byte(`{"message":"There is at least one repository that does not exist or is not accessible to the parent installation."}`))
	})
	mux.HandleFunc("/repos/{org}/{repo}/contents/.github/chainguard/{identity}", func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("policy read without a token: %s", r.URL.Path)
	})
	return newAppsTransport(t, &fakeGitHub{mux: mux})
}

func newReadablePolicyTransport(t *testing.T) *ghinstallation.AppsTransport {
	t.Helper()
	const policy = "issuer: https://example.com\nsubject: example\n"
	return newPolicyReadTransport(t, func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(github.RepositoryContent{
			Content:  new(base64.StdEncoding.EncodeToString([]byte(policy))),
			Type:     new("file"),
			Encoding: new("base64"),
		})
	})
}

// unreadableKey is a policy key on its own repository, so the per-repository
// unreadablePolicyRepos cache cannot leak into tests sharing org/repo.
func unreadableKey(t *testing.T, repo, identity string) cacheTrustPolicyKey {
	t.Helper()
	key := cacheTrustPolicyKey{owner: "org", repo: repo, identity: identity}
	clear := func() {
		trustPolicies.Remove(key)
		staleTrustPolicies.Remove(key)
		forbiddenPolicies.Remove(key)
		unreadablePolicyRepos.Remove(policyRepoKey{owner: key.owner, repo: key.repo})
	}
	clear()
	t.Cleanup(clear)
	return key
}

func lookupWithPool(t *testing.T, key cacheTrustPolicyKey, transports ...*ghinstallation.AppsTransport) (int64, error) {
	t.Helper()
	pool := &ghinstall.OrgPool{
		M:        &sequentialInstallMgr{transports: transports},
		AppCount: len(transports),
	}
	s := &sts{}
	_, id, err := s.lookupTrustPolicyWithRetry(t.Context(), pool, transports[0], 1234, key.owner, key.owner+"/"+key.repo, key.identity, key, &TrustPolicy{})
	return id, err
}

func TestPolicyReadTriesNextAppWhenRepoUnreadable(t *testing.T) {
	key := unreadableKey(t, "unreadable-then-readable", "foo")
	var mints atomic.Int32

	id, err := lookupWithPool(t, key, newUnreadableRepoTransport(t, &mints), newReadablePolicyTransport(t))
	if err != nil {
		t.Fatalf("lookupTrustPolicyWithRetry: %v", err)
	}
	if id != 1235 {
		t.Errorf("policy read by installation %d, want 1235", id)
	}
}

func TestPolicyReadUnreadableEverywhere(t *testing.T) {
	key := unreadableKey(t, "unreadable-everywhere", "foo")
	var mints atomic.Int32
	first, second := newUnreadableRepoTransport(t, &mints), newUnreadableRepoTransport(t, &mints)

	_, err := lookupWithPool(t, key, first, second)
	// The same answer as a missing policy, so callers cannot tell whether a
	// private repository exists.
	if got := status.Code(err); got != codes.NotFound {
		t.Fatalf("code = %v (%v), want NotFound", got, err)
	}
	// The failure says nothing about the policy, so it must not be cached as
	// absent for the identity.
	if _, ok := trustPolicies.Get(key); ok {
		t.Error("an unreadable repository was cached as a missing policy")
	}
	if got := mints.Load(); got != 2 {
		t.Fatalf("%d mints, want one per installation", got)
	}

	// Every installation agreed, so the next request for the repository, even
	// for another identity, mints nothing.
	other := cacheTrustPolicyKey{owner: key.owner, repo: key.repo, identity: "bar"}
	if _, err := lookupWithPool(t, other, first, second); status.Code(err) != codes.NotFound {
		t.Fatalf("code = %v (%v), want NotFound", status.Code(err), err)
	}
	if got := mints.Load(); got != 2 {
		t.Errorf("%d mints after the repository was known unreadable, want 2", got)
	}
}

func TestPolicyReadRotationIsCapped(t *testing.T) {
	key := unreadableKey(t, "unreadable-many-apps", "foo")
	var mints atomic.Int32
	transports := make([]*ghinstallation.AppsTransport, maxRetry+3)
	for i := range transports {
		transports[i] = newUnreadableRepoTransport(t, &mints)
	}

	if _, err := lookupWithPool(t, key, transports...); status.Code(err) != codes.NotFound {
		t.Fatalf("code = %v (%v), want NotFound", status.Code(err), err)
	}
	if got, want := mints.Load(), int32(1+maxRetry); got != want {
		t.Errorf("%d mints, want %d", got, want)
	}
	// Not every installation answered, so the repository is not cached.
	if _, ok := unreadablePolicyRepos.Get(policyRepoKey{owner: key.owner, repo: key.repo}); ok {
		t.Error("repository cached as unreadable without every installation agreeing")
	}
}

func TestIsUnreadableRepoMint(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		header http.Header
		want   bool
	}{
		{name: "422", status: http.StatusUnprocessableEntity, want: true},
		{name: "rate-limited 422", status: http.StatusUnprocessableEntity, header: http.Header{"X-Ratelimit-Remaining": {"0"}}, want: false},
		{name: "403", status: http.StatusForbidden, want: false},
		{name: "404", status: http.StatusNotFound, want: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := &ghinstallation.HTTPError{Response: &http.Response{StatusCode: tc.status, Header: tc.header}}
			if got := isUnreadableRepoMint(err); got != tc.want {
				t.Errorf("isUnreadableRepoMint = %v, want %v", got, tc.want)
			}
		})
	}
}
