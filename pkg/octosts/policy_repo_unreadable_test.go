// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package octosts

import (
	"encoding/json"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bradleyfalzon/ghinstallation/v2"
	"github.com/google/go-github/v88/github"
	expirablelru "github.com/hashicorp/golang-lru/v2/expirable"
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
	mux.HandleFunc("/repos/", func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("policy read without a token: %s", r.URL.Path)
		http.Error(w, "policy read without a token", http.StatusInternalServerError)
	})
	return newAppsTransport(t, &fakeGitHub{mux: mux})
}

func newReadablePolicyTransport(t *testing.T) *ghinstallation.AppsTransport {
	t.Helper()
	const policy = "issuer: https://example.com\nsubject: example\n"
	mux := http.NewServeMux()
	mux.HandleFunc("/app/installations/{appID}/access_tokens", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(github.InstallationToken{
			Token:     new("test-installation-token"),
			ExpiresAt: &github.Timestamp{Time: time.Now().Add(10 * time.Minute)},
		})
	})
	mux.HandleFunc("/installation/token", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	fakePolicyGit(mux, func(_, _ string) map[string]string {
		return map[string]string{".github/chainguard/foo.sts.yaml": policy}
	}, nil)
	return newAppsTransport(t, &fakeGitHub{mux: mux})
}

// unreadableKey is a policy key on its own repository, so the per-repository
// unreadablePolicyRepos cache cannot leak into tests sharing org/repo.
func unreadableKey(t *testing.T, repo string) cacheTrustPolicyKey {
	t.Helper()
	key := cacheTrustPolicyKey{owner: "org", repo: repo, identity: "foo"}
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
	key := unreadableKey(t, "unreadable-then-readable")
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
	key := unreadableKey(t, "unreadable-everywhere")
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

// TestPolicyReadRotationIsCapped covers a pool larger than one request may
// walk: each request asks at most maxRetry further installations, the next
// request goes on with the ones not asked yet, and the repository is settled
// once every installation has answered.
func TestPolicyReadRotationIsCapped(t *testing.T) {
	key := unreadableKey(t, "unreadable-many-apps")
	repoKey := policyRepoKey{owner: key.owner, repo: key.repo}
	var mints atomic.Int32
	transports := make([]*ghinstallation.AppsTransport, 2*maxRetry)
	for i := range transports {
		transports[i] = newUnreadableRepoTransport(t, &mints)
	}

	if _, err := lookupWithPool(t, key, transports...); status.Code(err) != codes.NotFound {
		t.Fatalf("code = %v (%v), want NotFound", status.Code(err), err)
	}
	if got, want := mints.Load(), int32(1+maxRetry); got != want {
		t.Errorf("%d mints, want %d", got, want)
	}
	known := unreadablePolicyRepos.Get(repoKey)
	if known.all || len(known.installs) != 1+maxRetry {
		t.Fatalf("known = %+v, want %d installations and not settled", known, 1+maxRetry)
	}

	// The next request skips the installations that already answered and
	// asks the remaining ones, after which every installation has agreed.
	if _, err := lookupWithPool(t, key, transports...); status.Code(err) != codes.NotFound {
		t.Fatalf("code = %v (%v), want NotFound", status.Code(err), err)
	}
	if got, want := mints.Load(), int32(len(transports)); got != want {
		t.Errorf("%d mints after the second request, want %d", got, want)
	}
	if !unreadablePolicyRepos.Get(repoKey).all {
		t.Fatal("repository not settled although every installation answered")
	}

	if _, err := lookupWithPool(t, key, transports...); status.Code(err) != codes.NotFound {
		t.Fatalf("code = %v (%v), want NotFound", status.Code(err), err)
	}
	if got, want := mints.Load(), int32(len(transports)); got != want {
		t.Errorf("%d mints after the repository was settled, want %d", got, want)
	}
}

// TestPolicyReadReachesLaterAppOnNextRequest: a repository that only the last
// App of a large pool can see is read by the request that reaches it.
func TestPolicyReadReachesLaterAppOnNextRequest(t *testing.T) {
	key := unreadableKey(t, "readable-by-last-app")
	var mints atomic.Int32
	transports := make([]*ghinstallation.AppsTransport, 2*maxRetry)
	for i := range transports[:len(transports)-1] {
		transports[i] = newUnreadableRepoTransport(t, &mints)
	}
	transports[len(transports)-1] = newReadablePolicyTransport(t)

	if _, err := lookupWithPool(t, key, transports...); status.Code(err) != codes.NotFound {
		t.Fatalf("first request: code = %v (%v), want NotFound", status.Code(err), err)
	}
	id, err := lookupWithPool(t, key, transports...)
	if err != nil {
		t.Fatalf("second request: %v", err)
	}
	if want := int64(1234 + len(transports) - 1); id != want {
		t.Errorf("policy read by installation %d, want %d", id, want)
	}
	if got, want := mints.Load(), int32(len(transports)-1); got != want {
		t.Errorf("%d refused mints, want one per blind installation (%d)", got, want)
	}
}

// TestPolicyReadSkippedInstallIsNotRecordedAgain: a request that skips an
// installation already recorded must not extend the entry, or steady traffic
// would keep the installation skipped after the repository became visible.
func TestPolicyReadSkippedInstallIsNotRecordedAgain(t *testing.T) {
	key := unreadableKey(t, "skipped-not-rerecorded")
	repoKey := policyRepoKey{owner: key.owner, repo: key.repo}
	// Transports first: their key generation must not eat into the TTL.
	var mints atomic.Int32
	blind, readable := newUnreadableRepoTransport(t, &mints), newReadablePolicyTransport(t)
	const ttl = 500 * time.Millisecond
	saved := unreadablePolicyRepos
	unreadablePolicyRepos = &unreadableRepos{lru: expirablelru.NewLRU[policyRepoKey, unreadableRepo](200, nil, ttl)}
	t.Cleanup(func() { unreadablePolicyRepos = saved })
	unreadablePolicyRepos.Record(repoKey, 1234)
	recorded := time.Now()

	time.Sleep(ttl / 2)
	id, err := lookupWithPool(t, key, blind, readable)
	if err != nil || id != 1235 {
		t.Fatalf("lookup = (%d, %v), want read by 1235", id, err)
	}
	if got := mints.Load(); got != 0 {
		t.Errorf("%d mints, want 0: the recorded installation must be skipped", got)
	}

	time.Sleep(time.Until(recorded.Add(ttl + ttl/4)))
	if known := unreadablePolicyRepos.Get(repoKey); len(known.installs) != 0 {
		t.Errorf("known = %+v after the TTL, want the entry expired: the skipped installation was recorded again", known)
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
