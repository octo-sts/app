// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package octosts

import (
	"context"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const suspectPolicy = "issuer: https://example.com\nsubject: sub\n"

// shortSuspectDelays keeps the suspect-404 re-reads but drops their waits, so
// tests that reach them don't sleep for seconds.
func shortSuspectDelays(t *testing.T) {
	t.Helper()
	orig := suspectNotFoundDelays
	suspectNotFoundDelays = []time.Duration{time.Millisecond, time.Millisecond, time.Millisecond, time.Millisecond}
	t.Cleanup(func() { suspectNotFoundDelays = orig })
}

// countMints wraps a fake GitHub and counts installation token mints.
func countMints(h http.Handler) (http.Handler, *atomic.Int32) {
	var mints atomic.Int32
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/access_tokens") {
			mints.Add(1)
		}
		h.ServeHTTP(w, r)
	}), &mints
}

func suspectCount(outcome string) float64 {
	return testutil.ToFloat64(suspectNotFoundTotal.WithLabelValues(outcome))
}

// TestSuspectNotFoundRecovers covers #1866: a 404 for a policy read within the
// last hour is re-read with the same token, and when GitHub then finds it the
// exchange succeeds and nothing is negatively cached.
func TestSuspectNotFoundRecovers(t *testing.T) {
	shortSuspectDelays(t)
	key := freshTPKey(t, "suspect-recovers")
	staleTrustPolicies.Add(key, suspectPolicy)
	gh, contents := newFakeGitHubContents(suspectPolicy, http.StatusNotFound, http.StatusNotFound, http.StatusOK)
	h, mints := countMints(gh.mux)
	before := suspectCount("recovered")

	s := &sts{}
	raw, err := s.fetchTrustPolicyRaw(context.Background(), newAppsTransport(t, h), 1234, key)
	if err != nil {
		t.Fatalf("fetchTrustPolicyRaw: %v", err)
	}
	if raw != suspectPolicy {
		t.Errorf("raw = %q, want the policy", raw)
	}
	if got := contents.Load(); got != 3 {
		t.Errorf("contents calls = %d, want 3 (the 404, a second 404, then the policy)", got)
	}
	if got := mints.Load(); got != 1 {
		t.Errorf("token mints = %d, want 1 (re-reads reuse the token)", got)
	}
	if cached, ok := trustPolicies.Get(key); !ok || cached != suspectPolicy {
		t.Errorf("trustPolicies = (%q, %v), want the policy", cached, ok)
	}
	if got, ok := staleTrustPolicies.Get(key); !ok || got != suspectPolicy {
		t.Errorf("staleTrustPolicies = (%q, %v), want the policy", got, ok)
	}
	if got := suspectCount("recovered") - before; got != 1 {
		t.Errorf("recovered count rose by %v, want 1", got)
	}
}

// TestSuspectNotFoundPersists checks that a policy that is really gone still
// fails closed after the re-reads, as #1847 requires: NotFound, a negative
// cache entry, and no stale copy left to serve.
func TestSuspectNotFoundPersists(t *testing.T) {
	shortSuspectDelays(t)
	key := freshTPKey(t, "suspect-persists")
	staleTrustPolicies.Add(key, suspectPolicy)
	gh, contents := newFakeGitHubContents("", http.StatusNotFound)
	h, mints := countMints(gh.mux)
	before := suspectCount("not_found")

	s := &sts{}
	_, err := s.fetchTrustPolicyRaw(context.Background(), newAppsTransport(t, h), 1234, key)
	if got := status.Code(err); got != codes.NotFound {
		t.Fatalf("code = %v, want NotFound; err = %v", got, err)
	}
	if got, want := contents.Load(), int32(1+len(suspectNotFoundDelays)); got != want {
		t.Errorf("contents calls = %d, want %d (the first read and each re-read)", got, want)
	}
	if got := mints.Load(); got != 1 {
		t.Errorf("token mints = %d, want 1", got)
	}
	if cached, ok := trustPolicies.Get(key); !ok || cached != negativeCacheConst {
		t.Error("a persistent 404 did not seed the negative cache")
	}
	if _, ok := staleTrustPolicies.Get(key); ok {
		t.Error("a persistent 404 left the stale copy in place")
	}
	if got := suspectCount("not_found") - before; got != 1 {
		t.Errorf("not_found count rose by %v, want 1", got)
	}
}

// TestSuspectNotFoundOneRoundPerFetch checks the re-reads run once per fetch:
// when a re-read fails transiently and the backoff retries the read, a 404 on
// that retry is final rather than starting another round of waits.
func TestSuspectNotFoundOneRoundPerFetch(t *testing.T) {
	shortSuspectDelays(t)
	key := freshTPKey(t, "suspect-one-round")
	staleTrustPolicies.Add(key, suspectPolicy)
	gh, contents := newFakeGitHubContents("",
		http.StatusNotFound,            // first read: suspect
		http.StatusInternalServerError, // re-read: transient, ends the round
		http.StatusInternalServerError, // backoff retry
		http.StatusNotFound,            // backoff's last try: final
	)
	before := suspectCount("error")

	s := &sts{}
	_, err := s.fetchTrustPolicyRaw(context.Background(), newAppsTransport(t, gh.mux), 1234, key)
	if got := status.Code(err); got != codes.NotFound {
		t.Fatalf("code = %v, want NotFound; err = %v", got, err)
	}
	if got := contents.Load(); got != 4 {
		t.Errorf("contents calls = %d, want 4", got)
	}
	if cached, ok := trustPolicies.Get(key); !ok || cached != negativeCacheConst {
		t.Error("the final 404 did not seed the negative cache")
	}
	if got := suspectCount("error") - before; got != 1 {
		t.Errorf("error count rose by %v, want 1", got)
	}
}

// TestNotFoundWithoutStaleIsNotReread checks that a 404 for a policy this
// process hasn't read recently is final at once, so callers asking for
// policies that don't exist cost no extra GitHub reads.
func TestNotFoundWithoutStaleIsNotReread(t *testing.T) {
	shortSuspectDelays(t)
	key := freshTPKey(t, "never-read")
	gh, contents := newFakeGitHubContents("", http.StatusNotFound)
	before := suspectCount("not_found")

	s := &sts{}
	_, err := s.fetchTrustPolicyRaw(context.Background(), newAppsTransport(t, gh.mux), 1234, key)
	if got := status.Code(err); got != codes.NotFound {
		t.Fatalf("code = %v, want NotFound; err = %v", got, err)
	}
	if got := contents.Load(); got != 1 {
		t.Errorf("contents calls = %d, want 1", got)
	}
	if got := suspectCount("not_found") - before; got != 0 {
		t.Errorf("not_found count rose by %v, want 0", got)
	}
}

// TestSuspectNotFoundReadTimeout checks that when the shared read's deadline
// passes during the waits, the caller gets Unavailable and nothing is cached:
// no negative entry, and the stale copy stays, since nothing proved the
// policy gone.
func TestSuspectNotFoundReadTimeout(t *testing.T) {
	origDelays, origTimeout := suspectNotFoundDelays, policyReadTimeout
	suspectNotFoundDelays = []time.Duration{time.Hour}
	policyReadTimeout = 100 * time.Millisecond
	t.Cleanup(func() { suspectNotFoundDelays, policyReadTimeout = origDelays, origTimeout })

	key := freshTPKey(t, "suspect-timeout")
	staleTrustPolicies.Add(key, suspectPolicy)
	gh, _ := newFakeGitHubContents("", http.StatusNotFound)
	before := suspectCount("error")

	s := &sts{}
	_, err := s.fetchTrustPolicyRaw(context.Background(), newAppsTransport(t, gh.mux), 1234, key)
	if got := status.Code(err); got != codes.Unavailable {
		t.Fatalf("code = %v, want Unavailable; err = %v", got, err)
	}
	if _, ok := trustPolicies.Get(key); ok {
		t.Error("a timed-out read wrote to trustPolicies")
	}
	if _, ok := staleTrustPolicies.Get(key); !ok {
		t.Error("a timed-out read dropped the stale copy")
	}
	if got := suspectCount("error") - before; got != 1 {
		t.Errorf("error count rose by %v, want 1", got)
	}
}
