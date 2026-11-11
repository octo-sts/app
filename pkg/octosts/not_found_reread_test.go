// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package octosts

import (
	"context"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TestMain keeps every 404 re-read in this package's tests but drops the
// waits between them, so tests that reach a 404 don't sleep for seconds.
// Tests that need the real waits set notFoundRereadDelays themselves.
func TestMain(m *testing.M) {
	notFoundRereadDelays = []time.Duration{time.Millisecond, time.Millisecond}
	os.Exit(m.Run())
}

const rereadPolicy = "issuer: https://example.com\nsubject: sub\n"

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

func rereadCount(outcome, known string) float64 {
	return testutil.ToFloat64(notFoundRereadTotal.WithLabelValues(outcome, known))
}

// TestNotFoundRereadRecovers covers #1866: a 404 is re-read with the same
// token, and when GitHub then finds the policy the exchange succeeds and
// nothing is negatively cached. It runs both with a stale copy (the policy
// was read within the last hour) and without one (a new instance, or an
// evicted entry).
func TestNotFoundRereadRecovers(t *testing.T) {
	for _, tc := range []struct {
		name  string
		stale bool
		known string
	}{
		{"read within the last hour", true, "true"},
		{"not read recently", false, "false"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key := freshTPKey(t, "reread-recovers")
			if tc.stale {
				staleTrustPolicies.Add(key, rereadPolicy)
			}
			gh, contents := newFakeGitHubContents(rereadPolicy, http.StatusNotFound, http.StatusNotFound, http.StatusOK)
			h, mints := countMints(gh.mux)
			before := rereadCount("recovered", tc.known)

			s := &sts{}
			raw, err := s.fetchTrustPolicyRaw(context.Background(), newAppsTransport(t, h), 1234, key)
			if err != nil {
				t.Fatalf("fetchTrustPolicyRaw: %v", err)
			}
			if raw != rereadPolicy {
				t.Errorf("raw = %q, want the policy", raw)
			}
			if got := contents.Load(); got != 3 {
				t.Errorf("contents calls = %d, want 3 (a 404, a re-read 404, then the policy)", got)
			}
			if got := mints.Load(); got != 1 {
				t.Errorf("token mints = %d, want 1 (re-reads reuse the token)", got)
			}
			if cached, ok := trustPolicies.Get(key); !ok || cached != rereadPolicy {
				t.Errorf("trustPolicies = (%q, %v), want the policy", cached, ok)
			}
			if got, ok := staleTrustPolicies.Get(key); !ok || got != rereadPolicy {
				t.Errorf("staleTrustPolicies = (%q, %v), want the policy", got, ok)
			}
			if got := rereadCount("recovered", tc.known) - before; got != 1 {
				t.Errorf("recovered{known=%s} rose by %v, want 1", tc.known, got)
			}
		})
	}
}

// TestNotFoundRereadPersists checks that a policy that is really gone still
// fails closed after the re-reads, as #1847 requires: NotFound, a negative
// cache entry, and no stale copy left to serve.
func TestNotFoundRereadPersists(t *testing.T) {
	key := freshTPKey(t, "reread-persists")
	staleTrustPolicies.Add(key, rereadPolicy)
	gh, contents := newFakeGitHubContents("", http.StatusNotFound)
	h, mints := countMints(gh.mux)
	before := rereadCount("not_found", "true")

	s := &sts{}
	_, err := s.fetchTrustPolicyRaw(context.Background(), newAppsTransport(t, h), 1234, key)
	if got := status.Code(err); got != codes.NotFound {
		t.Fatalf("code = %v, want NotFound; err = %v", got, err)
	}
	if got, want := contents.Load(), int32(1+len(notFoundRereadDelays)); got != want {
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
	if got := rereadCount("not_found", "true") - before; got != 1 {
		t.Errorf("not_found{known=true} rose by %v, want 1", got)
	}
}

// TestNotFoundRereadNegativeCacheStopsRereads checks that once a missing
// policy is negatively cached, later exchanges don't read GitHub at all, so
// the re-reads cost a missing policy at most once per negative-cache TTL.
func TestNotFoundRereadNegativeCacheStopsRereads(t *testing.T) {
	key := freshTPKey(t, "reread-never-existed")
	gh, contents := newFakeGitHubContents("", http.StatusNotFound)
	atr := newAppsTransport(t, gh.mux)
	before := rereadCount("not_found", "false")

	s := &sts{}
	for i := range 3 {
		if _, err := s.fetchTrustPolicyRaw(context.Background(), atr, 1234, key); status.Code(err) != codes.NotFound {
			t.Fatalf("exchange %d: code = %v, want NotFound", i+1, status.Code(err))
		}
	}
	if got, want := contents.Load(), int32(1+len(notFoundRereadDelays)); got != want {
		t.Errorf("contents calls = %d, want %d (one round, then the negative cache)", got, want)
	}
	if got := rereadCount("not_found", "false") - before; got != 1 {
		t.Errorf("not_found{known=false} rose by %v, want 1", got)
	}
}

// TestNotFoundRereadOneRoundPerFetch checks the re-reads run once per fetch:
// when a re-read fails transiently and the backoff retries the read, a 404 on
// that retry is final rather than starting another round of waits.
func TestNotFoundRereadOneRoundPerFetch(t *testing.T) {
	key := freshTPKey(t, "reread-one-round")
	gh, contents := newFakeGitHubContents("",
		http.StatusNotFound,            // first read
		http.StatusInternalServerError, // re-read: transient, ends the round
		http.StatusInternalServerError, // backoff retry
		http.StatusNotFound,            // backoff's last try: final
	)
	before := rereadCount("error", "false")

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
	if got := rereadCount("error", "false") - before; got != 1 {
		t.Errorf("error{known=false} rose by %v, want 1", got)
	}
}

// TestNotFoundRereadReadTimeout checks that when the shared read's deadline
// passes during the waits, the caller gets Unavailable and nothing is cached:
// no negative entry, and the stale copy stays, since nothing proved the
// policy gone.
func TestNotFoundRereadReadTimeout(t *testing.T) {
	origDelays, origTimeout := notFoundRereadDelays, policyReadTimeout
	notFoundRereadDelays = []time.Duration{time.Hour}
	policyReadTimeout = 100 * time.Millisecond
	t.Cleanup(func() { notFoundRereadDelays, policyReadTimeout = origDelays, origTimeout })

	key := freshTPKey(t, "reread-timeout")
	staleTrustPolicies.Add(key, rereadPolicy)
	gh, _ := newFakeGitHubContents("", http.StatusNotFound)
	before := rereadCount("error", "true")

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
	if got := rereadCount("error", "true") - before; got != 1 {
		t.Errorf("error{known=true} rose by %v, want 1", got)
	}
}
