// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package octosts

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bradleyfalzon/ghinstallation/v2"
	"github.com/google/go-github/v88/github"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// newFakeGitHubContents returns a fake GitHub whose contents endpoint responds
// with statuses[i] on the i-th call, clamping to the last entry once exhausted.
// A 200 serves policy; any other code is returned as a github.ErrorResponse so
// go-github surfaces it the way real GitHub does. The counter records contents
// calls so a test can assert how many attempts fetchTrustPolicyRaw made.
func newFakeGitHubContents(policy string, statuses ...int) (*fakeGitHub, *atomic.Int32) {
	var counter atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/app/installations", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode([]github.Installation{{
			ID:      new(int64(1234)),
			Account: &github.User{Login: new("org")},
		}})
	})
	mux.HandleFunc("/app/installations/{appID}/access_tokens", func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(github.InstallationToken{
			Token:     new(base64.StdEncoding.EncodeToString(b)),
			ExpiresAt: &github.Timestamp{Time: time.Now().Add(10 * time.Minute)},
		})
	})
	mux.HandleFunc("/repos/{org}/{repo}/contents/.github/chainguard/{identity}", func(w http.ResponseWriter, _ *http.Request) {
		n := int(counter.Add(1)) - 1
		code := statuses[min(n, len(statuses)-1)]
		if code == http.StatusOK {
			json.NewEncoder(w).Encode(github.RepositoryContent{
				Content:  new(base64.StdEncoding.EncodeToString([]byte(policy))),
				Type:     new("file"),
				Encoding: new("base64"),
			})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		json.NewEncoder(w).Encode(github.ErrorResponse{
			Response: &http.Response{StatusCode: code},
			Message:  http.StatusText(code),
		})
	})
	mux.HandleFunc("/installation/token", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotImplemented)
		fmt.Fprintf(io.MultiWriter(w, os.Stdout), "%s %s not implemented\n", r.Method, r.URL.Path)
	})
	return &fakeGitHub{mux: mux}, &counter
}

func freshTPKey(t *testing.T, identity string) cacheTrustPolicyKey {
	key := cacheTrustPolicyKey{owner: "org", repo: "repo", identity: identity}
	trustPolicies.Remove(key)
	staleTrustPolicies.Remove(key)
	t.Cleanup(func() {
		trustPolicies.Remove(key)
		staleTrustPolicies.Remove(key)
	})
	return key
}

// TestFetchTrustPolicyRawRetriesTransient covers GHSA-issue #1589: a persistent
// 5xx must be retried same-app and reported as Unavailable, not NotFound.
func TestFetchTrustPolicyRawRetriesTransient(t *testing.T) {
	key := freshTPKey(t, "boom")
	gh, counter := newFakeGitHubContents("", http.StatusInternalServerError)
	atr := newAppsTransport(t, gh)
	s := &sts{}

	_, err := s.fetchTrustPolicyRaw(context.Background(), atr, 1234, key)
	if got := status.Code(err); got != codes.Unavailable {
		t.Fatalf("code = %v, want Unavailable; err = %v", got, err)
	}
	if got := counter.Load(); got != int32(maxRetry) {
		t.Errorf("contents calls = %d, want %d (bounded retry)", got, maxRetry)
	}
	// A transient failure must never poison the negative cache.
	if _, ok := trustPolicies.Get(key); ok {
		t.Error("transient failure seeded the trust policy cache; it must not")
	}
}

// TestFetchTrustPolicyRawRecoversAfterTransient proves the retry actually heals
// a blip rather than merely reclassifying it.
func TestFetchTrustPolicyRawRecoversAfterTransient(t *testing.T) {
	key := freshTPKey(t, "flaky")
	const policy = "issuer: https://example.com\nsubject: sub\n"
	gh, counter := newFakeGitHubContents(policy, http.StatusBadGateway, http.StatusOK)
	atr := newAppsTransport(t, gh)
	s := &sts{}

	raw, err := s.fetchTrustPolicyRaw(context.Background(), atr, 1234, key)
	if err != nil {
		t.Fatalf("fetchTrustPolicyRaw = %v, want success after one retry", err)
	}
	if raw != policy {
		t.Errorf("raw = %q, want %q", raw, policy)
	}
	if got := counter.Load(); got != 2 {
		t.Errorf("contents calls = %d, want 2 (one failure, one success)", got)
	}
}

// TestFetchTrustPolicyRawNotFoundNotRetried keeps the 404 path fast and
// negative-cached: a real 404 must not be retried as if it were transient.
func TestFetchTrustPolicyRawNotFoundNotRetried(t *testing.T) {
	key := freshTPKey(t, "missing")
	gh, counter := newFakeGitHubContents("", http.StatusNotFound)
	atr := newAppsTransport(t, gh)
	s := &sts{}

	_, err := s.fetchTrustPolicyRaw(context.Background(), atr, 1234, key)
	if got := status.Code(err); got != codes.NotFound {
		t.Fatalf("code = %v, want NotFound; err = %v", got, err)
	}
	if got := counter.Load(); got != 1 {
		t.Errorf("contents calls = %d, want 1 (404 is not retried)", got)
	}
	if cached, ok := trustPolicies.Get(key); !ok || cached != negativeCacheConst {
		t.Error("404 did not seed the negative cache")
	}
}

// TestFetchTrustPolicyRawServesStaleOnRateLimit covers the rate-limit stale path
// after the retry refactor: it serves stale without retrying, and the fresh-only
// cache writes mean the stale entry's TTL is not renewed on the serve. A 429 is a
// proven rate limit; a bare 403 is not and is covered by the forbidden test below.
func TestFetchTrustPolicyRawServesStaleOnRateLimit(t *testing.T) {
	key := freshTPKey(t, "stale-me")
	const policy = "issuer: https://example.com\nsubject: sub\n"
	staleTrustPolicies.Add(key, policy) // stale present, primary empty
	gh, counter := newFakeGitHubContents("", http.StatusTooManyRequests)
	atr := newAppsTransport(t, gh)
	s := &sts{}

	raw, err := s.fetchTrustPolicyRaw(context.Background(), atr, 1234, key)
	if err != nil || raw != policy {
		t.Fatalf("fetchTrustPolicyRaw = (%q, %v), want stale (%q, nil)", raw, err, policy)
	}
	if got := counter.Load(); got != 1 {
		t.Errorf("contents calls = %d, want 1 (rate limit is not retried)", got)
	}
}

// TestFetchTrustPolicyRawForbiddenFailsClosed covers issue #1320: a bare 403 is a
// permission failure, not a rate limit. It must surface as PermissionDenied, not
// ResourceExhausted, must not be retried, and must fail closed by refusing to
// serve a stale policy even when one is cached (access may have been revoked).
func TestFetchTrustPolicyRawForbiddenFailsClosed(t *testing.T) {
	key := freshTPKey(t, "forbidden")
	const policy = "issuer: https://example.com\nsubject: sub\n"
	staleTrustPolicies.Add(key, policy) // stale present but must NOT be served
	gh, counter := newFakeGitHubContents("", http.StatusForbidden)
	atr := newAppsTransport(t, gh)
	s := &sts{}

	raw, err := s.fetchTrustPolicyRaw(context.Background(), atr, 1234, key)
	if got := status.Code(err); got != codes.PermissionDenied {
		t.Fatalf("code = %v, want PermissionDenied; err = %v", got, err)
	}
	if raw != "" {
		t.Errorf("raw = %q, want empty (stale must not be served on a 403)", raw)
	}
	if got := counter.Load(); got != 1 {
		t.Errorf("contents calls = %d, want 1 (a 403 is not retried)", got)
	}
	// A 403 is not a definitive "no policy" answer, so it must not poison the
	// negative cache the way a 404 does.
	if _, ok := trustPolicies.Get(key); ok {
		t.Error("a 403 seeded the trust policy cache; it must not")
	}
	// Failing closed means dropping the stale copy too: access may have been
	// revoked, so a later rate limit must not be able to resurrect it.
	if _, ok := staleTrustPolicies.Get(key); ok {
		t.Error("a 403 left the stale trust policy in place; it must drop it")
	}
}

// TestFetchTrustPolicyRawForbiddenThenRateLimitDoesNotResurrect proves the
// fail-closed drop holds across calls: once a 403 removes the stale copy, a
// later 429 on the same key cannot serve the policy GitHub refused to let us
// read. Without the stale removal a rate limit would resurrect and re-seed it.
func TestFetchTrustPolicyRawForbiddenThenRateLimitDoesNotResurrect(t *testing.T) {
	key := freshTPKey(t, "revoked")
	const policy = "issuer: https://example.com\nsubject: sub\n"
	staleTrustPolicies.Add(key, policy)
	s := &sts{}

	// First: a 403 fails closed and drops the stale copy.
	forbidden, _ := newFakeGitHubContents("", http.StatusForbidden)
	if _, err := s.fetchTrustPolicyRaw(context.Background(), newAppsTransport(t, forbidden), 1234, key); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("first fetch code = %v, want PermissionDenied; err = %v", status.Code(err), err)
	}

	// Then: a 429 on the same key must not find a stale policy to serve.
	limited, _ := newFakeGitHubContents("", http.StatusTooManyRequests)
	raw, err := s.fetchTrustPolicyRaw(context.Background(), newAppsTransport(t, limited), 1234, key)
	if status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("second fetch code = %v, want ResourceExhausted; err = %v", status.Code(err), err)
	}
	if raw != "" {
		t.Errorf("raw = %q, want empty (stale must not be resurrected by a rate limit)", raw)
	}
}

func TestIsProvenRateLimit(t *testing.T) {
	resp := func(code int) *github.ErrorResponse {
		return &github.ErrorResponse{Response: &http.Response{StatusCode: code}}
	}
	// respH builds a bare ErrorResponse (the shape go-github leaves when its
	// documentation_url anchor match fails to type a rate limit) with headers.
	// Headers are set through http.Header.Set so keys are canonicalized exactly
	// as net/http populates a real response, matching how isProvenRateLimit reads
	// them back with Get.
	respH := func(code int, kv ...string) *github.ErrorResponse {
		h := http.Header{}
		for i := 0; i+1 < len(kv); i += 2 {
			h.Set(kv[i], kv[i+1])
		}
		return &github.ErrorResponse{Response: &http.Response{StatusCode: code, Header: h}}
	}
	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"typed RateLimitError", &github.RateLimitError{Response: &http.Response{StatusCode: http.StatusForbidden}}, true},
		{"typed AbuseRateLimitError", &github.AbuseRateLimitError{Response: &http.Response{StatusCode: http.StatusForbidden}}, true},
		{"429", resp(http.StatusTooManyRequests), true},
		// A secondary limit go-github failed to type: a bare 403 with Retry-After.
		{"403 with Retry-After", respH(http.StatusForbidden, "Retry-After", "60"), true},
		// A primary limit surfacing as a bare 403 (untyped) with the count header.
		{"403 with X-RateLimit-Remaining 0", respH(http.StatusForbidden, "X-RateLimit-Remaining", "0"), true},
		// A permission 403: no rate-limit headers, remaining count not exhausted.
		{"403 with remaining budget", respH(http.StatusForbidden, "X-RateLimit-Remaining", "4999"), false},
		{"bare 403", resp(http.StatusForbidden), false},
		{"404", resp(http.StatusNotFound), false},
		{"500", resp(http.StatusInternalServerError), false},
		{"wrapped 429", fmt.Errorf("get contents: %w", resp(http.StatusTooManyRequests)), true},
		{"wrapped bare 403", fmt.Errorf("get contents: %w", resp(http.StatusForbidden)), false},
		{"wrapped 403 with Retry-After", fmt.Errorf("get contents: %w", respH(http.StatusForbidden, "Retry-After", "30")), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := isProvenRateLimit(tc.err); got != tc.want {
				t.Errorf("isProvenRateLimit(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

func TestIsForbidden(t *testing.T) {
	resp := func(code int) *github.ErrorResponse {
		return &github.ErrorResponse{Response: &http.Response{StatusCode: code}}
	}
	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"bare 403", resp(http.StatusForbidden), true},
		{"429", resp(http.StatusTooManyRequests), false},
		{"404", resp(http.StatusNotFound), false},
		{"wrapped 403", fmt.Errorf("get contents: %w", resp(http.StatusForbidden)), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := isForbidden(tc.err); got != tc.want {
				t.Errorf("isForbidden(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

// TestFetchTrustPolicyRawContextDeadline pins that a caller deadline expiring
// mid-fetch surfaces as DeadlineExceeded, not as a GitHub-transient Unavailable.
func TestFetchTrustPolicyRawContextDeadline(t *testing.T) {
	key := freshTPKey(t, "slowpoke")
	gh, _ := newFakeGitHubContents("", http.StatusInternalServerError)
	atr := newAppsTransport(t, gh)
	s := &sts{}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
	defer cancel()
	_, err := s.fetchTrustPolicyRaw(ctx, atr, 1234, key)
	if got := status.Code(err); got != codes.DeadlineExceeded {
		t.Fatalf("code = %v, want DeadlineExceeded; err = %v", got, err)
	}
}

// TestFetchTrustPolicyRawTransientThenNotFound pins the subtle boundary where
// backoff's try limit and a Permanent stop coincide on the final attempt: two
// 5xx then a 404 must resolve to NotFound and seed the negative cache.
func TestFetchTrustPolicyRawTransientThenNotFound(t *testing.T) {
	key := freshTPKey(t, "eventually-404")
	gh, counter := newFakeGitHubContents("",
		http.StatusInternalServerError, http.StatusInternalServerError, http.StatusNotFound)
	atr := newAppsTransport(t, gh)
	s := &sts{}

	_, err := s.fetchTrustPolicyRaw(context.Background(), atr, 1234, key)
	if got := status.Code(err); got != codes.NotFound {
		t.Fatalf("code = %v, want NotFound; err = %v", got, err)
	}
	if got := counter.Load(); got != int32(maxRetry) {
		t.Errorf("contents calls = %d, want %d", got, maxRetry)
	}
	if cached, ok := trustPolicies.Get(key); !ok || cached != negativeCacheConst {
		t.Error("final 404 did not seed the negative cache")
	}
}

func TestIsTransient(t *testing.T) {
	resp := func(code int) *github.ErrorResponse {
		return &github.ErrorResponse{Response: &http.Response{StatusCode: code}}
	}
	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"500", resp(http.StatusInternalServerError), true},
		{"502", resp(http.StatusBadGateway), true},
		{"503", resp(http.StatusServiceUnavailable), true},
		{"404", resp(http.StatusNotFound), false},
		{"403", resp(http.StatusForbidden), false},
		{"422", resp(http.StatusUnprocessableEntity), false},
		{"transport error", errors.New("dial tcp: connection refused"), true},
		{"context canceled", context.Canceled, false},
		{"deadline exceeded", context.DeadlineExceeded, false},
		{"wrapped 500", fmt.Errorf("get contents: %w", resp(http.StatusInternalServerError)), true},
		{"token-mint 500", &ghinstallation.HTTPError{Response: &http.Response{StatusCode: http.StatusBadGateway}}, true},
		{"token-mint 401", &ghinstallation.HTTPError{Response: &http.Response{StatusCode: http.StatusUnauthorized}}, false},
		{"token-mint 404", &ghinstallation.HTTPError{Response: &http.Response{StatusCode: http.StatusNotFound}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := isTransient(tc.err); got != tc.want {
				t.Errorf("isTransient(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}
