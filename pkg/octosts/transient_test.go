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
// cache writes mean the stale entry's TTL is not renewed on the serve.
func TestFetchTrustPolicyRawServesStaleOnRateLimit(t *testing.T) {
	key := freshTPKey(t, "stale-me")
	const policy = "issuer: https://example.com\nsubject: sub\n"
	staleTrustPolicies.Add(key, policy) // stale present, primary empty
	gh, counter := newFakeGitHubContents("", http.StatusForbidden)
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
