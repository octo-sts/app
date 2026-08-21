// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package provider

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// TestNewProviderWithRetryBoundsAttempts asserts that a failing discovery
// target is retried a bounded number of times even when the caller's context
// is generous, so an unauthenticated request cannot drive an open-ended number
// of outbound requests.
func TestNewProviderWithRetryBoundsAttempts(t *testing.T) {
	var attempts int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&attempts, 1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	// Far longer than the retry budget, so any bound observed comes from the
	// retry configuration rather than from the caller giving up.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	provider, err := newProviderWithRetry(ctx, server.URL)
	if err == nil {
		t.Fatal("newProviderWithRetry() = nil error, want failure once the retry budget is spent")
	}
	if provider != nil {
		t.Fatal("newProviderWithRetry() returned a provider, want nil")
	}
	if got := uint(atomic.LoadInt32(&attempts)); got != discoveryMaxTries {
		t.Errorf("attempts = %d, want %d", got, discoveryMaxTries)
	}
}

// TestNewProviderWithRetryBoundsStalledTarget asserts that a target which
// accepts the connection but never replies cannot hold the request for the
// caller's full deadline.
func TestNewProviderWithRetryBoundsStalledTarget(t *testing.T) {
	restore := shortenDiscoveryBudget(t, 200*time.Millisecond, 2*time.Second, 2)
	defer restore()

	stalled := make(chan struct{})
	defer close(stalled)

	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		// Hold the request until the test finishes or the client gives up.
		select {
		case <-stalled:
		case <-r.Context().Done():
		}
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	start := time.Now()
	if _, err := newProviderWithRetry(ctx, server.URL); err == nil {
		t.Fatal("newProviderWithRetry() = nil error, want failure against a stalled target")
	}
	// Each attempt is capped, and the attempts together are capped, so the
	// call must return long before the caller's own deadline.
	if elapsed := time.Since(start); elapsed > 30*time.Second {
		t.Errorf("newProviderWithRetry() took %v, want it bounded by the retry budget", elapsed)
	}
}

// shortenDiscoveryBudget lowers the discovery bounds for the duration of a
// test and returns a function restoring the previous values.
func shortenDiscoveryBudget(t *testing.T, attempt, elapsed time.Duration, tries uint) func() {
	t.Helper()
	oldAttempt, oldElapsed, oldTries := discoveryAttemptTimeout, discoveryMaxElapsedTime, discoveryMaxTries
	discoveryAttemptTimeout, discoveryMaxElapsedTime, discoveryMaxTries = attempt, elapsed, tries
	return func() {
		discoveryAttemptTimeout, discoveryMaxElapsedTime, discoveryMaxTries = oldAttempt, oldElapsed, oldTries
	}
}
